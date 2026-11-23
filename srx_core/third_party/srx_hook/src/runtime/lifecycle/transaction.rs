use std::mem;
use std::ptr;
use std::sync::Arc;

use crate::api::RefreshError;
use crate::errno::Errno;
use crate::runtime::fork;
use crate::runtime::refresh::PreparedRefresh;
use crate::runtime::state::{CoreState, ProcessRuntime};

pub(super) struct CommitResult {
    pub(super) status: Errno,
    pub(super) errors: Vec<RefreshError>,
    pub(super) committed: bool,
    retryable: bool,
}

impl CommitResult {
    fn failed(status: Errno) -> Self {
        Self {
            status,
            errors: Vec::new(),
            committed: false,
            retryable: false,
        }
    }
}

// 每轮从完整快照重新准备；重入过滤器和持续竞争受尝试次数约束。
// 被拒绝写入的模块在重试前已记入快照，其错误并入最终结果，调用方能看到哪些模块被跳过。
pub(super) fn run(
    runtime: &ProcessRuntime,
    allow_clearing: bool,
    mut prepare: impl FnMut(&CoreState) -> Result<PreparedRefresh, Errno>,
) -> CommitResult {
    let mut carried_errors = Vec::new();
    for _ in 0..ProcessRuntime::PUBLISH_ATTEMPTS {
        if let Err(status) = fork::check_management() {
            return CommitResult::failed(status);
        }
        if !runtime.is_current() {
            return CommitResult::failed(Errno::ForkContextUnavailable);
        }
        let source = runtime.snapshot();
        if !allow_clearing {
            if source.clearing {
                return CommitResult::failed(Errno::Busy);
            }
            if source.init.status != Errno::Ok {
                return CommitResult::failed(source.init.status);
            }
        }
        let prepared = match prepare(&source) {
            Ok(prepared) => prepared,
            Err(Errno::Busy) => continue,
            Err(status) => return CommitResult::failed(status),
        };
        let mut result = commit(runtime, &source, prepared);
        if !result.retryable {
            merge_errors(&mut carried_errors, result.errors);
            result.errors = carried_errors;
            return result;
        }
        merge_errors(&mut carried_errors, result.errors);
    }
    CommitResult {
        errors: carried_errors,
        ..CommitResult::failed(Errno::Busy)
    }
}

// 准备阶段的模块错误每轮都会重新产生，合并时按模块路径与错误码去重
fn merge_errors(merged: &mut Vec<RefreshError>, errors: Vec<RefreshError>) {
    for error in errors {
        if !merged
            .iter()
            .any(|known| known.module_path == error.module_path && known.errno == error.errno)
        {
            merged.push(error);
        }
    }
}

pub(super) fn commit(
    runtime: &ProcessRuntime,
    source: &CoreState,
    mut prepared: PreparedRefresh,
) -> CommitResult {
    prepared.draft.revision = source.revision.wrapping_add(1);
    let mut failure_draft = prepared.failure_draft(source);
    failure_draft.revision = prepared.draft.revision;
    let mut next = Some(Arc::new(mem::take(&mut prepared.draft)));
    let mut failure = Some(Arc::new(failure_draft));
    let mut old = ptr::null();
    let mut status = prepared.status;
    let mut callback_entered = false;
    let mut retryable = false;
    let result = prepared.with_loader_lease(|change| {
        callback_entered = true;
        fork::check_management()?;
        let Some(guard) = fork::try_publish() else {
            fork::check_management()?;
            retryable = true;
            return Err(Errno::Busy);
        };
        if !runtime.is_current() {
            return Err(Errno::ForkContextUnavailable);
        }
        if !runtime.revision_matches(source.revision) {
            retryable = true;
            return Err(Errno::Busy);
        }
        let applied = change.apply_prepared();
        if change.committed || change.protection_state_changed {
            let selected = if change.committed {
                &mut next
            } else {
                &mut failure
            };
            let draft = selected
                .as_mut()
                .and_then(Arc::get_mut)
                .ok_or(Errno::Invalid)?;
            change.write_protection_results(draft);
            change.write_refresh_coverage(draft);
            old = runtime.publish_raw(source.revision, selected)?;
        }
        drop(guard);
        retryable =
            (applied == Errno::Busy && !change.committed && !change.protection_state_changed)
                || (applied == Errno::SetProt && change.can_retry_without_write_denied());
        if applied != Errno::Ok {
            status = applied;
        }
        Ok(())
    });
    prepared.append_commit_errors();
    if let Err(error) = result {
        return CommitResult {
            retryable: retryable || (!callback_entered && error == Errno::Busy),
            errors: prepared.errors,
            ..CommitResult::failed(error)
        };
    }
    runtime.retire(old);
    let committed = !old.is_null() && prepared.committed;
    CommitResult {
        status,
        errors: prepared.errors,
        committed,
        retryable,
    }
}
