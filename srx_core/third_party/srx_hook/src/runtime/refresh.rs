// 模块发现与准备在发布锁外完成，GOT 与链只经租期内的纯提交发布。
use crate::api::RefreshError;
use crate::errno::Errno;

use super::state::ProcessRuntime;

mod lease;
mod matcher;
mod module_registry;
mod ops;
mod prepare;
mod transaction;

#[cfg(target_arch = "aarch64")]
pub(super) use prepare::prepare_cfi_init;
pub(super) use prepare::prepare_refresh;
pub(super) use transaction::PreparedRefresh;

pub(super) fn module_epoch() -> Option<(u64, u64)> {
    ops::module_epoch().map(|epoch| (epoch.adds, epoch.subs))
}

pub(super) fn is_current_refresh_covered(runtime: &ProcessRuntime) -> Result<bool, Errno> {
    lease::with_loader_lease(|epoch| {
        if !runtime.is_current() {
            return Err(Errno::ForkContextUnavailable);
        }
        let state = runtime.snapshot();
        if state.clearing {
            return Err(Errno::Busy);
        }
        if state.init.status != Errno::Ok {
            return Err(state.init.status);
        }
        Ok(state.refresh_coverage.is_some_and(|coverage| {
            coverage.revision == state.revision && coverage.loader_epoch == (epoch.adds, epoch.subs)
        }))
    })
}
