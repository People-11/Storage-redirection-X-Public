// hook 任务的添加、异步刷新请求与回调分发
use super::transaction;
use crate::api;
use crate::api::{HookMode, HookStub};
use crate::errno::Errno;
use crate::log;
use std::ffi::c_void;

use super::super::refresh::{self};
use super::super::state::{GLOBAL, Task};
use super::monitor;
use crate::runtime::fork;
use std::sync::atomic::Ordering;

pub(super) fn add_task_checked(task: Task) -> Result<HookStub, api::HookError> {
    register_task(task, None)
}

pub(super) fn add_monitor_task(
    task: Task,
    installation: &monitor::Installation,
) -> Option<HookStub> {
    register_task(task, Some(installation))
        .or_else(|error| error.stub.ok_or(error))
        .ok()
}

fn register_task(
    mut task: Task,
    installation: Option<&monitor::Installation>,
) -> Result<HookStub, api::HookError> {
    fork::check_management()?;
    let runtime = &*GLOBAL;
    let source = runtime.snapshot();
    if installation
        .is_some_and(|owner| !owner.is_current() || source.init.mode != HookMode::Automatic)
    {
        return Err(Errno::Busy.into());
    }
    if source.clearing {
        return Err(Errno::Busy.into());
    }
    if source.init.status != Errno::Ok {
        return Err(source.init.status.into());
    }
    let stub = runtime
        .next_stub
        .try_update(Ordering::AcqRel, Ordering::Acquire, |next| {
            next.checked_add(1)
        })
        .map_err(|_| Errno::InvalidArg)?;
    task.stub = stub;
    // Manual 模式下只入队，由后续 refresh() 统一应用
    let is_manual = source.init.mode == HookMode::Manual;
    if is_manual {
        let status = runtime.update(|state| {
            if state.clearing || state.init.mode != HookMode::Manual {
                return Errno::Busy;
            }
            if state.init.status != Errno::Ok {
                return state.init.status;
            }
            state.next_stub = runtime.next_stub.load(Ordering::Acquire);
            state.task_order.push(stub);
            state.tasks.insert(stub, task.clone());
            Errno::Ok
        });
        return if status == Errno::Ok {
            Ok(stub)
        } else {
            Err(status.into())
        };
    }
    let result = transaction::run(runtime, false, |source| {
        // epoch 校验使用本轮快照，clear 发布的新版本由 commit 再次核对。
        if source.init.mode != HookMode::Automatic
            || installation.is_some_and(|owner| !owner.is_current())
        {
            return Err(Errno::Busy);
        }
        let mut state = source.clone();
        state.next_stub = runtime.next_stub.load(Ordering::Acquire);
        state.task_order.push(stub);
        state.tasks.insert(stub, task.clone());
        let prepared = refresh::prepare_refresh(&state, false, Some(stub))?;
        Ok(prepared)
    });
    if !result.committed {
        return Err(api::HookError {
            status: result.status,
            stub: None,
            errors: result.errors,
        });
    }
    runtime.refresh_requested.store(true, Ordering::Release);
    monitor::start_monitor_thread();
    monitor::install_auto_loader_monitor_hooks();
    if result.status != Errno::Ok && result.status != Errno::NoSym {
        log::warn(format_args!(
            "hook task {} apply status {:?}",
            stub, result.status
        ));
        return Err(api::HookError {
            status: result.status,
            stub: Some(stub),
            errors: result.errors,
        });
    }
    Ok(stub)
}

pub(super) fn request_refresh_async() {
    GLOBAL.request_refresh_if_current();
}

// 异步事件触发模块重扫，由扫描阶段重新获取模块租期。
pub(super) fn request_refresh_async_with_handle(_handle: *mut c_void) {
    request_refresh_async();
}

// 卸载后重新核对所有模块的实例与 GOT。
pub(super) fn request_refresh_async_full() {
    request_refresh_async();
}
