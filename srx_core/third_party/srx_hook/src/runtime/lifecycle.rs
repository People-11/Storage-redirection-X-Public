// 生命周期管理模块，作为 runtime 子模块的统一入口
// 将 init/hook/refresh 等操作分发到各子模块
use crate::api;
use crate::api::{HookMode, HookStub, RefreshError};
use crate::errno::Errno;
use std::ffi::c_void;

mod batch_ops;
mod monitor;
mod monitor_calls;
mod proxy;
mod task_ops;
mod transaction;

mod entry_control;
mod entry_hook;
mod entry_init;

pub(super) fn init(mode: HookMode, debug: bool) -> Errno {
    entry_init::init(mode, debug)
}

pub(super) fn hook_all_checked(
    sym_name: &str,
    new_func: *mut c_void,
) -> Result<HookStub, api::HookError> {
    entry_hook::hook_all_checked(sym_name, new_func)
}

pub(super) fn add_ignore(caller_path_name: &str) -> Errno {
    entry_hook::add_ignore(caller_path_name)
}

pub(super) fn refresh() -> (Errno, Vec<RefreshError>) {
    entry_hook::refresh()
}

pub(super) fn with_prev_func<R, F>(func: *mut c_void, f: F) -> Option<R>
where
    F: FnOnce(*mut c_void) -> R,
{
    entry_control::with_prev_func(func, f)
}

pub(super) fn request_refresh_async_with_handle(handle: *mut c_void) {
    task_ops::request_refresh_async_with_handle(handle);
}

pub(super) fn request_refresh_async_full() {
    task_ops::request_refresh_async_full();
}
