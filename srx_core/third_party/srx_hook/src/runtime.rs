// runtime 模块入口，将内部子模块的功能统一暴露为 crate 级公共接口
use crate::api;
use crate::api::{HookMode, HookStub};
use crate::errno::Errno;
use std::ffi::c_void;

mod cfi;
mod fork;
mod hub;
mod lifecycle;
mod refresh;
mod rules;
mod state;
mod thread_state;

pub(crate) use fork::{InitializationCall, LoaderCall};
pub(crate) use state::PidLocal;

pub(crate) fn is_forked_child() -> bool {
    state::is_forked_child()
}

pub(crate) fn check_management() -> Result<(), Errno> {
    fork::check_management()
}

pub(crate) fn init(mode: HookMode, debug: bool) -> Errno {
    lifecycle::init(mode, debug)
}

pub(crate) fn hook_all_checked(
    sym_name: &str,
    new_func: *mut c_void,
) -> Result<HookStub, api::HookError> {
    lifecycle::hook_all_checked(sym_name, new_func)
}

pub(crate) fn add_ignore(caller_path_name: &str) -> Errno {
    lifecycle::add_ignore(caller_path_name)
}

pub(crate) fn refresh() -> (Errno, Vec<api::RefreshError>) {
    lifecycle::refresh()
}

pub(crate) fn with_prev_func<R, F>(func: *mut c_void, f: F) -> Option<R>
where
    F: FnOnce(*mut c_void) -> R,
{
    lifecycle::with_prev_func(func, f)
}
