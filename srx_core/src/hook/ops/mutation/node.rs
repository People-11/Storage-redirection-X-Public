use crate::hook::diagnostic;
use crate::hook::path as path_utils;
use crate::hook::runtime;
use crate::hook::stats::InterceptHub;
use crate::hook::util::c_str_to_string;
use crate::redirect::{process_redirect_path, record_redirect_hit};
use libc::{c_char, c_int, c_void, mode_t};
use std::ffi::CString;

// FuseDaemon 通过 mknod 创建文件节点，必须 hook
pub unsafe extern "C" fn hooked_mknod(
    pathname: *const c_char,
    mode: mode_t,
    dev: libc::dev_t,
) -> c_int {
    let self_ptr = hooked_mknod as *mut c_void;
    let call_with_path = |final_path: *const c_char| {
        runtime::call_prev(
            self_ptr,
            || libc::mknod(final_path, mode, dev),
            |prev| {
                let f: unsafe extern "C" fn(*const c_char, mode_t, libc::dev_t) -> c_int =
                    std::mem::transmute(prev);
                f(final_path, mode, dev)
            },
        )
    };
    runtime::with_hook_guard(
        || call_with_path(pathname),
        |hub| {
            hub.increment_mkdir_calls();
            if runtime::should_resolve_caller_context(hub) {
                crate::hook::caller::update_caller_package_for_current_thread(hub);
            }

            handle_mknod_like(hub, "mknod", pathname, mode, call_with_path)
        },
    )
}

pub unsafe extern "C" fn hooked_mknodat(
    dirfd: c_int,
    pathname: *const c_char,
    mode: mode_t,
    dev: libc::dev_t,
) -> c_int {
    let self_ptr = hooked_mknodat as *mut c_void;
    let call_with_path = |final_path: *const c_char| {
        runtime::call_prev(
            self_ptr,
            || libc::syscall(libc::SYS_mknodat, dirfd, final_path, mode, dev) as c_int,
            |prev| {
                let f: unsafe extern "C" fn(c_int, *const c_char, mode_t, libc::dev_t) -> c_int =
                    std::mem::transmute(prev);
                f(dirfd, final_path, mode, dev)
            },
        )
    };
    runtime::with_hook_guard(
        || call_with_path(pathname),
        |hub| {
            hub.increment_mkdir_calls();
            if runtime::should_resolve_caller_context(hub) {
                crate::hook::caller::update_caller_package_for_current_thread(hub);
            }

            handle_mknod_like(hub, "mknodat", pathname, mode, call_with_path)
        },
    )
}

// 统一按文件创建事件记录
fn handle_mknod_like<F>(
    hub: &InterceptHub,
    op_name: &str,
    pathname: *const c_char,
    mode: mode_t,
    call_original: F,
) -> c_int
where
    F: FnOnce(*const c_char) -> c_int,
{
    if pathname.is_null() {
        return call_original(pathname);
    }

    let path_text = unsafe { c_str_to_string(pathname) };
    if path_text.is_empty() || !path_text.starts_with('/') {
        return call_original(pathname);
    }

    diagnostic::log_diag_path_event(hub, op_name, "input", &path_text, mode as i32);

    if !path_utils::is_relevant_storage_path(&path_text) {
        diagnostic::record_fast_bypass(op_name, &path_text);
        return call_original(pathname);
    }

    let redirect_result = process_redirect_path(hub, &path_text);
    diagnostic::log_diag_redirect_decision(hub, op_name, &path_text, &redirect_result);

    if redirect_result.is_redirect() {
        record_redirect_hit(hub, op_name, &path_text, &redirect_result.new_path);
        runtime::ensure_redirect_parent_dirs(&redirect_result.new_path, mode);
        if let Ok(c_path) = CString::new(redirect_result.new_path.as_str()) {
            call_original(c_path.as_ptr())
        } else {
            call_original(pathname)
        }
    } else {
        call_original(pathname)
    }
}
