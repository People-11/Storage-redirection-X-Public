use super::super::path as path_utils;
use super::super::runtime;
use super::super::stats::InterceptHub;
use super::super::util::c_str_to_string;
use super::super::{caller, diagnostic};
use crate::redirect::{
    get_caller_mappings, has_any_caller_mappings, policy, process_redirect_path,
    record_redirect_hit, resolve_system_writer_mapped_path,
};
use libc::{c_char, c_int, c_uint, c_void};
use std::ffi::CString;
use std::sync::atomic::{AtomicU64, Ordering};

static SYSTEM_WRITER_QUERY_BYPASS_COUNT: AtomicU64 = AtomicU64::new(0);
const SYSTEM_WRITER_QUERY_BYPASS_LOG_STEP: u64 = 4096;

fn should_bypass_system_writer_query(hub: &InterceptHub, op_name: &str) -> bool {
    if !policy::is_system_writer_package(&hub.get_package_name()) {
        return false;
    }

    let count = SYSTEM_WRITER_QUERY_BYPASS_COUNT.fetch_add(1, Ordering::Relaxed) + 1;
    if count == 1 || count.is_multiple_of(SYSTEM_WRITER_QUERY_BYPASS_LOG_STEP) {
        log::debug!(
            "query bypass system_writer pkg={} op={} n={}",
            hub.get_package_name(),
            op_name,
            count
        );
    }
    true
}

// 代写查询默认优先真实路径，真实路径不存在时回落到写入重定向目标，
// 与代写 mkdir/创建落入沙盒保持一致，避免 MediaProvider mkdirs 后 exists() 仍为 false
fn query_with_system_writer_fallback<F>(
    hub: &InterceptHub,
    op_name: &str,
    pathname: *const c_char,
    call_original: F,
) -> c_int
where
    F: Fn(*const c_char) -> c_int,
{
    if pathname.is_null() {
        return call_original(pathname);
    }
    let path_text = unsafe { c_str_to_string(pathname) };
    if !path_utils::is_relevant_storage_path(&path_text) {
        return call_original(pathname);
    }

    if let Some(result) =
        query_mapped_path_first(hub, op_name, pathname, &path_text, &call_original)
    {
        return result;
    }

    let result = call_original(pathname);
    if result == 0 || unsafe { *libc::__errno() } != libc::ENOENT {
        return result;
    }

    caller::update_caller_package_for_current_thread(hub);
    let redirect_result = process_redirect_path(hub, &path_text);
    diagnostic::log_diag_redirect_decision(hub, op_name, &path_text, &redirect_result);
    if redirect_result.is_redirect()
        && let Ok(c_path) = CString::new(redirect_result.new_path.as_str())
        && call_original(c_path.as_ptr()) == 0
    {
        record_redirect_hit(hub, op_name, &path_text, &redirect_result.new_path);
        return 0;
    }

    unsafe { *libc::__errno() = libc::ENOENT };
    result
}

// 映射即路径替换：命中调用方映射时先查映射目标，MediaProvider 的同名检查才与实际写入位置一致；
// 目标不存在再查真实路径。调用方未配置映射时返回 None，不增加决策开销
fn query_mapped_path_first<F>(
    hub: &InterceptHub,
    op_name: &str,
    pathname: *const c_char,
    path_text: &str,
    call_original: &F,
) -> Option<c_int>
where
    F: Fn(*const c_char) -> c_int,
{
    if !has_any_caller_mappings() {
        return None;
    }
    caller::update_caller_package_for_current_thread(hub);
    let caller_package = hub.get_current_caller_package();
    if caller_package.is_empty()
        || get_caller_mappings(&caller_package, hub.get_current_caller_uid()).is_empty()
    {
        return None;
    }

    let mapped_path = resolve_system_writer_mapped_path(hub, path_text)?;
    let c_mapped = CString::new(mapped_path.as_str()).ok()?;
    if call_original(c_mapped.as_ptr()) == 0 {
        record_redirect_hit(hub, op_name, path_text, &mapped_path);
        return Some(0);
    }
    Some(call_original(pathname))
}

pub unsafe extern "C" fn hooked_stat(pathname: *const c_char, statbuf: *mut libc::stat) -> c_int {
    let self_ptr = hooked_stat as *mut c_void;
    let call_with_path = |final_path: *const c_char| {
        runtime::call_prev(
            self_ptr,
            || libc::stat(final_path, statbuf),
            |prev| {
                let f: unsafe extern "C" fn(*const c_char, *mut libc::stat) -> c_int =
                    std::mem::transmute(prev);
                f(final_path, statbuf)
            },
        )
    };
    runtime::with_hook_guard(
        || call_with_path(pathname),
        |hub| {
            hub.increment_stat_calls();
            if should_bypass_system_writer_query(hub, "stat") {
                return query_with_system_writer_fallback(hub, "stat", pathname, call_with_path);
            }
            runtime::with_redirected_path(hub, "stat", pathname, call_with_path)
        },
    )
}

pub unsafe extern "C" fn hooked_lstat(pathname: *const c_char, statbuf: *mut libc::stat) -> c_int {
    let self_ptr = hooked_lstat as *mut c_void;
    let call_with_path = |final_path: *const c_char| {
        runtime::call_prev(
            self_ptr,
            || libc::lstat(final_path, statbuf),
            |prev| {
                let f: unsafe extern "C" fn(*const c_char, *mut libc::stat) -> c_int =
                    std::mem::transmute(prev);
                f(final_path, statbuf)
            },
        )
    };
    runtime::with_hook_guard(
        || call_with_path(pathname),
        |hub| {
            hub.increment_stat_calls();
            if should_bypass_system_writer_query(hub, "lstat") {
                return query_with_system_writer_fallback(hub, "lstat", pathname, call_with_path);
            }
            runtime::with_redirected_path(hub, "lstat", pathname, call_with_path)
        },
    )
}

pub unsafe extern "C" fn hooked_fstatat(
    dirfd: c_int,
    pathname: *const c_char,
    statbuf: *mut libc::stat,
    flags: c_int,
) -> c_int {
    let self_ptr = hooked_fstatat as *mut c_void;
    let call_with_path = |final_path: *const c_char| {
        runtime::call_prev(
            self_ptr,
            || libc::fstatat(dirfd, final_path, statbuf, flags),
            |prev| {
                let f: unsafe extern "C" fn(c_int, *const c_char, *mut libc::stat, c_int) -> c_int =
                    std::mem::transmute(prev);
                f(dirfd, final_path, statbuf, flags)
            },
        )
    };
    runtime::with_hook_guard(
        || call_with_path(pathname),
        |hub| {
            hub.increment_stat_calls();
            if should_bypass_system_writer_query(hub, "fstatat") {
                return query_with_system_writer_fallback(hub, "fstatat", pathname, call_with_path);
            }
            runtime::with_redirected_path(hub, "fstatat", pathname, call_with_path)
        },
    )
}

pub unsafe extern "C" fn hooked_access(pathname: *const c_char, mode: c_int) -> c_int {
    let self_ptr = hooked_access as *mut c_void;
    let call_with_path = |final_path: *const c_char| {
        runtime::call_prev(
            self_ptr,
            || libc::access(final_path, mode),
            |prev| {
                let f: unsafe extern "C" fn(*const c_char, c_int) -> c_int =
                    std::mem::transmute(prev);
                f(final_path, mode)
            },
        )
    };
    runtime::with_hook_guard(
        || call_with_path(pathname),
        |hub| {
            hub.increment_access_calls();
            if should_bypass_system_writer_query(hub, "access") {
                return query_with_system_writer_fallback(hub, "access", pathname, call_with_path);
            }
            runtime::with_redirected_path(hub, "access", pathname, call_with_path)
        },
    )
}

pub unsafe extern "C" fn hooked_faccessat(
    dirfd: c_int,
    pathname: *const c_char,
    mode: c_int,
    flags: c_int,
) -> c_int {
    let self_ptr = hooked_faccessat as *mut c_void;
    let call_with_path = |final_path: *const c_char| {
        runtime::call_prev(
            self_ptr,
            || libc::faccessat(dirfd, final_path, mode, flags),
            |prev| {
                let f: unsafe extern "C" fn(c_int, *const c_char, c_int, c_int) -> c_int =
                    std::mem::transmute(prev);
                f(dirfd, final_path, mode, flags)
            },
        )
    };
    runtime::with_hook_guard(
        || call_with_path(pathname),
        |hub| {
            hub.increment_access_calls();
            if should_bypass_system_writer_query(hub, "faccessat") {
                return query_with_system_writer_fallback(
                    hub,
                    "faccessat",
                    pathname,
                    call_with_path,
                );
            }
            runtime::with_redirected_path(hub, "faccessat", pathname, call_with_path)
        },
    )
}

pub unsafe extern "C" fn hooked_statx(
    dirfd: c_int,
    pathname: *const c_char,
    flags: c_int,
    mask: c_uint,
    statxbuf: *mut libc::statx,
) -> c_int {
    let self_ptr = hooked_statx as *mut c_void;
    let call_with_path = |final_path: *const c_char| {
        runtime::call_prev(
            self_ptr,
            || libc::statx(dirfd, final_path, flags, mask, statxbuf),
            |prev| {
                let f: unsafe extern "C" fn(
                    c_int,
                    *const c_char,
                    c_int,
                    c_uint,
                    *mut libc::statx,
                ) -> c_int = std::mem::transmute(prev);
                f(dirfd, final_path, flags, mask, statxbuf)
            },
        )
    };
    runtime::with_hook_guard(
        || call_with_path(pathname),
        |hub| {
            hub.increment_stat_calls();
            if should_bypass_system_writer_query(hub, "statx") {
                return query_with_system_writer_fallback(hub, "statx", pathname, call_with_path);
            }
            runtime::with_redirected_path(hub, "statx", pathname, call_with_path)
        },
    )
}

pub unsafe extern "C" fn hooked_opendir(name: *const c_char) -> *mut libc::DIR {
    let self_ptr = hooked_opendir as *mut c_void;
    let call_with_path = |final_path: *const c_char| {
        runtime::call_prev(
            self_ptr,
            || libc::opendir(final_path),
            |prev| {
                let f: unsafe extern "C" fn(*const c_char) -> *mut libc::DIR =
                    std::mem::transmute(prev);
                f(final_path)
            },
        )
    };
    runtime::with_hook_guard(
        || call_with_path(name),
        |hub| {
            hub.increment_opendir_calls();
            if should_bypass_system_writer_query(hub, "opendir") {
                return call_with_path(name);
            }
            runtime::with_redirected_path(hub, "opendir", name, call_with_path)
        },
    )
}

pub unsafe extern "C" fn hooked_readlink(
    pathname: *const c_char,
    buf: *mut c_char,
    bufsiz: usize,
) -> isize {
    let self_ptr = hooked_readlink as *mut c_void;
    let call_with_path = |final_path: *const c_char| {
        runtime::call_prev(
            self_ptr,
            || libc::readlink(final_path, buf, bufsiz),
            |prev| {
                let f: unsafe extern "C" fn(*const c_char, *mut c_char, usize) -> isize =
                    std::mem::transmute(prev);
                f(final_path, buf, bufsiz)
            },
        )
    };
    runtime::with_hook_guard(
        || call_with_path(pathname),
        |hub| {
            hub.increment_readlink_calls();
            if should_bypass_system_writer_query(hub, "readlink") {
                return call_with_path(pathname);
            }
            runtime::with_redirected_path(hub, "readlink", pathname, call_with_path)
        },
    )
}
