use super::super::{context, runtime};
use libc::c_void;
use std::sync::atomic::{AtomicU64, Ordering};

// 每次 Binder 调用都会清除与恢复身份，只保留稀疏样本
const BINDER_IDENTITY_LOG_STEP: u64 = 4096;
static BINDER_IDENTITY_LOG_COUNT: AtomicU64 = AtomicU64::new(0);

fn next_binder_identity_log_count() -> Option<u64> {
    let count = BINDER_IDENTITY_LOG_COUNT.fetch_add(1, Ordering::Relaxed) + 1;
    (count == 1 || count.is_multiple_of(BINDER_IDENTITY_LOG_STEP)).then_some(count)
}

unsafe fn call_clear_calling_identity(this: *mut c_void) -> i64 {
    let self_ptr = hooked_clear_calling_identity as *mut c_void;
    runtime::call_prev_lazy(
        self_ptr,
        || 0i64,
        |prev| {
            let f: unsafe extern "C" fn(*mut c_void) -> i64 = std::mem::transmute(prev);
            f(this)
        },
    )
}

// 清除身份前抢先快照 UID，后续 hook 仍能溯源真实调用方
pub unsafe extern "C" fn hooked_clear_calling_identity(this: *mut c_void) -> i64 {
    super::super::caller::capture_binder_caller_uid_if_available();
    context::set_binder_identity_cleared(true);
    if let Some(count) = next_binder_identity_log_count() {
        log::debug!(
            "binder identity cleared saved_uid={} n={}",
            context::get_binder_saved_caller_uid(),
            count
        );
    }
    call_clear_calling_identity(this)
}

unsafe fn call_restore_calling_identity(this: *mut c_void, token: i64) {
    let self_ptr = hooked_restore_calling_identity as *mut c_void;
    runtime::call_prev_lazy(
        self_ptr,
        || {},
        |prev| {
            let f: unsafe extern "C" fn(*mut c_void, i64) = std::mem::transmute(prev);
            f(this, token)
        },
    );
}

pub unsafe extern "C" fn hooked_restore_calling_identity(this: *mut c_void, token: i64) {
    let saved_uid = context::get_binder_saved_caller_uid();
    let age_ms = context::get_binder_saved_caller_uid_age_ms();
    call_restore_calling_identity(this, token);
    context::clear_binder_saved_caller_uid();
    context::set_binder_identity_cleared(false);
    if let Some(count) = next_binder_identity_log_count() {
        log::debug!(
            "binder identity restored saved_uid={} age_ms={} n={}",
            saved_uid,
            age_ms,
            count
        );
    }
}
