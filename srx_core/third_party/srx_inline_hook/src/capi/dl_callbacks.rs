use core::mem;
use std::process;

use super::prelude::*;

// dl_init / dl_fini callback 检查序：Disabled → init_errno → Android < 21 NotSupport → (pre && post NULL) InvalidArg
fn dl_callback_precheck(pre: *mut c_void, post: *mut c_void) -> Result<(), Errno> {
    if api::is_disabled() {
        return Err(Errno::Disabled);
    }
    let init_err = api::get_init_errno();
    if init_err != Errno::Ok {
        return Err(init_err);
    }
    if android::device_api_level() < 21 {
        return Err(Errno::NotSupport);
    }
    if pre.is_null() && post.is_null() {
        return Err(Errno::InvalidArg);
    }
    Ok(())
}

fn dl_cb(pre: *mut c_void) -> Option<DlInfoCallback> {
    if pre.is_null() {
        None
    } else {
        Some(unsafe { mem::transmute::<*mut c_void, DlInfoCallback>(pre) })
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn srx_inline_hook_register_dl_init_callback(
    pre: *mut c_void,
    post: *mut c_void,
    data: *mut c_void,
) -> c_int {
    let r = dl_callback_precheck(pre, post)
        .and_then(|_| dlcb::register_init(dl_cb(pre), dl_cb(post), data));
    let e = match r {
        Ok(()) => Errno::Ok,
        Err(e) => e,
    };
    tls_errno::set(e);
    e as c_int
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn srx_inline_hook_unregister_dl_init_callback(
    pre: *mut c_void,
    post: *mut c_void,
    data: *mut c_void,
) -> c_int {
    let r = dl_callback_precheck(pre, post)
        .and_then(|_| dlcb::unregister_init(dl_cb(pre), dl_cb(post), data));
    let e = match r {
        Ok(()) => Errno::Ok,
        Err(e) => e,
    };
    tls_errno::set(e);
    e as c_int
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn srx_inline_hook_register_dl_fini_callback(
    pre: *mut c_void,
    post: *mut c_void,
    data: *mut c_void,
) -> c_int {
    let r = dl_callback_precheck(pre, post)
        .and_then(|_| dlcb::register_fini(dl_cb(pre), dl_cb(post), data));
    let e = match r {
        Ok(()) => Errno::Ok,
        Err(e) => e,
    };
    tls_errno::set(e);
    e as c_int
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn srx_inline_hook_unregister_dl_fini_callback(
    pre: *mut c_void,
    post: *mut c_void,
    data: *mut c_void,
) -> c_int {
    let r = dl_callback_precheck(pre, post)
        .and_then(|_| dlcb::unregister_fini(dl_cb(pre), dl_cb(post), data));
    let e = match r {
        Ok(()) => Errno::Ok,
        Err(e) => e,
    };
    tls_errno::set(e);
    e as c_int
}

// stack / reentrant 家族：最小 SHARED 语义依赖显式 push/pop 维护 TLS 栈帧
#[unsafe(no_mangle)]
pub unsafe extern "C" fn srx_inline_hook_pop_stack(return_address: *mut c_void) {
    shared_stack::pop(return_address);
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn srx_inline_hook_allow_reentrant(return_address: *mut c_void) {
    shared_stack::set_allow_reentrant(return_address, true);
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn srx_inline_hook_disallow_reentrant(return_address: *mut c_void) {
    shared_stack::set_allow_reentrant(return_address, false);
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn srx_inline_hook_get_return_address() -> *mut c_void {
    if !shared_stack::has_frame() {
        process::abort();
    }
    shared_stack::current_return_address()
}
