// C FFI 层：只导出 LSPlant 桥接使用的 init、hook_func_addr 与 unhook

use core::ffi::{c_int, c_void};
use core::ptr;

use crate::api::{self, HookStub};
use crate::errno::Errno;

#[unsafe(no_mangle)]
pub extern "C" fn srx_inline_hook_init(debuggable: bool) -> c_int {
    match api::init(debuggable) {
        Ok(()) => Errno::Ok as c_int,
        Err(e) => e as c_int,
    }
}

// orig_addr 可为 NULL；返回 stub 或 NULL
#[unsafe(no_mangle)]
pub unsafe extern "C" fn srx_inline_hook_hook_func_addr(
    func_addr: *mut c_void,
    new_addr: *mut c_void,
    orig_addr: *mut *mut c_void,
) -> *mut c_void {
    // SAFETY: func_addr / new_addr 为本进程有效代码地址；orig_addr 为 NULL 或可写槽
    match unsafe { api::hook_sym_addr(func_addr, new_addr, orig_addr as *mut *const c_void) } {
        Ok(s) => s.handle,
        Err(_) => ptr::null_mut(),
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn srx_inline_hook_unhook(stub: *mut c_void) -> c_int {
    if stub.is_null() {
        return -1;
    }
    // SAFETY: stub 来自先前 hook_func_addr 返回值，调用方保留到 unhook 完成
    match unsafe { api::unhook(HookStub { handle: stub }) } {
        Ok(()) => 0,
        Err(_) => -1,
    }
}
