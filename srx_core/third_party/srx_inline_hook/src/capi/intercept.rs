use core::mem;

use super::prelude::*;

// 公开 C ABI 的 intercept 入口
// 参数前置检查失败时返回 NULL 并写入线程局部 errno

// intercept 前置检查序：NULL → InvalidArg(3) → Disabled(45) → init_errno → NotSupport(38)
fn intercept_precheck_addr(target: *mut c_void, pre: *mut c_void, flags: u32) -> Result<(), Errno> {
    if target.is_null() || pre.is_null() {
        return Err(Errno::InvalidArg);
    }
    api::check_intercept_flags(flags)?;
    if api::is_disabled() {
        return Err(Errno::Disabled);
    }
    let init_err = api::get_init_errno();
    if init_err != Errno::Ok {
        return Err(init_err);
    }
    Ok(())
}

fn intercept_precheck_name(
    lib_name: *const c_char,
    sym_name: *const c_char,
    pre: *mut c_void,
    flags: u32,
) -> Result<(), Errno> {
    if lib_name.is_null() || sym_name.is_null() || pre.is_null() {
        return Err(Errno::InvalidArg);
    }
    api::check_intercept_flags(flags)?;
    if api::is_disabled() {
        return Err(Errno::Disabled);
    }
    let init_err = api::get_init_errno();
    if init_err != Errno::Ok {
        return Err(init_err);
    }
    Ok(())
}

unsafe fn intercept_instr_addr_impl(
    instr_addr: *mut c_void,
    pre: *mut c_void,
    data: *mut c_void,
    flags: u32,
    record_lib_name: Option<&CStr>,
    record_sym_name: Option<&CStr>,
    caller_addr: usize,
) -> *mut c_void {
    if let Err(e) = intercept_precheck_addr(instr_addr, pre, flags) {
        tls_errno::set(e);
        return ptr::null_mut();
    }
    let pre_fn: Interceptor = unsafe { mem::transmute(pre) };
    let r = unsafe {
        api::intercept_instr_addr_with_names_and_caller_addr(
            instr_addr,
            pre_fn,
            data,
            flags,
            record_lib_name,
            record_sym_name,
            caller_addr,
        )
    };
    stub_or_null(r)
}

unsafe fn intercept_func_addr_impl(
    func_addr: *mut c_void,
    pre: *mut c_void,
    data: *mut c_void,
    flags: u32,
    record_lib_name: Option<&CStr>,
    record_sym_name: Option<&CStr>,
    caller_addr: usize,
) -> *mut c_void {
    if let Err(e) = intercept_precheck_addr(func_addr, pre, flags) {
        tls_errno::set(e);
        return ptr::null_mut();
    }
    let pre_fn: Interceptor = unsafe { mem::transmute(pre) };
    let r = unsafe {
        api::intercept_func_addr_with_names_and_caller_addr(
            func_addr,
            pre_fn,
            data,
            flags,
            record_lib_name,
            record_sym_name,
            caller_addr,
        )
    };
    stub_or_null(r)
}

unsafe fn intercept_sym_addr_impl(
    sym_addr: *mut c_void,
    pre: *mut c_void,
    data: *mut c_void,
    flags: u32,
    record_lib_name: Option<&CStr>,
    record_sym_name: Option<&CStr>,
    caller_addr: usize,
) -> *mut c_void {
    if let Err(e) = intercept_precheck_addr(sym_addr, pre, flags) {
        tls_errno::set(e);
        return ptr::null_mut();
    }
    let pre_fn: Interceptor = unsafe { mem::transmute(pre) };
    let r = unsafe {
        api::intercept_sym_addr_with_names_and_caller_addr(
            sym_addr,
            pre_fn,
            data,
            flags,
            record_lib_name,
            record_sym_name,
            caller_addr,
        )
    };
    stub_or_null(r)
}

#[unsafe(no_mangle)]
unsafe extern "C" fn srx_inline_hook_intercept_instr_addr_impl(
    instr_addr: *mut c_void,
    pre: *mut c_void,
    data: *mut c_void,
    flags: u32,
    record_lib_name: *const c_char,
    record_sym_name: *const c_char,
    caller_addr: *mut c_void,
) -> *mut c_void {
    let (record_lib_name, record_sym_name) =
        match unsafe { parse_record_names(flags, record_lib_name, record_sym_name) } {
            Ok(v) => v,
            Err(e) => {
                tls_errno::set(e);
                return ptr::null_mut();
            }
        };
    unsafe {
        intercept_instr_addr_impl(
            instr_addr,
            pre,
            data,
            flags,
            record_lib_name,
            record_sym_name,
            caller_addr as usize,
        )
    }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn srx_inline_hook_intercept_func_addr_impl(
    func_addr: *mut c_void,
    pre: *mut c_void,
    data: *mut c_void,
    flags: u32,
    record_lib_name: *const c_char,
    record_sym_name: *const c_char,
    caller_addr: *mut c_void,
) -> *mut c_void {
    let (record_lib_name, record_sym_name) =
        match unsafe { parse_record_names(flags, record_lib_name, record_sym_name) } {
            Ok(v) => v,
            Err(e) => {
                tls_errno::set(e);
                return ptr::null_mut();
            }
        };
    unsafe {
        intercept_func_addr_impl(
            func_addr,
            pre,
            data,
            flags,
            record_lib_name,
            record_sym_name,
            caller_addr as usize,
        )
    }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn srx_inline_hook_intercept_sym_addr_impl(
    sym_addr: *mut c_void,
    pre: *mut c_void,
    data: *mut c_void,
    flags: u32,
    record_lib_name: *const c_char,
    record_sym_name: *const c_char,
    caller_addr: *mut c_void,
) -> *mut c_void {
    let (record_lib_name, record_sym_name) =
        match unsafe { parse_record_names(flags, record_lib_name, record_sym_name) } {
            Ok(v) => v,
            Err(e) => {
                tls_errno::set(e);
                return ptr::null_mut();
            }
        };
    unsafe {
        intercept_sym_addr_impl(
            sym_addr,
            pre,
            data,
            flags,
            record_lib_name,
            record_sym_name,
            caller_addr as usize,
        )
    }
}

#[cfg(target_arch = "x86_64")]
global_asm!(
    r#"
.hidden {instr_impl}
.hidden {func_impl}
.hidden {sym_impl}
.hidden {sym_name_impl}
.hidden {sym_name_cb_impl}
.globl srx_inline_hook_intercept_instr_addr
.type srx_inline_hook_intercept_instr_addr,@function
srx_inline_hook_intercept_instr_addr:
    mov r10, [rsp]
    test ecx, 4
    jne 1f
    xor r8d, r8d
    xor r9d, r9d
1:
    push r10
    call {instr_impl}
    add rsp, 8
    ret

.globl srx_inline_hook_intercept_func_addr
.type srx_inline_hook_intercept_func_addr,@function
srx_inline_hook_intercept_func_addr:
    mov r10, [rsp]
    test ecx, 4
    jne 1f
    xor r8d, r8d
    xor r9d, r9d
1:
    push r10
    call {func_impl}
    add rsp, 8
    ret

.globl srx_inline_hook_intercept_sym_addr
.type srx_inline_hook_intercept_sym_addr,@function
srx_inline_hook_intercept_sym_addr:
    mov r10, [rsp]
    test ecx, 4
    jne 1f
    xor r8d, r8d
    xor r9d, r9d
1:
    push r10
    call {sym_impl}
    add rsp, 8
    ret

.globl srx_inline_hook_intercept_sym_name
.type srx_inline_hook_intercept_sym_name,@function
srx_inline_hook_intercept_sym_name:
    mov r9, [rsp]
    jmp {sym_name_impl}

.globl srx_inline_hook_intercept_sym_name_callback
.type srx_inline_hook_intercept_sym_name_callback,@function
srx_inline_hook_intercept_sym_name_callback:
    mov r10, [rsp]
    mov r11, [rsp + 8]
    sub rsp, 24
    mov [rsp], r11
    mov [rsp + 8], r10
    call {sym_name_cb_impl}
    add rsp, 24
    ret
"#,
    instr_impl = sym srx_inline_hook_intercept_instr_addr_impl,
    func_impl = sym srx_inline_hook_intercept_func_addr_impl,
    sym_impl = sym srx_inline_hook_intercept_sym_addr_impl,
    sym_name_impl = sym srx_inline_hook_intercept_sym_name_impl,
    sym_name_cb_impl = sym srx_inline_hook_intercept_sym_name_callback_impl,
);

#[cfg(target_arch = "aarch64")]
global_asm!(
    r#"
.hidden {instr_impl}
.hidden {func_impl}
.hidden {sym_impl}
.hidden {sym_name_impl}
.hidden {sym_name_cb_impl}
.globl srx_inline_hook_intercept_instr_addr
.balign 4
.type srx_inline_hook_intercept_instr_addr, %function
srx_inline_hook_intercept_instr_addr:
    mov x6, x30
    tbz w3, #2, 1f
    b {instr_impl}
1:
    mov x4, xzr
    mov x5, xzr
    b {instr_impl}

.globl srx_inline_hook_intercept_func_addr
.balign 4
.type srx_inline_hook_intercept_func_addr, %function
srx_inline_hook_intercept_func_addr:
    mov x6, x30
    tbz w3, #2, 1f
    b {func_impl}
1:
    mov x4, xzr
    mov x5, xzr
    b {func_impl}

.globl srx_inline_hook_intercept_sym_addr
.balign 4
.type srx_inline_hook_intercept_sym_addr, %function
srx_inline_hook_intercept_sym_addr:
    mov x6, x30
    tbz w3, #2, 1f
    b {sym_impl}
1:
    mov x4, xzr
    mov x5, xzr
    b {sym_impl}

.globl srx_inline_hook_intercept_sym_name
.balign 4
.type srx_inline_hook_intercept_sym_name, %function
srx_inline_hook_intercept_sym_name:
    mov x5, x30
    b {sym_name_impl}

.globl srx_inline_hook_intercept_sym_name_callback
.balign 4
.type srx_inline_hook_intercept_sym_name_callback, %function
srx_inline_hook_intercept_sym_name_callback:
    mov x7, x30
    b {sym_name_cb_impl}
"#,
    instr_impl = sym srx_inline_hook_intercept_instr_addr_impl,
    func_impl = sym srx_inline_hook_intercept_func_addr_impl,
    sym_impl = sym srx_inline_hook_intercept_sym_addr_impl,
    sym_name_impl = sym srx_inline_hook_intercept_sym_name_impl,
    sym_name_cb_impl = sym srx_inline_hook_intercept_sym_name_callback_impl,
);

unsafe extern "C" fn srx_inline_hook_intercept_sym_name_impl(
    lib_name: *const c_char,
    sym_name: *const c_char,
    pre: *mut c_void,
    data: *mut c_void,
    flags: u32,
    caller_addr: *mut c_void,
) -> *mut c_void {
    if let Err(e) = intercept_precheck_name(lib_name, sym_name, pre, flags) {
        tls_errno::set(e);
        return ptr::null_mut();
    }
    let Some(lib) = (unsafe { cstr_from_ptr_no_libc(lib_name) }) else {
        tls_errno::set(Errno::InvalidArg);
        return ptr::null_mut();
    };
    let Some(sym) = (unsafe { cstr_from_ptr_no_libc(sym_name) }) else {
        tls_errno::set(Errno::InvalidArg);
        return ptr::null_mut();
    };
    let Ok(lib_owned) = sanitize_name_arg(lib) else {
        tls_errno::set(Errno::InvalidArg);
        return ptr::null_mut();
    };
    let Ok(sym_owned) = sanitize_name_arg(sym) else {
        tls_errno::set(Errno::InvalidArg);
        return ptr::null_mut();
    };
    let pre_fn: Interceptor = unsafe { mem::transmute(pre) };
    let r = unsafe {
        api::intercept_sym_name_with_caller_addr(
            lib_owned.as_c_str(),
            sym_owned.as_c_str(),
            pre_fn,
            data,
            flags,
            caller_addr as usize,
        )
    };
    stub_or_null(r)
}

unsafe extern "C" fn srx_inline_hook_intercept_sym_name_callback_impl(
    lib_name: *const c_char,
    sym_name: *const c_char,
    pre: *mut c_void,
    data: *mut c_void,
    flags: u32,
    hooked: *mut c_void,
    hooked_arg: *mut c_void,
    caller_addr: *mut c_void,
) -> *mut c_void {
    if let Err(e) = intercept_precheck_name(lib_name, sym_name, pre, flags) {
        tls_errno::set(e);
        return ptr::null_mut();
    }
    let Some(lib) = (unsafe { cstr_from_ptr_no_libc(lib_name) }) else {
        tls_errno::set(Errno::InvalidArg);
        return ptr::null_mut();
    };
    let Some(sym) = (unsafe { cstr_from_ptr_no_libc(sym_name) }) else {
        tls_errno::set(Errno::InvalidArg);
        return ptr::null_mut();
    };
    let Ok(lib_owned) = sanitize_name_arg(lib) else {
        tls_errno::set(Errno::InvalidArg);
        return ptr::null_mut();
    };
    let Ok(sym_owned) = sanitize_name_arg(sym) else {
        tls_errno::set(Errno::InvalidArg);
        return ptr::null_mut();
    };
    let pre_fn: Interceptor = unsafe { mem::transmute(pre) };
    let hooked_fn = if hooked.is_null() {
        None
    } else {
        Some(unsafe { mem::transmute::<*mut c_void, api::InterceptedCallback>(hooked) })
    };
    let r = unsafe {
        api::intercept_sym_name_callback_with_caller_addr(
            lib_owned.as_c_str(),
            sym_owned.as_c_str(),
            pre_fn,
            data,
            api::HookOptions {
                flags,
                callback: hooked_fn,
                callback_arg: hooked_arg,
                caller_addr: caller_addr as usize,
            },
        )
    };
    stub_or_null(r)
}

// unintercept 检查序：NULL → InvalidArg → Disabled → init_err → api::unintercept
unsafe extern "C" fn srx_inline_hook_unintercept_impl(
    stub: *mut c_void,
    caller_addr: *mut c_void,
) -> c_int {
    if stub.is_null() {
        tls_errno::set(Errno::InvalidArg);
        return -1;
    }
    if api::is_disabled() {
        tls_errno::set(Errno::Disabled);
        return -1;
    }
    let ie = api::get_init_errno();
    if ie != Errno::Ok {
        tls_errno::set(ie);
        return -1;
    }
    let s = HookStub { handle: stub };
    match unsafe { api::unintercept_with_caller_addr(s, caller_addr as usize) } {
        Ok(()) => {
            tls_errno::set(Errno::Ok);
            0
        }
        Err(e) => {
            tls_errno::set(e);
            -1
        }
    }
}

#[cfg(target_arch = "x86_64")]
global_asm!(
    r#"
.hidden {impl_sym}
.globl srx_inline_hook_unintercept
.type srx_inline_hook_unintercept,@function
srx_inline_hook_unintercept:
    mov rsi, [rsp]
    jmp {impl_sym}
"#,
    impl_sym = sym srx_inline_hook_unintercept_impl,
);

#[cfg(target_arch = "aarch64")]
global_asm!(
    r#"
.hidden {impl_sym}
.globl srx_inline_hook_unintercept
.balign 4
.type srx_inline_hook_unintercept, %function
srx_inline_hook_unintercept:
    mov x1, x30
    b {impl_sym}
"#,
    impl_sym = sym srx_inline_hook_unintercept_impl,
);
