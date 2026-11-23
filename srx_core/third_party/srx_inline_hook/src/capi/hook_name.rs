use super::prelude::*;

unsafe extern "C" fn srx_inline_hook_hook_sym_name_impl(
    lib_name: *const c_char,
    sym_name: *const c_char,
    new_addr: *mut c_void,
    orig_addr: *mut *mut c_void,
    caller_addr: *mut c_void,
) -> *mut c_void {
    // NULL 前置 → tls_errno = InvalidArg，返 NULL
    if lib_name.is_null() || sym_name.is_null() || new_addr.is_null() {
        tls_errno::set(Errno::InvalidArg);
        return ptr::null_mut();
    }
    // SAFETY: lib_name / sym_name 为 NUL 终止；手扫避免被 hook libc strlen 反噬
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
    // SAFETY: new_addr 有效；orig_addr 为 NULL 或可写槽
    let r = unsafe {
        api::hook_sym_name_with_caller_addr(
            lib_owned.as_c_str(),
            sym_owned.as_c_str(),
            new_addr,
            orig_addr as *mut *const c_void,
            caller_addr as usize,
        )
    };
    stub_or_null(r)
}

unsafe extern "C" fn srx_inline_hook_hook_sym_name_callback_impl(
    lib_name: *const c_char,
    sym_name: *const c_char,
    new_addr: *mut c_void,
    orig_addr: *mut *mut c_void,
    hooked: Option<HookedCallback>,
    hooked_arg: *mut c_void,
    caller_addr: *mut c_void,
) -> *mut c_void {
    if lib_name.is_null() || sym_name.is_null() || new_addr.is_null() {
        tls_errno::set(Errno::InvalidArg);
        return ptr::null_mut();
    }
    // SAFETY: CStr 存活期由调用方保证；手扫避免被 hook libc strlen 反噬
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
    // SAFETY: 同 hook_sym_name；hooked 可空
    let r = unsafe {
        api::hook_sym_name_callback_with_caller_addr(
            lib_owned.as_c_str(),
            sym_owned.as_c_str(),
            new_addr,
            orig_addr as *mut *const c_void,
            hooked,
            hooked_arg,
            caller_addr as usize,
        )
    };
    stub_or_null(r)
}

// 带 flags 的 _2 版本：仅 DEFAULT / UNIQUE / RECORD 合法；
// SHARED / MULTI → ModeConflict(43)；未知高位 → InvalidArg(3)
unsafe extern "C" fn srx_inline_hook_hook_sym_name_2_impl(
    lib_name: *const c_char,
    sym_name: *const c_char,
    new_addr: *mut c_void,
    orig_addr: *mut *mut c_void,
    flags: u32,
    caller_addr: *mut c_void,
) -> *mut c_void {
    if lib_name.is_null() || sym_name.is_null() || new_addr.is_null() {
        tls_errno::set(Errno::InvalidArg);
        return ptr::null_mut();
    }
    // SAFETY: CStr 存活期由调用方保证；手扫避免被 hook libc strlen 反噬
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
    // SAFETY: new_addr 有效；orig_addr 为 NULL 或可写槽
    let r = unsafe {
        api::hook_sym_name_2_with_caller_addr(
            lib_owned.as_c_str(),
            sym_owned.as_c_str(),
            new_addr,
            orig_addr as *mut *const c_void,
            flags,
            caller_addr as usize,
        )
    };
    stub_or_null(r)
}

unsafe extern "C" fn srx_inline_hook_hook_sym_name_callback_2_impl(
    lib_name: *const c_char,
    sym_name: *const c_char,
    new_addr: *mut c_void,
    orig_addr: *mut *mut c_void,
    flags: u32,
    hooked: Option<HookedCallback>,
    hooked_arg: *mut c_void,
    caller_addr: *mut c_void,
) -> *mut c_void {
    if lib_name.is_null() || sym_name.is_null() || new_addr.is_null() {
        tls_errno::set(Errno::InvalidArg);
        return ptr::null_mut();
    }
    // SAFETY: CStr 存活期由调用方保证；手扫避免被 hook libc strlen 反噬
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
    // SAFETY: 同 hook_sym_name_callback
    let r = unsafe {
        api::hook_sym_name_callback_2_with_caller_addr(
            lib_owned.as_c_str(),
            sym_owned.as_c_str(),
            new_addr,
            orig_addr as *mut *const c_void,
            api::HookOptions {
                flags,
                callback: hooked,
                callback_arg: hooked_arg,
                caller_addr: caller_addr as usize,
            },
        )
    };
    stub_or_null(r)
}

unsafe extern "C" fn srx_inline_hook_unhook_impl(
    stub: *mut c_void,
    caller_addr: *mut c_void,
) -> c_int {
    if stub.is_null() {
        tls_errno::set(Errno::InvalidArg);
        return -1;
    }
    let s = HookStub { handle: stub };
    // SAFETY: stub 来自先前 _hook_* 返回值，调用方保留到 unhook 完成
    match unsafe { api::unhook_with_caller_addr(s, caller_addr as usize) } {
        Ok(()) => 0,
        Err(_) => -1,
    }
}

#[cfg(target_arch = "x86_64")]
global_asm!(
    r#"
.hidden {hook_sym_name_impl}
.hidden {hook_sym_name_cb_impl}
.hidden {hook_sym_name_2_impl}
.hidden {hook_sym_name_cb_2_impl}
.hidden {impl_sym}
.globl srx_inline_hook_hook_sym_name
.type srx_inline_hook_hook_sym_name,@function
srx_inline_hook_hook_sym_name:
    mov r8, [rsp]
    jmp {hook_sym_name_impl}

.globl srx_inline_hook_hook_sym_name_callback
.type srx_inline_hook_hook_sym_name_callback,@function
srx_inline_hook_hook_sym_name_callback:
    mov r10, [rsp]
    sub rsp, 8
    mov [rsp], r10
    call {hook_sym_name_cb_impl}
    add rsp, 8
    ret

.globl srx_inline_hook_hook_sym_name_2
.type srx_inline_hook_hook_sym_name_2,@function
srx_inline_hook_hook_sym_name_2:
    mov r9, [rsp]
    jmp {hook_sym_name_2_impl}

.globl srx_inline_hook_hook_sym_name_callback_2
.type srx_inline_hook_hook_sym_name_callback_2,@function
srx_inline_hook_hook_sym_name_callback_2:
    mov r10, [rsp]
    mov r11, [rsp + 8]
    sub rsp, 24
    mov [rsp], r11
    mov [rsp + 8], r10
    call {hook_sym_name_cb_2_impl}
    add rsp, 24
    ret

.globl srx_inline_hook_unhook
.type srx_inline_hook_unhook,@function
srx_inline_hook_unhook:
    mov rsi, [rsp]
    jmp {impl_sym}
"#,
    hook_sym_name_impl = sym srx_inline_hook_hook_sym_name_impl,
    hook_sym_name_cb_impl = sym srx_inline_hook_hook_sym_name_callback_impl,
    hook_sym_name_2_impl = sym srx_inline_hook_hook_sym_name_2_impl,
    hook_sym_name_cb_2_impl = sym srx_inline_hook_hook_sym_name_callback_2_impl,
    impl_sym = sym srx_inline_hook_unhook_impl,
);

#[cfg(target_arch = "aarch64")]
global_asm!(
    r#"
.hidden {hook_sym_name_impl}
.hidden {hook_sym_name_cb_impl}
.hidden {hook_sym_name_2_impl}
.hidden {hook_sym_name_cb_2_impl}
.hidden {impl_sym}
.globl srx_inline_hook_hook_sym_name
.balign 4
.type srx_inline_hook_hook_sym_name, %function
srx_inline_hook_hook_sym_name:
    mov x4, x30
    b {hook_sym_name_impl}

.globl srx_inline_hook_hook_sym_name_callback
.balign 4
.type srx_inline_hook_hook_sym_name_callback, %function
srx_inline_hook_hook_sym_name_callback:
    mov x6, x30
    b {hook_sym_name_cb_impl}

.globl srx_inline_hook_hook_sym_name_2
.balign 4
.type srx_inline_hook_hook_sym_name_2, %function
srx_inline_hook_hook_sym_name_2:
    mov x5, x30
    b {hook_sym_name_2_impl}

.globl srx_inline_hook_hook_sym_name_callback_2
.balign 4
.type srx_inline_hook_hook_sym_name_callback_2, %function
srx_inline_hook_hook_sym_name_callback_2:
    mov x7, x30
    b {hook_sym_name_cb_2_impl}

.globl srx_inline_hook_unhook
.balign 4
.type srx_inline_hook_unhook, %function
srx_inline_hook_unhook:
    mov x1, x30
    b {impl_sym}
"#,
    hook_sym_name_impl = sym srx_inline_hook_hook_sym_name_impl,
    hook_sym_name_cb_impl = sym srx_inline_hook_hook_sym_name_callback_impl,
    hook_sym_name_2_impl = sym srx_inline_hook_hook_sym_name_2_impl,
    hook_sym_name_cb_2_impl = sym srx_inline_hook_hook_sym_name_callback_2_impl,
    impl_sym = sym srx_inline_hook_unhook_impl,
);
