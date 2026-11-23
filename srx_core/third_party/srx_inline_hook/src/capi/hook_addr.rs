use super::prelude::*;

// hook_func_addr：orig_addr 可为 NULL；返回 stub（即 target 地址）或 NULL
unsafe extern "C" fn srx_inline_hook_hook_func_addr_impl(
    func_addr: *mut c_void,
    new_addr: *mut c_void,
    orig_addr: *mut *mut c_void,
    caller_addr: *mut c_void,
) -> *mut c_void {
    // SAFETY: func_addr / new_addr 为本进程有效代码地址；orig_addr 为 NULL 或可写槽
    let r = unsafe {
        api::hook_with_orig_with_caller_addr(
            func_addr,
            new_addr,
            orig_addr as *mut *const c_void,
            caller_addr as usize,
        )
    };
    stub_or_null(r)
}

unsafe extern "C" fn srx_inline_hook_hook_sym_addr_impl(
    sym_addr: *mut c_void,
    new_addr: *mut c_void,
    orig_addr: *mut *mut c_void,
    caller_addr: *mut c_void,
) -> *mut c_void {
    // SAFETY: 同 hook_func_addr
    let r = unsafe {
        api::hook_sym_addr_with_caller_addr(
            sym_addr,
            new_addr,
            orig_addr as *mut *const c_void,
            caller_addr as usize,
        )
    };
    stub_or_null(r)
}

// _2 版本：固定 4 参签名 + flags 校验；MULTI 位按 mode dispatch
unsafe fn hook_func_addr_2_impl(
    func_addr: *mut c_void,
    new_addr: *mut c_void,
    orig_addr: *mut *mut c_void,
    flags: u32,
    record_lib_name: *const c_char,
    record_sym_name: *const c_char,
    caller_addr: usize,
) -> *mut c_void {
    if let Err(e) = api::check_hook_flags(flags) {
        tls_errno::set(e);
        return ptr::null_mut();
    }
    let (record_lib_name, record_sym_name) = if flags & 8 != 0 {
        match unsafe { parse_record_names(INTERCEPT_FLAG_RECORD, record_lib_name, record_sym_name) }
        {
            Ok(v) => v,
            Err(e) => {
                tls_errno::set(e);
                return ptr::null_mut();
            }
        }
    } else {
        (None, None)
    };
    let r = unsafe {
        api::hook_with_orig_2_with_names_and_caller_addr(
            func_addr,
            new_addr,
            orig_addr as *mut *const c_void,
            flags,
            record_lib_name,
            record_sym_name,
            caller_addr,
        )
    };
    stub_or_null(r)
}

unsafe fn hook_sym_addr_2_impl(
    sym_addr: *mut c_void,
    new_addr: *mut c_void,
    orig_addr: *mut *mut c_void,
    flags: u32,
    record_lib_name: *const c_char,
    record_sym_name: *const c_char,
    caller_addr: usize,
) -> *mut c_void {
    if let Err(e) = api::check_hook_flags(flags) {
        tls_errno::set(e);
        return ptr::null_mut();
    }
    let (record_lib_name, record_sym_name) = if flags & 8 != 0 {
        match unsafe { parse_record_names(INTERCEPT_FLAG_RECORD, record_lib_name, record_sym_name) }
        {
            Ok(v) => v,
            Err(e) => {
                tls_errno::set(e);
                return ptr::null_mut();
            }
        }
    } else {
        (None, None)
    };
    let r = unsafe {
        api::hook_sym_addr_2_with_names_and_caller_addr(
            sym_addr,
            new_addr,
            orig_addr as *mut *const c_void,
            flags,
            record_lib_name,
            record_sym_name,
            caller_addr,
        )
    };
    stub_or_null(r)
}

#[unsafe(no_mangle)]
unsafe extern "C" fn srx_inline_hook_hook_func_addr_2_impl(
    func_addr: *mut c_void,
    new_addr: *mut c_void,
    orig_addr: *mut *mut c_void,
    flags: u32,
    record_lib_name: *const c_char,
    record_sym_name: *const c_char,
    caller_addr: *mut c_void,
) -> *mut c_void {
    unsafe {
        hook_func_addr_2_impl(
            func_addr,
            new_addr,
            orig_addr,
            flags,
            record_lib_name,
            record_sym_name,
            caller_addr as usize,
        )
    }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn srx_inline_hook_hook_sym_addr_2_impl(
    sym_addr: *mut c_void,
    new_addr: *mut c_void,
    orig_addr: *mut *mut c_void,
    flags: u32,
    record_lib_name: *const c_char,
    record_sym_name: *const c_char,
    caller_addr: *mut c_void,
) -> *mut c_void {
    unsafe {
        hook_sym_addr_2_impl(
            sym_addr,
            new_addr,
            orig_addr,
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
.hidden {func_base_impl}
.hidden {sym_base_impl}
.hidden {func_impl}
.hidden {sym_impl}
.globl srx_inline_hook_hook_func_addr
.type srx_inline_hook_hook_func_addr,@function
srx_inline_hook_hook_func_addr:
    mov rcx, [rsp]
    jmp {func_base_impl}

.globl srx_inline_hook_hook_sym_addr
.type srx_inline_hook_hook_sym_addr,@function
srx_inline_hook_hook_sym_addr:
    mov rcx, [rsp]
    jmp {sym_base_impl}

.globl srx_inline_hook_hook_func_addr_2
.type srx_inline_hook_hook_func_addr_2,@function
srx_inline_hook_hook_func_addr_2:
    mov r10, [rsp]
    test ecx, 8
    jne 1f
    xor r8d, r8d
    xor r9d, r9d
1:
    push r10
    call {func_impl}
    add rsp, 8
    ret

.globl srx_inline_hook_hook_sym_addr_2
.type srx_inline_hook_hook_sym_addr_2,@function
srx_inline_hook_hook_sym_addr_2:
    mov r10, [rsp]
    test ecx, 8
    jne 1f
    xor r8d, r8d
    xor r9d, r9d
1:
    push r10
    call {sym_impl}
    add rsp, 8
    ret
"#,
    func_base_impl = sym srx_inline_hook_hook_func_addr_impl,
    sym_base_impl = sym srx_inline_hook_hook_sym_addr_impl,
    func_impl = sym srx_inline_hook_hook_func_addr_2_impl,
    sym_impl = sym srx_inline_hook_hook_sym_addr_2_impl,
);

#[cfg(target_arch = "aarch64")]
global_asm!(
    r#"
.hidden {func_base_impl}
.hidden {sym_base_impl}
.hidden {func_impl}
.hidden {sym_impl}
.globl srx_inline_hook_hook_func_addr
.balign 4
.type srx_inline_hook_hook_func_addr, %function
srx_inline_hook_hook_func_addr:
    mov x3, x30
    b {func_base_impl}

.globl srx_inline_hook_hook_sym_addr
.balign 4
.type srx_inline_hook_hook_sym_addr, %function
srx_inline_hook_hook_sym_addr:
    mov x3, x30
    b {sym_base_impl}

.globl srx_inline_hook_hook_func_addr_2
.balign 4
.type srx_inline_hook_hook_func_addr_2, %function
srx_inline_hook_hook_func_addr_2:
    mov x6, x30
    tbz w3, #3, 1f
    b {func_impl}
1:
    mov x4, xzr
    mov x5, xzr
    b {func_impl}

.globl srx_inline_hook_hook_sym_addr_2
.balign 4
.type srx_inline_hook_hook_sym_addr_2, %function
srx_inline_hook_hook_sym_addr_2:
    mov x6, x30
    tbz w3, #3, 1f
    b {sym_impl}
1:
    mov x4, xzr
    mov x5, xzr
    b {sym_impl}
"#,
    func_base_impl = sym srx_inline_hook_hook_func_addr_impl,
    sym_base_impl = sym srx_inline_hook_hook_sym_addr_impl,
    func_impl = sym srx_inline_hook_hook_func_addr_2_impl,
    sym_impl = sym srx_inline_hook_hook_sym_addr_2_impl,
);
