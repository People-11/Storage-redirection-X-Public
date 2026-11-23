use std::process;

use super::prelude::*;

unsafe extern "C" fn srx_inline_hook_get_prev_func_impl(
    func: *mut c_void,
    return_address: *mut c_void,
) -> *mut c_void {
    if func.is_null() {
        return ptr::null_mut();
    }
    if !shared_stack::has_frame() {
        process::abort();
    }
    if let Ok(body) = stub::get(func as usize).ok_or(Errno::UnhookNotFound) {
        if matches!(body.mode, SwitchMode::Shared | SwitchMode::Intercept) {
            shared_stack::ensure_top(body.target, return_address);
        }
    } else if let Some((_id, body)) = stub::find_by_new_addr(func as *const c_void, None)
        && matches!(body.mode, SwitchMode::Shared | SwitchMode::Intercept)
    {
        shared_stack::ensure_top(body.target, return_address);
    }
    match api::prev_func_by_addr(func as *const c_void) {
        Ok(p) => p as *mut c_void,
        Err(_) => ptr::null_mut(),
    }
}

#[cfg(target_arch = "x86_64")]
global_asm!(
    r#"
.hidden {impl_sym}
.globl srx_inline_hook_get_prev_func
.type srx_inline_hook_get_prev_func,@function
srx_inline_hook_get_prev_func:
    mov rsi, [rsp]
    jmp {impl_sym}
"#,
    impl_sym = sym srx_inline_hook_get_prev_func_impl,
);

#[cfg(target_arch = "aarch64")]
global_asm!(
    r#"
.hidden {impl_sym}
.globl srx_inline_hook_get_prev_func
.balign 4
.type srx_inline_hook_get_prev_func, %function
srx_inline_hook_get_prev_func:
    mov x1, x30
    b {impl_sym}
"#,
    impl_sym = sym srx_inline_hook_get_prev_func_impl,
);

// items bit 位输入；未知位截断，空 items / !recordable / fd < 0 时静默返回
#[unsafe(no_mangle)]
pub extern "C" fn srx_inline_hook_dump_records(fd: c_int, item_flags: u32) {
    if !api::is_recordable() || fd < 0 {
        return;
    }
    let items = RecordItems::from_bits_truncate(item_flags);
    if items.is_empty() {
        return;
    }
    let _ = api::dump_records_to_fd(fd, items);
}

// 分配 NUL 终止 C 字符串；用 libc::malloc 让 C 客户端可直接 free() 释放
// !recordable / item_flags 有效位为 0 → NULL
#[unsafe(no_mangle)]
pub extern "C" fn srx_inline_hook_get_records(item_flags: u32) -> *mut c_char {
    if !api::is_recordable() {
        return ptr::null_mut();
    }
    let items = RecordItems::from_bits_truncate(item_flags);
    if items.is_empty() {
        return ptr::null_mut();
    }
    let text = api::dump_records_with_items(items);
    let bytes = text.as_bytes();
    // 文本内含 NUL 字节时 C 字符串语义未定义；直接失败返 NULL
    if bytes.contains(&0) {
        return ptr::null_mut();
    }
    // SAFETY: size = len + 1 容纳 NUL；libc::malloc 失败直接短路
    let size = bytes.len() + 1;
    let buf = unsafe { libc::malloc(size) } as *mut u8;
    if buf.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: buf 刚分配 size 字节，拷入 bytes 与末尾 NUL
    unsafe {
        ptr::copy_nonoverlapping(bytes.as_ptr(), buf, bytes.len());
        *buf.add(bytes.len()) = 0;
    }
    buf as *mut c_char
}

// dlopen / dlclose / dlsym 包裹 bytesig::guard 捕获崩溃
// dlsym_symtab 按句柄库名回查已加载 so 的 .symtab/.strtab

#[unsafe(no_mangle)]
pub unsafe extern "C" fn srx_inline_hook_dlopen(lib_name: *const c_char) -> *mut c_void {
    if lib_name.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: lib_name NUL 终止；手扫避免被 hook libc strlen 反噬
    let Some(lib) = (unsafe { cstr_from_ptr_no_libc(lib_name) }) else {
        return ptr::null_mut();
    };
    let Ok(lib_owned) = sanitize_name_arg(lib) else {
        return ptr::null_mut();
    };
    // SAFETY: 内部裹 guard
    unsafe { api::sh_dlopen(lib_owned.as_c_str()) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn srx_inline_hook_dlclose(handle: *mut c_void) {
    // SAFETY: handle 来自先前 _dlopen 返回
    unsafe { api::sh_dlclose(handle) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn srx_inline_hook_dlsym(
    handle: *mut c_void,
    sym_name: *const c_char,
) -> *mut c_void {
    if sym_name.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: sym_name NUL 终止；手扫避免被 hook libc strlen 反噬
    let Some(sym) = (unsafe { cstr_from_ptr_no_libc(sym_name) }) else {
        return ptr::null_mut();
    };
    let Ok(sym_owned) = sanitize_name_arg(sym) else {
        return ptr::null_mut();
    };
    // SAFETY: handle 由调用方保证
    unsafe { api::sh_dlsym(handle, sym_owned.as_c_str()) }
}

// dynsym 变体：仅走 bionic dlsym，不做 symtab 回退
#[unsafe(no_mangle)]
pub unsafe extern "C" fn srx_inline_hook_dlsym_dynsym(
    handle: *mut c_void,
    sym_name: *const c_char,
) -> *mut c_void {
    if sym_name.is_null() {
        return ptr::null_mut();
    }
    let Some(sym) = (unsafe { cstr_from_ptr_no_libc(sym_name) }) else {
        return ptr::null_mut();
    };
    let Ok(sym_owned) = sanitize_name_arg(sym) else {
        return ptr::null_mut();
    };
    unsafe { api::sh_dlsym_dynsym(handle, sym_owned.as_c_str()) }
}

// symtab 变体：按已加载 so 的磁盘 ELF .symtab/.strtab 查符号
#[unsafe(no_mangle)]
pub unsafe extern "C" fn srx_inline_hook_dlsym_symtab(
    handle: *mut c_void,
    sym_name: *const c_char,
) -> *mut c_void {
    if sym_name.is_null() {
        return ptr::null_mut();
    }
    let Some(sym) = (unsafe { cstr_from_ptr_no_libc(sym_name) }) else {
        return ptr::null_mut();
    };
    let Ok(sym_owned) = sanitize_name_arg(sym) else {
        return ptr::null_mut();
    };
    unsafe { api::sh_dlsym_symtab(handle, sym_owned.as_c_str()) }
}
