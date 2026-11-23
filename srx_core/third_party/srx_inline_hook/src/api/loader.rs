use super::prelude::*;

#[repr(C)]
struct DlHandle {
    raw: *mut c_void,
    lib_name: CString,
}

unsafe fn dl_handle_raw(handle: *mut c_void) -> Option<*mut c_void> {
    if handle.is_null() {
        return None;
    }
    // SAFETY: handle 来自 sh_dlopen 分配的 DlHandle
    let raw = unsafe { (*(handle as *mut DlHandle)).raw };
    (!raw.is_null()).then_some(raw)
}

unsafe fn dl_handle_lib_name<'a>(handle: *mut c_void) -> Option<&'a CStr> {
    if handle.is_null() {
        return None;
    }
    // SAFETY: handle 来自 sh_dlopen 分配的 DlHandle；CString 生命周期由句柄持有
    Some(unsafe { (*(handle as *mut DlHandle)).lib_name.as_c_str() })
}

// dlopen / dlclose / dlsym 裹 bytesig::guard 捕获 crash；内部返回自有 opaque handle；
// 空串 lib_name / sym_name 返 NULL，避免 bionic 在极端输入上的未定义行为

pub unsafe fn sh_dlopen(lib_name: &CStr) -> *mut c_void {
    if lib_name.to_bytes().is_empty() {
        return ptr::null_mut();
    }
    let lib_ptr = lib_name.as_ptr();
    let raw = if runtime::get_init_errno() != Errno::Ok {
        // SAFETY: 未 init 时绕过 guard 直接走 bionic linker
        unsafe { libc::dlopen(lib_ptr, libc::RTLD_NOW) }
    } else {
        // SAFETY: guard 捕获 bionic 极端输入下的 SIGSEGV / SIGBUS
        match unsafe { bytesig::guard(|| libc::dlopen(lib_ptr, libc::RTLD_NOW)) } {
            Ok(h) => h,
            Err(_) => ptr::null_mut(),
        }
    };
    if raw.is_null() && !linker::has_loaded_library(lib_name) {
        return ptr::null_mut();
    }
    let Ok(name) = CString::new(lib_name.to_bytes()) else {
        if !raw.is_null() {
            // SAFETY: raw 来自成功 dlopen，失败时立即释放
            unsafe {
                libc::dlclose(raw);
            }
        }
        return ptr::null_mut();
    };
    Box::into_raw(Box::new(DlHandle {
        raw,
        lib_name: name,
    })) as *mut c_void
}

pub unsafe fn sh_dlclose(handle: *mut c_void) {
    if handle.is_null() {
        return;
    }
    // SAFETY: handle 来自 sh_dlopen 分配的 DlHandle
    let boxed = unsafe { Box::from_raw(handle as *mut DlHandle) };
    let raw = boxed.raw;
    if raw.is_null() {
        return;
    }
    if runtime::get_init_errno() != Errno::Ok {
        // SAFETY: 未 init 时绕过 guard
        unsafe {
            libc::dlclose(raw);
        }
        return;
    }
    // SAFETY: raw 来自先前 dlopen 的返回；guard 捕获 crash
    let _ = unsafe { bytesig::guard(|| libc::dlclose(raw)) };
}

pub unsafe fn sh_dlsym_dynsym(handle: *mut c_void, sym_name: &CStr) -> *mut c_void {
    if handle.is_null() || sym_name.to_bytes().is_empty() {
        return ptr::null_mut();
    }
    let sym_ptr = sym_name.as_ptr();
    // SAFETY: handle 来自 sh_dlopen 分配的 DlHandle
    if let Some(raw) = unsafe { dl_handle_raw(handle) } {
        if runtime::get_init_errno() != Errno::Ok {
            // SAFETY: 未 init 分支
            return unsafe { libc::dlsym(raw, sym_ptr) };
        }
        // SAFETY: handle 有效 + guard 捕获 crash
        return match unsafe { bytesig::guard(|| libc::dlsym(raw, sym_ptr)) } {
            Ok(p) => p,
            Err(_) => ptr::null_mut(),
        };
    }
    let Some(lib_name) = (unsafe { dl_handle_lib_name(handle) }) else {
        return ptr::null_mut();
    };
    match linker::find_loaded_symbol(lib_name, sym_name) {
        linker::LoadedSymbolLookup::Found(p) => p,
        _ => ptr::null_mut(),
    }
}

pub unsafe fn sh_dlsym(handle: *mut c_void, sym_name: &CStr) -> *mut c_void {
    let dynsym = unsafe { sh_dlsym_dynsym(handle, sym_name) };
    if !dynsym.is_null() || runtime::get_init_errno() != Errno::Ok {
        return dynsym;
    }
    unsafe { sh_dlsym_symtab(handle, sym_name) }
}

pub unsafe fn sh_dlsym_symtab(handle: *mut c_void, sym_name: &CStr) -> *mut c_void {
    if handle.is_null() || sym_name.to_bytes().is_empty() {
        return ptr::null_mut();
    }
    if runtime::get_init_errno() != Errno::Ok {
        return ptr::null_mut();
    }
    // SAFETY: handle 来自 sh_dlopen 分配的 DlHandle
    let Some(lib_name) = (unsafe { dl_handle_lib_name(handle) }) else {
        return ptr::null_mut();
    };
    // SAFETY: 只读已加载 so 的磁盘 ELF；guard 捕获极端 crash
    match unsafe { bytesig::guard(|| linker::find_loaded_symbol_by_symtab(lib_name, sym_name)) } {
        Ok(Some(p)) => p,
        _ => ptr::null_mut(),
    }
}

// 全局禁用开关；开启后新 hook 请求一律返 Disabled，已存活 hook 不受影响
