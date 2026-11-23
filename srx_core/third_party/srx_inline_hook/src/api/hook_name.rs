use super::prelude::*;

unsafe fn hook_sym_name_internal(
    lib_name: &CStr,
    sym_name: &CStr,
    replacement: *const c_void,
    orig_addr: *mut *const c_void,
    mode: SwitchMode,
    options: HookOptions<HookedCallback>,
) -> (Result<HookStub, Errno>, *mut c_void) {
    let HookOptions {
        flags, caller_addr, ..
    } = options;
    tls_errno::reset();
    // SAFETY: 参数存活性由调用方保证
    let sym = match unsafe { resolve_loaded_sym(lib_name, sym_name, replacement) } {
        Ok(s) => s,
        Err(Errno::Pending) => {
            let mode = match mode {
                SwitchMode::Unique => HookMode::Unique,
                SwitchMode::Shared | SwitchMode::Intercept => HookMode::Shared,
                SwitchMode::Multi => HookMode::Multi,
            };
            let result =
                pending::create_hook(lib_name, sym_name, replacement, orig_addr, mode, options);
            let (final_errno, stub) = match &result {
                Ok(stub) => (Errno::Pending, stub.handle as usize),
                Err(e) => (*e, 0),
            };
            recorder::record_with_meta(
                RecordOp::HookSymName,
                0,
                replacement as usize,
                final_errno,
                None,
                RecordMeta {
                    lib_name: Some(lib_name),
                    sym_name: Some(sym_name),
                    caller_addr: (caller_addr != 0).then_some(caller_addr),
                    stub,
                    flags: Some(flags),
                    ..RecordMeta::default()
                },
            );
            tls_errno::set(final_errno);
            return (result, ptr::null_mut());
        }
        Err(e) => {
            recorder::record_with_meta(
                RecordOp::HookSymName,
                0,
                replacement as usize,
                e,
                None,
                RecordMeta {
                    lib_name: Some(lib_name),
                    sym_name: Some(sym_name),
                    flags: Some(flags),
                    ..RecordMeta::default()
                },
            );
            tls_errno::set(e);
            return (Err(e), ptr::null_mut());
        }
    };
    remember_resolved_symbol(lib_name, sym_name, sym);
    // SAFETY: sym 为已加载代码地址；走 inline 主路径
    let result = unsafe { hook_inline_inner(sym, replacement, orig_addr, mode) };
    let (final_errno, backup, stub) = match &result {
        Ok((stub, consumed)) => (Errno::Ok, Some(*consumed), stub.handle as usize),
        Err(e) => (*e, None, 0),
    };
    match &result {
        Ok((stub, _)) => sh_info!(
            target: "srx_inline_hook",
            "hook_sym_name ok sym=0x{:x} replacement=0x{:x} stub=0x{:x}",
            sym as usize,
            replacement as usize,
            stub.handle as usize,
        ),
        Err(e) => sh_warn!(
            target: "srx_inline_hook",
            "hook_sym_name fail sym=0x{:x} replacement=0x{:x} errno={}({})",
            sym as usize,
            replacement as usize,
            *e as i32,
            e.message(),
        ),
    }
    recorder::record_with_meta(
        RecordOp::HookSymName,
        sym as usize,
        replacement as usize,
        final_errno,
        backup,
        RecordMeta {
            lib_name: Some(lib_name),
            sym_name: Some(sym_name),
            stub,
            flags: Some(flags),
            ..RecordMeta::default()
        },
    );
    tls_errno::set(final_errno);
    (result.map(|(stub, _)| stub), sym)
}

// 按 so 名 + 符号名 hook；RTLD_NOW 加载后 handle 由进程持有

pub unsafe fn hook_sym_name(
    lib_name: &CStr,
    sym_name: &CStr,
    replacement: *const c_void,
    orig_addr: *mut *const c_void,
) -> Result<HookStub, Errno> {
    unsafe { hook_sym_name_with_caller_addr(lib_name, sym_name, replacement, orig_addr, 0) }
}

pub(crate) unsafe fn hook_sym_name_with_caller_addr(
    lib_name: &CStr,
    sym_name: &CStr,
    replacement: *const c_void,
    orig_addr: *mut *const c_void,
    caller_addr: usize,
) -> Result<HookStub, Errno> {
    // SAFETY: 参数存活性由调用方保证
    unsafe {
        hook_sym_name_internal(
            lib_name,
            sym_name,
            replacement,
            orig_addr,
            SwitchMode::Unique,
            HookOptions {
                flags: 0,
                callback: None,
                callback_arg: ptr::null_mut(),
                caller_addr,
            },
        )
    }
    .0
}

// hook 完成回调，同步触发一次，携带最终 errno 与各地址
pub type HookedCallback = extern "C" fn(
    error: i32,
    lib_name: *const c_char,
    sym_name: *const c_char,
    sym_addr: *const c_void,
    new_addr: *const c_void,
    orig_addr: *const c_void,
    arg: *mut c_void,
);

// hook_sym_name 后置回调变体；成功 / 失败均会调用一次 hooked
pub unsafe fn hook_sym_name_callback(
    lib_name: &CStr,
    sym_name: &CStr,
    replacement: *const c_void,
    orig_addr: *mut *const c_void,
    hooked: Option<HookedCallback>,
    hooked_arg: *mut c_void,
) -> Result<HookStub, Errno> {
    unsafe {
        hook_sym_name_callback_with_caller_addr(
            lib_name,
            sym_name,
            replacement,
            orig_addr,
            hooked,
            hooked_arg,
            0,
        )
    }
}

pub(crate) unsafe fn hook_sym_name_callback_with_caller_addr(
    lib_name: &CStr,
    sym_name: &CStr,
    replacement: *const c_void,
    orig_addr: *mut *const c_void,
    hooked: Option<HookedCallback>,
    hooked_arg: *mut c_void,
    caller_addr: usize,
) -> Result<HookStub, Errno> {
    // SAFETY: 参数存活性同 hook_sym_name
    let (result, sym) = unsafe {
        hook_sym_name_internal(
            lib_name,
            sym_name,
            replacement,
            orig_addr,
            SwitchMode::Unique,
            HookOptions {
                flags: 0,
                callback: hooked,
                callback_arg: hooked_arg,
                caller_addr,
            },
        )
    };
    let is_pending_result = result
        .as_ref()
        .ok()
        .is_some_and(|stub| pending::is_pending_handle(stub.handle));
    if !is_pending_result && let Some(cb) = hooked {
        let err_code = match &result {
            Ok(_) => Errno::Ok as i32,
            Err(e) => *e as i32,
        };
        let sym_addr_ptr = if sym.is_null() {
            ptr::null()
        } else {
            sym as *const c_void
        };
        let orig_ptr = orig_addr as *const c_void;
        cb(
            err_code,
            lib_name.as_ptr(),
            sym_name.as_ptr(),
            sym_addr_ptr,
            replacement,
            orig_ptr,
            hooked_arg,
        );
    }
    result
}

// flag bits: SHARED=1 / UNIQUE=2 / MULTI=4 / RECORD=8；三种模式均合法，RECORD 忽略

pub unsafe fn hook_sym_name_2(
    lib_name: &CStr,
    sym_name: &CStr,
    replacement: *const c_void,
    orig_addr: *mut *const c_void,
    flags: u32,
) -> Result<HookStub, Errno> {
    unsafe {
        hook_sym_name_2_with_caller_addr(lib_name, sym_name, replacement, orig_addr, flags, 0)
    }
}

pub(crate) unsafe fn hook_sym_name_2_with_caller_addr(
    lib_name: &CStr,
    sym_name: &CStr,
    replacement: *const c_void,
    orig_addr: *mut *const c_void,
    flags: u32,
    caller_addr: usize,
) -> Result<HookStub, Errno> {
    if let Err(e) = check_hook_flags(flags) {
        tls_errno::set(e);
        return Err(e);
    }
    let mode = flags_to_mode(flags);
    if let Err(e) = ensure_multi_orig_addr(mode, orig_addr) {
        tls_errno::set(e);
        return Err(e);
    }
    // SAFETY: 参数存活性与主路径一致
    unsafe {
        hook_sym_name_internal(
            lib_name,
            sym_name,
            replacement,
            orig_addr,
            mode,
            HookOptions {
                flags,
                callback: None,
                callback_arg: ptr::null_mut(),
                caller_addr,
            },
        )
    }
    .0
}

pub unsafe fn hook_sym_name_callback_2(
    lib_name: &CStr,
    sym_name: &CStr,
    replacement: *const c_void,
    orig_addr: *mut *const c_void,
    flags: u32,
    hooked: Option<HookedCallback>,
    hooked_arg: *mut c_void,
) -> Result<HookStub, Errno> {
    unsafe {
        hook_sym_name_callback_2_with_caller_addr(
            lib_name,
            sym_name,
            replacement,
            orig_addr,
            HookOptions {
                flags,
                callback: hooked,
                callback_arg: hooked_arg,
                caller_addr: 0,
            },
        )
    }
}

pub(crate) unsafe fn hook_sym_name_callback_2_with_caller_addr(
    lib_name: &CStr,
    sym_name: &CStr,
    replacement: *const c_void,
    orig_addr: *mut *const c_void,
    options: HookOptions<HookedCallback>,
) -> Result<HookStub, Errno> {
    let HookOptions {
        flags,
        callback: hooked,
        callback_arg: hooked_arg,
        ..
    } = options;
    if let Err(e) = check_hook_flags(flags) {
        tls_errno::set(e);
        return Err(e);
    }
    let mode = flags_to_mode(flags);
    if let Err(e) = ensure_multi_orig_addr(mode, orig_addr) {
        tls_errno::set(e);
        return Err(e);
    }
    // SAFETY: 同 hook_sym_name_callback
    let (result, sym) = unsafe {
        hook_sym_name_internal(lib_name, sym_name, replacement, orig_addr, mode, options)
    };
    let is_pending_result = result
        .as_ref()
        .ok()
        .is_some_and(|stub| pending::is_pending_handle(stub.handle));
    if !is_pending_result && let Some(cb) = hooked {
        let err_code = match &result {
            Ok(_) => Errno::Ok as i32,
            Err(e) => *e as i32,
        };
        let sym_addr_ptr = if sym.is_null() {
            ptr::null()
        } else {
            sym as *const c_void
        };
        let orig_ptr = orig_addr as *const c_void;
        cb(
            err_code,
            lib_name.as_ptr(),
            sym_name.as_ptr(),
            sym_addr_ptr,
            replacement,
            orig_ptr,
            hooked_arg,
        );
    }
    result
}
