use super::prelude::*;

pub type InterceptedCallback = extern "C" fn(
    error: i32,
    lib_name: *const c_char,
    sym_name: *const c_char,
    sym_addr: *const c_void,
    pre: Interceptor,
    data: *mut c_void,
    arg: *mut c_void,
);

pub unsafe fn intercept_instr_addr(
    instr_addr: *mut c_void,
    pre: Interceptor,
    data: *mut c_void,
    flags: u32,
) -> Result<HookStub, Errno> {
    intercept_instr_addr_with_names(instr_addr, pre, data, flags, None, None)
}

pub(crate) unsafe fn intercept_instr_addr_with_names(
    instr_addr: *mut c_void,
    pre: Interceptor,
    data: *mut c_void,
    flags: u32,
    lib_name: Option<&CStr>,
    sym_name: Option<&CStr>,
) -> Result<HookStub, Errno> {
    unsafe {
        intercept_instr_addr_with_names_and_caller_addr(
            instr_addr, pre, data, flags, lib_name, sym_name, 0,
        )
    }
}

pub(crate) unsafe fn intercept_instr_addr_with_names_and_caller_addr(
    instr_addr: *mut c_void,
    pre: Interceptor,
    data: *mut c_void,
    flags: u32,
    lib_name: Option<&CStr>,
    sym_name: Option<&CStr>,
    caller_addr: usize,
) -> Result<HookStub, Errno> {
    tls_errno::reset();
    if let Err(e) = check_intercept_flags(flags) {
        tls_errno::set(e);
        return Err(e);
    }
    let result = intercept_addr_impl(instr_addr, pre, data, flags);
    let (final_errno, stub) = match &result {
        Ok(stub) => (Errno::Ok, stub.handle as usize),
        Err(e) => (*e, 0),
    };
    recorder::record_with_meta(
        RecordOp::InterceptInstrAddr,
        instr_addr as usize,
        pre as usize,
        final_errno,
        None,
        RecordMeta {
            lib_name,
            sym_name,
            caller_addr: (caller_addr != 0).then_some(caller_addr),
            stub,
            flags: Some(flags),
            ..RecordMeta::default()
        },
    );
    tls_errno::set(final_errno);
    result
}

pub unsafe fn intercept_func_addr(
    func_addr: *mut c_void,
    pre: Interceptor,
    data: *mut c_void,
    flags: u32,
) -> Result<HookStub, Errno> {
    intercept_func_addr_with_names(func_addr, pre, data, flags, None, None)
}

pub(crate) unsafe fn intercept_func_addr_with_names(
    func_addr: *mut c_void,
    pre: Interceptor,
    data: *mut c_void,
    flags: u32,
    lib_name: Option<&CStr>,
    sym_name: Option<&CStr>,
) -> Result<HookStub, Errno> {
    unsafe {
        intercept_func_addr_with_names_and_caller_addr(
            func_addr, pre, data, flags, lib_name, sym_name, 0,
        )
    }
}

pub(crate) unsafe fn intercept_func_addr_with_names_and_caller_addr(
    func_addr: *mut c_void,
    pre: Interceptor,
    data: *mut c_void,
    flags: u32,
    lib_name: Option<&CStr>,
    sym_name: Option<&CStr>,
    caller_addr: usize,
) -> Result<HookStub, Errno> {
    tls_errno::reset();
    if let Err(e) = check_intercept_flags(flags) {
        tls_errno::set(e);
        return Err(e);
    }
    let result = intercept_addr_impl(func_addr, pre, data, flags);
    let (final_errno, stub) = match &result {
        Ok(stub) => (Errno::Ok, stub.handle as usize),
        Err(e) => (*e, 0),
    };
    recorder::record_with_meta(
        RecordOp::InterceptFuncAddr,
        func_addr as usize,
        pre as usize,
        final_errno,
        None,
        RecordMeta {
            lib_name,
            sym_name,
            caller_addr: (caller_addr != 0).then_some(caller_addr),
            stub,
            flags: Some(flags),
            ..RecordMeta::default()
        },
    );
    tls_errno::set(final_errno);
    result
}

pub unsafe fn intercept_sym_addr(
    sym_addr: *mut c_void,
    pre: Interceptor,
    data: *mut c_void,
    flags: u32,
) -> Result<HookStub, Errno> {
    intercept_sym_addr_with_names(sym_addr, pre, data, flags, None, None)
}

pub(crate) unsafe fn intercept_sym_addr_with_names(
    sym_addr: *mut c_void,
    pre: Interceptor,
    data: *mut c_void,
    flags: u32,
    lib_name: Option<&CStr>,
    sym_name: Option<&CStr>,
) -> Result<HookStub, Errno> {
    unsafe {
        intercept_sym_addr_with_names_and_caller_addr(
            sym_addr, pre, data, flags, lib_name, sym_name, 0,
        )
    }
}

pub(crate) unsafe fn intercept_sym_addr_with_names_and_caller_addr(
    sym_addr: *mut c_void,
    pre: Interceptor,
    data: *mut c_void,
    flags: u32,
    lib_name: Option<&CStr>,
    sym_name: Option<&CStr>,
    caller_addr: usize,
) -> Result<HookStub, Errno> {
    tls_errno::reset();
    if let Err(e) = check_intercept_flags(flags) {
        tls_errno::set(e);
        return Err(e);
    }
    let result = intercept_addr_impl(sym_addr, pre, data, flags);
    let (final_errno, stub) = match &result {
        Ok(stub) => (Errno::Ok, stub.handle as usize),
        Err(e) => (*e, 0),
    };
    recorder::record_with_meta(
        RecordOp::InterceptSymAddr,
        sym_addr as usize,
        pre as usize,
        final_errno,
        None,
        RecordMeta {
            lib_name,
            sym_name,
            caller_addr: (caller_addr != 0).then_some(caller_addr),
            stub,
            flags: Some(flags),
            ..RecordMeta::default()
        },
    );
    tls_errno::set(final_errno);
    result
}

pub(crate) fn intercept_addr_impl(
    addr: *mut c_void,
    pre: Interceptor,
    data: *mut c_void,
    flags: u32,
) -> Result<HookStub, Errno> {
    let target_ptr = addr as *mut u8;
    let launcher = intercept::ensure_launcher(target_ptr)?;
    if !intercept::has_hook(target_ptr) {
        let (hook_stub, _) = unsafe {
            hook_inline_for_pending(
                addr,
                launcher as *const c_void,
                ptr::null_mut(),
                SwitchMode::Intercept,
            )
        }?;
        intercept::bind_hook(target_ptr, hook_stub)?;
    }
    intercept::add(target_ptr, pre, data, flags)
}

pub unsafe fn intercept_sym_name(
    lib_name: &CStr,
    sym_name: &CStr,
    pre: Interceptor,
    data: *mut c_void,
    flags: u32,
) -> Result<HookStub, Errno> {
    unsafe { intercept_sym_name_with_caller_addr(lib_name, sym_name, pre, data, flags, 0) }
}

pub(crate) unsafe fn intercept_sym_name_with_caller_addr(
    lib_name: &CStr,
    sym_name: &CStr,
    pre: Interceptor,
    data: *mut c_void,
    flags: u32,
    caller_addr: usize,
) -> Result<HookStub, Errno> {
    tls_errno::reset();
    if let Err(e) = check_intercept_flags(flags) {
        tls_errno::set(e);
        return Err(e);
    }
    let sym = match unsafe { resolve_loaded_sym(lib_name, sym_name, pre as *const c_void) } {
        Ok(s) => s,
        Err(Errno::Pending) => {
            let result = pending::create_intercept(
                lib_name,
                sym_name,
                pre,
                data,
                HookOptions {
                    flags,
                    callback: None,
                    callback_arg: ptr::null_mut(),
                    caller_addr,
                },
            );
            let (final_errno, stub) = match &result {
                Ok(stub) => (Errno::Pending, stub.handle as usize),
                Err(e) => (*e, 0),
            };
            recorder::record_with_meta(
                RecordOp::InterceptSymName,
                0,
                pre as usize,
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
            return result;
        }
        Err(e) => {
            tls_errno::set(e);
            return Err(e);
        }
    };
    remember_resolved_symbol(lib_name, sym_name, sym);
    let result = intercept_addr_impl(sym, pre, data, flags);
    let (final_errno, stub) = match &result {
        Ok(stub) => (Errno::Ok, stub.handle as usize),
        Err(e) => (*e, 0),
    };
    recorder::record_with_meta(
        RecordOp::InterceptSymName,
        sym as usize,
        pre as usize,
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
    result
}

pub unsafe fn intercept_sym_name_callback(
    lib_name: &CStr,
    sym_name: &CStr,
    pre: Interceptor,
    data: *mut c_void,
    flags: u32,
    intercepted: Option<InterceptedCallback>,
    intercepted_arg: *mut c_void,
) -> Result<HookStub, Errno> {
    unsafe {
        intercept_sym_name_callback_with_caller_addr(
            lib_name,
            sym_name,
            pre,
            data,
            HookOptions {
                flags,
                callback: intercepted,
                callback_arg: intercepted_arg,
                caller_addr: 0,
            },
        )
    }
}

pub(crate) unsafe fn intercept_sym_name_callback_with_caller_addr(
    lib_name: &CStr,
    sym_name: &CStr,
    pre: Interceptor,
    data: *mut c_void,
    options: HookOptions<InterceptedCallback>,
) -> Result<HookStub, Errno> {
    let HookOptions {
        flags,
        callback: intercepted,
        callback_arg: intercepted_arg,
        caller_addr,
    } = options;
    tls_errno::reset();
    if let Err(e) = check_intercept_flags(flags) {
        tls_errno::set(e);
        return Err(e);
    }
    let sym_addr = match unsafe { resolve_loaded_sym(lib_name, sym_name, pre as *const c_void) } {
        Ok(sym) => Some(sym),
        Err(Errno::Pending) => {
            let result = pending::create_intercept(lib_name, sym_name, pre, data, options);
            let (final_errno, stub) = match &result {
                Ok(stub) => (Errno::Pending, stub.handle as usize),
                Err(e) => (*e, 0),
            };
            recorder::record_with_meta(
                RecordOp::InterceptSymName,
                0,
                pre as usize,
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
            return result;
        }
        Err(e) => {
            tls_errno::set(e);
            if let Some(cb) = intercepted {
                cb(
                    e as i32,
                    lib_name.as_ptr(),
                    sym_name.as_ptr(),
                    ptr::null(),
                    pre,
                    data,
                    intercepted_arg,
                );
            }
            return Err(e);
        }
    };
    let result = unsafe {
        intercept_sym_name_with_caller_addr(lib_name, sym_name, pre, data, flags, caller_addr)
    };
    if let Some(cb) = intercepted {
        let error = match &result {
            Ok(_) => Errno::Ok as i32,
            Err(e) => *e as i32,
        };
        cb(
            error,
            lib_name.as_ptr(),
            sym_name.as_ptr(),
            sym_addr.map_or(ptr::null(), |addr| addr as *const c_void),
            pre,
            data,
            intercepted_arg,
        );
    }
    result
}

pub unsafe fn unintercept(stub: HookStub) -> Result<(), Errno> {
    unsafe { unintercept_with_caller_addr(stub, 0) }
}

pub unsafe fn unintercept_with_caller_addr(
    stub: HookStub,
    caller_addr: usize,
) -> Result<(), Errno> {
    tls_errno::reset();
    let result = if pending::is_pending_handle(stub.handle) {
        pending::unhook(stub.handle, caller_addr)
    } else if intercept::is_intercept_handle(stub.handle) {
        intercept::unhook_handle(stub.handle)
    } else {
        Err(Errno::UnhookNotFound)
    };
    let final_errno = match &result {
        Ok(_) => Errno::Ok,
        Err(e) => *e,
    };
    recorder::record_with_meta(
        RecordOp::Unintercept,
        stub.handle as usize,
        0,
        final_errno,
        None,
        RecordMeta {
            caller_addr: (caller_addr != 0).then_some(caller_addr),
            stub: stub.handle as usize,
            ..RecordMeta::default()
        },
    );
    tls_errno::set(final_errno);
    result
}
