use super::prelude::*;

pub unsafe fn hook_sym_addr(
    sym_addr: *mut c_void,
    replacement: *const c_void,
    orig_addr: *mut *const c_void,
) -> Result<HookStub, Errno> {
    unsafe { hook_sym_addr_with_caller_addr(sym_addr, replacement, orig_addr, 0) }
}

pub(crate) unsafe fn hook_sym_addr_2_with_names_and_caller_addr(
    sym_addr: *mut c_void,
    replacement: *const c_void,
    orig_addr: *mut *const c_void,
    flags: u32,
    lib_name: Option<&CStr>,
    sym_name: Option<&CStr>,
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
    tls_errno::reset();
    let result = unsafe { hook_inline_inner(sym_addr, replacement, orig_addr, mode) };
    let (final_errno, backup, stub) = match &result {
        Ok((stub, consumed)) => (Errno::Ok, Some(*consumed), stub.handle as usize),
        Err(e) => (*e, None, 0),
    };
    recorder::record_with_meta(
        RecordOp::HookSymAddr,
        sym_addr as usize,
        replacement as usize,
        final_errno,
        backup,
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
    result.map(|(stub, _)| stub)
}

pub(crate) unsafe fn hook_sym_addr_with_caller_addr(
    sym_addr: *mut c_void,
    replacement: *const c_void,
    orig_addr: *mut *const c_void,
    caller_addr: usize,
) -> Result<HookStub, Errno> {
    tls_errno::reset();
    // SAFETY: sym_addr / replacement 由调用方保证为本进程有效代码地址
    let result = unsafe { hook_with_orig_inner(sym_addr, replacement, orig_addr) };
    let (final_errno, backup, stub) = match &result {
        Ok((stub, consumed)) => (Errno::Ok, Some(*consumed), stub.handle as usize),
        Err(e) => (*e, None, 0),
    };
    recorder::record_with_meta(
        RecordOp::HookSymAddr,
        sym_addr as usize,
        replacement as usize,
        final_errno,
        backup,
        RecordMeta {
            caller_addr: (caller_addr != 0).then_some(caller_addr),
            stub,
            flags: Some(0),
            ..RecordMeta::default()
        },
    );
    tls_errno::set(final_errno);
    result.map(|(stub, _)| stub)
}

pub unsafe fn hook_sym_addr_2(
    sym_addr: *mut c_void,
    replacement: *const c_void,
    orig_addr: *mut *const c_void,
    flags: u32,
) -> Result<HookStub, Errno> {
    hook_sym_addr_2_with_names(sym_addr, replacement, orig_addr, flags, None, None)
}

pub(crate) unsafe fn hook_sym_addr_2_with_names(
    sym_addr: *mut c_void,
    replacement: *const c_void,
    orig_addr: *mut *const c_void,
    flags: u32,
    lib_name: Option<&CStr>,
    sym_name: Option<&CStr>,
) -> Result<HookStub, Errno> {
    if let Err(e) = check_hook_flags(flags) {
        tls_errno::set(e);
        return Err(e);
    }
    let mode = flags_to_mode(flags);
    tls_errno::reset();
    let result = unsafe { hook_inline_inner(sym_addr, replacement, orig_addr, mode) };
    let (final_errno, backup, stub) = match &result {
        Ok((stub, consumed)) => (Errno::Ok, Some(*consumed), stub.handle as usize),
        Err(e) => (*e, None, 0),
    };
    recorder::record_with_meta(
        RecordOp::HookSymAddr,
        sym_addr as usize,
        replacement as usize,
        final_errno,
        backup,
        RecordMeta {
            lib_name,
            sym_name,
            stub,
            flags: Some(flags),
            ..RecordMeta::default()
        },
    );
    tls_errno::set(final_errno);
    result.map(|(stub, _)| stub)
}
