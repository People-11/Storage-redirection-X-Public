use core::ffi::{CStr, c_char, c_int, c_void};
use core::ptr;
use std::ffi::CString;

use crate::api::HookStub;
use crate::errno::Errno;
use crate::intercept::INTERCEPT_FLAG_RECORD;
use crate::util::cstr_from_ptr_no_libc;

pub(super) fn sanitize_name_arg(raw: &CStr) -> Result<CString, Errno> {
    let bytes = raw.to_bytes();
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    CString::new(&bytes[..end]).map_err(|_| Errno::InvalidArg)
}

pub(super) fn errmsg_cstr(code: c_int) -> *const c_char {
    let msg: &'static [u8] = match code {
        0 => b"OK\0",
        1 => b"Pending task\0",
        2 => b"Not initialized\0",
        3 => b"Invalid argument\0",
        4 => b"Out of memory\0",
        5 => b"MProtect failed\0",
        6 => b"Write to arbitrary address crashed\0",
        7 => b"Init errno mod failed\0",
        8 => b"Init bytesig mod SIGSEGV failed\0",
        9 => b"Init bytesig mod SIGBUS failed\0",
        10 => b"Duplicate intercept\0",
        11 => b"Init safe mod failed\0",
        12 => b"Init linker mod failed\0",
        13 => b"Init hub mod failed\0",
        14 => b"Create hub failed\0",
        15 => b"Monitor dlopen failed\0",
        16 => b"Duplicate shared hook\0",
        17 => b"Open ELF crashed\0",
        18 => b"Find symbol in ELF failed\0",
        19 => b"Find symbol in ELF crashed\0",
        20 => b"Duplicate unique ook\0",
        21 => b"Dladdr crashed\0",
        22 => b"Find dlinfo failed\0",
        23 => b"Symbol size too small\0",
        24 => b"Alloc enter failed\0",
        25 => b"Instruction rewrite crashed\0",
        26 => b"Instruction rewrite failed\0",
        27 => b"Unop not found\0",
        28 => b"Verify original instruction crashed\0",
        29 => b"Verify original instruction failed\0",
        30 => b"Verify exit instruction failed\0",
        31 => b"Verify exit instruction crashed\0",
        32 => b"Unop on an error status task\0",
        33 => b"Unop on an unfinished task\0",
        34 => b"ELF with an unsupported architecture\0",
        35 => b"Linker with an unsupported architecture\0",
        36 => b"Duplicate init fini callback\0",
        37 => b"Unregister not-existed init fini callback\0",
        38 => b"Register callback not supported\0",
        39 => b"Init task mod failed\0",
        40 => b"Alloc island for exit failed\0",
        41 => b"Alloc island for enter failed\0",
        42 => b"Alloc island for rewrite failed\0",
        43 => b"Mode conflict\0",
        44 => b"Duplicate multi hook\0",
        45 => b"Disabled\0",
        100 => b"Instruction not supported by rewriter\0",
        101 => b"Patch range overlaps an existing hook\0",
        102 => b"Failed to install sigill handler\0",
        _ => b"Unknown error number\0",
    };
    msg.as_ptr() as *const c_char
}

fn check_record_name_valid(name: &CStr) -> bool {
    let bytes = name.to_bytes();
    !bytes.is_empty() && !bytes.iter().any(|b| b.is_ascii_whitespace())
}

pub(super) unsafe fn parse_record_names<'a>(
    flags: u32,
    record_lib_name: *const c_char,
    record_sym_name: *const c_char,
) -> Result<(Option<&'a CStr>, Option<&'a CStr>), Errno> {
    if flags & INTERCEPT_FLAG_RECORD == 0 {
        return Ok((None, None));
    }
    let lib = if record_lib_name.is_null() {
        None
    } else {
        let Some(lib) = (unsafe { cstr_from_ptr_no_libc(record_lib_name) }) else {
            return Err(Errno::InvalidArg);
        };
        if !check_record_name_valid(lib) {
            return Err(Errno::InvalidArg);
        }
        Some(lib)
    };
    let sym = if record_sym_name.is_null() {
        None
    } else {
        let Some(sym) = (unsafe { cstr_from_ptr_no_libc(record_sym_name) }) else {
            return Err(Errno::InvalidArg);
        };
        if !check_record_name_valid(sym) {
            return Err(Errno::InvalidArg);
        }
        Some(sym)
    };
    Ok((lib, sym))
}

pub(super) fn stub_or_null(r: Result<HookStub, Errno>) -> *mut c_void {
    match r {
        Ok(s) => s.handle,
        Err(Errno::Pending) => ptr::null_mut(),
        Err(_) => ptr::null_mut(),
    }
}
