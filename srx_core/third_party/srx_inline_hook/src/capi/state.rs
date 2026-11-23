use super::prelude::*;

#[unsafe(no_mangle)]
pub extern "C" fn srx_inline_hook_get_version() -> *const c_char {
    version::get_version_cstr()
}

#[unsafe(no_mangle)]
pub extern "C" fn srx_inline_hook_init(mode: c_int, debuggable: bool) -> c_int {
    // mode 非法（< 0 || > 2）返回 InvalidArg
    let m = match mode {
        0 => HookMode::Shared,
        1 => HookMode::Unique,
        2 => HookMode::Multi,
        _ => return Errno::InvalidArg as c_int,
    };
    match api::init(m, debuggable) {
        Ok(()) => Errno::Ok as c_int,
        Err(e) => e as c_int,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn srx_inline_hook_get_init_errno() -> c_int {
    api::get_init_errno() as c_int
}

#[unsafe(no_mangle)]
pub extern "C" fn srx_inline_hook_get_mode() -> c_int {
    api::get_mode() as c_int
}

#[unsafe(no_mangle)]
pub extern "C" fn srx_inline_hook_get_debuggable() -> bool {
    api::is_debug()
}

#[unsafe(no_mangle)]
pub extern "C" fn srx_inline_hook_set_debuggable(debuggable: bool) {
    api::set_debug(debuggable);
}

#[unsafe(no_mangle)]
pub extern "C" fn srx_inline_hook_get_recordable() -> bool {
    api::is_recordable()
}

#[unsafe(no_mangle)]
pub extern "C" fn srx_inline_hook_set_recordable(recordable: bool) {
    api::set_recordable(recordable);
}

#[unsafe(no_mangle)]
pub extern "C" fn srx_inline_hook_get_disable() -> bool {
    api::is_disabled()
}

#[unsafe(no_mangle)]
pub extern "C" fn srx_inline_hook_set_disable(disable: bool) {
    api::set_disabled(disable);
}

#[unsafe(no_mangle)]
pub extern "C" fn srx_inline_hook_get_errno() -> c_int {
    api::get_errno() as c_int
}

#[unsafe(no_mangle)]
pub extern "C" fn srx_inline_hook_to_errmsg(error_number: c_int) -> *const c_char {
    errmsg_cstr(error_number)
}
