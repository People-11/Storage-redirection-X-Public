#[cfg(target_os = "android")]
use core::ffi::c_char;

const VERSION: &str = concat!("srx_inline_hook version ", env!("CARGO_PKG_VERSION"));
const VERSION_CSTR: &str = concat!("srx_inline_hook version ", env!("CARGO_PKG_VERSION"), "\0");

pub fn get_version() -> &'static str {
    VERSION
}

#[cfg(target_os = "android")]
pub fn get_version_cstr() -> *const c_char {
    VERSION_CSTR.as_ptr().cast()
}
