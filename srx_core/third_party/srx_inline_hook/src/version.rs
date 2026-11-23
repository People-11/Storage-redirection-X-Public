const VERSION: &str = concat!("srx_inline_hook version ", env!("CARGO_PKG_VERSION"));

pub fn get_version() -> &'static str {
    VERSION
}
