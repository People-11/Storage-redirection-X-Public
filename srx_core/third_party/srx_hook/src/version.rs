const VERSION_STR: &str = env!("CARGO_PKG_VERSION");

#[cfg(target_arch = "aarch64")]
const VERSION_ARCH: &str = "aarch64";
#[cfg(target_arch = "x86_64")]
const VERSION_ARCH: &str = "x86_64";
#[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
const VERSION_ARCH: &str = "unknown";

pub fn version_str() -> &'static str {
    VERSION_STR
}

// 返回包含库名和架构的完整版本字符串
pub fn version_str_full() -> String {
    format!("srx_hook {} ({})", version_str(), VERSION_ARCH)
}
