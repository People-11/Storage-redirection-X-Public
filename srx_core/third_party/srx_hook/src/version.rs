const VERSION_STR: &str = env!("CARGO_PKG_VERSION");

#[cfg(target_arch = "aarch64")]
const VERSION_ARCH: &str = "aarch64";
#[cfg(target_arch = "x86_64")]
const VERSION_ARCH: &str = "x86_64";
#[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
const VERSION_ARCH: &str = "unknown";

// 返回版本号的 u32 编码：major << 16 | minor << 8 | patch
pub fn version() -> u32 {
    let normalized = VERSION_STR.split(['-', '+']).next().unwrap_or(VERSION_STR);
    let mut parts = normalized.split('.');

    let major = parse_part(parts.next());
    let minor = parse_part(parts.next());
    let patch = parse_part(parts.next());

    (major << 16) | (minor << 8) | patch
}

pub fn version_str() -> &'static str {
    VERSION_STR
}

// 返回包含库名和架构的完整版本字符串
pub fn version_str_full() -> String {
    format!("srx_hook {} ({})", version_str(), VERSION_ARCH)
}

fn parse_part(part: Option<&str>) -> u32 {
    part.and_then(|value| value.parse::<u32>().ok())
        .unwrap_or(0)
}
