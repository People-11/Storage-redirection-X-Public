// 只编译当前架构的指令解码与改写器，api 层通过 current 别名使用
#[cfg(target_arch = "aarch64")]
pub mod arm64;
#[cfg(target_arch = "x86_64")]
pub mod x86_64;
#[cfg(target_arch = "x86_64")]
mod x86_64_table;

#[cfg(target_arch = "aarch64")]
pub use arm64 as current;
#[cfg(target_arch = "x86_64")]
pub use x86_64 as current;
