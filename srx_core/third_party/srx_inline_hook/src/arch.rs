// arch 子模块对 host 也可见，便于 LDE / rewriter 纯函数在 host 跑单测
// api 层通过 current 别名按 target_arch 分发
pub mod arm64;
pub mod x86_64;
mod x86_64_table;

#[cfg(target_arch = "aarch64")]
#[allow(unused_imports)]
pub use arm64 as current;
#[cfg(target_arch = "x86_64")]
#[allow(unused_imports)]
pub use x86_64 as current;
