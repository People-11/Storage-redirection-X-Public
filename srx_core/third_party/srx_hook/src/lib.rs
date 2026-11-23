#![allow(unsafe_op_in_unsafe_fn)]
#![allow(clippy::missing_safety_doc)]

#[cfg(all(not(target_os = "android"), not(any(clippy, test, doc))))]
compile_error!(
    "srx_hook supports Android only (use cargo clippy/test/doc on host for development)"
);

#[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
compile_error!("srx_hook supports only 64-bit architectures: aarch64 and x86_64");

// 公共 API 层，提供 hook 注册、刷新、忽略等操作
#[cfg(target_os = "android")]
mod api;
// ELF 解析核心，处理动态段、符号表、重定位表
#[cfg(target_os = "android")]
mod elf;
// 错误码定义
#[cfg(target_os = "android")]
mod errno;
// 日志输出，使用 Android logcat
#[cfg(target_os = "android")]
mod log;
// Android 相关：内存保护与信号守卫
#[cfg(target_os = "android")]
mod android;
// 运行时状态管理：生命周期、刷新管道、规则编译
#[cfg(target_os = "android")]
mod runtime;
// 版本信息
#[cfg(target_os = "android")]
mod version;

// 只导出 srx_core 使用的接口
#[cfg(target_os = "android")]
pub use api::{
    HookMode, HookStub, RefreshError, add_ignore, hook_all, init, is_forked_child, refresh,
    with_prev_func,
};
#[cfg(target_os = "android")]
pub use errno::Errno as SrxHookErrno;
