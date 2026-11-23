#![allow(unsafe_op_in_unsafe_fn)]
#![allow(clippy::missing_safety_doc)]

#[cfg(all(not(target_os = "android"), not(any(clippy, debug_assertions, doc))))]
compile_error!("srx_inline_hook supports Android targets only");

#[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
compile_error!("srx_inline_hook supports aarch64 and x86_64 only");

// debuggable=false 时不求值日志参数，避免生产路径副作用
#[cfg(target_os = "android")]
#[macro_export]
macro_rules! sh_info {
    (target: $t:expr, $($arg:tt)+) => {
        if $crate::is_debug() {
            log::info!(target: $t, $($arg)+);
        }
    };
    ($($arg:tt)+) => {
        if $crate::is_debug() {
            log::info!($($arg)+);
        }
    };
}

#[cfg(target_os = "android")]
#[macro_export]
macro_rules! sh_warn {
    (target: $t:expr, $($arg:tt)+) => {
        if $crate::is_debug() {
            log::warn!(target: $t, $($arg)+);
        }
    };
    ($($arg:tt)+) => {
        if $crate::is_debug() {
            log::warn!($($arg)+);
        }
    };
}

// 关键事件通道：始终输出，不受 debuggable 控制；级别 error 保证任何过滤阈值下可见
#[cfg(target_os = "android")]
#[macro_export]
macro_rules! sh_always {
    (target: $t:expr, $($arg:tt)+) => {{
        log::error!(target: $t, $($arg)+);
    }};
    ($($arg:tt)+) => {{
        log::error!($($arg)+);
    }};
}

mod errno;
mod version;

// arch 与 util 只含纯计算，不依赖 Android libc
mod arch;
mod util;

#[cfg(target_os = "android")]
mod android;
#[cfg(target_os = "android")]
mod api;
#[cfg(target_os = "android")]
mod bytesig;
#[cfg(target_os = "android")]
mod capi;
#[cfg(target_os = "android")]
mod linker;
#[cfg(target_os = "android")]
mod runtime;
#[cfg(target_os = "android")]
mod stub;
#[cfg(target_os = "android")]
mod switch;
#[cfg(target_os = "android")]
mod trampoline;

pub use errno::Errno;

// 只导出 srx_core 使用的接口；日志宏经 $crate::is_debug 判断调试开关
#[cfg(target_os = "android")]
pub use api::{HookStub, hook_sym_addr, init, is_debug, sh_dlclose, sh_dlopen, sh_dlsym};
