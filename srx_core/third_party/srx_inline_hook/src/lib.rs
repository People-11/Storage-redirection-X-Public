#![allow(dead_code)]
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

// arch 纯计算，host 也可编译与单测（LDE / 重写器不依赖 libc）
mod arch;

// util 只含纯函数，host / android 通用，保证 cargo test --lib 可覆盖
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
mod dlcb;
#[cfg(target_os = "android")]
mod intercept;
#[cfg(target_os = "android")]
mod linker;
#[cfg(target_os = "android")]
mod pending;
#[cfg(target_os = "android")]
mod recorder;
#[cfg(target_os = "android")]
mod runtime;
#[cfg(target_os = "android")]
mod shared_stack;
#[cfg(target_os = "android")]
mod stub;
#[cfg(target_os = "android")]
mod switch;
#[cfg(target_os = "android")]
mod symbol;
#[cfg(target_os = "android")]
mod tls_errno;
#[cfg(target_os = "android")]
mod trampoline;

pub use errno::{Errno, errno_to_message};
pub use version::get_version;

#[cfg(target_os = "android")]
pub use api::{
    DiagnoseReport, HookMode, HookStub, HookedCallback, active_hook_count, check_hook_flags,
    clear_records, diagnose, dump_records, dump_records_to_fd, dump_records_with_items, get_errno,
    get_init_errno, get_mode, hook_multi, hook_single, hook_sym_addr, hook_sym_addr_2,
    hook_sym_name, hook_sym_name_2, hook_sym_name_callback, hook_sym_name_callback_2,
    hook_with_orig, hook_with_orig_2, init, intercept_func_addr, intercept_instr_addr,
    intercept_sym_addr, intercept_sym_name, intercept_sym_name_callback, is_debug, is_disabled,
    is_recordable, list_hooks, prev_func, prev_func_by_addr, set_debug, set_disabled,
    set_recordable, sh_dlclose, sh_dlopen, sh_dlsym, trampoline_stats, unhook, unintercept,
};
#[cfg(target_os = "android")]
pub use linker::{
    find_linker_symbol, find_linker_symbol_by_symtab, find_linker64_base, linker_ctor_hit_count,
    linker_dtor_hit_count, linker_hook_stub_count, linker_hooks_installed,
    reset_linker_hook_counters,
};
#[cfg(target_os = "android")]
pub use recorder::RecordItems;
#[cfg(target_os = "android")]
pub use switch::HookInfo;
#[cfg(target_os = "android")]
pub use symbol::{AddrInfo, addr_info};
#[cfg(target_os = "android")]
pub use trampoline::TrampolineStats;
