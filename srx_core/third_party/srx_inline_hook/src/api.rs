// 对外 hook API；按职责拆分公开入口与内部安装路径

mod prelude {
    pub(super) use core::ffi::{CStr, c_char, c_void};
    pub(super) use core::ptr;
    pub(super) use core::ptr::NonNull;

    pub(super) use std::collections::HashMap;
    pub(super) use std::ffi::CString;
    pub(super) use std::sync::Mutex;

    pub(super) use once_cell::sync::Lazy;

    pub(super) use crate::android;
    pub(super) use crate::arch::current;
    pub(super) use crate::bytesig;
    pub(super) use crate::errno::Errno;
    pub(super) use crate::intercept::{self, Interceptor};
    pub(super) use crate::linker::{self, LoadedSymbolLookup};
    pub(super) use crate::pending;
    pub(super) use crate::recorder::{self, RecordItems, RecordMeta, RecordOp};
    pub(super) use crate::runtime;
    pub(super) use crate::shared_stack;
    pub(super) use crate::stub;
    pub(super) use crate::switch::{self, RemoveOutcome, Switch, SwitchMode};
    pub(super) use crate::tls_errno;
    pub(super) use crate::trampoline;
    pub(super) use crate::version;

    pub(super) use super::flags::{
        HOOK_FLAG_MULTI, check_hook_flags, check_intercept_flags, ensure_multi_orig_addr,
        flags_to_mode,
    };
    pub(super) use super::install::{
        hook_inline_for_pending, hook_inline_inner, hook_with_orig_inner,
    };
    pub(super) use super::loader::{sh_dlclose, sh_dlopen, sh_dlsym_dynsym};
    pub(super) use super::resolve::{remember_resolved_symbol, resolve_loaded_sym};
    pub(super) use super::types::{HookMode, HookOptions, HookStub, PROLOGUE_PROBE_LEN, get_mode};
}

mod flags;
mod hook_addr;
mod hook_name;
mod install;
mod intercept_api;
mod loader;
mod resolve;
mod state;
mod types;
mod unhook;

pub use flags::{check_hook_flags, check_intercept_flags};
pub use hook_addr::{hook_sym_addr, hook_sym_addr_2};
pub(crate) use hook_addr::{
    hook_sym_addr_2_with_names_and_caller_addr, hook_sym_addr_with_caller_addr,
};
pub use hook_name::{
    HookedCallback, hook_sym_name, hook_sym_name_2, hook_sym_name_callback,
    hook_sym_name_callback_2,
};
pub(crate) use hook_name::{
    hook_sym_name_2_with_caller_addr, hook_sym_name_callback_2_with_caller_addr,
    hook_sym_name_callback_with_caller_addr, hook_sym_name_with_caller_addr,
};
pub(crate) use install::{
    hook_inline_for_pending, hook_with_orig_2_with_names_and_caller_addr,
    hook_with_orig_with_caller_addr,
};
pub use install::{hook_multi, hook_single, hook_with_orig, hook_with_orig_2};
pub use intercept_api::{
    InterceptedCallback, intercept_func_addr, intercept_instr_addr, intercept_sym_addr,
    intercept_sym_name, intercept_sym_name_callback, unintercept,
};
pub(crate) use intercept_api::{
    intercept_addr_impl, intercept_func_addr_with_names_and_caller_addr,
    intercept_instr_addr_with_names_and_caller_addr, intercept_sym_addr_with_names_and_caller_addr,
    intercept_sym_name_callback_with_caller_addr, intercept_sym_name_with_caller_addr,
    unintercept_with_caller_addr,
};
pub use loader::{sh_dlclose, sh_dlopen, sh_dlsym, sh_dlsym_dynsym, sh_dlsym_symtab};
pub use state::{
    DiagnoseReport, active_hook_count, clear_records, diagnose, dump_records, dump_records_to_fd,
    dump_records_with_items, get_errno, get_init_errno, init, is_debug, is_disabled, is_recordable,
    list_hooks, set_debug, set_disabled, set_recordable, trampoline_stats,
};
pub(crate) use types::HookOptions;
pub use types::{HookMode, HookStub, get_mode};
pub(crate) use unhook::{cleanup_hooks_for_dlinfo, unhook_active};
pub(crate) use unhook::{is_addr_in_dlinfo, unhook_with_caller_addr};
pub use unhook::{prev_func, prev_func_by_addr, unhook};
