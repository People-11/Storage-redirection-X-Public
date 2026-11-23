// 对外 hook API；按职责拆分公开入口与内部安装路径

mod prelude {
    pub(super) use core::ffi::{CStr, c_void};
    pub(super) use core::ptr;
    pub(super) use core::ptr::NonNull;

    pub(super) use std::ffi::CString;

    pub(super) use crate::android;
    pub(super) use crate::arch::current;
    pub(super) use crate::bytesig;
    pub(super) use crate::errno::Errno;
    pub(super) use crate::linker::{self};
    pub(super) use crate::runtime;
    pub(super) use crate::stub;
    pub(super) use crate::switch::{self, Switch};
    pub(super) use crate::trampoline;
    pub(super) use crate::version;

    pub(super) use super::types::{HookStub, PROLOGUE_PROBE_LEN};
}

mod install;
mod loader;
mod state;
mod types;
mod unhook;

pub use install::hook_sym_addr;
pub use loader::{sh_dlclose, sh_dlopen, sh_dlsym};
pub use state::{init, is_debug};
pub use types::HookStub;
pub(crate) use unhook::{cleanup_hooks_for_dlinfo, prev_func, unhook};
