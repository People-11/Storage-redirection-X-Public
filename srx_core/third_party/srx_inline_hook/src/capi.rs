// C FFI 层：导出 srx_inline_hook_* 供 Android app / JNI 调用
// 错误通过 tls_errno 传递，C 侧调 _get_errno 读取最近结果

mod common;
mod prelude {
    #[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
    pub(super) use core::arch::global_asm;
    pub(super) use core::ffi::{CStr, c_char, c_int, c_void};
    pub(super) use core::ptr;

    pub(super) use crate::android;
    pub(super) use crate::api::{self, HookMode, HookStub, HookedCallback};
    pub(super) use crate::dlcb::{self, DlInfoCallback};
    pub(super) use crate::errno::Errno;
    pub(super) use crate::intercept::{INTERCEPT_FLAG_RECORD, Interceptor};
    pub(super) use crate::recorder::RecordItems;
    pub(super) use crate::shared_stack;
    pub(super) use crate::stub;
    pub(super) use crate::switch::SwitchMode;
    pub(super) use crate::tls_errno;
    pub(super) use crate::util::cstr_from_ptr_no_libc;
    pub(super) use crate::version;

    pub(super) use super::common::{
        errmsg_cstr, parse_record_names, sanitize_name_arg, stub_or_null,
    };
}

mod dl_callbacks;
mod hook_addr;
mod hook_name;
mod intercept;
mod records;
mod state;
