use super::prelude::*;

#[derive(Clone, Copy)]
pub(crate) struct HookOptions<T> {
    pub flags: u32,
    pub callback: Option<T>,
    pub callback_arg: *mut c_void,
    pub caller_addr: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HookStub {
    pub(crate) handle: *mut c_void,
}

impl HookStub {
    pub fn as_ptr(self) -> *mut c_void {
        self.handle
    }
}

// SAFETY: handle 只是全局 stub 池的 opaque id，内部查询受 STUBS 锁保护
unsafe impl Send for HookStub {}
unsafe impl Sync for HookStub {}

// 默认使用 Unique；Shared / Multi 保留模式入口
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum HookMode {
    Shared = 0,
    Unique = 1,
    Multi = 2,
}

pub fn get_mode() -> HookMode {
    match runtime::get_mode() {
        0 => HookMode::Shared,
        2 => HookMode::Multi,
        _ => HookMode::Unique,
    }
}

#[cfg(target_arch = "aarch64")]
pub(super) const PROLOGUE_PROBE_LEN: usize = current::RELOCATION_LEN;
// 覆盖 x86_64 解码到改写边界所需的指令。
#[cfg(not(target_arch = "aarch64"))]
pub(super) const PROLOGUE_PROBE_LEN: usize = 24;
