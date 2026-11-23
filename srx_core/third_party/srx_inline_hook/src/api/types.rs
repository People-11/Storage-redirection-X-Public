use super::prelude::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HookStub {
    pub(crate) handle: *mut c_void,
}

// SAFETY: handle 只是全局 stub 池的 opaque id，内部查询受 STUBS 锁保护
unsafe impl Send for HookStub {}
unsafe impl Sync for HookStub {}

#[cfg(target_arch = "aarch64")]
pub(super) const PROLOGUE_PROBE_LEN: usize = current::RELOCATION_LEN;
// 覆盖 x86_64 解码到改写边界所需的指令。
#[cfg(not(target_arch = "aarch64"))]
pub(super) const PROLOGUE_PROBE_LEN: usize = 24;
