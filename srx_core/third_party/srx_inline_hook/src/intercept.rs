// 最小 intercept：为每个目标生成 launcher，支持按地址注册 pre 回调
// aarch64 补真实 CPU context 与最小 FPSIMD 读写语义

#[cfg(target_arch = "aarch64")]
use core::arch::global_asm;
use core::ffi::c_void;
use core::ptr::{self, NonNull};
use core::sync::atomic::{AtomicUsize, Ordering};
use std::collections::HashMap;
use std::sync::Mutex;

use once_cell::sync::Lazy;

use crate::android;
use crate::api::{self, HookStub};
use crate::errno::Errno;
use crate::stub;
use crate::switch::{self, SwitchMode};
use crate::trampoline;

pub const INTERCEPT_FLAG_FPSIMD_READ: u32 = 1;
pub const INTERCEPT_FLAG_FPSIMD_WRITE: u32 = 2;
pub const INTERCEPT_FLAG_RECORD: u32 = 4;
pub const INTERCEPT_FLAG_KNOWN_MASK: u32 =
    INTERCEPT_FLAG_FPSIMD_READ | INTERCEPT_FLAG_FPSIMD_WRITE | INTERCEPT_FLAG_RECORD;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[repr(C)]
pub struct SrxInlineHookVReg {
    pub d: [u64; 2],
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct SrxInlineHookCpuContext {
    pub regs: [u64; 31],
    pub sp: u64,
    pub pc: u64,
    pub pstate: u64,
    pub vregs: [SrxInlineHookVReg; 32],
    pub fpsr: u64,
    pub fpcr: u64,
}

pub type Interceptor = extern "C" fn(*mut SrxInlineHookCpuContext, *mut c_void);

#[derive(Clone, Copy)]
pub struct InterceptorEntry {
    pub id: usize,
    pub pre: Interceptor,
    pub data: *mut c_void,
    pub flags: u32,
}

pub struct InterceptTarget {
    pub launcher: *mut u8,
    pub hook_stub: Option<HookStub>,
    pub flags_union: u32,
    pub entries: Vec<InterceptorEntry>,
}

// SAFETY: data 仅保存地址值，真实解引用由调用方回调自己负责
unsafe impl Send for InterceptorEntry {}

// SAFETY: launcher 仅保存 trampoline 槽地址，访问受 TARGETS 锁保护
unsafe impl Send for InterceptTarget {}

const INTERCEPT_ID_BASE: usize = 1usize << 47;
static NEXT_INTERCEPT_ID: AtomicUsize = AtomicUsize::new(INTERCEPT_ID_BASE);
static TARGETS: Lazy<Mutex<HashMap<usize, InterceptTarget>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

fn alloc_id() -> usize {
    NEXT_INTERCEPT_ID.fetch_add(1, Ordering::Relaxed)
}

pub fn add(
    target: *mut u8,
    pre: Interceptor,
    data: *mut c_void,
    flags: u32,
) -> Result<HookStub, Errno> {
    let mut g = TARGETS.lock().map_err(|_| Errno::NotSupport)?;
    let target_entry = g.entry(target as usize).or_insert_with(|| InterceptTarget {
        launcher: ptr::null_mut(),
        hook_stub: None,
        flags_union: 0,
        entries: Vec::new(),
    });
    if target_entry
        .entries
        .iter()
        .any(|e| e.pre as usize == pre as usize && e.data == data)
    {
        return Err(Errno::InterceptDup);
    }
    let id = alloc_id();
    target_entry.entries.push(InterceptorEntry {
        id,
        pre,
        data,
        flags,
    });
    target_entry.flags_union |= flags;
    drop(g);
    let _ = switch::set_interceptors_active(target, true);
    Ok(HookStub {
        handle: id as *mut c_void,
    })
}

pub fn is_intercept_handle(handle: *mut c_void) -> bool {
    let id = handle as usize;
    (INTERCEPT_ID_BASE..(1usize << 48)).contains(&id)
}

pub fn has_hook(target: *mut u8) -> bool {
    TARGETS
        .lock()
        .map(|g| {
            g.get(&(target as usize))
                .is_some_and(|target_entry| target_entry.hook_stub.is_some())
        })
        .unwrap_or(false)
}

pub fn bind_hook(target: *mut u8, hook_stub: HookStub) -> Result<(), Errno> {
    let mut g = TARGETS.lock().map_err(|_| Errno::NotSupport)?;
    let target_entry = g.entry(target as usize).or_insert_with(|| InterceptTarget {
        launcher: ptr::null_mut(),
        hook_stub: None,
        flags_union: 0,
        entries: Vec::new(),
    });
    target_entry.hook_stub = Some(hook_stub);
    drop(g);
    let _ = switch::set_interceptors_active(target, has_entries(target));
    Ok(())
}

pub fn discard_unused_target(target: *mut u8) {
    let Ok(mut g) = TARGETS.lock() else {
        return;
    };
    let removable = g.get(&(target as usize)).is_some_and(|target_entry| {
        target_entry.hook_stub.is_none() && target_entry.entries.is_empty()
    });
    if removable
        && let Some(removed) = g.remove(&(target as usize))
        && let Some(launcher) = NonNull::new(removed.launcher)
    {
        let _ = trampoline::release(launcher);
    }
}

pub fn cleanup_target(target: *mut u8) {
    let Ok(mut g) = TARGETS.lock() else {
        return;
    };
    let Some(removed) = g.remove(&(target as usize)) else {
        return;
    };
    if let Some(launcher) = NonNull::new(removed.launcher) {
        let _ = trampoline::release(launcher);
    }
}

pub fn unhook_handle(handle: *mut c_void) -> Result<(), Errno> {
    let id = handle as usize;
    let last = {
        let g = TARGETS.lock().map_err(|_| Errno::NotSupport)?;
        let Some((target, target_entry)) = g.iter().find_map(|(target, target_entry)| {
            target_entry
                .entries
                .iter()
                .any(|entry| entry.id == id)
                .then_some((*target, target_entry))
        }) else {
            return Err(Errno::UnhookNotFound);
        };
        if target_entry.entries.len() == 1 {
            (
                target as *mut u8,
                target_entry.hook_stub.ok_or(Errno::UnhookNotFound)?,
                true,
            )
        } else {
            (
                target as *mut u8,
                HookStub {
                    handle: ptr::null_mut(),
                },
                false,
            )
        }
    };
    if last.2 {
        unsafe { api::unhook_active(last.1, 0) }?;
        let mut g = TARGETS.lock().map_err(|_| Errno::NotSupport)?;
        let removed = g.remove(&(last.0 as usize)).ok_or(Errno::UnhookNotFound)?;
        if let Some(launcher) = NonNull::new(removed.launcher) {
            let _ = trampoline::release(launcher);
        }
        Ok(())
    } else {
        let mut g = TARGETS.lock().map_err(|_| Errno::NotSupport)?;
        let target = last.0;
        let target_entry = g.get_mut(&(target as usize)).ok_or(Errno::UnhookNotFound)?;
        let idx = target_entry
            .entries
            .iter()
            .position(|entry| entry.id == id)
            .ok_or(Errno::UnhookNotFound)?;
        target_entry.entries.remove(idx);
        target_entry.flags_union = target_entry
            .entries
            .iter()
            .fold(0u32, |acc, entry| acc | entry.flags);
        let has_any = !target_entry.entries.is_empty();
        drop(g);
        let _ = switch::set_interceptors_active(target, has_any);
        Ok(())
    }
}

fn dispatch_with_ctx(target: *mut u8, ctx: &mut SrxInlineHookCpuContext) -> u32 {
    let (entries, flags_union) = {
        let Ok(g) = TARGETS.lock() else {
            return 0;
        };
        let Some(target_entry) = g.get(&(target as usize)) else {
            return 0;
        };
        (target_entry.entries.clone(), target_entry.flags_union)
    };
    ctx.pc = target as u64;
    for entry in entries {
        (entry.pre)(ctx, entry.data);
    }
    flags_union
}

pub fn dispatch(target: *mut u8) {
    let mut ctx = SrxInlineHookCpuContext::default();
    let _ = dispatch_with_ctx(target, &mut ctx);
}

pub fn dispatch_from_stub(stub_handle: *mut c_void) {
    let Some(body) = stub::get(stub_handle as usize) else {
        return;
    };
    dispatch(body.target);
}

pub fn has_entries(target: *mut u8) -> bool {
    TARGETS
        .lock()
        .map(|g| {
            g.get(&(target as usize))
                .is_some_and(|target_entry| !target_entry.entries.is_empty())
        })
        .unwrap_or(false)
}

pub fn launcher_of(target: *mut u8) -> Option<*mut u8> {
    TARGETS
        .lock()
        .ok()?
        .get(&(target as usize))
        .and_then(|target_entry| NonNull::new(target_entry.launcher).map(|p| p.as_ptr()))
}

pub fn ensure_launcher(target: *mut u8) -> Result<*mut u8, Errno> {
    if let Some(launcher) = launcher_of(target) {
        return Ok(launcher);
    }
    let slot = trampoline::acquire()?;
    let build_result = unsafe { arch::bytesig_build_launcher(slot.as_ptr(), target) };
    if let Err(e) = build_result {
        let _ = trampoline::release(slot);
        return Err(e);
    }
    let mut g = TARGETS.lock().map_err(|_| Errno::NotSupport)?;
    let target_entry = g.entry(target as usize).or_insert_with(|| InterceptTarget {
        launcher: ptr::null_mut(),
        hook_stub: None,
        flags_union: 0,
        entries: Vec::new(),
    });
    if target_entry.launcher.is_null() {
        target_entry.launcher = slot.as_ptr();
        Ok(slot.as_ptr())
    } else {
        let _ = trampoline::release(slot);
        Ok(target_entry.launcher)
    }
}

mod arch;

pub fn mode() -> SwitchMode {
    SwitchMode::Intercept
}
