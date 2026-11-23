// Shared 模式线程局部栈：保存 target / return_address / reentrant 标记
// 入口胶水负责入栈与递归抑制，代理侧只读写当前帧

#[cfg(target_arch = "aarch64")]
use core::arch::global_asm;
use core::ffi::c_void;
use core::ptr::{self, NonNull};
use std::cell::RefCell;

use crate::android;
use crate::errno::Errno;
use crate::switch;
use crate::trampoline;

#[derive(Clone, Copy)]
pub struct SharedFrame {
    pub target: *mut u8,
    pub return_address: *mut c_void,
    pub allow_reentrant: bool,
}

thread_local! {
    #[expect(clippy::missing_const_for_thread_local, reason = "Android TLS 宏展开仍报告已存在的常量初始化")]
    static STACK: RefCell<Vec<SharedFrame>> = const { RefCell::new(Vec::new()) };
}

pub fn push(target: *mut u8, return_address: *mut c_void) {
    STACK.with(|stack| {
        stack.borrow_mut().push(SharedFrame {
            target,
            return_address,
            allow_reentrant: false,
        });
    });
}

pub fn ensure_top(target: *mut u8, return_address: *mut c_void) {
    STACK.with(|stack| {
        let mut stack = stack.borrow_mut();
        if stack
            .last()
            .is_some_and(|frame| frame.target == target && frame.return_address == return_address)
        {
            return;
        }
        stack.push(SharedFrame {
            target,
            return_address,
            allow_reentrant: false,
        });
    });
}

pub fn enter(target: *mut u8, return_address: *mut c_void) -> bool {
    STACK.with(|stack| {
        let mut stack = stack.borrow_mut();
        if stack
            .iter()
            .rev()
            .any(|frame| frame.target == target && !frame.allow_reentrant)
        {
            return false;
        }
        stack.push(SharedFrame {
            target,
            return_address,
            allow_reentrant: false,
        });
        true
    })
}

pub fn pop(return_address: *mut c_void) {
    STACK.with(|stack| {
        let mut stack = stack.borrow_mut();
        if stack
            .last()
            .is_some_and(|frame| frame.return_address == return_address)
        {
            stack.pop();
        }
    });
}

pub fn set_allow_reentrant(return_address: *mut c_void, on: bool) {
    STACK.with(|stack| {
        let mut stack = stack.borrow_mut();
        if let Some(frame) = stack.last_mut()
            && frame.return_address == return_address
        {
            frame.allow_reentrant = on;
        }
    });
}

pub fn current_return_address() -> *mut c_void {
    STACK.with(|stack| {
        stack
            .borrow()
            .last()
            .map(|frame| frame.return_address)
            .unwrap_or(ptr::null_mut())
    })
}

pub fn current_target() -> *mut u8 {
    STACK.with(|stack| {
        stack
            .borrow()
            .last()
            .map(|frame| frame.target)
            .unwrap_or(ptr::null_mut())
    })
}

pub fn current_allow_reentrant() -> bool {
    STACK.with(|stack| {
        stack
            .borrow()
            .last()
            .is_some_and(|frame| frame.allow_reentrant)
    })
}

pub fn has_frame() -> bool {
    STACK.with(|stack| !stack.borrow().is_empty())
}

pub fn create_launcher(target: *mut u8) -> Result<NonNull<u8>, Errno> {
    let slot = trampoline::acquire()?;
    let build_result = unsafe { build_launcher(slot.as_ptr(), target) };
    if let Err(e) = build_result {
        let _ = trampoline::release(slot);
        return Err(e);
    }
    Ok(slot)
}

unsafe fn build_launcher(buf: *mut u8, target: *mut u8) -> Result<(), Errno> {
    if target.is_null() {
        return Err(Errno::InvalidArg);
    }
    #[cfg(target_arch = "x86_64")]
    unsafe {
        build_launcher_x86_64(buf, target);
        Ok(())
    }
    #[cfg(target_arch = "aarch64")]
    unsafe {
        build_launcher_arm64(buf, target);
        Ok(())
    }
}

extern "C" fn shared_dispatch_and_get_next_hop(
    target: *mut c_void,
    return_address: *mut c_void,
) -> *mut c_void {
    let target_ptr = target as *mut u8;
    if !enter(target_ptr, return_address) {
        return switch::trampoline_of(target_ptr)
            .map(|p| p as *mut c_void)
            .unwrap_or(ptr::null_mut());
    }
    switch::head_replacement_of(target_ptr)
        .or_else(|| switch::trampoline_of(target_ptr).map(|p| p as *const c_void))
        .unwrap_or(ptr::null()) as *mut c_void
}

#[cfg(target_arch = "x86_64")]
unsafe fn build_launcher_x86_64(buf: *mut u8, target: *mut u8) {
    let target_addr = target as usize as u64;
    let helper_addr = shared_dispatch_and_get_next_hop as *const () as usize as u64;
    let bytes: [u8; 51] = [
        0x50,
        0x57,
        0x56,
        0x52,
        0x51,
        0x41,
        0x50,
        0x41,
        0x51,
        0x48,
        0xBF,
        (target_addr & 0xFF) as u8,
        ((target_addr >> 8) & 0xFF) as u8,
        ((target_addr >> 16) & 0xFF) as u8,
        ((target_addr >> 24) & 0xFF) as u8,
        ((target_addr >> 32) & 0xFF) as u8,
        ((target_addr >> 40) & 0xFF) as u8,
        ((target_addr >> 48) & 0xFF) as u8,
        ((target_addr >> 56) & 0xFF) as u8,
        0x48,
        0x8B,
        0x74,
        0x24,
        0x38,
        0x48,
        0xB8,
        (helper_addr & 0xFF) as u8,
        ((helper_addr >> 8) & 0xFF) as u8,
        ((helper_addr >> 16) & 0xFF) as u8,
        ((helper_addr >> 24) & 0xFF) as u8,
        ((helper_addr >> 32) & 0xFF) as u8,
        ((helper_addr >> 40) & 0xFF) as u8,
        ((helper_addr >> 48) & 0xFF) as u8,
        ((helper_addr >> 56) & 0xFF) as u8,
        0xFF,
        0xD0,
        0x49,
        0x89,
        0xC3,
        0x41,
        0x59,
        0x41,
        0x58,
        0x59,
        0x5A,
        0x5E,
        0x5F,
        0x58,
        0x41,
        0xFF,
        0xE3,
    ];
    ptr::copy_nonoverlapping(bytes.as_ptr(), buf, bytes.len());
    android::clear_icache(buf, bytes.len());
}

#[cfg(target_arch = "aarch64")]
unsafe extern "C" {
    fn srx_shared_hub_glue_arm64();
}

#[cfg(target_arch = "aarch64")]
unsafe fn build_launcher_arm64(buf: *mut u8, target: *mut u8) {
    let glue_addr = srx_shared_hub_glue_arm64 as *const () as usize as u64;
    let mut out = Vec::with_capacity(64);
    emit_arm64_u32(&mut out, 0x5800_0070);
    emit_arm64_u32(&mut out, 0x5800_0091);
    emit_arm64_u32(&mut out, 0xD61F_0200);
    emit_arm64_u64(&mut out, glue_addr);
    emit_arm64_u64(&mut out, target as u64);
    ptr::copy_nonoverlapping(out.as_ptr(), buf, out.len());
    android::clear_icache(buf, out.len());
}

#[cfg(target_arch = "aarch64")]
fn emit_arm64_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}

#[cfg(target_arch = "aarch64")]
fn emit_arm64_u64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_le_bytes());
}

#[cfg(target_arch = "aarch64")]
global_asm!(
    r#"
.globl srx_shared_hub_glue_arm64
.balign 4
.type srx_shared_hub_glue_arm64, %function
srx_shared_hub_glue_arm64:
    sub sp, sp, #0x50
    stp x0, x1, [sp, #0x00]
    stp x2, x3, [sp, #0x10]
    stp x4, x5, [sp, #0x20]
    stp x6, x7, [sp, #0x30]
    stp x8, x30, [sp, #0x40]

    mov x0, x17
    mov x1, x30
    bl {dispatch}
    mov x16, x0

    ldp x8, x30, [sp, #0x40]
    ldp x6, x7, [sp, #0x30]
    ldp x4, x5, [sp, #0x20]
    ldp x2, x3, [sp, #0x10]
    ldp x0, x1, [sp, #0x00]
    add sp, sp, #0x50
    br x16
"#,
    dispatch = sym shared_dispatch_and_get_next_hop,
);
