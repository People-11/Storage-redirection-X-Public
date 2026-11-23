#[cfg(target_arch = "x86_64")]
use core::mem;

use super::*;

pub(super) unsafe fn bytesig_build_launcher(buf: *mut u8, target: *mut u8) -> Result<(), Errno> {
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

#[cfg(target_arch = "x86_64")]
#[repr(C)]
struct SavedRegsX86_64 {
    r9: u64,
    r8: u64,
    rcx: u64,
    rdx: u64,
    rsi: u64,
    rdi: u64,
    rax: u64,
}

#[cfg(target_arch = "x86_64")]
unsafe fn build_launcher_x86_64(buf: *mut u8, target: *mut u8) {
    let target_addr = target as usize as u64;
    let helper_addr = intercept_dispatch_and_get_next_hop_x86_64 as *const () as usize as u64;
    let bytes: [u8; 64] = [
        0x55,
        0x48,
        0x89,
        0xE5,
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
        0x83,
        0xEC,
        0x08,
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
        0x8D,
        0x74,
        0x24,
        0x08,
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
        0x48,
        0x83,
        0xC4,
        0x08,
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
        0xC9,
        0x41,
        0xFF,
        0xE3,
    ];
    ptr::copy_nonoverlapping(bytes.as_ptr(), buf, bytes.len());
    android::clear_icache(buf, bytes.len());
}

#[cfg(target_arch = "aarch64")]
unsafe extern "C" {
    fn srx_intercept_glue_arm64();
}

#[cfg(target_arch = "aarch64")]
unsafe fn build_launcher_arm64(buf: *mut u8, target: *mut u8) {
    let glue_addr = srx_intercept_glue_arm64 as *const () as usize as u64;
    let mut out = Vec::with_capacity(64);
    emit_arm64_u32(&mut out, 0xD100_43FF);
    emit_arm64_u32(&mut out, 0xA900_47F0);
    emit_arm64_u32(&mut out, ldr_x_pc(16, 12));
    emit_arm64_u32(&mut out, ldr_x_pc(17, 16));
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
fn ldr_x_pc(xt: u32, bytes: u32) -> u32 {
    let imm19 = bytes / 4;
    0x5800_0000 | ((imm19 & 0x7_FFFF) << 5) | (xt & 0x1F)
}

#[cfg(target_arch = "aarch64")]
#[repr(C)]
struct DispatchResultArm64 {
    next_hop: *mut c_void,
    flags: u64,
}

#[cfg(target_arch = "aarch64")]
extern "C" fn intercept_dispatch_and_get_next_hop_arm64(
    target: *mut c_void,
    ctx: *mut SrxInlineHookCpuContext,
) -> DispatchResultArm64 {
    let target_ptr = target as *mut u8;
    let ctx = unsafe { &mut *ctx };
    let flags = dispatch_with_ctx(target_ptr, ctx);
    let head = switch::head_replacement_of(target_ptr).unwrap_or(ptr::null());
    let next_hop = if has_entries(target_ptr) && !head.is_null() {
        head as *mut c_void
    } else {
        switch::trampoline_of(target_ptr)
            .map(|p| p as *mut c_void)
            .unwrap_or(ptr::null_mut())
    };
    DispatchResultArm64 {
        next_hop,
        flags: flags as u64,
    }
}

#[cfg(target_arch = "aarch64")]
global_asm!(
    r#"
.globl srx_intercept_glue_arm64
.balign 4
.type srx_intercept_glue_arm64, %function
srx_intercept_glue_arm64:
    sub sp, sp, #0x550
    stp x29, x30, [sp]
    mov x29, sp
    str x17, [sp, #0x330]

    stp x0,  x1,  [sp, #0x10]
    stp x2,  x3,  [sp, #0x20]
    stp x4,  x5,  [sp, #0x30]
    stp x6,  x7,  [sp, #0x40]
    stp x8,  x9,  [sp, #0x50]
    stp x10, x11, [sp, #0x60]
    stp x12, x13, [sp, #0x70]
    stp x14, x15, [sp, #0x80]
    ldr x14, [sp, #0x550]
    ldr x15, [sp, #0x558]
    stp x14, x15, [sp, #0x90]
    stp x18, x19, [sp, #0xA0]
    stp x20, x21, [sp, #0xB0]
    stp x22, x23, [sp, #0xC0]
    stp x24, x25, [sp, #0xD0]
    stp x26, x27, [sp, #0xE0]
    ldr x15, [sp]
    stp x28, x15, [sp, #0xF0]
    add x14, sp, #0x560
    stp x30, x14, [sp, #0x100]

    mrs x14, nzcv
    str x14, [sp, #0x118]

    stp q0,  q1,  [sp, #0x120]
    stp q2,  q3,  [sp, #0x140]
    stp q4,  q5,  [sp, #0x160]
    stp q6,  q7,  [sp, #0x180]
    stp q8,  q9,  [sp, #0x1A0]
    stp q10, q11, [sp, #0x1C0]
    stp q12, q13, [sp, #0x1E0]
    stp q14, q15, [sp, #0x200]
    stp q16, q17, [sp, #0x220]
    stp q18, q19, [sp, #0x240]
    stp q20, q21, [sp, #0x260]
    stp q22, q23, [sp, #0x280]
    stp q24, q25, [sp, #0x2A0]
    stp q26, q27, [sp, #0x2C0]
    stp q28, q29, [sp, #0x2E0]
    stp q30, q31, [sp, #0x300]

    add x14, sp, #0x340
    stp q0,  q1,  [x14, #0x00]
    stp q2,  q3,  [x14, #0x20]
    stp q4,  q5,  [x14, #0x40]
    stp q6,  q7,  [x14, #0x60]
    stp q8,  q9,  [x14, #0x80]
    stp q10, q11, [x14, #0xA0]
    stp q12, q13, [x14, #0xC0]
    stp q14, q15, [x14, #0xE0]
    stp q16, q17, [x14, #0x100]
    stp q18, q19, [x14, #0x120]
    stp q20, q21, [x14, #0x140]
    stp q22, q23, [x14, #0x160]
    stp q24, q25, [x14, #0x180]
    stp q26, q27, [x14, #0x1A0]
    stp q28, q29, [x14, #0x1C0]
    stp q30, q31, [x14, #0x1E0]

    mrs x15, fpsr
    str x15, [sp, #0x320]
    str x15, [x14, #0x200]
    mrs x15, fpcr
    str x15, [sp, #0x328]
    str x15, [x14, #0x208]

    ldr x0, [sp, #0x330]
    add x1, sp, #0x10
    bl {dispatch}
    str x0, [sp, #0x338]
    str x1, [sp, #0x330]

    ldr x14, [sp, #0x118]
    msr nzcv, x14

    ldp x0,  x1,  [sp, #0x10]
    ldp x2,  x3,  [sp, #0x20]
    ldp x4,  x5,  [sp, #0x30]
    ldp x6,  x7,  [sp, #0x40]
    ldp x8,  x9,  [sp, #0x50]
    ldp x10, x11, [sp, #0x60]
    ldp x12, x13, [sp, #0x70]
    ldp x14, x15, [sp, #0x80]
    ldp x16, x17, [sp, #0x90]
    ldp x18, x19, [sp, #0xA0]
    ldp x20, x21, [sp, #0xB0]
    ldp x22, x23, [sp, #0xC0]
    ldp x24, x25, [sp, #0xD0]
    ldp x26, x27, [sp, #0xE0]
    ldp x28, x29, [sp, #0xF0]
    ldr x30, [sp, #0x100]

    ldr x14, [sp, #0x330]
    tbz x14, #1, 1f

    ldp q0,  q1,  [sp, #0x120]
    ldp q2,  q3,  [sp, #0x140]
    ldp q4,  q5,  [sp, #0x160]
    ldp q6,  q7,  [sp, #0x180]
    ldp q8,  q9,  [sp, #0x1A0]
    ldp q10, q11, [sp, #0x1C0]
    ldp q12, q13, [sp, #0x1E0]
    ldp q14, q15, [sp, #0x200]
    ldp q16, q17, [sp, #0x220]
    ldp q18, q19, [sp, #0x240]
    ldp q20, q21, [sp, #0x260]
    ldp q22, q23, [sp, #0x280]
    ldp q24, q25, [sp, #0x2A0]
    ldp q26, q27, [sp, #0x2C0]
    ldp q28, q29, [sp, #0x2E0]
    ldp q30, q31, [sp, #0x300]
    ldr x14, [sp, #0x320]
    msr fpsr, x14
    ldr x14, [sp, #0x328]
    msr fpcr, x14
    b 2f

1:
    add x14, sp, #0x340
    ldp q0,  q1,  [x14, #0x00]
    ldp q2,  q3,  [x14, #0x20]
    ldp q4,  q5,  [x14, #0x40]
    ldp q6,  q7,  [x14, #0x60]
    ldp q8,  q9,  [x14, #0x80]
    ldp q10, q11, [x14, #0xA0]
    ldp q12, q13, [x14, #0xC0]
    ldp q14, q15, [x14, #0xE0]
    ldp q16, q17, [x14, #0x100]
    ldp q18, q19, [x14, #0x120]
    ldp q20, q21, [x14, #0x140]
    ldp q22, q23, [x14, #0x160]
    ldp q24, q25, [x14, #0x180]
    ldp q26, q27, [x14, #0x1A0]
    ldp q28, q29, [x14, #0x1C0]
    ldp q30, q31, [x14, #0x1E0]
    ldr x15, [x14, #0x200]
    msr fpsr, x15
    ldr x15, [x14, #0x208]
    msr fpcr, x15

2:
    ldr x16, [sp, #0x338]
    add sp, sp, #0x550
    add sp, sp, #0x10
    br x16
.size srx_intercept_glue_arm64, .-srx_intercept_glue_arm64
"#,
    dispatch = sym intercept_dispatch_and_get_next_hop_arm64,
);

#[cfg(target_arch = "x86_64")]
extern "C" fn intercept_dispatch_and_get_next_hop_x86_64(
    target: *mut c_void,
    saved: *mut SavedRegsX86_64,
) -> *mut c_void {
    let target_ptr = target as *mut u8;
    let mut ctx = SrxInlineHookCpuContext::default();
    let original_sp = unsafe { (saved as *const u8).add(mem::size_of::<SavedRegsX86_64>() + 8) };
    let saved = unsafe { &mut *saved };
    ctx.regs[0] = saved.rdi;
    ctx.regs[1] = saved.rsi;
    ctx.regs[2] = saved.rdx;
    ctx.regs[3] = saved.rcx;
    ctx.regs[4] = saved.r8;
    ctx.regs[5] = saved.r9;
    ctx.regs[30] = unsafe { *(original_sp as *const u64) };
    ctx.sp = original_sp as usize as u64;
    let _ = dispatch_with_ctx(target_ptr, &mut ctx);
    saved.rdi = ctx.regs[0];
    saved.rsi = ctx.regs[1];
    saved.rdx = ctx.regs[2];
    saved.rcx = ctx.regs[3];
    saved.r8 = ctx.regs[4];
    saved.r9 = ctx.regs[5];
    let head = switch::head_replacement_of(target_ptr).unwrap_or(ptr::null());
    if has_entries(target_ptr) && !head.is_null() {
        return head as *mut c_void;
    }
    switch::trampoline_of(target_ptr)
        .map(|p| p as *mut c_void)
        .unwrap_or(ptr::null_mut())
}
