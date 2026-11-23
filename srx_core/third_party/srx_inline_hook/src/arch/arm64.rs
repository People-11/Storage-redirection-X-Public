// arm64 指令分类 + PC 相对重写
// 覆盖 ADR / ADRP / B / BL / B.cond / CBZ / CBNZ / TBZ / TBNZ / LDR literal 的重定位

use crate::errno::Errno;

// 绝对跳转：LDR X16,[PC+8] + RET X16 + 8 字节目标。
// RET 不要求目标具备 BTI 标记。
pub const MIN_OVERWRITE_LEN: usize = 16;
// 备份覆盖带对齐填充的 24 字节绝对跳转；只改写 16 字节，避免覆盖邻接短函数。
pub const RELOCATION_LEN: usize = 24;

pub fn make_relative_jump(from: *const u8, to: *const u8, buf: &mut [u8]) -> Result<(), Errno> {
    let offset = (to as usize as i128) - (from as usize as i128);
    if buf.len() < MIN_OVERWRITE_LEN
        || offset % 4 != 0
        || !(-(1 << 27)..(1 << 27)).contains(&offset)
    {
        return Err(Errno::HookRewriteFailed);
    }
    let instruction = 0x1400_0000 | (((offset / 4) as u32) & 0x03ff_ffff);
    buf[..4].copy_from_slice(&instruction.to_le_bytes());
    for bytes in buf[4..MIN_OVERWRITE_LEN].as_chunks_mut::<4>().0 {
        bytes.copy_from_slice(&0xd503_201fu32.to_le_bytes());
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InsnKind {
    Other,
    Adr,
    Adrp,
    B,
    Bl,
    BCond,
    Cbz,
    Cbnz,
    Tbz,
    Tbnz,
    LdrLiteral,
    LdrSimdLiteral,
    PrfmLiteral,
}

#[derive(Debug, Clone, Copy)]
pub struct Insn {
    pub raw: u32,
    pub kind: InsnKind,
}

#[derive(Debug, Clone)]
pub struct Rewritten {
    pub bytes: Vec<u8>,
    pub consumed: usize,
    // 每条原指令重写后的字节数；fix_addr 查表使用
    pub inst_lens: Vec<usize>,
}

pub fn decode(raw: u32) -> Insn {
    Insn {
        raw,
        kind: classify(raw),
    }
}

fn classify(raw: u32) -> InsnKind {
    // ADR / ADRP：bit[28:24]=10000；bit31=0 → ADR，1 → ADRP
    if (raw & 0x1F00_0000) == 0x1000_0000 {
        return if raw & 0x8000_0000 == 0 {
            InsnKind::Adr
        } else {
            InsnKind::Adrp
        };
    }
    // B / BL：bit[30:26]=00101；bit31=0 → B，1 → BL
    if (raw & 0x7C00_0000) == 0x1400_0000 {
        return if raw & 0x8000_0000 == 0 {
            InsnKind::B
        } else {
            InsnKind::Bl
        };
    }
    // B.cond：bit[31:24]=0x54，bit4=0
    if (raw & 0xFF00_0010) == 0x5400_0000 {
        return InsnKind::BCond;
    }
    // CBZ/CBNZ/TBZ/TBNZ：bit[30:24] 四组取值
    match raw & 0x7F00_0000 {
        0x3400_0000 => return InsnKind::Cbz,
        0x3500_0000 => return InsnKind::Cbnz,
        0x3600_0000 => return InsnKind::Tbz,
        0x3700_0000 => return InsnKind::Tbnz,
        _ => {}
    }
    // PC 相对 literal load 家族：bit[29:27]=011，bit[25:24]=00
    // 按 opc(bit[31:30]) 与 V(bit[26]) 细分：GP / SIMD / PRFM，余下 reserved 归 Other
    if (raw & 0x3B00_0000) == 0x1800_0000 {
        let opc = raw >> 30;
        let v = (raw >> 26) & 1;
        return match (opc, v) {
            (0b00, 0) | (0b01, 0) | (0b10, 0) => InsnKind::LdrLiteral,
            (0b11, 0) => InsnKind::PrfmLiteral,
            (0b00, 1) | (0b01, 1) | (0b10, 1) => InsnKind::LdrSimdLiteral,
            _ => InsnKind::Other,
        };
    }
    InsnKind::Other
}

pub fn rewrite(bytes: &[u8], pc_src: u64, pc_dst: u64) -> Result<Rewritten, Errno> {
    if bytes.len() < RELOCATION_LEN {
        return Err(Errno::HookRewriteFailed);
    }
    // Phase 1：解码 prologue 每条指令、预算重写后长度，供 fix_addr 查表
    let total_insns = RELOCATION_LEN / 4;
    let mut insns: Vec<Insn> = Vec::with_capacity(total_insns);
    let mut inst_lens: Vec<usize> = Vec::with_capacity(total_insns);
    for i in 0..total_insns {
        let off = i * 4;
        let raw = u32::from_le_bytes([bytes[off], bytes[off + 1], bytes[off + 2], bytes[off + 3]]);
        let insn = decode(raw);
        inst_lens.push(rewrite_len_for(insn.kind));
        insns.push(insn);
    }

    let ctx = RewriteCtx {
        start_addr: pc_src,
        end_addr: pc_src.wrapping_add((total_insns * 4) as u64),
        buf: pc_dst,
        inst_lens: &inst_lens,
    };

    // Phase 2：生成重写字节；PC 相对目标在 prologue 内时走 fix_addr
    let mut out: Vec<u8> = Vec::with_capacity(MIN_OVERWRITE_LEN * 4);
    for (i, insn) in insns.iter().enumerate() {
        let src = pc_src.wrapping_add((i * 4) as u64);
        rewrite_one(insn, src, &ctx, &mut out)?;
    }

    Ok(Rewritten {
        bytes: out,
        consumed: total_insns * 4,
        inst_lens,
    })
}

// 重写后字节数预表：对齐各 rewrite 函数的实际产出
fn rewrite_len_for(kind: InsnKind) -> usize {
    match kind {
        InsnKind::Other => 4,
        InsnKind::Adr | InsnKind::Adrp => 16,
        InsnKind::B => 16,
        InsnKind::Bl => 20,
        InsnKind::BCond => 20,
        InsnKind::Cbz | InsnKind::Cbnz => 20,
        InsnKind::Tbz | InsnKind::Tbnz => 20,
        InsnKind::LdrLiteral => 20,
        InsnKind::LdrSimdLiteral | InsnKind::PrfmLiteral => 28,
    }
}

struct RewriteCtx<'a> {
    start_addr: u64,
    end_addr: u64,
    buf: u64,
    inst_lens: &'a [usize],
}

impl RewriteCtx<'_> {
    fn in_prologue(&self, addr: u64) -> bool {
        addr >= self.start_addr && addr < self.end_addr
    }

    // 把 PC 相对目标 addr 修正到 trampoline 内对应字节
    // 仅应在 in_prologue(addr) 为真时调用
    fn fix_addr(&self, addr: u64) -> u64 {
        debug_assert!(self.in_prologue(addr));
        let idx = ((addr - self.start_addr) / 4) as usize;
        let offset: usize = self.inst_lens[..idx].iter().sum();
        self.buf.wrapping_add(offset as u64)
    }
}

fn rewrite_one(insn: &Insn, src: u64, ctx: &RewriteCtx, out: &mut Vec<u8>) -> Result<(), Errno> {
    match insn.kind {
        InsnKind::Other => {
            emit_u32(out, insn.raw);
            Ok(())
        }
        InsnKind::Adr => rewrite_adr(insn.raw, src, ctx, out),
        InsnKind::Adrp => rewrite_adrp(insn.raw, src, ctx, out),
        InsnKind::B => rewrite_b(insn.raw, src, ctx, out),
        InsnKind::Bl => rewrite_bl(insn.raw, src, ctx, out),
        InsnKind::BCond => rewrite_bcond(insn.raw, src, ctx, out),
        InsnKind::Cbz | InsnKind::Cbnz => rewrite_cbz_cbnz(insn.raw, src, ctx, out),
        InsnKind::Tbz | InsnKind::Tbnz => rewrite_tbz_tbnz(insn.raw, src, ctx, out),
        InsnKind::LdrLiteral => rewrite_ldr_literal(insn.raw, src, ctx, out),
        InsnKind::LdrSimdLiteral => rewrite_ldr_simd(insn.raw, src, ctx, out),
        InsnKind::PrfmLiteral => rewrite_prfm(insn.raw, src, ctx, out),
    }
}

// 符号扩展：保留 value 低 bits 位的语义，扩展到 i64
fn sign_extend(value: u64, bits: u32) -> i64 {
    let shift = 64 - bits;
    ((value << shift) as i64) >> shift
}

// ADR/ADRP imm21：immhi(bit[23:5]) << 2 | immlo(bit[30:29])
fn extract_adr_imm21(raw: u32) -> i64 {
    let immlo = ((raw >> 29) & 0b11) as u64;
    let immhi = ((raw >> 5) & 0x7_FFFF) as u64;
    sign_extend((immhi << 2) | immlo, 21)
}

// B/BL imm26：bit[25:0]，*4 得到字节偏移
fn extract_b_offset(raw: u32) -> i64 {
    let imm26 = (raw & 0x03FF_FFFF) as u64;
    sign_extend(imm26, 26) << 2
}

// B.cond / CBZ / CBNZ / LDR literal imm19：bit[23:5]，*4
fn extract_imm19_offset(raw: u32) -> i64 {
    let imm19 = ((raw >> 5) & 0x7_FFFF) as u64;
    sign_extend(imm19, 19) << 2
}

// TBZ/TBNZ imm14：bit[18:5]，*4
fn extract_imm14_offset(raw: u32) -> i64 {
    let imm14 = ((raw >> 5) & 0x3FFF) as u64;
    sign_extend(imm14, 14) << 2
}

fn emit_u32(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_le_bytes());
}

fn emit_u64(out: &mut Vec<u8>, v: u64) {
    out.extend_from_slice(&v.to_le_bytes());
}

// LDR Xt, [PC+bytes]：imm19 = bytes/4，encoding = 0x5800_0000 | (imm19<<5) | Xt
fn ldr_x_pc(xt: u32, bytes: u32) -> u32 {
    let imm19 = bytes / 4;
    0x5800_0000 | ((imm19 & 0x7_FFFF) << 5) | (xt & 0x1F)
}

// RET X16 = 0xD65F0200；兼容 BTI（BR 要求目标具 BTI 指令，RET 无此约束）
const RET_X16: u32 = 0xD65F_0200;

// 写入 16 字节绝对跳：LDR X16,[PC+8]; RET X16; .quad target
fn emit_abs_jump(out: &mut Vec<u8>, target: u64) {
    emit_u32(out, ldr_x_pc(16, 8));
    emit_u32(out, RET_X16);
    emit_u64(out, target);
}

// ADR 目标在 prologue 内时拒绝：地址值后续可能参与算术
// trampoline 重写长度不一，非指令起点无法可靠映射
fn rewrite_adr(raw: u32, src: u64, ctx: &RewriteCtx, out: &mut Vec<u8>) -> Result<(), Errno> {
    let rd = raw & 0x1F;
    let target = src.wrapping_add(extract_adr_imm21(raw) as u64);
    if ctx.in_prologue(target) {
        return Err(Errno::RewriteUnsupported);
    }
    emit_u32(out, ldr_x_pc(rd, 8));
    emit_u32(out, 0x1400_0003); // B #+12
    emit_u64(out, target);
    Ok(())
}

// ADRP Xn, #label → 16 字节：页对齐目标
// 同 ADR：prologue 内落点禁止 fix_addr，返回 RewriteUnsupported
fn rewrite_adrp(raw: u32, src: u64, ctx: &RewriteCtx, out: &mut Vec<u8>) -> Result<(), Errno> {
    let rd = raw & 0x1F;
    let page_base = src & !0xFFF;
    let target = page_base.wrapping_add((extract_adr_imm21(raw) << 12) as u64);
    if ctx.in_prologue(target) {
        return Err(Errno::RewriteUnsupported);
    }
    emit_u32(out, ldr_x_pc(rd, 8));
    emit_u32(out, 0x1400_0003);
    emit_u64(out, target);
    Ok(())
}

// B label → 16 字节绝对跳
fn rewrite_b(raw: u32, src: u64, ctx: &RewriteCtx, out: &mut Vec<u8>) -> Result<(), Errno> {
    let mut target = src.wrapping_add(extract_b_offset(raw) as u64);
    if ctx.in_prologue(target) {
        target = ctx.fix_addr(target);
    }
    emit_abs_jump(out, target);
    Ok(())
}

// BL label → 20 字节：LDR X16,[PC+12]; ADR X30,#16; RET X16; .quad target
// ADR 将 X30 置为本序列之后的地址，callee RET 时回到 trampoline 下一条
fn rewrite_bl(raw: u32, src: u64, ctx: &RewriteCtx, out: &mut Vec<u8>) -> Result<(), Errno> {
    let mut target = src.wrapping_add(extract_b_offset(raw) as u64);
    if ctx.in_prologue(target) {
        target = ctx.fix_addr(target);
    }
    emit_u32(out, ldr_x_pc(16, 12));
    emit_u32(out, 0x1000_009E); // ADR X30, #16
    emit_u32(out, RET_X16);
    emit_u64(out, target);
    Ok(())
}

// B.cond label → 20 字节：反向 B.cond 跳过 abs jump；skip 距离 16(abs_jump)+4 换算 imm19=5
fn rewrite_bcond(raw: u32, src: u64, ctx: &RewriteCtx, out: &mut Vec<u8>) -> Result<(), Errno> {
    let mut target = src.wrapping_add(extract_imm19_offset(raw) as u64);
    if ctx.in_prologue(target) {
        target = ctx.fix_addr(target);
    }
    let cond = raw & 0x0F;
    let inverted_cond = cond ^ 0x1;
    let bcond_skip = 0x5400_0000 | (5 << 5) | inverted_cond;
    emit_u32(out, bcond_skip);
    emit_abs_jump(out, target);
    Ok(())
}

// CBZ/CBNZ Xt, label → 20 字节：翻转 op(bit24)，imm19=5 跳过 16 字节 abs jump
fn rewrite_cbz_cbnz(raw: u32, src: u64, ctx: &RewriteCtx, out: &mut Vec<u8>) -> Result<(), Errno> {
    let mut target = src.wrapping_add(extract_imm19_offset(raw) as u64);
    if ctx.in_prologue(target) {
        target = ctx.fix_addr(target);
    }
    let imm19_mask = 0x7_FFFFu32 << 5;
    let skip = ((raw ^ 0x0100_0000) & !imm19_mask) | (5 << 5);
    emit_u32(out, skip);
    emit_abs_jump(out, target);
    Ok(())
}

// TBZ/TBNZ Xt, #bit, label → 20 字节：翻转 op(bit24)，imm14=5 跳过 16 字节 abs jump
fn rewrite_tbz_tbnz(raw: u32, src: u64, ctx: &RewriteCtx, out: &mut Vec<u8>) -> Result<(), Errno> {
    let mut target = src.wrapping_add(extract_imm14_offset(raw) as u64);
    if ctx.in_prologue(target) {
        target = ctx.fix_addr(target);
    }
    let imm14_mask = 0x3FFFu32 << 5;
    let skip = ((raw ^ 0x0100_0000) & !imm14_mask) | (5 << 5);
    emit_u32(out, skip);
    emit_abs_jump(out, target);
    Ok(())
}

// LDR literal 目标在 prologue 内时拒绝：读到的是改写字节而非常量
// X16 为 AAPCS64 IP 临时寄存器，可用于中转地址
fn rewrite_ldr_literal(
    raw: u32,
    src: u64,
    ctx: &RewriteCtx,
    out: &mut Vec<u8>,
) -> Result<(), Errno> {
    let target = src.wrapping_add(extract_imm19_offset(raw) as u64);
    if ctx.in_prologue(target) {
        return Err(Errno::RewriteUnsupported);
    }
    let rt = raw & 0x1F;
    let inner = match raw >> 24 {
        0x58 => 0xF940_0000 | (16 << 5) | rt, // LDR Xt, [X16]
        0x18 => 0xB940_0000 | (16 << 5) | rt, // LDR Wt, [X16]
        0x98 => 0xB980_0000 | (16 << 5) | rt, // LDRSW Xt, [X16]
        _ => return Err(Errno::RewriteUnsupported),
    };
    emit_u32(out, ldr_x_pc(16, 12));
    emit_u32(out, inner);
    emit_u32(out, 0x1400_0003); // B #+12
    emit_u64(out, target);
    Ok(())
}

// LDR S/D/Q Rt, label → 28 字节：STP X16,X17 暂存 + LDR X17 取址 + SIMD load + 恢复 X17
// 目标落在 prologue 内 → 读到跳转字节非常量 → 拒绝
fn rewrite_ldr_simd(raw: u32, src: u64, ctx: &RewriteCtx, out: &mut Vec<u8>) -> Result<(), Errno> {
    let target = src.wrapping_add(extract_imm19_offset(raw) as u64);
    if ctx.in_prologue(target) {
        return Err(Errno::RewriteUnsupported);
    }
    let rt = raw & 0x1F;
    let opc = raw >> 30;
    let inner = match opc {
        0b00 => 0xBD40_0220 | rt, // LDR St, [X17]
        0b01 => 0xFD40_0220 | rt, // LDR Dt, [X17]
        0b10 => 0x3DC0_0220 | rt, // LDR Qt, [X17]
        _ => return Err(Errno::RewriteUnsupported),
    };
    emit_simd_or_prfm_seq(out, inner, target);
    Ok(())
}

// PRFM op, label → 28 字节：同 SIMD 结构；PRFM 无副作用，允许内部目标 fix_addr
fn rewrite_prfm(raw: u32, src: u64, ctx: &RewriteCtx, out: &mut Vec<u8>) -> Result<(), Errno> {
    let mut target = src.wrapping_add(extract_imm19_offset(raw) as u64);
    if ctx.in_prologue(target) {
        target = ctx.fix_addr(target);
    }
    let rt = raw & 0x1F;
    let inner = 0xF980_0220 | rt; // PRFM Rt, [X17]
    emit_simd_or_prfm_seq(out, inner, target);
    Ok(())
}

// 28 字节公共序列：STP X16,X17,[SP,-0x10]; LDR X17,[PC+16]; inner; LDR X17,[SP,-8]; B #+12; .quad
fn emit_simd_or_prfm_seq(out: &mut Vec<u8>, inner: u32, target: u64) {
    emit_u32(out, 0xA93F_47F0); // STP X16, X17, [SP, #-0x10]
    emit_u32(out, 0x5800_0091); // LDR X17, [PC+16]
    emit_u32(out, inner);
    emit_u32(out, 0xF85F_83F1); // LDR X17, [SP, #-0x8]
    emit_u32(out, 0x1400_0003); // B #+12
    emit_u64(out, target);
}

pub fn make_absolute_jump(to: *const u8, buf: &mut [u8]) -> Result<(), Errno> {
    if buf.len() < MIN_OVERWRITE_LEN {
        return Err(Errno::InvalidArg);
    }
    buf[0..4].copy_from_slice(&0x5800_0050u32.to_le_bytes());
    buf[4..8].copy_from_slice(&RET_X16.to_le_bytes());
    buf[8..16].copy_from_slice(&(to as u64).to_le_bytes());
    Ok(())
}
