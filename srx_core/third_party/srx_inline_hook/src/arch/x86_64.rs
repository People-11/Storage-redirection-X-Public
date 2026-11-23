// x86_64 指令长度解码与重写器
// 未覆盖指令返回 Errno::RewriteUnsupported，禁止按原样放行

use crate::errno::Errno;

// 绝对跳转：FF 25 00 00 00 00 + 8 字节目标地址
pub const MIN_OVERWRITE_LEN: usize = 14;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InsnKind {
    Other,
    JmpRel8,
    JmpRel32,
    CallRel32,
    JccRel8,
    JccRel32,
    Ret,
    RipRelative,
}

#[derive(Debug, Clone, Copy)]
pub struct Insn {
    pub len: usize,
    pub has_66: bool,
    pub rex: Option<u8>,
    pub opcode: [u8; 3],
    pub opcode_len: u8,
    pub has_modrm: bool,
    pub modrm: u8,
    pub has_sib: bool,
    pub sib: u8,
    pub disp_off: u8,
    pub disp_size: u8,
    pub imm_off: u8,
    pub imm_size: u8,
    pub is_rip_relative: bool,
    pub kind: InsnKind,
}

#[derive(Debug, Clone)]
pub struct Rewritten {
    pub bytes: Vec<u8>,
    pub consumed: usize,
}

use super::x86_64_table::{ImmKind, OpInfo, TABLE_0F, TABLE_1B};

pub fn decode(bytes: &[u8]) -> Result<Insn, Errno> {
    if bytes.is_empty() {
        return Err(Errno::RewriteUnsupported);
    }

    // 64 位模式下 0xC4 / 0xC5 是 VEX 前缀，当前解码器显式拒绝
    // 避免按废弃 LES/LDS 误算长度
    if matches!(bytes[0], 0xC4 | 0xC5) {
        return Err(Errno::RewriteUnsupported);
    }
    // 0x62 在 64 位下是 EVEX 前缀（AVX-512）；单测已覆盖失败路径，保留拒绝
    if bytes[0] == 0x62 {
        return Err(Errno::RewriteUnsupported);
    }

    let mut cur = 0usize;
    let mut has_66 = false;

    // legacy prefixes：最多 4 组各 1 字节
    let mut prefix_count = 0;
    while cur < bytes.len() && prefix_count < 4 {
        match bytes[cur] {
            0xF0 | 0xF2 | 0xF3 | 0x26 | 0x2E | 0x36 | 0x3E | 0x64 | 0x65 => cur += 1,
            0x66 => {
                has_66 = true;
                cur += 1;
            }
            0x67 => cur += 1,
            _ => break,
        }
        prefix_count += 1;
    }

    // REX 前缀
    let rex = if cur < bytes.len() && (bytes[cur] & 0xF0) == 0x40 {
        let r = bytes[cur];
        cur += 1;
        Some(r)
    } else {
        None
    };
    let rex_w = rex.map(|r| r & 0x08 != 0).unwrap_or(false);

    if cur >= bytes.len() {
        return Err(Errno::RewriteUnsupported);
    }

    let mut opcode = [0u8; 3];
    let opcode_len;
    let info;

    let b0 = bytes[cur];
    opcode[0] = b0;
    cur += 1;

    if b0 == 0x0F {
        if cur >= bytes.len() {
            return Err(Errno::RewriteUnsupported);
        }
        let b1 = bytes[cur];
        opcode[1] = b1;
        cur += 1;
        if b1 == 0x38 || b1 == 0x3A {
            if cur >= bytes.len() {
                return Err(Errno::RewriteUnsupported);
            }
            opcode[2] = bytes[cur];
            cur += 1;
            // 三字节 opcode 默认 ModR/M，无立即数
            info = OpInfo {
                modrm: true,
                imm: ImmKind::None,
                kind: InsnKind::Other,
                supported: true,
            };
            opcode_len = 3;
        } else {
            info = TABLE_0F[b1 as usize];
            opcode_len = 2;
        }
    } else {
        info = TABLE_1B[b0 as usize];
        opcode_len = 1;
    }

    if !info.supported {
        return Err(Errno::RewriteUnsupported);
    }

    let mut has_modrm = false;
    let mut modrm = 0u8;
    let mut has_sib = false;
    let mut sib = 0u8;
    let mut disp_off = 0u8;
    let mut disp_size = 0u8;
    let mut is_rip_relative = false;

    if info.modrm {
        if cur >= bytes.len() {
            return Err(Errno::RewriteUnsupported);
        }
        modrm = bytes[cur];
        has_modrm = true;
        cur += 1;
        let mod_f = modrm >> 6;
        let rm = modrm & 0b111;

        if mod_f != 0b11 && rm == 0b100 {
            // SIB
            if cur >= bytes.len() {
                return Err(Errno::RewriteUnsupported);
            }
            sib = bytes[cur];
            has_sib = true;
            cur += 1;
            if mod_f == 0b00 && (sib & 0b111) == 0b101 {
                disp_off = cur as u8;
                disp_size = 4;
                cur += 4;
            }
        } else if mod_f == 0b00 && rm == 0b101 {
            // 64 位模式：[RIP + disp32]
            disp_off = cur as u8;
            disp_size = 4;
            is_rip_relative = true;
            cur += 4;
        }
        if mod_f == 0b01 {
            disp_off = cur as u8;
            disp_size = 1;
            cur += 1;
        } else if mod_f == 0b10 {
            disp_off = cur as u8;
            disp_size = 4;
            cur += 4;
        }

        if cur > bytes.len() {
            return Err(Errno::RewriteUnsupported);
        }
    }

    let imm_off = cur as u8;
    let imm_size: u8 = match info.imm {
        ImmKind::None => 0,
        ImmKind::I8 | ImmKind::Rel8 => 1,
        ImmKind::I16 => 2,
        ImmKind::I32 | ImmKind::Rel32 => 4,
        ImmKind::I64 => 8,
        ImmKind::OpSz16or32 => {
            if has_66 {
                2
            } else {
                4
            }
        }
        ImmKind::OpSz16or32or64 => {
            if rex_w {
                8
            } else if has_66 {
                2
            } else {
                4
            }
        }
    };
    cur += imm_size as usize;

    if cur > bytes.len() {
        return Err(Errno::RewriteUnsupported);
    }

    let mut kind = info.kind;
    if kind == InsnKind::Other && is_rip_relative {
        kind = InsnKind::RipRelative;
    }

    Ok(Insn {
        len: cur,
        has_66,
        rex,
        opcode,
        opcode_len,
        has_modrm,
        modrm,
        has_sib,
        sib,
        disp_off,
        disp_size,
        imm_off,
        imm_size,
        is_rip_relative,
        kind,
    })
}

// rewrite 将 bytes 自 pc_src 起至少 MIN_OVERWRITE_LEN 字节的指令序列重定位到 pc_dst
// 返回生成的重定位字节与在源端消耗的字节数
pub fn rewrite(bytes: &[u8], pc_src: u64, pc_dst: u64) -> Result<Rewritten, Errno> {
    // Phase 1：预扫描每条原指令，估算重写后长度；用于 fix_addr 映射 src_off → new_off
    // 对齐 arm64 rewriter 的 two-phase 结构：JMP/JCC 目标落在 prologue 内时需 fix
    let mut infos: Vec<InsnInfo> = Vec::with_capacity(8);
    let mut consumed = 0usize;
    let mut new_total = 0usize;
    while consumed < MIN_OVERWRITE_LEN {
        if consumed >= bytes.len() {
            return Err(Errno::HookRewriteFailed);
        }
        let insn = decode(&bytes[consumed..])?;
        let new_len = rewritten_len(&insn);
        infos.push(InsnInfo {
            src_off: consumed,
            orig_len: insn.len,
            new_off: new_total,
            new_len,
        });
        consumed += insn.len;
        new_total += new_len;
    }

    // Phase 2：实际重写；JMP/JCC/Call target 落在 [pc_src, pc_src + consumed) 时 fix 到 pc_dst 内
    let context = RewriteContext {
        pc_src,
        pc_dst,
        consumed,
        infos: &infos,
    };
    let mut out: Vec<u8> = Vec::with_capacity(new_total);
    for info in &infos {
        let raw = &bytes[info.src_off..info.src_off + info.orig_len];
        let insn = decode(raw)?;
        let src = pc_src.wrapping_add(info.src_off as u64);
        let dst = pc_dst.wrapping_add(info.new_off as u64);
        rewrite_one(raw, &insn, src, dst, &context, &mut out)?;
    }

    Ok(Rewritten {
        bytes: out,
        consumed,
    })
}

// 重写后单条指令字节数：与 rewrite_one 实际 emit 保持一致
fn rewritten_len(insn: &Insn) -> usize {
    match insn.kind {
        InsnKind::Other | InsnKind::Ret | InsnKind::RipRelative => insn.len,
        InsnKind::JmpRel8 | InsnKind::JmpRel32 => MIN_OVERWRITE_LEN,
        InsnKind::JccRel8 | InsnKind::JccRel32 => 2 + MIN_OVERWRITE_LEN,
        InsnKind::CallRel32 => 16, // 8 字节 CALL+JMP 前导 + 8 字节目标
    }
}

// target 落在 prologue 内时按指令边界查表，命中→fix 到 trampoline 内；未对齐→Err
// 对齐 arm64 sh_a64_fix_addr：仅允许跳到指令起点，跳到指令中间视为不可重写
struct RewriteContext<'a> {
    pc_src: u64,
    pc_dst: u64,
    consumed: usize,
    infos: &'a [InsnInfo],
}

fn fix_target(target: u64, context: &RewriteContext<'_>) -> Result<u64, Errno> {
    let RewriteContext {
        pc_src,
        pc_dst,
        consumed,
        infos,
    } = *context;
    let lo = pc_src;
    let hi = pc_src.wrapping_add(consumed as u64);
    if target < lo || target >= hi {
        return Ok(target);
    }
    let off = (target - lo) as usize;
    for info in infos {
        if info.src_off == off {
            return Ok(pc_dst.wrapping_add(info.new_off as u64));
        }
    }
    // target 指向某指令中间，语义无法保留
    Err(Errno::RewriteUnsupported)
}

struct InsnInfo {
    src_off: usize,
    orig_len: usize,
    new_off: usize,
    new_len: usize,
}

fn rewrite_one(
    raw: &[u8],
    insn: &Insn,
    src: u64,
    dst: u64,
    context: &RewriteContext<'_>,
    out: &mut Vec<u8>,
) -> Result<(), Errno> {
    match insn.kind {
        InsnKind::Other | InsnKind::Ret => {
            out.extend_from_slice(raw);
            Ok(())
        }
        InsnKind::RipRelative => {
            // disp_new = disp_old + (src - dst)，保持 [RIP+disp] 指向同一地址
            let disp_idx = insn.disp_off as usize;
            let disp_old = i32::from_le_bytes([
                raw[disp_idx],
                raw[disp_idx + 1],
                raw[disp_idx + 2],
                raw[disp_idx + 3],
            ]);
            let delta = (src as i128) - (dst as i128);
            let new_disp = (disp_old as i128) + delta;
            if !(i32::MIN as i128..=i32::MAX as i128).contains(&new_disp) {
                return Err(Errno::HookRewriteFailed);
            }
            out.extend_from_slice(&raw[..disp_idx]);
            out.extend_from_slice(&(new_disp as i32).to_le_bytes());
            out.extend_from_slice(&raw[disp_idx + 4..]);
            Ok(())
        }
        InsnKind::JmpRel8 | InsnKind::JmpRel32 => {
            let target = resolve_rel_target(insn, raw, src)?;
            let target = fix_target(target, context)?;
            let mut abs = [0u8; MIN_OVERWRITE_LEN];
            make_absolute_jump(target as *const u8, &mut abs)?;
            out.extend_from_slice(&abs);
            Ok(())
        }
        InsnKind::JccRel8 | InsnKind::JccRel32 => {
            // 反向 Jcc 跳过 14 字节绝对跳转
            let target = resolve_rel_target(insn, raw, src)?;
            let target = fix_target(target, context)?;
            let cc = match insn.kind {
                InsnKind::JccRel8 => insn.opcode[0] & 0x0F,
                InsnKind::JccRel32 => insn.opcode[1] & 0x0F,
                _ => return Err(Errno::HookRewriteFailed),
            };
            let inverted = cc ^ 0x01;
            out.push(0x70 | inverted);
            out.push(MIN_OVERWRITE_LEN as u8);
            let mut abs = [0u8; MIN_OVERWRITE_LEN];
            make_absolute_jump(target as *const u8, &mut abs)?;
            out.extend_from_slice(&abs);
            Ok(())
        }
        InsnKind::CallRel32 => {
            // call qword ptr [rip+2] 后接 jmp +8，跳过内嵌目标地址
            // 布局：FF 15 02 00 00 00 EB 08 <8 byte target>
            let target = resolve_rel_target(insn, raw, src)?;
            let target = fix_target(target, context)?;
            out.extend_from_slice(&[0xFF, 0x15, 0x02, 0x00, 0x00, 0x00, 0xEB, 0x08]);
            out.extend_from_slice(&target.to_le_bytes());
            Ok(())
        }
    }
}

fn resolve_rel_target(insn: &Insn, raw: &[u8], src: u64) -> Result<u64, Errno> {
    let next_rip = src.wrapping_add(insn.len as u64);
    let off: i64 = match insn.imm_size {
        1 => raw[insn.imm_off as usize] as i8 as i64,
        4 => i32::from_le_bytes([
            raw[insn.imm_off as usize],
            raw[insn.imm_off as usize + 1],
            raw[insn.imm_off as usize + 2],
            raw[insn.imm_off as usize + 3],
        ]) as i64,
        _ => return Err(Errno::HookRewriteFailed),
    };
    Ok(next_rip.wrapping_add(off as u64))
}

// 写入绝对跳转：FF 25 00 00 00 00 + 8 字节目标
pub fn make_absolute_jump(to: *const u8, buf: &mut [u8]) -> Result<(), Errno> {
    if buf.len() < MIN_OVERWRITE_LEN {
        return Err(Errno::InvalidArg);
    }
    buf[0] = 0xFF;
    buf[1] = 0x25;
    buf[2] = 0x00;
    buf[3] = 0x00;
    buf[4] = 0x00;
    buf[5] = 0x00;
    buf[6..14].copy_from_slice(&(to as u64).to_le_bytes());
    Ok(())
}
