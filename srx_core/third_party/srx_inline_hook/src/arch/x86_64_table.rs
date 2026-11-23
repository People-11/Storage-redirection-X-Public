use super::x86_64::InsnKind;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum ImmKind {
    None,
    I8,
    I16,
    I32,
    I64,
    OpSz16or32,
    OpSz16or32or64,
    Rel8,
    Rel32,
}

#[derive(Clone, Copy)]
pub(super) struct OpInfo {
    pub(super) modrm: bool,
    pub(super) imm: ImmKind,
    pub(super) kind: InsnKind,
    pub(super) supported: bool,
}

const fn sup(modrm: bool, imm: ImmKind, kind: InsnKind) -> OpInfo {
    OpInfo {
        modrm,
        imm,
        kind,
        supported: true,
    }
}

const UNSUP: OpInfo = OpInfo {
    modrm: false,
    imm: ImmKind::None,
    kind: InsnKind::Other,
    supported: false,
};

pub(super) const TABLE_1B: [OpInfo; 256] = build_1b_table();
pub(super) const TABLE_0F: [OpInfo; 256] = build_0f_table();

const fn build_1b_table() -> [OpInfo; 256] {
    let mut t = [UNSUP; 256];
    // ALU 家族：00..3F 按 8 字节步进，子块布局一致（ADD/OR/ADC/SBB/AND/SUB/XOR/CMP）
    let alu_starts = [0x00u8, 0x08, 0x10, 0x18, 0x20, 0x28, 0x30, 0x38];
    let mut a = 0;
    while a < alu_starts.len() {
        let s = alu_starts[a] as usize;
        t[s] = sup(true, ImmKind::None, InsnKind::Other);
        t[s + 1] = sup(true, ImmKind::None, InsnKind::Other);
        t[s + 2] = sup(true, ImmKind::None, InsnKind::Other);
        t[s + 3] = sup(true, ImmKind::None, InsnKind::Other);
        t[s + 4] = sup(false, ImmKind::I8, InsnKind::Other);
        t[s + 5] = sup(false, ImmKind::OpSz16or32, InsnKind::Other);
        a += 1;
    }
    // 50..5F push/pop rXX
    let mut i = 0;
    while i < 16 {
        t[0x50 + i] = sup(false, ImmKind::None, InsnKind::Other);
        i += 1;
    }
    t[0x63] = sup(true, ImmKind::None, InsnKind::Other);
    t[0x68] = sup(false, ImmKind::OpSz16or32, InsnKind::Other);
    t[0x69] = sup(true, ImmKind::OpSz16or32, InsnKind::Other);
    t[0x6A] = sup(false, ImmKind::I8, InsnKind::Other);
    t[0x6B] = sup(true, ImmKind::I8, InsnKind::Other);
    // 70..7F Jcc rel8
    let mut j = 0;
    while j < 16 {
        t[0x70 + j] = sup(false, ImmKind::Rel8, InsnKind::JccRel8);
        j += 1;
    }
    t[0x80] = sup(true, ImmKind::I8, InsnKind::Other);
    t[0x81] = sup(true, ImmKind::OpSz16or32, InsnKind::Other);
    t[0x83] = sup(true, ImmKind::I8, InsnKind::Other);
    t[0x84] = sup(true, ImmKind::None, InsnKind::Other);
    t[0x85] = sup(true, ImmKind::None, InsnKind::Other);
    t[0x86] = sup(true, ImmKind::None, InsnKind::Other);
    t[0x87] = sup(true, ImmKind::None, InsnKind::Other);
    t[0x88] = sup(true, ImmKind::None, InsnKind::Other);
    t[0x89] = sup(true, ImmKind::None, InsnKind::Other);
    t[0x8A] = sup(true, ImmKind::None, InsnKind::Other);
    t[0x8B] = sup(true, ImmKind::None, InsnKind::Other);
    t[0x8D] = sup(true, ImmKind::None, InsnKind::Other);
    t[0x8F] = sup(true, ImmKind::None, InsnKind::Other);
    t[0x90] = sup(false, ImmKind::None, InsnKind::Other);
    t[0x98] = sup(false, ImmKind::None, InsnKind::Other);
    t[0x99] = sup(false, ImmKind::None, InsnKind::Other);
    t[0x9C] = sup(false, ImmKind::None, InsnKind::Other);
    t[0x9D] = sup(false, ImmKind::None, InsnKind::Other);
    t[0xA8] = sup(false, ImmKind::I8, InsnKind::Other);
    t[0xA9] = sup(false, ImmKind::OpSz16or32, InsnKind::Other);
    // B0..B7 mov r8, imm8
    let mut k = 0;
    while k < 8 {
        t[0xB0 + k] = sup(false, ImmKind::I8, InsnKind::Other);
        k += 1;
    }
    // B8..BF mov r16/32/64, imm
    let mut kk = 0;
    while kk < 8 {
        t[0xB8 + kk] = sup(false, ImmKind::OpSz16or32or64, InsnKind::Other);
        kk += 1;
    }
    t[0xC0] = sup(true, ImmKind::I8, InsnKind::Other);
    t[0xC1] = sup(true, ImmKind::I8, InsnKind::Other);
    t[0xC2] = sup(false, ImmKind::I16, InsnKind::Ret);
    t[0xC3] = sup(false, ImmKind::None, InsnKind::Ret);
    t[0xC6] = sup(true, ImmKind::I8, InsnKind::Other);
    t[0xC7] = sup(true, ImmKind::OpSz16or32, InsnKind::Other);
    t[0xC9] = sup(false, ImmKind::None, InsnKind::Other);
    t[0xCC] = sup(false, ImmKind::None, InsnKind::Other);
    t[0xCD] = sup(false, ImmKind::I8, InsnKind::Other);
    t[0xD0] = sup(true, ImmKind::None, InsnKind::Other);
    t[0xD1] = sup(true, ImmKind::None, InsnKind::Other);
    t[0xD2] = sup(true, ImmKind::None, InsnKind::Other);
    t[0xD3] = sup(true, ImmKind::None, InsnKind::Other);
    t[0xE8] = sup(false, ImmKind::Rel32, InsnKind::CallRel32);
    t[0xE9] = sup(false, ImmKind::Rel32, InsnKind::JmpRel32);
    t[0xEB] = sup(false, ImmKind::Rel8, InsnKind::JmpRel8);
    t[0xF4] = sup(false, ImmKind::None, InsnKind::Other);
    t[0xF5] = sup(false, ImmKind::None, InsnKind::Other);
    t[0xF8] = sup(false, ImmKind::None, InsnKind::Other);
    t[0xF9] = sup(false, ImmKind::None, InsnKind::Other);
    t[0xFA] = sup(false, ImmKind::None, InsnKind::Other);
    t[0xFB] = sup(false, ImmKind::None, InsnKind::Other);
    t[0xFC] = sup(false, ImmKind::None, InsnKind::Other);
    t[0xFD] = sup(false, ImmKind::None, InsnKind::Other);
    t[0xFE] = sup(true, ImmKind::None, InsnKind::Other);
    t[0xFF] = sup(true, ImmKind::None, InsnKind::Other);
    t
}

const fn build_0f_table() -> [OpInfo; 256] {
    let mut t = [UNSUP; 256];
    t[0x05] = sup(false, ImmKind::None, InsnKind::Other);
    t[0x0B] = sup(false, ImmKind::None, InsnKind::Other);
    t[0x1E] = sup(true, ImmKind::None, InsnKind::Other);
    t[0x1F] = sup(true, ImmKind::None, InsnKind::Other);
    // 0F 10..17 / 28..2F SSE MOV 系列
    let mut m = 0;
    while m < 8 {
        t[0x10 + m] = sup(true, ImmKind::None, InsnKind::Other);
        t[0x28 + m] = sup(true, ImmKind::None, InsnKind::Other);
        m += 1;
    }
    // 0F 40..4F CMOVcc
    let mut c = 0;
    while c < 16 {
        t[0x40 + c] = sup(true, ImmKind::None, InsnKind::Other);
        c += 1;
    }
    // 0F 50..5F SSE 数学：movmskp*/sqrt/rcp/rsqrt/and*/or*/xor*/add*/mul*/cvt*/sub*/min*/div*/max*
    let mut n = 0;
    while n < 16 {
        t[0x50 + n] = sup(true, ImmKind::None, InsnKind::Other);
        n += 1;
    }
    // 0F 60..6F MMX/SSE2 打包与解包：punpck/packss/pcmp/movd/movq
    let mut p = 0;
    while p < 16 {
        t[0x60 + p] = sup(true, ImmKind::None, InsnKind::Other);
        p += 1;
    }
    // 0F 70 pshuf*（ModR/M + imm8）；71/72/73 shift immediate（ModR/M + imm8）
    t[0x70] = sup(true, ImmKind::I8, InsnKind::Other);
    t[0x71] = sup(true, ImmKind::I8, InsnKind::Other);
    t[0x72] = sup(true, ImmKind::I8, InsnKind::Other);
    t[0x73] = sup(true, ImmKind::I8, InsnKind::Other);
    // 0F 74..76 pcmpeqb/w/d；77 emms
    t[0x74] = sup(true, ImmKind::None, InsnKind::Other);
    t[0x75] = sup(true, ImmKind::None, InsnKind::Other);
    t[0x76] = sup(true, ImmKind::None, InsnKind::Other);
    t[0x77] = sup(false, ImmKind::None, InsnKind::Other);
    t[0x7E] = sup(true, ImmKind::None, InsnKind::Other);
    t[0x7F] = sup(true, ImmKind::None, InsnKind::Other);
    // 0F 80..8F Jcc rel32
    let mut j = 0;
    while j < 16 {
        t[0x80 + j] = sup(false, ImmKind::Rel32, InsnKind::JccRel32);
        j += 1;
    }
    // 0F 90..9F SETcc
    let mut s = 0;
    while s < 16 {
        t[0x90 + s] = sup(true, ImmKind::None, InsnKind::Other);
        s += 1;
    }
    t[0xA3] = sup(true, ImmKind::None, InsnKind::Other);
    t[0xA4] = sup(true, ImmKind::I8, InsnKind::Other);
    t[0xA5] = sup(true, ImmKind::None, InsnKind::Other);
    t[0xAB] = sup(true, ImmKind::None, InsnKind::Other);
    t[0xAC] = sup(true, ImmKind::I8, InsnKind::Other);
    t[0xAD] = sup(true, ImmKind::None, InsnKind::Other);
    t[0xAE] = sup(true, ImmKind::None, InsnKind::Other);
    t[0xAF] = sup(true, ImmKind::None, InsnKind::Other);
    t[0xB0] = sup(true, ImmKind::None, InsnKind::Other);
    t[0xB1] = sup(true, ImmKind::None, InsnKind::Other);
    t[0xB3] = sup(true, ImmKind::None, InsnKind::Other);
    t[0xB6] = sup(true, ImmKind::None, InsnKind::Other);
    t[0xB7] = sup(true, ImmKind::None, InsnKind::Other);
    t[0xBA] = sup(true, ImmKind::I8, InsnKind::Other);
    t[0xBB] = sup(true, ImmKind::None, InsnKind::Other);
    t[0xBC] = sup(true, ImmKind::None, InsnKind::Other);
    t[0xBD] = sup(true, ImmKind::None, InsnKind::Other);
    t[0xBE] = sup(true, ImmKind::None, InsnKind::Other);
    t[0xBF] = sup(true, ImmKind::None, InsnKind::Other);
    t[0xC0] = sup(true, ImmKind::None, InsnKind::Other);
    t[0xC1] = sup(true, ImmKind::None, InsnKind::Other);
    t[0xC2] = sup(true, ImmKind::I8, InsnKind::Other);
    t[0xC3] = sup(true, ImmKind::None, InsnKind::Other);
    t[0xC4] = sup(true, ImmKind::I8, InsnKind::Other);
    t[0xC5] = sup(true, ImmKind::I8, InsnKind::Other);
    t[0xC6] = sup(true, ImmKind::I8, InsnKind::Other);
    // 0F C8..CF bswap r32/r64
    let mut bs = 0;
    while bs < 8 {
        t[0xC8 + bs] = sup(false, ImmKind::None, InsnKind::Other);
        bs += 1;
    }
    // 0F D0..FF SSE2 / MMX 向量运算：全部 ModR/M 无 imm（0xFF 保留未用，屏蔽）
    let mut d = 0;
    while d < 0x30 {
        t[0xD0 + d] = sup(true, ImmKind::None, InsnKind::Other);
        d += 1;
    }
    t[0xFF] = UNSUP;
    t
}
