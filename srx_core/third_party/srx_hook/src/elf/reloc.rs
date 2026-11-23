// 从 ELF64 重定位条目的 r_info 字段提取符号索引和重定位类型

use super::ElfXword;

// 提取高 32 位作为符号索引
pub(super) fn elf_r_sym(info: ElfXword) -> u32 {
    (info >> 32) as u32
}

// 提取低 32 位作为重定位类型
pub(super) fn elf_r_type(info: ElfXword) -> u32 {
    (info & 0xffff_ffff) as u32
}
