// ELF 符号哈希算法，支持 DT_HASH 和 DT_GNU_HASH 两种查找方式

// ELF HASH 算法，用于 DT_HASH 符号查找
pub(super) fn elf_hash(name: &[u8]) -> u32 {
    let mut h: u32 = 0;
    let mut g: u32;
    for &ch in name {
        h = (h << 4).wrapping_add(ch as u32);
        g = h & 0xf000_0000;
        h ^= g;
        h ^= g >> 24;
    }
    h
}

// GNU HASH 算法，用于 DT_GNU_HASH 符号查找
pub(super) fn elf_gnu_hash(name: &[u8]) -> u32 {
    let mut h: u32 = 5381;
    for &ch in name {
        h = h.wrapping_add((h << 5).wrapping_add(ch as u32));
    }
    h
}
