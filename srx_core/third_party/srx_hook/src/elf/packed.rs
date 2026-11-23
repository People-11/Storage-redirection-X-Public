// Android packed relocation 解码，处理 APS2 格式的 SLEB128 编码重定位表

use crate::errno::Errno;
use crate::log;
use std::mem;

use super::ElfXword;

// SLEB128 变长整数解码器，逐字节读取并拼接
struct Sleb128Decoder {
    cur: *const u8,
    end: *const u8,
}

impl Sleb128Decoder {
    unsafe fn new(addr: usize, size: usize) -> Self {
        let cur = addr as *const u8;
        let end = cur.add(size);
        Self { cur, end }
    }

    unsafe fn next(&mut self) -> Result<usize, Errno> {
        let mut value: usize = 0;
        let size = mem::size_of::<usize>() * 8;
        let mut shift = 0usize;
        let mut byte: u8;

        // 每次取 7 位有效数据，最高位为续传标志
        loop {
            if self.cur >= self.end {
                return Err(Errno::Format);
            }
            byte = *self.cur;
            self.cur = self.cur.add(1);
            value |= ((byte & 0x7f) as usize) << shift;
            shift += 7;
            if (byte & 0x80) == 0 {
                break;
            }
        }

        // 符号扩展：最后一个字节的第 6 位为符号位
        if shift < size && (byte & 0x40) != 0 {
            value |= (!0usize) << shift;
        }

        Ok(value)
    }
}

// Android packed relocation 迭代器，按分组逐条产出重定位条目
pub(super) struct PackedRelocIterator {
    decoder: Sleb128Decoder,
    relocation_count: usize,
    group_size: usize,
    group_flags: usize,
    group_r_offset_delta: usize,
    relocation_index: usize,
    relocation_group_index: usize,
    r_offset: usize,
    r_info: usize,
    r_addend: isize,
    is_use_rela: bool,
}

// 解码后的单条重定位条目
pub(super) struct PackedReloc {
    pub(super) r_offset: usize,
    pub(super) r_info: ElfXword,
}

impl PackedRelocIterator {
    // 分组标志位：组内共享 r_info / offset delta / addend
    const RELOCATION_GROUPED_BY_INFO_FLAG: usize = 1;
    const RELOCATION_GROUPED_BY_OFFSET_DELTA_FLAG: usize = 2;
    const RELOCATION_GROUPED_BY_ADDEND_FLAG: usize = 4;
    const RELOCATION_GROUP_HAS_ADDEND_FLAG: usize = 8;

    pub(super) unsafe fn new(addr: usize, size: usize, is_use_rela: bool) -> Result<Self, Errno> {
        let mut decoder = Sleb128Decoder::new(addr, size);
        let relocation_count = decoder.next()?;
        let r_offset = decoder.next()?;
        Ok(Self {
            decoder,
            relocation_count,
            group_size: 0,
            group_flags: 0,
            group_r_offset_delta: 0,
            relocation_index: 0,
            relocation_group_index: 0,
            r_offset,
            r_info: 0,
            r_addend: 0,
            is_use_rela,
        })
    }

    // 读取新分组的头部字段，根据 flags 决定哪些字段组内共享
    unsafe fn read_group_fields(&mut self) -> Result<(), Errno> {
        self.group_size = self.decoder.next()?;
        self.group_flags = self.decoder.next()?;

        if (self.group_flags & Self::RELOCATION_GROUPED_BY_OFFSET_DELTA_FLAG) != 0 {
            self.group_r_offset_delta = self.decoder.next()?;
        }

        if (self.group_flags & Self::RELOCATION_GROUPED_BY_INFO_FLAG) != 0 {
            self.r_info = self.decoder.next()?;
        }

        if (self.group_flags & Self::RELOCATION_GROUP_HAS_ADDEND_FLAG) != 0
            && (self.group_flags & Self::RELOCATION_GROUPED_BY_ADDEND_FLAG) != 0
        {
            if !self.is_use_rela {
                log::error(format_args!("unexpected r_addend in android.rel section"));
                return Err(Errno::Format);
            }
            let val = self.decoder.next()?;
            self.r_addend += val as isize;
        } else if (self.group_flags & Self::RELOCATION_GROUP_HAS_ADDEND_FLAG) == 0 {
            self.r_addend = 0;
        }

        self.relocation_group_index = 0;
        Ok(())
    }

    // 产出下一条重定位条目，分组耗尽时自动读取下一组
    pub(super) unsafe fn next(&mut self) -> Result<Option<PackedReloc>, Errno> {
        if self.relocation_index >= self.relocation_count {
            return Ok(None);
        }

        if self.relocation_group_index == self.group_size {
            self.read_group_fields()?;
        }

        if (self.group_flags & Self::RELOCATION_GROUPED_BY_OFFSET_DELTA_FLAG) != 0 {
            self.r_offset = self.r_offset.wrapping_add(self.group_r_offset_delta);
        } else {
            let val = self.decoder.next()?;
            self.r_offset = self.r_offset.wrapping_add(val);
        }

        if (self.group_flags & Self::RELOCATION_GROUPED_BY_INFO_FLAG) == 0 {
            self.r_info = self.decoder.next()?;
        }

        if self.is_use_rela
            && (self.group_flags & Self::RELOCATION_GROUP_HAS_ADDEND_FLAG) != 0
            && (self.group_flags & Self::RELOCATION_GROUPED_BY_ADDEND_FLAG) == 0
        {
            let val = self.decoder.next()?;
            self.r_addend += val as isize;
        }

        self.relocation_index += 1;
        self.relocation_group_index += 1;

        Ok(Some(PackedReloc {
            r_offset: self.r_offset,
            r_info: self.r_info as ElfXword,
        }))
    }
}
