// 符号查找与 GOT slot 替换逻辑，通过 include! 嵌入 elf.rs

impl Elf {
    // 按名称查找符号索引，根据 hash 类型分派到对应查找算法
    fn find_symidx_by_name(&self, symbol: &str) -> Result<u32, Errno> {
        if self.is_use_gnu_hash {
            self.gnu_hash_lookup(symbol)
        } else {
            self.elf_hash_lookup(symbol)
        }
    }

    // 通过 DT_HASH 的 bucket/chain 链表查找符号
    fn elf_hash_lookup(&self, symbol: &str) -> Result<u32, Errno> {
        if self.bucket_cnt == 0 {
            return Err(Errno::NotFound);
        }
        let hash = elf_hash(symbol.as_bytes());
        let mut i = unsafe { *self.bucket.add((hash % self.bucket_cnt) as usize) };
        while i != 0 {
            if let Some(name) = unsafe { self.sym_name(i) }
                && name == symbol
            {
                log::info(format_args!("found {} at symidx: {} (ELF_HASH)", symbol, i));
                return Ok(i);
            }
            i = unsafe { *self.chain.add(i as usize) };
        }
        Err(Errno::NotFound)
    }

    // GNU hash 查找：先尝试已定义符号，失败后回退到未定义符号区间
    fn gnu_hash_lookup(&self, symbol: &str) -> Result<u32, Errno> {
        if let Ok(symidx) = self.gnu_hash_lookup_def(symbol) {
            return Ok(symidx);
        }
        self.gnu_hash_lookup_undef(symbol)
    }

    // GNU hash 查找已定义符号：bloom filter 快速排除 -> bucket 定位 -> chain 遍历
    fn gnu_hash_lookup_def(&self, symbol: &str) -> Result<u32, Errno> {
        if self.bucket_cnt == 0 {
            return Err(Errno::NotFound);
        }
        let hash = elf_gnu_hash(symbol.as_bytes());
        let elfclass_bits = mem::size_of::<ElfAddr>() * 8;
        let bloom_idx = (hash as usize / elfclass_bits) % self.bloom_sz as usize;
        let word = unsafe { *self.bloom.add(bloom_idx) };
        // bloom filter 双位检测，任一位未命中则符号必不存在
        let mask = (1usize << (hash as usize % elfclass_bits))
            | (1usize << ((hash >> self.bloom_shift) as usize % elfclass_bits));
        if (word & mask) != mask {
            return Err(Errno::NotFound);
        }

        let mut i = unsafe { *self.bucket.add((hash % self.bucket_cnt) as usize) };
        if i < self.symoffset {
            return Err(Errno::NotFound);
        }

        // 遍历 chain，hash 低位匹配后再比较符号名；chain 最低位为 1 表示链尾
        loop {
            let symname = unsafe { self.sym_name(i) };
            let symhash = unsafe { *self.chain.add((i - self.symoffset) as usize) };
            if let Some(name) = symname
                && (hash | 1) == (symhash | 1)
                && name == symbol
            {
                log::info(format_args!(
                    "found {} at symidx: {} (GNU_HASH DEF)",
                    symbol, i
                ));
                return Ok(i);
            }
            if (symhash & 1) != 0 {
                break;
            }
            i += 1;
        }

        Err(Errno::NotFound)
    }

    // 线性扫描 symoffset 之前的未定义符号区间（GNU hash 不索引这些符号）
    fn gnu_hash_lookup_undef(&self, symbol: &str) -> Result<u32, Errno> {
        let mut i = 0u32;
        while i < self.symoffset {
            if let Some(name) = unsafe { self.sym_name(i) }
                && name == symbol
            {
                log::info(format_args!(
                    "found {} at symidx: {} (GNU_HASH UNDEF)",
                    symbol, i
                ));
                return Ok(i);
            }
            i += 1;
        }
        Err(Errno::NotFound)
    }

    // 通过符号索引从 strtab 获取符号名
    unsafe fn sym_name(&self, idx: u32) -> Option<&str> {
        if self.symtab.is_null() || self.strtab.is_null() {
            return None;
        }
        let sym = &*self.symtab.add(idx as usize);
        let name_ptr = self.strtab.add(sym.st_name as usize);
        let cstr = CStr::from_ptr(name_ptr);
        cstr.to_str().ok()
    }

    // 匹配重定位条目的符号索引和类型，命中则执行 GOT slot 替换
    #[allow(clippy::too_many_arguments)]
    fn find_and_replace(
        &self,
        section: &str,
        is_plt: bool,
        symbol: &str,
        new_func: *mut libc::c_void,
        old_func: *mut *mut libc::c_void,
        symidx: u32,
        r_offset: usize,
        r_info: ElfXword,
        found: Option<&mut bool>,
    ) -> Result<(), Errno> {
        let r_sym = elf_r_sym(r_info);
        if r_sym != symidx {
            return Ok(());
        }
        let r_type = elf_r_type(r_info);
        if is_plt && r_type != R_GENERIC_JUMP_SLOT {
            return Ok(());
        }
        if !is_plt && r_type != R_GENERIC_GLOB_DAT && r_type != R_GENERIC_ABS {
            return Ok(());
        }

        if let Some(found) = found {
            *found = true;
        }

        log::info(format_args!(
            "found {} at {} offset: {:p}",
            symbol, section, r_offset as *const ()
        ));

        let addr = self.bias_addr + r_offset;
        if addr < self.base_addr {
            return Err(Errno::Format);
        }

        unsafe { self.replace_function(symbol, addr, new_func, old_func) }
    }

    // 修改 GOT slot 指向新函数，必要时临时设置页面为可写并在完成后恢复
    unsafe fn replace_function(
        &self,
        symbol: &str,
        addr: usize,
        new_func: *mut libc::c_void,
        old_func: *mut *mut libc::c_void,
    ) -> Result<(), Errno> {
        let slot = addr as *mut *mut libc::c_void;
        if ptr::read(slot) == new_func {
            return Ok(());
        }

        let old_prot = util::get_addr_protect(addr, Some(&self.pathname))?;
        let need_prot = util::PROT_READ_FLAG | util::PROT_WRITE_FLAG;
        if old_prot != need_prot {
            util::set_addr_protect(addr, need_prot)?;
        }

        let old_addr = ptr::read(slot);
        if !old_func.is_null() {
            *old_func = old_addr;
        }

        ptr::write(slot, new_func);

        if old_prot != need_prot
            && let Err(err) = util::set_addr_protect(addr, old_prot)
        {
            log::warn(format_args!("restore addr prot failed: {:?}", err));
        }

        util::flush_instruction_cache(addr);
        log::info(format_args!(
            "SRX_HK_OK {:p}: {:p} -> {:p} {} {}",
            slot, old_addr, new_func, symbol, self.pathname
        ));
        Ok(())
    }
}
