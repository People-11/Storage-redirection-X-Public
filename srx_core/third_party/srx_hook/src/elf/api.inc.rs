// 对外 API：PLT/GOT hook、导出函数查找、GOT slot 收集

impl Elf {

    // 通过符号名查找导出函数的绝对地址，未定义或值为 0 时返回 None
    #[cfg(target_arch = "aarch64")]
    pub fn find_export_function(&self, symbol: &str) -> Option<usize> {
        let symidx = self.find_symidx_by_name(symbol).ok()?;
        unsafe {
            let sym = &*self.symtab.add(symidx as usize);
            if sym.st_shndx == SHN_UNDEF || sym.st_value == 0 {
                return None;
            }
            Some(self.bias_addr + sym.st_value as usize)
        }
    }

    // 收集指定符号的所有 GOT slot 地址
    pub unsafe fn find_got_slots(
        &self,
        symbol: &str,
    ) -> Result<Vec<usize>, Errno> {
        let symidx = match self.find_symidx_by_name(symbol) {
            Ok(value) => value,
            Err(Errno::NotFound) => return Ok(Vec::new()),
            Err(err) => return Err(err),
        };

        let mut slots = BTreeSet::new();

        if self.relplt != 0 {
            let relplt_cnt = self.relplt_sz
                / if self.is_use_rela {
                    mem::size_of::<ElfRela>()
                } else {
                    mem::size_of::<ElfRel>()
                };
            if self.is_use_rela {
                let relas = slice::from_raw_parts(self.relplt as *const ElfRela, relplt_cnt);
                for rela in relas {
                    self.collect_slot(
                        &mut slots,
                        true,
                        symidx,
                        rela.r_offset as usize,
                        rela.r_info,
                    )?;
                }
            } else {
                let rels = slice::from_raw_parts(self.relplt as *const ElfRel, relplt_cnt);
                for rel in rels {
                    self.collect_slot(
                        &mut slots,
                        true,
                        symidx,
                        rel.r_offset as usize,
                        rel.r_info,
                    )?;
                }
            }
        }

        if self.reldyn != 0 {
            let reldyn_cnt = self.reldyn_sz
                / if self.is_use_rela {
                    mem::size_of::<ElfRela>()
                } else {
                    mem::size_of::<ElfRel>()
                };
            if self.is_use_rela {
                let relas = slice::from_raw_parts(self.reldyn as *const ElfRela, reldyn_cnt);
                for rela in relas {
                    self.collect_slot(
                        &mut slots,
                        false,
                        symidx,
                        rela.r_offset as usize,
                        rela.r_info,
                    )?;
                }
            } else {
                let rels = slice::from_raw_parts(self.reldyn as *const ElfRel, reldyn_cnt);
                for rel in rels {
                    self.collect_slot(
                        &mut slots,
                        false,
                        symidx,
                        rel.r_offset as usize,
                        rel.r_info,
                    )?;
                }
            }
        }

        if self.relandroid != 0 {
            let mut packed =
                PackedRelocIterator::new(self.relandroid, self.relandroid_sz, self.is_use_rela)?;
            while let Some(reloc) = packed.next()? {
                self.collect_slot(
                    &mut slots,
                    false,
                    symidx,
                    reloc.r_offset,
                    reloc.r_info,
                )?;
            }
        }

        Ok(slots.into_iter().collect())
    }

    // 检查单条重定位条目是否匹配目标符号，匹配则将 GOT slot 地址加入集合
    fn collect_slot(
        &self,
        slots: &mut BTreeSet<usize>,
        is_plt: bool,
        symidx: u32,
        r_offset: usize,
        r_info: ElfXword,
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

        let addr = self.bias_addr + r_offset;
        if addr < self.base_addr {
            return Err(Errno::Format);
        }

        slots.insert(addr);
        Ok(())
    }
}
