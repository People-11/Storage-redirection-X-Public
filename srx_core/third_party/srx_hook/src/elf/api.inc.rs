// 对外 API：PLT/GOT hook、导出函数查找、GOT slot 收集

impl Elf {
    // 对指定符号执行 PLT/GOT hook，依次扫描 .rel(a).plt、.rel(a).dyn、.rel(a).android
    pub unsafe fn hook(
        &self,
        symbol: &str,
        new_func: *mut libc::c_void,
        old_func: *mut *mut libc::c_void,
    ) -> Result<(), Errno> {
        if symbol.is_empty() || new_func.is_null() {
            return Err(Errno::Invalid);
        }

        log::info(format_args!("hooking {} in {}", symbol, self.pathname));

        let symidx = match self.find_symidx_by_name(symbol) {
            Ok(symidx) => symidx,
            Err(Errno::NotFound) => return Ok(()),
            Err(err) => return Err(err),
        };

        // .rel(a).plt：每个符号最多一个 JUMP_SLOT，找到即停
        if self.relplt != 0 {
            let relplt_cnt = self.relplt_sz
                / if self.is_use_rela {
                    mem::size_of::<ElfRela>()
                } else {
                    mem::size_of::<ElfRel>()
                };
            let mut found = false;
            if self.is_use_rela {
                let relas = slice::from_raw_parts(self.relplt as *const ElfRela, relplt_cnt);
                for rela in relas {
                    self.find_and_replace(
                        if self.is_use_rela {
                            ".rela.plt"
                        } else {
                            ".rel.plt"
                        },
                        true,
                        symbol,
                        new_func,
                        old_func,
                        symidx,
                        rela.r_offset as usize,
                        rela.r_info,
                        Some(&mut found),
                    )?;
                    if found {
                        break;
                    }
                }
            } else {
                let rels = slice::from_raw_parts(self.relplt as *const ElfRel, relplt_cnt);
                for rel in rels {
                    self.find_and_replace(
                        if self.is_use_rela {
                            ".rela.plt"
                        } else {
                            ".rel.plt"
                        },
                        true,
                        symbol,
                        new_func,
                        old_func,
                        symidx,
                        rel.r_offset as usize,
                        rel.r_info,
                        Some(&mut found),
                    )?;
                    if found {
                        break;
                    }
                }
            }
        }

        // .rel(a).dyn：GLOB_DAT / ABS 可能有多个，全部替换
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
                    self.find_and_replace(
                        if self.is_use_rela {
                            ".rela.dyn"
                        } else {
                            ".rel.dyn"
                        },
                        false,
                        symbol,
                        new_func,
                        old_func,
                        symidx,
                        rela.r_offset as usize,
                        rela.r_info,
                        None,
                    )?;
                }
            } else {
                let rels = slice::from_raw_parts(self.reldyn as *const ElfRel, reldyn_cnt);
                for rel in rels {
                    self.find_and_replace(
                        if self.is_use_rela {
                            ".rela.dyn"
                        } else {
                            ".rel.dyn"
                        },
                        false,
                        symbol,
                        new_func,
                        old_func,
                        symidx,
                        rel.r_offset as usize,
                        rel.r_info,
                        None,
                    )?;
                }
            }
        }

        if self.relandroid != 0 {
            let mut packed =
                PackedRelocIterator::new(self.relandroid, self.relandroid_sz, self.is_use_rela)?;
            while let Some(reloc) = packed.next()? {
                self.find_and_replace(
                    if self.is_use_rela {
                        ".rela.android"
                    } else {
                        ".rel.android"
                    },
                    false,
                    symbol,
                    new_func,
                    old_func,
                    symidx,
                    reloc.r_offset,
                    reloc.r_info,
                    None,
                )?;
            }
        }

        Ok(())
    }

    // 通过符号名查找导出函数的绝对地址，未定义或值为 0 时返回 None
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

    // 收集指定符号的所有 GOT slot 地址，可选按 callee 地址过滤
    pub unsafe fn find_got_slots(
        &self,
        symbol: &str,
        callee_addrs: Option<&BTreeSet<usize>>,
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
                        callee_addrs,
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
                        callee_addrs,
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
                        callee_addrs,
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
                        callee_addrs,
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
                    callee_addrs,
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
        callee_addrs: Option<&BTreeSet<usize>>,
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

        if let Some(expected_addrs) = callee_addrs {
            let value = unsafe { ptr::read(addr as *const usize) };
            let matched = expected_addrs.contains(&value);
            if !matched {
                // PLT lazy binding 场景：slot 尚未解析，值指向 LOAD 段内的 stub
                let may_lazy_match =
                    is_plt && expected_addrs.len() == 1 && self.is_addr_in_load_segments(value);
                if !may_lazy_match {
                    return Ok(());
                }
            }
        }

        slots.insert(addr);
        Ok(())
    }
}
