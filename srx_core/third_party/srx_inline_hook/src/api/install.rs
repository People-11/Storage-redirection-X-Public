use super::prelude::*;

pub unsafe fn hook_single(
    target: *mut c_void,
    replacement: *const c_void,
) -> Result<HookStub, Errno> {
    // SAFETY: 调用方保证 target / replacement 为本进程有效代码地址
    unsafe { hook_with_orig(target, replacement, ptr::null_mut()) }
}

// orig_addr 非空时 hook 激活前写跳板地址，unhook 清零；
// replacement 可直接 (*orig_addr)(...) 调用原函数
pub unsafe fn hook_with_orig(
    target: *mut c_void,
    replacement: *const c_void,
    orig_addr: *mut *const c_void,
) -> Result<HookStub, Errno> {
    unsafe { hook_with_orig_with_caller_addr(target, replacement, orig_addr, 0) }
}

pub(crate) unsafe fn hook_with_orig_with_caller_addr(
    target: *mut c_void,
    replacement: *const c_void,
    orig_addr: *mut *const c_void,
    caller_addr: usize,
) -> Result<HookStub, Errno> {
    tls_errno::reset();
    // SAFETY: 参数有效性由调用方维护
    let result = unsafe { hook_with_orig_inner(target, replacement, orig_addr) };
    match &result {
        Ok((stub, _)) => sh_info!(
            target: "srx_inline_hook",
            "hook ok target=0x{:x} replacement=0x{:x} stub=0x{:x}",
            target as usize,
            replacement as usize,
            stub.handle as usize,
        ),
        Err(e) => sh_warn!(
            target: "srx_inline_hook",
            "hook fail target=0x{:x} replacement=0x{:x} errno={}({})",
            target as usize,
            replacement as usize,
            *e as i32,
            e.message(),
        ),
    }
    let (final_errno, backup, stub) = match &result {
        Ok((stub, consumed)) => (Errno::Ok, Some(*consumed), stub.handle as usize),
        Err(e) => (*e, None, 0),
    };
    recorder::record_with_meta(
        RecordOp::HookFuncAddr,
        target as usize,
        replacement as usize,
        final_errno,
        backup,
        RecordMeta {
            caller_addr: (caller_addr != 0).then_some(caller_addr),
            stub,
            flags: Some(0),
            ..RecordMeta::default()
        },
    );
    tls_errno::set(final_errno);
    result.map(|(stub, _)| stub)
}

// MULTI 模式：同一 target 允许多次 hook，每个 proxy 独占 orig_slot 指向下一环
pub unsafe fn hook_multi(
    target: *mut c_void,
    replacement: *const c_void,
    orig_addr: *mut *const c_void,
) -> Result<HookStub, Errno> {
    tls_errno::reset();
    if let Err(e) = ensure_multi_orig_addr(SwitchMode::Multi, orig_addr) {
        tls_errno::set(e);
        return Err(e);
    }
    // SAFETY: 参数有效性由调用方保证
    let result = unsafe { hook_inline_inner(target, replacement, orig_addr, SwitchMode::Multi) };
    match &result {
        Ok((stub, _)) => sh_info!(
            target: "srx_inline_hook",
            "hook_multi ok target=0x{:x} replacement=0x{:x} stub=0x{:x}",
            target as usize,
            replacement as usize,
            stub.handle as usize,
        ),
        Err(e) => sh_warn!(
            target: "srx_inline_hook",
            "hook_multi fail target=0x{:x} replacement=0x{:x} errno={}({})",
            target as usize,
            replacement as usize,
            *e as i32,
            e.message(),
        ),
    }
    let (final_errno, backup, stub) = match &result {
        Ok((stub, consumed)) => (Errno::Ok, Some(*consumed), stub.handle as usize),
        Err(e) => (*e, None, 0),
    };
    recorder::record_with_meta(
        RecordOp::HookFuncAddr,
        target as usize,
        replacement as usize,
        final_errno,
        backup,
        RecordMeta {
            stub,
            flags: Some(HOOK_FLAG_MULTI),
            ..RecordMeta::default()
        },
    );
    tls_errno::set(final_errno);
    result.map(|(stub, _)| stub)
}

pub(crate) unsafe fn hook_with_orig_inner(
    target: *mut c_void,
    replacement: *const c_void,
    orig_addr: *mut *const c_void,
) -> Result<(HookStub, usize), Errno> {
    // SAFETY: UNIQUE 薄 wrapper，参数有效性同 inline 主路径
    unsafe { hook_inline_inner(target, replacement, orig_addr, SwitchMode::Unique) }
}

pub(crate) unsafe fn hook_inline_for_pending(
    target: *mut c_void,
    replacement: *const c_void,
    orig_addr: *mut *const c_void,
    mode: SwitchMode,
) -> Result<(HookStub, usize), Errno> {
    // SAFETY: pending 队列已筛到已加载目标，参数有效性同常规安装
    unsafe { hook_inline_inner(target, replacement, orig_addr, mode) }
}

pub(crate) unsafe fn hook_inline_inner(
    target: *mut c_void,
    replacement: *const c_void,
    orig_addr: *mut *const c_void,
    mode: SwitchMode,
) -> Result<(HookStub, usize), Errno> {
    if target.is_null() || replacement.is_null() {
        return Err(Errno::InvalidArg);
    }
    // 检查序：InvalidArg → Disabled → init_errno
    if runtime::is_disabled() {
        return Err(Errno::Disabled);
    }
    let init_err = runtime::get_init_errno();
    if init_err != Errno::Ok {
        return Err(init_err);
    }

    let target_ptr = target as *mut u8;

    // 前置模式分支：UNIQUE 撞同址 → HookUniqueDup；MULTI 撞同址同模式 → 追加 proxy
    match switch::mode_of(target_ptr) {
        Some(SwitchMode::Unique) => {
            return Err(if mode == SwitchMode::Unique {
                Errno::HookUniqueDup
            } else {
                Errno::ModeConflict
            });
        }
        Some(SwitchMode::Intercept) if mode == SwitchMode::Multi => {
            let orig_slot = if orig_addr.is_null() {
                None
            } else {
                Some(orig_addr)
            };
            let id = stub::alloc(target_ptr, replacement, SwitchMode::Multi, orig_slot);
            if let Err(e) = switch::push_multi(target_ptr, id, replacement, orig_slot) {
                stub::take(id);
                return Err(e);
            }
            switch::set_mode(target_ptr, SwitchMode::Multi)?;
            return Ok((
                HookStub {
                    handle: id as *mut c_void,
                },
                0,
            ));
        }
        Some(SwitchMode::Intercept) if mode == SwitchMode::Shared => {
            let user_orig_slot = if orig_addr.is_null() {
                None
            } else {
                Some(orig_addr)
            };
            let id = stub::alloc(target_ptr, replacement, SwitchMode::Shared, user_orig_slot);
            if let Err(e) = switch::push_shared(target_ptr, id, replacement, user_orig_slot) {
                stub::take(id);
                return Err(e);
            }
            switch::set_mode(target_ptr, SwitchMode::Shared)?;
            return Ok((
                HookStub {
                    handle: id as *mut c_void,
                },
                0,
            ));
        }
        Some(SwitchMode::Intercept) if mode == SwitchMode::Unique => {
            let orig_slot = if orig_addr.is_null() {
                None
            } else {
                Some(orig_addr)
            };
            let id = stub::alloc(target_ptr, replacement, SwitchMode::Unique, orig_slot);
            if let Err(e) = switch::push_unique(target_ptr, id, replacement, orig_slot) {
                stub::take(id);
                return Err(e);
            }
            switch::set_mode(target_ptr, SwitchMode::Unique)?;
            return Ok((
                HookStub {
                    handle: id as *mut c_void,
                },
                0,
            ));
        }
        Some(SwitchMode::Intercept) => {
            return Err(Errno::ModeConflict);
        }
        Some(SwitchMode::Multi) if mode == SwitchMode::Multi => {
            let orig_slot = if orig_addr.is_null() {
                None
            } else {
                Some(orig_addr)
            };
            let id = stub::alloc(target_ptr, replacement, SwitchMode::Multi, orig_slot);
            if let Err(e) = switch::push_multi(target_ptr, id, replacement, orig_slot) {
                stub::take(id);
                return Err(e);
            }
            return Ok((
                HookStub {
                    handle: id as *mut c_void,
                },
                0,
            ));
        }
        Some(SwitchMode::Shared) if mode == SwitchMode::Shared => {
            let user_orig_slot = if orig_addr.is_null() {
                None
            } else {
                Some(orig_addr)
            };
            let id = stub::alloc(target_ptr, replacement, SwitchMode::Shared, user_orig_slot);
            if let Err(e) = switch::push_shared(target_ptr, id, replacement, user_orig_slot) {
                stub::take(id);
                return Err(e);
            }
            return Ok((
                HookStub {
                    handle: id as *mut c_void,
                },
                0,
            ));
        }
        Some(_) => return Err(Errno::ModeConflict),
        None => {}
    }

    // 邻近函数入口改写区间相交时拒绝。
    if switch::has_overlap(target_ptr, current::MIN_OVERWRITE_LEN) {
        return Err(Errno::HookOverlap);
    }

    let mut prologue = [0u8; PROLOGUE_PROBE_LEN];
    unsafe {
        bytesig::guard(|| {
            ptr::copy_nonoverlapping(target_ptr, prologue.as_mut_ptr(), PROLOGUE_PROBE_LEN);
        })?;
    }
    let shared_launcher = if mode == SwitchMode::Shared {
        Some(shared_stack::create_launcher(target_ptr)?)
    } else {
        None
    };
    #[cfg(target_arch = "aarch64")]
    let allocation = trampoline::acquire_near(target_ptr as usize);
    #[cfg(not(target_arch = "aarch64"))]
    let allocation = trampoline::acquire();
    let tramp_ptr = match allocation {
        Ok(value) => value,
        Err(error) => {
            if let Some(launcher) = shared_launcher {
                let _ = trampoline::release(launcher);
            }
            return Err(error);
        }
    };

    let rewritten = match current::rewrite(&prologue, target_ptr as u64, tramp_ptr.as_ptr() as u64)
    {
        Ok(value) => value,
        Err(e) => {
            if let Some(launcher) = shared_launcher {
                let _ = trampoline::release(launcher);
            }
            let _ = trampoline::release(tramp_ptr);
            return Err(e);
        }
    };

    if rewritten.consumed < current::MIN_OVERWRITE_LEN
        || rewritten.bytes.len() + current::MIN_OVERWRITE_LEN > trampoline::RELOCATION_CAPACITY
    {
        if let Some(launcher) = shared_launcher {
            let _ = trampoline::release(launcher);
        }
        let _ = trampoline::release(tramp_ptr);
        return Err(Errno::HookRewriteFailed);
    }

    // 跳板尾部：绝对跳转回 target + consumed
    let mut tail = [0u8; current::MIN_OVERWRITE_LEN];
    // SAFETY: consumed 不超过 PROLOGUE_PROBE_LEN，指针仍处于原函数区域
    let tail_to = unsafe { target_ptr.add(rewritten.consumed) };
    if let Err(e) = current::make_absolute_jump(tail_to, &mut tail) {
        if let Some(launcher) = shared_launcher {
            let _ = trampoline::release(launcher);
        }
        let _ = trampoline::release(tramp_ptr);
        return Err(e);
    }

    // SAFETY: 跳板 slot 由池分配，RWX 且已清零
    unsafe {
        ptr::copy_nonoverlapping(
            rewritten.bytes.as_ptr(),
            tramp_ptr.as_ptr(),
            rewritten.bytes.len(),
        );
        ptr::copy_nonoverlapping(
            tail.as_ptr(),
            tramp_ptr.as_ptr().add(rewritten.bytes.len()),
            tail.len(),
        );
        // 跳板位于 RWX 页，指令写入后需刷 icache
        android::clear_icache(tramp_ptr.as_ptr(), rewritten.bytes.len() + tail.len());
    }

    let mut original = vec![0u8; current::MIN_OVERWRITE_LEN];
    let mut patch = [0u8; current::MIN_OVERWRITE_LEN];
    let patch_target = if mode == SwitchMode::Shared {
        shared_launcher
            .as_ref()
            .map(|p| p.as_ptr() as *const u8)
            .unwrap_or(replacement as *const u8)
    } else {
        replacement as *const u8
    };
    if let Err(e) = unsafe {
        trampoline::prepare_entry_jump(target_ptr, patch_target, tramp_ptr.as_ptr(), &mut patch)
    } {
        if let Some(launcher) = shared_launcher {
            let _ = trampoline::release(launcher);
        }
        let _ = trampoline::release(tramp_ptr);
        return Err(e);
    }

    // 写 orig_slot 必须在 patch 落地前：并发调用读到的须已是跳板
    let orig_slot = if orig_addr.is_null() {
        None
    } else {
        // SAFETY: 调用方承诺 orig_addr 指向有效可写槽位且生命周期覆盖 hook
        unsafe { ptr::write(orig_addr, tramp_ptr.as_ptr() as *const c_void) };
        Some(orig_addr)
    };

    let patch_result = unsafe {
        bytesig::guard(|| -> Result<(), Errno> {
            // SAFETY: guard 捕获并发读写下的 SIGSEGV / SIGBUS
            ptr::copy_nonoverlapping(target_ptr, original.as_mut_ptr(), original.len());
            android::mprotect_rwx(target_ptr, current::MIN_OVERWRITE_LEN)?;
            // arm64 16B 对齐 patch 走 LDXP/STXP 单拷贝原子；否则退化 memcpy
            android::write_inst(target_ptr, &patch);
            // mprotect_rx 失败须回写原字节：避免 target 跳入已回收的跳板
            if let Err(e) = android::mprotect_rx(target_ptr, current::MIN_OVERWRITE_LEN) {
                android::write_inst(target_ptr, &original);
                let _ = android::mprotect_rx(target_ptr, current::MIN_OVERWRITE_LEN);
                android::clear_icache(target_ptr, current::MIN_OVERWRITE_LEN);
                return Err(e);
            }
            android::clear_icache(target_ptr, current::MIN_OVERWRITE_LEN);
            Ok(())
        })
    };
    // patch 阶段信号归类为 WriteCrash，与 rewrite 阶段的 HookRewriteCrash 区分
    let patch_result = match patch_result {
        Err(Errno::HookRewriteCrash) => Err(Errno::WriteCrash),
        other => other.and_then(|inner| inner),
    };
    if let Err(e) = patch_result {
        // 失败回滚：清 orig_slot 避免调用方误用
        if let Some(slot) = orig_slot {
            // SAFETY: 与写入时同一槽位
            unsafe { ptr::write(slot, ptr::null()) };
        }
        if let Some(launcher) = shared_launcher {
            let _ = trampoline::release(launcher);
        }
        let _ = trampoline::release(tramp_ptr);
        return Err(e);
    }

    let id = stub::alloc(target_ptr, replacement, mode, orig_slot);
    let sw = Switch::new(
        mode,
        switch::EntryPatch {
            target: target_ptr,
            original: original.clone(),
            patch: patch.to_vec(),
            consumed: rewritten.consumed,
            tramp_addr: tramp_ptr.as_ptr(),
        },
        switch::ProxyNode {
            id,
            new_addr: replacement,
            orig_slot,
        },
        shared_launcher
            .as_ref()
            .map(|p| p.as_ptr())
            .unwrap_or(ptr::null_mut()),
    );
    let insert_result = match mode {
        SwitchMode::Unique => switch::insert_unique(target_ptr, sw),
        SwitchMode::Multi => switch::insert_multi(target_ptr, sw),
        SwitchMode::Shared => switch::insert_shared(target_ptr, sw),
        SwitchMode::Intercept => switch::insert_shared(target_ptr, sw),
    };
    if let Err(e) = insert_result {
        stub::take(id);
        // TOCTOU 漏判：回滚 patch / orig_slot / tramp 三者防悬挂跳转
        if let Some(slot) = orig_slot {
            // SAFETY: 与写入时同一槽位
            unsafe { ptr::write(slot, ptr::null()) };
        }
        let _ = unsafe {
            bytesig::guard(|| -> Result<(), Errno> {
                android::mprotect_rwx(target_ptr, current::MIN_OVERWRITE_LEN)?;
                android::write_inst(target_ptr, &original);
                let _ = android::mprotect_rx(target_ptr, current::MIN_OVERWRITE_LEN);
                android::clear_icache(target_ptr, current::MIN_OVERWRITE_LEN);
                Ok(())
            })
        };
        let _ = trampoline::release(tramp_ptr);
        return Err(e);
    }

    Ok((
        HookStub {
            handle: id as *mut c_void,
        },
        rewritten.consumed,
    ))
}

pub unsafe fn hook_with_orig_2(
    target: *mut c_void,
    replacement: *const c_void,
    orig_addr: *mut *const c_void,
    flags: u32,
) -> Result<HookStub, Errno> {
    hook_with_orig_2_with_names(target, replacement, orig_addr, flags, None, None)
}

pub(crate) unsafe fn hook_with_orig_2_with_names(
    target: *mut c_void,
    replacement: *const c_void,
    orig_addr: *mut *const c_void,
    flags: u32,
    lib_name: Option<&CStr>,
    sym_name: Option<&CStr>,
) -> Result<HookStub, Errno> {
    unsafe {
        hook_with_orig_2_with_names_and_caller_addr(
            target,
            replacement,
            orig_addr,
            flags,
            lib_name,
            sym_name,
            0,
        )
    }
}

pub(crate) unsafe fn hook_with_orig_2_with_names_and_caller_addr(
    target: *mut c_void,
    replacement: *const c_void,
    orig_addr: *mut *const c_void,
    flags: u32,
    lib_name: Option<&CStr>,
    sym_name: Option<&CStr>,
    caller_addr: usize,
) -> Result<HookStub, Errno> {
    if let Err(e) = check_hook_flags(flags) {
        tls_errno::set(e);
        return Err(e);
    }
    let mode = flags_to_mode(flags);
    if let Err(e) = ensure_multi_orig_addr(mode, orig_addr) {
        tls_errno::set(e);
        return Err(e);
    }
    tls_errno::reset();
    let result = unsafe { hook_inline_inner(target, replacement, orig_addr, mode) };
    let (final_errno, backup, stub) = match &result {
        Ok((stub, consumed)) => (Errno::Ok, Some(*consumed), stub.handle as usize),
        Err(e) => (*e, None, 0),
    };
    recorder::record_with_meta(
        RecordOp::HookFuncAddr,
        target as usize,
        replacement as usize,
        final_errno,
        backup,
        RecordMeta {
            lib_name,
            sym_name,
            caller_addr: (caller_addr != 0).then_some(caller_addr),
            stub,
            flags: Some(flags),
            ..RecordMeta::default()
        },
    );
    tls_errno::set(final_errno);
    result.map(|(stub, _)| stub)
}
