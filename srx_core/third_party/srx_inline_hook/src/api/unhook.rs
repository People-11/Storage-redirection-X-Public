use core::sync::atomic;
use core::sync::atomic::Ordering;

use super::prelude::*;

pub(crate) unsafe fn unhook_active(stub: HookStub, caller_addr: usize) -> Result<(), Errno> {
    // SAFETY: 仅给 pending 模块复用真实已安装 stub 的拆除逻辑
    unsafe { unhook_inner(stub, caller_addr) }
}

pub unsafe fn unhook(stub: HookStub) -> Result<(), Errno> {
    unsafe { unhook_with_caller_addr(stub, 0) }
}

pub unsafe fn unhook_with_caller_addr(stub: HookStub, caller_addr: usize) -> Result<(), Errno> {
    tls_errno::reset();
    let result = if runtime::is_disabled() {
        Err(Errno::Disabled)
    } else {
        let init_err = runtime::get_init_errno();
        if init_err != Errno::Ok {
            Err(init_err)
        } else if pending::is_pending_handle(stub.handle) {
            pending::unhook(stub.handle, caller_addr)
        } else {
            unsafe { unhook_inner(stub, caller_addr) }
        }
    };
    match &result {
        Ok(()) => sh_info!(
            target: "srx_inline_hook",
            "unhook ok stub=0x{:x}",
            stub.handle as usize,
        ),
        Err(e) => sh_warn!(
            target: "srx_inline_hook",
            "unhook fail stub=0x{:x} errno={}({})",
            stub.handle as usize,
            *e as i32,
            e.message(),
        ),
    }
    let final_errno = match &result {
        Ok(_) => Errno::Ok,
        Err(e) => *e,
    };
    recorder::record_with_meta(
        RecordOp::Unhook,
        stub.handle as usize,
        0,
        final_errno,
        None,
        RecordMeta {
            caller_addr: (caller_addr != 0).then_some(caller_addr),
            stub: stub.handle as usize,
            ..RecordMeta::default()
        },
    );
    tls_errno::set(final_errno);
    result
}

unsafe fn unhook_inner(stub: HookStub, _caller_addr: usize) -> Result<(), Errno> {
    // 检查序：NULL 在 capi 层挡 → Disabled → init_errno
    if runtime::is_disabled() {
        return Err(Errno::Disabled);
    }
    let init_err = runtime::get_init_errno();
    if init_err != Errno::Ok {
        return Err(init_err);
    }
    let id = stub.handle as usize;
    let body = stub::get(id).ok_or(Errno::UnhookNotFound)?;
    let target_ptr = body.target;

    match body.mode {
        SwitchMode::Unique => {
            let mut switch_entry = switch::remove(target_ptr)?;
            stub::take(id);
            if switch_entry.has_interceptors && switch_entry.intercept_carrier_id != 0 {
                if let Some(node) = switch_entry.queue.pop()
                    && let Some(slot) = node.orig_slot
                {
                    unsafe { ptr::write(slot, ptr::null()) };
                }
                switch_entry.mode = SwitchMode::Intercept;
                switch::insert_existing(switch_entry)?;
                if let Some(launcher) = intercept::launcher_of(target_ptr) {
                    unsafe { repatch_head(target_ptr, launcher as *const c_void) }?;
                    return Ok(());
                }
                let switch_entry = switch::remove(target_ptr)?;
                // SAFETY: launcher 缺失时回退到完整卸载
                return unsafe { unhook_finalize(switch_entry) };
            }
            // SAFETY: switch_entry 来自注册表，target/patch/tramp 字段由 hook 路径写入
            unsafe { unhook_finalize(switch_entry) }
        }
        SwitchMode::Multi => {
            let outcome = switch::remove_proxy_by_id(target_ptr, id)?;
            stub::take(id);
            match outcome {
                RemoveOutcome::Drained(switch_entry) => {
                    // SAFETY: 同 UNIQUE 分支
                    unsafe { unhook_finalize(switch_entry) }
                }
                RemoveOutcome::Remaining {
                    was_head,
                    new_head_addr,
                    ..
                } => {
                    if was_head {
                        unsafe { repatch_head(target_ptr, new_head_addr) }
                    } else {
                        Ok(())
                    }
                }
            }
        }
        SwitchMode::Shared => {
            let outcome = switch::remove_proxy_by_id(target_ptr, id)?;
            stub::take(id);
            match outcome {
                RemoveOutcome::Drained(switch_entry) => unsafe { unhook_finalize(switch_entry) },
                RemoveOutcome::Remaining { was_head, .. } => {
                    if was_head {
                        let new_head = switch::shared_launcher_of(target_ptr)
                            .map(|p| p as *const c_void)
                            .ok_or(Errno::UnhookNotFound)?;
                        unsafe { repatch_head(target_ptr, new_head) }
                    } else {
                        Ok(())
                    }
                }
            }
        }
        SwitchMode::Intercept => {
            let outcome = switch::remove_proxy_by_id(target_ptr, id)?;
            stub::take(id);
            match outcome {
                RemoveOutcome::Drained(switch_entry) => unsafe { unhook_finalize(switch_entry) },
                RemoveOutcome::Remaining {
                    was_head,
                    new_head_addr,
                    ..
                } => {
                    if was_head {
                        unsafe { repatch_head(target_ptr, new_head_addr) }
                    } else {
                        Ok(())
                    }
                }
            }
        }
    }
}

// Switch 整体拆除：比对 patch → 还原 original → 回收 tramp + 清 orig_slot
unsafe fn unhook_finalize(sw: Switch) -> Result<(), Errno> {
    let target_ptr = sw.target;
    // memcmp target：读崩 → CmpCrash；不等 → TrampoMismatch；等 → 继续
    let cmp_result = unsafe {
        bytesig::guard(|| -> bool {
            let mut current = vec![0u8; sw.patch.len()];
            // SAFETY: guard 捕获并发读写下的 SIGSEGV / SIGBUS
            ptr::copy_nonoverlapping(target_ptr, current.as_mut_ptr(), current.len());
            current == sw.patch
        })
    };
    let cmp: Result<(), Errno> = match cmp_result {
        Err(Errno::HookRewriteCrash) => Err(Errno::UnhookCmpCrash),
        Err(e) => Err(e),
        Ok(true) => Ok(()),
        Ok(false) => Err(Errno::UnhookTrampoMismatch),
    };
    if let Err(e) = cmp {
        // cmp 失败不 restore：避免踩坏第三方 patch 或读崩的未知状态
        if let Some(lp) = NonNull::new(sw.shared_launcher) {
            let _ = trampoline::release(lp);
        }
        if let Some(tp) = NonNull::new(sw.tramp_addr) {
            let _ = trampoline::release(tp);
        }
        return Err(e);
    }

    // 恢复 prologue 走 guard：被 hook 函数此刻可能正被其他线程执行
    let restore = unsafe {
        bytesig::guard(|| -> Result<(), Errno> {
            // SAFETY: guard 捕获并发读写下的 SIGSEGV / SIGBUS
            android::mprotect_rwx(target_ptr, sw.original.len())?;
            // 16B 对齐走原子 LDXP/STXP，其余 memcpy
            android::write_inst(target_ptr, &sw.original);
            android::mprotect_rx(target_ptr, sw.original.len())?;
            android::clear_icache(target_ptr, sw.original.len());
            // SEQ_CST fence：arm64 clear_icache 已含，x86_64 显式补一次
            atomic::fence(Ordering::SeqCst);
            Ok(())
        })
    };
    let restore = match restore {
        Err(Errno::HookRewriteCrash) => Err(Errno::UnhookExitCrash),
        other => other.and_then(|inner| inner),
    };
    // restore 成败都清 orig_slot + 归还 tramp，避免泄露槽 / 残留跳板
    for node in &sw.queue {
        if let Some(slot) = node.orig_slot {
            // SAFETY: 槽位由调用方保障存活期 ≥ hook 存活期
            unsafe { ptr::write(slot, ptr::null()) };
        }
    }
    if let Some(lp) = NonNull::new(sw.shared_launcher) {
        let _ = trampoline::release(lp);
    }
    let tramp_ptr = NonNull::new(sw.tramp_addr);
    if let Some(tp) = tramp_ptr {
        let _ = trampoline::release(tp);
    }
    restore?;
    // tramp null 视作 switch 损坏；restore 成功但池归位失败才触发
    if tramp_ptr.is_none() {
        return Err(Errno::UnhookTrampoMismatch);
    }
    Ok(())
}

// MULTI 首节点被拆除且 queue 仍有残留：patch target 跳转新 head
unsafe fn repatch_head(target_ptr: *mut u8, new_head: *const c_void) -> Result<(), Errno> {
    let mut patch = [0u8; current::MIN_OVERWRITE_LEN];
    let tramp = switch::trampoline_of(target_ptr).ok_or(Errno::UnhookNotFound)?;
    unsafe {
        trampoline::prepare_entry_jump(target_ptr, new_head as *const u8, tramp, &mut patch)?;
    }
    let guarded = unsafe {
        bytesig::guard(|| -> Result<(), Errno> {
            // SAFETY: guard 捕获并发读写 SIGSEGV / SIGBUS
            android::mprotect_rwx(target_ptr, current::MIN_OVERWRITE_LEN)?;
            android::write_inst(target_ptr, &patch);
            android::mprotect_rx(target_ptr, current::MIN_OVERWRITE_LEN)?;
            android::clear_icache(target_ptr, current::MIN_OVERWRITE_LEN);
            atomic::fence(Ordering::SeqCst);
            Ok(())
        })
    };
    let result = match guarded {
        Err(Errno::HookRewriteCrash) => Err(Errno::WriteCrash),
        other => other.and_then(|inner| inner),
    };
    if result.is_ok() {
        switch::set_head_patch(target_ptr, &patch)?;
    }
    result
}

pub(crate) fn cleanup_hooks_for_dlinfo(info: &libc::dl_phdr_info) {
    let base = info.dlpi_addr as usize;
    let drained = switch::drain_filter(|target| is_addr_in_dlinfo(target, info));
    for sw in drained {
        let _ = stub::remove_by_target(sw.target);
        for node in &sw.queue {
            if let Some(slot) = node.orig_slot {
                // SAFETY: 目标 so 已卸载，orig 槽需要同步清零避免悬挂 trampoline
                unsafe { ptr::write(slot, ptr::null()) };
            }
        }
        intercept::cleanup_target(sw.target);
        if let Some(tp) = NonNull::new(sw.tramp_addr) {
            let _ = trampoline::release(tp);
        }
        sh_info!(
            target: "srx_inline_hook",
            "cleanup_after_dlclose target=0x{:x} base=0x{:x}",
            sw.target as usize,
            base,
        );
    }
}

pub(crate) fn is_addr_in_dlinfo(addr: usize, info: &libc::dl_phdr_info) -> bool {
    let base = info.dlpi_addr as usize;
    for i in 0..info.dlpi_phnum as usize {
        // SAFETY: dlpi_phdr 数组长度由 dlpi_phnum 保证
        let ph = unsafe { &*info.dlpi_phdr.add(i) };
        if ph.p_type != libc::PT_LOAD {
            continue;
        }
        let seg_start = base.saturating_add(ph.p_vaddr as usize);
        let seg_end = seg_start.saturating_add(ph.p_memsz as usize);
        if seg_start <= addr && addr < seg_end {
            return true;
        }
    }
    false
}

pub unsafe fn prev_func(stub: HookStub) -> Result<*const c_void, Errno> {
    let init_err = runtime::get_init_errno();
    if init_err != Errno::Ok {
        return Err(init_err);
    }
    if pending::is_pending_handle(stub.handle) {
        return pending::prev_func(stub.handle);
    }
    let id = stub.handle as usize;
    let body = stub::get(id).ok_or(Errno::UnhookNotFound)?;
    match body.mode {
        SwitchMode::Shared | SwitchMode::Intercept => {
            switch::prev_addr_by_id(stub.handle as usize).ok_or(Errno::UnhookNotFound)
        }
        _ => switch::trampoline_of(body.target)
            .map(|p| p as *const c_void)
            .ok_or(Errno::UnhookNotFound),
    }
}

// C ABI 的 prev_func 入参可为 stub id 或运行时 target 地址；先按 id 查 stub
// 命中则跳到该 target 的跳板；否则把入参当 target 地址查
pub fn prev_func_by_addr(addr: *const c_void) -> Result<*const c_void, Errno> {
    let init_err = runtime::get_init_errno();
    if init_err != Errno::Ok {
        return Err(init_err);
    }
    if pending::is_pending_handle(addr as *mut c_void) {
        return pending::prev_func(addr as *mut c_void);
    }
    if let Some(body) = stub::get(addr as usize) {
        return match body.mode {
            SwitchMode::Shared | SwitchMode::Intercept => {
                switch::prev_addr_by_id(addr as usize).ok_or(Errno::UnhookNotFound)
            }
            _ => switch::trampoline_of(body.target)
                .map(|p| p as *const c_void)
                .ok_or(Errno::UnhookNotFound),
        };
    }
    let target_ptr = addr as *mut u8;
    if let Some((id, body)) = stub::find_by_new_addr(addr, Some(target_ptr)) {
        return match body.mode {
            SwitchMode::Shared | SwitchMode::Intercept => {
                switch::prev_addr_by_id(id).ok_or(Errno::UnhookNotFound)
            }
            _ => switch::trampoline_of(body.target)
                .map(|p| p as *const c_void)
                .ok_or(Errno::UnhookNotFound),
        };
    }
    if let Some((id, body)) = stub::find_by_new_addr(addr, None) {
        return match body.mode {
            SwitchMode::Shared | SwitchMode::Intercept => {
                switch::prev_addr_by_id(id).ok_or(Errno::UnhookNotFound)
            }
            _ => switch::trampoline_of(body.target)
                .map(|p| p as *const c_void)
                .ok_or(Errno::UnhookNotFound),
        };
    }
    switch::trampoline_of(target_ptr)
        .map(|p| p as *const c_void)
        .ok_or(Errno::UnhookNotFound)
}

// 只查已加载 so：未命中库返回 Pending，命中库但缺符号才是 DlSymFailed
