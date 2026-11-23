use super::prelude::*;

// orig_addr 非空时 hook 激活前写跳板地址，unhook 清零；
// replacement 可直接 (*orig_addr)(...) 调用原函数
pub unsafe fn hook_sym_addr(
    target: *mut c_void,
    replacement: *const c_void,
    orig_addr: *mut *const c_void,
) -> Result<HookStub, Errno> {
    // SAFETY: 参数有效性由调用方维护
    let result = unsafe { install(target, replacement, orig_addr) };
    match &result {
        Ok(stub) => sh_info!(
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
    result
}

unsafe fn install(
    target: *mut c_void,
    replacement: *const c_void,
    orig_addr: *mut *const c_void,
) -> Result<HookStub, Errno> {
    if target.is_null() || replacement.is_null() {
        return Err(Errno::InvalidArg);
    }
    runtime::check_ready()?;

    let target_ptr = target as *mut u8;
    if switch::contains(target_ptr) {
        return Err(Errno::HookUniqueDup);
    }
    // 邻近函数入口改写区间相交时拒绝
    if switch::has_overlap(target_ptr, current::MIN_OVERWRITE_LEN) {
        return Err(Errno::HookOverlap);
    }

    let mut prologue = [0u8; PROLOGUE_PROBE_LEN];
    unsafe {
        bytesig::guard(|| {
            ptr::copy_nonoverlapping(target_ptr, prologue.as_mut_ptr(), PROLOGUE_PROBE_LEN);
        })?;
    }
    #[cfg(target_arch = "aarch64")]
    let tramp_ptr = trampoline::acquire_near(target_ptr as usize)?;
    #[cfg(not(target_arch = "aarch64"))]
    let tramp_ptr = trampoline::acquire()?;

    // SAFETY: tramp_ptr 刚从池中取得，失败时归还
    let patch = match unsafe { fill_trampoline(target_ptr, replacement, &prologue, tramp_ptr) } {
        Ok(patch) => patch,
        Err(e) => {
            let _ = trampoline::release(tramp_ptr);
            return Err(e);
        }
    };

    // 写 orig_slot 必须在 patch 落地前：并发调用读到的须已是跳板
    let orig_slot = NonNull::new(orig_addr).map(|slot| {
        // SAFETY: 调用方承诺 orig_addr 指向有效可写槽位且生命周期覆盖 hook
        unsafe { ptr::write(slot.as_ptr(), tramp_ptr.as_ptr() as *const c_void) };
        slot.as_ptr()
    });
    let rollback = |restore: Option<&[u8]>| {
        if let Some(slot) = orig_slot {
            // SAFETY: 与写入时同一槽位
            unsafe { ptr::write(slot, ptr::null()) };
        }
        if let Some(original) = restore {
            // SAFETY: original 是本次 patch 前读出的同一区间字节
            let _ = unsafe { bytesig::guard(|| write_code(target_ptr, original)) };
        }
        let _ = trampoline::release(tramp_ptr);
    };

    let mut original = vec![0u8; current::MIN_OVERWRITE_LEN];
    let patch_result = unsafe {
        bytesig::guard(|| -> Result<(), Errno> {
            ptr::copy_nonoverlapping(target_ptr, original.as_mut_ptr(), original.len());
            write_code(target_ptr, &patch)
        })
    };
    // patch 阶段信号归类为 WriteCrash，与 rewrite 阶段的 HookRewriteCrash 区分
    let patch_result = match patch_result {
        Err(Errno::HookRewriteCrash) => Err(Errno::WriteCrash),
        other => other.and_then(|inner| inner),
    };
    if let Err(e) = patch_result {
        rollback(None);
        return Err(e);
    }

    let sw = Switch {
        target: target_ptr,
        original: original.clone(),
        patch: patch.to_vec(),
        tramp_addr: tramp_ptr.as_ptr(),
        orig_slot,
    };
    // 并发安装同一 target 时只有一方能登记；落败方回写自己读到的字节并归还跳板
    if let Err(e) = switch::insert(sw) {
        rollback(Some(&original));
        return Err(e);
    }
    Ok(HookStub {
        handle: stub::alloc(target_ptr) as *mut c_void,
    })
}

// 改写 prologue 到跳板并在尾部跳回原函数剩余部分，返回入口补丁字节
unsafe fn fill_trampoline(
    target_ptr: *mut u8,
    replacement: *const c_void,
    prologue: &[u8; PROLOGUE_PROBE_LEN],
    tramp_ptr: NonNull<u8>,
) -> Result<[u8; current::MIN_OVERWRITE_LEN], Errno> {
    let rewritten = current::rewrite(prologue, target_ptr as u64, tramp_ptr.as_ptr() as u64)?;
    if rewritten.consumed < current::MIN_OVERWRITE_LEN
        || rewritten.bytes.len() + current::MIN_OVERWRITE_LEN > trampoline::RELOCATION_CAPACITY
    {
        return Err(Errno::HookRewriteFailed);
    }

    let mut tail = [0u8; current::MIN_OVERWRITE_LEN];
    // SAFETY: consumed 不超过 PROLOGUE_PROBE_LEN，指针仍处于原函数区域
    let tail_to = unsafe { target_ptr.add(rewritten.consumed) };
    current::make_absolute_jump(tail_to, &mut tail)?;

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
        android::clear_icache(tramp_ptr.as_ptr(), rewritten.bytes.len() + tail.len());
    }

    let mut patch = [0u8; current::MIN_OVERWRITE_LEN];
    unsafe {
        trampoline::prepare_entry_jump(
            target_ptr,
            replacement as *const u8,
            tramp_ptr.as_ptr(),
            &mut patch,
        )
    }?;
    Ok(patch)
}

// 改写代码页：mprotect_rx 失败时回写原字节，避免 target 跳入将被回收的跳板
pub(super) unsafe fn write_code(target_ptr: *mut u8, bytes: &[u8]) -> Result<(), Errno> {
    let mut previous = vec![0u8; bytes.len()];
    unsafe {
        ptr::copy_nonoverlapping(target_ptr, previous.as_mut_ptr(), previous.len());
        android::mprotect_rwx(target_ptr, bytes.len())?;
        // arm64 16B 对齐 patch 走 LDXP/STXP 单拷贝原子；否则退化 memcpy
        android::write_inst(target_ptr, bytes);
        if let Err(e) = android::mprotect_rx(target_ptr, bytes.len()) {
            android::write_inst(target_ptr, &previous);
            let _ = android::mprotect_rx(target_ptr, bytes.len());
            android::clear_icache(target_ptr, bytes.len());
            return Err(e);
        }
        android::clear_icache(target_ptr, bytes.len());
    }
    Ok(())
}
