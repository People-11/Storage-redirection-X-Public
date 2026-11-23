use core::sync::atomic;
use core::sync::atomic::Ordering;

use super::install::write_code;
use super::prelude::*;

pub unsafe fn unhook(stub: HookStub) -> Result<(), Errno> {
    // SAFETY: stub 来自先前 hook 返回值
    let result = runtime::check_ready().and_then(|()| unsafe { unhook_inner(stub) });
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
    result
}

unsafe fn unhook_inner(stub: HookStub) -> Result<(), Errno> {
    let id = stub.handle as usize;
    let target_ptr = stub::target_of(id).ok_or(Errno::UnhookNotFound)?;
    let sw = switch::remove(target_ptr)?;
    stub::take(id);
    // SAFETY: sw 来自注册表，target/patch/tramp 字段由 hook 路径写入
    unsafe { unhook_finalize(sw) }
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
    let cmp = match cmp_result {
        Err(Errno::HookRewriteCrash) => Err(Errno::UnhookCmpCrash),
        Err(e) => Err(e),
        Ok(true) => Ok(()),
        Ok(false) => Err(Errno::UnhookTrampoMismatch),
    };
    if let Err(e) = cmp {
        // cmp 失败不 restore：避免踩坏第三方 patch 或读崩的未知状态
        if let Some(tp) = NonNull::new(sw.tramp_addr) {
            let _ = trampoline::release(tp);
        }
        return Err(e);
    }

    // 恢复 prologue 走 guard：被 hook 函数此刻可能正被其他线程执行
    let restore = unsafe {
        bytesig::guard(|| -> Result<(), Errno> {
            write_code(target_ptr, &sw.original)?;
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
    release_switch(&sw);
    restore
}

fn release_switch(sw: &Switch) {
    if let Some(slot) = sw.orig_slot {
        // SAFETY: 槽位由调用方保障存活期 ≥ hook 存活期
        unsafe { ptr::write(slot, ptr::null()) };
    }
    if let Some(tp) = NonNull::new(sw.tramp_addr) {
        let _ = trampoline::release(tp);
    }
}

// 目标 so 卸载后清理其中的 hook：代码已不存在，只回收跳板并清零 orig 槽
pub(crate) fn cleanup_hooks_for_dlinfo(info: &libc::dl_phdr_info) {
    let base = info.dlpi_addr as usize;
    let drained = switch::drain_filter(|target| is_addr_in_dlinfo(target, info));
    for sw in drained {
        stub::remove_by_target(sw.target);
        release_switch(&sw);
        sh_info!(
            target: "srx_inline_hook",
            "cleanup_after_dlclose target=0x{:x} base=0x{:x}",
            sw.target as usize,
            base,
        );
    }
}

fn is_addr_in_dlinfo(addr: usize, info: &libc::dl_phdr_info) -> bool {
    let base = info.dlpi_addr as usize;
    (0..info.dlpi_phnum as usize).any(|i| {
        // SAFETY: dlpi_phdr 数组长度由 dlpi_phnum 保证
        let ph = unsafe { &*info.dlpi_phdr.add(i) };
        let seg_start = base.saturating_add(ph.p_vaddr as usize);
        let seg_end = seg_start.saturating_add(ph.p_memsz as usize);
        ph.p_type == libc::PT_LOAD && seg_start <= addr && addr < seg_end
    })
}

pub fn prev_func(stub: HookStub) -> Result<*const c_void, Errno> {
    let target = stub::target_of(stub.handle as usize).ok_or(Errno::UnhookNotFound)?;
    switch::trampoline_of(target)
        .map(|p| p as *const c_void)
        .ok_or(Errno::UnhookNotFound)
}
