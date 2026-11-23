// 跳板池：按页 mmap RWX + 固定 slot 分配；free 走延迟复用以兼容仍在执行跳板的线程

use core::ffi::c_void;
use core::mem;
use core::ptr;
use core::ptr::NonNull;
#[cfg(target_arch = "aarch64")]
use std::fs;
use std::sync::Mutex;

use once_cell::sync::Lazy;

use crate::android;
use crate::arch::current;
use crate::errno::Errno;

// ARM64 最坏重定位 6×28 字节，另需续接跳转与独立入口中转各 16 字节。
#[cfg(target_arch = "aarch64")]
pub const TRAMPOLINE_SIZE: usize = 256;
#[cfg(not(target_arch = "aarch64"))]
pub const TRAMPOLINE_SIZE: usize = 128;
#[cfg(target_arch = "aarch64")]
pub const RELOCATION_CAPACITY: usize = TRAMPOLINE_SIZE - 16;
#[cfg(not(target_arch = "aarch64"))]
pub const RELOCATION_CAPACITY: usize = TRAMPOLINE_SIZE;
// 延迟复用 10s：避开其他线程仍在 trampoline 内执行的窗口
const REUSE_DELAY_SECS: u32 = 10;

struct Page {
    base: NonNull<u8>,
    page_bytes: usize,
    slot_count: usize,
    // 每 slot 一个 flag：bit31=used；低 31 位=free 时间戳（单调秒）
    flags: Vec<u32>,
}

// SAFETY: Page.base 为 mmap 基址，仅在 POOL 锁保护下访问
unsafe impl Send for Page {}

struct Pool {
    pages: Mutex<Vec<Page>>,
}

static POOL: Lazy<Pool> = Lazy::new(|| Pool {
    pages: Mutex::new(Vec::new()),
});

fn monotonic_secs() -> u32 {
    // 加 86400 偏移避开 ts=0 歧义（flag 低 31 位=0 表示未 release）
    // SAFETY: clock_gettime 仅读取内核时钟
    let mut ts: libc::timespec = unsafe { mem::zeroed() };
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    (ts.tv_sec as u32).wrapping_add(24 * 60 * 60)
}

pub fn acquire() -> Result<NonNull<u8>, Errno> {
    let mut pages = POOL.pages.lock().map_err(|_| Errno::NotSupport)?;
    let now = monotonic_secs();
    for page in pages.iter_mut() {
        if let Some(ptr) = try_alloc_in_page(page, now) {
            return Ok(ptr);
        }
    }
    let new = new_page()?;
    pages.push(new);
    let page = pages.last_mut().ok_or(Errno::Oom)?;
    try_alloc_in_page(page, now).ok_or(Errno::Oom)
}

#[cfg(target_arch = "aarch64")]
pub fn acquire_near(target: usize) -> Result<NonNull<u8>, Errno> {
    let range = (
        target.saturating_sub(1 << 27),
        target.saturating_add(1 << 27),
    );
    let now = monotonic_secs();
    {
        let mut pages = POOL.pages.lock().map_err(|_| Errno::NotSupport)?;
        for page in pages.iter_mut() {
            let start = page.base.as_ptr() as usize;
            if start < range.0 || start + page.page_bytes > range.1 {
                continue;
            }
            if let Some(slot) = try_alloc_in_page(page, now) {
                return Ok(slot);
            }
        }
    }
    let new = new_near_page(target, range)?;
    let mut pages = POOL.pages.lock().map_err(|_| Errno::NotSupport)?;
    pages.push(new);
    try_alloc_in_page(pages.last_mut().ok_or(Errno::Oom)?, now).ok_or(Errno::Oom)
}

#[cfg(target_arch = "aarch64")]
fn new_near_page(target: usize, range: (usize, usize)) -> Result<Page, Errno> {
    let maps = fs::read_to_string("/proc/self/maps").map_err(|_| Errno::Oom)?;
    let page_bytes = android::page_size();
    let mut previous_end = (range.0 + page_bytes - 1) & !(page_bytes - 1);
    let mut candidates = Vec::new();
    for line in maps.lines() {
        let span = line.split_whitespace().next().ok_or(Errno::NotSupport)?;
        let (start, end) = span.split_once('-').ok_or(Errno::NotSupport)?;
        let start = usize::from_str_radix(start, 16).map_err(|_| Errno::NotSupport)?;
        let end = usize::from_str_radix(end, 16).map_err(|_| Errno::NotSupport)?;
        let gap_end = start.min(range.1);
        if previous_end + page_bytes <= gap_end {
            let candidate = (target & !(page_bytes - 1))
                .clamp(previous_end, (gap_end - page_bytes) & !(page_bytes - 1));
            candidates.push(candidate);
        }
        previous_end = previous_end.max(end);
        if previous_end >= range.1 {
            break;
        }
    }
    if previous_end + page_bytes <= range.1 {
        candidates.push(previous_end);
    }
    candidates.sort_unstable_by_key(|address| address.abs_diff(target));
    for candidate in candidates {
        let page = match new_page_at(candidate as *mut c_void) {
            Ok(page) => page,
            Err(Errno::Oom) => continue,
            Err(error) => return Err(error),
        };
        let address = page.base.as_ptr() as usize;
        if address >= range.0 && address + page_bytes <= range.1 {
            return Ok(page);
        }
        // 地址提示可能被内核忽略，只释放本次分配的页，不覆盖现有映射。
        unsafe { libc::munmap(page.base.as_ptr().cast(), page.page_bytes) };
    }
    Err(Errno::Oom)
}

pub unsafe fn prepare_entry_jump(
    target: *mut u8,
    replacement: *const u8,
    trampoline: *mut u8,
    patch: &mut [u8],
) -> Result<(), Errno> {
    #[cfg(target_arch = "aarch64")]
    {
        let relay = unsafe { trampoline.add(TRAMPOLINE_SIZE - 16) };
        current::make_relative_jump(target, relay, patch)?;
        let mut relay_bytes = [0u8; 16];
        current::make_absolute_jump(replacement, &mut relay_bytes)?;
        unsafe {
            android::write_inst(relay, &relay_bytes);
            android::clear_icache(relay, relay_bytes.len());
        }
        Ok(())
    }
    #[cfg(not(target_arch = "aarch64"))]
    {
        let _ = (target, trampoline);
        current::make_absolute_jump(replacement, patch)
    }
}

fn try_alloc_in_page(page: &mut Page, now: u32) -> Option<NonNull<u8>> {
    for i in 0..page.slot_count {
        let f = page.flags[i];
        if f >> 31 != 0 {
            continue;
        }
        let ts = f & 0x7FFF_FFFF;
        if ts != 0 && (now <= ts || now - ts <= REUSE_DELAY_SECS) {
            continue;
        }
        page.flags[i] = 0x8000_0000;
        // SAFETY: i < slot_count 保证 slot 位于 page 有效区内
        let slot = unsafe { page.base.as_ptr().add(i * TRAMPOLINE_SIZE) };
        // SAFETY: slot 指向 RWX 页内 TRAMPOLINE_SIZE 字节
        unsafe { ptr::write_bytes(slot, 0, TRAMPOLINE_SIZE) };
        return NonNull::new(slot);
    }
    None
}

fn new_page() -> Result<Page, Errno> {
    new_page_at(ptr::null_mut())
}

fn new_page_at(address: *mut c_void) -> Result<Page, Errno> {
    let page_bytes = android::page_size();
    // 地址仅作提示，内核不得覆盖现有映射。
    let raw = unsafe {
        libc::mmap(
            address,
            page_bytes,
            libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    if raw == libc::MAP_FAILED {
        return Err(Errno::Oom);
    }
    let base = NonNull::new(raw as *mut u8).ok_or(Errno::Oom)?;
    // SAFETY: base 指向刚 mmap 的匿名页；prctl 失败仅影响诊断命名
    unsafe {
        android::name_anon_page(base.as_ptr(), page_bytes, c"srx_inline_hook_trampo");
    }
    let slot_count = page_bytes / TRAMPOLINE_SIZE;
    Ok(Page {
        base,
        page_bytes,
        slot_count,
        flags: vec![0u32; slot_count],
    })
}

pub fn release(addr: NonNull<u8>) -> Result<(), Errno> {
    let mut pages = POOL.pages.lock().map_err(|_| Errno::NotSupport)?;
    let now = monotonic_secs();
    let target = addr.as_ptr() as usize;
    for page in pages.iter_mut() {
        let base = page.base.as_ptr() as usize;
        let end = base + page.page_bytes;
        if target >= base && target < end {
            let offset = target - base;
            if !offset.is_multiple_of(TRAMPOLINE_SIZE) {
                return Err(Errno::UnhookTrampoMismatch);
            }
            let idx = offset / TRAMPOLINE_SIZE;
            if idx >= page.slot_count || page.flags[idx] >> 31 == 0 {
                return Err(Errno::UnhookTrampoMismatch);
            }
            page.flags[idx] = now & 0x7FFF_FFFF;
            return Ok(());
        }
    }
    Err(Errno::UnhookTrampoMismatch)
}

// 诊断快照：pages/总 slot/占用/冷却/可立即复用
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TrampolineStats {
    pub pages: usize,
    pub slots_total: usize,
    pub slots_used: usize,
    pub slots_cooldown: usize,
    pub slots_free: usize,
}

pub fn stats() -> TrampolineStats {
    let Ok(pages) = POOL.pages.lock() else {
        return TrampolineStats::default();
    };
    let now = monotonic_secs();
    let mut s = TrampolineStats {
        pages: pages.len(),
        ..TrampolineStats::default()
    };
    for page in pages.iter() {
        s.slots_total += page.slot_count;
        for i in 0..page.slot_count {
            let f = page.flags[i];
            if f >> 31 != 0 {
                s.slots_used += 1;
                continue;
            }
            let ts = f & 0x7FFF_FFFF;
            if ts != 0 && (now <= ts || now - ts <= REUSE_DELAY_SECS) {
                s.slots_cooldown += 1;
            } else {
                s.slots_free += 1;
            }
        }
    }
    s
}
