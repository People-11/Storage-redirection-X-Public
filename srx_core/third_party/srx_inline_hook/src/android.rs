// 封装 Android 侧内存页权限翻转、页大小查询与指令缓存刷新

use core::ffi::{CStr, c_char, c_int, c_void};
use core::ptr;
use core::str;

use once_cell::sync::OnceCell;

use crate::errno::Errno;

pub unsafe fn mprotect_rwx(addr: *mut u8, len: usize) -> Result<(), Errno> {
    unsafe {
        mprotect_range(
            addr,
            len,
            libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
        )
    }
}

pub unsafe fn mprotect_rx(addr: *mut u8, len: usize) -> Result<(), Errno> {
    unsafe { mprotect_range(addr, len, libc::PROT_READ | libc::PROT_EXEC) }
}

unsafe fn mprotect_range(addr: *mut u8, len: usize, prot: c_int) -> Result<(), Errno> {
    if len == 0 {
        return Ok(());
    }
    let page = page_size();
    let start = (addr as usize) & !(page - 1);
    let end = ((addr as usize).wrapping_add(len).wrapping_add(page - 1)) & !(page - 1);
    // SAFETY: start 已页对齐，长度覆盖请求区间且非零
    let ret = unsafe { libc::mprotect(start as *mut c_void, end - start, prot) };
    if ret != 0 {
        return Err(Errno::Mprot);
    }
    Ok(())
}

pub fn page_size() -> usize {
    static PAGE: OnceCell<usize> = OnceCell::new();
    *PAGE.get_or_init(|| {
        // SAFETY: sysconf 对 _SC_PAGESIZE 不依赖外部状态
        let v = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        if v <= 0 { 4096 } else { v as usize }
    })
}

// 给匿名页附上可读名称，便于 /proc/<pid>/maps 排障
// prctl 在旧 kernel / 无 CONFIG_ANON_VMA_NAME 时返回 -1；仅诊断，忽略错误
pub unsafe fn name_anon_page(addr: *mut u8, len: usize, name: &CStr) {
    // SAFETY: prctl 对未知参数返回 -1，不解引用 name 以外的指针
    unsafe {
        libc::prctl(
            libc::PR_SET_VMA,
            libc::PR_SET_VMA_ANON_NAME as libc::c_ulong,
            addr as libc::c_ulong,
            len as libc::c_ulong,
            name.as_ptr() as libc::c_ulong,
        );
    }
}

pub fn device_api_level() -> i32 {
    static API_LEVEL: OnceCell<i32> = OnceCell::new();
    *API_LEVEL.get_or_init(|| {
        let mut buf = [0u8; libc::PROP_VALUE_MAX as usize];
        // SAFETY: 常量 key 为 NUL 终止；buf 长度满足 PROP_VALUE_MAX
        let len = unsafe {
            libc::__system_property_get(
                c"ro.build.version.sdk".as_ptr(),
                buf.as_mut_ptr() as *mut c_char,
            )
        };
        if len <= 0 {
            return 0;
        }
        str::from_utf8(&buf[..len as usize])
            .ok()
            .and_then(|s| s.parse::<i32>().ok())
            .unwrap_or(0)
    })
}

pub unsafe fn clear_icache(addr: *mut u8, len: usize) {
    #[cfg(target_arch = "aarch64")]
    {
        // aarch64 要求 self-modifying code 手动 DC CVAU + IC IVAU + DSB/ISB
        // line size 取 arm64 通行最小值 16，不足会重复但无副作用
        use core::arch::asm;
        if len == 0 {
            return;
        }
        let line: usize = 16;
        let start = (addr as usize) & !(line - 1);
        let end = (addr as usize).wrapping_add(len);
        let mut p = start;
        while p < end {
            // SAFETY: p 位于 addr..addr+len 覆盖的可执行页
            unsafe { asm!("dc cvau, {0}", in(reg) p, options(nostack, preserves_flags)) };
            p = p.wrapping_add(line);
        }
        // SAFETY: 纯屏障指令
        unsafe { asm!("dsb ish", options(nostack, preserves_flags)) };
        p = start;
        while p < end {
            // SAFETY: 同上
            unsafe { asm!("ic ivau, {0}", in(reg) p, options(nostack, preserves_flags)) };
            p = p.wrapping_add(line);
        }
        // SAFETY: 纯屏障指令
        unsafe {
            asm!("dsb ish", options(nostack, preserves_flags));
            asm!("isb", options(nostack, preserves_flags));
        }
    }
    #[cfg(target_arch = "x86_64")]
    {
        // x86_64 指令缓存由硬件维护一致，占位以对齐跨架构签名
        let _ = (addr, len);
    }
}

// 对齐路径下做单拷贝原子写；不满足退化 memcpy；返回值指示是否走了原子路径
pub unsafe fn write_inst(target: *mut u8, bytes: &[u8]) -> bool {
    let addr = target as usize;
    let len = bytes.len();

    #[cfg(target_arch = "aarch64")]
    if len == 16 && addr.is_multiple_of(16) {
        // SAFETY: 对齐 16 字节的连续 16 字节写；LDXP/STXP 在合法 AArch64 内存上定义良好
        unsafe {
            let mut lo_bytes = [0u8; 8];
            let mut hi_bytes = [0u8; 8];
            lo_bytes.copy_from_slice(&bytes[..8]);
            hi_bytes.copy_from_slice(&bytes[8..]);
            let lo = u64::from_le_bytes(lo_bytes);
            let hi = u64::from_le_bytes(hi_bytes);
            atomic_store_16(target, lo, hi);
        }
        return true;
    }
    if len == 8 && addr.is_multiple_of(8) {
        let mut value = [0u8; 8];
        value.copy_from_slice(bytes);
        let v = u64::from_le_bytes(value);
        // SAFETY: 8 字节对齐下 AArch64 / x86_64 原子 u64 store 单拷贝原子
        unsafe { (target as *mut u64).write(v) };
        return true;
    }
    if len == 4 && addr.is_multiple_of(4) {
        let mut value = [0u8; 4];
        value.copy_from_slice(bytes);
        let v = u32::from_le_bytes(value);
        // SAFETY: 4 字节对齐下原子 u32 store 单拷贝原子
        unsafe { (target as *mut u32).write(v) };
        return true;
    }

    // 退化 memcpy：x86_64 14B 路径、arm64 非 16B 对齐路径走这里
    // SAFETY: 调用方已 mprotect RWX；上层 guard 捕获信号
    unsafe { ptr::copy_nonoverlapping(bytes.as_ptr(), target, len) };
    false
}

// AArch64 LDXP/STXP 循环做 128 位原子写；addr 必须 16 字节对齐
#[cfg(target_arch = "aarch64")]
unsafe fn atomic_store_16(addr: *mut u8, lo: u64, hi: u64) {
    use core::arch::asm;
    // SAFETY: addr 16 字节对齐由调用方保证；LDAXP/STLXP 自带 acquire/release
    unsafe {
        asm!(
            "2:",
            "ldaxp {tlo}, {thi}, [{addr}]",
            "stlxp {s:w}, {lo}, {hi}, [{addr}]",
            "cbnz {s:w}, 2b",
            addr = in(reg) addr,
            lo = in(reg) lo,
            hi = in(reg) hi,
            tlo = out(reg) _,
            thi = out(reg) _,
            s = out(reg) _,
            options(nostack, preserves_flags),
        );
    }
}
