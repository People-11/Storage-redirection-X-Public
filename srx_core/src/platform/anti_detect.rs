use std::ffi::CString;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

const PR_SET_VMA: libc::c_int = 0x53564d41;
const PR_SET_VMA_ANON_NAME: libc::c_ulong = 0;
const ANON_REGION_LOG_STEP: u64 = 128;
// 命名 guest 代码缓存会破坏转译器内部管理并触发信号异常
const TRANSLATOR_MARKERS: &[&str] = &[
    "libndk_translation.so", // berberis (AOSP / Google)
    "libberberis",           // berberis 相关库前缀
    "libhoudini",            // Intel Houdini
    "houdini",               // /system/lib/arm[64]/nb/houdini 等路径
    "libnb.so",              // Intel native bridge
];
static ANON_REGION_LOG_COUNT: AtomicU64 = AtomicU64::new(0);

#[inline]
fn should_log_step(count: u64, step: u64) -> bool {
    count == 1 || count.is_multiple_of(step)
}

pub fn name_anonymous_executable_regions() -> usize {
    let mut count = 0;
    let file = match File::open("/proc/self/maps") {
        Ok(f) => f,
        Err(_) => return 0,
    };
    let reader = BufReader::new(file);
    let lines: Vec<String> = reader.lines().map_while(Result::ok).collect();

    // 命中转译器标志则整体跳过，避免误伤 guest 代码缓存
    if lines
        .iter()
        .any(|l| TRANSLATOR_MARKERS.iter().any(|m| l.contains(m)))
    {
        log::info!("translator detected, skip anon rename");
        return 0;
    }

    for line in lines {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 5 {
            continue;
        }

        let range = parts[0];
        let perms = parts[1];
        let dev = parts[3];
        if perms != "r-xp" || dev != "00:00" {
            continue;
        }

        if parts.len() > 5 && !parts[5].is_empty() {
            continue;
        }

        let mut range_parts = range.split('-');
        let start_str = match range_parts.next() {
            Some(s) => s,
            None => continue,
        };
        let end_str = match range_parts.next() {
            Some(s) => s,
            None => continue,
        };
        let start = match usize::from_str_radix(start_str, 16) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let end = match usize::from_str_radix(end_str, 16) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let len = end.saturating_sub(start);
        if len == 0 {
            continue;
        }

        if set_vma_name(start, len, "dalvik-jit-code-cache").is_ok() {
            let log_count = ANON_REGION_LOG_COUNT.fetch_add(1, Ordering::Relaxed) + 1;
            if should_log_step(log_count, ANON_REGION_LOG_STEP) {
                log::info!(
                    "anon region named range=0x{:x}-0x{:x} kb={} name=dalvik-jit-code-cache n={}",
                    start,
                    end,
                    len / 1024,
                    log_count
                );
            }
            count += 1;
        }
    }

    count
}

fn set_vma_name(addr: usize, len: usize, name: &str) -> Result<(), ()> {
    let c_name = CString::new(name).map_err(|_| ())?;
    let result = unsafe {
        libc::prctl(
            PR_SET_VMA,
            PR_SET_VMA_ANON_NAME,
            addr as libc::c_ulong,
            len as libc::c_ulong,
            c_name.as_ptr() as libc::c_ulong,
        )
    };
    if result != 0 {
        return Err(());
    }
    Ok(())
}

// mremap flags（部分 target 的 libc 未导出常量，这里固定取内核值）
const MREMAP_MAYMOVE: libc::c_int = 1;
const MREMAP_FIXED: libc::c_int = 2;
static SELF_RELOCATED: AtomicBool = AtomicBool::new(false);

struct Seg {
    start: usize,
    len: usize,
    // 该段在 .so 文件内的偏移；偏移 0 的段起始处是 ELF 头
    offset: usize,
    prot: libc::c_int,
    readable: bool,
    exec: bool,
}
struct SegCopy {
    src: *mut libc::c_void,
    dst: usize,
    len: usize,
    exec: bool,
}

// 把本模块自身的文件背书映射整体搬进匿名内存，消除 /proc/self/maps 里
// /data/adb/modules/.../<abi>.so 的路径泄露，以及 "maps 有 / dl_iterate_phdr 无"
// 的孤儿映射指纹。
//
// 仅可对常驻进程调用（未请求 DLCLOSE 的进程）。会被 DLCLOSE 的进程由 ReZygisk
// 负责 munmap 清理，若在那里搬迁，ReZygisk 后续按原 base/size 卸载会打到我们的
// 匿名段上导致崩溃。
//
// 安全性：用 mremap(MREMAP_FIXED) 原子替换每个段。单次调用在内核内完成
// "解除 dst 旧映射 + 把 src 匿名映射移动到 dst"，用户态全程挂起，返回时 dst
// 已是内容字节级一致、地址不变的匿名映射。因此即使正在替换的就是当前执行的
// .text，svc 返回后落回的还是同一地址同样字节，不会崩。任一段 mremap 失败时
// 该 dst 保持原映射不变（mremap 全有或全无），故部分失败也不会留下未映射代码段。
pub fn relocate_self() -> usize {
    if SELF_RELOCATED.swap(true, Ordering::AcqRel) {
        return 0;
    }

    let segs = collect_self_segments();
    if segs.is_empty() {
        log::info!("self relocate: no file-backed module segments found");
        return 0;
    }

    // 阶段一：原段尚在，逐段拷到匿名内存并设好最终权限。失败则整体放弃、保持原状。
    let mut copies: Vec<SegCopy> = Vec::with_capacity(segs.len());
    for seg in &segs {
        match stage_segment_copy(seg) {
            Some(c) => copies.push(c),
            None => {
                for c in &copies {
                    unsafe { libc::munmap(c.src, c.len) };
                }
                log::warn!("self relocate: stage failed, aborted (mappings untouched)");
                return 0;
            }
        }
    }

    // 阶段二：逐段原子落位。此循环体本身在 .text 内，但每次 mremap 的非映射窗口
    // 全部位于内核态，故安全。
    let mut done = 0usize;
    let total = copies.len();
    for c in &copies {
        // libc 0.2 未对 android 导出 mremap 包装，直接走 syscall。
        // 成功返回新地址（== dst），失败返回 -1。
        let ret = unsafe {
            libc::syscall(
                libc::SYS_mremap,
                c.src,
                c.len,
                c.len,
                (MREMAP_MAYMOVE | MREMAP_FIXED) as libc::c_long,
                c.dst as *mut libc::c_void,
            )
        };
        if ret == -1 {
            // dst 仍是原文件映射，未被破坏；回收没用上的副本，继续其余段
            unsafe { libc::munmap(c.src, c.len) };
            continue;
        }
        // dst 现在是匿名映射：给可执行段命名以混入 ART JIT 代码缓存
        // 此处只命中我们自己的段，不会动到转译器（houdini/berberis）区域
        if c.exec {
            let _ = set_vma_name(c.dst, c.len, "dalvik-jit-code-cache");
        }
        done += 1;
    }

    log::info!("self relocate done segments={}/{}", done, total);
    done
}

fn collect_self_segments() -> Vec<Seg> {
    let anchor = relocate_self as *const () as usize;
    let content = match std::fs::read_to_string("/proc/self/maps") {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };

    let mut module_path = None;
    for line in content.lines() {
        if let Some((start, end, _perms, _offset, Some(path))) = parse_maps_line(line)
            && anchor >= start
            && anchor < end
            && path.starts_with('/')
        {
            module_path = Some(path);
            break;
        }
    }
    let Some(module_path) = module_path else {
        return Vec::new();
    };

    let mut segs = Vec::new();
    for line in content.lines() {
        if let Some((start, end, perms, offset, Some(path))) = parse_maps_line(line) {
            if path != module_path {
                continue;
            }
            let len = end.saturating_sub(start);
            if len == 0 {
                continue;
            }
            let (prot, readable, exec) = perms_to_prot(perms);
            segs.push(Seg {
                start,
                len,
                offset,
                prot,
                readable,
                exec,
            });
        }
    }
    segs
}

fn stage_segment_copy(seg: &Seg) -> Option<SegCopy> {
    // 源不可读则临时加读权限（段归我们所有，无副作用，且马上会被替换掉）
    if !seg.readable {
        let r = unsafe {
            libc::mprotect(
                seg.start as *mut libc::c_void,
                seg.len,
                seg.prot | libc::PROT_READ,
            )
        };
        if r != 0 {
            return None;
        }
    }

    let src = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            seg.len,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    if src == libc::MAP_FAILED {
        return None;
    }

    unsafe { std::ptr::copy_nonoverlapping(seg.start as *const u8, src as *mut u8, seg.len) };

    // 偏移 0 的段起始是 ELF 头：抹掉魔数及 Ehdr，挫败"扫描匿名段找 \x7fELF / 解析隐藏
    // ELF"类注入检测。运行期不再需要本模块的 ELF 头（已加载且 BIND_NOW 重定位完毕，
    // 异常处理为 abort），故清零安全。只在确认确为 ELF 头时动手。
    if seg.offset == 0 && seg.len >= 64 {
        let p = src as *mut u8;
        unsafe {
            if *p == 0x7f && *p.add(1) == b'E' && *p.add(2) == b'L' && *p.add(3) == b'F' {
                std::ptr::write_bytes(p, 0, 64);
            }
        }
    }

    let r = unsafe { libc::mprotect(src, seg.len, seg.prot) };
    if r != 0 {
        unsafe { libc::munmap(src, seg.len) };
        return None;
    }

    Some(SegCopy {
        src,
        dst: seg.start,
        len: seg.len,
        exec: seg.exec,
    })
}

fn parse_maps_line(line: &str) -> Option<(usize, usize, &str, usize, Option<&str>)> {
    let mut it = line.split_whitespace();
    let range = it.next()?;
    let perms = it.next()?;
    let offset_str = it.next()?;
    let _dev = it.next()?;
    let _inode = it.next()?;
    let path = it.next();
    let dash = range.find('-')?;
    let start = usize::from_str_radix(&range[..dash], 16).ok()?;
    let end = usize::from_str_radix(range.get(dash + 1..)?, 16).ok()?;
    let offset = usize::from_str_radix(offset_str, 16).ok()?;
    Some((start, end, perms, offset, path))
}

fn perms_to_prot(perms: &str) -> (libc::c_int, bool, bool) {
    let b = perms.as_bytes();
    let r = b.first() == Some(&b'r');
    let w = b.get(1) == Some(&b'w');
    let x = b.get(2) == Some(&b'x');
    (
        (if r { libc::PROT_READ } else { 0 })
            | (if w { libc::PROT_WRITE } else { 0 })
            | (if x { libc::PROT_EXEC } else { 0 }),
        r,
        x,
    )
}
