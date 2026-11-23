// 操作记录：默认关闭；开启后成功与失败均入环形队列
// 容量耗尽覆盖最旧项，关闭时不记录

use core::ffi::{CStr, c_void};
use core::mem;
use core::ptr;
use core::sync::atomic::{AtomicBool, Ordering};
use std::collections::VecDeque;
use std::env;
use std::sync::Mutex;

use bitflags::bitflags;
use once_cell::sync::Lazy;

use crate::bytesig;
use crate::errno::Errno;
use crate::symbol::addr_info;
use crate::util::basename_of;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordOp {
    HookFuncAddr,
    HookSymAddr,
    HookSymName,
    InterceptInstrAddr,
    InterceptFuncAddr,
    InterceptSymAddr,
    InterceptSymName,
    Unhook,
    Unintercept,
}

impl RecordOp {
    fn tag(self) -> &'static str {
        match self {
            Self::HookFuncAddr => "hook_func_addr",
            Self::HookSymAddr => "hook_sym_addr",
            Self::HookSymName => "hook_sym_name",
            Self::InterceptInstrAddr => "intercept_instr_addr",
            Self::InterceptFuncAddr => "intercept_func_addr",
            Self::InterceptSymAddr => "intercept_sym_addr",
            Self::InterceptSymName => "intercept_sym_name",
            Self::Unhook => "unhook",
            Self::Unintercept => "unintercept",
        }
    }
}

bitflags! {
    // RecordItems bit 位布局与公开 C ABI 对齐
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct RecordItems: u32 {
        const TIMESTAMP       = 1 << 0;
        const CALLER_LIB_NAME = 1 << 1;
        const OP              = 1 << 2;
        const LIB_NAME        = 1 << 3;
        const SYM_NAME        = 1 << 4;
        const SYM_ADDR        = 1 << 5;
        const NEW_ADDR        = 1 << 6;
        const BACKUP_LEN      = 1 << 7;
        const ERRNO           = 1 << 8;
        const STUB            = 1 << 9;
        const FLAGS           = 1 << 10;
    }
}

impl RecordItems {
    pub const ALL: Self = Self::TIMESTAMP
        .union(Self::CALLER_LIB_NAME)
        .union(Self::OP)
        .union(Self::LIB_NAME)
        .union(Self::SYM_NAME)
        .union(Self::SYM_ADDR)
        .union(Self::NEW_ADDR)
        .union(Self::BACKUP_LEN)
        .union(Self::ERRNO)
        .union(Self::STUB)
        .union(Self::FLAGS);
}

#[derive(Debug, Clone)]
pub struct Record {
    pub ts_ms: u64,
    pub caller_lib_name: Option<String>,
    pub op: RecordOp,
    pub target: usize,
    pub replacement: usize,
    pub errno: Errno,
    pub sym_name: Option<String>,
    pub lib_name: Option<String>,
    // hook 成功时记 rewriter 消耗的源字节数；失败或 unhook 为 None
    pub backup_len: Option<usize>,
    pub stub: usize,
    pub flags: Option<u32>,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct RecordMeta<'a> {
    pub lib_name: Option<&'a CStr>,
    pub sym_name: Option<&'a CStr>,
    pub caller_lib_name: Option<&'a CStr>,
    pub caller_addr: Option<usize>,
    pub stub: usize,
    pub flags: Option<u32>,
}

const CAPACITY: usize = 256;

static RECORDABLE: AtomicBool = AtomicBool::new(false);
// RECORD_ERROR：record() 内 Mutex 中毒时置位；dump 末尾追加 "error" 行给运维识别丢失记录
static RECORD_ERROR: AtomicBool = AtomicBool::new(false);
static RECORDS: Lazy<Mutex<VecDeque<Record>>> =
    Lazy::new(|| Mutex::new(VecDeque::with_capacity(CAPACITY)));

pub fn set_recordable(on: bool) {
    RECORDABLE.store(on, Ordering::Release);
}

pub fn is_recordable() -> bool {
    RECORDABLE.load(Ordering::Acquire)
}

pub fn record(
    op: RecordOp,
    target: usize,
    replacement: usize,
    errno: Errno,
    backup_len: Option<usize>,
) {
    record_with_meta(
        op,
        target,
        replacement,
        errno,
        backup_len,
        RecordMeta::default(),
    )
}

pub fn record_with_names(
    op: RecordOp,
    target: usize,
    replacement: usize,
    errno: Errno,
    backup_len: Option<usize>,
    lib_name: Option<&CStr>,
    sym_name: Option<&CStr>,
) {
    record_with_meta(
        op,
        target,
        replacement,
        errno,
        backup_len,
        RecordMeta {
            lib_name,
            sym_name,
            ..RecordMeta::default()
        },
    )
}

pub fn record_with_meta(
    op: RecordOp,
    target: usize,
    replacement: usize,
    errno: Errno,
    backup_len: Option<usize>,
    meta: RecordMeta<'_>,
) {
    if !is_recordable() {
        return;
    }
    let RecordMeta {
        lib_name,
        sym_name,
        caller_lib_name,
        caller_addr,
        stub,
        flags,
    } = meta;
    let (sym_name, lib_name) = if lib_name.is_some() || sym_name.is_some() {
        (
            sym_name.and_then(|s| normalized_name(s.to_str().ok())),
            lib_name.and_then(|s| normalized_basename(s.to_str().ok())),
        )
    } else if target != 0 {
        // SAFETY: guard 仅捕信号；addr_info 对任意 *const c_void 输入安全
        let info = unsafe { bytesig::guard(|| addr_info(target as *const c_void)) }
            .ok()
            .flatten();
        info.map(|i| {
            (
                normalized_name(i.sym_name.as_deref()),
                normalized_basename(i.lib_path.as_deref()),
            )
        })
        .unwrap_or((None, None))
    } else {
        (None, None)
    };
    let caller_lib_name = normalized_basename(caller_lib_name.and_then(|s| s.to_str().ok()))
        .or_else(|| caller_addr.and_then(default_caller_lib_name_by_addr))
        .or_else(default_caller_lib_name);
    let Ok(mut q) = RECORDS.lock() else {
        RECORD_ERROR.store(true, Ordering::Release);
        return;
    };
    if q.len() >= CAPACITY {
        q.pop_front();
    }
    q.push_back(Record {
        ts_ms: timestamp_ms(),
        caller_lib_name,
        op,
        target,
        replacement,
        errno,
        sym_name,
        lib_name,
        backup_len,
        stub,
        flags,
    });
}

// 快照一份当前记录，按入队顺序返回；不清空原队列
pub fn snapshot() -> Vec<Record> {
    RECORDS
        .lock()
        .map(|q| q.iter().cloned().collect())
        .unwrap_or_default()
}

// 当前累积记录条数；快照 .len() 等价但省一次 clone
pub fn count() -> usize {
    RECORDS.lock().map(|q| q.len()).unwrap_or(0)
}

// RECORD_ERROR 当前置位状态；诊断 / 运维观察用
pub fn has_record_error() -> bool {
    RECORD_ERROR.load(Ordering::Acquire)
}

// 清空环形队列；开关状态独立不受影响
// RECORD_ERROR 也同步清零：dump 不再暗示旧的失败信号
pub fn clear() {
    if let Ok(mut q) = RECORDS.lock() {
        q.clear();
    }
    RECORD_ERROR.store(false, Ordering::Release);
}

pub fn dump() -> String {
    dump_with_items(RecordItems::ALL)
}

// 按 items 过滤后直写 fd；循环消化 EINTR 与 partial write，保证写全
// recordable 关时直接 Ok(0)
pub fn dump_to_fd(fd: i32, items: RecordItems) -> Result<usize, Errno> {
    if !is_recordable() {
        return Ok(0);
    }
    if fd < 0 {
        return Err(Errno::InvalidArg);
    }
    let text = dump_with_items(items);
    let bytes = text.as_bytes();
    let mut written = 0usize;
    while written < bytes.len() {
        let remaining = &bytes[written..];
        // SAFETY: fd >= 0 由上方检查；buf 指针覆盖 remaining.len() 字节
        let n = unsafe { libc::write(fd, remaining.as_ptr() as *const c_void, remaining.len()) };
        if n < 0 {
            // SAFETY: bionic __errno 返回线程内有效 errno 槽位指针
            let err = unsafe { *libc::__errno() };
            if err == libc::EINTR {
                continue;
            }
            return Err(Errno::NotSupport);
        }
        written += n as usize;
    }
    Ok(written)
}

// 按 items 过滤输出；字段间以逗号拼接并以换行结尾，保持公开 C ABI 文本
// 锁内直遍历 VecDeque，避免 snapshot clone 全部 Record（含 String 字段）
pub fn dump_with_items(items: RecordItems) -> String {
    let mut out = String::new();
    let Ok(q) = RECORDS.lock() else {
        RECORD_ERROR.store(true, Ordering::Release);
        return out;
    };
    for r in q.iter() {
        append_record(&mut out, r, items);
    }
    drop(q);
    if RECORD_ERROR.load(Ordering::Acquire) {
        append_error_record(&mut out, items);
    }
    out
}

fn append_record(out: &mut String, r: &Record, items: RecordItems) {
    use core::fmt::Write as _;
    let is_unop = matches!(r.op, RecordOp::Unhook | RecordOp::Unintercept);
    let mut wrote_any = false;
    let push_field = |out: &mut String, wrote: &mut bool, f: &mut dyn FnMut(&mut String)| {
        f(out);
        out.push(',');
        *wrote = true;
    };
    if items.contains(RecordItems::TIMESTAMP) {
        push_field(out, &mut wrote_any, &mut |out| {
            let _ = write!(out, "{}", format_timestamp_ms(r.ts_ms));
        });
    }
    if items.contains(RecordItems::CALLER_LIB_NAME) {
        push_field(out, &mut wrote_any, &mut |out| {
            out.push_str(r.caller_lib_name.as_deref().unwrap_or("unknown"));
        });
    }
    if items.contains(RecordItems::OP) {
        push_field(out, &mut wrote_any, &mut |out| {
            out.push_str(r.op.tag());
        });
    }
    if items.contains(RecordItems::LIB_NAME) && !is_unop {
        push_field(out, &mut wrote_any, &mut |out| {
            out.push_str(r.lib_name.as_deref().unwrap_or("unknown"));
        });
    }
    if items.contains(RecordItems::SYM_NAME) && !is_unop {
        push_field(out, &mut wrote_any, &mut |out| {
            out.push_str(r.sym_name.as_deref().unwrap_or("unknown"));
        });
    }
    if items.contains(RecordItems::SYM_ADDR) && !is_unop {
        push_field(out, &mut wrote_any, &mut |out| {
            let _ = write!(out, "{:x}", r.target);
        });
    }
    if items.contains(RecordItems::NEW_ADDR) && !is_unop {
        push_field(out, &mut wrote_any, &mut |out| {
            let _ = write!(out, "{:x}", r.replacement);
        });
    }
    if items.contains(RecordItems::BACKUP_LEN) && !is_unop {
        push_field(out, &mut wrote_any, &mut |out| {
            let _ = write!(out, "{}", r.backup_len.unwrap_or(0));
        });
    }
    if items.contains(RecordItems::ERRNO) {
        push_field(out, &mut wrote_any, &mut |out| {
            let _ = write!(out, "{}", r.errno as i32);
        });
    }
    if items.contains(RecordItems::STUB) {
        push_field(out, &mut wrote_any, &mut |out| {
            let _ = write!(out, "{:x}", r.stub);
        });
    }
    if items.contains(RecordItems::FLAGS) && !is_unop {
        push_field(out, &mut wrote_any, &mut |out| {
            let _ = write!(out, "{}", r.flags.unwrap_or(0));
        });
    }
    if wrote_any {
        let _ = out.pop();
        out.push('\n');
    }
}

fn append_error_record(out: &mut String, items: RecordItems) {
    if items.is_empty() {
        return;
    }
    let mut wrote_any = false;
    let push = |out: &mut String, wrote: &mut bool, value: &str| {
        out.push_str(value);
        out.push(',');
        *wrote = true;
    };
    if items.contains(RecordItems::TIMESTAMP) {
        push(out, &mut wrote_any, "9999-99-99T00:00:00.000+00:00");
    }
    if items.contains(RecordItems::CALLER_LIB_NAME) {
        push(out, &mut wrote_any, "error");
    }
    if items.contains(RecordItems::OP) {
        push(out, &mut wrote_any, "error");
    }
    if !wrote_any {
        push(out, &mut wrote_any, "error");
    }
    let _ = out.pop();
    out.push('\n');
}

fn default_caller_lib_name_by_addr(addr: usize) -> Option<String> {
    // SAFETY: guard 仅捕信号；addr_info 对任意 *const c_void 输入安全
    let info = unsafe { bytesig::guard(|| addr_info(addr as *const c_void)) }
        .ok()
        .flatten()?;
    normalized_basename(info.lib_path.as_deref())
}

fn default_caller_lib_name() -> Option<String> {
    normalized_name(
        env::current_exe()
            .ok()
            .and_then(|p| p.file_name().map(|n| n.to_string_lossy().into_owned()))
            .as_deref(),
    )
}

fn normalized_basename(name: Option<&str>) -> Option<String> {
    normalized_name(name.map(basename_of))
}

fn normalized_name(name: Option<&str>) -> Option<String> {
    let name = name?;
    if name.is_empty() {
        None
    } else {
        Some(name.to_owned())
    }
}

fn timestamp_ms() -> u64 {
    // SAFETY: gettimeofday 仅读系统时钟
    let mut tv: libc::timeval = unsafe { mem::zeroed() };
    // SAFETY: tv 已完整初始化
    unsafe { libc::gettimeofday(&mut tv, ptr::null_mut()) };
    tv.tv_sec as u64 * 1000 + tv.tv_usec as u64 / 1000
}

fn format_timestamp_ms(ts_ms: u64) -> String {
    let secs = (ts_ms / 1000) as libc::time_t;
    let millis = ts_ms % 1000;
    let mut tm: libc::tm = unsafe { mem::zeroed() };
    // SAFETY: secs 与 tm 指针有效；上游 recorder 固定输出 +00:00
    unsafe { libc::gmtime_r(&secs, &mut tm) };
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}+00:00",
        tm.tm_year + 1900,
        tm.tm_mon + 1,
        tm.tm_mday,
        tm.tm_hour,
        tm.tm_min,
        tm.tm_sec,
        millis
    )
}
