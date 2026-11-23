// hook 操作审计记录的写入、格式化与导出
use crate::api::{
    HookStub, RECORD_ITEM_CALLER_LIB_NAME, RECORD_ITEM_ERRNO, RECORD_ITEM_LIB_NAME,
    RECORD_ITEM_NEW_ADDR, RECORD_ITEM_OP, RECORD_ITEM_STUB, RECORD_ITEM_SYM_NAME,
    RECORD_ITEM_TIMESTAMP,
};
use crate::errno::Errno;
use std::fmt::Write;
use std::time::{SystemTime, UNIX_EPOCH};

use super::state::{CoreState, RecordEntry, RecordOp};

// 环形缓冲区上限，超出后淘汰最早的记录
const MAX_RECORDS: usize = 4096;
const CALLER_LIB_UNKNOWN: &str = "unknown";

#[inline]
fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0)
}

// recordable 关闭时静默丢弃，满时淘汰队首
#[inline]
fn push_record(state: &mut CoreState, entry: RecordEntry) {
    if !state.recordable {
        return;
    }
    if state.records.len() >= MAX_RECORDS {
        state.records.remove(0);
    }
    state.records.push(entry);
}

pub(super) fn add_hook_record(
    state: &mut CoreState,
    status_code: i32,
    lib_name: &str,
    sym_name: &str,
    new_addr: usize,
    stub: HookStub,
) {
    push_record(
        state,
        RecordEntry {
            op: RecordOp::Hook,
            ts_ms: now_ms(),
            status_code,
            caller_lib_name: CALLER_LIB_UNKNOWN.to_string(),
            lib_name: lib_name.to_string(),
            sym_name: sym_name.to_string(),
            new_addr,
            stub,
        },
    );
}

pub(super) fn add_unhook_record(state: &mut CoreState, status_code: i32, stub: HookStub) {
    push_record(
        state,
        RecordEntry {
            op: RecordOp::Unhook,
            ts_ms: now_ms(),
            status_code,
            caller_lib_name: CALLER_LIB_UNKNOWN.to_string(),
            lib_name: String::new(),
            sym_name: String::new(),
            new_addr: 0,
            stub,
        },
    );
}

fn op_name(op: RecordOp) -> &'static str {
    match op {
        RecordOp::Hook => "HOOK",
        RecordOp::Unhook => "UNHOOK",
    }
}

// 按 item_flags 位掩码选择性输出字段，CSV 格式
fn format_entry(entry: &RecordEntry, item_flags: u32) -> String {
    let mut line = String::new();
    if item_flags & RECORD_ITEM_TIMESTAMP != 0 {
        let _ = write!(line, "{},", entry.ts_ms);
    }
    if item_flags & RECORD_ITEM_CALLER_LIB_NAME != 0 {
        let _ = write!(line, "{},", entry.caller_lib_name);
    }
    if item_flags & RECORD_ITEM_OP != 0 {
        let _ = write!(line, "{},", op_name(entry.op));
    }
    if item_flags & RECORD_ITEM_LIB_NAME != 0 {
        let _ = write!(line, "{},", entry.lib_name);
    }
    if item_flags & RECORD_ITEM_SYM_NAME != 0 {
        let _ = write!(line, "{},", entry.sym_name);
    }
    if item_flags & RECORD_ITEM_NEW_ADDR != 0 {
        let _ = write!(line, "0x{:x},", entry.new_addr);
    }
    if item_flags & RECORD_ITEM_ERRNO != 0 {
        let _ = write!(line, "{},", entry.status_code);
    }
    if item_flags & RECORD_ITEM_STUB != 0 {
        let _ = write!(line, "0x{:x},", entry.stub);
    }
    line.push('\n');
    line
}

pub(super) fn get_records_text(state: &CoreState, item_flags: u32) -> Option<String> {
    if !state.recordable || state.records.is_empty() {
        return None;
    }
    let mut output = String::new();
    for entry in &state.records {
        output.push_str(&format_entry(entry, item_flags));
    }
    Some(output)
}

// 循环写入直到全部字节落盘，处理 short write
pub(super) fn dump_records_text(fd: i32, text: &str) -> Result<(), Errno> {
    if fd < 0 {
        return Err(Errno::InvalidArg);
    }
    let bytes = text.as_bytes();
    let mut offset = 0usize;
    while offset < bytes.len() {
        let written = unsafe {
            libc::write(
                fd,
                bytes[offset..].as_ptr() as *const libc::c_void,
                bytes.len() - offset,
            )
        };
        if written <= 0 {
            return Err(Errno::Invalid);
        }
        offset += written as usize;
    }
    Ok(())
}
