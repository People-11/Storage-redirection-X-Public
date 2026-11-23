// 纯函数工具模块：host 可编译，便于 cargo test --lib 覆盖
// 从 Android 模块抽离可测逻辑

use core::ffi::{CStr, c_char, c_int};
use core::slice;

// 取路径文件名；无分隔符整段原样返回，尾斜杠视作空名返回原串
pub fn basename_of(path: &str) -> &str {
    match path.rfind('/') {
        Some(i) if i + 1 < path.len() => &path[i + 1..],
        _ => path,
    }
}

// 合成 siglongjmp 回跳码：signum<<16 | (code>0 ? code<<8 : |code|)；编码 si_signo / si_code
pub fn encode_signal_exit(signum: c_int, code: c_int) -> c_int {
    let sig_part = ((signum as u32) & 0xFF) << 16;
    let code_part = if code > 0 {
        ((code as u32) & 0xFF) << 8
    } else if code < 0 {
        ((-(code as i64)) as u32) & 0xFF
    } else {
        0
    };
    (sig_part | code_part) as c_int
}

pub unsafe fn cstr_from_ptr_no_libc<'a>(ptr: *const c_char) -> Option<&'a CStr> {
    if ptr.is_null() {
        return None;
    }
    let mut len = 0usize;
    loop {
        // SAFETY: 调用方保证 ptr 指向可读 NUL 终止字符串；逐字节扫描避免走 libc strlen
        let ch = unsafe { *ptr.add(len) };
        if ch == 0 {
            break;
        }
        len += 1;
    }
    // SAFETY: 上面已找到 NUL 终止，长度覆盖 ptr..=ptr+len
    Some(unsafe {
        CStr::from_bytes_with_nul_unchecked(slice::from_raw_parts(ptr.cast::<u8>(), len + 1))
    })
}
