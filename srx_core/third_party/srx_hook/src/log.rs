use std::fmt;
use std::sync::atomic::{AtomicI32, Ordering};

pub const ANDROID_LOG_DEBUG: i32 = 3;
pub const ANDROID_LOG_INFO: i32 = 4;
pub const ANDROID_LOG_WARN: i32 = 5;
pub const ANDROID_LOG_ERROR: i32 = 6;

const LOG_TAG_ANDROID: &[u8] = b"srx_hook\0";

static LOG_PRIORITY: AtomicI32 = AtomicI32::new(ANDROID_LOG_WARN);

#[link(name = "log")]
unsafe extern "C" {
    fn __android_log_write(prio: i32, tag: *const i8, text: *const i8) -> i32;
}

// 设置日志级别，启用时输出 DEBUG 及以上，禁用时仅输出 WARN 及以上
pub fn set_debug_enabled(enabled: bool) {
    let priority = if enabled {
        ANDROID_LOG_DEBUG
    } else {
        ANDROID_LOG_WARN
    };
    LOG_PRIORITY.store(priority, Ordering::SeqCst);
}

fn enabled(priority: i32) -> bool {
    LOG_PRIORITY.load(Ordering::Relaxed) <= priority
}

fn write_log(priority: i32, args: fmt::Arguments) {
    if !enabled(priority) {
        return;
    }

    unsafe {
        let mut text = format!("{args}").into_bytes();
        for byte in &mut text {
            if *byte == 0 {
                *byte = b' ';
            }
        }
        text.push(0);

        __android_log_write(
            priority,
            LOG_TAG_ANDROID.as_ptr() as *const i8,
            text.as_ptr() as *const i8,
        );
    }
}

pub(crate) fn info(args: fmt::Arguments) {
    write_log(ANDROID_LOG_INFO, args);
}

pub(crate) fn debug(args: fmt::Arguments) {
    write_log(ANDROID_LOG_DEBUG, args);
}

pub(crate) fn warn(args: fmt::Arguments) {
    write_log(ANDROID_LOG_WARN, args);
}

pub(crate) fn error(args: fmt::Arguments) {
    write_log(ANDROID_LOG_ERROR, args);
}
