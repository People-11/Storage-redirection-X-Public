// 线程局部 "最近一次 API 结果"：仅存 i32，避免 hook libc 时 pthread_setspecific 递归
// 默认值 Ok：对齐 pthread_getspecific 未 set 时返回 NULL（0）的语义

use core::cell::Cell;

use crate::errno::Errno;

thread_local! {
    #[expect(clippy::missing_const_for_thread_local, reason = "Android TLS 宏展开仍报告已存在的常量初始化")]
    static LAST: Cell<i32> = const { Cell::new(Errno::Ok as i32) };
}

pub fn set(e: Errno) {
    LAST.with(|c| c.set(e as i32));
}

pub fn reset() {
    set(Errno::Ok);
}

pub fn get() -> Errno {
    LAST.with(|c| Errno::from_i32(c.get()))
}
