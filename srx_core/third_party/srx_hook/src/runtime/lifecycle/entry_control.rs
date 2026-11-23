// 运行时控制入口：proxy 调用链中的前驱函数查询
use std::ffi::c_void;

use super::proxy;

pub(super) fn with_prev_func<R, F>(func: *mut c_void, f: F) -> Option<R>
where
    F: FnOnce(*mut c_void) -> R,
{
    proxy::with_prev_func(func, f)
}
