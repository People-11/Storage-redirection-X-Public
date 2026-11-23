// 进程级运行时状态：调试开关与 init 终态 errno

use core::sync::atomic::{AtomicBool, AtomicI32, Ordering};

use crate::bytesig;
use crate::errno::Errno;
use crate::linker;

static DEBUG: AtomicBool = AtomicBool::new(false);
// init 终态：Uninit 表示未调过；成功 Ok；失败写具体错误，下次 init 重试
static INIT_ERRNO: AtomicI32 = AtomicI32::new(Errno::Uninit as i32);

pub fn init(debuggable: bool) -> Result<(), Errno> {
    if is_ready() {
        return Ok(());
    }
    DEBUG.store(debuggable, Ordering::Release);
    bytesig::init().inspect_err(|e| store_errno(*e))?;
    // linker hook 自身经 hook 路径安装，需先标记就绪
    store_errno(Errno::Ok);
    linker::install_linker_hooks().inspect_err(|e| store_errno(*e))
}

fn store_errno(e: Errno) {
    INIT_ERRNO.store(e as i32, Ordering::Release);
}

pub fn check_ready() -> Result<(), Errno> {
    match Errno::from_i32(INIT_ERRNO.load(Ordering::Acquire)) {
        Errno::Ok => Ok(()),
        e => Err(e),
    }
}

pub fn is_ready() -> bool {
    check_ready().is_ok()
}

pub fn is_debug() -> bool {
    DEBUG.load(Ordering::Acquire)
}
