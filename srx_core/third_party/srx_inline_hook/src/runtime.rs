// 进程级运行时状态：初始化标志、调试开关、模式、init 终态 errno
// hook 注册表已迁至 switch.rs；此处仅持有全局开关

use core::sync::atomic::{AtomicBool, AtomicI32, Ordering};

use crate::bytesig;
use crate::errno::Errno;
use crate::linker;

static INITED: AtomicBool = AtomicBool::new(false);
static DEBUG: AtomicBool = AtomicBool::new(false);
static DISABLED: AtomicBool = AtomicBool::new(false);
// 0=Shared 1=Unique 2=Multi；初值 Shared(0)，init 首次写入后不覆盖
static MODE: AtomicI32 = AtomicI32::new(0);
// init 终态：Uninit 表示未调过；成功 Ok；失败写具体错误
static INIT_ERRNO: AtomicI32 = AtomicI32::new(Errno::Uninit as i32);

pub fn init() -> Result<(), Errno> {
    if INITED.load(Ordering::Acquire) {
        return Ok(());
    }
    // init 前已 set_disable(true) → INIT_ERRNO 记 Disabled，不跑真实 init
    if DISABLED.load(Ordering::Acquire) {
        INIT_ERRNO.store(Errno::Disabled as i32, Ordering::Release);
        return Err(Errno::Disabled);
    }
    match bytesig::init() {
        Ok(()) => {
            INIT_ERRNO.store(Errno::Ok as i32, Ordering::Release);
            match linker::install_linker_hooks() {
                Ok(()) => {
                    INITED.store(true, Ordering::Release);
                    INIT_ERRNO.store(Errno::Ok as i32, Ordering::Release);
                    Ok(())
                }
                Err(e) => {
                    INIT_ERRNO.store(e as i32, Ordering::Release);
                    Err(e)
                }
            }
        }
        Err(e) => {
            INIT_ERRNO.store(e as i32, Ordering::Release);
            Err(e)
        }
    }
}

pub fn is_inited() -> bool {
    INITED.load(Ordering::Acquire)
}

pub fn get_init_errno() -> Errno {
    Errno::from_i32(INIT_ERRNO.load(Ordering::Acquire))
}

pub fn set_debug(on: bool) {
    DEBUG.store(on, Ordering::Release);
}

// 仅首次 init 前生效；已 INITED 后由 set_debug 显式调整
pub fn set_debug_if_uninit(on: bool) {
    if !INITED.load(Ordering::Acquire) {
        DEBUG.store(on, Ordering::Release);
    }
}

pub fn is_debug() -> bool {
    DEBUG.load(Ordering::Acquire)
}

// 仅首次 init 保存；幂等调用不覆盖
pub fn set_mode_if_uninit(mode: i32) {
    if !INITED.load(Ordering::Acquire) {
        MODE.store(mode, Ordering::Release);
    }
}

pub fn get_mode() -> i32 {
    MODE.load(Ordering::Acquire)
}

pub fn set_disabled(on: bool) {
    DISABLED.store(on, Ordering::Release);
}

pub fn is_disabled() -> bool {
    DISABLED.load(Ordering::Acquire)
}
