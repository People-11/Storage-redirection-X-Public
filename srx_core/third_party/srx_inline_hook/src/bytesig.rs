// 每个线程只发布当前最内层守卫，信号注册与转发由 handlers 负责。

use core::ffi::c_int;
use core::ptr;
use core::sync::atomic::{AtomicI32, AtomicPtr, Ordering};

use crate::errno::Errno;
use crate::util::encode_signal_exit;

mod handlers;

pub use handlers::init;

// 固定数组便于在信号处理器中无锁查找当前线程。
const MAX_PROTECTED_THREADS: usize = 256;
// sigjmp_buf 兼容上限：aarch64 bionic ~272B / x86_64 bionic ~160B
const SIGJMP_BUF_WORDS: usize = 64;

#[repr(C, align(16))]
pub struct SigJmpBuf([u64; SIGJMP_BUF_WORDS]);

impl SigJmpBuf {
    pub const fn zeroed() -> Self {
        Self([0; SIGJMP_BUF_WORDS])
    }
}

unsafe extern "C" {
    fn sigsetjmp(env: *mut SigJmpBuf, savesigs: c_int) -> c_int;
    fn siglongjmp(env: *mut SigJmpBuf, val: c_int) -> !;
}

struct Slots {
    tids: [AtomicI32; MAX_PROTECTED_THREADS],
    jbufs: [AtomicPtr<SigJmpBuf>; MAX_PROTECTED_THREADS],
}

impl Slots {
    const fn new() -> Self {
        Self {
            tids: [const { AtomicI32::new(0) }; MAX_PROTECTED_THREADS],
            jbufs: [const { AtomicPtr::new(ptr::null_mut()) }; MAX_PROTECTED_THREADS],
        }
    }
}

static SLOTS: Slots = Slots::new();

#[inline]
fn current_tid() -> i32 {
    // SAFETY: SYS_gettid 纯查询，无副作用
    unsafe { libc::syscall(libc::SYS_gettid) as i32 }
}

unsafe fn handle_guard_signal(signum: c_int, info: *mut libc::siginfo_t) {
    // 用户发送的异步信号不属于受保护内存操作的故障。
    let code = unsafe { (*info).si_code };
    if code <= 0 {
        return;
    }
    let tid = current_tid();
    for i in 0..MAX_PROTECTED_THREADS {
        if SLOTS.tids[i].load(Ordering::Acquire) != tid {
            continue;
        }
        let jbuf = SLOTS.jbufs[i].load(Ordering::Acquire);
        if !jbuf.is_null() {
            unsafe { siglongjmp(jbuf, encode_signal_exit(signum, code)) };
        }
        return;
    }
}

// 闭包只执行可被中断的叶子操作，不能依赖被跳过栈帧的析构或解锁。
pub unsafe fn guard<F, R>(f: F) -> Result<R, Errno>
where
    F: FnOnce() -> R,
{
    if !handlers::is_installed() {
        return Err(Errno::Uninit);
    }
    let tid = current_tid();
    let mut jbuf = SigJmpBuf::zeroed();
    let jbuf_ptr: *mut SigJmpBuf = &mut jbuf;

    let (index, is_owner) = occupy_slot(tid)?;
    let _registration = Registration {
        index,
        is_owner,
        previous: SLOTS.jbufs[index].load(Ordering::Acquire),
    };

    // SAFETY: sigsetjmp 保存上下文；siglongjmp 回跳时 rc 非零
    let rc = unsafe { sigsetjmp(jbuf_ptr, 1) };
    if rc == 0 {
        // 完成上下文保存后才允许信号处理器跳回这一层。
        SLOTS.jbufs[index].store(jbuf_ptr, Ordering::Release);
        return Ok(f());
    }
    Err(Errno::HookRewriteCrash)
}

fn occupy_slot(tid: i32) -> Result<(usize, bool), Errno> {
    if let Some(index) = SLOTS
        .tids
        .iter()
        .position(|slot| slot.load(Ordering::Acquire) == tid)
    {
        return Ok((index, false));
    }
    for i in 0..MAX_PROTECTED_THREADS {
        if SLOTS.tids[i]
            .compare_exchange(0, tid, Ordering::AcqRel, Ordering::Relaxed)
            .is_ok()
        {
            return Ok((i, true));
        }
    }
    Err(Errno::NotSupport)
}

struct Registration {
    index: usize,
    is_owner: bool,
    previous: *mut SigJmpBuf,
}

impl Drop for Registration {
    fn drop(&mut self) {
        SLOTS.jbufs[self.index].store(self.previous, Ordering::Release);
        if self.is_owner {
            SLOTS.tids[self.index].store(0, Ordering::Release);
        }
    }
}
