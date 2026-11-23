use core::ffi::{c_int, c_void};
use core::mem;
use core::ptr;
use core::sync::atomic::{AtomicBool, AtomicPtr, Ordering};
use std::sync::Mutex;

use once_cell::sync::{Lazy, OnceCell};

use crate::errno::Errno;
use crate::linker::{LoadedSymbolLookup, find_loaded_symbol};

use super::handle_guard_signal;

type Sigaction = unsafe extern "C" fn(c_int, *const libc::sigaction, *mut libc::sigaction) -> c_int;
type Sigprocmask = unsafe extern "C" fn(c_int, *const libc::sigset_t, *mut libc::sigset_t) -> c_int;

struct SignalApi {
    register: Sigaction,
    kernel_action: Sigaction,
    kernel_mask: Sigprocmask,
}

struct SignalState {
    previous: AtomicPtr<libc::sigaction>,
    is_installed: AtomicBool,
    has_reset: AtomicBool,
}

impl SignalState {
    const fn new() -> Self {
        Self {
            previous: AtomicPtr::new(ptr::null_mut()),
            is_installed: AtomicBool::new(false),
            has_reset: AtomicBool::new(false),
        }
    }
}

static API: OnceCell<SignalApi> = OnceCell::new();
static INIT_LOCK: Lazy<Mutex<()>> = Lazy::new(|| Mutex::new(()));
static INSTALLED: AtomicBool = AtomicBool::new(false);
static SEGV: SignalState = SignalState::new();
static BUS: SignalState = SignalState::new();
static ILL: SignalState = SignalState::new();

fn resolve_api() -> Result<SignalApi, Errno> {
    let LoadedSymbolLookup::Found(action) = find_loaded_symbol(c"libc.so", c"sigaction") else {
        return Err(Errno::InitSafe);
    };
    let LoadedSymbolLookup::Found(mask) = find_loaded_symbol(c"libc.so", c"sigprocmask") else {
        return Err(Errno::InitSafe);
    };
    // ART 保留内核入口，普通 sigaction 注册不占用有限的特殊 handler 槽。
    let register = match find_loaded_symbol(c"libsigchain.so", c"sigaction") {
        LoadedSymbolLookup::Found(symbol) => symbol,
        LoadedSymbolLookup::LibNotFound => action,
        LoadedSymbolLookup::SymNotFound => return Err(Errno::InitSafe),
    };
    Ok(SignalApi {
        register: unsafe { mem::transmute::<*mut c_void, Sigaction>(register) },
        kernel_action: unsafe { mem::transmute::<*mut c_void, Sigaction>(action) },
        kernel_mask: unsafe { mem::transmute::<*mut c_void, Sigprocmask>(mask) },
    })
}

pub(super) fn is_installed() -> bool {
    INSTALLED.load(Ordering::Acquire)
}

pub fn init() -> Result<(), Errno> {
    if is_installed() {
        return Ok(());
    }
    let _lock = INIT_LOCK.lock().map_err(|_| Errno::InitSafe)?;
    let api = API.get_or_try_init(resolve_api)?;
    for (signum, state, error) in [
        (libc::SIGSEGV, &SEGV, Errno::InitSigsegv),
        (libc::SIGBUS, &BUS, Errno::InitSigbus),
        (libc::SIGILL, &ILL, Errno::InitSigill),
    ] {
        if !state.is_installed.load(Ordering::Acquire) {
            unsafe { install(api, signum, state) }.map_err(|()| error)?;
        }
    }
    INSTALLED.store(true, Ordering::Release);
    Ok(())
}

unsafe fn install(api: &SignalApi, signum: c_int, state: &SignalState) -> Result<(), ()> {
    let mut previous = Box::new(mem::zeroed::<libc::sigaction>());
    if (api.register)(signum, ptr::null(), &mut *previous) != 0 {
        return Err(());
    }
    let mut action: libc::sigaction = mem::zeroed();
    libc::sigfillset(&mut action.sa_mask);
    const SA_EXPOSE_TAGBITS: c_int = 0x800;
    action.sa_flags = libc::SA_SIGINFO
        | libc::SA_ONSTACK
        | (previous.sa_flags & (libc::SA_RESTART | SA_EXPOSE_TAGBITS));
    // 忽略信号不应中断可重启的阻塞调用。
    if previous.sa_sigaction == libc::SIG_IGN {
        action.sa_flags |= libc::SA_RESTART;
    }
    action.sa_sigaction = handler as *const () as libc::sighandler_t;
    // 先发布安装窗口的前任，随后发布替换操作返回的准确前任；两份都保持只读。
    state
        .previous
        .store(Box::into_raw(previous), Ordering::Release);
    let mut replaced = Box::new(mem::zeroed::<libc::sigaction>());
    if (api.register)(signum, &action, &mut *replaced) != 0 {
        return Err(());
    }
    state
        .previous
        .store(Box::into_raw(replaced), Ordering::Release);
    state.is_installed.store(true, Ordering::Release);
    Ok(())
}

unsafe extern "C" fn handler(signum: c_int, info: *mut libc::siginfo_t, context: *mut c_void) {
    handle_guard_signal(signum, info);
    let state = match signum {
        libc::SIGSEGV => &SEGV,
        libc::SIGBUS => &BUS,
        libc::SIGILL => &ILL,
        _ => return,
    };
    // API 与前任均在安装 handler 前发布，信号路径不进行初始化。
    let api = API.get_unchecked();
    let previous = &*state.previous.load(Ordering::Acquire);
    if state.has_reset.load(Ordering::Acquire) || previous.sa_sigaction == libc::SIG_DFL {
        terminate(api, signum);
    }
    if previous.sa_sigaction == libc::SIG_IGN {
        return;
    }
    if previous.sa_flags & libc::SA_RESETHAND != 0 && state.has_reset.swap(true, Ordering::AcqRel) {
        terminate(api, signum);
    }
    forward(api, previous, signum, info, context);
}

unsafe fn forward(
    api: &SignalApi,
    previous: &libc::sigaction,
    signum: c_int,
    info: *mut libc::siginfo_t,
    context: *mut c_void,
) {
    #[cfg(target_arch = "aarch64")]
    let mut mask = (*(context as *const libc::ucontext_t)).uc_sigmask;
    #[cfg(target_arch = "x86_64")]
    let mut mask = ptr::addr_of!((*(context as *const libc::ucontext_t)).uc_sigmask64)
        .cast::<libc::sigset_t>()
        .read();
    for signal in 1..=(mem::size_of::<libc::sigset_t>() * 8) as c_int {
        if libc::sigismember(&previous.sa_mask, signal) == 1 {
            libc::sigaddset(&mut mask, signal);
        }
    }
    if previous.sa_flags & libc::SA_NODEFER == 0 {
        libc::sigaddset(&mut mask, signum);
    }
    let mut saved: libc::sigset_t = mem::zeroed();
    if (api.kernel_mask)(libc::SIG_SETMASK, &mask, &mut saved) != 0 {
        terminate(api, signum);
    }
    if previous.sa_flags & libc::SA_SIGINFO != 0 {
        let callback: unsafe extern "C" fn(c_int, *mut libc::siginfo_t, *mut c_void) =
            mem::transmute(previous.sa_sigaction);
        callback(signum, info, context);
    } else {
        let callback: unsafe extern "C" fn(c_int) = mem::transmute(previous.sa_sigaction);
        callback(signum);
    }
    if (api.kernel_mask)(libc::SIG_SETMASK, &saved, ptr::null_mut()) != 0 {
        terminate(api, signum);
    }
}

unsafe fn terminate(api: &SignalApi, signum: c_int) -> ! {
    let mut action: libc::sigaction = mem::zeroed();
    action.sa_sigaction = libc::SIG_DFL;
    let mut mask: libc::sigset_t = mem::zeroed();
    libc::sigaddset(&mut mask, signum);
    if (api.kernel_action)(signum, &action, ptr::null_mut()) == 0
        && (api.kernel_mask)(libc::SIG_UNBLOCK, &mask, ptr::null_mut()) == 0
    {
        libc::raise(signum);
    }
    libc::_exit(128 + signum);
}
