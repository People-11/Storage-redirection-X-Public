// 最小 pending 队列：按 lib + sym 暂存 UNIQUE hook，dl_init pre 命中后补装
// 句柄仍走 HookStub.handle；已完成任务复用 active_stub，未完成任务保留 pending id

use core::ffi::{CStr, c_void};
use core::mem;
use core::ptr;
use core::sync::atomic::{AtomicUsize, Ordering};
use std::collections::HashMap;
use std::sync::Mutex;

use once_cell::sync::Lazy;

use crate::api::{self, HookMode, HookOptions, HookStub, HookedCallback, InterceptedCallback};
use crate::errno::Errno;
use crate::intercept::Interceptor;
use crate::linker;
use crate::recorder::{self, RecordMeta, RecordOp};
use crate::switch::SwitchMode;
use crate::util::cstr_from_ptr_no_libc;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum PendingTaskKind {
    Hook,
    Intercept,
}

#[derive(Clone)]
pub struct PendingTask {
    pub kind: PendingTaskKind,
    pub lib_name: Box<[u8]>,
    pub sym_name: Box<[u8]>,
    pub replacement: usize,
    pub orig_addr: usize,
    pub mode: HookMode,
    pub flags: u32,
    pub data: usize,
    pub hooked: Option<HookedCallback>,
    pub hooked_arg: usize,
    pub intercepted: Option<InterceptedCallback>,
    pub intercepted_arg: usize,
    pub caller_addr: usize,
    pub is_finished: bool,
    pub is_corrupted: bool,
    pub target_addr: usize,
    pub active_stub: usize,
}

// SAFETY: 裸指针仅做地址值存储，真实解引用仍在调用线程完成
unsafe impl Send for PendingTask {}

static NEXT_PENDING_ID: AtomicUsize = AtomicUsize::new(1usize << 48);
static TASKS: Lazy<Mutex<HashMap<usize, PendingTask>>> = Lazy::new(|| Mutex::new(HashMap::new()));

fn alloc_pending_id() -> usize {
    NEXT_PENDING_ID.fetch_add(1, Ordering::Relaxed)
}

fn cbytes(bytes: &[u8]) -> &CStr {
    // SAFETY: 所有保存字符串都来自 CStr::to_bytes_with_nul()
    unsafe { CStr::from_bytes_with_nul_unchecked(bytes) }
}

fn task_stub(id: usize, task: &PendingTask) -> HookStub {
    if task.is_finished && task.active_stub != 0 {
        HookStub {
            handle: task.active_stub as *mut c_void,
        }
    } else {
        HookStub {
            handle: id as *mut c_void,
        }
    }
}

pub fn create_hook(
    lib_name: &CStr,
    sym_name: &CStr,
    replacement: *const c_void,
    orig_addr: *mut *const c_void,
    mode: HookMode,
    options: HookOptions<HookedCallback>,
) -> Result<HookStub, Errno> {
    if replacement.is_null() || lib_name.to_bytes().is_empty() || sym_name.to_bytes().is_empty() {
        return Err(Errno::InvalidArg);
    }
    let id = alloc_pending_id();
    let task = PendingTask {
        kind: PendingTaskKind::Hook,
        lib_name: lib_name.to_bytes_with_nul().into(),
        sym_name: sym_name.to_bytes_with_nul().into(),
        replacement: replacement as usize,
        orig_addr: orig_addr as usize,
        mode,
        flags: options.flags,
        data: 0,
        hooked: options.callback,
        hooked_arg: options.callback_arg as usize,
        intercepted: None,
        intercepted_arg: 0,
        caller_addr: options.caller_addr,
        is_finished: false,
        is_corrupted: false,
        target_addr: 0,
        active_stub: 0,
    };
    TASKS
        .lock()
        .map_err(|_| Errno::NotSupport)?
        .insert(id, task);
    Ok(HookStub {
        handle: id as *mut c_void,
    })
}

pub fn create_intercept(
    lib_name: &CStr,
    sym_name: &CStr,
    pre: Interceptor,
    data: *mut c_void,
    options: HookOptions<InterceptedCallback>,
) -> Result<HookStub, Errno> {
    if lib_name.to_bytes().is_empty() || sym_name.to_bytes().is_empty() || pre as usize == 0 {
        return Err(Errno::InvalidArg);
    }
    let id = alloc_pending_id();
    let task = PendingTask {
        kind: PendingTaskKind::Intercept,
        lib_name: lib_name.to_bytes_with_nul().into(),
        sym_name: sym_name.to_bytes_with_nul().into(),
        replacement: pre as usize,
        orig_addr: 0,
        mode: HookMode::Shared,
        flags: options.flags,
        data: data as usize,
        hooked: None,
        hooked_arg: 0,
        intercepted: options.callback,
        intercepted_arg: options.callback_arg as usize,
        caller_addr: options.caller_addr,
        is_finished: false,
        is_corrupted: false,
        target_addr: 0,
        active_stub: 0,
    };
    TASKS
        .lock()
        .map_err(|_| Errno::NotSupport)?
        .insert(id, task);
    Ok(HookStub {
        handle: id as *mut c_void,
    })
}

pub fn is_pending_handle(handle: *mut c_void) -> bool {
    let id = handle as usize;
    id >= (1usize << 48)
}

pub fn hook_stub_of(handle: *mut c_void) -> Option<HookStub> {
    let id = handle as usize;
    let g = TASKS.lock().ok()?;
    let task = g.get(&id)?;
    Some(task_stub(id, task))
}

pub fn active_stub_of(handle: *mut c_void) -> Option<HookStub> {
    let id = handle as usize;
    let g = TASKS.lock().ok()?;
    let task = g.get(&id)?;
    if task.is_finished && task.active_stub != 0 {
        Some(HookStub {
            handle: task.active_stub as *mut c_void,
        })
    } else {
        None
    }
}

pub fn prev_func(handle: *mut c_void) -> Result<*const c_void, Errno> {
    let stub = active_stub_of(handle).ok_or(Errno::UnhookNotFound)?;
    // SAFETY: active_stub 来自已安装成功的真实 hook
    unsafe { api::prev_func(stub) }
}

pub fn unhook(handle: *mut c_void, caller_addr: usize) -> Result<(), Errno> {
    let id = handle as usize;
    let task = TASKS.lock().map_err(|_| Errno::NotSupport)?.remove(&id);
    let Some(task) = task else {
        return Err(Errno::UnhookNotFound);
    };
    if !task.is_finished {
        return Err(Errno::UnhookOnUnfinishedTask);
    }
    if task.is_corrupted {
        return Err(Errno::UnhookOnErrorTask);
    }
    let stub = HookStub {
        handle: task.active_stub as *mut c_void,
    };
    match task.kind {
        PendingTaskKind::Hook => {
            // SAFETY: active_stub 对应仍在 switch/stub 注册表中的真实 hook
            unsafe { api::unhook_active(stub, caller_addr) }
        }
        PendingTaskKind::Intercept => {
            // SAFETY: active_stub 为已补装成功的 intercept 句柄
            unsafe { api::unintercept_with_caller_addr(stub, caller_addr) }
        }
    }
}

pub fn try_pending_from_info(info: *mut libc::dl_phdr_info, size: usize) {
    if info.is_null() {
        return;
    }
    let matched = {
        let Ok(g) = TASKS.lock() else {
            return;
        };
        let Some(name) = info_name(info) else {
            return;
        };
        g.iter()
            .filter_map(|(id, task)| {
                if task.is_finished || task.is_corrupted {
                    return None;
                }
                let task_lib = cbytes(&task.lib_name);
                let task_name = task_lib.to_str().ok()?;
                linker::path_name_matches(&name, task_name).then_some(*id)
            })
            .collect::<Vec<_>>()
    };
    for id in matched {
        let _ = install_pending(id, info, size);
    }
}

pub fn reset_after_dlclose(info: &libc::dl_phdr_info) {
    let reset_ids = {
        let Ok(g) = TASKS.lock() else {
            return;
        };
        g.iter()
            .filter_map(|(id, task)| {
                (task.is_finished
                    && task.target_addr != 0
                    && api::is_addr_in_dlinfo(task.target_addr, info))
                .then_some(*id)
            })
            .collect::<Vec<_>>()
    };
    let Ok(mut g) = TASKS.lock() else {
        return;
    };
    for id in reset_ids {
        let Some(task) = g.get_mut(&id) else {
            continue;
        };
        task.is_finished = false;
        task.is_corrupted = false;
        task.target_addr = 0;
        task.active_stub = 0;
    }
}

fn install_pending(id: usize, info: *mut libc::dl_phdr_info, _size: usize) -> Result<(), Errno> {
    let snapshot = {
        let g = TASKS.lock().map_err(|_| Errno::NotSupport)?;
        let task = g.get(&id).ok_or(Errno::UnhookNotFound)?;
        if task.is_finished || task.is_corrupted {
            return Ok(());
        }
        task.clone()
    };

    // SAFETY: info 来自 linker dl_init pre，同步期间结构体内容稳定
    let info_ref = unsafe { &*info };
    let Some(sym_addr) = linker::find_symbol_in_dlinfo(info_ref, cbytes(&snapshot.sym_name)) else {
        let mut g = TASKS.lock().map_err(|_| Errno::NotSupport)?;
        if let Some(task) = g.get_mut(&id) {
            task.is_finished = true;
            task.is_corrupted = true;
            task.target_addr = 0;
            task.active_stub = 0;
            run_pending_callback(task, Errno::DlSymFailed as i32, ptr::null());
        }
        return Err(Errno::DlSymFailed);
    };
    let sym = sym_addr as *mut c_void;

    let mode = match snapshot.mode {
        HookMode::Multi => SwitchMode::Multi,
        HookMode::Shared => SwitchMode::Shared,
        HookMode::Unique => SwitchMode::Unique,
    };
    let orig_addr = snapshot.orig_addr as *mut *const c_void;
    let result = match snapshot.kind {
        PendingTaskKind::Hook => unsafe {
            api::hook_inline_for_pending(
                sym,
                snapshot.replacement as *const c_void,
                orig_addr,
                mode,
            )
        },
        PendingTaskKind::Intercept => {
            let pre: Interceptor = unsafe { mem::transmute(snapshot.replacement) };
            let data = snapshot.data as *mut c_void;
            let stub = api::intercept_addr_impl(sym, pre, data, snapshot.flags)?;
            Ok((stub, 0))
        }
    };

    let mut g = TASKS.lock().map_err(|_| Errno::NotSupport)?;
    let task = g.get_mut(&id).ok_or(Errno::UnhookNotFound)?;
    match result {
        Ok((stub, consumed)) => {
            task.is_finished = true;
            task.is_corrupted = false;
            task.target_addr = sym as usize;
            task.active_stub = stub.handle as usize;
            recorder::record_with_meta(
                if snapshot.kind == PendingTaskKind::Hook {
                    RecordOp::HookSymName
                } else {
                    RecordOp::InterceptSymName
                },
                sym as usize,
                snapshot.replacement,
                Errno::Ok,
                Some(consumed),
                RecordMeta {
                    lib_name: Some(cbytes(&snapshot.lib_name)),
                    sym_name: Some(cbytes(&snapshot.sym_name)),
                    caller_addr: (snapshot.caller_addr != 0).then_some(snapshot.caller_addr),
                    stub: stub.handle as usize,
                    flags: Some(snapshot.flags),
                    ..RecordMeta::default()
                },
            );
            run_pending_callback(task, Errno::Ok as i32, sym as *const c_void);
            Ok(())
        }
        Err(e) => {
            task.is_finished = true;
            task.is_corrupted = true;
            task.target_addr = sym as usize;
            recorder::record_with_meta(
                if snapshot.kind == PendingTaskKind::Hook {
                    RecordOp::HookSymName
                } else {
                    RecordOp::InterceptSymName
                },
                sym as usize,
                snapshot.replacement,
                e,
                None,
                RecordMeta {
                    lib_name: Some(cbytes(&snapshot.lib_name)),
                    sym_name: Some(cbytes(&snapshot.sym_name)),
                    caller_addr: (snapshot.caller_addr != 0).then_some(snapshot.caller_addr),
                    flags: Some(snapshot.flags),
                    ..RecordMeta::default()
                },
            );
            run_pending_callback(task, e as i32, sym as *const c_void);
            Err(e)
        }
    }
}

fn run_pending_callback(task: &PendingTask, error: i32, sym_addr: *const c_void) {
    match task.kind {
        PendingTaskKind::Hook => {
            let Some(cb) = task.hooked else {
                return;
            };
            cb(
                error,
                cbytes(&task.lib_name).as_ptr(),
                cbytes(&task.sym_name).as_ptr(),
                sym_addr,
                task.replacement as *const c_void,
                task.orig_addr as *const c_void,
                task.hooked_arg as *mut c_void,
            );
        }
        PendingTaskKind::Intercept => {
            let Some(cb) = task.intercepted else {
                return;
            };
            let pre: Interceptor = unsafe { mem::transmute(task.replacement) };
            cb(
                error,
                cbytes(&task.lib_name).as_ptr(),
                cbytes(&task.sym_name).as_ptr(),
                sym_addr,
                pre,
                task.data as *mut c_void,
                task.intercepted_arg as *mut c_void,
            );
        }
    }
}

fn info_name(info: *mut libc::dl_phdr_info) -> Option<String> {
    // SAFETY: info 由 linker 回调同步提供；手扫避免走 libc strlen
    unsafe { cstr_from_ptr_no_libc((*info).dlpi_name) }
        .and_then(|s| s.to_str().ok())
        .map(str::to_owned)
}
