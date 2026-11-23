// dl_init / dl_fini 回调注册表：保持 C API 的重复注册 / 未命中注销错误码语义
// 派发时按注册顺序调用；读写锁保护队列，回调执行不持写锁

use core::ffi::c_void;
use std::sync::RwLock;

use crate::errno::Errno;

pub type DlInfoCallback = unsafe extern "C" fn(*mut libc::dl_phdr_info, usize, *mut c_void);

#[derive(Clone, Copy)]
pub struct CallbackEntry {
    pub pre: Option<DlInfoCallback>,
    pub post: Option<DlInfoCallback>,
    pub data: *mut c_void,
}

// SAFETY: 回调函数指针和 opaque data 仅做转发，不在此线程间解引用
unsafe impl Send for CallbackEntry {}
unsafe impl Sync for CallbackEntry {}

static DL_INIT_CBS: RwLock<Vec<CallbackEntry>> = RwLock::new(Vec::new());
static DL_FINI_CBS: RwLock<Vec<CallbackEntry>> = RwLock::new(Vec::new());

pub fn register_init(
    pre: Option<DlInfoCallback>,
    post: Option<DlInfoCallback>,
    data: *mut c_void,
) -> Result<(), Errno> {
    register(&DL_INIT_CBS, pre, post, data)
}

pub fn unregister_init(
    pre: Option<DlInfoCallback>,
    post: Option<DlInfoCallback>,
    data: *mut c_void,
) -> Result<(), Errno> {
    unregister(&DL_INIT_CBS, pre, post, data)
}

pub fn register_fini(
    pre: Option<DlInfoCallback>,
    post: Option<DlInfoCallback>,
    data: *mut c_void,
) -> Result<(), Errno> {
    register(&DL_FINI_CBS, pre, post, data)
}

pub fn unregister_fini(
    pre: Option<DlInfoCallback>,
    post: Option<DlInfoCallback>,
    data: *mut c_void,
) -> Result<(), Errno> {
    unregister(&DL_FINI_CBS, pre, post, data)
}

pub fn has_init_callbacks() -> bool {
    DL_INIT_CBS.read().map(|v| !v.is_empty()).unwrap_or(false)
}

pub fn has_fini_callbacks() -> bool {
    DL_FINI_CBS.read().map(|v| !v.is_empty()).unwrap_or(false)
}

pub fn dispatch_init_pre(info: *mut libc::dl_phdr_info, size: usize) {
    dispatch(&DL_INIT_CBS, info, size, true)
}

pub fn dispatch_init_post(info: *mut libc::dl_phdr_info, size: usize) {
    dispatch(&DL_INIT_CBS, info, size, false)
}

pub fn dispatch_fini_pre(info: *mut libc::dl_phdr_info, size: usize) {
    dispatch(&DL_FINI_CBS, info, size, true)
}

pub fn dispatch_fini_post(info: *mut libc::dl_phdr_info, size: usize) {
    dispatch(&DL_FINI_CBS, info, size, false)
}

fn register(
    q: &RwLock<Vec<CallbackEntry>>,
    pre: Option<DlInfoCallback>,
    post: Option<DlInfoCallback>,
    data: *mut c_void,
) -> Result<(), Errno> {
    let mut g = q.write().map_err(|_| Errno::NotSupport)?;
    if g.iter().any(|e| same_entry(*e, pre, post, data)) {
        return Err(Errno::from_i32(36));
    }
    g.push(CallbackEntry { pre, post, data });
    Ok(())
}

fn unregister(
    q: &RwLock<Vec<CallbackEntry>>,
    pre: Option<DlInfoCallback>,
    post: Option<DlInfoCallback>,
    data: *mut c_void,
) -> Result<(), Errno> {
    let mut g = q.write().map_err(|_| Errno::NotSupport)?;
    let Some(idx) = g.iter().position(|e| same_entry(*e, pre, post, data)) else {
        return Err(Errno::from_i32(37));
    };
    g.remove(idx);
    Ok(())
}

fn dispatch(q: &RwLock<Vec<CallbackEntry>>, info: *mut libc::dl_phdr_info, size: usize, pre: bool) {
    let Ok(g) = q.read() else {
        return;
    };
    for entry in g.iter().copied() {
        let cb = if pre { entry.pre } else { entry.post };
        if let Some(cb) = cb {
            // SAFETY: info 指向栈上构造的 dl_phdr_info；回调签名由 C API 约定
            unsafe { cb(info, size, entry.data) };
        }
    }
}

fn same_entry(
    entry: CallbackEntry,
    pre: Option<DlInfoCallback>,
    post: Option<DlInfoCallback>,
    data: *mut c_void,
) -> bool {
    same_fn(entry.pre, pre) && same_fn(entry.post, post) && entry.data == data
}

fn same_fn(a: Option<DlInfoCallback>, b: Option<DlInfoCallback>) -> bool {
    match (a, b) {
        (Some(a), Some(b)) => a as usize == b as usize,
        (None, None) => true,
        _ => false,
    }
}
