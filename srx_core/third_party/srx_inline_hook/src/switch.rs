// 以 target 地址为键的 hook 注册表，每个 Switch 记录一个目标的入口补丁与跳板
// 每个 target 只允许一个 hook，重复安装由调用方返回 HookUniqueDup

use core::ffi::c_void;
use std::collections::HashMap;
use std::sync::Mutex;

use once_cell::sync::Lazy;

use crate::errno::Errno;

pub struct Switch {
    pub target: *mut u8,
    pub original: Vec<u8>,
    pub patch: Vec<u8>,
    pub tramp_addr: *mut u8,
    pub orig_slot: Option<*mut *const c_void>,
}

// SAFETY: 裸指针仅在 SWITCHES 锁保护下访问，跨线程由 Mutex 串行化
unsafe impl Send for Switch {}

static SWITCHES: Lazy<Mutex<HashMap<usize, Switch>>> = Lazy::new(|| Mutex::new(HashMap::new()));

pub fn contains(target: *mut u8) -> bool {
    SWITCHES
        .lock()
        .map(|g| g.contains_key(&(target as usize)))
        .unwrap_or(false)
}

// 新 patch 区间 [target, target+patch_len) 与已 hook original 区间相交检测
// 精确相同地址由 contains 先行拦截；此处专治邻近函数 prologue 踩踏
pub fn has_overlap(target: *mut u8, patch_len: usize) -> bool {
    let start = target as usize;
    let end = start.saturating_add(patch_len);
    SWITCHES
        .lock()
        .map(|g| {
            g.values().any(|s| {
                let es = s.target as usize;
                let ee = es.saturating_add(s.original.len());
                start < ee && es < end
            })
        })
        .unwrap_or(false)
}

pub fn insert(sw: Switch) -> Result<(), Errno> {
    let mut g = SWITCHES.lock().map_err(|_| Errno::NotSupport)?;
    let key = sw.target as usize;
    if g.contains_key(&key) {
        return Err(Errno::HookUniqueDup);
    }
    g.insert(key, sw);
    Ok(())
}

pub fn remove(target: *mut u8) -> Result<Switch, Errno> {
    let mut g = SWITCHES.lock().map_err(|_| Errno::NotSupport)?;
    g.remove(&(target as usize)).ok_or(Errno::UnhookNotFound)
}

pub fn drain_filter(mut pred: impl FnMut(usize) -> bool) -> Vec<Switch> {
    let Ok(mut g) = SWITCHES.lock() else {
        return Vec::new();
    };
    let keys = g.keys().filter(|k| pred(**k)).copied().collect::<Vec<_>>();
    keys.into_iter().filter_map(|k| g.remove(&k)).collect()
}

pub fn trampoline_of(target: *mut u8) -> Option<*mut u8> {
    let g = SWITCHES.lock().ok()?;
    g.get(&(target as usize)).map(|s| s.tramp_addr)
}
