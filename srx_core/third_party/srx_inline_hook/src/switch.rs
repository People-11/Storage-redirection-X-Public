// 以 target 地址为键的中央注册表，每个 Switch 承载一个目标的 hook 状态
// queue 串联多 proxy 节点；前驱 orig_slot 原子指向后继 new_addr，末节点指向 tramp

use core::ffi::c_void;
use core::ptr;
use core::sync::atomic::{AtomicPtr, Ordering};
use std::collections::HashMap;
use std::sync::Mutex;

use once_cell::sync::Lazy;

use crate::errno::Errno;

#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum SwitchMode {
    Unique,
    Shared,
    Multi,
    Intercept,
}

pub struct ProxyNode {
    pub id: usize,
    pub new_addr: *const c_void,
    pub orig_slot: Option<*mut *const c_void>,
}

pub struct EntryPatch {
    pub target: *mut u8,
    pub original: Vec<u8>,
    pub patch: Vec<u8>,
    pub consumed: usize,
    pub tramp_addr: *mut u8,
}

pub struct Switch {
    pub target: *mut u8,
    pub original: Vec<u8>,
    pub patch: Vec<u8>,
    pub consumed: usize,
    pub tramp_addr: *mut u8,
    pub mode: SwitchMode,
    pub queue: Vec<ProxyNode>,
    pub shared_orig_slot: Option<*mut *const c_void>,
    pub shared_launcher: *mut u8,
    pub has_interceptors: bool,
    pub intercept_carrier_id: usize,
}

// SAFETY: 裸指针仅在 SWITCHES 锁保护下访问，跨线程由 Mutex 串行化
unsafe impl Send for Switch {}

impl Switch {
    pub fn new(
        mode: SwitchMode,
        entry: EntryPatch,
        mut proxy: ProxyNode,
        shared_launcher: *mut u8,
    ) -> Self {
        let (queue, shared_orig_slot, intercept_carrier_id) = match mode {
            SwitchMode::Shared => {
                let orig_slot = proxy.orig_slot.take();
                (vec![proxy], orig_slot, 0)
            }
            SwitchMode::Intercept => (Vec::new(), None, proxy.id),
            SwitchMode::Unique | SwitchMode::Multi => (vec![proxy], None, 0),
        };
        Self {
            target: entry.target,
            original: entry.original,
            patch: entry.patch,
            consumed: entry.consumed,
            tramp_addr: entry.tramp_addr,
            mode,
            queue,
            shared_orig_slot,
            shared_launcher,
            has_interceptors: false,
            intercept_carrier_id,
        }
    }

    pub fn head_orig_slot(&self) -> Option<*mut *const c_void> {
        self.queue.first().and_then(|n| n.orig_slot)
    }

    pub fn head_replacement(&self) -> *const c_void {
        self.queue
            .first()
            .map(|n| n.new_addr)
            .unwrap_or(ptr::null())
    }
}

// 64 位对齐槽位的原子 Release store：保证并发读者看到的 orig 指向一致
fn atomic_store_slot(slot: *mut *const c_void, val: *const c_void) {
    // SAFETY: slot 来自调用方保障的有效可写槽；AtomicPtr<T> 布局等同 *mut T
    unsafe {
        let atomic = &*(slot as *const AtomicPtr<c_void>);
        atomic.store(val as *mut c_void, Ordering::Release);
    }
}

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

pub fn insert_unique(target: *mut u8, sw: Switch) -> Result<(), Errno> {
    let mut g = SWITCHES.lock().map_err(|_| Errno::NotSupport)?;
    if g.contains_key(&(target as usize)) {
        return Err(Errno::HookUniqueDup);
    }
    g.insert(target as usize, sw);
    Ok(())
}

// MULTI 首次 hook：target 不存在时落入新 Switch；已存在返 ModeConflict（避免与 UNIQUE 共存）
pub fn insert_multi(target: *mut u8, sw: Switch) -> Result<(), Errno> {
    let mut g = SWITCHES.lock().map_err(|_| Errno::NotSupport)?;
    if g.contains_key(&(target as usize)) {
        return Err(Errno::ModeConflict);
    }
    g.insert(target as usize, sw);
    Ok(())
}

pub fn insert_shared(target: *mut u8, sw: Switch) -> Result<(), Errno> {
    let mut g = SWITCHES.lock().map_err(|_| Errno::NotSupport)?;
    if g.contains_key(&(target as usize)) {
        return Err(Errno::ModeConflict);
    }
    g.insert(target as usize, sw);
    Ok(())
}

// MULTI 追加 proxy 到队尾；前驱 orig_slot 原子切到新 new_addr，新节点 orig_slot 指 tramp
pub fn push_unique(
    target: *mut u8,
    id: usize,
    new_addr: *const c_void,
    orig_slot: Option<*mut *const c_void>,
) -> Result<(), Errno> {
    let mut g = SWITCHES.lock().map_err(|_| Errno::NotSupport)?;
    let sw = g.get_mut(&(target as usize)).ok_or(Errno::UnhookNotFound)?;
    if sw.mode != SwitchMode::Intercept || !sw.queue.is_empty() {
        return Err(Errno::HookUniqueDup);
    }
    let tramp = sw.tramp_addr as *const c_void;
    if let Some(slot) = orig_slot {
        atomic_store_slot(slot, tramp);
    }
    sw.mode = SwitchMode::Unique;
    sw.queue.push(ProxyNode {
        id,
        new_addr,
        orig_slot,
    });
    Ok(())
}

pub fn push_multi(
    target: *mut u8,
    id: usize,
    new_addr: *const c_void,
    orig_slot: Option<*mut *const c_void>,
) -> Result<(), Errno> {
    let mut g = SWITCHES.lock().map_err(|_| Errno::NotSupport)?;
    let sw = g.get_mut(&(target as usize)).ok_or(Errno::UnhookNotFound)?;
    if sw.mode != SwitchMode::Multi && sw.mode != SwitchMode::Intercept {
        return Err(Errno::ModeConflict);
    }
    if sw.queue.iter().any(|n| n.new_addr == new_addr) {
        return Err(Errno::HookMultiDup);
    }
    let tramp = sw.tramp_addr as *const c_void;
    if let Some(slot) = orig_slot {
        atomic_store_slot(slot, tramp);
    }
    if let Some(prev_slot) = sw.queue.last().and_then(|n| n.orig_slot) {
        atomic_store_slot(prev_slot, new_addr);
    }
    sw.mode = SwitchMode::Multi;
    sw.queue.push(ProxyNode {
        id,
        new_addr,
        orig_slot,
    });
    Ok(())
}

pub fn push_shared(
    target: *mut u8,
    id: usize,
    new_addr: *const c_void,
    orig_slot: Option<*mut *const c_void>,
) -> Result<(), Errno> {
    let mut g = SWITCHES.lock().map_err(|_| Errno::NotSupport)?;
    let sw = g.get_mut(&(target as usize)).ok_or(Errno::UnhookNotFound)?;
    if sw.mode != SwitchMode::Shared && sw.mode != SwitchMode::Intercept {
        return Err(Errno::ModeConflict);
    }
    if sw.queue.iter().any(|n| n.new_addr == new_addr) {
        return Err(Errno::HookDup);
    }
    let tramp = sw.tramp_addr as *const c_void;
    if let Some(slot) = orig_slot {
        atomic_store_slot(slot, tramp);
    }
    if let Some(slot) = sw.shared_orig_slot {
        atomic_store_slot(slot, tramp);
    } else {
        sw.shared_orig_slot = orig_slot;
    }
    sw.mode = SwitchMode::Shared;
    sw.queue.push(ProxyNode {
        id,
        new_addr,
        orig_slot: None,
    });
    Ok(())
}

pub enum RemoveOutcome {
    // 节点移除后 queue 仍有残留；was_head=true 表示 target 的 patch 需 repatch 到 new_head_addr
    Remaining {
        was_head: bool,
        new_head_addr: *const c_void,
        target: *mut u8,
    },
    // queue 空了，Switch 已出表；api 层还原 patch 并回收 tramp
    Drained(Switch),
}

// MULTI 精确拆除某 id 节点；UNIQUE 下只会命中 queue[0]，走 Drained 分支
pub fn remove_proxy_by_id(target: *mut u8, id: usize) -> Result<RemoveOutcome, Errno> {
    let mut g = SWITCHES.lock().map_err(|_| Errno::NotSupport)?;
    let sw = g.get_mut(&(target as usize)).ok_or(Errno::UnhookNotFound)?;
    if sw.queue.is_empty() {
        if sw.intercept_carrier_id == id {
            let Some(drained) = g.remove(&(target as usize)) else {
                return Err(Errno::UnhookNotFound);
            };
            return Ok(RemoveOutcome::Drained(drained));
        }
        return Err(Errno::UnhookNotFound);
    }
    let idx = sw
        .queue
        .iter()
        .position(|n| n.id == id)
        .ok_or(Errno::UnhookNotFound)?;
    let was_head = idx == 0;
    let tramp = sw.tramp_addr as *const c_void;
    // rewire 前驱 orig_slot 先行：避免调用流踩进即将被移除的节点
    if !was_head {
        let next_addr: *const c_void = sw.queue.get(idx + 1).map(|n| n.new_addr).unwrap_or(tramp);
        if let Some(prev_slot) = sw.queue.get(idx - 1).and_then(|n| n.orig_slot) {
            atomic_store_slot(prev_slot, next_addr);
        }
    }
    let removed = sw.queue.remove(idx);
    if sw.queue.is_empty() {
        sw.mode = if sw.has_interceptors {
            SwitchMode::Intercept
        } else {
            sw.mode
        };
    }
    if let Some(slot) = removed.orig_slot {
        // SAFETY: 用户登记的槽位，清零让调用方感知 proxy 已拆
        unsafe { ptr::write(slot, ptr::null()) };
    }
    if sw.queue.is_empty() {
        let Some(drained) = g.remove(&(target as usize)) else {
            return Err(Errno::UnhookNotFound);
        };
        return Ok(RemoveOutcome::Drained(drained));
    }
    let new_head_addr = sw.queue.first().map(|n| n.new_addr).unwrap_or(ptr::null());
    Ok(RemoveOutcome::Remaining {
        was_head,
        new_head_addr,
        target: sw.target,
    })
}

pub fn set_head_patch(target: *mut u8, patch: &[u8]) -> Result<(), Errno> {
    let mut g = SWITCHES.lock().map_err(|_| Errno::NotSupport)?;
    let sw = g.get_mut(&(target as usize)).ok_or(Errno::UnhookNotFound)?;
    sw.patch.clear();
    sw.patch.extend_from_slice(patch);
    Ok(())
}

pub fn set_mode(target: *mut u8, mode: SwitchMode) -> Result<(), Errno> {
    let mut g = SWITCHES.lock().map_err(|_| Errno::NotSupport)?;
    let sw = g.get_mut(&(target as usize)).ok_or(Errno::UnhookNotFound)?;
    sw.mode = mode;
    Ok(())
}

pub fn intercept_carrier_of(target: *mut u8) -> Option<usize> {
    let g = SWITCHES.lock().ok()?;
    let sw = g.get(&(target as usize))?;
    (sw.intercept_carrier_id != 0).then_some(sw.intercept_carrier_id)
}

// UNIQUE 整体拔出；MULTI 路径改走 remove_proxy_by_id，不再调用此函数
pub fn remove(target: *mut u8) -> Result<Switch, Errno> {
    let mut g = SWITCHES.lock().map_err(|_| Errno::NotSupport)?;
    g.remove(&(target as usize)).ok_or(Errno::UnhookNotFound)
}

pub fn insert_existing(sw: Switch) -> Result<(), Errno> {
    let mut g = SWITCHES.lock().map_err(|_| Errno::NotSupport)?;
    g.insert(sw.target as usize, sw);
    Ok(())
}

pub fn drain_filter(mut pred: impl FnMut(usize) -> bool) -> Vec<Switch> {
    let Ok(mut g) = SWITCHES.lock() else {
        return Vec::new();
    };
    let keys = g
        .iter()
        .filter_map(|(k, sw)| pred(sw.target as usize).then_some(*k))
        .collect::<Vec<_>>();
    keys.into_iter().filter_map(|k| g.remove(&k)).collect()
}

pub fn trampoline_of(target: *mut u8) -> Option<*mut u8> {
    let g = SWITCHES.lock().ok()?;
    g.get(&(target as usize)).map(|s| s.tramp_addr)
}

pub fn shared_launcher_of(target: *mut u8) -> Option<*mut u8> {
    let g = SWITCHES.lock().ok()?;
    let sw = g.get(&(target as usize))?;
    (!sw.shared_launcher.is_null()).then_some(sw.shared_launcher)
}

pub fn head_replacement_of(target: *mut u8) -> Option<*const c_void> {
    let g = SWITCHES.lock().ok()?;
    let sw = g.get(&(target as usize))?;
    (!sw.queue.is_empty()).then(|| sw.head_replacement())
}

pub fn prev_addr_by_id(id: usize) -> Option<*const c_void> {
    let g = SWITCHES.lock().ok()?;
    let sw = g.values().find(|sw| sw.queue.iter().any(|n| n.id == id))?;
    let idx = sw.queue.iter().position(|n| n.id == id)?;
    sw.queue
        .get(idx + 1)
        .map(|n| n.new_addr)
        .or(Some(sw.tramp_addr as *const c_void))
}

pub fn set_interceptors_active(target: *mut u8, on: bool) -> Result<(), Errno> {
    let mut g = SWITCHES.lock().map_err(|_| Errno::NotSupport)?;
    let sw = g.get_mut(&(target as usize)).ok_or(Errno::UnhookNotFound)?;
    sw.has_interceptors = on;
    Ok(())
}

pub fn has_interceptors(target: *mut u8) -> bool {
    SWITCHES
        .lock()
        .ok()
        .and_then(|g| g.get(&(target as usize)).map(|sw| sw.has_interceptors))
        .unwrap_or(false)
}

// target 已注册的 Switch 模式；不存在返 None
pub fn mode_of(target: *mut u8) -> Option<SwitchMode> {
    let g = SWITCHES.lock().ok()?;
    g.get(&(target as usize)).map(|s| s.mode)
}

pub fn active_count() -> usize {
    SWITCHES.lock().map(|g| g.len()).unwrap_or(0)
}

#[derive(Debug, Clone)]
pub struct HookInfo {
    pub target: usize,
    pub replacement: usize,
    pub tramp_addr: usize,
    pub consumed: usize,
    pub has_orig_slot: bool,
}

pub fn list() -> Vec<HookInfo> {
    SWITCHES
        .lock()
        .map(|g| {
            g.values()
                .map(|s| HookInfo {
                    target: s.target as usize,
                    replacement: s.head_replacement() as usize,
                    tramp_addr: s.tramp_addr as usize,
                    consumed: s.consumed,
                    has_orig_slot: s.head_orig_slot().is_some(),
                })
                .collect()
        })
        .unwrap_or_default()
}
