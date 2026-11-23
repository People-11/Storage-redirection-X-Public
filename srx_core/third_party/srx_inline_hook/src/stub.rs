// HookStub id 池：id 对外作 opaque C void*，内部映射回 target + proxy 信息
// id 单调递增不复用；0 保留为 NULL 哨兵

use core::ffi::c_void;
use core::sync::atomic::{AtomicUsize, Ordering};
use std::collections::HashMap;
use std::sync::Mutex;

use once_cell::sync::Lazy;

use crate::switch::SwitchMode;

#[derive(Clone, Copy)]
pub struct StubBody {
    pub target: *mut u8,
    pub new_addr: *const c_void,
    pub mode: SwitchMode,
    pub user_orig_slot: Option<*mut *const c_void>,
}

// SAFETY: 裸指针仅作为键/槽位值存储，读写受 STUBS 锁串行化
unsafe impl Send for StubBody {}

static NEXT_ID: AtomicUsize = AtomicUsize::new(1);
static STUBS: Lazy<Mutex<HashMap<usize, StubBody>>> = Lazy::new(|| Mutex::new(HashMap::new()));

pub fn alloc(
    target: *mut u8,
    new_addr: *const c_void,
    mode: SwitchMode,
    user_orig_slot: Option<*mut *const c_void>,
) -> usize {
    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    if let Ok(mut g) = STUBS.lock() {
        g.insert(
            id,
            StubBody {
                target,
                new_addr,
                mode,
                user_orig_slot,
            },
        );
    }
    id
}

pub fn get(id: usize) -> Option<StubBody> {
    STUBS.lock().ok()?.get(&id).copied()
}

pub fn find_by_new_addr(
    new_addr: *const c_void,
    preferred_target: Option<*mut u8>,
) -> Option<(usize, StubBody)> {
    let g = STUBS.lock().ok()?;
    if let Some(target) = preferred_target {
        let mut hit = None;
        for (id, body) in g.iter() {
            if body.target == target && body.new_addr == new_addr {
                if hit.is_some() {
                    return None;
                }
                hit = Some((*id, *body));
            }
        }
        if hit.is_some() {
            return hit;
        }
    }

    let mut hit = None;
    for (id, body) in g.iter() {
        if body.new_addr == new_addr {
            if hit.is_some() {
                return None;
            }
            hit = Some((*id, *body));
        }
    }
    hit
}

pub fn take(id: usize) -> Option<StubBody> {
    STUBS.lock().ok()?.remove(&id)
}

pub fn remove_by_target(target: *mut u8) -> Vec<usize> {
    let Ok(mut g) = STUBS.lock() else {
        return Vec::new();
    };
    let ids = g
        .iter()
        .filter_map(|(id, body)| (body.target == target).then_some(*id))
        .collect::<Vec<_>>();
    for id in &ids {
        g.remove(id);
    }
    ids
}
