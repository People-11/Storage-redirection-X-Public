// HookStub id 池：id 对外作 opaque C void*，内部映射回 target 地址
// id 单调递增不复用，旧 stub 不会误卸同一 target 上新装的 hook；0 保留为 NULL 哨兵

use core::sync::atomic::{AtomicUsize, Ordering};
use std::collections::HashMap;
use std::sync::Mutex;

use once_cell::sync::Lazy;

static NEXT_ID: AtomicUsize = AtomicUsize::new(1);
static STUBS: Lazy<Mutex<HashMap<usize, usize>>> = Lazy::new(|| Mutex::new(HashMap::new()));

pub fn alloc(target: *mut u8) -> usize {
    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    if let Ok(mut g) = STUBS.lock() {
        g.insert(id, target as usize);
    }
    id
}

pub fn target_of(id: usize) -> Option<*mut u8> {
    STUBS.lock().ok()?.get(&id).map(|t| *t as *mut u8)
}

pub fn take(id: usize) {
    if let Ok(mut g) = STUBS.lock() {
        g.remove(&id);
    }
}

pub fn remove_by_target(target: *mut u8) {
    if let Ok(mut g) = STUBS.lock() {
        g.retain(|_, t| *t != target as usize);
    }
}
