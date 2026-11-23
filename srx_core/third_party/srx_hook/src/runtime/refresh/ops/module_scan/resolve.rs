// 基于 dlinfo/dladdr1 的模块身份解析，从 handle 或符号地址提取完整 ModuleInfo
use crate::log;
use std::ffi::c_void;
use std::mem;
use std::ptr;
use std::sync::atomic::{AtomicUsize, Ordering};

use super::{DlinfoFn, LinkMap, RTLD_DI_LINKMAP, RTLD_DI_LMID, RTLD_NEXT_FALLBACK};

// 延迟解析 dlinfo 函数地址，优先 RTLD_NEXT 再回退到 libdl.so NOLOAD
pub(super) fn resolve_dlinfo_fn() -> Option<DlinfoFn> {
    static DLINFO_FN: AtomicUsize = AtomicUsize::new(0);
    let address = cached_address(&DLINFO_FN, || {
        let mut symbol = unsafe { libc::dlsym(RTLD_NEXT_FALLBACK, c"dlinfo".as_ptr()) };
        if symbol.is_null() {
            let handle =
                unsafe { libc::dlopen(c"libdl.so".as_ptr(), libc::RTLD_NOW | libc::RTLD_NOLOAD) };
            if !handle.is_null() {
                symbol = unsafe { libc::dlsym(handle, c"dlinfo".as_ptr()) };
                unsafe {
                    libc::dlclose(handle);
                }
            }
        }
        if symbol.is_null() {
            log::debug(format_args!("dlinfo symbol unavailable"));
            0
        } else {
            log::debug(format_args!(
                "dlinfo symbol resolved at 0x{:x}",
                symbol as usize
            ));
            symbol as usize
        }
    });
    (address != 0).then(|| unsafe { mem::transmute::<usize, DlinfoFn>(address) })
}

fn cached_address(cache: &AtomicUsize, resolve: impl FnOnce() -> usize) -> usize {
    let cached = cache.load(Ordering::Acquire);
    let value = if cached == 0 {
        let resolved = resolve().max(1);
        match cache.compare_exchange(0, resolved, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => resolved,
            Err(published) => published,
        }
    } else {
        cached
    };
    if value == 1 { 0 } else { value }
}

pub(super) fn resolve_link_map_from_handle(
    dlinfo: DlinfoFn,
    handle: *mut c_void,
) -> Option<*mut LinkMap> {
    let mut link_map_ptr: *mut LinkMap = ptr::null_mut();
    let info_ptr = (&mut link_map_ptr as *mut *mut LinkMap).cast::<c_void>();
    if unsafe { dlinfo(handle, RTLD_DI_LINKMAP, info_ptr) } != 0 || link_map_ptr.is_null() {
        return None;
    }
    Some(link_map_ptr)
}

pub(super) fn resolve_namespace_id_from_handle(
    dlinfo: DlinfoFn,
    handle: *mut c_void,
) -> Option<usize> {
    let mut namespace_id = 0usize;
    let info_ptr = (&mut namespace_id as *mut usize).cast::<c_void>();
    if unsafe { dlinfo(handle, RTLD_DI_LMID, info_ptr) } != 0 {
        return None;
    }
    Some(namespace_id)
}

// 沿 link_map 双向链表回溯到头节点，头节点地址即为 namespace_id
pub(super) fn resolve_namespace_id_from_link_map(link_map_ptr: *mut LinkMap) -> Option<usize> {
    if link_map_ptr.is_null() {
        return None;
    }

    let mut head = link_map_ptr;
    let mut guard = 0usize;
    while !head.is_null() && guard < 4096 {
        let prev = unsafe { (*head).l_prev };
        if prev.is_null() {
            break;
        }
        head = prev;
        guard += 1;
    }
    if head.is_null() || guard >= 4096 {
        return None;
    }
    Some(head as usize)
}
