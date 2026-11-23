// 模块扫描与身份解析，合并 dl_iterate_phdr 和 /proc/self/maps 两种数据源
use crate::runtime::LoaderCall;
use std::collections::BTreeMap;
use std::ffi::c_void;

use super::super::super::state::ModuleInfo;
use super::ModuleEpoch;

const RTLD_DI_LINKMAP: libc::c_int = 2;
const RTLD_DI_LMID: libc::c_int = 1;
const RTLD_NEXT_FALLBACK: *mut c_void = (-1isize) as *mut c_void;
const NOLOAD_NAMESPACE_HINT_LIMIT: usize = 512;

// ELF link_map 结构体，与 linker 内部布局一致
#[repr(C)]
pub(super) struct LinkMap {
    pub(super) l_addr: usize,
    pub(super) l_name: *const libc::c_char,
    pub(super) l_ld: *mut c_void,
    pub(super) l_next: *mut LinkMap,
    pub(super) l_prev: *mut LinkMap,
}

pub(super) type DlinfoFn =
    unsafe extern "C" fn(*mut c_void, libc::c_int, *mut c_void) -> libc::c_int;

// 缓存的模块身份信息，通过 dlopen handle 观察获得
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct ObservedIdentityHint {
    pub(super) instance_id: usize,
    pub(super) namespace_id: usize,
}

mod hints;
mod maps;
mod noload;
mod phdr;
mod resolve;

use hints::apply_observed_instance_hints;
use maps::enumerate_modules_maps_cached;
use phdr::PhdrModules;

// 通过 dl_iterate_phdr 获取模块加载/卸载计数，仅需遍历第一个条目
pub(super) fn module_epoch() -> Option<ModuleEpoch> {
    let _loader_call = LoaderCall::enter();
    unsafe extern "C" fn iterate_cb(
        info: *mut libc::dl_phdr_info,
        _size: usize,
        data: *mut c_void,
    ) -> libc::c_int {
        if info.is_null() || data.is_null() {
            return 1;
        }
        let info = unsafe { &*info };
        let epoch = unsafe { &mut *(data as *mut ModuleEpoch) };
        epoch.adds = info.dlpi_adds;
        epoch.subs = info.dlpi_subs;
        1
    }

    let mut epoch = ModuleEpoch { adds: 0, subs: 0 };
    let ret =
        unsafe { libc::dl_iterate_phdr(Some(iterate_cb), &mut epoch as *mut _ as *mut c_void) };
    if ret == 0 { None } else { Some(epoch) }
}

// 合并 phdr 和 maps 两种数据源，应用 hint 缓存补全 namespace_id
pub(super) fn enumerate_modules() -> Vec<ModuleInfo> {
    let _loader_call = LoaderCall::enter();
    let phdr = PhdrModules::capture();
    let maps: BTreeMap<usize, ModuleInfo> = enumerate_modules_maps_cached()
        .into_iter()
        .map(|module| (module.base_addr, module))
        .collect();
    let mut modules_by_base = BTreeMap::<usize, (ModuleInfo, bool)>::new();
    for module in phdr.modules.values() {
        modules_by_base.insert(module.base_addr, (module.clone(), true));
    }

    for module in maps.values() {
        if phdr.is_segment_alias(module, &maps) {
            continue;
        }
        modules_by_base
            .entry(module.base_addr)
            .and_modify(|(existing, _)| {
                // 采用内核记录的实际映射路径，保持 caller 匹配一致。
                if !module.pathname.is_empty() && existing.pathname != module.pathname {
                    existing.pathname = module.pathname.clone();
                }
            })
            .or_insert((module.clone(), false));
    }

    let mut modules: Vec<_> = modules_by_base.into_values().collect();
    apply_observed_instance_hints(&mut modules);
    let mut modules: Vec<_> = modules.into_iter().map(|(module, _)| module).collect();
    modules.sort_by(|left, right| {
        left.pathname
            .cmp(&right.pathname)
            .then(left.base_addr.cmp(&right.base_addr))
            .then(left.instance_id.cmp(&right.instance_id))
            .then(left.namespace_id.cmp(&right.namespace_id))
    });
    modules
}
