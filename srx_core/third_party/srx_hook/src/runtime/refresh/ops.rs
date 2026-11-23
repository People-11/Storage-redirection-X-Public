// GOT slot 读写、ELF 解析和模块扫描的底层操作，所有操作均在信号保护下执行
use crate::android::signal_guard;
use crate::elf;
use crate::errno::Errno;
use std::ptr;

use super::super::state::ModuleInfo;

mod module_scan;

// 模块加载/卸载计数，用于检测模块列表是否发生变化
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct ModuleEpoch {
    pub(super) adds: u64,
    pub(super) subs: u64,
}

pub(super) fn read_slot(addr: usize) -> Result<usize, Errno> {
    signal_guard::with_guard(|| unsafe { ptr::read(addr as *const usize) })
        .map_err(|_| Errno::ReadElf)
}

pub(super) fn init_elf_guard(base_addr: usize, pathname: &str) -> Result<elf::Elf, Errno> {
    signal_guard::with_guard(|| unsafe { elf::Elf::init(base_addr, pathname) })
        .map_err(|_| Errno::ReadElf)?
}

pub(super) fn find_slots_guard(elf: &elf::Elf, symbol_name: &str) -> Result<Vec<usize>, Errno> {
    signal_guard::with_guard(|| unsafe { elf.find_got_slots(symbol_name) })
        .map_err(|_| Errno::ReadElf)?
}

pub(super) fn module_epoch() -> Option<ModuleEpoch> {
    module_scan::module_epoch()
}

pub(super) fn enumerate_modules() -> Vec<ModuleInfo> {
    module_scan::enumerate_modules()
}
