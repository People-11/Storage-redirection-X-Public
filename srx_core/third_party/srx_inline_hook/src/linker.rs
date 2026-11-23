// bionic linker 定位：A12+ linker64 load bias + .dynsym / .symtab 双路径查符号
// .dynsym 走 GNU/SYSV hash；.symtab 读 linker64 文件，覆盖 soinfo 内部 C++ 符号

mod prelude {
    pub(super) use core::ffi::{CStr, c_char, c_int, c_void};
    pub(super) use core::mem::size_of;
    pub(super) use core::ptr;
    pub(super) use core::sync::atomic::{AtomicBool, AtomicPtr, AtomicUsize, Ordering};
    pub(super) use std::fs;

    pub(super) use once_cell::sync::OnceCell;

    pub(super) use crate::android;
    pub(super) use crate::api::{self, HookStub};
    pub(super) use crate::errno::Errno;
    pub(super) use crate::util;

    pub(super) use super::elf::{
        Elf64Dyn, dynsym_lookup, is_linker64, linker_name, path_name_matches, symtab_lookup,
    };
    pub(super) use super::lookup::find_linker_symbol_by_symtab;
}

mod elf;
mod hook;
mod lookup;

pub use hook::install_linker_hooks;
pub(crate) use lookup::{
    LoadedSymbolLookup, find_loaded_symbol, find_loaded_symbol_by_symtab, has_loaded_library,
};
