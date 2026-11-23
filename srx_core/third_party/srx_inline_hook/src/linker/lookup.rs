use super::prelude::*;

pub fn find_linker64_base() -> Option<usize> {
    let mut result: usize = 0;
    // SAFETY: iter_base_cb 在 dl_iterate_phdr 同步上下文执行；data 指本函数栈槽
    unsafe {
        libc::dl_iterate_phdr(Some(iter_base_cb), &mut result as *mut usize as *mut c_void);
    }
    if result == 0 { None } else { Some(result) }
}

// linker64 .dynsym 查询：命中返回 load_bias+st_value 运行时地址；未命中返 None
// A12+ 优先 DT_GNU_HASH，缺失时退回 DT_HASH
pub fn find_linker_symbol(name: &CStr) -> Option<usize> {
    let mut ctx = LookupCtx { name, result: 0 };
    // SAFETY: iter_lookup_cb 在 dl_iterate_phdr 同步上下文执行
    unsafe {
        libc::dl_iterate_phdr(
            Some(iter_lookup_cb),
            &mut ctx as *mut LookupCtx as *mut c_void,
        );
    }
    if ctx.result == 0 {
        None
    } else {
        Some(ctx.result)
    }
}

// linker64 .symtab 查询：读磁盘 ELF 的 .symtab/.strtab，覆盖 soinfo 内部 C++ 符号
// 命中返回 load_bias+st_value 运行时地址；未命中返 None
pub fn find_linker_symbol_by_symtab(name: &CStr) -> Option<usize> {
    let info = find_linker64_info()?;
    symtab_lookup(&info.path, info.load_bias, name)
}

pub(crate) enum LoadedSymbolLookup {
    Found(*mut c_void),
    LibNotFound,
    SymNotFound,
}

struct LoadedExistsCtx<'a> {
    lib_name: &'a CStr,
    found: bool,
}

pub(crate) fn has_loaded_library(lib_name: &CStr) -> bool {
    let mut ctx = LoadedExistsCtx {
        lib_name,
        found: false,
    };
    unsafe {
        libc::dl_iterate_phdr(
            Some(iter_loaded_exists_cb),
            &mut ctx as *mut LoadedExistsCtx<'_> as *mut c_void,
        );
    }
    ctx.found
}

pub(crate) fn find_loaded_symbol(lib_name: &CStr, sym_name: &CStr) -> LoadedSymbolLookup {
    let mut ctx = LoadedLookupCtx {
        lib_name,
        sym_name,
        result: 0,
        saw_lib: false,
    };
    // SAFETY: iter_loaded_lookup_cb 在 dl_iterate_phdr 同步上下文执行
    unsafe {
        libc::dl_iterate_phdr(
            Some(iter_loaded_lookup_cb),
            &mut ctx as *mut LoadedLookupCtx as *mut c_void,
        );
    }
    if ctx.result != 0 {
        LoadedSymbolLookup::Found(ctx.result as *mut c_void)
    } else if ctx.saw_lib {
        LoadedSymbolLookup::SymNotFound
    } else {
        LoadedSymbolLookup::LibNotFound
    }
}

pub(crate) fn find_symbol_in_dlinfo(info: &libc::dl_phdr_info, name: &CStr) -> Option<usize> {
    let load_bias = info.dlpi_addr as usize;
    for i in 0..info.dlpi_phnum as usize {
        // SAFETY: dlpi_phdr 数组长度为 dlpi_phnum
        let ph = unsafe { &*info.dlpi_phdr.add(i) };
        if ph.p_type != libc::PT_DYNAMIC {
            continue;
        }
        let dyn_ptr = (load_bias + ph.p_vaddr as usize) as *const Elf64Dyn;
        // SAFETY: dyn_ptr 指向已映射的 .dynamic 段，DT_NULL 收尾
        return unsafe { dynsym_lookup(load_bias, dyn_ptr, name) };
    }
    None
}

pub(crate) fn find_loaded_symbol_by_symtab(
    lib_name: &CStr,
    sym_name: &CStr,
) -> Option<*mut c_void> {
    let mut ctx = LoadedSymtabLookupCtx {
        lib_name,
        sym_name,
        result: 0,
    };
    // SAFETY: iter_loaded_symtab_lookup_cb 在 dl_iterate_phdr 同步上下文执行
    unsafe {
        libc::dl_iterate_phdr(
            Some(iter_loaded_symtab_lookup_cb),
            &mut ctx as *mut LoadedSymtabLookupCtx as *mut c_void,
        );
    }
    if ctx.result == 0 {
        None
    } else {
        Some(ctx.result as *mut c_void)
    }
}

struct LookupCtx<'a> {
    name: &'a CStr,
    result: usize,
}

struct LinkerInfo {
    load_bias: usize,
    path: String,
}

struct LinkerInfoCtx {
    load_bias: usize,
    path: Option<String>,
}

struct LoadedLookupCtx<'a> {
    lib_name: &'a CStr,
    sym_name: &'a CStr,
    result: usize,
    saw_lib: bool,
}

struct LoadedSymtabLookupCtx<'a> {
    lib_name: &'a CStr,
    sym_name: &'a CStr,
    result: usize,
}

unsafe extern "C" fn iter_base_cb(
    info: *mut libc::dl_phdr_info,
    _size: libc::size_t,
    data: *mut c_void,
) -> c_int {
    if info.is_null() || data.is_null() {
        return 0;
    }
    // SAFETY: info 由 libc 提供
    let info = unsafe { &*info };
    if !is_linker64(info) {
        return 0;
    }
    // SAFETY: data 指向栈上 usize 槽
    unsafe { *(data as *mut usize) = info.dlpi_addr as usize };
    1
}

unsafe extern "C" fn iter_lookup_cb(
    info: *mut libc::dl_phdr_info,
    _size: libc::size_t,
    data: *mut c_void,
) -> c_int {
    if info.is_null() || data.is_null() {
        return 0;
    }
    // SAFETY: info 由 libc 提供
    let info = unsafe { &*info };
    if !is_linker64(info) {
        return 0;
    }
    let load_bias = info.dlpi_addr as usize;
    // SAFETY: LookupCtx 由调用方在栈上持有
    let ctx = unsafe { &mut *(data as *mut LookupCtx) };

    // 遍历 phdr 找 PT_DYNAMIC
    for i in 0..info.dlpi_phnum as usize {
        // SAFETY: dlpi_phdr 数组长度为 dlpi_phnum
        let ph = unsafe { &*info.dlpi_phdr.add(i) };
        if ph.p_type != libc::PT_DYNAMIC {
            continue;
        }
        let dyn_ptr = (load_bias + ph.p_vaddr as usize) as *const Elf64Dyn;
        // SAFETY: dyn_ptr 指向已映射的 .dynamic 段，DT_NULL 收尾
        if let Some(addr) = unsafe { dynsym_lookup(load_bias, dyn_ptr, ctx.name) } {
            ctx.result = addr;
            return 1;
        }
        return 0;
    }
    0
}

unsafe extern "C" fn iter_info_cb(
    info: *mut libc::dl_phdr_info,
    _size: libc::size_t,
    data: *mut c_void,
) -> c_int {
    if info.is_null() || data.is_null() {
        return 0;
    }
    // SAFETY: info 由 libc 提供
    let info = unsafe { &*info };
    if !is_linker64(info) {
        return 0;
    }
    let Some(path) = linker_name(info).map(str::to_owned) else {
        return 0;
    };
    // SAFETY: data 指向本函数栈上的 LinkerInfoCtx
    let ctx = unsafe { &mut *(data as *mut LinkerInfoCtx) };
    ctx.load_bias = info.dlpi_addr as usize;
    ctx.path = Some(path);
    1
}

fn find_linker64_info() -> Option<LinkerInfo> {
    let mut ctx = LinkerInfoCtx {
        load_bias: 0,
        path: None,
    };
    // SAFETY: iter_info_cb 在 dl_iterate_phdr 同步上下文执行；data 指本函数栈槽
    unsafe {
        libc::dl_iterate_phdr(
            Some(iter_info_cb),
            &mut ctx as *mut LinkerInfoCtx as *mut c_void,
        );
    }
    Some(LinkerInfo {
        load_bias: ctx.load_bias,
        path: ctx.path?,
    })
}

unsafe extern "C" fn iter_loaded_exists_cb(
    info: *mut libc::dl_phdr_info,
    _size: libc::size_t,
    data: *mut c_void,
) -> c_int {
    if info.is_null() || data.is_null() {
        return 0;
    }
    let info = unsafe { &*info };
    let Some(loaded_name) = linker_name(info) else {
        return 0;
    };
    let ctx = unsafe { &mut *(data as *mut LoadedExistsCtx<'_>) };
    let Some(request_name) = ctx.lib_name.to_str().ok() else {
        return 0;
    };
    if path_name_matches(loaded_name, request_name) {
        ctx.found = true;
        return 1;
    }
    0
}

unsafe extern "C" fn iter_loaded_lookup_cb(
    info: *mut libc::dl_phdr_info,
    _size: libc::size_t,
    data: *mut c_void,
) -> c_int {
    if info.is_null() || data.is_null() {
        return 0;
    }
    // SAFETY: info 由 libc 提供
    let info = unsafe { &*info };
    let Some(loaded_name) = linker_name(info) else {
        return 0;
    };
    // SAFETY: data 指向本函数栈上的 LoadedLookupCtx
    let ctx = unsafe { &mut *(data as *mut LoadedLookupCtx) };
    let Some(request_name) = ctx.lib_name.to_str().ok() else {
        return 0;
    };
    if !path_name_matches(loaded_name, request_name) {
        return 0;
    }
    ctx.saw_lib = true;
    if let Some(addr) = find_symbol_in_dlinfo(info, ctx.sym_name) {
        ctx.result = addr;
        return 1;
    }
    0
}

unsafe extern "C" fn iter_loaded_symtab_lookup_cb(
    info: *mut libc::dl_phdr_info,
    _size: libc::size_t,
    data: *mut c_void,
) -> c_int {
    if info.is_null() || data.is_null() {
        return 0;
    }
    // SAFETY: info 由 libc 提供
    let info = unsafe { &*info };
    let Some(loaded_name) = linker_name(info) else {
        return 0;
    };
    // SAFETY: data 指向本函数栈上的 LoadedSymtabLookupCtx
    let ctx = unsafe { &mut *(data as *mut LoadedSymtabLookupCtx) };
    let Some(request_name) = ctx.lib_name.to_str().ok() else {
        return 0;
    };
    if !path_name_matches(loaded_name, request_name) || info.dlpi_name.is_null() {
        return 0;
    }
    let Some(path) =
        unsafe { util::cstr_from_ptr_no_libc(info.dlpi_name) }.and_then(|s| s.to_str().ok())
    else {
        return 0;
    };
    if let Some(addr) = symtab_lookup(path, info.dlpi_addr as usize, ctx.sym_name) {
        ctx.result = addr;
        return 1;
    }
    0
}
