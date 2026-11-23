use super::prelude::*;

type SymbolNameKey = (Vec<u8>, Vec<u8>);

static RESOLVED_NAME_TARGETS: Lazy<Mutex<HashMap<SymbolNameKey, usize>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

fn resolved_name_key(lib_name: &CStr, sym_name: &CStr) -> SymbolNameKey {
    (lib_name.to_bytes().to_vec(), sym_name.to_bytes().to_vec())
}

fn cached_resolved_symbol(lib_name: &CStr, sym_name: &CStr) -> Option<*mut c_void> {
    let g = RESOLVED_NAME_TARGETS.lock().ok()?;
    let target = *g.get(&resolved_name_key(lib_name, sym_name))? as *mut u8;
    switch::contains(target).then_some(target as *mut c_void)
}

pub(crate) fn remember_resolved_symbol(lib_name: &CStr, sym_name: &CStr, sym: *mut c_void) {
    if sym.is_null() {
        return;
    }
    let Ok(mut g) = RESOLVED_NAME_TARGETS.lock() else {
        return;
    };
    g.insert(resolved_name_key(lib_name, sym_name), sym as usize);
}

// 幂等；mode / debuggable 仅首次 init 生效

pub(crate) unsafe fn resolve_loaded_sym(
    lib_name: &CStr,
    sym_name: &CStr,
    replacement: *const c_void,
) -> Result<*mut c_void, Errno> {
    if replacement.is_null() || lib_name.to_bytes().is_empty() || sym_name.to_bytes().is_empty() {
        return Err(Errno::InvalidArg);
    }
    // 检查序：InvalidArg → Disabled → init_errno
    if runtime::is_disabled() {
        return Err(Errno::Disabled);
    }
    let init_err = runtime::get_init_errno();
    if init_err != Errno::Ok {
        return Err(init_err);
    }
    if let Some(sym) = cached_resolved_symbol(lib_name, sym_name) {
        return Ok(sym);
    }
    let is_loaded = linker::has_loaded_library(lib_name);
    if is_loaded {
        let handle = unsafe { sh_dlopen(lib_name) };
        if !handle.is_null() {
            let sym = unsafe { sh_dlsym_dynsym(handle, sym_name) };
            unsafe { sh_dlclose(handle) };
            if !sym.is_null() {
                return Ok(sym);
            }
        }
    }
    match linker::find_loaded_symbol(lib_name, sym_name) {
        LoadedSymbolLookup::Found(sym) => Ok(sym),
        LoadedSymbolLookup::LibNotFound => Err(Errno::Pending),
        LoadedSymbolLookup::SymNotFound => Err(Errno::DlSymFailed),
    }
}

// hook_sym_name 与 callback 共用的内部实现：返回 (stub, sym_addr)；sym_addr 可被 callback 读作回传地址
