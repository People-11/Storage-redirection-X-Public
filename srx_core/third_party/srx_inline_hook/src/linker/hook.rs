use core::mem;

use super::prelude::*;

const LINKER_SYM_CALL_CONSTRUCTORS_M: &CStr = c"__dl__ZN6soinfo17call_constructorsEv";
const LINKER_SYM_CALL_DESTRUCTORS_M: &CStr = c"__dl__ZN6soinfo16call_destructorsEv";

static LINKER_CTORS_STUB: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());
static LINKER_DTORS_STUB: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());
static SOINFO_SCAN_ACTIVE: AtomicBool = AtomicBool::new(false);
static SOINFO_SCAN_OK: AtomicBool = AtomicBool::new(false);
static SOINFO_OFFSET_PHDR: AtomicUsize = AtomicUsize::new(usize::MAX);
static SOINFO_OFFSET_PHNUM: AtomicUsize = AtomicUsize::new(usize::MAX);
static SOINFO_OFFSET_LOAD_BIAS: AtomicUsize = AtomicUsize::new(usize::MAX);
static SOINFO_OFFSET_NAME: AtomicUsize = AtomicUsize::new(usize::MAX);
static SOINFO_OFFSET_CONSTRUCTORS_CALLED: AtomicUsize = AtomicUsize::new(usize::MAX);

pub fn install_linker_hooks() -> Result<(), Errno> {
    install_linker_hook(
        &LINKER_CTORS_STUB,
        LINKER_SYM_CALL_CONSTRUCTORS_M,
        linker_call_constructors_proxy as *const c_void,
    )?;
    install_linker_hook(
        &LINKER_DTORS_STUB,
        LINKER_SYM_CALL_DESTRUCTORS_M,
        linker_call_destructors_proxy as *const c_void,
    )?;
    warm_up_soinfo_scan();
    Ok(())
}

fn install_linker_hook(
    stub_slot: &AtomicPtr<c_void>,
    symbol: &CStr,
    proxy: *const c_void,
) -> Result<(), Errno> {
    if !stub_slot.load(Ordering::Acquire).is_null() {
        return Ok(());
    }
    let target = find_linker_symbol_by_symtab(symbol).ok_or(Errno::DlSymFailed)? as *mut c_void;
    // SAFETY: target 是 linker64 内有效函数入口；proxy ABI 与 soinfo 成员函数保持单参调用约定
    let stub = unsafe { api::hook_sym_addr(target, proxy, ptr::null_mut()) }?;
    stub_slot.store(stub.handle, Ordering::Release);
    Ok(())
}

fn empty_dlinfo() -> libc::dl_phdr_info {
    libc::dl_phdr_info {
        dlpi_addr: 0,
        dlpi_name: ptr::null(),
        dlpi_phdr: ptr::null(),
        dlpi_phnum: 0,
        dlpi_adds: 0,
        dlpi_subs: 0,
        dlpi_tls_modid: 0,
        dlpi_tls_data: ptr::null_mut(),
    }
}

// 构造阶段只用于学习 soinfo 字段偏移，学到后由析构阶段识别被卸载的 so
extern "C" fn linker_call_constructors_proxy(soinfo: *mut c_void) {
    let scan_pre_ok = SOINFO_SCAN_ACTIVE.load(Ordering::Acquire) && scan_soinfo_pre(soinfo).is_ok();

    call_prev_soinfo(LINKER_CTORS_STUB.load(Ordering::Acquire), soinfo);

    if scan_pre_ok {
        scan_soinfo_post(soinfo);
    }
}

extern "C" fn linker_call_destructors_proxy(soinfo: *mut c_void) {
    let mut dlinfo = empty_dlinfo();
    let do_process = SOINFO_SCAN_OK.load(Ordering::Acquire)
        && soinfo_to_dlinfo(soinfo, &mut dlinfo).is_ok()
        && dlinfo.dlpi_addr != 0
        && !dlinfo.dlpi_name.is_null()
        && soinfo_is_loading(soinfo).is_ok_and(|loading| !loading);

    call_prev_soinfo(LINKER_DTORS_STUB.load(Ordering::Acquire), soinfo);

    if do_process {
        api::cleanup_hooks_for_dlinfo(&dlinfo);
    }
}

fn warm_up_soinfo_scan() {
    if !SOINFO_SCAN_OK.load(Ordering::Acquire) {
        SOINFO_SCAN_ACTIVE.store(true, Ordering::Release);
    }
}

fn call_prev_soinfo(stub: *mut c_void, soinfo: *mut c_void) {
    if stub.is_null() {
        return;
    }
    let Ok(prev) = api::prev_func(HookStub { handle: stub }) else {
        return;
    };
    // SAFETY: prev_func 返回 trampoline，ABI 与 soinfo 成员函数保持单参调用约定
    let orig: extern "C" fn(*mut c_void) = unsafe { mem::transmute(prev) };
    orig(soinfo);
}

// 本次 soinfo 命中已加载 so 的特征并学全偏移时返回 Ok
fn scan_soinfo_pre(soinfo: *mut c_void) -> Result<(), Errno> {
    let probes = loaded_scan_infos();
    if probes.is_empty() {
        return Err(Errno::DlInfoFailed);
    }

    let word = size_of::<usize>();
    let mut matched = false;
    let mut i = 0usize;
    while i < word * 96 {
        let val0 = read_word(soinfo, i).ok_or(Errno::DlInfoFailed)?;
        let val1 = read_word(soinfo, i + word).ok_or(Errno::DlInfoFailed)?;
        let val2 = read_word(soinfo, i + word * 2).ok_or(Errno::DlInfoFailed)?;
        let val3 = read_word(soinfo, i + word * 3).ok_or(Errno::DlInfoFailed)?;
        let val4 = read_word(soinfo, i + word * 4).ok_or(Errno::DlInfoFailed)?;
        let val5 = read_word(soinfo, i + word * 5).ok_or(Errno::DlInfoFailed)?;
        let val6 = read_word(soinfo, i + word * 6).ok_or(Errno::DlInfoFailed)?;

        for probe in &probes {
            if SOINFO_OFFSET_PHDR.load(Ordering::Acquire) == usize::MAX
                && val0 == probe.phdr as usize
                && val1 == probe.phnum
            {
                SOINFO_OFFSET_PHDR.store(i, Ordering::Release);
                SOINFO_OFFSET_PHNUM.store(i + word, Ordering::Release);
            }

            if SOINFO_OFFSET_LOAD_BIAS.load(Ordering::Acquire) == usize::MAX
                && val0 == probe.load_bias
                && val2 == probe.l_ld
                && val5 == 0
                && val6 == val0
                && ptr_name_matches(val1, &probe.name)
            {
                SOINFO_OFFSET_LOAD_BIAS.store(i, Ordering::Release);
                SOINFO_OFFSET_NAME.store(i + word, Ordering::Release);
                SOINFO_OFFSET_CONSTRUCTORS_CALLED.store(i + word * 5, Ordering::Release);
                matched = true;
            }
        }

        if soinfo_offsets_ready() {
            break;
        }
        if probes.iter().all(|probe| {
            val0 != probe.phdr as usize
                && val0 != probe.load_bias
                && val1 != probe.phdr as usize
                && val1 != probe.load_bias
                && val2 != probe.phdr as usize
                && val2 != probe.load_bias
                && val3 != probe.phdr as usize
                && val3 != probe.load_bias
                && val4 != probe.phdr as usize
                && val4 != probe.load_bias
                && val5 != probe.phdr as usize
                && val5 != probe.load_bias
                && val6 != probe.phdr as usize
                && val6 != probe.load_bias
        }) {
            i += word * 6;
            continue;
        }
        i += word;
    }

    if !matched || !soinfo_offsets_ready() {
        return Err(Errno::DlInfoFailed);
    }
    Ok(())
}

fn scan_soinfo_post(soinfo: *mut c_void) {
    let off = SOINFO_OFFSET_CONSTRUCTORS_CALLED.load(Ordering::Acquire);
    if off == usize::MAX {
        return;
    }
    if let Some(v) = read_word(soinfo, off)
        && v != 0
    {
        SOINFO_SCAN_OK.store(true, Ordering::Release);
        SOINFO_SCAN_ACTIVE.store(false, Ordering::Release);
    }
}

fn soinfo_to_dlinfo(soinfo: *mut c_void, out: &mut libc::dl_phdr_info) -> Result<(), Errno> {
    if !soinfo_offsets_ready() {
        return Err(Errno::DlInfoFailed);
    }
    out.dlpi_addr = read_word(soinfo, SOINFO_OFFSET_LOAD_BIAS.load(Ordering::Acquire))
        .ok_or(Errno::DlInfoFailed)? as _;
    out.dlpi_name = read_word(soinfo, SOINFO_OFFSET_NAME.load(Ordering::Acquire))
        .ok_or(Errno::DlInfoFailed)? as *const c_char;
    out.dlpi_phdr = read_word(soinfo, SOINFO_OFFSET_PHDR.load(Ordering::Acquire))
        .ok_or(Errno::DlInfoFailed)? as *const libc::Elf64_Phdr;
    out.dlpi_phnum = read_word(soinfo, SOINFO_OFFSET_PHNUM.load(Ordering::Acquire))
        .ok_or(Errno::DlInfoFailed)? as _;
    Ok(())
}

fn soinfo_is_loading(soinfo: *mut c_void) -> Result<bool, Errno> {
    let off = SOINFO_OFFSET_CONSTRUCTORS_CALLED.load(Ordering::Acquire);
    if off == usize::MAX {
        return Err(Errno::DlInfoFailed);
    }
    Ok(read_word(soinfo, off).ok_or(Errno::DlInfoFailed)? == 0)
}

fn soinfo_offsets_ready() -> bool {
    SOINFO_OFFSET_PHDR.load(Ordering::Acquire) != usize::MAX
        && SOINFO_OFFSET_PHNUM.load(Ordering::Acquire) != usize::MAX
        && SOINFO_OFFSET_LOAD_BIAS.load(Ordering::Acquire) != usize::MAX
        && SOINFO_OFFSET_NAME.load(Ordering::Acquire) != usize::MAX
        && SOINFO_OFFSET_CONSTRUCTORS_CALLED.load(Ordering::Acquire) != usize::MAX
}

fn read_word(base: *mut c_void, off: usize) -> Option<usize> {
    let ptr = (base as usize).checked_add(off)? as *const usize;
    Some(unsafe { ptr.read_unaligned() })
}

fn ptr_name_matches(ptr_val: usize, expected_name: &str) -> bool {
    if ptr_val == 0 {
        return false;
    }
    unsafe { util::cstr_from_ptr_no_libc(ptr_val as *const c_char) }
        .and_then(|s| s.to_str().ok())
        .is_some_and(|s| {
            s == expected_name || util::basename_of(s) == util::basename_of(expected_name)
        })
}

struct ScanInfo {
    load_bias: usize,
    phdr: *const libc::Elf64_Phdr,
    phnum: usize,
    l_ld: usize,
    name: String,
}

struct ScanInfoCtx {
    probes: Vec<ScanInfo>,
}

fn loaded_scan_infos() -> Vec<ScanInfo> {
    let mut ctx = ScanInfoCtx { probes: Vec::new() };
    unsafe {
        libc::dl_iterate_phdr(
            Some(iter_scan_info_cb),
            &mut ctx as *mut ScanInfoCtx as *mut c_void,
        );
    }
    ctx.probes
}

unsafe extern "C" fn iter_scan_info_cb(
    info: *mut libc::dl_phdr_info,
    _size: libc::size_t,
    data: *mut c_void,
) -> c_int {
    if info.is_null() || data.is_null() {
        return 0;
    }
    let info = unsafe { &*info };
    if info.dlpi_phdr.is_null() || info.dlpi_phnum == 0 {
        return 0;
    }
    let Some(name) = linker_name(info).map(str::to_owned) else {
        return 0;
    };
    let load_bias = info.dlpi_addr as usize;
    let mut l_ld = usize::MAX;
    for i in 0..info.dlpi_phnum as usize {
        let phdr = unsafe { &*info.dlpi_phdr.add(i) };
        if phdr.p_type == libc::PT_DYNAMIC {
            l_ld = load_bias.wrapping_add(phdr.p_vaddr as usize);
            break;
        }
    }
    if l_ld == usize::MAX {
        return 0;
    }
    let ctx = unsafe { &mut *(data as *mut ScanInfoCtx) };
    ctx.probes.push(ScanInfo {
        load_bias,
        phdr: info.dlpi_phdr,
        phnum: info.dlpi_phnum as usize,
        l_ld,
        name,
    });
    0
}
