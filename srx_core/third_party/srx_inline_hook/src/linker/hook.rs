use core::mem;

use super::prelude::*;

const LINKER_SYM_CALL_CONSTRUCTORS_M: &CStr = c"__dl__ZN6soinfo17call_constructorsEv";
const LINKER_SYM_CALL_DESTRUCTORS_M: &CStr = c"__dl__ZN6soinfo16call_destructorsEv";

static LINKER_CTORS_STUB: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());
static LINKER_DTORS_STUB: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());
static LINKER_CTORS_HITS: AtomicUsize = AtomicUsize::new(0);
static LINKER_DTORS_HITS: AtomicUsize = AtomicUsize::new(0);
static SOINFO_SCAN_ACTIVE: AtomicBool = AtomicBool::new(false);
static SOINFO_SCAN_OK: AtomicBool = AtomicBool::new(false);
static SOINFO_OFFSET_PHDR: AtomicUsize = AtomicUsize::new(usize::MAX);
static SOINFO_OFFSET_PHNUM: AtomicUsize = AtomicUsize::new(usize::MAX);
static SOINFO_OFFSET_LOAD_BIAS: AtomicUsize = AtomicUsize::new(usize::MAX);
static SOINFO_OFFSET_NAME: AtomicUsize = AtomicUsize::new(usize::MAX);
static SOINFO_OFFSET_CONSTRUCTORS_CALLED: AtomicUsize = AtomicUsize::new(usize::MAX);

pub fn install_linker_hooks() -> Result<(), Errno> {
    if !LINKER_CTORS_STUB.load(Ordering::Acquire).is_null()
        && !LINKER_DTORS_STUB.load(Ordering::Acquire).is_null()
    {
        return Ok(());
    }

    let ctors = find_linker_symbol_by_symtab(LINKER_SYM_CALL_CONSTRUCTORS_M)
        .ok_or(Errno::DlSymFailed)? as *mut c_void;
    let dtors = find_linker_symbol_by_symtab(LINKER_SYM_CALL_DESTRUCTORS_M)
        .ok_or(Errno::DlSymFailed)? as *mut c_void;

    if LINKER_CTORS_STUB.load(Ordering::Acquire).is_null() {
        // SAFETY: ctors 是 linker64 内有效函数入口；proxy ABI 与 soinfo 成员函数保持单参调用约定
        let stub = unsafe {
            api::hook_with_orig(
                ctors,
                linker_call_constructors_proxy as *const c_void,
                ptr::null_mut(),
            )
        }?;
        LINKER_CTORS_STUB.store(stub.handle, Ordering::Release);
    }

    if LINKER_DTORS_STUB.load(Ordering::Acquire).is_null() {
        // SAFETY: dtors 同上
        let stub = unsafe {
            api::hook_with_orig(
                dtors,
                linker_call_destructors_proxy as *const c_void,
                ptr::null_mut(),
            )
        }?;
        LINKER_DTORS_STUB.store(stub.handle, Ordering::Release);
    }

    warm_up_soinfo_scan()?;
    Ok(())
}

pub fn linker_hooks_installed() -> bool {
    !LINKER_CTORS_STUB.load(Ordering::Acquire).is_null()
        && !LINKER_DTORS_STUB.load(Ordering::Acquire).is_null()
}

pub fn linker_ctor_hit_count() -> usize {
    LINKER_CTORS_HITS.load(Ordering::Acquire)
}

pub fn linker_dtor_hit_count() -> usize {
    LINKER_DTORS_HITS.load(Ordering::Acquire)
}

pub fn linker_hook_stub_count() -> usize {
    usize::from(!LINKER_CTORS_STUB.load(Ordering::Acquire).is_null())
        + usize::from(!LINKER_DTORS_STUB.load(Ordering::Acquire).is_null())
}

pub fn reset_linker_hook_counters() {
    LINKER_CTORS_HITS.store(0, Ordering::Release);
    LINKER_DTORS_HITS.store(0, Ordering::Release);
}

extern "C" fn linker_call_constructors_proxy(soinfo: *mut c_void) {
    LINKER_CTORS_HITS.fetch_add(1, Ordering::AcqRel);

    let do_scan = SOINFO_SCAN_ACTIVE.load(Ordering::Acquire);
    let callbacks_registered = dlcb::has_init_callbacks();
    let mut dlinfo = libc::dl_phdr_info {
        dlpi_addr: 0,
        dlpi_name: ptr::null(),
        dlpi_phdr: ptr::null(),
        dlpi_phnum: 0,
        #[cfg(any(target_os = "linux", target_os = "android"))]
        dlpi_adds: 0,
        #[cfg(any(target_os = "linux", target_os = "android"))]
        dlpi_subs: 0,
        #[cfg(any(target_os = "linux", target_os = "android"))]
        dlpi_tls_modid: 0,
        #[cfg(any(target_os = "linux", target_os = "android"))]
        dlpi_tls_data: ptr::null_mut(),
    };
    let scan_pre_ok = do_scan && scan_soinfo_pre(soinfo, &mut dlinfo).is_ok();
    let scan_process_ok = scan_pre_ok && !dlinfo.dlpi_name.is_null();
    let steady_process_ok = !do_scan
        && SOINFO_SCAN_OK.load(Ordering::Acquire)
        && soinfo_is_loading(soinfo).unwrap_or(false)
        && soinfo_to_dlinfo(soinfo, &mut dlinfo).is_ok();
    let can_process = scan_process_ok || steady_process_ok;

    if can_process {
        pending::try_pending_from_info(&mut dlinfo, size_of::<libc::dl_phdr_info>());
        if callbacks_registered {
            dlcb::dispatch_init_pre(&mut dlinfo, size_of::<libc::dl_phdr_info>());
        }
    }

    call_prev_soinfo(LINKER_CTORS_STUB.load(Ordering::Acquire), soinfo);

    if scan_pre_ok {
        scan_soinfo_post(soinfo);
    }
    if can_process && callbacks_registered && !dlinfo.dlpi_name.is_null() {
        dlcb::dispatch_init_post(&mut dlinfo, size_of::<libc::dl_phdr_info>());
    }
}

extern "C" fn linker_call_destructors_proxy(soinfo: *mut c_void) {
    LINKER_DTORS_HITS.fetch_add(1, Ordering::AcqRel);

    let can_process = SOINFO_SCAN_OK.load(Ordering::Acquire);
    let can_dispatch = can_process && dlcb::has_fini_callbacks();
    let mut dlinfo = libc::dl_phdr_info {
        dlpi_addr: 0,
        dlpi_name: ptr::null(),
        dlpi_phdr: ptr::null(),
        dlpi_phnum: 0,
        #[cfg(any(target_os = "linux", target_os = "android"))]
        dlpi_adds: 0,
        #[cfg(any(target_os = "linux", target_os = "android"))]
        dlpi_subs: 0,
        #[cfg(any(target_os = "linux", target_os = "android"))]
        dlpi_tls_modid: 0,
        #[cfg(any(target_os = "linux", target_os = "android"))]
        dlpi_tls_data: ptr::null_mut(),
    };
    let do_process = can_process
        && soinfo_to_dlinfo(soinfo, &mut dlinfo).is_ok()
        && dlinfo.dlpi_addr != 0
        && !dlinfo.dlpi_name.is_null()
        && soinfo_is_loading(soinfo).map(|v| !v).unwrap_or(false);

    if do_process && can_dispatch {
        dlcb::dispatch_fini_pre(&mut dlinfo, size_of::<libc::dl_phdr_info>());
    }

    call_prev_soinfo(LINKER_DTORS_STUB.load(Ordering::Acquire), soinfo);

    if do_process {
        api::cleanup_hooks_for_dlinfo(&dlinfo);
        pending::reset_after_dlclose(&dlinfo);
        if can_dispatch {
            dlcb::dispatch_fini_post(&mut dlinfo, size_of::<libc::dl_phdr_info>());
        }
    }
}

fn warm_up_soinfo_scan() -> Result<(), Errno> {
    if SOINFO_SCAN_OK.load(Ordering::Acquire) {
        return Ok(());
    }
    SOINFO_SCAN_ACTIVE.store(true, Ordering::Release);
    Ok(())
}

fn call_prev_soinfo(stub: *mut c_void, soinfo: *mut c_void) {
    if stub.is_null() {
        return;
    }
    let Ok(prev) = (unsafe { api::prev_func(HookStub { handle: stub }) }) else {
        return;
    };
    // SAFETY: prev_func 返回 trampoline，ABI 与 soinfo 成员函数保持单参调用约定
    let orig: extern "C" fn(*mut c_void) = unsafe { mem::transmute(prev) };
    orig(soinfo);
}

fn scan_soinfo_pre(soinfo: *mut c_void, out: &mut libc::dl_phdr_info) -> Result<(), Errno> {
    let probes = loaded_scan_infos();
    if probes.is_empty() {
        return Err(Errno::DlInfoFailed);
    }

    let word = size_of::<usize>();
    let mut matched_name = ptr::null();
    let mut matched_probe = None;
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
                matched_name = val1 as *const c_char;
                matched_probe = Some((probe.load_bias, probe.phdr, probe.phnum));
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

    if !soinfo_offsets_ready() {
        return Err(Errno::DlInfoFailed);
    }
    let Some((load_bias, phdr, phnum)) = matched_probe else {
        return Err(Errno::DlInfoFailed);
    };
    out.dlpi_addr = load_bias as _;
    out.dlpi_name = matched_name;
    out.dlpi_phdr = phdr;
    out.dlpi_phnum = phnum as _;
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
