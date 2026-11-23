use core::cmp::Ordering as CmpOrdering;
use core::mem;

use super::prelude::*;

const DT_NULL: i64 = 0;
const DT_HASH: i64 = 4;
const DT_STRTAB: i64 = 5;
const DT_SYMTAB: i64 = 6;
const DT_GNU_HASH: i64 = 0x6ffffef5;

const ELF_MAGIC: [u8; 4] = [0x7f, b'E', b'L', b'F'];
const ELF_CLASS_64: u8 = 2;
const SHT_SYMTAB: u32 = 2;
const SHT_STRTAB: u32 = 3;
const SHT_PROGBITS: u32 = 1;
const SHN_UNDEF: u16 = 0;
const SHN_LORESERVE: u16 = 0xff00;
const SHN_HIRESERVE: u16 = 0xffff;
const GNU_DEBUGDATA: &[u8] = b".gnu_debugdata";
const SYMTAB_NAME: &[u8] = b".symtab";
// 优先按当前链接器命名空间解析，绝对路径仅作后续候选。
const LIBLZMA_PATHS_64: [&CStr; 4] = [
    c"liblzma.so",
    c"/system/lib64/liblzma.so",
    c"/apex/com.android.art/lib64/liblzma.so",
    c"/apex/com.android.runtime/lib64/liblzma.so",
];
const LIBLZMA_PATHS_32: [&CStr; 4] = [
    c"liblzma.so",
    c"/system/lib/liblzma.so",
    c"/apex/com.android.art/lib/liblzma.so",
    c"/apex/com.android.runtime/lib/liblzma.so",
];
const LIBLZMA_SYM_CRCGEN: &CStr = c"CrcGenerateTable";
const LIBLZMA_SYM_CRC64GEN: &CStr = c"Crc64GenerateTable";
const LIBLZMA_SYM_CONSTRUCT: &CStr = c"XzUnpacker_Construct";
const LIBLZMA_SYM_IS_FINISHED: &CStr = c"XzUnpacker_IsStreamWasFinished";
const LIBLZMA_SYM_FREE: &CStr = c"XzUnpacker_Free";
const LIBLZMA_SYM_CODE: &CStr = c"XzUnpacker_Code";

#[repr(C)]
#[derive(Clone, Copy)]
pub(super) struct Elf64Dyn {
    d_tag: i64,
    d_un: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(super) struct Elf64Sym {
    st_name: u32,
    st_info: u8,
    st_other: u8,
    st_shndx: u16,
    st_value: u64,
    st_size: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Elf64Ehdr {
    e_ident: [u8; 16],
    e_type: u16,
    e_machine: u16,
    e_version: u32,
    e_entry: u64,
    e_phoff: u64,
    e_shoff: u64,
    e_flags: u32,
    e_ehsize: u16,
    e_phentsize: u16,
    e_phnum: u16,
    e_shentsize: u16,
    e_shnum: u16,
    e_shstrndx: u16,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Elf64Shdr {
    sh_name: u32,
    sh_type: u32,
    sh_flags: u64,
    sh_addr: u64,
    sh_offset: u64,
    sh_size: u64,
    sh_link: u32,
    sh_info: u32,
    sh_addralign: u64,
    sh_entsize: u64,
}

#[repr(C)]
struct ISzAlloc {
    alloc: extern "C" fn(*const ISzAlloc, usize) -> *mut c_void,
    free: extern "C" fn(*const ISzAlloc, *mut c_void),
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq)]
enum ECoderStatus {
    NotSpecified = 0,
    FinishedWithMark = 1,
    NotFinished = 2,
    NeedsMoreInput = 3,
}

#[repr(C)]
#[derive(Clone, Copy)]
enum ECoderFinishMode {
    Any = 0,
}

type LzmaCrcGenerateTable = extern "C" fn();
type LzmaCrc64GenerateTable = extern "C" fn();
type LzmaConstruct = extern "C" fn(*mut c_void, *const ISzAlloc);
type LzmaIsFinished = extern "C" fn(*const c_void) -> c_int;
type LzmaFree = extern "C" fn(*mut c_void);
type LzmaCode = extern "C" fn(
    *mut c_void,
    *mut u8,
    *mut usize,
    *const u8,
    *mut usize,
    ECoderFinishMode,
    *mut ECoderStatus,
) -> c_int;
type LzmaCodeQ = extern "C" fn(
    *mut c_void,
    *mut u8,
    *mut usize,
    *const u8,
    *mut usize,
    c_int,
    ECoderFinishMode,
    *mut ECoderStatus,
) -> c_int;

struct LzmaApi {
    construct: LzmaConstruct,
    is_finished: LzmaIsFinished,
    free: LzmaFree,
    code: LzmaCode,
    code_q: LzmaCodeQ,
}

// 解 PT_DYNAMIC → DT_SYMTAB / DT_STRTAB / DT_GNU_HASH / DT_HASH
pub(super) unsafe fn dynsym_lookup(
    load_bias: usize,
    dyn_ptr: *const Elf64Dyn,
    target: &CStr,
) -> Option<usize> {
    let mut sym_tab: *const Elf64Sym = ptr::null();
    let mut str_tab: *const c_char = ptr::null();
    let mut sysv_hash_ptr: *const u32 = ptr::null();
    let mut gnu_hash_ptr: *const u32 = ptr::null();

    let mut d = dyn_ptr;
    loop {
        // SAFETY: DT_NULL(0) 为终止哨兵，bionic 保证 .dynamic 段以 DT_NULL 收尾
        let entry = unsafe { &*d };
        if entry.d_tag == DT_NULL {
            break;
        }
        let val = entry.d_un as usize;
        match entry.d_tag {
            DT_SYMTAB => sym_tab = (load_bias + val) as *const Elf64Sym,
            DT_STRTAB => str_tab = (load_bias + val) as *const c_char,
            DT_HASH => sysv_hash_ptr = (load_bias + val) as *const u32,
            DT_GNU_HASH => gnu_hash_ptr = (load_bias + val) as *const u32,
            _ => {}
        }
        // SAFETY: 按 Elf64Dyn 步长前进
        d = unsafe { d.add(1) };
    }

    if sym_tab.is_null() || str_tab.is_null() {
        return None;
    }
    if !gnu_hash_ptr.is_null() {
        // SAFETY: gnu_hash_ptr 指向合法 .gnu.hash 头与后续 bloom/bucket/chain 数据
        if let Some(addr) =
            unsafe { gnu_hash_lookup(load_bias, sym_tab, str_tab, gnu_hash_ptr, target) }
        {
            return Some(addr);
        }
    }
    if !sysv_hash_ptr.is_null() {
        // SAFETY: sysv .hash 布局 [nbucket, nchain, buckets..., chains...]
        return unsafe { sysv_hash_lookup(load_bias, sym_tab, str_tab, sysv_hash_ptr, target) };
    }
    None
}

unsafe fn sysv_hash_lookup(
    load_bias: usize,
    sym_tab: *const Elf64Sym,
    str_tab: *const c_char,
    hash_ptr: *const u32,
    target: &CStr,
) -> Option<usize> {
    let nbucket = unsafe { *hash_ptr } as usize;
    if nbucket == 0 {
        return None;
    }
    let buckets = unsafe { hash_ptr.add(2) };
    let chains = unsafe { buckets.add(nbucket) };
    let hash = sysv_hash(target.to_bytes());
    let mut i = unsafe { *buckets.add(hash as usize % nbucket) } as usize;
    while i != 0 {
        // SAFETY: i 由 .hash bucket/chain 给出，指向有效 dynsym 索引
        let sym = unsafe { &*sym_tab.add(i) };
        if sym.st_name != 0 {
            // SAFETY: st_name 为 strtab 内 NUL 终止偏移；手扫避免走 libc strlen
            let Some(sym_name) =
                (unsafe { util::cstr_from_ptr_no_libc(str_tab.add(sym.st_name as usize)) })
            else {
                i = unsafe { *chains.add(i) } as usize;
                continue;
            };
            if sym_name.to_bytes() == target.to_bytes() {
                return Some(load_bias + sym.st_value as usize);
            }
        }
        i = unsafe { *chains.add(i) } as usize;
    }
    None
}

unsafe fn gnu_hash_lookup(
    load_bias: usize,
    sym_tab: *const Elf64Sym,
    str_tab: *const c_char,
    hash_ptr: *const u32,
    target: &CStr,
) -> Option<usize> {
    let nbucket = unsafe { *hash_ptr } as usize;
    let sym_offset = unsafe { *hash_ptr.add(1) } as usize;
    let bloom_count = unsafe { *hash_ptr.add(2) } as usize;
    let bloom_shift = unsafe { *hash_ptr.add(3) } as usize;
    if nbucket == 0 || bloom_count == 0 {
        return None;
    }

    let bloom = unsafe { hash_ptr.add(4) } as *const usize;
    let buckets = unsafe { bloom.add(bloom_count) } as *const u32;
    let chains = unsafe { buckets.add(nbucket) };
    let hash = gnu_hash(target.to_bytes());
    let elfclass_bits = usize::BITS as usize;
    // SAFETY: bloom_count > 0，bloom 指向 bloom filter 数组
    let word = unsafe { *bloom.add((hash as usize / elfclass_bits) % bloom_count) };
    let mask = (1usize << (hash as usize % elfclass_bits))
        | (1usize << ((hash as usize >> bloom_shift) % elfclass_bits));
    if (word & mask) != mask {
        return None;
    }

    let mut i = unsafe { *buckets.add(hash as usize % nbucket) } as usize;
    if i < sym_offset {
        return None;
    }

    loop {
        // SAFETY: bucket 与 chain 给出有效 dynsym 索引
        let sym = unsafe { &*sym_tab.add(i) };
        let sym_hash = unsafe { *chains.add(i - sym_offset) };
        if (hash | 1) == (sym_hash | 1) && sym.st_name != 0 {
            // SAFETY: st_name 为 strtab 内 NUL 终止偏移；手扫避免走 libc strlen
            let Some(sym_name) =
                (unsafe { util::cstr_from_ptr_no_libc(str_tab.add(sym.st_name as usize)) })
            else {
                if (sym_hash & 1) != 0 {
                    break;
                }
                i += 1;
                continue;
            };
            if sym_name.to_bytes() == target.to_bytes() {
                return Some(load_bias + sym.st_value as usize);
            }
        }
        if (sym_hash & 1) != 0 {
            break;
        }
        i += 1;
    }
    None
}

pub(super) fn symtab_lookup(path: &str, load_bias: usize, target: &CStr) -> Option<usize> {
    let image = fs::read(path).ok()?;
    symtab_lookup_in_image(&image, load_bias, target)
        .or_else(|| symtab_lookup_in_debugdata(&image, load_bias, target))
}

fn symtab_lookup_in_image(image: &[u8], load_bias: usize, target: &CStr) -> Option<usize> {
    let ehdr = checked_ehdr(image)?;
    let shstr = section_bytes(image, &section_at(image, &ehdr, ehdr.e_shstrndx as usize)?)?;
    for i in 0..ehdr.e_shnum as usize {
        let symtab = section_at(image, &ehdr, i)?;
        if symtab.sh_type != SHT_SYMTAB || !section_name_is(shstr, symtab.sh_name, SYMTAB_NAME) {
            continue;
        }
        if let Some(found) = lookup_in_symtab_section(image, &ehdr, &symtab, load_bias, target) {
            return Some(found);
        }
    }
    None
}

fn symtab_lookup_in_debugdata(image: &[u8], load_bias: usize, target: &CStr) -> Option<usize> {
    let ehdr = checked_ehdr(image)?;
    let shstr = section_bytes(image, &section_at(image, &ehdr, ehdr.e_shstrndx as usize)?)?;
    for i in 0..ehdr.e_shnum as usize {
        let debugdata = section_at(image, &ehdr, i)?;
        if debugdata.sh_type != SHT_PROGBITS
            || !section_name_is(shstr, debugdata.sh_name, GNU_DEBUGDATA)
        {
            continue;
        }
        let zipped = section_bytes(image, &debugdata)?;
        let unpacked = decompress_gnu_debugdata(zipped)?;
        if let Some(found) = symtab_lookup_in_image(&unpacked, load_bias, target) {
            return Some(found);
        }
    }
    None
}

fn checked_ehdr(image: &[u8]) -> Option<Elf64Ehdr> {
    let ehdr = read_pod::<Elf64Ehdr>(image, 0)?;
    if ehdr.e_ident[0..4] != ELF_MAGIC
        || ehdr.e_ident[4] != ELF_CLASS_64
        || ehdr.e_shoff == 0
        || ehdr.e_shnum == 0
        || ehdr.e_shentsize as usize != size_of::<Elf64Shdr>()
        || ehdr.e_shstrndx == 0
        || ehdr.e_shstrndx >= ehdr.e_shnum
    {
        return None;
    }
    Some(ehdr)
}

fn lookup_in_symtab_section(
    image: &[u8],
    ehdr: &Elf64Ehdr,
    symtab: &Elf64Shdr,
    load_bias: usize,
    target: &CStr,
) -> Option<usize> {
    if symtab.sh_link >= ehdr.e_shnum as u32 || symtab.sh_entsize as usize != size_of::<Elf64Sym>()
    {
        return None;
    }
    let strtab = section_at(image, ehdr, symtab.sh_link as usize)?;
    if strtab.sh_type != SHT_STRTAB {
        return None;
    }
    let strtab_bytes = section_bytes(image, &strtab)?;
    let count = (symtab.sh_size / symtab.sh_entsize) as usize;
    let mut off = symtab.sh_offset as usize;
    for _ in 0..count {
        let sym = read_pod::<Elf64Sym>(image, off)?;
        if symtab_symbol_matches(strtab_bytes, &sym, target.to_bytes()) {
            return Some(load_bias + sym.st_value as usize);
        }
        off = off.checked_add(symtab.sh_entsize as usize)?;
    }
    None
}

fn section_at(image: &[u8], ehdr: &Elf64Ehdr, index: usize) -> Option<Elf64Shdr> {
    if index >= ehdr.e_shnum as usize {
        return None;
    }
    let off = (ehdr.e_shoff as usize).checked_add(index.checked_mul(size_of::<Elf64Shdr>())?)?;
    read_pod::<Elf64Shdr>(image, off)
}

fn section_bytes<'a>(image: &'a [u8], shdr: &Elf64Shdr) -> Option<&'a [u8]> {
    slice_at(image, shdr.sh_offset as usize, shdr.sh_size as usize)
}

fn read_pod<T: Copy>(bytes: &[u8], offset: usize) -> Option<T> {
    let end = offset.checked_add(size_of::<T>())?;
    let ptr = bytes.get(offset..end)?.as_ptr() as *const T;
    // SAFETY: 范围已校验；ELF 文件缓冲未对齐，需走 read_unaligned
    Some(unsafe { ptr.read_unaligned() })
}

fn slice_at(bytes: &[u8], offset: usize, len: usize) -> Option<&[u8]> {
    let end = offset.checked_add(len)?;
    bytes.get(offset..end)
}

fn read_c_bytes(bytes: &[u8], offset: usize) -> Option<&[u8]> {
    let tail = bytes.get(offset..)?;
    let nul = tail.iter().position(|b| *b == 0)?;
    Some(&tail[..nul])
}

extern "C" fn lzma_alloc(_p: *const ISzAlloc, size: usize) -> *mut c_void {
    unsafe { libc::malloc(size) }
}

extern "C" fn lzma_free_alloc(_p: *const ISzAlloc, address: *mut c_void) {
    unsafe { libc::free(address) };
}

fn lzma_api() -> Option<&'static LzmaApi> {
    static API: OnceCell<Option<LzmaApi>> = OnceCell::new();
    API.get_or_init(load_lzma_api).as_ref()
}

fn load_lzma_api() -> Option<LzmaApi> {
    let paths = if cfg!(target_pointer_width = "64") {
        &LIBLZMA_PATHS_64
    } else {
        &LIBLZMA_PATHS_32
    };
    for path in paths {
        if let Some(api) = load_lzma_api_from(path) {
            return Some(api);
        }
    }
    None
}

fn load_lzma_api_from(path: &CStr) -> Option<LzmaApi> {
    let handle = unsafe { libc::dlopen(path.as_ptr(), libc::RTLD_NOW) };
    if handle.is_null() {
        return None;
    }
    let crc = unsafe { libc::dlsym(handle, LIBLZMA_SYM_CRCGEN.as_ptr()) };
    let crc64 = unsafe { libc::dlsym(handle, LIBLZMA_SYM_CRC64GEN.as_ptr()) };
    let construct = unsafe { libc::dlsym(handle, LIBLZMA_SYM_CONSTRUCT.as_ptr()) };
    let is_finished = unsafe { libc::dlsym(handle, LIBLZMA_SYM_IS_FINISHED.as_ptr()) };
    let free = unsafe { libc::dlsym(handle, LIBLZMA_SYM_FREE.as_ptr()) };
    let code = unsafe { libc::dlsym(handle, LIBLZMA_SYM_CODE.as_ptr()) };
    if crc.is_null()
        || construct.is_null()
        || is_finished.is_null()
        || free.is_null()
        || code.is_null()
    {
        unsafe { libc::dlclose(handle) };
        return None;
    }
    let crc: LzmaCrcGenerateTable = unsafe { mem::transmute(crc) };
    crc();
    if !crc64.is_null() {
        let crc64: LzmaCrc64GenerateTable = unsafe { mem::transmute(crc64) };
        crc64();
    }
    Some(LzmaApi {
        construct: unsafe { mem::transmute::<*mut c_void, LzmaConstruct>(construct) },
        is_finished: unsafe { mem::transmute::<*mut c_void, LzmaIsFinished>(is_finished) },
        free: unsafe { mem::transmute::<*mut c_void, LzmaFree>(free) },
        code: unsafe { mem::transmute::<*mut c_void, LzmaCode>(code) },
        code_q: unsafe { mem::transmute::<*mut c_void, LzmaCodeQ>(code) },
    })
}

fn decompress_gnu_debugdata(src: &[u8]) -> Option<Vec<u8>> {
    let api = lzma_api()?;
    let alloc = ISzAlloc {
        alloc: lzma_alloc,
        free: lzma_free_alloc,
    };
    let mut state = [0u64; 512];
    (api.construct)(state.as_mut_ptr() as *mut c_void, &alloc);
    let mut dst = Vec::<u8>::new();
    let mut total_out = 0usize;
    let mut src_offset = 0usize;
    let api_level = android::device_api_level();
    loop {
        // 至少保留 64KiB 写空间
        if dst.len() < total_out + 0x10000 {
            dst.resize(total_out + 0x10000, 0);
        }
        let mut dst_room = dst.len() - total_out;
        let mut src_room = match src.len().checked_sub(src_offset) {
            Some(r) => r,
            None => {
                (api.free)(state.as_mut_ptr() as *mut c_void);
                return None;
            }
        };
        let mut status = ECoderStatus::NotSpecified;
        // SAFETY: 偏移在 dst/src 范围内；指针由 ptr::add 计算
        let result = unsafe {
            if api_level >= 29 {
                (api.code_q)(
                    state.as_mut_ptr() as *mut c_void,
                    dst.as_mut_ptr().add(total_out),
                    &mut dst_room,
                    src.as_ptr().add(src_offset),
                    &mut src_room,
                    1,
                    ECoderFinishMode::Any,
                    &mut status,
                )
            } else {
                (api.code)(
                    state.as_mut_ptr() as *mut c_void,
                    dst.as_mut_ptr().add(total_out),
                    &mut dst_room,
                    src.as_ptr().add(src_offset),
                    &mut src_room,
                    ECoderFinishMode::Any,
                    &mut status,
                )
            }
        };
        if result != 0 {
            (api.free)(state.as_mut_ptr() as *mut c_void);
            return None;
        }
        total_out += dst_room;
        src_offset += src_room;
        if status != ECoderStatus::NotFinished {
            break;
        }
        if dst_room == 0 && src_room == 0 {
            (api.free)(state.as_mut_ptr() as *mut c_void);
            return None;
        }
    }
    let finished = (api.is_finished)(state.as_mut_ptr() as *mut c_void) != 0;
    (api.free)(state.as_mut_ptr() as *mut c_void);
    if !finished {
        return None;
    }
    dst.truncate(total_out);
    Some(dst)
}

fn section_name_is(shstr: &[u8], name_off: u32, expected: &[u8]) -> bool {
    matches!(read_c_bytes(shstr, name_off as usize), Some(name) if name == expected)
}

fn symtab_symbol_matches(strtab: &[u8], sym: &Elf64Sym, target: &[u8]) -> bool {
    if target.is_empty() || !is_export_symtab_symbol(sym.st_shndx) {
        return false;
    }
    let Some(name) = read_c_bytes(strtab, sym.st_name as usize) else {
        return false;
    };
    match name.len().cmp(&target.len()) {
        CmpOrdering::Less => false,
        CmpOrdering::Equal => name == target,
        CmpOrdering::Greater => {
            name.starts_with(target) && matches!(name[target.len()], b'.' | b'$')
        }
    }
}

fn is_export_symtab_symbol(shndx: u16) -> bool {
    shndx != SHN_UNDEF && !(SHN_LORESERVE..=SHN_HIRESERVE).contains(&shndx)
}

fn sysv_hash(name: &[u8]) -> u32 {
    let mut h = 0u32;
    for &b in name {
        h = (h << 4).wrapping_add(b as u32);
        let g = h & 0xf0000000;
        h ^= g;
        h ^= g >> 24;
    }
    h
}

fn gnu_hash(name: &[u8]) -> u32 {
    let mut h = 5381u32;
    for &b in name {
        h = h.wrapping_add((h << 5).wrapping_add(b as u32));
    }
    h
}

pub(super) fn linker_name(info: &libc::dl_phdr_info) -> Option<&str> {
    // SAFETY: dlpi_name 由 libc 提供，NUL 终止；手扫避免被 hook libc strlen 反噬
    unsafe { util::cstr_from_ptr_no_libc(info.dlpi_name) }?
        .to_str()
        .ok()
}

pub(super) fn is_linker64(info: &libc::dl_phdr_info) -> bool {
    matches!(linker_name(info), Some(name) if util::basename_of(name) == "linker64")
}

fn normalized_match_name(mut name: &str) -> &str {
    while let Some(rest) = name.strip_prefix("./") {
        name = rest;
    }
    name
}

pub(crate) fn path_name_matches(loaded_name: &str, request_name: &str) -> bool {
    let loaded_name = normalized_match_name(loaded_name);
    let request_name = normalized_match_name(request_name);
    if loaded_name.starts_with('/') && !request_name.starts_with('/') {
        loaded_name.ends_with(request_name)
    } else if !loaded_name.starts_with('/') && request_name.starts_with('/') {
        request_name.ends_with(loaded_name)
    } else {
        loaded_name == request_name
    }
}
