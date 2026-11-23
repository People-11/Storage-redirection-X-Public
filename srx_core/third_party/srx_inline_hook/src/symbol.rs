// 符号查询：基于 dladdr 的地址反查，返回 so 路径 / 基址 / 符号名 / 符号地址
// bionic dladdr 仅保证 so 级别定位；细粒度 sym_name 需 ELF 解析

use core::ffi::c_void;
use core::mem;

use crate::util::cstr_from_ptr_no_libc;

#[derive(Debug, Clone)]
pub struct AddrInfo {
    pub lib_path: Option<String>,
    pub lib_base: usize,
    pub sym_name: Option<String>,
    pub sym_addr: usize,
}

// dladdr 成功返回 Some；addr 不属于任何已加载段时返回 None
#[expect(
    clippy::not_unsafe_ptr_arg_deref,
    reason = "Bionic dladdr 只匹配地址所属模块，不解引用查询地址"
)]
pub fn addr_info(addr: *const c_void) -> Option<AddrInfo> {
    // SAFETY: Dl_info 零初始化；dladdr 仅按字段写入
    let mut info: libc::Dl_info = unsafe { mem::zeroed() };
    // SAFETY: addr 由调用方传入；libc::dladdr 对任意地址安全
    let rc = unsafe { libc::dladdr(addr, &mut info) };
    if rc == 0 {
        return None;
    }
    let lib_path = if info.dli_fname.is_null() {
        None
    } else {
        // SAFETY: dli_fname 为 NUL 终止字符串；手扫避免走 libc strlen
        unsafe { cstr_from_ptr_no_libc(info.dli_fname) }
            .and_then(|s| s.to_str().ok())
            .map(String::from)
    };
    let sym_name = if info.dli_sname.is_null() {
        None
    } else {
        // SAFETY: 同上
        unsafe { cstr_from_ptr_no_libc(info.dli_sname) }
            .and_then(|s| s.to_str().ok())
            .map(String::from)
    };
    Some(AddrInfo {
        lib_path,
        lib_base: info.dli_fbase as usize,
        sym_name,
        sym_addr: info.dli_saddr as usize,
    })
}
