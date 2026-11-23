use crate::errno::Errno;
use crate::log;
use crate::runtime;
use std::ffi::c_void;

// hook 任务的唯一标识，由运行时分配
pub type HookStub = u64;

#[derive(Debug)]
pub struct HookError {
    pub status: Errno,
    pub stub: Option<HookStub>,
    pub errors: Vec<RefreshError>,
}

impl From<Errno> for HookError {
    fn from(status: Errno) -> Self {
        Self {
            status,
            stub: None,
            errors: Vec::new(),
        }
    }
}

// refresh 中单个模块的错误详情，用于诊断 ELF 解析失败等问题
#[derive(Debug)]
pub struct RefreshError {
    pub module_path: String,
    pub errno: Errno,
}

// Automatic: dlopen/dlclose 事件自动触发刷新
// Manual: 需要手动调用 refresh() 应用 hook
#[repr(i32)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum HookMode {
    Automatic = 0,
    Manual = 1,
}

// 无锁检测当前进程是否为 fork 子进程
pub fn is_forked_child() -> bool {
    runtime::is_forked_child()
}

// 初始化 hook 运行时，只能调用一次
pub fn init(mode: HookMode, debug: bool) -> Errno {
    if let Err(error) = runtime::check_management() {
        return error;
    }
    runtime::init(mode, debug)
}

// hook 所有已加载和未来加载的 caller 模块；已登记但部分模块应用失败时仍返回 stub
pub fn hook_all(sym_name: &str, new_func: *mut c_void) -> Option<HookStub> {
    let error = match runtime::hook_all_checked(sym_name, new_func) {
        Ok(stub) => return Some(stub),
        Err(error) => error,
    };
    log::warn(format_args!(
        "hook_all {} status={:?} stub={:?} errors={:?}",
        sym_name, error.status, error.stub, error.errors
    ));
    error.stub
}

// 将指定 caller 路径加入忽略列表，后续 hook 跳过该模块
pub fn add_ignore(caller_path_name: &str) -> Errno {
    if let Err(error) = runtime::check_management() {
        return error;
    }
    runtime::add_ignore(caller_path_name)
}

// 手动模式下触发一次全量刷新，将待生效的 hook 应用到已加载模块
pub fn refresh() -> (Errno, Vec<RefreshError>) {
    if let Err(error) = runtime::check_management() {
        return (error, Vec::new());
    }
    runtime::refresh()
}

// 获取 prev_func 并在闭包中执行，自动管理栈帧释放与环路检测
pub fn with_prev_func<R, F>(func: *mut c_void, f: F) -> Option<R>
where
    F: FnOnce(*mut c_void) -> R,
{
    runtime::with_prev_func(func, f)
}
