// hook 操作错误码，0 表示成功
#[repr(i32)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Errno {
    Ok = 0,                      // 成功
    Uninit = 1,                  // 未初始化
    InitErrTrampo = 8,           // trampoline 管理器初始化失败
    InitErrSig = 9,              // 信号守卫初始化失败
    InitErrDlMtr = 10,           // dlopen 监控器初始化失败
    InvalidArg = 11,             // 参数无效
    NoSym = 13,                  // 符号未找到
    GetProt = 14,                // 读取内存保护属性失败
    SetProt = 15,                // 设置内存保护属性失败
    NewTrampo = 17,              // 创建 trampoline 失败
    ReadElf = 21,                // 读取 ELF 信息失败
    InitErrCfi = 24,             // CFI 模块初始化失败
    InitErrSafe = 26,            // 线程状态或 fork 处理器初始化失败
    NotFound = 30,               // 未找到目标
    Busy = 31,                   // 发布或进程接管正在进行
    ForkContextUnavailable = 32, // 子进程缺少可继续管理的 loader 上下文
    ModuleLeaseUnavailable = 33, // 无法证明目标模块在提交期间保持有效
    Unknown = 1001,              // 未知错误
    Invalid = 1002,              // 无效状态
    NoMem = 1003,                // 内存不足
    BadMaps = 1006,              // /proc/self/maps 解析失败
    Format = 1007,               // 格式错误
    SegvErr = 1009,              // 信号保护触发
}

impl Errno {
    pub const fn is_ok(self) -> bool {
        matches!(self, Self::Ok)
    }
}
