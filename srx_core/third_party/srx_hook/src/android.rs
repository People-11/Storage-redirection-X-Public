// Android 平台相关功能的模块入口

// 内存保护操作：读取和修改页面权限
pub mod memory;
// 信号守卫：sigsetjmp/siglongjmp 保护 hook 过程中的致命信号
pub mod signal_guard;
