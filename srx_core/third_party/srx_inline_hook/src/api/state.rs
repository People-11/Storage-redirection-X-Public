use core::fmt;

use super::prelude::*;

pub fn init(mode: HookMode, debuggable: bool) -> Result<(), Errno> {
    tls_errno::reset();
    runtime::set_mode_if_uninit(mode as i32);
    runtime::set_debug_if_uninit(debuggable);
    let r = runtime::init();
    match &r {
        Ok(()) => {
            log::info!(target: "srx_inline_hook", "init ok {}", version::get_version())
        }
        Err(e) => sh_always!(
            target: "srx_inline_hook",
            "init fail errno={}({})",
            *e as i32,
            e.message(),
        ),
    }
    tls_errno::set(match &r {
        Ok(()) => Errno::Ok,
        Err(e) => *e,
    });
    r
}

// 未调过 init → Uninit；成功 → Ok；失败 → 具体错误
pub fn get_init_errno() -> Errno {
    runtime::get_init_errno()
}

// 线程局部 "最近一次 API 结果"；未调过任何 API 的线程读到 Uninit
pub fn get_errno() -> Errno {
    tls_errno::get()
}
pub fn set_debug(on: bool) {
    runtime::set_debug(on);
}

pub fn is_debug() -> bool {
    runtime::is_debug()
}
pub fn set_disabled(on: bool) {
    sh_always!(target: "srx_inline_hook", "set disable = {}", if on { "TRUE" } else { "FALSE" });
    runtime::set_disabled(on);
}

pub fn is_disabled() -> bool {
    runtime::is_disabled()
}

pub fn set_recordable(on: bool) {
    recorder::set_recordable(on);
}

pub fn is_recordable() -> bool {
    recorder::is_recordable()
}

// 当前已累积记录文本；每行 "[ts] OP target=... replacement=... errno=N(msg)"
pub fn dump_records() -> String {
    recorder::dump()
}

// 按 items 过滤字段；items=RecordItems::ALL 等价 dump_records
pub fn dump_records_with_items(items: RecordItems) -> String {
    recorder::dump_with_items(items)
}

// 按 items 过滤写入 fd；recordable=false 返 Ok(0)，fd < 0 返 InvalidArg
pub fn dump_records_to_fd(fd: i32, items: RecordItems) -> Result<usize, Errno> {
    recorder::dump_to_fd(fd, items)
}

// 清空记录队列；不影响 set_recordable
pub fn clear_records() {
    recorder::clear();
}

// 跳板池快照：pages / 总槽位 / 占用 / 冷却 / 可复用
pub fn trampoline_stats() -> trampoline::TrampolineStats {
    trampoline::stats()
}

// 当前存活 hook 数；与 trampoline_stats().slots_used 恒等
pub fn active_hook_count() -> usize {
    switch::active_count()
}

// 存活 hook 的地址骨架快照；访问需持 switch 内部锁
pub fn list_hooks() -> Vec<switch::HookInfo> {
    switch::list()
}

// 综合诊断：版本 / init 状态 / 各开关 / 活跃 hook / 跳板池 / 记录条数
#[derive(Debug, Clone)]
pub struct DiagnoseReport {
    pub version: &'static str,
    pub mode: HookMode,
    pub init_errno: Errno,
    // 调用线程的最近一次 API 结果；可用于排障流水
    pub tls_errno: Errno,
    pub is_disabled: bool,
    pub is_debug: bool,
    pub is_recordable: bool,
    pub active_hooks: usize,
    pub trampoline: trampoline::TrampolineStats,
    pub record_count: usize,
    pub linker_hooks_installed: bool,
    pub linker_hook_stubs: usize,
    pub linker_ctor_hits: usize,
    pub linker_dtor_hits: usize,
    // recorder 是否在某次 record() / dump 中触发过 Mutex 中毒
    pub record_error: bool,
}

impl fmt::Display for DiagnoseReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} mode={:?} init={} tls={} disabled={} debug={} recordable={} \
             hooks={} tramp(pages={} used={} cooldown={} free={}) records={} \
             linker(installed={} stubs={} ctor_hits={} dtor_hits={}) rec_err={}",
            self.version,
            self.mode,
            self.init_errno as i32,
            self.tls_errno as i32,
            self.is_disabled,
            self.is_debug,
            self.is_recordable,
            self.active_hooks,
            self.trampoline.pages,
            self.trampoline.slots_used,
            self.trampoline.slots_cooldown,
            self.trampoline.slots_free,
            self.record_count,
            self.linker_hooks_installed,
            self.linker_hook_stubs,
            self.linker_ctor_hits,
            self.linker_dtor_hits,
            self.record_error,
        )
    }
}

pub fn diagnose() -> DiagnoseReport {
    DiagnoseReport {
        version: version::get_version(),
        mode: get_mode(),
        init_errno: runtime::get_init_errno(),
        tls_errno: tls_errno::get(),
        is_disabled: runtime::is_disabled(),
        is_debug: runtime::is_debug(),
        is_recordable: recorder::is_recordable(),
        active_hooks: switch::active_count(),
        trampoline: trampoline::stats(),
        record_count: recorder::count(),
        linker_hooks_installed: linker::linker_hooks_installed(),
        linker_hook_stubs: linker::linker_hook_stub_count(),
        linker_ctor_hits: linker::linker_ctor_hit_count(),
        linker_dtor_hits: linker::linker_dtor_hit_count(),
        record_error: recorder::has_record_error(),
    }
}
