use super::prelude::*;

// 幂等；debuggable 仅在首次成功 init 前生效
pub fn init(debuggable: bool) -> Result<(), Errno> {
    let r = runtime::init(debuggable);
    match &r {
        Ok(()) => log::info!(target: "srx_inline_hook", "init ok {}", version::get_version()),
        Err(e) => sh_always!(
            target: "srx_inline_hook",
            "init fail errno={}({})",
            *e as i32,
            e.message(),
        ),
    }
    r
}

pub fn is_debug() -> bool {
    runtime::is_debug()
}
