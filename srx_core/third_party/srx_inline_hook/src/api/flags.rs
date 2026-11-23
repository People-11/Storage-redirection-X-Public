use super::prelude::*;

const HOOK_FLAG_SHARED: u32 = 0b0001;
const HOOK_FLAG_UNIQUE: u32 = 0b0010;
pub(super) const HOOK_FLAG_MULTI: u32 = 0b0100;
const HOOK_FLAG_RECORD: u32 = 0b1000;
const HOOK_FLAG_MODE_MASK: u32 = 0b0111;
const HOOK_FLAG_KNOWN_MASK: u32 =
    HOOK_FLAG_SHARED | HOOK_FLAG_UNIQUE | HOOK_FLAG_MULTI | HOOK_FLAG_RECORD;

pub fn check_hook_flags(flags: u32) -> Result<(), Errno> {
    if flags & !HOOK_FLAG_KNOWN_MASK != 0 {
        return Err(Errno::InvalidArg);
    }
    let mode = flags & HOOK_FLAG_MODE_MASK;
    // mode 位必须恰为 0 / 1 / 2 / 4 之一
    if mode != 0 && mode != HOOK_FLAG_SHARED && mode != HOOK_FLAG_UNIQUE && mode != HOOK_FLAG_MULTI
    {
        return Err(Errno::InvalidArg);
    }
    Ok(())
}

// flags 位 → SwitchMode；DEFAULT 与 UNIQUE 均返 Unique，MULTI 返 Multi，SHARED 返 Shared
pub(crate) fn flags_to_mode(flags: u32) -> SwitchMode {
    let mode = flags & HOOK_FLAG_MODE_MASK;
    if mode == HOOK_FLAG_MULTI {
        SwitchMode::Multi
    } else if mode == HOOK_FLAG_SHARED {
        SwitchMode::Shared
    } else {
        SwitchMode::Unique
    }
}

// capi 层 dispatch 用：仅判 MULTI 位，不关心其他合法位
pub(crate) fn is_multi_mode(flags: u32) -> bool {
    flags & HOOK_FLAG_MODE_MASK == HOOK_FLAG_MULTI
}

pub(crate) fn ensure_multi_orig_addr(
    mode: SwitchMode,
    orig_addr: *mut *const c_void,
) -> Result<(), Errno> {
    if mode == SwitchMode::Multi && orig_addr.is_null() {
        return Err(Errno::InvalidArg);
    }
    Ok(())
}

pub fn check_intercept_flags(flags: u32) -> Result<(), Errno> {
    if flags & !intercept::INTERCEPT_FLAG_KNOWN_MASK != 0 {
        return Err(Errno::InvalidArg);
    }
    Ok(())
}

// 带 flags 版；非法位 → InvalidArg；DEFAULT / UNIQUE / SHARED / MULTI 走对应安装路径
