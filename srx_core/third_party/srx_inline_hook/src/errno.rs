// 错误码：数值沿用原 C 接口的编号，便于对照历史日志
// RewriteUnsupported / HookOverlap / InitSigill 为扩展码

use core::fmt;
use std::error::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum Errno {
    Ok = 0,
    Uninit = 2,
    InvalidArg = 3,
    Oom = 4,
    Mprot = 5,
    WriteCrash = 6,
    InitSigsegv = 8,
    InitSigbus = 9,
    InitSafe = 11,
    HookUniqueDup = 16,
    DlSymFailed = 18,
    DlInfoFailed = 22,
    HookRewriteCrash = 25,
    HookRewriteFailed = 26,
    UnhookNotFound = 27,
    UnhookCmpCrash = 28,
    UnhookTrampoMismatch = 29,
    UnhookExitCrash = 31,
    NotSupport = 38,
    RewriteUnsupported = 100,
    HookOverlap = 101,
    InitSigill = 102,
}

impl Errno {
    pub fn message(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Uninit => "not initialized",
            Self::InvalidArg => "invalid argument",
            Self::Oom => "out of memory",
            Self::Mprot => "mprotect failed",
            Self::WriteCrash => "crashed while writing patch",
            Self::InitSigsegv => "failed to install sigsegv handler",
            Self::InitSigbus => "failed to install sigbus handler",
            Self::InitSafe => "init safe mod failed",
            Self::HookUniqueDup => "target already hooked",
            Self::DlSymFailed => "find symbol in ELF failed",
            Self::DlInfoFailed => "find dlinfo failed",
            Self::HookRewriteCrash => "crashed while rewriting instructions",
            Self::HookRewriteFailed => "failed to rewrite instructions",
            Self::UnhookNotFound => "no hook found at address",
            Self::UnhookCmpCrash => "crashed while comparing patched bytes on unhook",
            Self::UnhookTrampoMismatch => "trampoline mismatch while unhooking",
            Self::UnhookExitCrash => "crashed while restoring instructions on unhook",
            Self::NotSupport => "not supported",
            Self::RewriteUnsupported => "instruction not supported by rewriter",
            Self::HookOverlap => "patch range overlaps an existing hook",
            Self::InitSigill => "failed to install sigill handler",
        }
    }

    // 从 i32 恢复；未识别归 NotSupport
    pub fn from_i32(v: i32) -> Self {
        match v {
            0 => Self::Ok,
            2 => Self::Uninit,
            3 => Self::InvalidArg,
            4 => Self::Oom,
            5 => Self::Mprot,
            6 => Self::WriteCrash,
            8 => Self::InitSigsegv,
            9 => Self::InitSigbus,
            11 => Self::InitSafe,
            16 => Self::HookUniqueDup,
            18 => Self::DlSymFailed,
            22 => Self::DlInfoFailed,
            25 => Self::HookRewriteCrash,
            26 => Self::HookRewriteFailed,
            27 => Self::UnhookNotFound,
            28 => Self::UnhookCmpCrash,
            29 => Self::UnhookTrampoMismatch,
            31 => Self::UnhookExitCrash,
            38 => Self::NotSupport,
            100 => Self::RewriteUnsupported,
            101 => Self::HookOverlap,
            102 => Self::InitSigill,
            _ => Self::NotSupport,
        }
    }
}

impl fmt::Display for Errno {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} (errno={})", self.message(), *self as i32)
    }
}

impl Error for Errno {}
