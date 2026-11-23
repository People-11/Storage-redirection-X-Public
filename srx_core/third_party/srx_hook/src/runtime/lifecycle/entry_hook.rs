// hook 操作入口，提供 hook_all、add_ignore 与 refresh 的实现
use super::task_ops;
use crate::api;
use crate::api::{HookMode, HookStub, RefreshError};
use crate::errno::Errno;
use std::ffi::c_void;

use super::super::refresh::{self};
use super::super::state::{GLOBAL, Task, TaskType};
use super::{monitor, transaction};
use crate::runtime::fork;

pub(super) fn hook_all_checked(
    sym_name: &str,
    new_func: *mut c_void,
) -> Result<HookStub, api::HookError> {
    fork::check_management()?;
    if sym_name.is_empty() || new_func.is_null() {
        return Err(Errno::InvalidArg.into());
    }
    let task = Task {
        stub: 0,
        task_type: TaskType::All,
        caller_path_name: None,
        sym_name: sym_name.to_string(),
        new_func: new_func as usize,
    };
    task_ops::add_task_checked(task)
}

pub(super) fn add_ignore(caller_path_name: &str) -> Errno {
    if caller_path_name.is_empty() {
        return Errno::InvalidArg;
    }

    if let Err(error) = fork::check_management() {
        return error;
    }
    GLOBAL.update(|state| {
        if state.clearing {
            return Errno::Busy;
        }
        if !state
            .ignore_callers
            .iter()
            .any(|value| value == caller_path_name)
        {
            state.ignore_callers.push(caller_path_name.to_string());
        }
        Errno::Ok
    })
}

pub(super) fn refresh() -> (Errno, Vec<RefreshError>) {
    if let Err(error) = fork::check_management() {
        return (error, Vec::new());
    }
    let runtime = &*GLOBAL;
    let result = transaction::run(runtime, false, |state| {
        refresh::prepare_refresh(state, false, None)
    });
    if result.status == Errno::Ok && runtime.snapshot().init.mode == HookMode::Automatic {
        monitor::start_monitor_thread();
    }
    (result.status, result.errors)
}

pub(super) fn refresh_if_needed() -> (Errno, Vec<RefreshError>) {
    if let Err(error) = fork::check_management() {
        return (error, Vec::new());
    }
    match refresh::is_current_refresh_covered(&GLOBAL) {
        Ok(true) => (Errno::Ok, Vec::new()),
        Ok(false) => refresh(),
        Err(error) => (error, Vec::new()),
    }
}
