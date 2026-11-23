// hook 任务与 caller 模块的匹配逻辑

use super::super::rules::module_match;
use super::super::state::{CoreState, ModuleInfo, Task, TaskType};
use super::module_registry::module_key;

pub(super) fn is_task_match_caller(task: &Task, caller: &ModuleInfo) -> bool {
    match task.task_type {
        TaskType::Single => task
            .caller_path_name
            .as_deref()
            .map(|name| {
                module_match(
                    &caller.pathname,
                    caller.base_addr,
                    caller.instance_id,
                    caller.namespace_id,
                    name,
                )
            })
            .unwrap_or(false),
        TaskType::All => true,
    }
}

// Single 任务已绑定到特定模块时，跳过其他模块避免重复 hook
pub(super) fn is_single_task_bound_to_other_module(
    state: &CoreState,
    task: &Task,
    caller: &ModuleInfo,
) -> bool {
    if task.task_type != TaskType::Single {
        return false;
    }
    let Some(target_key) = state.single_task_targets.get(&task.stub) else {
        return false;
    };
    *target_key != module_key(caller)
}
