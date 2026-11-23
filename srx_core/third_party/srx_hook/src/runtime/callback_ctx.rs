// 外部回调上下文追踪，通过线程局部深度计数器判断当前是否处于用户回调中
use std::cell::Cell;

thread_local! {
    #[allow(clippy::missing_const_for_thread_local)]
    static EXTERNAL_CALLBACK_DEPTH: Cell<u32> = Cell::new(0);
}

pub(super) fn is_in_external_callback() -> bool {
    EXTERNAL_CALLBACK_DEPTH.with(|depth| depth.get() > 0)
}

// 在 RAII guard 保护下执行外部回调，确保 panic 时深度也能正确回退
pub(super) fn run_in_external_callback<R, F>(f: F) -> R
where
    F: FnOnce() -> R,
{
    struct CallbackGuard;

    impl Drop for CallbackGuard {
        fn drop(&mut self) {
            EXTERNAL_CALLBACK_DEPTH.with(|depth| {
                let current = depth.get();
                if current == 0 {
                    return;
                }
                depth.set(current - 1);
            });
        }
    }

    EXTERNAL_CALLBACK_DEPTH.with(|depth| {
        let current = depth.get();
        depth.set(current.saturating_add(1));
    });
    let _guard = CallbackGuard;
    f()
}
