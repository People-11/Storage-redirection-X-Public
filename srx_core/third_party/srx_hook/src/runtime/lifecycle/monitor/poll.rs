// monitor 线程轮询循环，结合事件驱动与周期性轮询两种刷新策略
use std::sync::atomic::Ordering;
use std::thread;
use std::time::{Duration, Instant};

use super::{
    MONITOR_FALLBACK_BURST_ROUNDS, MONITOR_FALLBACK_REFRESH_INTERVAL_MAX,
    MONITOR_FALLBACK_REFRESH_INTERVAL_MIN, flags, install_auto_loader_monitor_hooks,
    maybe_install_legacy_hooks_on_demand,
};
use crate::errno::Errno;
use crate::log;
use crate::runtime::fork;
use crate::runtime::lifecycle::entry_hook::refresh_if_needed;
use crate::runtime::refresh;
use crate::runtime::state::{MutexPoisonRecover, ProcessRuntime};

// 周期性轮询状态，管理退避间隔和 burst 轮次
struct FallbackPollState {
    interval: Duration,
    // burst 阶段保持最小间隔，耗尽后开始指数退避
    burst_rounds: u8,
    last_module_epoch: Option<(u64, u64)>,
}

// 模块 epoch 变化分类，用于决定刷新策略
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum EpochDelta {
    Unchanged,
    AddedOnly,
    Changed,
    Unknown,
}

impl FallbackPollState {
    fn new() -> Self {
        Self {
            interval: MONITOR_FALLBACK_REFRESH_INTERVAL_MIN,
            burst_rounds: MONITOR_FALLBACK_BURST_ROUNDS,
            last_module_epoch: refresh::module_epoch(),
        }
    }

    fn timeout(&self) -> Duration {
        self.interval
    }

    fn on_event_refresh(&mut self) {
        self.interval = MONITOR_FALLBACK_REFRESH_INTERVAL_MIN;
        self.burst_rounds = MONITOR_FALLBACK_BURST_ROUNDS;
        self.last_module_epoch = refresh::module_epoch();
    }

    fn on_periodic_refresh(&mut self, module_changed: bool) {
        if module_changed {
            self.on_event_refresh();
            return;
        }

        if self.burst_rounds > 0 {
            self.burst_rounds -= 1;
            return;
        }

        let doubled_ms = self
            .interval
            .as_millis()
            .saturating_mul(2)
            .min(MONITOR_FALLBACK_REFRESH_INTERVAL_MAX.as_millis());
        let doubled_ms = doubled_ms as u64;
        self.interval = Duration::from_millis(doubled_ms);
    }

    fn reset_for_event_mode(&mut self) {
        self.interval = MONITOR_FALLBACK_REFRESH_INTERVAL_MIN;
        self.burst_rounds = MONITOR_FALLBACK_BURST_ROUNDS;
    }

    fn poll_epoch_delta(&mut self) -> EpochDelta {
        let Some(epoch) = refresh::module_epoch() else {
            self.last_module_epoch = None;
            return EpochDelta::Unknown;
        };
        let delta = classify_epoch_delta(self.last_module_epoch, epoch);
        self.last_module_epoch = Some(epoch);
        delta
    }
}

fn classify_epoch_delta(last: Option<(u64, u64)>, current: (u64, u64)) -> EpochDelta {
    let Some((last_adds, last_subs)) = last else {
        return EpochDelta::Changed;
    };
    let (current_adds, current_subs) = current;
    if current_adds == last_adds && current_subs == last_subs {
        return EpochDelta::Unchanged;
    }
    if current_subs == last_subs && current_adds > last_adds {
        return EpochDelta::AddedOnly;
    }
    EpochDelta::Changed
}

fn is_live(runtime: &ProcessRuntime, epoch: usize) -> bool {
    runtime.is_current()
        && runtime.monitor_running.load(Ordering::Acquire)
        && flags().epoch.load(Ordering::Acquire) == epoch
}

fn is_owner(runtime: &ProcessRuntime, epoch: usize) -> bool {
    is_live(runtime, epoch)
        && runtime
            .monitor_thread
            .lock_or_poison()
            .as_ref()
            .is_some_and(|handle| handle.thread().id() == thread::current().id())
}

pub(super) fn monitor_loop(runtime: &'static ProcessRuntime, epoch: usize) {
    let event_interval = Duration::from_millis(50);
    // spawn 在锁外执行，等待创建方发布线程句柄后再处理任务。
    while is_live(runtime, epoch) {
        if is_owner(runtime, epoch) {
            break;
        }
        thread::park_timeout(event_interval);
    }
    while is_owner(runtime, epoch) {
        match fork::check_management() {
            Ok(()) => break,
            Err(Errno::Busy) => thread::park_timeout(event_interval),
            Err(_) => return,
        }
    }
    if !is_owner(runtime, epoch) {
        return;
    }
    let mut fallback_poll = FallbackPollState::new();
    let mut last_refresh = Instant::now();
    while is_owner(runtime, epoch) {
        if fork::check_management() == Err(Errno::Busy) {
            thread::park_timeout(event_interval);
            continue;
        }
        install_auto_loader_monitor_hooks();
        maybe_install_legacy_hooks_on_demand();
        if !is_owner(runtime, epoch) {
            break;
        }
        let event_refresh = runtime.refresh_requested.swap(false, Ordering::AcqRel);
        let periodic_enabled = flags().periodic_enabled.load(Ordering::Acquire);
        if !periodic_enabled {
            fallback_poll.reset_for_event_mode();
        }
        let periodic_refresh =
            periodic_enabled && last_refresh.elapsed() >= fallback_poll.timeout();
        if !event_refresh && !periodic_refresh {
            thread::park_timeout(event_interval);
            continue;
        }
        let mut module_changed = false;
        if periodic_refresh && !event_refresh {
            match fallback_poll.poll_epoch_delta() {
                EpochDelta::Unchanged => {}
                EpochDelta::AddedOnly | EpochDelta::Changed => module_changed = true,
                EpochDelta::Unknown => {}
            }
        }
        let (status, _) = refresh_if_needed();
        if !is_owner(runtime, epoch) {
            break;
        }
        if status == Errno::Busy {
            runtime.refresh_requested.store(true, Ordering::Release);
            thread::park_timeout(event_interval);
            continue;
        }
        if matches!(status, Errno::Uninit | Errno::ForkContextUnavailable) {
            break;
        }
        if status != Errno::Ok {
            log::warn(format_args!("auto refresh status {status:?}"));
        }
        last_refresh = Instant::now();
        if event_refresh {
            fallback_poll.on_event_refresh();
        } else {
            fallback_poll.on_periodic_refresh(module_changed);
        }
    }
}
