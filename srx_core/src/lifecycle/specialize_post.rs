// 应用 specialize 后流程：读取挂载结果并安装 PLT Hook
use super::RuntimeFlow;
use crate::hook::InterceptHub;
use crate::platform::fs;
use crate::platform::paths::monotonic_ms;
use crate::platform::{self, anti_detect};
use crate::zygisk::abi;
use libc::c_int;
use std::sync::atomic::{AtomicBool, Ordering};

static PLT_HOOK_INSTALLED: AtomicBool = AtomicBool::new(false);
// 读取伴生进程挂载结果的超时；companion 挂载完成后才写回，故此读取兼作同步屏障
const MOUNT_RESULT_TIMEOUT_SEC: i64 = 3;
const POST_SPECIALIZE_SLOW_MS: i64 = 20;

impl RuntimeFlow {
    pub fn post_app_specialize(&mut self, _args: *const abi::AppSpecializeArgs) {
        let perf_started_ms = monotonic_ms();
        if self.should_install_fuse_fixer {
            crate::hook::install_fuse_fixer_hook();
        }

        if self.should_skip_post_work {
            log_post_perf(self, "skip", 0, 0, 0, perf_started_ms);
            return;
        }

        if !self.should_redirect && !self.should_monitor {
            let anti_started_ms = monotonic_ms();
            // 此分支只在模块常驻（如 fuse_fixer）时到达，搬迁自身消除 .so 路径泄露
            let relocated = anti_detect::relocate_self();
            if relocated > 0 {
                log::info!("self relocated segments n={}", relocated);
            }
            // 无需重定向或监控的应用仍需命名匿名可执行区域
            let named_count = anti_detect::name_anonymous_executable_regions();
            let anti_ms = monotonic_ms().saturating_sub(anti_started_ms);
            if named_count > 0 {
                log::info!("anon regions named n={}", named_count);
            }
            log_post_perf(self, "bypass", 0, 0, anti_ms, perf_started_ms);
            return;
        }

        let mut mount_wait_ms = 0;
        if self.should_redirect && !self.is_system_writer_hook_redirect {
            if platform::is_isolated_uid(self.app_uid) {
                self.is_mount_applied = false;
                log::info!(
                    "isolated uid skip mount wait uid={} pid={}",
                    self.app_uid,
                    self.app_pid
                );
            } else {
                let mount_started_ms = monotonic_ms();
                read_mount_result(
                    self.companion_fd,
                    self.is_mount_request_sent,
                    &mut self.is_mount_applied,
                );
                mount_wait_ms = monotonic_ms().saturating_sub(mount_started_ms);
            }
        } else if self.should_redirect && self.is_system_writer_hook_redirect {
            self.is_mount_applied = false;
            log::info!("writer per-caller hook map (skip mount wait)");
        }
        // 伴生 fd 用完即关，无论是否真的读取了结果
        if self.companion_fd >= 0 {
            unsafe { libc::close(self.companion_fd) };
            self.companion_fd = -1;
        }

        let hook_started_ms = monotonic_ms();
        let is_redirect_via_hook = self.should_redirect && self.is_system_writer_hook_redirect;
        install_plt_hook(
            &self.package_name,
            self.should_monitor,
            is_redirect_via_hook,
        );
        let hook_ms = monotonic_ms().saturating_sub(hook_started_ms);

        let anti_started_ms = monotonic_ms();
        // Hook 安装后先把自身文件背书段搬进匿名内存（消除 .so 路径与孤儿映射指纹），
        // 再命名所有匿名可执行区域，覆盖模块代码和 hook trampoline
        let relocated = anti_detect::relocate_self();
        if relocated > 0 {
            log::info!("self relocated segments n={}", relocated);
        }
        let named_count = anti_detect::name_anonymous_executable_regions();
        let anti_ms = monotonic_ms().saturating_sub(anti_started_ms);
        if named_count > 0 {
            log::info!("anon regions named n={}", named_count);
        }
        log_post_perf(
            self,
            "done",
            mount_wait_ms,
            hook_ms,
            anti_ms,
            perf_started_ms,
        );
    }
}

// 从伴生进程 fd 读取挂载结果（4 字节 i32），兼作挂载完成的同步屏障，带 SO_RCVTIMEO
fn read_mount_result(companion_fd: c_int, is_mount_request_sent: bool, is_mount_applied_out: &mut bool) {
    *is_mount_applied_out = false;

    if !is_mount_request_sent || companion_fd < 0 {
        log::debug!("mount req not sent, skip wait");
        return;
    }

    let tv = libc::timeval {
        tv_sec: MOUNT_RESULT_TIMEOUT_SEC,
        tv_usec: 0,
    };
    unsafe {
        libc::setsockopt(
            companion_fd,
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            &tv as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::timeval>() as libc::socklen_t,
        );
    }

    let mut buf = [0u8; 4];
    if fs::read_all(companion_fd, &mut buf) {
        let status = i32::from_ne_bytes(buf);
        *is_mount_applied_out = status == 1;
        log::info!("mount result status={} applied={}", status, *is_mount_applied_out);
    } else {
        log::debug!("mount result not delivered fd={} (mount applied async)", companion_fd);
    }
}

fn log_post_perf(
    flow: &RuntimeFlow,
    exit_reason: &str,
    mount_wait_ms: i64,
    hook_ms: i64,
    anti_ms: i64,
    started_ms: i64,
) {
    let total_ms = monotonic_ms().saturating_sub(started_ms);
    if total_ms < POST_SPECIALIZE_SLOW_MS && !flow.should_redirect && !flow.should_monitor {
        return;
    }
    log::info!(
        "perf post pkg={} pid={} exit={} redirect={} monitor={} hook_redirect={} mount_sent={} mount_applied={} mount_wait_ms={} hook_ms={} anti_ms={} total_ms={}",
        flow.package_name,
        flow.app_pid,
        exit_reason,
        flow.should_redirect,
        flow.should_monitor,
        flow.is_system_writer_hook_redirect,
        flow.is_mount_request_sent,
        flow.is_mount_applied,
        mount_wait_ms,
        hook_ms,
        anti_ms,
        total_ms
    );
}

fn install_plt_hook(package_name: &str, should_monitor: bool, is_redirect_via_hook: bool) {
    let is_monitor_only = !is_redirect_via_hook;
    let should_install = should_monitor || is_redirect_via_hook;
    if !should_install {
        log::info!("plt hook skip");
        return;
    }

    if PLT_HOOK_INSTALLED.swap(true, Ordering::AcqRel) {
        log::info!("plt hook already installed");
        return;
    }

    log::info!(
        "plt hook install redirect={} monitor={}",
        !is_monitor_only,
        should_monitor
    );

    let hub = InterceptHub::instance();
    hub.init(package_name, is_monitor_only, should_monitor);
    if hub.install() {
        log::info!("plt hook ok");
    } else {
        PLT_HOOK_INSTALLED.store(false, Ordering::Release);
        log::warn!("plt hook failed");
    }
}
