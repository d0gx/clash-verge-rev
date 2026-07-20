use super::{CoreManager, RunningMode};
use crate::config::{Config, IVerge};
use crate::core::handle::Handle;
use crate::core::manager::CLASH_LOGGER;
#[cfg(not(target_os = "windows"))]
use crate::core::service::{SERVICE_MANAGER, ServiceStatus};
use anyhow::{Context as _, Result};
use clash_verge_logging::{Type, logging};
use scopeguard::defer;
use smartstring::alias::String;
use tauri_plugin_clash_verge_sysinfo;
#[cfg(target_os = "windows")]
use tauri_plugin_clash_verge_sysinfo::is_current_app_handle_admin;

#[cfg(target_os = "windows")]
struct WindowsTunFallbackSnapshot;

#[cfg(target_os = "windows")]
struct WindowsStartupPreparation {
    sidecar_owner: Option<clash_verge_service_ipc::CoreOwnerGuard>,
    tun_fallback: Option<WindowsTunFallbackSnapshot>,
}

#[cfg(any(target_os = "windows", test))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TunFallbackResolution {
    KeepSessionRuntime,
    RollBack,
}

#[cfg(any(target_os = "windows", test))]
const fn resolve_tun_fallback(sidecar_started: bool) -> TunFallbackResolution {
    if sidecar_started {
        TunFallbackResolution::KeepSessionRuntime
    } else {
        TunFallbackResolution::RollBack
    }
}

#[cfg(any(target_os = "windows", test))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HandoffRuntimeResolution {
    ApplyUserIntent,
    RestoreSessionRuntime,
}

#[cfg(any(target_os = "windows", test))]
const fn resolve_handoff_runtime(service_controls_core: bool) -> HandoffRuntimeResolution {
    if service_controls_core {
        HandoffRuntimeResolution::ApplyUserIntent
    } else {
        HandoffRuntimeResolution::RestoreSessionRuntime
    }
}

#[cfg(any(target_os = "windows", test))]
const fn should_rearm_handoff_watcher(
    observed_generation: u64,
    requested_generation: u64,
    sidecar_running: bool,
) -> bool {
    sidecar_running && requested_generation != observed_generation
}

#[cfg(any(target_os = "windows", test))]
const fn should_wait_for_service_ownership(service_ready: bool) -> bool {
    !service_ready
}

#[cfg(any(target_os = "windows", test))]
const fn service_controls_startup(live_compatible_service: bool, service_core_owner_confirmed: bool) -> bool {
    live_compatible_service || service_core_owner_confirmed
}

#[cfg(any(target_os = "windows", test))]
const fn should_disable_tun_for_sidecar(tun_enabled: bool, service_owns_startup: bool, is_admin: bool) -> bool {
    tun_enabled && !service_owns_startup && !is_admin
}

#[cfg(any(target_os = "windows", test))]
const fn requires_extended_service_wait(
    tun_enabled: bool,
    is_admin: bool,
    ipc_present: bool,
    service_process_present: bool,
) -> bool {
    (tun_enabled && !is_admin) || ipc_present || service_process_present
}

#[cfg(any(target_os = "windows", test))]
const fn sidecar_fallback_is_safe(
    service_ipc_present: bool,
    incompatible_upgrade_pending: bool,
    mihomo_controller_present: bool,
    scm_allows_sidecar: bool,
) -> bool {
    !service_ipc_present && !incompatible_upgrade_pending && !mihomo_controller_present && scm_allows_sidecar
}

/// sidecar→service 交接结果
#[cfg(target_os = "windows")]
enum HandoffOutcome {
    /// 服务尚未就绪
    NotReady,
    /// 已完成或无需交接
    Done,
    /// 交接失败并已回退
    Failed,
}

impl CoreManager {
    pub async fn start_core(&self) -> Result<()> {
        let _config = self.begin_config_transaction().await;
        self.start_core_in_transaction().await
    }

    pub(crate) async fn start_core_in_transaction(&self) -> Result<()> {
        let _life = self.lifecycle_lock.lock().await;
        self.start_core_inner().await
    }

    /// 调用者须已持有 `lifecycle_lock`。
    async fn start_core_inner(&self) -> Result<()> {
        // 退出中不再启动新内核。
        if Handle::global().is_exiting() {
            return Ok(());
        }

        // 已有内核运行时保持幂等,重启请走 restart_core。
        if !matches!(*self.get_running_mode(), RunningMode::NotRunning) {
            logging!(
                info,
                Type::Core,
                "start_core called while a core is running; treated as no-op"
            );
            return Ok(());
        }

        #[cfg(target_os = "windows")]
        let mut startup = self.prepare_startup().await?;
        #[cfg(not(target_os = "windows"))]
        self.prepare_startup().await?;
        defer! {
            self.after_core_process();
        }

        // 等待服务期间可能进入退出;未真正启动时回滚状态。
        if Handle::global().is_exiting() {
            #[cfg(target_os = "windows")]
            if let Some(snapshot) = startup.tun_fallback.take() {
                let rollback_errors = Self::rollback_windows_tun_fallback(snapshot).await;
                if !rollback_errors.is_empty() {
                    self.set_running_mode(RunningMode::NotRunning);
                    return Err(anyhow::anyhow!(
                        "application began exiting during sidecar preparation; rollback errors: {}",
                        rollback_errors.join("; ")
                    ));
                }
            }
            self.set_running_mode(RunningMode::NotRunning);
            return Ok(());
        }

        #[cfg(target_os = "windows")]
        let attempted_service_start = matches!(*self.get_running_mode(), RunningMode::Service);
        let result = match *self.get_running_mode() {
            RunningMode::Service => {
                // A previous session-only sidecar fallback may have committed
                // an execution runtime with TUN=false while Verge still holds
                // the user's TUN=true intent. Every fresh service start must
                // regenerate from that durable intent before writing/syncing.
                #[cfg(target_os = "windows")]
                {
                    match Config::generate().await {
                        Ok(()) => self.start_core_by_service().await,
                        Err(error) => Err(error.context("failed to regenerate user intent before service startup")),
                    }
                }
                #[cfg(not(target_os = "windows"))]
                self.start_core_by_service().await
            }
            RunningMode::NotRunning | RunningMode::Sidecar => {
                #[cfg(target_os = "windows")]
                {
                    match startup.sidecar_owner.take() {
                        Some(owner_guard) => self.start_core_by_sidecar_with_owner(owner_guard).await,
                        None => Err(anyhow::anyhow!(
                            "sidecar startup selected without an acquired core owner"
                        )),
                    }
                }
                #[cfg(not(target_os = "windows"))]
                self.start_core_by_sidecar().await
            }
        };

        #[cfg(target_os = "windows")]
        let result = if let Some(snapshot) = startup.tun_fallback.take() {
            match resolve_tun_fallback(result.is_ok()) {
                TunFallbackResolution::KeepSessionRuntime => self.commit_windows_tun_fallback(snapshot).await,
                TunFallbackResolution::RollBack => match result {
                    Err(error) => {
                        let rollback_errors = Self::rollback_windows_tun_fallback(snapshot).await;
                        if rollback_errors.is_empty() {
                            Err(error)
                        } else {
                            Err(error.context(format!(
                                "failed to roll back the uncommitted TUN sidecar fallback: {}",
                                rollback_errors.join("; ")
                            )))
                        }
                    }
                    Ok(()) => Err(anyhow::anyhow!(
                        "internal TUN fallback state did not match the successful sidecar result"
                    )),
                },
            }
        } else {
            result
        };

        // 启动失败时回滚 mode,允许后续重试。
        if result.is_err() {
            #[cfg(target_os = "windows")]
            {
                // Lease contention alone cannot identify the owner: it can be
                // this process's just-spawned/killing sidecar. Only a service
                // status snapshot may preserve Service mode after failure.
                if attempted_service_start && matches!(crate::core::service::service_core_running().await, Ok(true)) {
                    self.set_running_mode(RunningMode::Service);
                } else {
                    self.set_running_mode(RunningMode::NotRunning);
                }
            }
            #[cfg(not(target_os = "windows"))]
            self.set_running_mode(RunningMode::NotRunning);
            return result;
        }

        // The generated runtime is now the configuration owned by the running
        // process, regardless of whether it was started by service or sidecar.
        Config::runtime().await.apply();

        // 回退 sidecar 后,后台等待服务就绪再交接
        #[cfg(target_os = "windows")]
        if matches!(*self.get_running_mode(), RunningMode::Sidecar) {
            self.spawn_service_handoff_watcher();
        }

        result
    }

    pub async fn stop_core(&self) -> Result<()> {
        let _config = self.begin_config_transaction().await;
        self.stop_core_in_transaction().await
    }

    pub(crate) async fn stop_core_in_transaction(&self) -> Result<()> {
        let _life = self.lifecycle_lock.lock().await;
        self.stop_core_inner().await
    }

    /// 调用者须已持有 `lifecycle_lock`。
    async fn stop_core_inner(&self) -> Result<()> {
        CLASH_LOGGER.clear_logs().await;
        defer! {
            self.after_core_process();
        }

        match *self.get_running_mode() {
            RunningMode::Service => self.stop_core_by_service().await,
            RunningMode::Sidecar => self.stop_core_by_sidecar().await,
            RunningMode::NotRunning => Ok(()),
        }
    }

    pub async fn restart_core(&self) -> Result<()> {
        let _config = self.begin_config_transaction().await;
        self.restart_core_in_transaction().await
    }

    pub(crate) async fn restart_core_in_transaction(&self) -> Result<()> {
        // 持锁覆盖 stop+start,避免生命周期操作插入。
        let _life = self.lifecycle_lock.lock().await;
        logging!(info, Type::Core, "Restarting core");
        self.stop_core_inner().await?;
        self.start_core_inner().await
    }

    pub async fn change_core(&self, clash_core: &String) -> Result<(), String> {
        if !IVerge::VALID_CLASH_CORES.contains(&clash_core.as_str()) {
            return Err(format!("Invalid clash core: {}", clash_core).into());
        }

        let _config = self.begin_config_transaction().await;
        let verge_before = (**Config::verge().await.data_arc()).clone();
        let runtime_before = (**Config::runtime().await.data_arc()).clone();
        Config::verge().await.edit_draft(|d| {
            d.clash_core = Some(clash_core.to_owned());
        });

        let result: Result<()> = async {
            Config::verge().await.latest_arc().save_file().await?;
            self.update_config_checked_in_transaction().await?;
            Ok(())
        }
        .await;

        match result {
            Ok(()) => {
                Config::verge().await.apply();
                Ok(())
            }
            Err(error) => {
                let verge = Config::verge().await;
                verge.edit_draft(|draft| *draft = verge_before.clone());
                verge.apply();
                let mut rollback_errors = Vec::new();
                if let Err(rollback_error) = self.restore_runtime_in_transaction(&runtime_before).await {
                    rollback_errors.push(format!("runtime rollback failed: {rollback_error:#}"));
                }
                if let Err(rollback_error) = verge_before.save_file().await {
                    rollback_errors.push(format!("verge file rollback failed: {rollback_error:#}"));
                }
                if rollback_errors.is_empty() {
                    Err(error.to_string().into())
                } else {
                    Err(format!("{error:#}; rollback errors: {}", rollback_errors.join("; ")).into())
                }
            }
        }
    }

    #[cfg(target_os = "windows")]
    async fn prepare_startup(&self) -> Result<WindowsStartupPreparation> {
        let startup = self.wait_for_initial_service_ownership().await?;
        self.set_running_mode(if startup.sidecar_owner.is_some() {
            RunningMode::Sidecar
        } else {
            RunningMode::Service
        });
        Ok(startup)
    }

    #[cfg(not(target_os = "windows"))]
    async fn prepare_startup(&self) -> Result<()> {
        // Unix has no Windows core-owner Event. Preserve the operation barrier
        // so an in-flight install/reinstall cannot race a sidecar with a
        // service that restores its own core a moment later.
        let service_ready = matches!(SERVICE_MANAGER.current().await, ServiceStatus::Ready);
        self.set_running_mode(if service_ready {
            RunningMode::Service
        } else {
            RunningMode::Sidecar
        });
        Ok(())
    }

    fn after_core_process(&self) {
        let app_handle = Handle::app_handle();
        tauri_plugin_clash_verge_sysinfo::set_app_core_mode(app_handle, self.get_running_mode().to_string());
    }

    #[cfg(target_os = "windows")]
    async fn acquire_startup_core_owner() -> Result<Option<clash_verge_service_ipc::CoreOwnerGuard>> {
        use crate::{constants::timing, core::service};
        use tokio::time::Instant;

        if let Some(owner_guard) =
            clash_verge_service_ipc::try_acquire_core_owner().context("failed to acquire the core startup lease")?
        {
            return Ok(Some(owner_guard));
        }

        let contention_deadline = Instant::now() + timing::SERVICE_WAIT_MAX;
        loop {
            let live_service_status = service::query_compatible_service_status().await;
            let (live_compatible_service, service_core_owner_confirmed) = match live_service_status {
                Ok(status) => (true, status.core_pid.is_some() || status.core_owner_held),
                Err(error) => {
                    if service::is_service_ipc_path_exists() {
                        logging!(
                            debug,
                            Type::Core,
                            "contended core owner did not expose a live compatible service endpoint: {error:#}"
                        );
                    }
                    (false, false)
                }
            };
            if service_controls_startup(live_compatible_service, service_core_owner_confirmed) {
                return Ok(None);
            }
            if !sidecar_fallback_is_safe(
                service::is_service_ipc_path_exists(),
                service::incompatible_service_upgrade_pending(),
                service::is_mihomo_controller_present(),
                matches!(service::windows_scm_allows_sidecar(), Ok(true)),
            ) {
                return Err(anyhow::anyhow!(
                    "refusing sidecar startup while a legacy/unverified service or unmanaged Mihomo core may still be active"
                ));
            }

            match clash_verge_service_ipc::try_acquire_core_owner()
                .context("failed to recheck the contended core startup lease")?
            {
                Some(owner_guard) => return Ok(Some(owner_guard)),
                None if Instant::now() < contention_deadline => {
                    tokio::time::sleep(timing::SERVICE_WAIT_INTERVAL).await;
                }
                None => {
                    return Err(anyhow::anyhow!(
                        "another process retained core ownership but no service control endpoint was confirmed"
                    ));
                }
            }
        }
    }

    #[cfg(target_os = "windows")]
    async fn wait_for_initial_service_ownership(&self) -> Result<WindowsStartupPreparation> {
        use crate::{config::Config, constants::timing, core::service};
        use tokio::time::Instant;

        // No core is running while this preparation executes. Clear a stale
        // execution overlay from an earlier failed start before deciding who
        // owns the next runtime.
        self.set_windows_sidecar_tun_fallback_active(false);
        let tun_enabled = Config::verge().await.latest_arc().enable_tun_mode.unwrap_or(false);
        let is_admin = is_current_app_handle_admin(Handle::app_handle());

        // Maintenance owns connection/reinstall/UAC for the whole process and
        // is idempotently scheduled. Startup only polls snapshots, so dropping
        // this bounded handshake can neither cancel nor repeat a UAC prompt.
        service::schedule_startup_service_maintenance();
        let started = Instant::now();
        let full_deadline = started + timing::SERVICE_WAIT_MAX;
        let mut deadline = if requires_extended_service_wait(
            tun_enabled,
            is_admin,
            service::is_service_ipc_path_exists(),
            service::is_service_owner_present() || !matches!(service::windows_scm_allows_sidecar(), Ok(true)),
        ) {
            full_deadline
        } else {
            started + timing::SERVICE_OWNERSHIP_PROBE_MAX
        };
        // A cached Ready value is only UI state. The service can crash or be
        // replaced later in the same GUI process, so every startup handshake
        // is driven by a fresh exact-version VERSION + Status probe.
        let mut live_service_probe = service::query_compatible_service_status().await;
        while should_wait_for_service_ownership(live_service_probe.is_ok()) && Instant::now() < deadline {
            // The owner lock is acquired before reconcile/restore and before
            // the IPC endpoint is created. If it appears during the short
            // probe, extend the same handshake rather than racing a restored
            // service core with a new sidecar.
            if deadline != full_deadline
                && (service::is_service_owner_present()
                    || service::is_service_ipc_path_exists()
                    || !matches!(service::windows_scm_allows_sidecar(), Ok(true)))
            {
                deadline = full_deadline;
            }

            let next_probe = Instant::now() + timing::SERVICE_WAIT_INTERVAL;
            tokio::time::sleep_until(std::cmp::min(next_probe, deadline)).await;
            live_service_probe = service::query_compatible_service_status().await;
        }

        // Close a readiness transition at the wait boundary. This remains a
        // live probe even when the loop was skipped because a previous probe
        // succeeded.
        if live_service_probe.is_err() {
            live_service_probe = service::query_compatible_service_status().await;
        }
        let live_compatible_service = live_service_probe.is_ok();
        // The service process/PID owner is only a reason to wait longer. It is
        // not the core lease and cannot select Service mode by itself.
        if service_controls_startup(live_compatible_service, false) {
            return Ok(WindowsStartupPreparation {
                sidecar_owner: None,
                tun_fallback: None,
            });
        }
        if !sidecar_fallback_is_safe(
            service::is_service_ipc_path_exists(),
            service::incompatible_service_upgrade_pending(),
            service::is_mihomo_controller_present(),
            matches!(service::windows_scm_allows_sidecar(), Ok(true)),
        ) {
            return Err(live_service_probe
                .err()
                .unwrap_or_else(|| anyhow::anyhow!("service endpoint was not compatible"))
                .context(
                    "refusing sidecar startup while a legacy/unverified service or unmanaged Mihomo core may still be active",
                ));
        }

        // This acquisition closes the observation-to-spawn race. Once the GUI
        // wins the cross-process lease, a late SCM restore cannot start a
        // second core; if another process wins, never attempt a sidecar.
        let Some(owner_guard) = Self::acquire_startup_core_owner().await? else {
            return Ok(WindowsStartupPreparation {
                sidecar_owner: None,
                tun_fallback: None,
            });
        };

        // Close the final wait-to-acquire race. The service can finish opening
        // its control endpoint immediately after our last snapshot but before
        // the GUI wins the still-free core lease. Prefer that now-ready service
        // and drop the guard before it attempts StartClash.
        match service::query_compatible_service_status().await {
            Ok(_) => {
                drop(owner_guard);
                return Ok(WindowsStartupPreparation {
                    sidecar_owner: None,
                    tun_fallback: None,
                });
            }
            Err(error)
                if !sidecar_fallback_is_safe(
                    service::is_service_ipc_path_exists(),
                    service::incompatible_service_upgrade_pending(),
                    service::is_mihomo_controller_present(),
                    matches!(service::windows_scm_allows_sidecar(), Ok(true)),
                ) =>
            {
                drop(owner_guard);
                return Err(error
                    .context("service/core state changed after lease acquisition; refusing unsafe sidecar startup"));
            }
            Err(_) => {}
        }

        let tun_enabled = Config::verge().await.latest_arc().enable_tun_mode.unwrap_or(false);
        let is_admin = is_current_app_handle_admin(Handle::app_handle());
        let tun_fallback = if should_disable_tun_for_sidecar(tun_enabled, false, is_admin) {
            // A non-elevated sidecar cannot create the TUN adapter. Preserve
            // the slow-service startup window, but once it expires enable a
            // session execution overlay. Config generation keeps the user's
            // TUN intent; only the Run file consumed by this sidecar receives
            // `tun.enable=false`.
            logging!(
                warn,
                Type::Core,
                "service did not become ready in time; disabling TUN before sidecar fallback"
            );
            self.set_windows_sidecar_tun_fallback_active(true);
            Some(WindowsTunFallbackSnapshot)
        } else {
            None
        };
        Ok(WindowsStartupPreparation {
            sidecar_owner: Some(owner_guard),
            tun_fallback,
        })
    }

    #[cfg(target_os = "windows")]
    async fn commit_windows_tun_fallback(&self, _snapshot: WindowsTunFallbackSnapshot) -> Result<()> {
        // Keep the overlay armed for every subsequent Run-file generation in
        // this sidecar session. The in-memory runtime already contains and may
        // safely commit the user's durable TUN intent.
        if !self.windows_sidecar_tun_fallback_active() || !self.windows_sidecar_session_is_live() {
            self.set_windows_sidecar_tun_fallback_active(false);
            Config::generate_file(crate::config::ConfigType::Run)
                .await
                .context("failed to restore the durable Run file after an early sidecar exit")?;
            return Err(anyhow::anyhow!(
                "sidecar exited before the session-only TUN fallback could be committed"
            ));
        }
        Ok(())
    }

    #[cfg(target_os = "windows")]
    async fn rollback_windows_tun_fallback(_snapshot: WindowsTunFallbackSnapshot) -> Vec<std::string::String> {
        use crate::config::ConfigType;

        let mut rollback_errors = Vec::new();
        Self::global().set_windows_sidecar_tun_fallback_active(false);

        if let Err(error) = Config::generate_file(ConfigType::Run).await {
            rollback_errors.push(format!("runtime file rollback failed: {error:#}"));
        }
        rollback_errors
    }

    /// 在窗口内等待服务就绪,再从 sidecar 交接到 service
    #[cfg(target_os = "windows")]
    fn spawn_service_handoff_watcher(&self) {
        use crate::constants::timing;
        use crate::process::AsyncHandler;
        use std::sync::atomic::Ordering;
        use std::time::Instant;

        // 单实例,避免并发交接
        let watcher_generation = self
            .handoff_watcher_generation
            .fetch_add(1, Ordering::AcqRel)
            .wrapping_add(1);
        if self.handoff_watcher_running.swap(true, Ordering::AcqRel) {
            return;
        }

        logging!(
            info,
            Type::Core,
            "service not ready at startup; sidecar active, watching for handoff"
        );

        AsyncHandler::spawn(move || async move {
            let manager = Self::global();
            let started = Instant::now();
            loop {
                if started.elapsed() >= timing::SERVICE_HANDOFF_WINDOW {
                    logging!(
                        info,
                        Type::Core,
                        "service handoff window elapsed; staying in sidecar mode"
                    );
                    break;
                }
                tokio::time::sleep(timing::SERVICE_HANDOFF_INTERVAL).await;

                // 模式已变更时退出
                if !matches!(*manager.get_running_mode(), RunningMode::Sidecar) {
                    break;
                }
                match manager.try_handoff_sidecar_to_service().await {
                    // 已交接或无需交接
                    HandoffOutcome::Done => break,
                    // 已回退 sidecar,停止重试
                    HandoffOutcome::Failed => {
                        logging!(
                            warn,
                            Type::Core,
                            "handoff attempt failed; automatic handoff retry stopped"
                        );
                        break;
                    }
                    HandoffOutcome::NotReady => {}
                }
            }
            manager.handoff_watcher_running.store(false, Ordering::Release);
            let requested_generation = manager.handoff_watcher_generation.load(Ordering::Acquire);
            if should_rearm_handoff_watcher(
                watcher_generation,
                requested_generation,
                matches!(*manager.get_running_mode(), RunningMode::Sidecar),
            ) {
                manager.spawn_service_handoff_watcher();
            }
        });
    }

    /// Resolve an ambiguous service start without risking a second core.
    #[cfg(target_os = "windows")]
    async fn resolve_contended_handoff_owner(&self) {
        use crate::core::service;

        Config::runtime().await.apply();
        match service::service_core_running().await {
            Ok(true) => {
                self.set_running_mode(RunningMode::Service);
                logging!(
                    error,
                    Type::Core,
                    "service confirms a running core after ambiguous handoff; refusing sidecar fallback"
                );
            }
            Ok(false) => {
                self.set_running_mode(RunningMode::NotRunning);
                logging!(
                    error,
                    Type::Core,
                    "an unidentified process temporarily retained core ownership after handoff; no service core was confirmed"
                );
            }
            Err(status_error) => {
                self.set_running_mode(RunningMode::NotRunning);
                logging!(
                    error,
                    Type::Core,
                    "could not identify the contended core owner after handoff; refusing sidecar fallback: {}",
                    status_error
                );
            }
        }
    }

    #[cfg(target_os = "windows")]
    async fn abandon_failed_handoff_sidecar_recovery(&self, message: impl std::fmt::Display) {
        let rollback_errors = Self::rollback_windows_tun_fallback(WindowsTunFallbackSnapshot).await;
        Config::runtime().await.apply();
        self.set_running_mode(RunningMode::NotRunning);
        logging!(error, Type::Core, "{message}");
        if !rollback_errors.is_empty() {
            logging!(
                error,
                Type::Core,
                "failed to restore the durable Run file after sidecar recovery stopped: {}",
                rollback_errors.join("; ")
            );
        }
    }

    #[cfg(target_os = "windows")]
    async fn recover_sidecar_after_failed_handoff(&self, restore_tun_fallback: bool) {
        use crate::core::service;

        // stop_core_by_sidecar clears the overlay only after kernel-confirmed
        // process exit. Start from the durable/service execution view and arm
        // it again only after every fail-closed sidecar check succeeds.
        self.set_windows_sidecar_tun_fallback_active(false);
        match clash_verge_service_ipc::try_acquire_core_owner() {
            Ok(Some(owner_guard)) => {
                let live_probe = service::query_compatible_service_status().await;
                if live_probe.is_ok()
                    || !sidecar_fallback_is_safe(
                        service::is_service_ipc_path_exists(),
                        service::incompatible_service_upgrade_pending(),
                        service::is_mihomo_controller_present(),
                        matches!(service::windows_scm_allows_sidecar(), Ok(true)),
                    )
                {
                    drop(owner_guard);
                    self.abandon_failed_handoff_sidecar_recovery(format!(
                        "service/core state is not safe for sidecar recovery after failed handoff; refusing fallback: {}",
                        live_probe
                            .err()
                            .map(|error| format!("{error:#}"))
                            .unwrap_or_else(|| "a live compatible service endpoint is still present".to_string())
                    ))
                    .await;
                    return;
                }

                debug_assert!(matches!(
                    resolve_handoff_runtime(false),
                    HandoffRuntimeResolution::RestoreSessionRuntime
                ));
                self.set_windows_sidecar_tun_fallback_active(restore_tun_fallback);
                match self.start_core_by_sidecar_with_owner(owner_guard).await {
                    Err(sidecar_error) => {
                        self.abandon_failed_handoff_sidecar_recovery(format!(
                            "failed to restart sidecar after reacquiring core ownership: {sidecar_error}"
                        ))
                        .await;
                    }
                    Ok(()) if !self.windows_sidecar_session_is_live() => {
                        self.abandon_failed_handoff_sidecar_recovery(
                            "sidecar exited before failed-handoff recovery could be committed",
                        )
                        .await;
                    }
                    Ok(()) => {
                        Config::runtime().await.apply();
                    }
                }
            }
            Ok(None) => self.resolve_contended_handoff_owner().await,
            Err(owner_error) => {
                self.abandon_failed_handoff_sidecar_recovery(format!(
                    "could not prove exclusive core ownership after handoff failure; refusing sidecar fallback: {owner_error}"
                ))
                .await;
            }
        }
    }

    /// Stop the sidecar and restart the core through a newly compatible service.
    #[cfg(target_os = "windows")]
    async fn try_handoff_sidecar_to_service(&self) -> HandoffOutcome {
        use crate::core::service;

        // 主动刷新服务状态,避免缓存状态阻止交接
        service::schedule_startup_service_maintenance();
        if service::query_compatible_service_status().await.is_err() {
            return HandoffOutcome::NotReady;
        }

        // 先抢 config 锁;失败则让位给正在进行的更新。
        let Some(_config) = self.try_begin_config_transaction() else {
            return HandoffOutcome::NotReady;
        };

        // 再取 lifecycle 锁;锁序固定为 config→lifecycle。
        let _life = self.lifecycle_lock.lock().await;

        // 持锁后复检运行模式。所有配置都交接 ownership，TUN=false
        // 也不能与服务恢复的 core 并行运行。
        if !matches!(*self.get_running_mode(), RunningMode::Sidecar) {
            return HandoffOutcome::Done;
        }
        if let Err(error) = service::query_compatible_service_status().await {
            logging!(
                debug,
                Type::Core,
                "service endpoint changed before handoff could begin: {error:#}"
            );
            return HandoffOutcome::NotReady;
        }

        let was_tun_fallback_active = self.windows_sidecar_tun_fallback_active();

        // A session-only TUN fallback changes only the sidecar Run file. The
        // in-memory runtime already retains user intent; regenerate it so the
        // service start uses the latest profile and a failed handoff can write
        // the same intent through the previous execution overlay.
        if let Err(error) = Config::generate().await {
            logging!(
                error,
                Type::Core,
                "failed to regenerate persisted user intent before service handoff: {error:#}"
            );
            return HandoffOutcome::Failed;
        }

        logging!(
            info,
            Type::Core,
            "service became ready; handing off from sidecar to service"
        );
        if let Err(error) = self.stop_core_by_sidecar().await {
            logging!(
                error,
                Type::Core,
                "failed to stop sidecar and release core ownership before handoff: {error}"
            );
            return HandoffOutcome::Failed;
        }

        match self.start_core_by_service().await {
            Ok(()) => {
                debug_assert!(matches!(
                    resolve_handoff_runtime(true),
                    HandoffRuntimeResolution::ApplyUserIntent
                ));
                Config::runtime().await.apply();
                logging!(info, Type::Core, "handoff to service mode succeeded");
                HandoffOutcome::Done
            }
            Err(e) => {
                logging!(
                    error,
                    Type::Core,
                    "handoff to service failed: {}; resolving service ownership before any sidecar fallback",
                    e
                );
                self.recover_sidecar_after_failed_handoff(was_tun_fallback_active).await;
                HandoffOutcome::Failed
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        HandoffRuntimeResolution, TunFallbackResolution, requires_extended_service_wait, resolve_handoff_runtime,
        resolve_tun_fallback, service_controls_startup, should_disable_tun_for_sidecar, should_rearm_handoff_watcher,
        should_wait_for_service_ownership, sidecar_fallback_is_safe,
    };

    #[test]
    fn every_unready_windows_start_performs_an_ownership_handshake() {
        assert!(should_wait_for_service_ownership(false));
        assert!(!should_wait_for_service_ownership(true));
    }

    #[test]
    fn only_non_admin_tun_requires_sidecar_fallback_to_disable_tun() {
        assert!(should_disable_tun_for_sidecar(true, false, false));
        assert!(!should_disable_tun_for_sidecar(true, false, true));
        assert!(!should_disable_tun_for_sidecar(true, true, false));
        assert!(!should_disable_tun_for_sidecar(false, false, false));
    }

    #[test]
    fn service_process_presence_or_ipc_only_extends_the_wait() {
        assert!(requires_extended_service_wait(false, true, false, true));
        assert!(requires_extended_service_wait(false, false, true, false));
        assert!(requires_extended_service_wait(true, false, false, false));
        assert!(!requires_extended_service_wait(false, true, false, false));
    }

    #[test]
    fn sidecar_fallback_requires_quiet_scm_ipc_upgrade_and_core_state() {
        assert!(sidecar_fallback_is_safe(false, false, false, true));
        assert!(!sidecar_fallback_is_safe(true, false, false, true));
        assert!(!sidecar_fallback_is_safe(false, true, false, true));
        assert!(!sidecar_fallback_is_safe(false, false, true, true));
        assert!(!sidecar_fallback_is_safe(false, false, false, false));
    }

    #[test]
    fn only_live_compatible_service_or_its_confirmed_core_lease_selects_service() {
        assert!(service_controls_startup(false, true));
        assert!(service_controls_startup(true, false));
        assert!(!service_controls_startup(false, false));
    }

    #[test]
    fn tun_fallback_keeps_only_the_successful_session_runtime() {
        assert_eq!(resolve_tun_fallback(false), TunFallbackResolution::RollBack);
        assert_eq!(resolve_tun_fallback(true), TunFallbackResolution::KeepSessionRuntime);
    }

    #[test]
    fn service_handoff_commits_user_intent_or_restores_session_runtime() {
        assert_eq!(resolve_handoff_runtime(true), HandoffRuntimeResolution::ApplyUserIntent);
        assert_eq!(
            resolve_handoff_runtime(false),
            HandoffRuntimeResolution::RestoreSessionRuntime
        );
    }

    #[test]
    fn handoff_watcher_rearms_only_for_a_missed_sidecar_request() {
        assert!(should_rearm_handoff_watcher(7, 8, true));
        assert!(!should_rearm_handoff_watcher(7, 7, true));
        assert!(!should_rearm_handoff_watcher(7, 8, false));
    }
}
