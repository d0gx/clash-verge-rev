mod config;
mod lifecycle;
mod state;

use anyhow::Result;
use arc_swap::{ArcSwap, ArcSwapOption};
use clash_verge_logger::AsyncLogger;
use once_cell::sync::Lazy;
use std::{fmt, sync::Arc, time::Instant};
use tauri_plugin_shell::process::CommandChild;

use crate::singleton;
#[cfg(target_os = "windows")]
use std::os::windows::io::{AsRawHandle as _, OwnedHandle};
#[cfg(target_os = "windows")]
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
#[cfg(target_os = "windows")]
use windows_sys::Win32::{Foundation::WAIT_TIMEOUT, System::Threading::WaitForSingleObject};

#[cfg(target_os = "windows")]
#[derive(Debug)]
struct SidecarChild {
    generation: u64,
    child: CommandChild,
}

#[cfg(target_os = "windows")]
struct SidecarCoreOwner {
    generation: u64,
    pid: u32,
    _guard: clash_verge_service_ipc::CoreOwnerGuard,
}

#[cfg(target_os = "windows")]
impl fmt::Debug for SidecarCoreOwner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SidecarCoreOwner")
            .field("generation", &self.generation)
            .field("pid", &self.pid)
            .finish()
    }
}

#[cfg(target_os = "windows")]
#[derive(Debug)]
struct SidecarJob {
    generation: u64,
    job_handle: OwnedHandle,
    process_handle: OwnedHandle,
}

#[cfg(any(target_os = "windows", test))]
const fn sidecar_owner_matches(stored: Option<(u64, u32)>, generation: u64, pid: u32) -> bool {
    matches!(stored, Some((stored_generation, stored_pid)) if stored_generation == generation && stored_pid == pid)
}

pub(crate) static CLASH_LOGGER: Lazy<Arc<AsyncLogger>> = Lazy::new(|| Arc::new(AsyncLogger::new()));

#[derive(Debug, serde::Serialize, PartialEq, Eq)]
pub enum RunningMode {
    Service,
    Sidecar,
    NotRunning,
}

impl fmt::Display for RunningMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Service => write!(f, "Service"),
            Self::Sidecar => write!(f, "Sidecar"),
            Self::NotRunning => write!(f, "NotRunning"),
        }
    }
}

#[derive(Debug)]
pub struct CoreManager {
    state: ArcSwap<State>,
    last_update: ArcSwapOption<Instant>,
    #[cfg(target_os = "windows")]
    sidecar_job: parking_lot::Mutex<Option<SidecarJob>>,
    #[cfg(target_os = "windows")]
    next_sidecar_generation: AtomicU64,
    #[cfg(target_os = "windows")]
    finished_sidecar_generation: AtomicU64,
    #[cfg(target_os = "windows")]
    sidecar_core_owner: parking_lot::Mutex<Option<SidecarCoreOwner>>,
    #[cfg(target_os = "windows")]
    sidecar_core_owner_released: tokio::sync::Notify,
    // Serializes every Clash/Verge/runtime draft transaction from the first
    // edit through generate/apply, persistence, and rollback.
    config_transaction_lock: tokio::sync::Mutex<()>,
    // 串行化 start/stop/restart 和 sidecar→service 交接。需要两把锁时，
    // 锁序固定为 config_transaction_lock → lifecycle_lock。
    lifecycle_lock: tokio::sync::Mutex<()>,
    // sidecar→service 交接 watcher 单实例标志。
    #[cfg(target_os = "windows")]
    handoff_watcher_running: AtomicBool,
    #[cfg(target_os = "windows")]
    handoff_watcher_generation: AtomicU64,
    /// Session-only execution overlay for a non-elevated Windows sidecar.
    ///
    /// The generated in-memory runtime remains the user's durable TUN intent;
    /// only the Run file consumed by the sidecar is written with TUN disabled.
    #[cfg(target_os = "windows")]
    windows_sidecar_tun_fallback_active: AtomicBool,
}

#[derive(Debug)]
struct State {
    running_mode: ArcSwap<RunningMode>,
    #[cfg(not(target_os = "windows"))]
    child_sidecar: ArcSwapOption<CommandChild>,
    #[cfg(target_os = "windows")]
    child_sidecar: parking_lot::Mutex<Option<SidecarChild>>,
}

pub(crate) struct ConfigTransactionGuard<'a> {
    #[cfg(target_os = "windows")]
    windows_ics_scope: Option<crate::core::service::WindowsIcsConfigTransactionScope>,
    _config_guard: tokio::sync::MutexGuard<'a, ()>,
}

impl Drop for ConfigTransactionGuard<'_> {
    fn drop(&mut self) {
        #[cfg(target_os = "windows")]
        {
            // Invalidate transaction-bound rollback receipts before releasing
            // the config gate to the next transaction.
            self.windows_ics_scope.take();
        }
    }
}

impl Default for State {
    fn default() -> Self {
        Self {
            running_mode: ArcSwap::new(Arc::new(RunningMode::NotRunning)),
            #[cfg(not(target_os = "windows"))]
            child_sidecar: ArcSwapOption::new(None),
            #[cfg(target_os = "windows")]
            child_sidecar: parking_lot::Mutex::new(None),
        }
    }
}

impl Default for CoreManager {
    fn default() -> Self {
        Self {
            state: ArcSwap::new(Arc::new(State::default())),
            last_update: ArcSwapOption::new(None),
            #[cfg(target_os = "windows")]
            sidecar_job: parking_lot::Mutex::new(None),
            #[cfg(target_os = "windows")]
            next_sidecar_generation: AtomicU64::new(1),
            #[cfg(target_os = "windows")]
            finished_sidecar_generation: AtomicU64::new(0),
            #[cfg(target_os = "windows")]
            sidecar_core_owner: parking_lot::Mutex::new(None),
            #[cfg(target_os = "windows")]
            sidecar_core_owner_released: tokio::sync::Notify::new(),
            config_transaction_lock: tokio::sync::Mutex::new(()),
            lifecycle_lock: tokio::sync::Mutex::new(()),
            #[cfg(target_os = "windows")]
            handoff_watcher_running: AtomicBool::new(false),
            #[cfg(target_os = "windows")]
            handoff_watcher_generation: AtomicU64::new(0),
            #[cfg(target_os = "windows")]
            windows_sidecar_tun_fallback_active: AtomicBool::new(false),
        }
    }
}

impl CoreManager {
    fn new() -> Self {
        Self::default()
    }

    pub fn get_running_mode(&self) -> Arc<RunningMode> {
        Arc::clone(&self.state.load().running_mode.load())
    }

    #[cfg(not(target_os = "windows"))]
    fn take_child_sidecar(&self) -> Option<CommandChild> {
        self.state
            .load()
            .child_sidecar
            .swap(None)
            .and_then(|arc| Arc::try_unwrap(arc).ok())
    }

    #[cfg(target_os = "windows")]
    fn take_child_sidecar(&self) -> Option<SidecarChild> {
        self.state.load().child_sidecar.lock().take()
    }

    pub fn get_last_update(&self) -> Option<Arc<Instant>> {
        self.last_update.load_full()
    }

    pub fn set_running_mode(&self, mode: RunningMode) {
        let state = self.state.load();
        state.running_mode.store(Arc::new(mode));
    }

    #[cfg(target_os = "windows")]
    pub(crate) fn windows_sidecar_tun_fallback_active(&self) -> bool {
        self.windows_sidecar_tun_fallback_active.load(Ordering::Acquire)
    }

    #[cfg(target_os = "windows")]
    pub(super) fn set_windows_sidecar_tun_fallback_active(&self, active: bool) {
        self.windows_sidecar_tun_fallback_active
            .store(active, Ordering::Release);
    }

    #[cfg(target_os = "windows")]
    pub(super) fn windows_sidecar_session_is_live(&self) -> bool {
        if !matches!(*self.get_running_mode(), RunningMode::Sidecar) {
            return false;
        }

        let child_identity = self
            .state
            .load()
            .child_sidecar
            .lock()
            .as_ref()
            .map(|child| (child.generation, child.child.pid()));
        let owner_identity = self
            .sidecar_core_owner
            .lock()
            .as_ref()
            .map(|owner| (owner.generation, owner.pid));
        let job_identity = self.sidecar_job.lock().as_ref().and_then(|job| {
            // Structural ownership can briefly outlive an immediately failed
            // process until the async event listener runs. The retained,
            // non-reusable process handle is the authoritative zero-time liveness
            // check at the startup/fallback commit boundary.
            let wait_status = unsafe { WaitForSingleObject(job.process_handle.as_raw_handle(), 0) };
            (wait_status == WAIT_TIMEOUT).then_some(job.generation)
        });

        child_identity.is_some_and(|(generation, pid)| {
            owner_identity == Some((generation, pid)) && job_identity == Some(generation)
        })
    }

    #[cfg(not(target_os = "windows"))]
    pub(super) fn set_running_child_sidecar(&self, child: CommandChild) {
        let state = self.state.load();
        state.child_sidecar.store(Some(Arc::new(child)));
    }

    #[cfg(target_os = "windows")]
    pub(super) fn set_running_child_sidecar(
        &self,
        generation: u64,
        child: CommandChild,
    ) -> std::result::Result<(), (anyhow::Error, CommandChild)> {
        let state = self.state.load();
        let mut current = state.child_sidecar.lock();
        if let Some(existing) = current.as_ref() {
            return Err((
                anyhow::anyhow!(
                    "sidecar child is already stored for generation {} PID {}",
                    existing.generation,
                    existing.child.pid()
                ),
                child,
            ));
        }
        *current = Some(SidecarChild { generation, child });
        drop(current);
        Ok(())
    }

    #[cfg(target_os = "windows")]
    fn clear_running_child_sidecar_if_generation(&self, generation: u64, pid: u32) {
        let state = self.state.load();
        let mut child = state.child_sidecar.lock();
        let matches_generation = child
            .as_ref()
            .is_some_and(|sidecar| sidecar.generation == generation && sidecar.child.pid() == pid);
        if matches_generation {
            child.take();
        }
    }

    #[cfg(target_os = "windows")]
    pub(super) fn allocate_sidecar_generation(&self) -> u64 {
        self.next_sidecar_generation.fetch_add(1, Ordering::AcqRel)
    }

    #[cfg(target_os = "windows")]
    pub(super) fn store_sidecar_core_owner(
        &self,
        generation: u64,
        pid: u32,
        guard: clash_verge_service_ipc::CoreOwnerGuard,
    ) -> Result<()> {
        let mut owner = self.sidecar_core_owner.lock();
        if let Some(existing) = owner.as_ref() {
            return Err(anyhow::anyhow!(
                "sidecar core ownership is already held by generation {} PID {}",
                existing.generation,
                existing.pid
            ));
        }
        *owner = Some(SidecarCoreOwner {
            generation,
            pid,
            _guard: guard,
        });
        drop(owner);
        Ok(())
    }

    #[cfg(target_os = "windows")]
    pub(super) fn finish_sidecar_generation(&self, generation: u64, pid: u32) -> bool {
        let released = {
            let mut owner = self.sidecar_core_owner.lock();
            let stored = owner.as_ref().map(|owner| (owner.generation, owner.pid));
            if sidecar_owner_matches(stored, generation, pid) {
                owner.take()
            } else {
                None
            }
        };
        if released.is_some() {
            self.clear_running_child_sidecar_if_generation(generation, pid);
            self.release_sidecar_job_if_generation(generation);
            if matches!(*self.get_running_mode(), RunningMode::Sidecar) {
                self.set_running_mode(RunningMode::NotRunning);
            }
            self.set_windows_sidecar_tun_fallback_active(false);
            drop(released);
            self.finished_sidecar_generation.fetch_max(generation, Ordering::AcqRel);
            self.sidecar_core_owner_released.notify_waiters();
            true
        } else {
            false
        }
    }

    #[cfg(target_os = "windows")]
    pub(super) async fn wait_for_sidecar_core_owner_release(&self, generation: u64, pid: u32) -> Result<()> {
        let wait = async {
            loop {
                let notified = self.sidecar_core_owner_released.notified();
                tokio::pin!(notified);
                // `notify_waiters` stores no permit. Register before checking
                // the generation so a concurrent process-exit notification
                // cannot be lost between the atomic load and await.
                notified.as_mut().enable();
                if self.finished_sidecar_generation.load(Ordering::Acquire) >= generation {
                    break;
                }
                notified.as_mut().await;
            }
        };
        tokio::time::timeout(crate::constants::timing::SIDECAR_STOP_WAIT_MAX, wait)
            .await
            .map_err(|_| {
                anyhow::anyhow!(
                    "timed out waiting for sidecar generation {generation} PID {pid} to release core ownership"
                )
            })
    }

    pub fn set_last_update(&self, time: Instant) {
        self.last_update.store(Some(Arc::new(time)));
    }

    #[cfg(target_os = "windows")]
    pub(super) fn store_sidecar_job(&self, generation: u64, handles: (OwnedHandle, OwnedHandle)) -> Result<()> {
        let mut job = self.sidecar_job.lock();
        if let Some(existing) = job.as_ref() {
            return Err(anyhow::anyhow!(
                "sidecar Job Object is already held by generation {}",
                existing.generation
            ));
        }
        let (job_handle, process_handle) = handles;
        *job = Some(SidecarJob {
            generation,
            job_handle,
            process_handle,
        });
        drop(job);
        Ok(())
    }

    #[cfg(target_os = "windows")]
    fn take_sidecar_job_if_generation(&self, generation: u64) -> Option<SidecarJob> {
        let mut job = self.sidecar_job.lock();
        let released = if job.as_ref().is_some_and(|job| job.generation == generation) {
            job.take()
        } else {
            None
        };
        drop(job);
        released
    }

    #[cfg(target_os = "windows")]
    pub(super) fn release_sidecar_job_if_generation(&self, generation: u64) -> bool {
        let released = self.take_sidecar_job_if_generation(generation);
        let did_release = released.is_some();
        drop(released);
        did_release
    }

    pub(crate) async fn begin_config_transaction(&self) -> ConfigTransactionGuard<'_> {
        let config_guard = self.config_transaction_lock.lock().await;
        ConfigTransactionGuard {
            #[cfg(target_os = "windows")]
            windows_ics_scope: Some(crate::core::service::begin_windows_ics_config_transaction()),
            _config_guard: config_guard,
        }
    }

    pub(crate) fn try_begin_config_transaction(&self) -> Option<ConfigTransactionGuard<'_>> {
        let config_guard = self.config_transaction_lock.try_lock().ok()?;
        Some(ConfigTransactionGuard {
            #[cfg(target_os = "windows")]
            windows_ics_scope: Some(crate::core::service::begin_windows_ics_config_transaction()),
            _config_guard: config_guard,
        })
    }

    pub async fn init(&self) -> Result<()> {
        self.start_core().await?;
        Ok(())
    }
}

singleton!(CoreManager, CORE_MANAGER);

#[cfg(test)]
mod tests {
    use super::{CoreManager, sidecar_owner_matches};

    #[tokio::test]
    async fn config_transaction_gate_is_exclusive() {
        let manager = CoreManager::default();
        let guard = manager.begin_config_transaction().await;
        assert!(manager.try_begin_config_transaction().is_none());
        drop(guard);
        assert!(manager.try_begin_config_transaction().is_some());
    }

    #[test]
    fn stale_sidecar_termination_cannot_release_new_owner() {
        assert!(sidecar_owner_matches(Some((7, 42)), 7, 42));
        assert!(!sidecar_owner_matches(Some((8, 42)), 7, 42));
        assert!(!sidecar_owner_matches(Some((7, 43)), 7, 42));
        assert!(!sidecar_owner_matches(None, 7, 42));
    }
}
