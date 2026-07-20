#[cfg(target_os = "windows")]
use super::SidecarJob;
use super::{CoreManager, RunningMode};
use crate::{
    AsyncHandler,
    config::{Config, IClashTemp},
    core::{handle, logger::Logger, manager::CLASH_LOGGER, service},
    logging,
    utils::dirs,
};
use anyhow::Result;
use clash_verge_logging::Type;
use compact_str::CompactString;
use log::Level;
use scopeguard::defer;
use tauri_plugin_shell::{ShellExt as _, process::CommandChild};

#[cfg(target_os = "windows")]
use {
    std::os::windows::io::{AsRawHandle as _, FromRawHandle as _, OwnedHandle},
    windows_sys::Win32::{
        Foundation::{HANDLE, WAIT_FAILED, WAIT_OBJECT_0},
        System::{
            JobObjects::{
                AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
                JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation, SetInformationJobObject,
            },
            Threading::{
                INFINITE, OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_SET_QUOTA, PROCESS_SYNCHRONIZE,
                PROCESS_TERMINATE, WaitForSingleObject,
            },
        },
    },
};

impl CoreManager {
    pub async fn get_clash_logs(&self) -> Result<Vec<CompactString>> {
        match *self.get_running_mode() {
            RunningMode::Service => service::get_clash_logs_by_service().await,
            RunningMode::Sidecar => Ok(CLASH_LOGGER.get_logs().await),
            RunningMode::NotRunning => Ok(Vec::new()),
        }
    }

    #[cfg(not(target_os = "windows"))]
    pub(super) async fn start_core_by_sidecar(&self) -> Result<()> {
        self.start_core_by_sidecar_inner().await
    }

    #[cfg(target_os = "windows")]
    pub(super) async fn start_core_by_sidecar_with_owner(
        &self,
        owner_guard: clash_verge_service_ipc::CoreOwnerGuard,
    ) -> Result<()> {
        self.start_core_by_sidecar_inner(owner_guard).await
    }

    async fn start_core_by_sidecar_inner(
        &self,
        #[cfg(target_os = "windows")] owner_guard: clash_verge_service_ipc::CoreOwnerGuard,
    ) -> Result<()> {
        logging!(info, Type::Core, "Starting core in sidecar mode");

        #[cfg(target_os = "windows")]
        let generation = self.allocate_sidecar_generation();

        let config_file = Config::generate_file(crate::config::ConfigType::Run).await?;
        let app_handle = handle::Handle::app_handle();
        let clash_core = Config::verge().await.latest_arc().get_valid_clash_core();
        let config_dir = dirs::app_home_dir()?;

        #[cfg(unix)]
        let previous_mask = unsafe { tauri_plugin_clash_verge_sysinfo::libc::umask(0o007) };
        let sidecar_command = app_handle.shell().sidecar(clash_core.as_str())?.args([
            "-d",
            dirs::path_to_str(&config_dir)?,
            "-f",
            dirs::path_to_str(&config_file)?,
            if cfg!(windows) {
                "-ext-ctl-pipe"
            } else {
                "-ext-ctl-unix"
            },
            &IClashTemp::guard_external_controller_ipc(),
        ]);
        #[cfg(target_os = "windows")]
        let inheritance_token = owner_guard
            .prepare_inheritance()
            .map_err(|error| anyhow::anyhow!("failed to prepare inherited sidecar core ownership: {error:#}"))?;
        let spawn_result = sidecar_command.spawn();
        // The temporary inheritable duplicate must span CreateProcess but not
        // remain in the GUI afterwards. The child receives its own handle
        // before spawn returns; attach_to_process below remains a second,
        // independently checked copy.
        #[cfg(target_os = "windows")]
        drop(inheritance_token);
        let (rx, child) = spawn_result?;
        let pid = child.pid();
        #[cfg(target_os = "windows")]
        {
            // Establish a kernel-enforced termination path before any
            // post-spawn validation. If later setup fails, dropping this local
            // KILL_ON_JOB_CLOSE handle terminates the child even when the
            // higher-level kill request itself reports an error.
            let job = match create_and_assign_sidecar_job(&child) {
                Ok(job) => job,
                Err(job_error) => {
                    // CommandChild owns the handle returned by CreateProcess,
                    // so its kill path has PROCESS_TERMINATE rights. An error
                    // here normally means the just-spawned child already
                    // exited; either way its inherited lease prevents overlap
                    // until Windows has actually torn the process down.
                    let error = match child.kill() {
                        Ok(()) => job_error,
                        Err(kill_error) => anyhow::anyhow!(
                            "failed to configure Job Object for sidecar PID {pid}: \
                            {job_error:#}; failed to terminate child: {kill_error:#}"
                        ),
                    };

                    logging!(error, Type::Core, "Failed to start sidecar: {error:#}");
                    return Err(error);
                }
            };

            // The inherited handle already closes the parent-crash interval;
            // explicit post-spawn duplication is defense in depth and verifies
            // that the child remains attachable before it is committed.
            if let Err(attach_error) = attach_sidecar_owner(&owner_guard, &child) {
                let kill_error = child.kill().err();
                drop(job);
                let mut details = vec![format!("failed to attach core ownership to sidecar: {attach_error:#}")];
                if let Some(error) = kill_error {
                    details.push(format!("failed to terminate sidecar: {error:#}"));
                }
                let error = anyhow::anyhow!(
                    "failed to start sidecar generation {generation} PID {pid}: {}",
                    details.join("; ")
                );
                logging!(error, Type::Core, "Failed to start sidecar: {error:#}");
                return Err(error);
            }

            if let Err(job_error) = self.store_sidecar_job(generation, job) {
                let kill_error = child.kill().err();
                let error = match kill_error {
                    Some(kill_error) => anyhow::anyhow!(
                        "failed to retain Job Object for sidecar generation {generation} PID {pid}: \
                         {job_error:#}; failed to terminate child: {kill_error:#}"
                    ),
                    None => job_error,
                };
                logging!(error, Type::Core, "Failed to start sidecar: {error:#}");
                return Err(error);
            }
            if let Err(owner_error) = self.store_sidecar_core_owner(generation, pid, owner_guard) {
                self.release_sidecar_job_if_generation(generation);
                let kill_error = child.kill().err();
                let error = match kill_error {
                    Some(kill_error) => anyhow::anyhow!(
                        "failed to retain core owner for sidecar generation {generation} PID {pid}: \
                         {owner_error:#}; failed to terminate child: {kill_error:#}"
                    ),
                    None => owner_error,
                };
                logging!(error, Type::Core, "Failed to start sidecar: {error:#}");
                return Err(error);
            }
        }

        #[cfg(unix)]
        unsafe {
            tauri_plugin_clash_verge_sysinfo::libc::umask(previous_mask)
        };

        logging!(trace, Type::Core, "Sidecar started with PID: {}", pid);

        #[cfg(target_os = "windows")]
        if let Err((state_error, child)) = self.set_running_child_sidecar(generation, child) {
            if let Some(job) = self.take_sidecar_job_if_generation(generation) {
                Self::schedule_finish_after_sidecar_exit(job, generation, pid);
            }
            let kill_error = child.kill().err();
            return match kill_error {
                Some(kill_error) => Err(anyhow::anyhow!(
                    "failed to commit sidecar generation {generation} PID {pid}: {state_error:#}; \
                     failed to terminate child: {kill_error:#}"
                )),
                None => Err(state_error),
            };
        }
        #[cfg(not(target_os = "windows"))]
        self.set_running_child_sidecar(child);
        self.set_running_mode(RunningMode::Sidecar);

        #[cfg(target_os = "windows")]
        Self::spawn_sidecar_event_listener(rx, pid, generation);
        #[cfg(not(target_os = "windows"))]
        Self::spawn_sidecar_event_listener(rx, pid);

        Ok(())
    }

    fn spawn_sidecar_event_listener(
        mut rx: tauri::async_runtime::Receiver<tauri_plugin_shell::process::CommandEvent>,
        pid: u32,
        #[cfg(target_os = "windows")] generation: u64,
    ) {
        AsyncHandler::spawn(move || async move {
            #[cfg(target_os = "windows")]
            let mut generation_finished = false;
            while let Some(event) = rx.recv().await {
                match event {
                    tauri_plugin_shell::process::CommandEvent::Stdout(line)
                    | tauri_plugin_shell::process::CommandEvent::Stderr(line) => {
                        let message = CompactString::from(&*String::from_utf8_lossy(&line));
                        Logger::global().writer_sidecar_log(Level::Error, &message);
                        CLASH_LOGGER.append_log(message).await;
                    }
                    tauri_plugin_shell::process::CommandEvent::Terminated(term) => {
                        #[cfg(target_os = "windows")]
                        {
                            // Process exit is the ownership barrier. Release
                            // the generation before any async log cleanup so a
                            // slow logger cannot manufacture a stop timeout.
                            let manager = Self::global();
                            manager.finish_sidecar_generation(generation, pid);
                            generation_finished = true;
                        }
                        let message = if let Some(code) = term.code {
                            CompactString::from(format!("Process terminated with code: {}", code))
                        } else if let Some(signal) = term.signal {
                            CompactString::from(format!("Process terminated by signal: {}", signal))
                        } else {
                            CompactString::from("Process terminated")
                        };
                        Logger::global().writer_sidecar_log(Level::Info, &message);
                        CLASH_LOGGER.clear_logs().await;
                        break;
                    }
                    _ => {}
                }
            }
            #[cfg(target_os = "windows")]
            if !generation_finished {
                // EOF without Terminated means the shell event pump vanished.
                // Close the Job to request termination, but do not publish
                // generation completion until the retained process handle is
                // signaled. The inherited lease protects exclusivity; this
                // wait preserves the stronger stop/handoff barrier.
                let manager = Self::global();
                if let Some(job) = manager.take_sidecar_job_if_generation(generation) {
                    Self::schedule_finish_after_sidecar_exit(job, generation, pid);
                }
            }
        });
    }

    #[cfg(target_os = "windows")]
    fn schedule_finish_after_sidecar_exit(job: SidecarJob, generation: u64, pid: u32) {
        let SidecarJob {
            job_handle,
            process_handle,
            ..
        } = job;
        // KILL_ON_JOB_CLOSE requests termination. Keep the independent process
        // handle alive so PID reuse is impossible and wait for kernel-confirmed
        // exit before dropping the parent lease and notifying handoff.
        drop(job_handle);
        AsyncHandler::spawn(move || async move {
            let wait_result = tokio::task::spawn_blocking(move || {
                let status = unsafe { WaitForSingleObject(process_handle.as_raw_handle() as HANDLE, INFINITE) };
                match status {
                    WAIT_OBJECT_0 => Ok(()),
                    WAIT_FAILED => Err(last_win32_error("WaitForSingleObject failed for sidecar")),
                    status => Err(anyhow::anyhow!("unexpected sidecar wait status {status}")),
                }
            })
            .await;

            match wait_result {
                Ok(Ok(())) => {
                    Self::global().finish_sidecar_generation(generation, pid);
                }
                Ok(Err(error)) => logging!(
                    error,
                    Type::Core,
                    "failed to confirm sidecar generation {generation} PID {pid} exit: {error:#}"
                ),
                Err(error) => logging!(
                    error,
                    Type::Core,
                    "sidecar generation {generation} PID {pid} exit waiter failed: {error:#}"
                ),
            }
        });
    }

    #[cfg(target_os = "windows")]
    pub(super) async fn stop_core_by_sidecar(&self) -> Result<()> {
        logging!(info, Type::Core, "Stopping sidecar");
        defer! {
            self.set_running_mode(RunningMode::NotRunning);
        }
        if let Some(sidecar) = self.take_child_sidecar() {
            let generation = sidecar.generation;
            let pid = sidecar.child.pid();
            let result = sidecar.child.kill();
            if let Some(job) = self.take_sidecar_job_if_generation(generation) {
                Self::schedule_finish_after_sidecar_exit(job, generation, pid);
            }
            logging!(
                trace,
                Type::Core,
                "Closed job handle for sidecar generation {} PID {}",
                generation,
                pid
            );
            if let Err(wait_error) = self.wait_for_sidecar_core_owner_release(generation, pid).await {
                return match result {
                    Ok(()) => Err(wait_error),
                    Err(kill_error) => Err(anyhow::anyhow!(
                        "failed to terminate sidecar generation {generation} PID {pid}: \
                         {kill_error:#}; {wait_error:#}"
                    )),
                };
            }

            logging!(
                trace,
                Type::Core,
                "Sidecar stopped (PID: {:?}, Result: {:?})",
                pid,
                result
            );
        }
        Ok(())
    }

    #[cfg(not(target_os = "windows"))]
    pub(super) async fn stop_core_by_sidecar(&self) -> Result<()> {
        logging!(info, Type::Core, "Stopping sidecar");
        defer! {
            self.set_running_mode(RunningMode::NotRunning);
        }
        if let Some(child) = self.take_child_sidecar() {
            let pid = child.pid();
            let result = child.kill();
            logging!(
                trace,
                Type::Core,
                "Sidecar stopped (PID: {:?}, Result: {:?})",
                pid,
                result
            );
            result?;
        }
        Ok(())
    }

    pub(super) async fn start_core_by_service(&self) -> Result<()> {
        logging!(info, Type::Core, "Starting core in service mode");
        let config_file = Config::generate_file(crate::config::ConfigType::Run).await?;

        // 交接时等待 sidecar 释放 ext-controller 通道。
        #[cfg(target_os = "windows")]
        {
            use crate::constants::timing;
            let mut service_rollback_snapshot = None;
            let mut last_err = None;
            for attempt in 0..timing::SERVICE_START_RETRIES {
                if service_rollback_snapshot.is_none() {
                    match service::snapshot_windows_ics_recovery().await {
                        Ok(snapshot) => service_rollback_snapshot = Some(snapshot),
                        Err(error) => {
                            logging!(
                                warn,
                                Type::Core,
                                "service start attempt {}/{} could not snapshot persistent ICS state: {}",
                                attempt + 1,
                                timing::SERVICE_START_RETRIES,
                                error
                            );
                            last_err = Some(error);
                            if attempt + 1 < timing::SERVICE_START_RETRIES {
                                tokio::time::sleep(timing::SERVICE_START_RETRY_DELAY).await;
                            }
                            continue;
                        }
                    }
                }
                // Sync immediately before every StartClash attempt. A failed
                // sync never crosses the core-start mutation boundary, while
                // a retry can recover when service maintenance just completed.
                let (start_attempted, attempt_result) = match service::configure_effective_windows_ics_recovery().await
                {
                    Ok(()) => (true, service::run_core_by_service(&config_file).await),
                    Err(error) => (false, Err(error)),
                };
                match attempt_result {
                    Ok(()) => {
                        self.set_running_mode(RunningMode::Service);
                        service::schedule_windows_ics_recovery("core-started");
                        return Ok(());
                    }
                    Err(e) => {
                        if start_attempted {
                            match service::service_core_running().await {
                                Ok(true) => {
                                    logging!(
                                        warn,
                                        Type::Core,
                                        "service start response was ambiguous, but service status confirms a running core"
                                    );
                                    self.set_running_mode(RunningMode::Service);
                                    service::schedule_windows_ics_recovery("core-start-confirmed-by-status");
                                    return Ok(());
                                }
                                Ok(false) => {}
                                Err(status_error) => logging!(
                                    debug,
                                    Type::Core,
                                    "unable to resolve ambiguous service start response: {status_error}"
                                ),
                            }
                        }
                        logging!(
                            warn,
                            Type::Core,
                            "service start attempt {}/{} failed: {}",
                            attempt + 1,
                            timing::SERVICE_START_RETRIES,
                            e
                        );
                        last_err = Some(e);
                        if attempt + 1 < timing::SERVICE_START_RETRIES {
                            tokio::time::sleep(timing::SERVICE_START_RETRY_DELAY).await;
                        }
                    }
                }
            }
            let error = last_err.unwrap_or_else(|| anyhow::anyhow!("service start failed"));
            if let Some(snapshot) = service_rollback_snapshot
                && let Err(rollback_error) = service::restore_windows_ics_recovery_snapshot(&snapshot).await
            {
                return Err(error.context(format!(
                    "failed to restore persistent Windows ICS config after StartClash retries: {rollback_error:#}"
                )));
            }
            Err(error)
        }

        #[cfg(not(target_os = "windows"))]
        {
            service::run_core_by_service(&config_file).await?;
            self.set_running_mode(RunningMode::Service);
            Ok(())
        }
    }

    pub(super) async fn stop_core_by_service(&self) -> Result<()> {
        logging!(info, Type::Core, "Stopping service");
        defer! {
            self.set_running_mode(RunningMode::NotRunning);
        }
        service::stop_core_by_service().await?;
        Ok(())
    }
}

#[cfg(target_os = "windows")]
fn create_and_assign_sidecar_job(child: &CommandChild) -> Result<(OwnedHandle, OwnedHandle)> {
    // `CommandChild` does not expose its CreateProcess handle, but it owns an
    // Arc<SharedChild> which retains that handle. Windows cannot recycle the
    // PID until every process handle is closed and the process object is
    // released. Taking the child by reference therefore pins the numeric PID
    // to this spawn for the complete OpenProcess/assignment operation, even
    // when an ultra-fast child has already exited.
    create_and_assign_process_job(child.pid())
}

#[cfg(target_os = "windows")]
fn attach_sidecar_owner(owner_guard: &clash_verge_service_ipc::CoreOwnerGuard, child: &CommandChild) -> Result<()> {
    // Keep the same spawn-handle witness borrowed while the IPC helper must
    // reopen the process by PID. See `create_and_assign_sidecar_job`.
    owner_guard.attach_to_process(child.pid())
}

#[cfg(target_os = "windows")]
fn create_and_assign_process_job(child_pid: u32) -> Result<(OwnedHandle, OwnedHandle)> {
    unsafe {
        let raw_job: HANDLE = CreateJobObjectW(std::ptr::null(), std::ptr::null());
        if raw_job.is_null() {
            return Err(last_win32_error("CreateJobObjectW failed"));
        }
        let job = OwnedHandle::from_raw_handle(raw_job);
        let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = std::mem::zeroed();
        info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;

        let set_info_result = SetInformationJobObject(
            job.as_raw_handle() as HANDLE,
            JobObjectExtendedLimitInformation,
            &mut info as *mut _ as *mut _,
            std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
        );
        if set_info_result == 0 {
            return Err(last_win32_error("SetInformationJobObject failed"));
        }

        let raw_process_handle = OpenProcess(
            PROCESS_SET_QUOTA | PROCESS_TERMINATE | PROCESS_QUERY_INFORMATION | PROCESS_SYNCHRONIZE,
            0,
            child_pid,
        );
        if raw_process_handle.is_null() {
            return Err(last_win32_error("OpenProcess failed"));
        }
        let process_handle = OwnedHandle::from_raw_handle(raw_process_handle);

        let assign_result = AssignProcessToJobObject(job.as_raw_handle(), process_handle.as_raw_handle());
        if assign_result == 0 {
            return Err(last_win32_error("AssignProcessToJobObject failed"));
        }

        Ok((job, process_handle))
    }
}

#[cfg(target_os = "windows")]
fn last_win32_error(operation: &'static str) -> anyhow::Error {
    anyhow::Error::new(std::io::Error::last_os_error()).context(operation)
}

#[cfg(all(test, target_os = "windows"))]
mod tests {
    use super::{create_and_assign_process_job, last_win32_error};
    use anyhow::Result;
    use std::{
        os::windows::io::{AsRawHandle as _, FromRawHandle as _, OwnedHandle},
        process::{Child, Command, Stdio},
        thread::sleep,
        time::{Duration, Instant},
    };
    use windows_sys::Win32::{
        Foundation::HANDLE,
        System::Threading::{GetProcessId, OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_SYNCHRONIZE},
    };

    // 起一个长命子进程用于验证 Job Object 的生命周期绑定。
    // 直接使用 System32 下的 ping.exe，避免 cmd 中间层。
    fn spawn_long_lived() -> Result<Child> {
        let child = Command::new("ping")
            .args(["-n", "999", "127.0.0.1"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;
        Ok(child)
    }

    // 在超时内轮询子进程是否退出，返回是否已退出。
    fn wait_until_exited(child: &mut Child, timeout: Duration) -> Result<bool> {
        let deadline = Instant::now() + timeout;
        loop {
            if child.try_wait()?.is_some() {
                return Ok(true);
            }
            if Instant::now() >= deadline {
                return Ok(false);
            }
            sleep(Duration::from_millis(50));
        }
    }

    // 成功路径：进程被分配进 Job Object 后仍存活；drop Job 句柄触发
    // KILL_ON_JOB_CLOSE，进程应在超时内被 OS 终止。
    #[test]
    fn job_kills_child_on_handle_drop() -> Result<()> {
        let mut child = spawn_long_lived()?;

        let job = create_and_assign_process_job(child.id())?;

        // 分配后进程应仍在运行。
        assert!(
            child.try_wait()?.is_none(),
            "child should still be running after being assigned to the job"
        );

        // 关闭 Job 句柄，OS 应连带终止其成员进程。
        drop(job);

        assert!(
            wait_until_exited(&mut child, Duration::from_secs(5))?,
            "child should be terminated after the job handle is dropped"
        );

        Ok(())
    }

    // 失败路径：对一个不存在的 PID 调用时 OpenProcess 应失败，函数返回 Err。
    #[test]
    fn returns_err_for_invalid_pid() {
        // PID 必须为 4 的倍数且极不可能存在；0xFFFF_FFFC 对应不到真实进程。
        let result = create_and_assign_process_job(0xFFFF_FFFC);
        assert!(result.is_err(), "expected Err for a non-existent PID");
    }

    #[test]
    fn retained_spawn_handle_pins_exited_process_identity() -> Result<()> {
        let mut child = Command::new("cmd.exe")
            .args(["/D", "/C", "exit", "0"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;
        let pid = child.id();
        child.wait()?;

        // `Child` still owns the handle returned by CreateProcess after wait.
        // Therefore the process object and its PID cannot be recycled, and a
        // PID-based reopen must still identify this exact exited process.
        let raw_process = unsafe { OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_SYNCHRONIZE, 0, pid) };
        if raw_process.is_null() {
            return Err(last_win32_error("OpenProcess failed for retained exited child"));
        }
        let process = unsafe { OwnedHandle::from_raw_handle(raw_process) };
        let reopened_pid = unsafe { GetProcessId(process.as_raw_handle() as HANDLE) };

        assert_eq!(
            reopened_pid, pid,
            "retained spawn handle must pin the original PID identity"
        );
        Ok(())
    }
}
