use crate::{
    config::{Config, IClashTemp},
    core::{logger::Logger, tray::Tray},
    utils::dirs,
};
#[cfg(target_os = "windows")]
use crate::{
    config::{IVerge, runtime::IRuntime},
    core::CoreManager,
    process::AsyncHandler,
};
use anyhow::{Context as _, Result, bail};
use backon::{ConstantBuilder, Retryable as _};
use clash_verge_logging::{Type, logging};
use clash_verge_service_ipc::CoreConfig;
use compact_str::CompactString;
use once_cell::sync::Lazy;
use parking_lot::Mutex;
use scopeguard::defer;
#[cfg(target_os = "windows")]
use std::sync::{Arc, atomic::AtomicU64};
#[cfg(target_os = "windows")]
use std::time::Instant;
use std::{
    borrow::Cow,
    env::current_exe,
    future::Future,
    path::{Path, PathBuf},
    process::Command as StdCommand,
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
};
use tokio::sync::Notify;
#[cfg(target_os = "windows")]
use {
    std::os::windows::io::{AsRawHandle as _, FromRawHandle as _, OwnedHandle},
    windows_sys::Win32::{
        Foundation::{ERROR_INVALID_PARAMETER, ERROR_SERVICE_DOES_NOT_EXIST, GetLastError, STILL_ACTIVE},
        System::{
            Services::{
                CloseServiceHandle, OpenSCManagerW, OpenServiceW, QueryServiceStatusEx, SC_MANAGER_CONNECT,
                SC_STATUS_PROCESS_INFO, SERVICE_QUERY_STATUS, SERVICE_STATUS_PROCESS, SERVICE_STOPPED,
            },
            Threading::{GetExitCodeProcess, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION},
        },
    },
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServiceStatus {
    Ready,
    NeedsReinstall,
    InstallRequired,
    UninstallRequired,
    ReinstallRequired,
    ForceReinstallRequired,
    Unavailable(String),
}

pub struct ServiceManager {
    status: Mutex<ServiceStatus>,
    operation_running: AtomicBool,
    operation_done: Notify,
    /// Startup maintenance can display UAC. Never turn a delayed or rejected
    /// prompt into an automatic prompt loop within one application process.
    startup_maintenance_attempted: AtomicBool,
}

#[cfg(target_os = "windows")]
static WINDOWS_ICS_AUTO_RECOVERY_RUNNING: AtomicBool = AtomicBool::new(false);
#[cfg(target_os = "windows")]
static WINDOWS_ICS_AUTO_RECOVERY_GENERATION: AtomicU64 = AtomicU64::new(0);
#[cfg(target_os = "windows")]
static WINDOWS_ICS_CONFIG_SYNC_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
#[cfg(target_os = "windows")]
static WINDOWS_ICS_CONFIG_TRANSACTION_SEQUENCE: AtomicU64 = AtomicU64::new(1);
#[cfg(target_os = "windows")]
static ACTIVE_WINDOWS_ICS_CONFIG_TRANSACTION: Lazy<Mutex<Option<ActiveWindowsIcsConfigTransaction>>> =
    Lazy::new(|| Mutex::new(None));
#[cfg(target_os = "windows")]
static INCOMPATIBLE_SERVICE_UPGRADE_PENDING: AtomicBool = AtomicBool::new(false);

#[cfg(target_os = "windows")]
type WindowsIcsRecoveryConfigSnapshot = clash_verge_service_ipc::WindowsIcsRecoveryConfigSnapshot;

#[cfg(target_os = "windows")]
type WindowsIcsRollbackReceipt = Arc<Mutex<Option<WindowsIcsRecoveryConfigSnapshot>>>;

#[cfg(target_os = "windows")]
struct ActiveWindowsIcsConfigTransaction {
    id: u64,
    receipt: WindowsIcsRollbackReceipt,
}

/// Binds all Windows ICS CAS writes to one held CoreManager config gate.
/// Dropping this scope invalidates every snapshot/token captured by that
/// transaction before the next transaction may acquire the gate.
#[cfg(target_os = "windows")]
pub(crate) struct WindowsIcsConfigTransactionScope {
    id: u64,
}

#[cfg(target_os = "windows")]
impl Drop for WindowsIcsConfigTransactionScope {
    fn drop(&mut self) {
        let mut active = ACTIVE_WINDOWS_ICS_CONFIG_TRANSACTION.lock();
        let is_active = active.as_ref().is_some_and(|transaction| transaction.id == self.id);
        debug_assert!(is_active, "Windows ICS config transaction scope was not active at drop");
        if is_active {
            active.take();
        }
    }
}

#[cfg(target_os = "windows")]
pub(crate) fn begin_windows_ics_config_transaction() -> WindowsIcsConfigTransactionScope {
    let id = WINDOWS_ICS_CONFIG_TRANSACTION_SEQUENCE.fetch_add(1, Ordering::AcqRel);
    let mut active = ACTIVE_WINDOWS_ICS_CONFIG_TRANSACTION.lock();
    assert!(
        active.is_none(),
        "CoreManager config gate must serialize Windows ICS transactions"
    );
    *active = Some(ActiveWindowsIcsConfigTransaction {
        id,
        receipt: Arc::new(Mutex::new(None)),
    });
    drop(active);
    WindowsIcsConfigTransactionScope { id }
}

#[cfg(target_os = "windows")]
fn active_windows_ics_config_transaction() -> Result<(u64, WindowsIcsRollbackReceipt)> {
    ACTIVE_WINDOWS_ICS_CONFIG_TRANSACTION
        .lock()
        .as_ref()
        .map(|transaction| (transaction.id, Arc::clone(&transaction.receipt)))
        .context("Windows ICS mutation requires an active CoreManager config transaction")
}

#[cfg(target_os = "windows")]
#[derive(Clone)]
pub(crate) struct WindowsIcsRecoveryTransaction {
    original: WindowsIcsRecoveryConfigSnapshot,
    scope_id: u64,
    receipt: WindowsIcsRollbackReceipt,
}

#[cfg(target_os = "windows")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WindowsIcsRollbackDecision {
    AlreadyRestored,
    CompareAndSwap { expected_generation: u64 },
    Conflict,
}

#[cfg(target_os = "windows")]
fn windows_ics_rollback_decision(
    original: &WindowsIcsRecoveryConfigSnapshot,
    current: &WindowsIcsRecoveryConfigSnapshot,
    applied: Option<&WindowsIcsRecoveryConfigSnapshot>,
) -> WindowsIcsRollbackDecision {
    if current.config == original.config {
        WindowsIcsRollbackDecision::AlreadyRestored
    } else if applied == Some(current) {
        WindowsIcsRollbackDecision::CompareAndSwap {
            expected_generation: current.generation,
        }
    } else {
        WindowsIcsRollbackDecision::Conflict
    }
}

#[cfg(target_os = "windows")]
pub(super) fn incompatible_service_upgrade_pending() -> bool {
    INCOMPATIBLE_SERVICE_UPGRADE_PENDING.load(Ordering::Acquire)
}

#[cfg(target_os = "windows")]
fn mark_incompatible_service_upgrade_pending() {
    INCOMPATIBLE_SERVICE_UPGRADE_PENDING.store(true, Ordering::Release);
}

#[cfg(target_os = "windows")]
pub(super) fn is_mihomo_controller_present() -> bool {
    Path::new(IClashTemp::guard_external_controller_ipc().as_str()).exists()
}

/// A legacy service does not participate in the new core-owner Event. Before
/// starting a sidecar, query SCM directly so a running/starting/stopping old
/// service cannot race us even when its IPC endpoint is temporarily absent.
/// Only an absent service is safe to bypass. Even a stopped legacy service can
/// be started later and does not participate in the new core-owner Event.
#[cfg(target_os = "windows")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum WindowsScmServiceState {
    Absent,
    Stopped,
    Active,
}

#[cfg(target_os = "windows")]
const fn classify_installed_windows_scm_state(current_state: u32) -> WindowsScmServiceState {
    if current_state == SERVICE_STOPPED {
        WindowsScmServiceState::Stopped
    } else {
        WindowsScmServiceState::Active
    }
}

#[cfg(target_os = "windows")]
const fn windows_scm_state_allows_sidecar(state: WindowsScmServiceState) -> bool {
    matches!(state, WindowsScmServiceState::Absent)
}

#[cfg(target_os = "windows")]
pub(super) fn query_windows_scm_service_state() -> Result<WindowsScmServiceState> {
    let scm = unsafe { OpenSCManagerW(std::ptr::null(), std::ptr::null(), SC_MANAGER_CONNECT) };
    if scm.is_null() {
        return Err(std::io::Error::last_os_error()).context("unable to open Windows Service Control Manager");
    }
    defer! {
        unsafe {
            CloseServiceHandle(scm);
        }
    }

    let service_name = "clash_verge_service"
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let service = unsafe { OpenServiceW(scm, service_name.as_ptr(), SERVICE_QUERY_STATUS) };
    if service.is_null() {
        let error = unsafe { GetLastError() };
        if error == ERROR_SERVICE_DOES_NOT_EXIST {
            return Ok(WindowsScmServiceState::Absent);
        }
        return Err(std::io::Error::from_raw_os_error(error as i32))
            .context("unable to open clash_verge_service for status query");
    }
    defer! {
        unsafe {
            CloseServiceHandle(service);
        }
    }

    let mut status: SERVICE_STATUS_PROCESS = unsafe { std::mem::zeroed() };
    let mut bytes_needed = 0;
    let queried = unsafe {
        QueryServiceStatusEx(
            service,
            SC_STATUS_PROCESS_INFO,
            std::ptr::from_mut(&mut status).cast::<u8>(),
            std::mem::size_of::<SERVICE_STATUS_PROCESS>() as u32,
            &mut bytes_needed,
        )
    };
    if queried == 0 {
        return Err(std::io::Error::last_os_error()).context("unable to query clash_verge_service status");
    }

    Ok(classify_installed_windows_scm_state(status.dwCurrentState))
}

#[cfg(target_os = "windows")]
pub(super) fn windows_scm_allows_sidecar() -> Result<bool> {
    Ok(windows_scm_state_allows_sidecar(query_windows_scm_service_state()?))
}

/// Whether a foreground configuration transaction can publish a persistent
/// Windows ICS desired state to the service.  Keep callers' rollback decision
/// on the same predicate as the actual sync path.
#[cfg(target_os = "windows")]
pub(crate) fn windows_ics_service_sync_required(
    running_as_service: bool,
    previous_recovery_enabled: Option<bool>,
    current_recovery_enabled: Option<bool>,
) -> bool {
    running_as_service || previous_recovery_enabled.unwrap_or(false) || current_recovery_enabled.unwrap_or(false)
}

#[cfg(not(target_os = "macos"))]
fn service_core_path(clash_core: &str, bin_ext: &str) -> Result<PathBuf> {
    Ok(current_exe()?.with_file_name(format!("{clash_core}{bin_ext}")))
}

#[cfg(target_os = "macos")]
fn service_core_path(clash_core: &str, bin_ext: &str) -> Result<PathBuf> {
    let binary_name = format!("{clash_core}{bin_ext}");
    let exe_path = current_exe()?;
    let candidate = exe_path.with_file_name(&binary_name);

    if !is_macos_app_translocated(&exe_path) {
        return Ok(candidate);
    }

    if let Some(stable_path) = stable_macos_core_path_for_translocated_app(&exe_path, &binary_name) {
        logging!(
            warn,
            Type::Service,
            "macOS App Translocation detected for core path {:?}; using stable installed path {:?}",
            candidate,
            stable_path
        );
        return Ok(stable_path);
    }

    // 给用户一个可操作的提示,再 bail 让服务启动失败 —— 避免用临时路径起内核。
    notify_translocated_core_path();
    bail!(
        "macOS App Translocation detected; refusing to start service with temporary core path {:?}",
        candidate
    )
}

/// 发送 translocation 用户提示。**延迟**发送:app 启动期会自动尝试起 core,此时前端的
/// `verge://notice-message` 监听器(随 React 布局挂载后才注册)可能尚未就绪,而后端 emit
/// 没有重放队列 —— 立即发会丢失。延迟到前端挂载后再发,既覆盖"启动自动起 core 失败"、
/// 也兼顾手动启动(错误提示略迟可接受)。复用前端 `set_config::error` 处理器直接展示该消息。
#[cfg(target_os = "macos")]
fn notify_translocated_core_path() {
    crate::process::AsyncHandler::spawn(|| async {
        tokio::time::sleep(std::time::Duration::from_secs(3)).await;
        crate::core::handle::Handle::notice_message(
            "set_config::error",
            clash_verge_i18n::t!("service.translocatedCorePath").to_string(),
        );
    });
}

#[cfg(target_os = "macos")]
fn is_macos_app_translocated(path: &Path) -> bool {
    path.components()
        .any(|component| component.as_os_str() == "AppTranslocation")
}

#[cfg(target_os = "macos")]
fn stable_macos_core_path_for_translocated_app(exe_path: &Path, binary_name: &str) -> Option<PathBuf> {
    let bundle_name = macos_app_bundle_name(exe_path)?;
    macos_core_path_in_install_roots(
        &bundle_name,
        binary_name,
        [Path::new("/Applications"), Path::new("/Applications/Utilities")],
    )
}

#[cfg(target_os = "macos")]
fn macos_app_bundle_name(path: &Path) -> Option<std::ffi::OsString> {
    path.ancestors().find_map(|ancestor| {
        let is_app_bundle = ancestor
            .extension()
            .and_then(|extension| extension.to_str())
            .is_some_and(|extension| extension.eq_ignore_ascii_case("app"));

        if is_app_bundle {
            ancestor.file_name().map(std::ffi::OsString::from)
        } else {
            None
        }
    })
}

#[cfg(target_os = "macos")]
fn macos_core_path_in_install_roots<'a>(
    bundle_name: &std::ffi::OsStr,
    binary_name: &str,
    install_roots: impl IntoIterator<Item = &'a Path>,
) -> Option<PathBuf> {
    install_roots.into_iter().find_map(|root| {
        let core_path = root
            .join(Path::new(bundle_name))
            .join("Contents")
            .join("MacOS")
            .join(binary_name);

        core_path.is_file().then_some(core_path)
    })
}

#[cfg(target_os = "macos")]
const fn macos_cleanup_translocated_desired_state_shell() -> &'static str {
    "for f in '/var/root/.local/state/clash-verge-service/desired-state.json' '/var/lib/clash-verge-service/desired-state.json'; do if [ -f \"$f\" ] && /usr/bin/grep -q AppTranslocation \"$f\"; then backup=\"$f.apptranslocation.bak\"; if [ -e \"$backup\" ]; then backup=\"$f.apptranslocation.$(/bin/date +%s).bak\"; fi; /bin/mv \"$f\" \"$backup\"; fi; done"
}

/// 卸载服务前以 root 清理残留 core 和 IPC 套接字。
#[cfg(target_os = "macos")]
fn macos_force_stop_core_shell() -> String {
    use crate::config::IVerge;

    // 只清理 root 拥有的服务内核。
    let mut parts: Vec<String> = IVerge::VALID_CLASH_CORES
        .iter()
        .map(|core| format!("/usr/bin/pkill -U root -x {core} 2>/dev/null || true"))
        .collect();

    if let Ok(ipc) = dirs::ipc_path()
        && let Ok(ipc_str) = dirs::path_to_str(&ipc)
    {
        // 转义单引号,避免破坏 shell 参数。
        let escaped = ipc_str.replace('\'', r"'\''");
        parts.push(format!("/bin/rm -f '{escaped}' 2>/dev/null || true"));
    }

    parts.join("; ")
}

#[cfg(target_os = "macos")]
fn escape_osascript_double_quoted_string(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

#[cfg(target_os = "macos")]
fn shell_single_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', r"'\''"))
}

#[cfg(target_os = "windows")]
fn uninstall_service() -> Result<()> {
    logging!(info, Type::Service, "uninstall service");

    use deelevate::{PrivilegeLevel, Token};
    use runas::Command as RunasCommand;
    use std::os::windows::process::CommandExt as _;

    let binary_path = dirs::service_path()?;
    let uninstall_path = binary_path.with_file_name("clash-verge-service-uninstall.exe");

    if !uninstall_path.exists() {
        bail!(format!("uninstaller not found: {uninstall_path:?}"));
    }

    let token = Token::with_current_process()?;
    let level = token.privilege_level()?;
    let status = match level {
        PrivilegeLevel::NotPrivileged => RunasCommand::new(uninstall_path).show(false).status()?,
        _ => StdCommand::new(uninstall_path).creation_flags(0x08000000).status()?,
    };

    if !status.success() {
        bail!(
            "failed to uninstall service with status {}",
            status.code().unwrap_or(-1)
        );
    }

    Ok(())
}

#[cfg(target_os = "windows")]
fn install_service() -> Result<()> {
    use std::process::Output;
    logging!(info, Type::Service, "install service");

    use deelevate::{PrivilegeLevel, Token};
    use runas::Command as RunasCommand;
    use std::os::windows::process::CommandExt as _;

    let binary_path = dirs::service_path()?;
    let install_path = binary_path.with_file_name("clash-verge-service-install.exe");

    if !install_path.exists() {
        bail!(format!("installer not found: {install_path:?}"));
    }

    let token = Token::with_current_process()?;
    let level = token.privilege_level()?;
    let output = match level {
        PrivilegeLevel::NotPrivileged => {
            let status = RunasCommand::new(&install_path).show(false).status()?;
            Output {
                status,
                stdout: Vec::new(),
                stderr: Vec::new(),
            }
        }
        _ => {
            // StdCommand returns Output directly
            StdCommand::new(&install_path).creation_flags(0x08000000).output()?
        }
    };

    if let Some((code, err)) = check_output_error(&output) {
        logging!(
            error,
            Type::Service,
            "failed to install service code: {}, details: {}",
            code,
            err
        );
        bail!("failed to install service code: {}, details: {}", code, err);
    }

    Ok(())
}

#[cfg(target_os = "linux")]
fn uninstall_service() -> Result<()> {
    logging!(info, Type::Service, "uninstall service");

    let uninstall_path = tauri::utils::platform::current_exe()?.with_file_name("clash-verge-service-uninstall");

    if !uninstall_path.exists() {
        bail!(format!("uninstaller not found: {uninstall_path:?}"));
    }

    let elevator = crate::utils::help::linux_elevator();
    let status = if linux_running_as_root() {
        StdCommand::new(&uninstall_path).status()?
    } else {
        let result = StdCommand::new(&elevator).arg(&uninstall_path).status()?;

        // 如果 pkexec 执行失败，回退到 sudo
        if !result.success() && elevator.contains("pkexec") {
            logging!(
                warn,
                Type::Service,
                "pkexec failed with code {}, falling back to sudo",
                result.code().unwrap_or(-1)
            );
            StdCommand::new("sudo").arg(&uninstall_path).status()?
        } else {
            result
        }
    };
    logging!(
        info,
        Type::Service,
        "uninstall status code:{}",
        status.code().unwrap_or(-1)
    );

    if !status.success() {
        bail!(
            "failed to uninstall service with status {}",
            status.code().unwrap_or(-1)
        );
    }

    Ok(())
}

#[cfg(target_os = "linux")]
fn install_service() -> Result<()> {
    logging!(info, Type::Service, "install service");

    let install_path = tauri::utils::platform::current_exe()?.with_file_name("clash-verge-service-install");

    if !install_path.exists() {
        bail!(format!("installer not found: {install_path:?}"));
    }

    let elevator = crate::utils::help::linux_elevator();
    let output = if linux_running_as_root() {
        StdCommand::new(&install_path).output()?
    } else {
        let result = StdCommand::new(&elevator).arg(&install_path).output()?;

        // 如果 pkexec 执行失败，回退到 sudo
        if !result.status.success() && elevator.contains("pkexec") {
            logging!(
                warn,
                Type::Service,
                "pkexec failed with code {}, falling back to sudo",
                result.status.code().unwrap_or(-1)
            );
            StdCommand::new("sudo").arg(&install_path).output()?
        } else {
            result
        }
    };

    if let Some((code, err)) = check_output_error(&output) {
        logging!(
            error,
            Type::Service,
            "failed to install service code: {}, details: {}",
            code,
            err
        );
        bail!("failed to install service code: {}, details: {}", code, err);
    }

    Ok(())
}

#[cfg(target_os = "linux")]
fn linux_running_as_root() -> bool {
    use crate::core::handle;
    use tauri_plugin_clash_verge_sysinfo::is_current_app_handle_admin;
    let app_handle = handle::Handle::app_handle();
    is_current_app_handle_admin(app_handle)
}

#[cfg(target_os = "macos")]
fn uninstall_service() -> Result<()> {
    logging!(info, Type::Service, "uninstall service");

    let binary_path = dirs::service_path()?;
    let uninstall_path = binary_path.with_file_name("clash-verge-service-uninstall");

    if !uninstall_path.exists() {
        bail!(format!("uninstaller not found: {uninstall_path:?}"));
    }

    let uninstall_shell: String = uninstall_path.to_string_lossy().into_owned();

    // clash_verge_i18n::sync_locale(Config::verge().await.latest_arc().language.as_deref());

    let prompt = clash_verge_i18n::t!("service.adminUninstallPrompt");
    // 先清理服务残留,再执行卸载器。
    let uninstall_quoted = shell_single_quote(&uninstall_shell);
    let shell = format!("{}; sudo {uninstall_quoted}", macos_force_stop_core_shell());
    let shell = escape_osascript_double_quoted_string(&shell);
    let command = format!(r#"do shell script "{shell}" with administrator privileges with prompt "{prompt}""#);

    // logging!(debug, Type::Service, "uninstall command: {}", command);

    let status = StdCommand::new("osascript").args(vec!["-e", &command]).status()?;

    if !status.success() {
        bail!(
            "failed to uninstall service with status {}",
            status.code().unwrap_or(-1)
        );
    }

    Ok(())
}

#[cfg(target_os = "macos")]
fn install_service() -> Result<()> {
    logging!(info, Type::Service, "install service");

    let binary_path = dirs::service_path()?;
    let install_path = binary_path.with_file_name("clash-verge-service-install");

    if !install_path.exists() {
        bail!(format!("installer not found: {install_path:?}"));
    }

    let install_shell: String = install_path.to_string_lossy().into_owned();

    // clash_verge_i18n::sync_locale(Config::verge().await.latest_arc().language.as_deref());

    let gid = tauri_plugin_clash_verge_sysinfo::current_gid();
    let prompt = clash_verge_i18n::t!("service.adminInstallPrompt");
    let install_quoted = shell_single_quote(&install_shell);
    let shell = format!(
        "{}; sudo CLASH_VERGE_SERVICE_GID={gid} {install_quoted}",
        macos_cleanup_translocated_desired_state_shell()
    );
    let shell = escape_osascript_double_quoted_string(&shell);
    let command = format!(r#"do shell script "{shell}" with administrator privileges with prompt "{prompt}""#);

    let output = StdCommand::new("osascript").args(vec!["-e", &command]).output()?;
    if let Some((code, err)) = check_output_error(&output) {
        logging!(
            error,
            Type::Service,
            "failed to install service code: {}, details: {}",
            code,
            err
        );
        bail!("failed to install service code: {}, details: {}", code, err);
    }

    Ok(())
}

fn check_output_error(output: &std::process::Output) -> Option<(i32, Cow<'_, str>)> {
    if output.status.success() {
        return None;
    }
    let code = output.status.code().unwrap_or(-1);
    let stderr = String::from_utf8_lossy(&output.stderr);
    if !stderr.is_empty() {
        return Some((code, stderr));
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    if !stdout.is_empty() {
        return Some((code, stdout));
    }
    Some((code, Cow::Borrowed("Unknown error")))
}

fn reinstall_service() -> Result<()> {
    logging!(info, Type::Service, "reinstall service");

    // 先卸载服务
    if let Err(err) = uninstall_service() {
        logging!(warn, Type::Service, "failed to uninstall service: {}", err);
    }

    // 再安装服务
    match install_service() {
        Ok(_) => Ok(()),
        Err(err) => {
            bail!(format!("failed to install service: {err}"))
        }
    }
}

/// 强制重装服务（UI修复按钮）
fn force_reinstall_service() -> Result<()> {
    logging!(info, Type::Service, "用户请求强制重装服务");
    reinstall_service().map_err(|err| {
        logging!(error, Type::Service, "强制重装服务失败: {}", err);
        err
    })
}

/// 尝试使用服务启动core
pub(super) async fn start_with_existing_service(config_file: &PathBuf) -> Result<()> {
    logging!(info, Type::Service, "尝试使用现有服务启动核心");

    let verge_config = Config::verge().await;
    let clash_core = verge_config.latest_arc().get_valid_clash_core();
    drop(verge_config);

    let bin_ext = if cfg!(windows) { ".exe" } else { "" };
    let bin_path = service_core_path(&clash_core, bin_ext)?;

    let payload = clash_verge_service_ipc::ClashConfig {
        core_config: CoreConfig {
            config_path: dirs::path_to_str(config_file)?.into(),
            core_path: dirs::path_to_str(&bin_path)?.into(),
            core_ipc_path: IClashTemp::guard_external_controller_ipc(),
            config_dir: dirs::path_to_str(&dirs::app_home_dir()?)?.into(),
        },
        log_config: Logger::global().service_writer_config()?,
    };

    let response = clash_verge_service_ipc::start_clash(&payload)
        .await
        .context("无法连接到Clash Verge Service")?;

    if response.code > 0 {
        let err_msg = response.message;
        logging!(error, Type::Service, "启动核心失败: {}", err_msg);
        bail!(err_msg);
    }

    logging!(info, Type::Service, "服务成功启动核心");
    Ok(())
}

// 以服务启动core
pub(super) async fn run_core_by_service(config_file: &PathBuf) -> Result<()> {
    logging!(info, Type::Service, "正在尝试通过服务启动核心");

    SERVICE_MANAGER.refresh().await?;

    logging!(info, Type::Service, "服务已运行且版本匹配，直接使用");
    start_with_existing_service(config_file).await
}

pub(super) async fn get_clash_logs_by_service() -> Result<Vec<CompactString>> {
    logging!(info, Type::Service, "正在获取服务模式下的 Clash 日志");

    let response = clash_verge_service_ipc::get_clash_logs()
        .await
        .context("无法连接到Clash Verge Service")?;

    if response.code > 0 {
        let err_msg = response.message;
        logging!(error, Type::Service, "获取服务模式下的 Clash 日志失败: {}", err_msg);
        bail!(err_msg);
    }

    logging!(info, Type::Service, "成功获取服务模式下的 Clash 日志");
    Ok(response.data.unwrap_or_default())
}

/// 通过服务停止core
pub(super) async fn stop_core_by_service() -> Result<()> {
    logging!(info, Type::Service, "通过服务停止核心 (IPC)");

    let response = clash_verge_service_ipc::stop_clash()
        .await
        .context("无法连接到Clash Verge Service")?;

    if response.code > 0 {
        let err_msg = response.message;
        logging!(error, Type::Service, "停止核心失败: {}", err_msg);
        bail!(err_msg);
    }

    logging!(info, Type::Service, "服务成功停止核心");
    Ok(())
}

#[cfg(target_os = "windows")]
const fn service_status_confirms_running_core(
    core_pid: Option<u32>,
    service_state: clash_verge_service_ipc::ServiceLifecycleState,
) -> bool {
    core_pid.is_some() && matches!(service_state, clash_verge_service_ipc::ServiceLifecycleState::Running)
}

/// Resolve an ambiguous StartClash result. A lost IPC response does not mean
/// the service failed to start the core, but durable desired intent alone also
/// does not prove that the service has a usable core. The owner lease is only a
/// fail-closed exclusion signal: it can remain held while startup cleanup is
/// degraded. Only a live PID in the Running lifecycle may select Service mode.
#[cfg(target_os = "windows")]
pub(super) async fn query_service_status() -> Result<clash_verge_service_ipc::ServiceStatusSnapshot> {
    let response = clash_verge_service_ipc::get_status()
        .await
        .context("unable to query Clash Verge Service status")?;
    if response.code > 0 {
        bail!(response.message);
    }
    response.data.context("service status response has no data")
}

/// Return a live status only when the endpoint speaks the exact Windows
/// service protocol bundled with this client. A cached `ServiceStatus::Ready`
/// is deliberately insufficient here: the service may have restarted or been
/// replaced since that cache entry was produced.
#[cfg(target_os = "windows")]
pub(super) async fn query_compatible_service_status() -> Result<clash_verge_service_ipc::ServiceStatusSnapshot> {
    if !is_service_ipc_path_exists() {
        bail!("Clash Verge Service IPC endpoint is not present");
    }

    let version_response = clash_verge_service_ipc::get_version()
        .await
        .context("unable to query Clash Verge Service version")?;
    if version_response.code > 0 {
        bail!(version_response.message);
    }
    let version = version_response.data.context("service version response has no data")?;
    if version.as_str() != clash_verge_service_ipc::VERSION {
        mark_incompatible_service_upgrade_pending();
        bail!(
            "Clash Verge Service version {version} is incompatible with bundled protocol {}",
            clash_verge_service_ipc::VERSION
        );
    }

    let status = query_service_status().await?;
    // Only an exact-version endpoint plus a live status response completes a
    // previously observed legacy-service upgrade. A transient endpoint gap is
    // intentionally unable to clear this process-lifetime latch.
    INCOMPATIBLE_SERVICE_UPGRADE_PENDING.store(false, Ordering::Release);
    Ok(status)
}

#[cfg(target_os = "windows")]
pub(super) async fn service_core_running() -> Result<bool> {
    let status = query_compatible_service_status().await?;
    Ok(service_status_confirms_running_core(
        status.core_pid,
        status.service_state,
    ))
}

/// 检查服务是否正在运行
pub async fn is_service_available() -> Result<()> {
    if let Err(e) = Path::metadata(clash_verge_service_ipc::IPC_PATH.as_ref()) {
        let verge = Config::verge().await;
        let verge_last = verge.latest_arc();
        let is_enable = verge_last.enable_tun_mode.unwrap_or(false);
        if is_enable {
            logging!(warn, Type::Service, "Some issue with service IPC Path: {}", e);
        }
        return Err(e.into());
    }
    clash_verge_service_ipc::connect().await?;
    Ok(())
}

async fn wait_for_service_ipc(manager: &ServiceManager) -> Result<()> {
    let config = ServiceManager::config();

    let backoff = ConstantBuilder::default()
        .with_delay(config.retry_delay)
        .with_max_times(config.max_retries);

    let result = (|| async {
        if !is_service_ipc_path_exists() {
            bail!("IPC path not ready");
        }
        clash_verge_service_ipc::connect().await.map(drop)
    })
    .retry(backoff)
    .await;

    if result.is_ok() {
        manager.set_status(ServiceStatus::Ready);
    } else {
        manager.set_status(ServiceStatus::Unavailable("Waiting for service to be available".into()));
    }

    result
}

pub fn is_service_ipc_path_exists() -> bool {
    Path::new(clash_verge_service_ipc::IPC_PATH).exists()
}

#[cfg(target_os = "windows")]
pub fn is_service_owner_present() -> bool {
    let paths = clash_verge_service_ipc::service_paths();
    if !paths.owner_lock_path().exists() && !paths.pid_file_path().exists() {
        return false;
    }

    let pid = std::fs::read_to_string(paths.pid_file_path())
        .ok()
        .and_then(|content| content.trim().parse::<u32>().ok())
        .or_else(|| {
            std::fs::read_to_string(paths.owner_lock_path())
                .ok()?
                .lines()
                .find_map(|line| line.strip_prefix("pid=")?.trim().parse::<u32>().ok())
        });
    let Some(pid) = pid else {
        // A lock can exist briefly before metadata is flushed. Treat an
        // unparseable owner as live rather than crossing the ownership line.
        return true;
    };

    unsafe {
        let raw_handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if raw_handle.is_null() {
            // Invalid PID is a stale artifact; access denied is conservatively
            // treated as a live service owner.
            return GetLastError() != ERROR_INVALID_PARAMETER;
        }
        let handle = OwnedHandle::from_raw_handle(raw_handle);
        let mut exit_code = 0;
        GetExitCodeProcess(handle.as_raw_handle(), &mut exit_code) != 0 && exit_code == STILL_ACTIVE as u32
    }
}

/// Start automatic service maintenance once for this application process.
///
/// The detached task owns the complete operation, including a potentially
/// delayed UAC-backed installer. Windows core startup performs independent
/// live probes, so its timeout cannot cancel the owner and accidentally clear
/// the operation guard while the installer is still running.
#[cfg(target_os = "windows")]
pub fn schedule_startup_service_maintenance() {
    if SERVICE_MANAGER
        .startup_maintenance_attempted
        .swap(true, Ordering::AcqRel)
    {
        return;
    }

    AsyncHandler::spawn(|| async {
        let deadline = tokio::time::Instant::now() + crate::constants::timing::SERVICE_HANDOFF_WINDOW;
        let mut start_attempted = false;
        let result = loop {
            if is_service_ipc_path_exists() {
                match SERVICE_MANAGER.init().await {
                    Ok(()) => break SERVICE_MANAGER.refresh().await,
                    Err(error) => logging!(debug, Type::Service, "startup service connection not ready: {error}"),
                }
            }

            match query_windows_scm_service_state() {
                Ok(WindowsScmServiceState::Absent) => {
                    // No service is the normal sidecar-only installation. Do
                    // not latch or auto-install, but keep observing during the
                    // handoff window in case the user installs it explicitly.
                }
                Ok(WindowsScmServiceState::Stopped) => {
                    mark_incompatible_service_upgrade_pending();
                    if !start_attempted {
                        start_attempted = true;
                        if let Err(error) = run_service_command(install_service, "start installed service").await {
                            break Err(error);
                        }
                    }
                }
                Ok(WindowsScmServiceState::Active) => {
                    // The endpoint may disappear while an old service is
                    // stopping/reinstalling. Latch before observing that gap.
                    mark_incompatible_service_upgrade_pending();
                }
                Err(error) => {
                    mark_incompatible_service_upgrade_pending();
                    break Err(error).context("unable to determine installed service state");
                }
            }

            if tokio::time::Instant::now() >= deadline {
                break Err(anyhow::anyhow!(
                    "service did not become reachable in the startup maintenance window"
                ));
            }
            tokio::time::sleep(crate::constants::timing::SERVICE_WAIT_INTERVAL).await;
        };

        match result {
            Ok(()) => schedule_windows_ics_recovery("service-maintenance-ready"),
            Err(error) => logging!(warn, Type::Service, "startup service maintenance failed: {error}"),
        }
    });
}

impl ServiceManager {
    pub const fn config() -> clash_verge_service_ipc::IpcConfig {
        clash_verge_service_ipc::IpcConfig {
            default_timeout: Duration::from_millis(150),
            retry_delay: Duration::from_millis(250),
            max_retries: 20,
        }
    }

    pub async fn init(&self) -> Result<()> {
        if let Err(e) = clash_verge_service_ipc::connect().await {
            self.set_status(ServiceStatus::Unavailable("服务连接失败: {e}".to_string()));
            return Err(e);
        }
        Ok(())
    }

    pub async fn list_windows_ics_connections(&self) -> Result<Vec<clash_verge_service_ipc::WindowsIcsConnection>> {
        #[cfg(target_os = "windows")]
        {
            let response = clash_verge_service_ipc::list_windows_ics_connections()
                .await
                .context("unable to list Windows ICS connections")?;
            if response.code > 0 {
                bail!(response.message);
            }
            Ok(response.data.unwrap_or_default())
        }

        #[cfg(not(target_os = "windows"))]
        bail!("Windows ICS is only available on Windows")
    }

    pub async fn repair_windows_ics(
        &self,
        request: &clash_verge_service_ipc::WindowsIcsRepairRequest,
    ) -> Result<clash_verge_service_ipc::WindowsIcsRepairResult> {
        #[cfg(target_os = "windows")]
        {
            let response = clash_verge_service_ipc::repair_windows_ics(request)
                .await
                .context("unable to repair Windows ICS")?;
            if response.code > 0 {
                bail!(response.message);
            }
            response.data.context("Windows ICS repair returned no result")
        }

        #[cfg(not(target_os = "windows"))]
        {
            let _ = request;
            bail!("Windows ICS is only available on Windows")
        }
    }

    /// Wait for an install/reinstall operation before selecting a core mode.
    /// Unix services do not participate in the Windows core-owner Event, so
    /// their startup path must retain this ordering barrier.
    #[cfg(not(target_os = "windows"))]
    pub async fn current(&self) -> ServiceStatus {
        loop {
            let notified = self.operation_done.notified();
            tokio::pin!(notified);
            // `notify_waiters` stores no permit. Register this waiter before
            // observing the atomic so completion between the check and await
            // cannot strand Unix startup indefinitely.
            notified.as_mut().enable();
            if !self.operation_running.load(Ordering::Acquire) {
                let status = self.status.lock().clone();
                if !self.operation_running.load(Ordering::Acquire) {
                    return status;
                }
            }
            notified.as_mut().await;
        }
    }

    fn set_status(&self, status: ServiceStatus) {
        *self.status.lock() = status;
    }

    async fn run_operation(&self, operation: impl Future<Output = Result<()>>) -> Result<()> {
        {
            if self.operation_running.swap(true, Ordering::AcqRel) {
                bail!("service operation already running");
            }
            defer! {
                self.operation_running.store(false, Ordering::Release);
                self.operation_done.notify_waiters();
            }

            operation.await?;
        }

        Tray::global().update_menu().await
    }

    pub async fn refresh(&self) -> Result<()> {
        self.run_operation(async {
            let reinstall_needed = clash_verge_service_ipc::is_reinstall_service_needed().await;
            #[cfg(target_os = "windows")]
            if reinstall_needed {
                // Latch before invoking the UAC-backed reinstall. The old
                // endpoint disappears during a normal upgrade, but that gap
                // must not authorize a sidecar while an old core may survive.
                mark_incompatible_service_upgrade_pending();
            }
            self.apply_service_status(if reinstall_needed {
                ServiceStatus::NeedsReinstall
            } else {
                ServiceStatus::Ready
            })
            .await
        })
        .await
    }

    pub async fn handle_service_status(&self, status: ServiceStatus) -> Result<()> {
        self.run_operation(self.apply_service_status(status)).await
    }

    async fn apply_service_status(&self, status: ServiceStatus) -> Result<()> {
        self.set_status(status.clone());
        match status {
            ServiceStatus::Ready => logging!(info, Type::Service, "服务就绪，直接启动"),
            ServiceStatus::NeedsReinstall | ServiceStatus::ReinstallRequired => {
                #[cfg(target_os = "windows")]
                mark_incompatible_service_upgrade_pending();
                logging!(info, Type::Service, "服务需要重装，执行重装流程");
                run_service_command(reinstall_service, "reinstall service").await?;
                wait_for_service_ipc(self).await?;
            }
            ServiceStatus::ForceReinstallRequired => {
                #[cfg(target_os = "windows")]
                mark_incompatible_service_upgrade_pending();
                logging!(info, Type::Service, "服务需要强制重装，执行强制重装流程");
                run_service_command(force_reinstall_service, "force reinstall service").await?;
                wait_for_service_ipc(self).await?;
            }
            ServiceStatus::InstallRequired => {
                #[cfg(target_os = "windows")]
                mark_incompatible_service_upgrade_pending();
                logging!(info, Type::Service, "需要安装服务，执行安装流程");
                run_service_command(install_service, "install service").await?;
                wait_for_service_ipc(self).await?;
                if clash_verge_service_ipc::is_reinstall_service_needed().await {
                    #[cfg(target_os = "windows")]
                    mark_incompatible_service_upgrade_pending();
                    logging!(info, Type::Service, "服务版本不匹配，执行重装流程");
                    self.set_status(ServiceStatus::NeedsReinstall);
                    run_service_command(reinstall_service, "reinstall service").await?;
                    wait_for_service_ipc(self).await?;
                }
            }
            ServiceStatus::UninstallRequired => {
                logging!(info, Type::Service, "服务需要卸载，执行卸载流程");
                run_service_command(uninstall_service, "uninstall service").await?;
                self.set_status(ServiceStatus::Unavailable("Service Uninstalled".into()));
            }
            ServiceStatus::Unavailable(reason) => {
                logging!(info, Type::Service, "服务不可用: {}，将使用Sidecar模式", reason);
                bail!("服务不可用: {}", reason);
            }
        }

        Ok(())
    }
}

#[cfg(target_os = "windows")]
fn build_windows_ics_repair_request(
    recovery_enabled: bool,
    tun_enabled: bool,
    public_name: Option<&str>,
    private_guid: Option<&str>,
    private_name: Option<&str>,
    force_rebind: bool,
) -> Result<Option<clash_verge_service_ipc::WindowsIcsRepairRequest>> {
    if !recovery_enabled || !tun_enabled {
        return Ok(None);
    }

    let public_name = public_name
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("Mihomo");
    let private_guid = private_guid
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned);
    let private_name = private_name
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned);

    if private_guid.is_none() && private_name.is_none() {
        bail!("Windows ICS private adapter is not configured");
    }

    Ok(Some(clash_verge_service_ipc::WindowsIcsRepairRequest {
        public_connection: clash_verge_service_ipc::WindowsIcsConnectionSelector {
            guid: None,
            name: Some(public_name.to_owned()),
        },
        private_connection: clash_verge_service_ipc::WindowsIcsConnectionSelector {
            guid: private_guid,
            name: private_name,
        },
        force_rebind,
    }))
}

#[cfg(target_os = "windows")]
fn windows_runtime_tun(runtime: &IRuntime) -> (bool, Option<&str>) {
    let tun = runtime
        .config
        .as_ref()
        .and_then(|config| config.get("tun"))
        .and_then(serde_yaml_ng::Value::as_mapping);

    (
        tun.and_then(|tun| tun.get("enable"))
            .and_then(serde_yaml_ng::Value::as_bool)
            .unwrap_or(false),
        tun.and_then(|tun| tun.get("device"))
            .and_then(serde_yaml_ng::Value::as_str),
    )
}

#[cfg(target_os = "windows")]
fn windows_ics_repair_request_from_config(
    verge: &IVerge,
    runtime: &IRuntime,
    force_rebind: bool,
) -> Result<Option<clash_verge_service_ipc::WindowsIcsRepairRequest>> {
    let (tun_enabled, public_name) = windows_runtime_tun(runtime);
    build_windows_ics_repair_request(
        verge.enable_windows_ics_recovery.unwrap_or(false),
        tun_enabled,
        public_name,
        verge.windows_ics_private_adapter_guid.as_deref(),
        verge.windows_ics_private_adapter_name.as_deref(),
        force_rebind,
    )
}

#[cfg(target_os = "windows")]
fn windows_ics_recovery_config_from_config(
    verge: &IVerge,
    runtime: &IRuntime,
) -> Result<Option<clash_verge_service_ipc::WindowsIcsRecoveryConfig>> {
    Ok(
        windows_ics_repair_request_from_config(verge, runtime, true)?.map(|request| {
            clash_verge_service_ipc::WindowsIcsRecoveryConfig {
                public_connection: request.public_connection,
                private_connection: request.private_connection,
            }
        }),
    )
}

#[cfg(target_os = "windows")]
pub(crate) async fn configure_windows_ics_recovery_for_config(verge: &IVerge, runtime: &IRuntime) -> Result<()> {
    let _sync = WINDOWS_ICS_CONFIG_SYNC_LOCK.lock().await;
    configure_windows_ics_recovery_for_config_unlocked(verge, runtime).await
}

#[cfg(target_os = "windows")]
async fn configure_windows_ics_recovery_for_config_unlocked(verge: &IVerge, runtime: &IRuntime) -> Result<()> {
    let config = windows_ics_recovery_config_from_config(verge, runtime)?;
    configure_windows_ics_recovery_target_unlocked(config.as_ref())
        .await
        .map(drop)
}

#[cfg(target_os = "windows")]
async fn configure_windows_ics_recovery_target_unlocked(
    config: Option<&clash_verge_service_ipc::WindowsIcsRecoveryConfig>,
) -> Result<clash_verge_service_ipc::WindowsIcsRecoveryConfigSnapshot> {
    let (_, receipt) = active_windows_ics_config_transaction()?;
    let current = windows_ics_recovery_snapshot_unlocked().await?;
    compare_and_swap_windows_ics_recovery_target_unlocked(config, current.generation, &receipt).await
}

#[cfg(target_os = "windows")]
async fn compare_and_swap_windows_ics_recovery_target_unlocked(
    config: Option<&clash_verge_service_ipc::WindowsIcsRecoveryConfig>,
    expected_generation: u64,
    receipt: &WindowsIcsRollbackReceipt,
) -> Result<clash_verge_service_ipc::WindowsIcsRecoveryConfigSnapshot> {
    let update = clash_verge_service_ipc::WindowsIcsRecoveryConfigUpdate {
        expected_generation,
        config: config.cloned(),
    };
    // Exactly one mutation is sent for this observed generation. Retrying by
    // reading a newer generation and rebasing the same payload would turn a
    // stale transaction into a last-writer-wins overwrite.
    let response = clash_verge_service_ipc::compare_and_swap_windows_ics_recovery_config(&update)
        .await
        .context("unable to configure persistent Windows ICS recovery")?;
    if response.code > 0 {
        let current_generation = response
            .data
            .as_ref()
            .map(|snapshot| snapshot.generation)
            .map_or_else(|| "unknown".to_string(), |generation| generation.to_string());
        bail!(
            "{} (expected generation {expected_generation}, current generation {current_generation})",
            response.message
        );
    }
    let applied = response
        .data
        .context("Windows ICS recovery CAS returned no applied snapshot")?;
    if applied.generation == expected_generation || applied.config.as_ref() != config {
        bail!(
            "Windows ICS recovery CAS returned an unexpected snapshot (expected generation {expected_generation}, applied generation {})",
            applied.generation
        );
    }
    *receipt.lock() = Some(applied.clone());
    Ok(applied)
}

#[cfg(target_os = "windows")]
async fn windows_ics_recovery_snapshot_unlocked() -> Result<clash_verge_service_ipc::WindowsIcsRecoveryConfigSnapshot> {
    let response = clash_verge_service_ipc::get_windows_ics_recovery_config_snapshot()
        .await
        .context("unable to snapshot persistent Windows ICS recovery")?;
    if response.code > 0 {
        bail!(response.message);
    }
    response.data.context("Windows ICS recovery snapshot returned no data")
}

/// Capture the service-owned target before a local configuration transaction
/// can mutate it. Rollback must restore this authoritative value, not infer it
/// from an execution runtime that may carry a session-only overlay.
#[cfg(target_os = "windows")]
pub(crate) async fn snapshot_windows_ics_recovery() -> Result<WindowsIcsRecoveryTransaction> {
    let _sync = WINDOWS_ICS_CONFIG_SYNC_LOCK.lock().await;
    let (scope_id, receipt) = active_windows_ics_config_transaction()?;
    let original = windows_ics_recovery_snapshot_unlocked().await?;
    Ok(WindowsIcsRecoveryTransaction {
        original,
        scope_id,
        receipt,
    })
}

#[cfg(target_os = "windows")]
pub(crate) async fn restore_windows_ics_recovery_snapshot(transaction: &WindowsIcsRecoveryTransaction) -> Result<()> {
    let _sync = WINDOWS_ICS_CONFIG_SYNC_LOCK.lock().await;
    let (active_scope_id, active_receipt) = active_windows_ics_config_transaction()?;
    if active_scope_id != transaction.scope_id || !Arc::ptr_eq(&active_receipt, &transaction.receipt) {
        bail!("refusing to use a Windows ICS rollback token outside its originating config transaction");
    }

    let current = windows_ics_recovery_snapshot_unlocked().await?;
    let applied = transaction.receipt.lock().clone();
    match windows_ics_rollback_decision(&transaction.original, &current, applied.as_ref()) {
        WindowsIcsRollbackDecision::AlreadyRestored => Ok(()),
        WindowsIcsRollbackDecision::CompareAndSwap { expected_generation } => {
            compare_and_swap_windows_ics_recovery_target_unlocked(
                transaction.original.config.as_ref(),
                expected_generation,
                &transaction.receipt,
            )
            .await
            .map(drop)
            .with_context(|| {
                format!(
                    "unable to restore Windows ICS recovery snapshot from generation {}",
                    transaction.original.generation
                )
            })
        }
        WindowsIcsRollbackDecision::Conflict => bail!(
            "refusing to restore Windows ICS generation {} over newer unowned generation {}; another client changed the recovery target",
            transaction.original.generation,
            current.generation
        ),
    }
}

#[cfg(target_os = "windows")]
pub(crate) async fn configure_effective_windows_ics_recovery() -> Result<()> {
    let verge = Config::verge().await.latest_arc();
    let runtime = Config::runtime().await;
    let runtime_latest = runtime.latest_arc();
    let runtime_data = runtime.data_arc();
    let runtime = if runtime_latest.config.is_some() {
        &*runtime_latest
    } else {
        &*runtime_data
    };
    configure_windows_ics_recovery_for_config(&verge, runtime).await
}

#[cfg(target_os = "windows")]
async fn configure_committed_windows_ics_recovery() -> Result<()> {
    let manager = CoreManager::global();
    let transaction = manager.begin_config_transaction().await;
    // Keep the per-transaction CAS receipt and config snapshot linearized
    // through the bounded IPC write. Retry sleep still happens after both
    // gates are released, so foreground work is never blocked by backoff.
    let sync = WINDOWS_ICS_CONFIG_SYNC_LOCK.lock().await;
    let verge = (**Config::verge().await.data_arc()).clone();
    let runtime = (**Config::runtime().await.data_arc()).clone();

    let result = configure_windows_ics_recovery_for_config_unlocked(&verge, &runtime).await;
    drop(sync);
    drop(transaction);
    result
}

#[cfg(target_os = "windows")]
async fn configure_committed_windows_ics_recovery_with_retry() -> Result<()> {
    const SYNC_TIMEOUT: Duration = Duration::from_secs(30);
    const SYNC_INTERVAL: Duration = Duration::from_secs(1);

    let deadline = Instant::now() + SYNC_TIMEOUT;
    loop {
        // The committed snapshot and one CAS remain one transaction. Both
        // gates are released before any retry sleep.
        let result = configure_committed_windows_ics_recovery().await;
        match result {
            Ok(()) => return Ok(()),
            Err(error) if Instant::now() >= deadline => {
                return Err(error).context("persistent Windows ICS configuration sync timed out");
            }
            Err(error) => logging!(
                debug,
                Type::Service,
                "persistent Windows ICS configuration is not ready: {error}"
            ),
        }
        tokio::time::sleep(SYNC_INTERVAL).await;
    }
}

#[cfg(target_os = "windows")]
pub fn schedule_windows_ics_recovery(trigger: &'static str) {
    WINDOWS_ICS_AUTO_RECOVERY_GENERATION.fetch_add(1, Ordering::AcqRel);
    if WINDOWS_ICS_AUTO_RECOVERY_RUNNING.swap(true, Ordering::AcqRel) {
        logging!(
            debug,
            Type::Service,
            "Windows ICS recovery coalesced; trigger={trigger}"
        );
        return;
    }

    AsyncHandler::spawn(move || async move {
        loop {
            // Wait for a real quiet period after the latest trigger. The
            // service config endpoint is idempotent and schedules recovery
            // itself; the mutating repair endpoint is never retried here.
            let observed_generation = WINDOWS_ICS_AUTO_RECOVERY_GENERATION.load(Ordering::Acquire);
            tokio::time::sleep(Duration::from_millis(250)).await;
            if WINDOWS_ICS_AUTO_RECOVERY_GENERATION.load(Ordering::Acquire) != observed_generation {
                continue;
            }

            let result = configure_committed_windows_ics_recovery_with_retry().await;

            match result {
                Ok(()) => logging!(
                    info,
                    Type::Service,
                    "persistent Windows ICS recovery configuration synchronized; trigger={trigger}"
                ),
                Err(err) => logging!(
                    warn,
                    Type::Service,
                    "Windows ICS recovery configuration sync failed; trigger={}: {}",
                    trigger,
                    err
                ),
            }

            if WINDOWS_ICS_AUTO_RECOVERY_GENERATION.load(Ordering::Acquire) != observed_generation {
                continue;
            }

            WINDOWS_ICS_AUTO_RECOVERY_RUNNING.store(false, Ordering::Release);
            if WINDOWS_ICS_AUTO_RECOVERY_GENERATION.load(Ordering::Acquire) != observed_generation
                && !WINDOWS_ICS_AUTO_RECOVERY_RUNNING.swap(true, Ordering::AcqRel)
            {
                continue;
            }
            break;
        }
    });
}

async fn run_service_command(
    operation: impl FnOnce() -> Result<()> + Send + 'static,
    label: &'static str,
) -> Result<()> {
    tokio::task::spawn_blocking(operation)
        .await
        .with_context(|| format!("{label} task failed"))?
        .with_context(|| format!("{label} failed"))
}

pub static SERVICE_MANAGER: Lazy<ServiceManager> = Lazy::new(|| ServiceManager {
    status: Mutex::new(ServiceStatus::Unavailable("Need Checks".into())),
    operation_running: AtomicBool::new(false),
    operation_done: Notify::new(),
    startup_maintenance_attempted: AtomicBool::new(false),
});

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::*;
    use std::fs;

    fn test_dir(name: &str) -> std::io::Result<PathBuf> {
        let path = std::env::temp_dir().join(format!("clash-verge-service-path-test-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path)?;
        Ok(path)
    }

    #[test]
    fn detects_app_translocation_paths() {
        let path = Path::new(
            "/private/var/folders/example/T/AppTranslocation/123/d/Clash Verge.app/Contents/MacOS/Clash Verge",
        );

        assert!(is_macos_app_translocated(path));
    }

    #[test]
    fn extracts_app_bundle_name_from_executable_path() {
        let path = Path::new("/Applications/Clash Verge.app/Contents/MacOS/Clash Verge");

        assert_eq!(
            macos_app_bundle_name(path).as_deref(),
            Some(std::ffi::OsStr::new("Clash Verge.app"))
        );
    }

    #[test]
    fn resolves_existing_core_path_from_install_roots() -> std::io::Result<()> {
        let root = test_dir("resolve-existing-core-path")?;
        let core_dir = root.join("Clash Verge.app").join("Contents").join("MacOS");
        let core_path = core_dir.join("verge-mihomo");

        fs::create_dir_all(&core_dir)?;
        fs::write(&core_path, b"")?;

        let resolved = macos_core_path_in_install_roots(
            std::ffi::OsStr::new("Clash Verge.app"),
            "verge-mihomo",
            [root.as_path()],
        );

        assert_eq!(resolved, Some(core_path));

        fs::remove_dir_all(root)?;
        Ok(())
    }
}

#[cfg(all(test, target_os = "windows"))]
mod windows_ics_tests {
    use super::{
        WindowsIcsRollbackDecision, WindowsScmServiceState, build_windows_ics_repair_request,
        classify_installed_windows_scm_state, service_status_confirms_running_core, windows_ics_rollback_decision,
        windows_ics_service_sync_required, windows_scm_state_allows_sidecar,
    };
    use windows_sys::Win32::System::Services::SERVICE_STOPPED;

    fn recovery_snapshot(
        generation: u64,
        public_guid: &str,
    ) -> clash_verge_service_ipc::WindowsIcsRecoveryConfigSnapshot {
        clash_verge_service_ipc::WindowsIcsRecoveryConfigSnapshot {
            generation,
            config: Some(clash_verge_service_ipc::WindowsIcsRecoveryConfig {
                public_connection: clash_verge_service_ipc::WindowsIcsConnectionSelector {
                    guid: Some(public_guid.to_owned()),
                    name: Some("Mihomo".to_owned()),
                },
                private_connection: clash_verge_service_ipc::WindowsIcsConnectionSelector {
                    guid: Some("private-guid".to_owned()),
                    name: Some("vEthernet (VMs)".to_owned()),
                },
            }),
        }
    }

    #[test]
    fn only_absent_scm_service_allows_legacy_safe_sidecar_fallback() {
        assert!(windows_scm_state_allows_sidecar(WindowsScmServiceState::Absent));
        assert!(!windows_scm_state_allows_sidecar(WindowsScmServiceState::Stopped));
        assert!(!windows_scm_state_allows_sidecar(WindowsScmServiceState::Active));
        assert_eq!(
            classify_installed_windows_scm_state(SERVICE_STOPPED),
            WindowsScmServiceState::Stopped
        );
        assert_eq!(
            classify_installed_windows_scm_state(SERVICE_STOPPED + 1),
            WindowsScmServiceState::Active
        );
    }

    #[test]
    fn ambiguous_service_start_requires_running_lifecycle_and_pid() {
        use clash_verge_service_ipc::ServiceLifecycleState;

        assert!(service_status_confirms_running_core(
            Some(42),
            ServiceLifecycleState::Running
        ));
        assert!(!service_status_confirms_running_core(
            None,
            ServiceLifecycleState::Running
        ));
        assert!(!service_status_confirms_running_core(
            Some(42),
            ServiceLifecycleState::Fatal
        ));
    }

    #[test]
    fn sidecar_with_existing_ics_requires_service_sync_and_rollback() {
        assert!(windows_ics_service_sync_required(false, Some(true), None));
        assert!(windows_ics_service_sync_required(false, Some(true), Some(false)));
        assert!(!windows_ics_service_sync_required(false, Some(false), None));
        assert!(windows_ics_service_sync_required(true, Some(false), None));
    }

    #[test]
    fn rollback_uses_only_the_exact_generation_applied_by_this_process() {
        let original = recovery_snapshot(7, "old-public");
        let applied = recovery_snapshot(8, "new-public");

        assert_eq!(
            windows_ics_rollback_decision(&original, &applied, Some(&applied)),
            WindowsIcsRollbackDecision::CompareAndSwap { expected_generation: 8 }
        );
    }

    #[test]
    fn rollback_refuses_to_rebase_over_a_newer_client_target() {
        let original = recovery_snapshot(7, "old-public");
        let newer_client = recovery_snapshot(9, "other-client-public");

        assert_eq!(
            windows_ics_rollback_decision(&original, &newer_client, None),
            WindowsIcsRollbackDecision::Conflict
        );
    }

    #[test]
    fn older_transaction_receipt_cannot_rollback_a_newer_same_process_mutation() {
        let original = recovery_snapshot(7, "old-public");
        let old_transaction_applied = recovery_snapshot(8, "old-transaction-public");
        let newer_transaction_applied = recovery_snapshot(9, "new-transaction-public");

        assert_eq!(
            windows_ics_rollback_decision(&original, &newer_transaction_applied, Some(&old_transaction_applied),),
            WindowsIcsRollbackDecision::Conflict
        );
    }

    #[test]
    fn rollback_is_a_noop_when_the_original_target_is_already_restored() {
        let original = recovery_snapshot(7, "old-public");
        let restored_by_another_client = recovery_snapshot(10, "old-public");

        assert_eq!(
            windows_ics_rollback_decision(&original, &restored_by_another_client, None),
            WindowsIcsRollbackDecision::AlreadyRestored
        );
    }

    #[test]
    fn automatic_ics_repair_requires_both_switches() -> anyhow::Result<()> {
        assert!(
            build_windows_ics_repair_request(false, true, Some("Mihomo"), Some("{private-guid}"), None, false,)?
                .is_none()
        );
        assert!(
            build_windows_ics_repair_request(true, false, Some("Mihomo"), Some("{private-guid}"), None, false,)?
                .is_none()
        );
        Ok(())
    }

    #[test]
    fn automatic_ics_repair_prefers_private_guid_and_forces_rebind() -> anyhow::Result<()> {
        let request = build_windows_ics_repair_request(
            true,
            true,
            Some("Mihomo"),
            Some("{private-guid}"),
            Some("vEthernet (Private)"),
            true,
        )?
        .ok_or_else(|| anyhow::anyhow!("repair request should be created"))?;

        assert_eq!(request.public_connection.guid, None);
        assert_eq!(request.public_connection.name.as_deref(), Some("Mihomo"));
        assert_eq!(request.private_connection.guid.as_deref(), Some("{private-guid}"));
        assert_eq!(request.private_connection.name.as_deref(), Some("vEthernet (Private)"));
        assert!(request.force_rebind);
        Ok(())
    }
}
