use super::{CmdResult, StringifyErr as _};
use crate::core::service::{self, SERVICE_MANAGER, ServiceStatus};

async fn execute_service_operation_sync(status: ServiceStatus, op_type: &str) -> CmdResult {
    SERVICE_MANAGER
        .handle_service_status(status)
        .await
        .map_err(|e| format!("{op_type} Service failed: {e}").into())
}

#[tauri::command]
pub async fn install_service() -> CmdResult {
    execute_service_operation_sync(ServiceStatus::InstallRequired, "Install").await
}

#[tauri::command]
pub async fn uninstall_service() -> CmdResult {
    execute_service_operation_sync(ServiceStatus::UninstallRequired, "Uninstall").await
}

#[tauri::command]
pub async fn reinstall_service() -> CmdResult {
    execute_service_operation_sync(ServiceStatus::ReinstallRequired, "Reinstall").await
}

#[tauri::command]
pub async fn repair_service() -> CmdResult {
    execute_service_operation_sync(ServiceStatus::ForceReinstallRequired, "Repair").await
}

#[tauri::command]
pub async fn is_service_available() -> CmdResult<bool> {
    service::is_service_available().await.stringify_err()?;
    Ok(true)
}

#[tauri::command]
pub async fn list_windows_ics_connections() -> CmdResult<Vec<clash_verge_service_ipc::WindowsIcsConnection>> {
    SERVICE_MANAGER.list_windows_ics_connections().await.stringify_err()
}

#[tauri::command]
pub async fn repair_windows_ics(
    request: clash_verge_service_ipc::WindowsIcsRepairRequest,
) -> CmdResult<clash_verge_service_ipc::WindowsIcsRepairResult> {
    SERVICE_MANAGER.repair_windows_ics(&request).await.stringify_err()
}
