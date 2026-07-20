#[cfg(target_os = "windows")]
use crate::core::service;
use crate::{
    config::{Config, IVerge},
    core::{CoreManager, autostart, handle, hotkey, logger::Logger, sysopt, tray},
    module::{auto_backup::AutoBackupManager, lightweight},
};
use anyhow::Result;
use bitflags::bitflags;
use clash_verge_draft::SharedDraft;
use clash_verge_logging::{Type, logging, logging_error};
use serde_yaml_ng::Mapping;

#[cfg(target_os = "windows")]
use crate::core::manager::RunningMode;

/// Patch Clash configuration
pub async fn patch_clash(patch: &Mapping) -> Result<()> {
    let manager = CoreManager::global();
    let _transaction = manager.begin_config_transaction().await;
    let clash_before = (**Config::clash().await.data_arc()).clone();
    #[cfg(target_os = "windows")]
    let verge_before = (**Config::verge().await.data_arc()).clone();
    let runtime_before = (**Config::runtime().await.data_arc()).clone();
    #[cfg(target_os = "windows")]
    let service_sync_may_have_occurred = service::windows_ics_service_sync_required(
        matches!(*manager.get_running_mode(), RunningMode::Service),
        verge_before.enable_windows_ics_recovery,
        verge_before.enable_windows_ics_recovery,
    );
    #[cfg(target_os = "windows")]
    let service_before = if service_sync_may_have_occurred {
        Some(service::snapshot_windows_ics_recovery().await?)
    } else {
        None
    };
    Config::clash().await.edit_draft(|d| d.patch_config(patch));

    let res: Result<()> = async {
        // 激活订阅
        if patch.get("secret").is_some() || patch.get("external-controller").is_some() {
            Config::generate().await?;
            manager.restart_core_in_transaction().await?;
        } else if patch.get("allow-lan").is_some() {
            manager.update_config_checked_in_transaction().await?;
        } else {
            if patch.get("mode").is_some() {
                tray::Tray::global().update_menu_and_icon().await;
            }
            Config::runtime().await.edit_draft(|d| d.patch_config(patch));
            manager.update_config_checked_in_transaction().await?;
        }
        handle::Handle::refresh_clash();
        Config::clash().await.latest_arc().save_config().await?;
        <Result<()>>::Ok(())
    }
    .await;
    match res {
        Ok(()) => {
            Config::clash().await.apply();
            Ok(())
        }
        Err(err) => {
            let clash = Config::clash().await;
            clash.edit_draft(|draft| *draft = clash_before.clone());
            clash.apply();
            let mut rollback_errors = Vec::new();
            if let Err(rollback_error) = manager.restore_runtime_in_transaction(&runtime_before).await {
                rollback_errors.push(format!("runtime rollback failed: {rollback_error:#}"));
            }
            #[cfg(target_os = "windows")]
            if service_sync_may_have_occurred
                && let Some(snapshot) = service_before.as_ref()
                && let Err(rollback_error) = service::restore_windows_ics_recovery_snapshot(snapshot).await
            {
                rollback_errors.push(format!("service rollback failed: {rollback_error:#}"));
            }
            if let Err(rollback_error) = clash_before.save_config().await {
                rollback_errors.push(format!("clash file rollback failed: {rollback_error:#}"));
            }
            if rollback_errors.is_empty() {
                Err(err)
            } else {
                Err(err.context(format!("rollback errors: {}", rollback_errors.join("; "))))
            }
        }
    }
}

#[cfg(target_os = "windows")]
pub async fn patch_windows_tun_and_ics(tun: &Mapping, ics: &IVerge) -> Result<()> {
    let private_guid = ics
        .windows_ics_private_adapter_guid
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let private_name = ics
        .windows_ics_private_adapter_name
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty());
    if ics.enable_windows_ics_recovery.unwrap_or(false) && private_guid.is_none() && private_name.is_none() {
        return Err(anyhow::anyhow!("Windows ICS private adapter is not configured"));
    }

    // Accept only the three fields owned by this dialog. This keeps the new
    // transaction boundary from becoming a generic IVerge patch backdoor.
    let ics = IVerge {
        enable_windows_ics_recovery: ics.enable_windows_ics_recovery,
        windows_ics_private_adapter_guid: ics.windows_ics_private_adapter_guid.clone(),
        windows_ics_private_adapter_name: ics.windows_ics_private_adapter_name.clone(),
        ..IVerge::default()
    };

    CoreManager::global().patch_windows_tun_and_ics(tun, &ics).await?;
    handle::Handle::refresh_clash();
    handle::Handle::refresh_verge();
    logging_error!(Type::Backup, AutoBackupManager::global().refresh_settings().await);
    Ok(())
}

// Define update flags as bitflags for better performance
bitflags! {
     #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
     struct UpdateFlags: u16 {
        const RESTART_CORE = 1 << 0;
        const CLASH_CONFIG = 1 << 1;
        const VERGE_CONFIG = 1 << 2;
        const LAUNCH = 1 << 3;
        const SYS_PROXY = 1 << 4;
        const SYSTRAY_ICON = 1 << 5;
        const HOTKEY = 1 << 6;
        const SYSTRAY_MENU = 1 << 7;
        const SYSTRAY_TOOLTIP = 1 << 8;
        const SYSTRAY_CLICK_BEHAVIOR = 1 << 9;
        const LIGHT_WEIGHT = 1 << 10;
        const LANGUAGE = 1 << 11;
        const LOG_LEVEL = 1 << 12;
        const LOG_FILE = 1 << 13;

        const GROUP_SYS_TRAY = Self::SYSTRAY_MENU.bits()
                             | Self::SYSTRAY_TOOLTIP.bits()
                             | Self::SYSTRAY_ICON.bits();
     }
}

fn determine_update_flags(patch: &IVerge) -> UpdateFlags {
    let tun_mode = patch.enable_tun_mode;
    let auto_launch = patch.enable_auto_launch;
    let system_proxy = patch.enable_system_proxy;
    let pac = patch.proxy_auto_config;
    let pac_content = &patch.pac_file_content;
    let proxy_bypass = &patch.system_proxy_bypass;
    let language = &patch.language;
    let mixed_port = patch.verge_mixed_port;
    #[cfg(target_os = "macos")]
    let tray_icon = &patch.tray_icon;
    #[cfg(not(target_os = "macos"))]
    let tray_icon: Option<String> = None;
    let common_tray_icon = patch.common_tray_icon;
    let sysproxy_tray_icon = patch.sysproxy_tray_icon;
    let tun_tray_icon = patch.tun_tray_icon;
    #[cfg(not(target_os = "windows"))]
    let redir_enabled = patch.verge_redir_enabled;
    #[cfg(not(target_os = "windows"))]
    let redir_port = patch.verge_redir_port;
    #[cfg(target_os = "linux")]
    let tproxy_enabled = patch.verge_tproxy_enabled;
    #[cfg(target_os = "linux")]
    let tproxy_port = patch.verge_tproxy_port;
    let socks_enabled = patch.verge_socks_enabled;
    let socks_port = patch.verge_socks_port;
    let http_enabled = patch.verge_http_enabled;
    let http_port = patch.verge_port;
    #[cfg(target_os = "macos")]
    let enable_tray_speed = patch.enable_tray_speed;
    #[cfg(not(target_os = "macos"))]
    let enable_tray_speed: Option<bool> = None;
    // let enable_tray_icon = patch.enable_tray_icon;
    let enable_global_hotkey = patch.enable_global_hotkey;
    let tray_event = &patch.tray_event;
    let home_cards = patch.home_cards.as_ref();
    let enable_auto_light_weight = patch.enable_auto_light_weight_mode;
    let enable_external_controller = patch.enable_external_controller;
    let tray_proxy_groups_display_mode = &patch.tray_proxy_groups_display_mode;
    let tray_inline_outbound_modes = patch.tray_inline_outbound_modes;
    let enable_proxy_guard = patch.enable_proxy_guard;
    let proxy_guard_duration = patch.proxy_guard_duration;
    let log_level = &patch.app_log_level;
    let log_max_size = patch.app_log_max_size;
    let log_max_count = patch.app_log_max_count;

    #[cfg(target_os = "windows")]
    let restart_core_needed = socks_enabled.is_some()
        || http_enabled.is_some()
        || socks_port.is_some()
        || http_port.is_some()
        || mixed_port.is_some()
        || enable_external_controller.is_some();
    #[cfg(not(target_os = "windows"))]
    let mut restart_core_needed = socks_enabled.is_some()
        || http_enabled.is_some()
        || socks_port.is_some()
        || http_port.is_some()
        || mixed_port.is_some()
        || enable_external_controller.is_some();
    #[cfg(not(target_os = "windows"))]
    {
        restart_core_needed |= redir_enabled.is_some() || redir_port.is_some();
    }
    #[cfg(target_os = "linux")]
    {
        restart_core_needed |= tproxy_enabled.is_some() || tproxy_port.is_some();
        restart_core_needed |= tun_mode == Some(true);
    }

    let mut update_flags = UpdateFlags::empty();
    if restart_core_needed {
        update_flags.insert(UpdateFlags::RESTART_CORE);
    }
    if tun_mode.is_some() {
        update_flags.insert(UpdateFlags::CLASH_CONFIG | UpdateFlags::GROUP_SYS_TRAY);
    }
    if enable_global_hotkey.is_some() || home_cards.is_some() {
        update_flags.insert(UpdateFlags::VERGE_CONFIG);
    }
    if auto_launch.is_some() {
        update_flags.insert(UpdateFlags::LAUNCH);
    }
    if system_proxy.is_some() {
        update_flags.insert(UpdateFlags::SYS_PROXY | UpdateFlags::GROUP_SYS_TRAY);
    }
    if proxy_bypass.is_some()
        || pac_content.is_some()
        || pac.is_some()
        || enable_proxy_guard.is_some()
        || proxy_guard_duration.is_some()
    {
        update_flags.insert(UpdateFlags::SYS_PROXY);
    }
    if language.is_some() {
        update_flags.insert(UpdateFlags::LANGUAGE | UpdateFlags::SYSTRAY_MENU | UpdateFlags::SYSTRAY_TOOLTIP);
    }
    if common_tray_icon.is_some()
        || sysproxy_tray_icon.is_some()
        || tun_tray_icon.is_some()
        || tray_icon.is_some()
        || enable_tray_speed.is_some()
    {
        update_flags.insert(UpdateFlags::SYSTRAY_ICON);
    }
    if patch.hotkeys.is_some() {
        update_flags.insert(UpdateFlags::HOTKEY | UpdateFlags::SYSTRAY_MENU);
    }
    if tray_event.is_some() {
        update_flags.insert(UpdateFlags::SYSTRAY_CLICK_BEHAVIOR);
    }
    if enable_auto_light_weight.is_some() {
        update_flags.insert(UpdateFlags::LIGHT_WEIGHT);
    }
    if tray_proxy_groups_display_mode.is_some() {
        update_flags.insert(UpdateFlags::SYSTRAY_MENU);
    }
    if log_level.is_some() {
        update_flags.insert(UpdateFlags::LOG_LEVEL);
    }
    if log_max_size.is_some() || log_max_count.is_some() {
        update_flags.insert(UpdateFlags::LOG_FILE);
    }
    if tray_inline_outbound_modes.is_some() {
        update_flags.insert(UpdateFlags::SYSTRAY_MENU);
    }

    update_flags
}

#[allow(clippy::cognitive_complexity)]
async fn process_terminated_flags(manager: &CoreManager, update_flags: UpdateFlags, patch: &IVerge) -> Result<()> {
    // Process updates based on flags
    if update_flags.contains(UpdateFlags::RESTART_CORE) {
        Config::generate().await?;
        manager.restart_core_in_transaction().await?;
    }
    if update_flags.contains(UpdateFlags::CLASH_CONFIG) {
        manager.update_config_checked_in_transaction().await?;
        handle::Handle::refresh_clash();
    }
    if update_flags.contains(UpdateFlags::VERGE_CONFIG) {
        handle::Handle::refresh_verge();
    }
    if update_flags.contains(UpdateFlags::LAUNCH) {
        autostart::update_launch().await?;
    }
    if update_flags.contains(UpdateFlags::LANGUAGE)
        && let Some(language) = &patch.language
    {
        clash_verge_i18n::set_locale(language.as_str());
    }
    if update_flags.contains(UpdateFlags::SYS_PROXY) {
        sysopt::Sysopt::global().update_sysproxy().await?;
        sysopt::Sysopt::global().refresh_guard().await;
    }
    if update_flags.contains(UpdateFlags::HOTKEY)
        && let Some(hotkeys) = &patch.hotkeys
    {
        hotkey::Hotkey::global().update(hotkeys.to_owned()).await?;
    }
    if update_flags.contains(UpdateFlags::SYSTRAY_MENU) {
        tray::Tray::global().update_menu().await?;
    }
    if update_flags.contains(UpdateFlags::SYSTRAY_ICON) {
        tray::Tray::global()
            .update_icon(&Config::verge().await.latest_arc())
            .await?;
        #[cfg(target_os = "macos")]
        if patch.enable_tray_speed.is_some() {
            tray::Tray::global().update_speed_task(patch.enable_tray_speed.unwrap_or(false));
        }
    }
    if update_flags.contains(UpdateFlags::SYSTRAY_TOOLTIP) {
        tray::Tray::global().update_tooltip().await?;
    }
    if update_flags.contains(UpdateFlags::SYSTRAY_CLICK_BEHAVIOR) {
        tray::Tray::global().update_click_behavior().await?;
    }
    if update_flags.contains(UpdateFlags::LIGHT_WEIGHT) {
        if patch.enable_auto_light_weight_mode.unwrap_or(false) {
            lightweight::enable_auto_light_weight_mode().await;
        } else {
            lightweight::disable_auto_light_weight_mode();
        }
    }
    if update_flags.contains(UpdateFlags::LOG_LEVEL) {
        Logger::global().update_log_level(patch.get_log_level())?;
    }
    if update_flags.contains(UpdateFlags::LOG_FILE) {
        let log_max_size = patch.app_log_max_size.unwrap_or(128);
        let log_max_count = patch.app_log_max_count.unwrap_or(8);
        Logger::global().update_log_config(log_max_size, log_max_count).await?;
    }
    Ok(())
}

fn non_runtime_side_effect_flags(update_flags: UpdateFlags) -> UpdateFlags {
    update_flags.difference(UpdateFlags::RESTART_CORE | UpdateFlags::CLASH_CONFIG)
}

async fn restore_non_runtime_side_effects(
    manager: &CoreManager,
    update_flags: UpdateFlags,
    verge_before: &IVerge,
) -> Vec<std::string::String> {
    let rollback_flags = non_runtime_side_effect_flags(update_flags);
    let mut rollback_patch = verge_before.clone();

    // `None` is a valid legacy value, but restoring it still has to undo a
    // newly registered hotkey set / locale / macOS tray-speed task.
    if rollback_flags.contains(UpdateFlags::HOTKEY) && rollback_patch.hotkeys.is_none() {
        rollback_patch.hotkeys = Some(Vec::new());
    }
    if rollback_flags.contains(UpdateFlags::LANGUAGE) && rollback_patch.language.is_none() {
        rollback_patch.language = Some(clash_verge_i18n::system_language().into());
    }
    #[cfg(target_os = "macos")]
    if rollback_flags.contains(UpdateFlags::SYSTRAY_ICON) && rollback_patch.enable_tray_speed.is_none() {
        rollback_patch.enable_tray_speed = Some(false);
    }

    let ordered_flags = [
        UpdateFlags::VERGE_CONFIG,
        UpdateFlags::LAUNCH,
        UpdateFlags::LANGUAGE,
        UpdateFlags::SYS_PROXY,
        UpdateFlags::HOTKEY,
        UpdateFlags::SYSTRAY_MENU,
        UpdateFlags::SYSTRAY_ICON,
        UpdateFlags::SYSTRAY_TOOLTIP,
        UpdateFlags::SYSTRAY_CLICK_BEHAVIOR,
        UpdateFlags::LIGHT_WEIGHT,
        UpdateFlags::LOG_LEVEL,
        UpdateFlags::LOG_FILE,
    ];
    let mut errors = Vec::new();
    for flag in ordered_flags {
        if rollback_flags.contains(flag)
            && let Err(error) = process_terminated_flags(manager, flag, &rollback_patch).await
        {
            errors.push(format!("{flag:?} side-effect rollback failed: {error:#}"));
        }
    }
    errors
}

pub async fn patch_verge(patch: &IVerge, not_save_file: bool) -> Result<()> {
    let manager = CoreManager::global();
    let _transaction = manager.begin_config_transaction().await;
    patch_verge_in_transaction(manager, patch, not_save_file).await
}

pub(crate) async fn patch_verge_in_transaction(
    manager: &CoreManager,
    patch: &IVerge,
    not_save_file: bool,
) -> Result<()> {
    let verge_before = (**Config::verge().await.data_arc()).clone();
    let runtime_before = (**Config::runtime().await.data_arc()).clone();

    let update_flags = determine_update_flags(patch);
    let runtime_may_change = update_flags.intersects(UpdateFlags::RESTART_CORE | UpdateFlags::CLASH_CONFIG);
    #[cfg(target_os = "windows")]
    let ics_fields_changed = patch.enable_windows_ics_recovery.is_some()
        || patch.windows_ics_private_adapter_guid.is_some()
        || patch.windows_ics_private_adapter_name.is_some();
    #[cfg(target_os = "windows")]
    let service_sync_required = service::windows_ics_service_sync_required(
        matches!(*manager.get_running_mode(), RunningMode::Service),
        verge_before.enable_windows_ics_recovery,
        patch.enable_windows_ics_recovery,
    );
    #[cfg(target_os = "windows")]
    let explicit_ics_sync_required = ics_fields_changed && service_sync_required;
    #[cfg(target_os = "windows")]
    let service_sync_may_have_occurred = (runtime_may_change && service_sync_required) || explicit_ics_sync_required;
    #[cfg(target_os = "windows")]
    let service_before = if service_sync_may_have_occurred {
        Some(service::snapshot_windows_ics_recovery().await?)
    } else {
        None
    };
    Config::verge().await.edit_draft(|d| d.patch_config(patch));
    logging!(debug, Type::Setup, "Determined update flags: {:?}", update_flags);
    let transaction_result: Result<()> = async {
        process_terminated_flags(manager, update_flags, patch).await?;
        #[cfg(target_os = "windows")]
        if explicit_ics_sync_required {
            let verge_current = Config::verge().await.latest_arc();
            let runtime_current = Config::runtime().await.data_arc();
            service::configure_windows_ics_recovery_for_config(&verge_current, &runtime_current).await?;
        }
        if !not_save_file {
            logging!(debug, Type::Setup, "Saving Verge configuration to file...");
            Config::verge().await.latest_arc().save_file().await?;
        }
        Ok(())
    }
    .await;

    if let Err(err) = transaction_result {
        let verge = Config::verge().await;
        verge.edit_draft(|draft| *draft = verge_before.clone());
        verge.apply();
        let mut rollback_errors = Vec::new();
        if runtime_may_change && let Err(rollback_error) = manager.restore_runtime_in_transaction(&runtime_before).await
        {
            rollback_errors.push(format!("runtime rollback failed: {rollback_error:#}"));
        }
        #[cfg(target_os = "windows")]
        if service_sync_may_have_occurred
            && let Some(snapshot) = service_before.as_ref()
            && let Err(rollback_error) = service::restore_windows_ics_recovery_snapshot(snapshot).await
        {
            rollback_errors.push(format!("service rollback failed: {rollback_error:#}"));
        }
        if !not_save_file && let Err(rollback_error) = verge_before.save_file().await {
            rollback_errors.push(format!("verge file rollback failed: {rollback_error:#}"));
        }
        rollback_errors.extend(restore_non_runtime_side_effects(manager, update_flags, &verge_before).await);
        return if rollback_errors.is_empty() {
            Err(err)
        } else {
            Err(err.context(format!("rollback errors: {}", rollback_errors.join("; "))))
        };
    }
    let verge = Config::verge().await;
    verge.apply();
    logging_error!(Type::Backup, AutoBackupManager::global().refresh_settings().await);
    #[cfg(target_os = "windows")]
    if patch.enable_tun_mode.is_some()
        || patch.enable_windows_ics_recovery.is_some()
        || patch.windows_ics_private_adapter_guid.is_some()
        || patch.windows_ics_private_adapter_name.is_some()
    {
        service::schedule_windows_ics_recovery("verge-config-changed");
    }
    Ok(())
}

pub async fn fetch_verge_config() -> Result<SharedDraft<IVerge>> {
    let draft = Config::verge().await;
    let data = draft.data_arc();
    Ok(data)
}

#[cfg(test)]
mod tests {
    use super::{UpdateFlags, non_runtime_side_effect_flags};

    #[test]
    fn verge_rollback_replays_every_non_runtime_side_effect_only() {
        let all = UpdateFlags::all();
        let rollback = non_runtime_side_effect_flags(all);

        assert!(!rollback.intersects(UpdateFlags::RESTART_CORE | UpdateFlags::CLASH_CONFIG));
        assert!(rollback.contains(UpdateFlags::LAUNCH));
        assert!(rollback.contains(UpdateFlags::SYS_PROXY));
        assert!(rollback.contains(UpdateFlags::LANGUAGE));
        assert!(rollback.contains(UpdateFlags::HOTKEY));
        assert!(rollback.contains(UpdateFlags::GROUP_SYS_TRAY));
        assert!(rollback.contains(UpdateFlags::SYSTRAY_CLICK_BEHAVIOR));
        assert!(rollback.contains(UpdateFlags::LIGHT_WEIGHT));
        assert!(rollback.contains(UpdateFlags::LOG_LEVEL | UpdateFlags::LOG_FILE));
    }
}
