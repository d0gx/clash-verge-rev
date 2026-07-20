use super::CoreManager;
use crate::{
    config::{Config, ConfigType, runtime::IRuntime},
    constants::timing,
    core::{
        handle,
        validate::{CoreConfigValidator, ValidationOutcome, ValidationSkipReason},
    },
    utils::{dirs, help},
};
use anyhow::{Result, anyhow};
use clash_verge_logging::{Type, logging};
use smartstring::alias::String;
use std::{collections::HashSet, path::PathBuf, time::Instant};
use tauri_plugin_mihomo::Error as MihomoError;

#[cfg(target_os = "windows")]
use super::RunningMode;
#[cfg(target_os = "windows")]
use crate::config::IVerge;

#[cfg(target_os = "windows")]
fn runtime_windows_tun_config(runtime: &IRuntime) -> Option<serde_yaml_ng::Mapping> {
    runtime
        .config
        .as_ref()
        .and_then(|config| config.get("tun"))
        .and_then(serde_yaml_ng::Value::as_mapping)
        .cloned()
}

#[cfg(target_os = "windows")]
fn windows_ics_service_state_relevant(current: Option<bool>, requested: Option<bool>) -> bool {
    current.unwrap_or(false) || requested.unwrap_or(false)
}

impl CoreManager {
    pub async fn use_default_config(&self, error_key: &str, error_msg: &str) -> Result<()> {
        use crate::constants::files::RUNTIME_CONFIG;

        let runtime_path = dirs::app_home_dir()?.join(RUNTIME_CONFIG);
        let clash_config = &Config::clash().await.latest_arc().0;

        Config::runtime().await.edit_draft(|d| {
            *d = IRuntime {
                config: Some(clash_config.to_owned()),
                exists_keys: HashSet::new(),
                chain_logs: Default::default(),
            }
        });

        help::save_yaml(&runtime_path, &clash_config, Some("# Clash Verge Runtime")).await?;
        handle::Handle::notice_message(error_key, error_msg);
        Ok(())
    }

    pub async fn update_config_forced(&self) -> Result<ValidationOutcome> {
        self.update_config_with_force(true).await
    }

    pub async fn update_config_with_force(&self, force: bool) -> Result<ValidationOutcome> {
        if handle::Handle::global().is_exiting() {
            return Ok(ValidationOutcome::Skipped {
                reason: ValidationSkipReason::Exiting,
            });
        }

        let Some(_transaction) = self.try_begin_config_transaction() else {
            logging!(info, Type::Core, "Configuration update is already running");
            return Ok(ValidationOutcome::Busy);
        };

        self.update_config_with_force_in_transaction(force).await
    }

    pub(crate) async fn update_config_with_force_in_transaction(&self, force: bool) -> Result<ValidationOutcome> {
        if !force && !self.should_update_config() {
            logging!(debug, Type::Core, "Skipping config update due to debounce");
            return Ok(ValidationOutcome::Skipped {
                reason: ValidationSkipReason::Debounced,
            });
        }

        if force {
            self.set_last_update(Instant::now());
        }

        self.perform_config_update().await
    }

    pub async fn update_config_checked(&self) -> Result<()> {
        let outcome = self.update_config_forced().await?;
        Self::validation_outcome_to_result(outcome)
    }

    pub(crate) async fn update_config_checked_in_transaction(&self) -> Result<()> {
        if handle::Handle::global().is_exiting() {
            return Err(anyhow!("application is exiting"));
        }
        self.set_last_update(Instant::now());
        let outcome = self.perform_config_update().await?;
        Self::validation_outcome_to_result(outcome)
    }

    fn validation_outcome_to_result(outcome: ValidationOutcome) -> Result<()> {
        if outcome.is_valid() {
            Ok(())
        } else {
            Err(anyhow!("{outcome}"))
        }
    }

    fn should_update_config(&self) -> bool {
        let now = Instant::now();
        let last = self.get_last_update();

        if let Some(last_time) = last
            && now.duration_since(*last_time) < timing::CONFIG_UPDATE_DEBOUNCE
        {
            return false;
        }

        self.set_last_update(now);
        true
    }

    async fn perform_config_update(&self) -> Result<ValidationOutcome> {
        if let Err(err) = Config::generate().await {
            let message: String = err.to_string().into();
            Config::runtime().await.discard();
            return Ok(ValidationOutcome::invalid_from_message(message));
        }

        self.apply_generate_config_inner().await
    }

    pub(crate) async fn update_runtime_config<F>(&self, f: F) -> Result<ValidationOutcome>
    where
        F: FnOnce(&mut IRuntime),
    {
        let Some(_transaction) = self.try_begin_config_transaction() else {
            logging!(info, Type::Core, "Configuration update is already running");
            return Ok(ValidationOutcome::Busy);
        };

        Config::runtime().await.edit_draft(f);
        self.apply_generate_config_inner().await
    }

    #[cfg(target_os = "windows")]
    pub(crate) async fn patch_windows_tun_and_ics(&self, tun: &serde_yaml_ng::Mapping, ics: &IVerge) -> Result<()> {
        let _transaction = self.begin_config_transaction().await;

        // Snapshot the effective drafts, not only committed data. During cold
        // startup the runtime used by Mihomo may still live exclusively in the
        // draft until the first successful reload.
        let clash_before = (**Config::clash().await.latest_arc()).clone();
        let verge_before = (**Config::verge().await.latest_arc()).clone();
        let runtime_before = (**Config::runtime().await.latest_arc()).clone();
        // Admin users may run Mihomo directly without installing the service.
        // When ICS recovery stays disabled, ordinary TUN edits must not acquire
        // an otherwise unnecessary dependency on the service being online.
        let ics_service_state_relevant = windows_ics_service_state_relevant(
            verge_before.enable_windows_ics_recovery,
            ics.enable_windows_ics_recovery,
        );
        let service_before = if ics_service_state_relevant {
            Some(crate::core::service::snapshot_windows_ics_recovery().await?)
        } else {
            None
        };
        let mut runtime_transaction_started = false;

        let result: Result<()> = async {
            let mut clash_patch = serde_yaml_ng::Mapping::new();
            clash_patch.insert("tun".into(), tun.clone().into());
            Config::clash()
                .await
                .edit_draft(|draft| draft.patch_config(&clash_patch));
            Config::verge().await.edit_draft(|draft| draft.patch_config(ics));

            // Regenerate from the complete enhanced configuration so Merge and
            // Script overrides become the source of truth for the ICS target.
            Config::generate().await?;
            // apply_config may fall back to a full service restart, which
            // synchronizes the new desired ICS state before returning. From
            // this point onward rollback must therefore restore runtime and,
            // when ICS recovery is involved, service state even if apply_config
            // ultimately fails.
            runtime_transaction_started = true;
            let outcome = self.apply_generate_config_inner_with_ics_schedule(false).await?;
            if !outcome.is_valid() {
                return Err(anyhow!(outcome.to_string()));
            }
            if ics_service_state_relevant {
                let verge_current = Config::verge().await.latest_arc();
                let runtime_current = Config::runtime().await.data_arc();
                crate::core::service::configure_windows_ics_recovery_for_config(&verge_current, &runtime_current)
                    .await?;
            }

            let clash = Config::clash().await;
            let verge = Config::verge().await;
            clash.apply();
            verge.apply();
            clash.data_arc().save_config().await?;
            verge.data_arc().save_file().await?;
            Ok(())
        }
        .await;

        if let Err(error) = result {
            let clash = Config::clash().await;
            clash.edit_draft(|draft| *draft = clash_before.clone());
            clash.apply();
            let verge = Config::verge().await;
            verge.edit_draft(|draft| *draft = verge_before.clone());
            verge.apply();

            let mut rollback_errors = Vec::new();
            let runtime = Config::runtime().await;
            runtime.edit_draft(|draft| *draft = runtime_before.clone());
            if runtime_transaction_started {
                match Config::generate_file(ConfigType::Run).await {
                    Ok(path) => {
                        if let Err(rollback_error) = self.apply_config(path).await {
                            rollback_errors.push(format!("runtime rollback failed: {rollback_error:#}"));
                        }
                    }
                    Err(rollback_error) => {
                        rollback_errors.push(format!("runtime rollback file failed: {rollback_error:#}"));
                    }
                }
            }

            if runtime_transaction_started
                && let Some(snapshot) = service_before.as_ref()
                && let Err(rollback_error) = crate::core::service::restore_windows_ics_recovery_snapshot(snapshot).await
            {
                rollback_errors.push(format!("service rollback failed: {rollback_error:#}"));
            }
            if let Err(rollback_error) = clash_before.save_config().await {
                rollback_errors.push(format!("clash file rollback failed: {rollback_error:#}"));
            }
            if let Err(rollback_error) = verge_before.save_file().await {
                rollback_errors.push(format!("verge file rollback failed: {rollback_error:#}"));
            }

            if rollback_errors.is_empty() {
                return Err(error);
            }
            return Err(error.context(format!("rollback errors: {}", rollback_errors.join("; "))));
        }

        Ok(())
    }

    async fn apply_generate_config_inner(&self) -> Result<ValidationOutcome> {
        self.apply_generate_config_inner_with_ics_schedule(true).await
    }

    async fn apply_generate_config_inner_with_ics_schedule(
        &self,
        schedule_ics_recovery: bool,
    ) -> Result<ValidationOutcome> {
        #[cfg(target_os = "windows")]
        let (tun_changed, runtime_before, verge_before) = {
            let runtime = Config::runtime().await;
            let runtime_before = (**runtime.data_arc()).clone();
            (
                runtime_windows_tun_config(&runtime_before) != runtime_windows_tun_config(&runtime.latest_arc()),
                runtime_before,
                (**Config::verge().await.data_arc()).clone(),
            )
        };
        #[cfg(target_os = "windows")]
        let service_sync_required = if schedule_ics_recovery && tun_changed {
            let verge_current = Config::verge().await.latest_arc();
            crate::core::service::windows_ics_service_sync_required(
                matches!(*self.get_running_mode(), RunningMode::Service),
                verge_before.enable_windows_ics_recovery,
                verge_current.enable_windows_ics_recovery,
            )
        } else {
            false
        };
        #[cfg(target_os = "windows")]
        let service_before = if service_sync_required {
            match crate::core::service::snapshot_windows_ics_recovery().await {
                Ok(snapshot) => Some(snapshot),
                Err(error) => {
                    Config::runtime().await.discard();
                    return Err(error);
                }
            }
        } else {
            None
        };

        match CoreConfigValidator::global().validate_config_outcome().await {
            Ok(outcome) if outcome.is_valid() => {
                self.apply_pending_runtime_config().await?;
                #[cfg(target_os = "windows")]
                if schedule_ics_recovery && tun_changed {
                    let verge_current = Config::verge().await.latest_arc();
                    let runtime_current = Config::runtime().await.data_arc();
                    if service_sync_required
                        && let Err(error) = crate::core::service::configure_windows_ics_recovery_for_config(
                            &verge_current,
                            &runtime_current,
                        )
                        .await
                    {
                        let mut rollback_errors = Vec::new();
                        if let Err(rollback_error) = self.restore_runtime_in_transaction(&runtime_before).await {
                            rollback_errors.push(format!("runtime rollback failed: {rollback_error:#}"));
                        }
                        if let Some(snapshot) = service_before.as_ref()
                            && let Err(rollback_error) =
                                crate::core::service::restore_windows_ics_recovery_snapshot(snapshot).await
                        {
                            rollback_errors.push(format!("service rollback failed: {rollback_error:#}"));
                        }
                        return if rollback_errors.is_empty() {
                            Err(error)
                        } else {
                            Err(error.context(format!("rollback errors: {}", rollback_errors.join("; "))))
                        };
                    }
                }
                Ok(ValidationOutcome::Valid)
            }
            Ok(outcome) => {
                Config::runtime().await.discard();
                Ok(outcome)
            }
            Err(e) => {
                Config::runtime().await.discard();
                Err(e)
            }
        }
    }

    async fn apply_pending_runtime_config(&self) -> Result<()> {
        let result = async {
            let run_path = Config::generate_file(ConfigType::Run).await?;
            self.apply_config(run_path).await
        }
        .await;

        if result.is_err() {
            // apply_config also discards on a failed restart. Repeat the
            // idempotent rollback here to cover failures before it reaches
            // reload/restart (for example path conversion or Run-file I/O).
            Config::runtime().await.discard();
        }
        result
    }

    pub(crate) async fn restore_runtime_in_transaction(&self, runtime_before: &IRuntime) -> Result<()> {
        Config::runtime()
            .await
            .edit_draft(|draft| *draft = runtime_before.clone());
        let run_path = Config::generate_file(ConfigType::Run).await?;
        self.apply_config(run_path).await
    }

    async fn apply_config(&self, path: PathBuf) -> Result<()> {
        let path = dirs::path_to_str(&path)?;
        match self.reload_config(path).await {
            Ok(_) => {
                Config::runtime().await.apply();
                logging!(info, Type::Core, "Configuration applied");
                Ok(())
            }
            Err(err) => {
                logging!(
                    warn,
                    Type::Core,
                    "Failed to apply configuration by mihomo api, restart core to apply it, error msg: {err}"
                );
                match self.restart_core_in_transaction().await {
                    Ok(_) => {
                        Config::runtime().await.apply();
                        logging!(info, Type::Core, "Configuration applied after restart");
                        Ok(())
                    }
                    Err(err) => {
                        logging!(error, Type::Core, "Failed to restart core: {}", err);
                        Config::runtime().await.discard();
                        Err(anyhow!("Failed to apply config: {}", err))
                    }
                }
            }
        }
    }

    async fn reload_config(&self, path: &str) -> Result<(), MihomoError> {
        handle::Handle::mihomo().await.reload_config(true, path).await
    }
}

#[cfg(all(test, target_os = "windows"))]
mod windows_ics_runtime_tests {
    use super::{runtime_windows_tun_config, windows_ics_service_state_relevant};
    use crate::config::runtime::IRuntime;
    use serde_yaml_ng::{Mapping, Value};

    fn runtime_with_tun(tun: Mapping) -> IRuntime {
        let mut config = Mapping::new();
        config.insert(Value::from("tun"), Value::Mapping(tun));
        IRuntime {
            config: Some(config),
            ..IRuntime::default()
        }
    }

    #[test]
    fn detects_changes_to_any_effective_tun_field() {
        let mut before = Mapping::new();
        before.insert(Value::from("enable"), Value::Bool(true));
        before.insert(Value::from("device"), Value::from("Mihomo"));
        before.insert(Value::from("mtu"), Value::from(1500));

        let mut after = before.clone();
        after.insert(Value::from("mtu"), Value::from(1400));

        assert_ne!(
            runtime_windows_tun_config(&runtime_with_tun(before)),
            runtime_windows_tun_config(&runtime_with_tun(after))
        );
    }

    #[test]
    fn ignores_changes_outside_the_tun_mapping() {
        let mut tun = Mapping::new();
        tun.insert(Value::from("enable"), Value::Bool(true));
        let before = runtime_with_tun(tun.clone());
        let mut after = runtime_with_tun(tun);
        if let Some(config) = after.config.as_mut() {
            config.insert(Value::from("mode"), Value::from("global"));
        }

        assert_eq!(runtime_windows_tun_config(&before), runtime_windows_tun_config(&after));
    }

    #[test]
    fn skips_service_sync_only_when_ics_recovery_stays_disabled() {
        assert!(!windows_ics_service_state_relevant(Some(false), Some(false)));
        assert!(!windows_ics_service_state_relevant(Some(false), None));
        assert!(!windows_ics_service_state_relevant(None, Some(false)));
        assert!(!windows_ics_service_state_relevant(None, None));

        assert!(windows_ics_service_state_relevant(Some(false), Some(true)));
        assert!(windows_ics_service_state_relevant(Some(true), Some(false)));
        assert!(windows_ics_service_state_relevant(Some(true), Some(true)));
        assert!(windows_ics_service_state_relevant(Some(true), None));
    }
}
