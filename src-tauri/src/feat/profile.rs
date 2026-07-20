use crate::{
    cmd,
    config::{
        Config, PrfItem, PrfOption,
        profiles::{
            acquire_profile_download_commit, lock_profile_revision, profiles_draft_update_item_if_current_safe,
        },
    },
    core::{CoreManager, handle, tray, validate::ValidationOutcome},
    utils::help::{mask_err, mask_url},
};
use anyhow::{Result, bail};
use clash_verge_logging::{Type, logging, logging_error};
use smartstring::alias::String;
use tauri::Emitter as _;

/// Toggle proxy profile
pub async fn toggle_proxy_profile(profile_index: String) {
    logging_error!(
        Type::Config,
        cmd::patch_profiles_config_by_profile_index(profile_index).await
    );
}

pub async fn switch_proxy_node(group_name: &str, proxy_name: &str) {
    match handle::Handle::mihomo()
        .await
        .select_node_for_group(group_name, proxy_name)
        .await
    {
        Ok(_) => {
            logging!(info, Type::Tray, "切换代理成功: {} -> {}", group_name, proxy_name);
            let _ = handle::Handle::app_handle().emit("verge://refresh-proxy-config", ());
            let _ = tray::Tray::global().update_menu().await;
            return;
        }
        Err(err) => {
            logging!(
                error,
                Type::Tray,
                "切换代理失败: {} -> {}, 错误: {:?}",
                group_name,
                proxy_name,
                err
            );
        }
    }

    match handle::Handle::mihomo()
        .await
        .select_node_for_group(group_name, proxy_name)
        .await
    {
        Ok(_) => {
            logging!(info, Type::Tray, "代理切换回退成功: {} -> {}", group_name, proxy_name);
            let _ = tray::Tray::global().update_menu().await;
        }
        Err(err) => {
            logging!(
                error,
                Type::Tray,
                "代理切换最终失败: {} -> {}, 错误: {:?}",
                group_name,
                proxy_name,
                err
            );
        }
    }
}

async fn should_update_profile(uid: &String, ignore_auto_update: bool) -> Result<Option<(String, Option<PrfOption>)>> {
    let profiles = Config::profiles().await;
    let profiles = profiles.latest_arc();
    let item = profiles.get_item(uid)?;
    let is_remote = item.itype.as_ref().is_some_and(|s| s == "remote");

    if !is_remote {
        logging!(info, Type::Config, "[订阅更新] {uid} 不是远程订阅，跳过更新");
        Ok(None)
    } else if item.url.is_none() {
        logging!(warn, Type::Config, "Warning: [订阅更新] {uid} 缺少URL，无法更新");
        bail!("failed to get the profile item url");
    } else if !ignore_auto_update && !item.option.as_ref().and_then(|o| o.allow_auto_update).unwrap_or(true) {
        logging!(info, Type::Config, "[订阅更新] {} 禁止自动更新，跳过更新", uid);
        Ok(None)
    } else {
        logging!(
            info,
            Type::Config,
            "[订阅更新] {} 是远程订阅，URL: {}",
            uid,
            mask_url(
                item.url
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("Profile URL is None"))?
            )
        );
        Ok(Some((
            item.url.clone().ok_or_else(|| anyhow::anyhow!("Profile URL is None"))?,
            item.option.clone(),
        )))
    }
}

fn profile_download_snapshot_matches(item: Option<&PrfItem>, url: &String, option: Option<&PrfOption>) -> bool {
    item.is_some_and(|item| {
        item.itype.as_deref() == Some("remote") && item.url.as_ref() == Some(url) && item.option.as_ref() == option
    })
}

async fn perform_profile_update(
    uid: &String,
    url: &String,
    opt: Option<&PrfOption>,
    option: Option<&PrfOption>,
    is_mannual_trigger: bool,
) -> Result<(Option<PrfItem>, Option<String>)> {
    logging!(info, Type::Config, "[订阅更新] 开始下载新的订阅内容");
    let mut merged_opt = PrfOption::merge(opt, option);
    let profiles = Config::profiles().await;
    let profiles_arc = profiles.latest_arc();
    let profile_name = profiles_arc
        .get_name_by_uid(uid)
        .cloned()
        .unwrap_or_else(|| String::from("UnKnown Profile"));

    let mut last_err;

    match PrfItem::from_url(url, None, None, merged_opt.as_ref()).await {
        Ok(item) => {
            logging!(info, Type::Config, "[订阅更新] 更新订阅配置成功");
            return Ok((Some(item), None));
        }
        Err(err) => {
            logging!(
                warn,
                Type::Config,
                "Warning: [订阅更新] 正常更新失败: {}，尝试使用Clash代理更新",
                mask_err(&err.to_string())
            );
            last_err = err;
        }
    }

    merged_opt.get_or_insert_with(PrfOption::default).self_proxy = Some(true);
    merged_opt.get_or_insert_with(PrfOption::default).with_proxy = Some(false);

    match PrfItem::from_url(url, None, None, merged_opt.as_ref()).await {
        Ok(item) => {
            logging!(info, Type::Config, "[订阅更新] 使用 Clash代理 更新订阅配置成功");
            drop(last_err);
            return Ok((Some(item), Some(profile_name)));
        }
        Err(err) => {
            logging!(
                warn,
                Type::Config,
                "Warning: [订阅更新] Clash代理更新失败: {}，尝试使用系统代理更新",
                mask_err(&err.to_string())
            );
            last_err = err;
        }
    }

    merged_opt.get_or_insert_with(PrfOption::default).self_proxy = Some(false);
    merged_opt.get_or_insert_with(PrfOption::default).with_proxy = Some(true);

    match PrfItem::from_url(url, None, None, merged_opt.as_ref()).await {
        Ok(item) => {
            logging!(info, Type::Config, "[订阅更新] 使用 系统代理 更新订阅配置成功");
            drop(last_err);
            return Ok((Some(item), Some(profile_name)));
        }
        Err(err) => {
            logging!(
                warn,
                Type::Config,
                "Warning: [订阅更新] 系统代理更新失败: {}，所有重试均已失败",
                mask_err(&err.to_string())
            );
            last_err = err;
        }
    }

    if is_mannual_trigger {
        handle::Handle::notice_message("update_failed_even_with_clash", format!("{profile_name} - {last_err}"));
    }
    Ok((None, None))
}

// The caller holds CoreManager's configuration transaction gate. Revalidate
// only after acquiring it so an in-flight profile edit cannot be overwritten
// by a download that used an older URL or option set.
async fn revalidate_downloaded_profile(
    uid: &String,
    snapshot: Option<&(String, Option<PrfOption>)>,
    downloaded_item: Option<PrfItem>,
    proxy_notice: Option<String>,
) -> (Option<PrfItem>, Option<String>) {
    if downloaded_item.is_none() {
        return (downloaded_item, proxy_notice);
    }

    let snapshot_matches = match snapshot {
        Some((url, option)) => {
            let profiles = Config::profiles().await;
            let profiles = profiles.latest_arc();
            profile_download_snapshot_matches(profiles.get_item(uid).ok(), url, option.as_ref())
        }
        None => false,
    };
    if snapshot_matches {
        (downloaded_item, proxy_notice)
    } else {
        logging!(
            info,
            Type::Config,
            "profile {uid} changed while its update was downloading; discarding the stale result"
        );
        (None, None)
    }
}

async fn refresh_profile_runtime(manager: &CoreManager, is_mannual_trigger: bool) {
    logging!(info, Type::Config, "[订阅更新] 更新内核配置");
    match manager
        .update_config_with_force_in_transaction(is_mannual_trigger)
        .await
    {
        Ok(outcome) if outcome.is_valid() => {
            logging!(info, Type::Config, "[订阅更新] 更新成功");
            handle::Handle::refresh_clash();
        }
        Ok(outcome @ (ValidationOutcome::Skipped { .. } | ValidationOutcome::Busy)) if !is_mannual_trigger => {
            logging!(info, Type::Config, "[订阅更新] 本次配置刷新已跳过: {}", outcome);
        }
        Ok(outcome) => {
            let message = outcome.to_string();
            logging!(error, Type::Config, "[订阅更新] 更新失败: {}", message);
            handle::Handle::notice_message("update_failed", message);
        }
        Err(err) => {
            logging!(error, Type::Config, "[订阅更新] 更新失败: {}", err);
            handle::Handle::notice_message("update_failed", format!("{err}"));
            logging!(error, Type::Config, "{err}");
        }
    }
}

pub async fn update_profile(
    uid: &String,
    option: Option<&PrfOption>,
    auto_refresh: bool,
    ignore_auto_update: bool,
    is_mannual_trigger: bool,
) -> Result<()> {
    logging!(info, Type::Config, "[订阅更新] 开始更新订阅 {}", uid);
    // Bind the URL/options snapshot and its revision while holding the same
    // UID gate used by file edits, imports, deletes, and downloaded commits.
    // A same-UID writer cannot slip into the old-read -> new-token gap.
    let profile_revision = lock_profile_revision(uid).await;
    let url_opt = should_update_profile(uid, ignore_auto_update).await?;
    // Downloads intentionally happen outside the global configuration gate.
    // Give each real download a latest-wins revision so a skipped timer
    // check does not cancel a manual update, while an older completed download
    // still cannot commit after a newer request with identical URL/options.
    let update_revision = url_opt.as_ref().map(|_| profile_revision.begin_download());
    drop(profile_revision);
    let download_snapshot = url_opt.clone();

    let (downloaded_item, proxy_notice) = match url_opt {
        Some((url, opt)) => perform_profile_update(uid, &url, opt.as_ref(), option, is_mannual_trigger).await?,
        None => (None, None),
    };

    if downloaded_item.is_some() || auto_refresh {
        let manager = CoreManager::global();
        let _transaction = manager.begin_config_transaction().await;
        // A new request must advance its revision through the same per-UID
        // gate held from this final check through profile persistence. This
        // makes latest-wins linearizable: once the old request is admitted to
        // commit, a newer request begins after that commit; otherwise the old
        // result is discarded before it can touch disk.
        let profile_commit = match update_revision.as_ref() {
            Some(revision) => match acquire_profile_download_commit(uid, revision).await {
                Some(commit) => Some(commit),
                None => {
                    logging!(info, Type::Config, "discarding stale profile update for {uid}");
                    return Ok(());
                }
            },
            None => None,
        };
        let (downloaded_item, proxy_notice) =
            revalidate_downloaded_profile(uid, download_snapshot.as_ref(), downloaded_item, proxy_notice).await;
        if let Some(mut item) = downloaded_item {
            let Some(commit) = profile_commit.as_ref() else {
                bail!("downloaded profile update has no revision commit guard");
            };
            if !profiles_draft_update_item_if_current_safe(uid, &mut item, commit).await? {
                logging!(info, Type::Config, "discarding stale profile update for {uid}");
                return Ok(());
            }
            if let Some(profile_name) = proxy_notice {
                handle::Handle::notice_message("update_with_clash_proxy", profile_name);
            }
        }
        // Profile data is now committed. A later request may become the new
        // revision while this request refreshes the core, which correctly
        // linearizes that request after this persisted update.
        drop(profile_commit);
        // Preserve the legacy explicit-refresh behavior when no download was
        // due. A real download refreshes the runtime only for the active
        // profile, as before.
        let should_refresh = auto_refresh
            && (update_revision.is_none() || Config::profiles().await.latest_arc().is_current_profile_index(uid));
        if !should_refresh {
            return Ok(());
        }
        refresh_profile_runtime(manager, is_mannual_trigger).await;
    }

    Ok(())
}

/// 增强配置
pub async fn enhance_profiles() -> Result<ValidationOutcome> {
    CoreManager::global().update_config_forced().await
}

#[cfg(test)]
mod tests {
    use super::profile_download_snapshot_matches;
    use crate::config::{
        PrfItem, PrfOption,
        profiles::{
            acquire_profile_download_commit, begin_profile_bulk_mutation, begin_profile_mutation, lock_profile_revision,
        },
    };
    use std::time::Duration;

    fn remote_item(url: &str, option: Option<PrfOption>) -> PrfItem {
        PrfItem {
            itype: Some("remote".into()),
            url: Some(url.into()),
            option,
            ..PrfItem::default()
        }
    }

    #[test]
    fn downloaded_profile_requires_its_original_url_and_options() {
        let option = PrfOption {
            user_agent: Some("snapshot-agent".into()),
            ..PrfOption::default()
        };
        let item = remote_item("https://example.test/profile", Some(option.clone()));
        let url = "https://example.test/profile".into();

        assert!(profile_download_snapshot_matches(Some(&item), &url, Some(&option)));
        assert!(!profile_download_snapshot_matches(
            Some(&remote_item("https://example.test/changed", Some(option.clone()))),
            &url,
            Some(&option)
        ));
        assert!(!profile_download_snapshot_matches(
            Some(&remote_item("https://example.test/profile", None)),
            &url,
            Some(&option)
        ));
        assert!(!profile_download_snapshot_matches(None, &url, Some(&option)));
    }

    #[tokio::test]
    async fn content_save_bulk_restore_and_latest_request_invalidate_old_downloads() -> anyhow::Result<()> {
        let uid: smartstring::alias::String = "profile-revision-save".into();
        let option = PrfOption {
            user_agent: Some("same-metadata".into()),
            ..PrfOption::default()
        };
        let unchanged_item = remote_item("https://example.test/same", Some(option.clone()));
        let unchanged_url = "https://example.test/same".into();

        let download = lock_profile_revision(&uid).await;
        let before_save = download.begin_download();
        drop(download);
        assert!(profile_download_snapshot_matches(
            Some(&unchanged_item),
            &unchanged_url,
            Some(&option)
        ));

        // This is the revision boundary used by save_profile_file: content can
        // change while type/URL/options stay byte-for-byte identical.
        let save = begin_profile_mutation(&uid).await;
        drop(save);
        assert!(acquire_profile_download_commit(&uid, &before_save).await.is_none());

        let old = lock_profile_revision(&uid).await;
        let old_token = old.begin_download();
        drop(old);
        let latest = lock_profile_revision(&uid).await;
        let latest_token = latest.begin_download();
        drop(latest);
        assert!(acquire_profile_download_commit(&uid, &old_token).await.is_none());

        let latest_commit = acquire_profile_download_commit(&uid, &latest_token)
            .await
            .ok_or_else(|| anyhow::anyhow!("latest request should reach its commit boundary"))?;
        let newer = {
            let uid = uid.clone();
            tokio::spawn(async move {
                let revision = lock_profile_revision(&uid).await;
                revision.begin_download()
            })
        };
        tokio::task::yield_now().await;
        assert!(
            !newer.is_finished(),
            "a newer request must not cross the old request's checked commit boundary"
        );

        let other_uid: smartstring::alias::String = "profile-revision-other".into();
        let other = tokio::time::timeout(Duration::from_secs(1), lock_profile_revision(&other_uid)).await?;
        drop(other);
        drop(latest_commit);
        let _newer_token = newer.await?;

        let bulk_uid: smartstring::alias::String = "profile-revision-bulk".into();
        let before_bulk = lock_profile_revision(&bulk_uid).await;
        let before_bulk_token = before_bulk.begin_download();
        drop(before_bulk);
        let bulk = begin_profile_bulk_mutation(vec![bulk_uid.clone()]).await;
        drop(bulk);
        assert!(
            acquire_profile_download_commit(&bulk_uid, &before_bulk_token)
                .await
                .is_none()
        );
        Ok(())
    }
}
