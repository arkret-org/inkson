//! Import the account checkpoint secret without claiming content recovery.

use anyhow::{Context, Result, anyhow};
use garth::mls::backup_series::verify_series_chain;
use serde_json::{Value, json};

use super::backup_body::{
    decrypt_mls_account_secret_backup, open_mls_account_secret_recovery_public_key_backup,
};
use crate::mls::runtime::{
    active_secret_storage_series_id_for, all_secret_storage_backups, backup_series_seq_of,
    select_mls_account_secret_backup, select_mls_account_secret_recovery_public_key_backup,
    select_preferred_mls_account_secret_backup,
};

/// Offer recovery when the active series has a recoverable metadata candidate
/// and this device lacks a verified account secret. Discovery does not claim
/// that the candidate contains MLS material; unlocking its complete body and
/// validating the item, Account, policy and chain remain mandatory.
pub fn mls_restore_prompt_required(
    list_payload: &Value,
    secure_store: &dyn crate::secure_key_store::SecureKeyStore,
    authority: &arkret_sdk::AccountId,
    actor_id: &str,
    device_id: &str,
) -> bool {
    let Some(candidate) = crate::mls::runtime::select_recovery_backup_candidate(list_payload)
    else {
        tracing::warn!(
            target: "recovery_diag",
            actor_id,
            device_id,
            required = false,
            reason = "no_recovery_backup_candidate",
            "MLS restore prompt decision"
        );
        return false;
    };
    if candidate.actor_id != arkret_sdk::ActorId::account(authority.clone()) {
        return false;
    }
    let account_secret_present =
        crate::mls::runtime::load_account_mls_secret(secure_store, authority)
            .ok()
            .flatten()
            .is_some();
    let account_secret_verified =
        crate::mls::runtime::account_mls_secret_verified(secure_store, authority).unwrap_or(false);
    let required = !account_secret_present || !account_secret_verified;
    tracing::warn!(
        target: "recovery_diag",
        actor_id,
        device_id,
        account_secret_present,
        account_secret_verified,
        required,
        reason = if !account_secret_present {
            "local_account_secret_missing"
        } else if !account_secret_verified {
            "local_account_secret_unverified"
        } else {
            "account_secret_ready"
        },
        "MLS restore prompt decision"
    );
    required
}

/// A metadata candidate can contain only account state, before the first MLS
/// write. An admitted local device may distinguish that case after fetching
/// the complete active series with unlock proof. Incomplete or changing cuts
/// retain the metadata decision; a local secret never proves absence by itself.
pub(crate) fn mls_restore_prompt_required_after_material(
    metadata: &Value,
    material: Option<&Value>,
    secure_store: &dyn crate::secure_key_store::SecureKeyStore,
    authority: &arkret_sdk::AccountId,
    actor_id: &str,
    device_id: &str,
) -> bool {
    let required =
        mls_restore_prompt_required(metadata, secure_store, authority, actor_id, device_id);
    if !required {
        return false;
    }
    let Some(material) = material else {
        return true;
    };
    let Ok(list) = serde_json::from_value::<arkret_sdk::KeysBackupsPage>(metadata.clone()) else {
        return true;
    };
    let bodies = material
        .get("backups")
        .cloned()
        .and_then(|value| serde_json::from_value::<Vec<arkret_sdk::KeyBackup>>(value).ok());
    let Some(bodies) = bodies else {
        return true;
    };
    if list.has_more
        || list.next_cursor.is_some()
        || material.get("active_series") != metadata.get("active_series")
        || material.get("has_more") == Some(&Value::Bool(true))
        || material
            .get("next_cursor")
            .is_some_and(|cursor| !cursor.is_null())
        || bodies.len() != list.backups.len()
        || list.backups.iter().any(|summary| {
            bodies
                .iter()
                .filter(|body| crate::key_backup::backup_matches_summary(body, summary))
                .count()
                != 1
        })
        || bodies.iter().any(|body| {
            list.backups
                .iter()
                .filter(|summary| crate::key_backup::backup_matches_summary(body, summary))
                .count()
                != 1
        })
        || validate_backup_account(material, authority, actor_id).is_err()
        || verify_active_backup_series(material, "secret_storage").is_err()
    {
        return true;
    }
    let contains_mls_secret = bodies.iter().any(|body| {
        body.contents
            .iter()
            .any(|item| item.item_kind == arkret_sdk::SecretStorageItemKind::MlsAccountSecret)
    });
    tracing::debug!(
        contains_mls_secret,
        "complete active recovery material classified"
    );
    contains_mls_secret
}

/// Counts returned by [`auto_restore_mls_account_secret_with_passphrase`].
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AccountSecretRestoreReport {
    /// Whether the account MLS secret was imported or refreshed from the
    /// server backup on this call.
    pub account_secret_imported: bool,
}

pub(super) fn verify_active_backup_series(list_payload: &Value, backup_kind: &str) -> Result<()> {
    let class = arkret_sdk::BackupKind::try_from(backup_kind).map_err(|error| anyhow!(error))?;
    let Some(active_series) = active_secret_storage_series_id_for(list_payload, class) else {
        return Err(anyhow!(
            "{backup_kind} active-series pointer is unavailable"
        ));
    };
    let bodies = crate::mls::runtime::iter_backup_bodies(list_payload)
        .filter(|body| body.get("backup_kind").and_then(Value::as_str) == Some(backup_kind))
        .filter(|body| {
            body.get("series_id").and_then(Value::as_str) == Some(active_series.as_str())
        })
        .cloned()
        .collect::<Vec<_>>();
    let Some(tail) = bodies.iter().max_by_key(|body| backup_series_seq_of(body)) else {
        return Err(anyhow!(
            "authoritative {backup_kind} series has no envelopes"
        ));
    };
    let tail: arkret_models_crypto::KeyBackup = serde_json::from_value(tail.clone())?;
    let chain = bodies
        .into_iter()
        .map(serde_json::from_value::<arkret_models_crypto::KeyBackup>)
        .collect::<std::result::Result<Vec<_>, _>>()?;
    verify_series_chain(&tail, &chain).map_err(|error| anyhow!("{error}"))
}

pub(super) fn validate_backup_account(
    list_payload: &Value,
    authority: &arkret_sdk::AccountId,
    actor_id: &str,
) -> Result<()> {
    if crate::mls_api_helpers::principal_core_id(actor_id)? != authority.principal_id {
        return Err(anyhow!("backup restore principal binding mismatch"));
    }
    let current: arkret_sdk::BackupActiveSeriesState = serde_json::from_value(
        list_payload
            .get("active_series")
            .cloned()
            .ok_or_else(|| anyhow!("current backup pointers are unavailable"))?,
    )?;
    if current.account_id != *authority {
        return Err(anyhow!("active-series account binding mismatch"));
    }
    let expected_actor = arkret_sdk::ActorId::account(authority.clone());
    for body in crate::mls::runtime::iter_backup_bodies(list_payload) {
        if backup_actor(body)? != expected_actor {
            return Err(anyhow!("backup envelope actor binding mismatch"));
        }
    }
    Ok(())
}

fn backup_actor(body: &Value) -> Result<arkret_sdk::ActorId> {
    serde_json::from_value(
        body.get("actor_id")
            .cloned()
            .ok_or_else(|| anyhow!("backup record omits actor_id"))?,
    )
    .map_err(|error| anyhow!("invalid backup actor_id: {error}"))
}

/// Fetch metadata only for the two currently active series. Each page is
/// bounded by the wire contract; the aggregate has a separate client budget.
/// An interrupted or changing listing is never returned as a complete restore.
pub async fn fetch_mls_restore_payload(
    api: &crate::transport::TransportClient,
    actor_id: &str,
) -> Result<Value> {
    use arkret_sdk::{BackupKind, KeyBackupsListQuery};
    let discovery = api
        .list_key_backups_page(&KeyBackupsListQuery {
            series_id: None,
            backup_kind: None,
            cursor: None,
            limit: Some(1),
            agent_id: None,
        })
        .await?;
    let current = discovery.active_series;
    if current.account_id.principal_id != crate::mls_api_helpers::principal_core_id(actor_id)? {
        return Err(anyhow!("backup discovery account binding mismatch"));
    }
    let mut backups = Vec::new();
    let mut bytes = 0usize;
    for kind in [BackupKind::SecretStorage] {
        let Some(series_id) = garth::mls::backup_selection::active_series_id(&current) else {
            continue;
        };
        let series_id = series_id.clone();
        let mut query = KeyBackupsListQuery {
            series_id: Some(series_id.clone()),
            backup_kind: Some(kind),
            cursor: None,
            limit: Some(200),
            agent_id: None,
        };
        let mut seen = std::collections::BTreeSet::new();
        loop {
            let page = api.list_key_backups_page(&query).await?;
            if page.active_series != current {
                return Err(anyhow!(
                    "backup state changed during recovery discovery; retry"
                ));
            }
            bytes = bytes.saturating_add(serde_json::to_vec(&page)?.len());
            if bytes > 8 * 1024 * 1024 || backups.len() + page.backups.len() > 4096 {
                return Err(anyhow!(
                    "active backup series exceeds this device's recovery metadata budget"
                ));
            }
            backups.extend(page.backups);
            let Some(cursor) = page.next_cursor else {
                break;
            };
            if !seen.insert(cursor.to_string()) {
                return Err(anyhow!("backup listing repeated its cursor"));
            }
            query.cursor = Some(cursor);
        }
    }
    Ok(serde_json::to_value(arkret_sdk::KeysBackupsPage {
        backups,
        active_series: current,
        next_cursor: None,
        has_more: false,
    })?)
}

/// Fresh-device discovery can race the projection of backups uploaded moments
/// earlier by another device. Retry the real LIST read briefly instead of
/// caching the first empty projection for the lifetime of the app session.
pub async fn fetch_mls_restore_payload_after_projection(
    api: &crate::transport::TransportClient,
    actor_id: &str,
) -> Result<Value> {
    let mut payload = fetch_mls_restore_payload(api, actor_id).await?;
    for _ in 0..5 {
        if crate::mls::runtime::select_recovery_backup_candidate(&payload).is_some() {
            break;
        }
        crate::runtime_helpers::sleep_for(std::time::Duration::from_secs(1)).await;
        payload = fetch_mls_restore_payload(api, actor_id).await?;
    }
    Ok(payload)
}

/// An encrypted projection can arrive before its portable backup metadata.
/// Wait briefly for an active recoverable candidate. This metadata probe
/// never establishes the candidate's contents or decryptability.
pub async fn fetch_mls_restore_payload_after_encrypted_projection(
    api: &crate::transport::TransportClient,
    actor_id: &str,
) -> Result<Value> {
    let mut payload = fetch_mls_restore_payload(api, actor_id).await?;
    for _ in 0..5 {
        if crate::mls::runtime::select_recovery_backup_candidate(&payload).is_some() {
            break;
        }
        crate::runtime_helpers::sleep_for(std::time::Duration::from_secs(1)).await;
        payload = fetch_mls_restore_payload(api, actor_id).await?;
    }
    Ok(payload)
}

pub async fn fetch_mls_restore_payload_with_unlock_proof(
    api: &crate::transport::TransportClient,
    actor_id: &str,
    device_id: &str,
) -> Result<Value> {
    let payload = fetch_mls_restore_payload(api, actor_id).await?;
    hydrate_mls_restore_payload_with_unlock_proof(api, payload, actor_id, device_id, None).await
}

pub async fn fetch_mls_restore_payload_with_recovery_session_unlock_proof(
    api: &crate::transport::TransportClient,
    actor_id: &str,
    device_id: &str,
    recovery_session: &arkret_sdk::RecoverySession,
) -> Result<Value> {
    let payload = fetch_mls_restore_payload_after_projection(api, actor_id).await?;
    hydrate_mls_restore_payload_with_unlock_proof(
        api,
        payload,
        actor_id,
        device_id,
        Some(recovery_session),
    )
    .await
}

async fn hydrate_mls_restore_payload_with_unlock_proof(
    api: &crate::transport::TransportClient,
    payload: Value,
    actor_id: &str,
    device_id: &str,
    recovery_session: Option<&arkret_sdk::RecoverySession>,
) -> Result<Value> {
    let mut full_backups = Vec::new();
    for entry in payload
        .get("backups")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
    {
        let backup_id = entry
            .get("backup_id")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
        let backup_kind = entry
            .get("backup_kind")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if let Ok(class) = arkret_sdk::BackupKind::try_from(backup_kind) {
            let active_series = active_secret_storage_series_id_for(&payload, class);
            if entry.get("series_id").and_then(Value::as_str) != active_series.as_deref() {
                continue;
            }
        }
        if entry.get("ciphertext").and_then(Value::as_str).is_some() {
            full_backups.push(entry);
            continue;
        }
        if backup_kind != "secret_storage" {
            full_backups.push(entry);
            continue;
        }
        let backup_id = if backup_id.is_empty() {
            "(unknown)"
        } else {
            backup_id.as_str()
        };
        let full = match recovery_session {
            Some(session) => {
                crate::key_backup::fetch_key_backup_with_recovery_session_unlock_proof(
                    api, &entry, actor_id, device_id, session,
                )
                .await
            }
            None => {
                let signer = crate::event_signer::active_signer();
                crate::key_backup::fetch_key_backup_with_device_unlock_proof(
                    api,
                    &entry,
                    actor_id,
                    device_id,
                    signer.as_ref(),
                )
                .await
            }
        }
        .with_context(|| format!("fetch key backup {backup_id} with unlock proof"))?;
        full_backups.push(full);
    }
    let full_payload = json!({
        "backups": full_backups,
        "active_series": payload.get("active_series").cloned().unwrap_or(Value::Null),
        "next_cursor": payload.get("next_cursor").cloned().unwrap_or(Value::Null),
        "has_more": false,
        "state": payload.get("state").cloned().unwrap_or_else(|| json!("active")),
    });
    Ok(full_payload)
}

/// Import the account checkpoint secret from a complete authenticated backup list.
/// This never installs MLS private state or marks historical content as recovered.
pub async fn restore_mls_account_secret_with_passphrase_from_payload(
    list_payload: &Value,
    secure_store: &dyn crate::secure_key_store::SecureKeyStore,
    authority: &arkret_sdk::AccountId,
    actor_id: &str,
    device_id: &str,
    passphrase: &[u8],
) -> Result<AccountSecretRestoreReport> {
    let mut report = AccountSecretRestoreReport::default();
    validate_backup_account(list_payload, authority, actor_id)?;

    // Refresh an incomplete bootstrap's checkpoint key when a backup exists.
    let has_local_secret = crate::mls::runtime::load_device_checkpoint_secret(
        secure_store,
        authority,
        &arkret_sdk::DeviceId::new(device_id.to_owned())
            .map_err(|error| anyhow!("invalid device id: {error}"))?,
    )
    .is_ok();
    if let Some(secret_body) = select_mls_account_secret_backup(list_payload) {
        // Fail closed against series rollback / withholding: the selected tail
        // must sit at the end of a complete, digest-linked chain back to genesis
        // before we trust it as the account secret to import.
        let tail: arkret_models_crypto::KeyBackup = serde_json::from_value(secret_body.clone())?;
        let chain = all_secret_storage_backups(list_payload)
            .into_iter()
            .map(serde_json::from_value::<arkret_models_crypto::KeyBackup>)
            .collect::<std::result::Result<Vec<_>, _>>()?;
        verify_series_chain(&tail, &chain).map_err(|error| anyhow!("{error}"))?;
        let (secret_bytes, version) = decrypt_mls_account_secret_backup(passphrase, &secret_body)?;
        let secret = String::from_utf8(secret_bytes)
            .map_err(|err| anyhow!("account secret is not valid UTF-8: {err}"))?;
        crate::mls::runtime::replace_account_mls_secret_version(
            secure_store,
            authority,
            version,
            &secret,
        )
        .map_err(|err| anyhow!("replace account MLS secret: {err}"))?;
        crate::mls::runtime::mark_account_mls_secret_verified(secure_store, authority)
            .map_err(|err| anyhow!("mark restored account MLS secret verified: {err}"))?;
        report.account_secret_imported = true;
    } else if !has_local_secret {
        return Err(anyhow!(
            "no mls_account_secret backup on server; checkpoint secret cannot be imported"
        ));
    }
    Ok(report)
}

/// Open the policy-bound account checkpoint secret with the backup HPKE key.
/// Historical originals and fresh MLS membership require their own verification.
pub async fn restore_mls_account_secret_with_recovery_key_from_payload(
    list_payload: &Value,
    secure_store: &dyn crate::secure_key_store::SecureKeyStore,
    authority: &arkret_sdk::AccountId,
    actor_id: &str,
    recovery_private_key: &[u8],
    expected_recovery_policy_ref: (&str, u64),
) -> Result<AccountSecretRestoreReport> {
    let mut report = AccountSecretRestoreReport::default();
    validate_backup_account(list_payload, authority, actor_id)?;
    verify_active_backup_series(
        list_payload,
        crate::key_backup::BackupKind::SecretStorage.as_str(),
    )?;
    let secret_body = select_mls_account_secret_recovery_public_key_backup(list_payload)
        .ok_or_else(|| anyhow!("no recovery_public_key account-secret backup on server"))?;
    let (secret, version) = open_mls_account_secret_recovery_public_key_backup(
        recovery_private_key,
        &secret_body,
        expected_recovery_policy_ref,
    )?;
    crate::mls::runtime::replace_account_mls_secret_version(
        secure_store,
        authority,
        version,
        &secret,
    )
    .map_err(|err| anyhow!("replace account MLS secret: {err}"))?;
    crate::mls::runtime::mark_account_mls_secret_verified(secure_store, authority)
        .map_err(|err| anyhow!("mark restored account MLS secret verified: {err}"))?;
    report.account_secret_imported = true;

    Ok(report)
}

/// Fetch authenticated backup material and import only the checkpoint secret.
pub async fn auto_restore_mls_account_secret_with_passphrase(
    api: &crate::transport::TransportClient,
    secure_store: &dyn crate::secure_key_store::SecureKeyStore,
    authority: &arkret_sdk::AccountId,
    actor_id: &str,
    device_id: &str,
    passphrase: &[u8],
) -> Result<AccountSecretRestoreReport> {
    // Fetch complete material before importing the account checkpoint key.
    let payload = fetch_mls_restore_payload_with_unlock_proof(api, actor_id, device_id).await?;
    restore_mls_account_secret_with_passphrase_from_payload(
        &payload,
        secure_store,
        authority,
        actor_id,
        device_id,
        passphrase,
    )
    .await
}

/// Decide whether the app should prompt the user to set a recovery passphrase
/// and back up their account MLS secret.
///
/// This is the mirror of [`mls_restore_prompt_required`]: it fires when the
/// user HAS used encryption (a local account MLS secret exists) but the server
/// holds NO `mls_account_secret` backup yet, so switching browsers would lose
/// their checkpoint key. Normal users never reach the explicit recovery-setup screen,
/// so without this nudge their account secret stays purely local.
///
/// Returns `false` when a server backup already exists (nothing to do), and
/// `false` when there is no local account secret (the user never used
/// encryption — don't nag).
pub fn mls_backup_prompt_required(
    list_payload: &Value,
    secure_store: &dyn crate::secure_key_store::SecureKeyStore,
    authority: &arkret_sdk::AccountId,
) -> bool {
    if select_preferred_mls_account_secret_backup(list_payload).is_some() {
        return false;
    }
    matches!(
        crate::mls::runtime::load_account_mls_secret(secure_store, authority),
        Ok(Some(_))
    )
}
