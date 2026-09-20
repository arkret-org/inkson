//! Fetch + restore flow: the account MLS secret and the private-plaintext
//! sidecar.

use crate::mls::runtime::{
    active_secret_storage_series_id_for, all_secret_storage_backups, backup_series_seq_of,
    mls_account_secret_backup_version, select_mls_account_secret_backup,
    select_mls_account_secret_recovery_public_key_backup, select_mls_private_plaintext_backup,
    select_preferred_mls_account_secret_backup,
};
use anyhow::{Result, anyhow};
use garth::mls::backup_series::verify_series_chain;
use serde_json::{Value, json};

use super::backup_body::{
    decrypt_mls_account_secret_backup, decrypt_mls_private_plaintext_backup,
    open_mls_account_secret_recovery_public_key_backup,
};

/// Decide whether the app should ask the user for their Recovery Key to unlock
/// the account MLS secret.
///
/// A local account secret alone is not enough readiness proof: an earlier
/// incomplete bootstrap can leave a stale/random local secret without any
/// usable per-Realm MLS snapshot. In that state encrypted writes still fail
/// with `MissingWelcome`, so the prompt must stay available whenever the
/// server has account-secret recovery material and local history is missing,
/// stale, or undecryptable.
pub fn mls_restore_prompt_required(
    list_payload: &Value,
    _state_store: &crate::state::LocalStateStore,
    secure_store: &dyn crate::secure_key_store::SecureKeyStore,
    authority: &arkret_sdk::AccountId,
    actor_id: &str,
    device_id: &str,
) -> bool {
    let Some(account_secret_backup) = select_preferred_mls_account_secret_backup(list_payload)
    else {
        tracing::warn!(
            target: "recovery_diag",
            actor_id,
            device_id,
            required = false,
            reason = "no_account_secret_backup",
            "MLS restore prompt decision"
        );
        return false;
    };
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
        account_backup_id = account_secret_backup
            .get("backup_id")
            .and_then(|value| value.as_str())
            .unwrap_or("<missing>"),
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

/// Counts returned by [`auto_restore_mls_account_secret_with_passphrase`].
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RestoreReport {
    /// Whether the account MLS secret was imported or refreshed from the
    /// server backup on this call.
    pub account_secret_imported: bool,
    /// Number of stored artifacts successfully restored into the state store.
    pub restored: usize,
    /// Number of stored artifacts that failed to restore.
    pub failed: usize,
    /// X5.3 — whether the encrypted local-plaintext sidecar backup was
    /// successfully decrypted and merged into the local state store on this
    /// call. Stays `false` when no sidecar backup exists or restore of it
    /// failed (a non-fatal condition; see `first_error`).
    pub private_plaintext_restored: bool,
    /// First restore failure reason, for diagnostics.
    pub first_error: Option<String>,
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
        .filter(|body| body.get("series_id").and_then(Value::as_str) == Some(active_series))
        .cloned()
        .collect::<Vec<_>>();
    let Some(tail) = bodies.iter().max_by_key(|body| backup_series_seq_of(body)) else {
        return Err(anyhow!(
            "authoritative {backup_kind} series has no envelopes"
        ));
    };
    verify_series_chain(tail, &bodies).map_err(|error| anyhow!("{error}"))
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
    current.validate()?;
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

/// Pure-fetch helper: list the server's key backups and return the
/// preferred `mls_account_secret` body if one is present (None if absent). No
/// Recovery Key is required — this is the SAFE half that can run at silent boot
/// to *detect* whether account-secret recovery is available.
pub async fn fetch_mls_account_secret_backup(
    api: &crate::transport::TransportClient,
    actor_id: &str,
) -> Result<Option<Value>> {
    let payload = fetch_mls_restore_payload(api, actor_id).await?;
    Ok(select_preferred_mls_account_secret_backup(&payload))
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
    Ok(json!({"backups": backups, "active_series": current}))
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
        if select_preferred_mls_account_secret_backup(&payload).is_some() {
            break;
        }
        crate::runtime_helpers::sleep_for(std::time::Duration::from_secs(1)).await;
        payload = fetch_mls_restore_payload(api, actor_id).await?;
    }
    Ok(payload)
}

pub(super) fn encrypted_restore_projection_complete(payload: &Value) -> bool {
    select_preferred_mls_account_secret_backup(payload).is_some()
}

/// First-Realm creation publishes the account-secret backup and the first
/// `mls_history` backup through separate server projections. When this browser
/// already has encrypted local state, seeing only the account backup is not a
/// complete recovery view: classifying that half-projected payload can
/// transiently report that the creator device needs to restore its own keys.
///
/// Give both projections the same bounded convergence window before the UI is
/// allowed to classify the result. A genuinely incomplete recovery set still
/// returns after five retries and therefore remains fail-closed.
pub async fn fetch_mls_restore_payload_after_encrypted_projection(
    api: &crate::transport::TransportClient,
    actor_id: &str,
) -> Result<Value> {
    let mut payload = fetch_mls_restore_payload(api, actor_id).await?;
    for _ in 0..5 {
        if encrypted_restore_projection_complete(&payload) {
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
            if entry.get("series_id").and_then(Value::as_str) != active_series {
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
        .map_err(|err| anyhow!("fetch key backup {backup_id} with unlock proof: {err}"))?;
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

/// Restore MLS account secret + history from an already-fetched
/// `list_key_backups` payload.
///
/// Network reads must complete before entering this function. Candidate bytes
/// are then committed one at a time through the durable Garth ledger.
pub async fn restore_mls_history_with_passphrase_from_payload(
    list_payload: &Value,
    state_store: &crate::runtime::input::StateStoreHandle,
    secure_store: &dyn crate::secure_key_store::SecureKeyStore,
    authority: &arkret_sdk::AccountId,
    actor_id: &str,
    device_id: &str,
    passphrase: &[u8],
) -> Result<RestoreReport> {
    let mut report = RestoreReport::default();
    validate_backup_account(list_payload, authority, actor_id)?;

    // Step 1: refresh the local account secret from the server backup when it
    // exists. This deliberately runs even if a local secret is present: a
    // previous incomplete bootstrap may have generated a stale/random secret,
    // which would make every history restore fail with a secret mismatch.
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
        verify_series_chain(&secret_body, &all_secret_storage_backups(list_payload))
            .map_err(|error| anyhow!("{error}"))?;
        let secret_bytes = decrypt_mls_account_secret_backup(passphrase, &secret_body)?;
        let secret = String::from_utf8(secret_bytes)
            .map_err(|err| anyhow!("account secret is not valid UTF-8: {err}"))?;
        let version = mls_account_secret_backup_version(&secret_body);
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
            "no mls_account_secret backup on server; cannot recover MLS history"
        ));
    }
    restore_private_sidecar(
        list_payload,
        state_store,
        secure_store,
        authority,
        &mut report,
    )
    .await;
    Ok(report)
}

/// A3 (key-management.md §7.5.2): fresh-device restore via the recovery PRIVATE
/// key (no passphrase prompt). Opens the HPKE `recovery_public_key`
/// account-secret backup, imports the secret, then restores history + sidecar
/// — the passphrase-free counterpart of
/// [`restore_mls_history_with_passphrase_from_payload`]. The recovery private
/// key is the one unlocked by the recovery policy (saved recovery key /
/// threshold / hardware); on a brand-new browser (empty secure store) this is
/// the path that works without first holding the account secret.
pub async fn restore_mls_history_with_recovery_key_from_payload(
    list_payload: &Value,
    state_store: &crate::runtime::input::StateStoreHandle,
    secure_store: &dyn crate::secure_key_store::SecureKeyStore,
    authority: &arkret_sdk::AccountId,
    actor_id: &str,
    device_id: &str,
    recovery_private_key: &[u8],
    expected_recovery_policy_ref: (&str, u64),
) -> Result<RestoreReport> {
    let _ = device_id;
    let mut report = RestoreReport::default();
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

    let _ = recovery_private_key;
    restore_private_sidecar(
        list_payload,
        state_store,
        secure_store,
        authority,
        &mut report,
    )
    .await;
    Ok(report)
}

/// Restore server-side MLS history using the account/device snapshot secret
/// that is already present on this device. This is the no-prompt path for an
/// unlocked device whose local snapshot is stale relative to another device's
/// uploaded `mls_history` backup.
pub async fn restore_mls_history_with_local_secret_from_payload(
    list_payload: &Value,
    state_store: &crate::runtime::input::StateStoreHandle,
    secure_store: &dyn crate::secure_key_store::SecureKeyStore,
    authority: &arkret_sdk::AccountId,
    actor_id: &str,
) -> RestoreReport {
    let mut report = RestoreReport::default();
    if let Err(error) = validate_backup_account(list_payload, authority, actor_id) {
        report.failed = 1;
        report.first_error = Some(error.to_string());
        return report;
    }
    restore_private_sidecar(
        list_payload,
        state_store,
        secure_store,
        authority,
        &mut report,
    )
    .await;
    report
}

/// Shared restore tail for both entry points: with the account secret already
/// local, restore the author's `mls_private_plaintext` sidecar. A failure is
/// counted, never fatal.
async fn restore_private_sidecar(
    list_payload: &Value,
    state_store: &crate::runtime::input::StateStoreHandle,
    secure_store: &dyn crate::secure_key_store::SecureKeyStore,
    authority: &arkret_sdk::AccountId,
    report: &mut RestoreReport,
) {
    let Some(sidecar_body) = select_mls_private_plaintext_backup(list_payload) else {
        return;
    };
    match state_store.write(|store| {
        restore_private_plaintext_sidecar(&sidecar_body, store, secure_store, authority)
    }) {
        Ok(()) => {
            report.private_plaintext_restored = true;
            report.restored += 1;
        }
        Err(err) => {
            report.failed += 1;
            report
                .first_error
                .get_or_insert_with(|| format!("private plaintext restore: {err}"));
        }
    }
}

/// X5.3 — decrypt the `mls_private_plaintext` sidecar backup with the local
/// account secret and merge it into `state_store`. Factored out so the restore
/// step stays readable and so the `?` short-circuit doesn't abort the whole
/// restore.
fn restore_private_plaintext_sidecar(
    sidecar_body: &Value,
    state_store: &mut crate::state::LocalStateStore,
    secure_store: &dyn crate::secure_key_store::SecureKeyStore,
    authority: &arkret_sdk::AccountId,
) -> Result<()> {
    let stored = crate::mls::runtime::load_account_mls_secret(secure_store, authority)
        .map_err(|err| anyhow!("load account MLS secret: {err}"))?
        .ok_or_else(|| anyhow!("no account secret available to decrypt sidecar"))?;
    let sidecar_json =
        decrypt_mls_private_plaintext_backup(stored.secret.as_bytes(), sidecar_body)?;
    let map: std::collections::BTreeMap<
        String,
        std::collections::BTreeMap<String, std::collections::BTreeMap<String, String>>,
    > = serde_json::from_slice(&sidecar_json)
        .map_err(|err| anyhow!("parse sidecar JSON: {err}"))?;
    state_store.merge_private_plaintext_map(map);
    Ok(())
}

/// Auto-restore MLS history for a fresh device using the recovery passphrase.
///
/// Flow:
///   1. Fetch the server's `mls_account_secret` backup when present, decrypt it with `passphrase`,
///      and replace the local account key with it. This also repairs stale local secrets left by
///      incomplete bootstraps.
///   2. Restore portable history ranges only after every epoch has an exact replay-derived
///      ciphersuite pin; restored bytes remain external candidates.
///
/// This is the function the recovery UI / a future "unlock MLS" prompt calls
/// once the user has supplied the passphrase. Returns per-backup counts.
pub async fn auto_restore_mls_history_with_passphrase(
    api: &crate::transport::TransportClient,
    state_store: &crate::runtime::input::StateStoreHandle,
    secure_store: &dyn crate::secure_key_store::SecureKeyStore,
    authority: &arkret_sdk::AccountId,
    actor_id: &str,
    device_id: &str,
    passphrase: &[u8],
) -> Result<RestoreReport> {
    // List once and reuse for both the account-secret and history selection.
    let payload = fetch_mls_restore_payload_with_unlock_proof(api, actor_id, device_id).await?;
    restore_mls_history_with_passphrase_from_payload(
        &payload,
        state_store,
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
/// their history. Normal users never reach the explicit recovery-setup screen,
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
