//! Fetch + restore flow: account secret, MLS history, and the private-plaintext
//! sidecar.

use anyhow::{Result, anyhow};
use garth::mls::backup_series::verify_series_chain;
use serde_json::{Value, json};

use super::backup_body::{
    decrypt_mls_account_secret_backup, decrypt_mls_private_plaintext_backup,
    open_mls_account_secret_recovery_public_key_backup,
};
use super::selection::{
    all_mls_account_secret_backups, is_mls_history_backup, latest_mls_history_backups_by_scope,
    mls_account_secret_backup_version, select_mls_account_secret_backup,
    select_mls_account_secret_recovery_public_key_backup, select_mls_history_backups,
    select_mls_private_plaintext_backup, select_preferred_mls_account_secret_backup,
};

fn mls_history_recipient_method(body: &Value) -> Option<arkret_sdk::KeyBackupRecipientMethod> {
    serde_json::from_value::<arkret_sdk::KeyBackupSummaryEncryption>(
        body.get("encryption")?.clone(),
    )
    .ok()
    .map(|encryption| encryption.recipient_method)
}

/// Whether an MLS-history envelope is comparable with the local account MLS
/// secret. `recovery_public_key` history is HPKE-sealed for the Recovery Key
/// flow (and intentionally has `aead.enc` instead of a wire `nonce`), so it
/// must never be passed to the `secret_storage_key` decoder or influence the
/// already-unlocked-device prompt decision.
fn is_local_secret_mls_history_backup(body: &Value) -> bool {
    mls_history_recipient_method(body)
        == Some(arkret_sdk::KeyBackupRecipientMethod::SecretStorageKey)
}

fn select_local_secret_mls_history_backups(list_payload: &Value) -> Vec<Value> {
    select_mls_history_backups(list_payload)
        .into_iter()
        .filter(is_local_secret_mls_history_backup)
        .collect()
}

/// Decide whether the app should ask the user for their Recovery Key to unlock
/// MLS history.
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
    let portable_history_available = select_local_secret_mls_history_backups(list_payload)
        .into_iter()
        .next()
        .is_some();
    let required =
        !account_secret_present || !account_secret_verified || portable_history_available;
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
        portable_history_available,
        required,
        reason = if portable_history_available {
            "portable_history_available"
        } else if !account_secret_present {
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

/// Counts returned by [`auto_restore_mls_history_with_passphrase`].
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RestoreReport {
    /// Whether the account MLS secret was imported or refreshed from the
    /// server backup on this call.
    pub account_secret_imported: bool,
    /// Number of `mls_history` backups successfully restored into the state store.
    pub restored: usize,
    /// Number of `mls_history` backups that failed to restore.
    pub failed: usize,
    /// X5.3 — whether the encrypted local-plaintext sidecar backup was
    /// successfully decrypted and merged into the local state store on this
    /// call. Stays `false` when no sidecar backup exists or restore of it
    /// failed (a non-fatal condition; see `first_error`).
    pub private_plaintext_restored: bool,
    /// First restore failure reason, for diagnostics.
    pub first_error: Option<String>,
}

fn verify_active_backup_series(list_payload: &Value, backup_kind: &str) -> Result<()> {
    let Some(active_series) =
        super::selection::active_series_id_for_backup_class(list_payload, backup_kind)
    else {
        return Err(anyhow!(
            "{backup_kind} active-series pointer is unavailable"
        ));
    };
    let bodies = super::selection::iter_backup_bodies(list_payload)
        .filter(|body| body.get("backup_kind").and_then(Value::as_str) == Some(backup_kind))
        .filter(|body| body.get("series_id").and_then(Value::as_str) == Some(active_series))
        .cloned()
        .collect::<Vec<_>>();
    let Some(tail) = bodies
        .iter()
        .max_by_key(|body| super::selection::backup_series_seq(body))
    else {
        return Err(anyhow!(
            "authoritative {backup_kind} series has no envelopes"
        ));
    };
    verify_series_chain(tail, &bodies).map_err(|error| anyhow!("{error}"))
}

pub(super) fn observe_active_series_versions(
    list_payload: &Value,
    state_store: &mut crate::state::LocalStateStore,
    authority: &arkret_sdk::AccountId,
    actor_id: &str,
) -> Result<()> {
    if crate::mls_api_helpers::principal_core_id(actor_id)? != authority.principal_id {
        return Err(anyhow!("backup restore principal binding mismatch"));
    }
    let expected_actor = arkret_sdk::ActorId::account(authority.clone());
    // Validate both pointers and envelopes before advancing any rollback floor.
    // A shared principal at another Station is a distinct backup owner.
    for body in super::selection::iter_backup_bodies(list_payload) {
        if backup_actor(body)? != expected_actor {
            return Err(anyhow!("backup envelope actor binding mismatch"));
        }
    }
    let mut versions = Vec::new();
    for record in list_payload
        .get("active_series")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        if backup_actor(record)? != expected_actor {
            return Err(anyhow!("active-series actor binding mismatch"));
        }
        let backup_kind = record
            .get("backup_kind")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("active-series record omitted backup_kind"))?;
        let version = record
            .get("series_pointer_version")
            .and_then(Value::as_u64)
            .ok_or_else(|| anyhow!("active-series record omitted series_pointer_version"))?;
        versions.push((backup_kind, version));
    }
    for (backup_kind, version) in versions {
        state_store.observe_key_backup_active_series_version(
            &expected_actor,
            backup_kind,
            version,
        )?;
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

/// Fetch the full key-backup list once for MLS account-secret import +
/// history restore.
///
/// UI callers that hold a Dioxus `SyncSignal<LocalStateStore>` should call this
/// before acquiring `state_store.write()`, then pass the returned payload into
/// [`restore_mls_history_with_passphrase_from_payload`]. That keeps the local
/// state write guard out of the network await.
pub async fn fetch_mls_restore_payload(
    api: &crate::transport::TransportClient,
    actor_id: &str,
) -> Result<Value> {
    let backups = api
        .list_key_backups()
        .await
        .map_err(|err| anyhow!("list key backups: {err}"))?;
    let needs_active_series = backups
        .backups
        .iter()
        .fold(
            std::collections::BTreeMap::<
                &'static str,
                std::collections::BTreeSet<arkret_sdk::BackupSeriesId>,
            >::new(),
            |mut kinds, backup| {
                kinds
                    .entry(backup.backup_kind.as_str())
                    .or_default()
                    .insert(backup.series_id.clone());
                kinds
            },
        )
        .values()
        .any(|series| series.len() > 1);
    let mut payload = serde_json::to_value(&backups)?;
    payload["active_series"] = if needs_active_series {
        Value::Array(fetch_authoritative_active_series(api, actor_id).await?)
    } else {
        Value::Array(Vec::new())
    };
    Ok(payload)
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
        && !select_local_secret_mls_history_backups(payload).is_empty()
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

async fn fetch_authoritative_active_series(
    _api: &crate::transport::TransportClient,
    _actor_id: &str,
) -> Result<Vec<Value>> {
    Err(anyhow!(
        "remote first-device active-series recovery is unsupported in v1 because historical completeness is not a protocol guarantee"
    ))
}
/// The DID URL shapes that may authorize an `ak.key_backup.active_series`
/// record for one `(actor_id, device_id, device_signing_key)` triple.
///
/// `did-usage-and-verification.md` §2.2: a verification method is a **DID URL**
/// and MUST carry a `#fragment`; a bare DID is never one. Exactly three shapes
/// are accepted:
///
/// - `<principal_did>#<device_id>` — the principal-bound device reference;
/// - `<device_signing_key>#<multikey>` — the self-describing `did:key` form;
/// - `<device_signing_key>#device` — the same key with the conventional fragment.
#[cfg(test)]
fn active_series_verification_method_matches(
    verification_method: &str,
    principal_id: &arkret_sdk::DidCoreId,
    device_id: &str,
    device_signing_key: &str,
    multikey: &str,
) -> bool {
    active_series_principal_device(verification_method, principal_id)
        .is_some_and(|device| device.as_str() == device_id)
        || verification_method == format!("{device_signing_key}#{multikey}")
        || verification_method == format!("{device_signing_key}#device")
}

#[cfg(test)]
fn active_series_principal_device(
    verification_method: &str,
    principal_id: &arkret_sdk::DidCoreId,
) -> Option<arkret_sdk::DeviceId> {
    let method = arkret_sdk::DidUrl::new(verification_method).ok()?;
    let did = arkret_sdk::verification_method_did(method.as_str()).ok()?;
    if arkret_sdk::project_did_to_core_id(&did).ok().as_ref() != Some(principal_id) {
        return None;
    }
    let (controller, fragment) = method.as_str().split_once('#')?;
    if controller != did.as_str() {
        return None;
    }
    arkret_sdk::DeviceId::new(fragment).ok()
}

pub async fn fetch_mls_restore_payload_with_unlock_proof(
    api: &crate::transport::TransportClient,
    actor_id: &str,
    device_id: &str,
) -> Result<Value> {
    let payload = fetch_mls_restore_payload(api, actor_id).await?;
    hydrate_mls_restore_payload_with_unlock_proof(api, payload, actor_id, device_id, None, None)
        .await
}

pub async fn fetch_mls_restore_payload_with_recovery_session_unlock_proof(
    api: &crate::transport::TransportClient,
    actor_id: &str,
    device_id: &str,
    recovery_session: &arkret_sdk::RecoverySessionState,
    recovery_key_material: &arkret_sdk::identity_root::IdentityRecoveryKeyMaterial,
) -> Result<Value> {
    let payload = fetch_mls_restore_payload_after_projection(api, actor_id).await?;
    hydrate_mls_restore_payload_with_unlock_proof(
        api,
        payload,
        actor_id,
        device_id,
        Some(recovery_session),
        Some(recovery_key_material),
    )
    .await
}

async fn hydrate_mls_restore_payload_with_unlock_proof(
    api: &crate::transport::TransportClient,
    payload: Value,
    actor_id: &str,
    device_id: &str,
    recovery_session: Option<&arkret_sdk::RecoverySessionState>,
    recovery_key_material: Option<&arkret_sdk::identity_root::IdentityRecoveryKeyMaterial>,
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
        if matches!(backup_kind, "secret_storage" | "mls_history") {
            let active_series =
                super::selection::active_series_id_for_backup_class(&payload, backup_kind);
            if entry.get("series_id").and_then(Value::as_str) != active_series {
                continue;
            }
        }
        if entry.get("ciphertext").and_then(Value::as_str).is_some() {
            full_backups.push(entry);
            continue;
        }
        if !matches!(backup_kind, "secret_storage" | "mls_history") {
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
                    api,
                    &entry,
                    actor_id,
                    device_id,
                    session,
                    recovery_key_material.ok_or_else(|| {
                        anyhow!("recovery-session backup unlock omitted recovery key material")
                    })?,
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
        "active_series": payload.get("active_series").cloned().unwrap_or_else(|| json!([])),
        "next_cursor": payload.get("next_cursor").cloned().unwrap_or(Value::Null),
        "has_more": false,
        "state": payload.get("state").cloned().unwrap_or_else(|| json!("active")),
    });
    Ok(full_payload)
}

/// Hydrate the complete active MLS-history series needed by the silent
/// already-unlocked-device restore path.
///
/// The list endpoint intentionally returns metadata-only summaries. Passing
/// those summaries to the envelope decoder produces a misleading missing-AEAD
/// error. This helper replaces eligible history summaries with full envelopes
/// obtained through the standard unlock-proof endpoint while leaving account
/// recovery metadata available for prompt selection. Every active chain link
/// is fetched so `supersedes_digest` can be verified locally before any tail is
/// used.
pub async fn fetch_mls_history_restore_payload_with_unlock_proof(
    api: &crate::transport::TransportClient,
    list_payload: &Value,
    actor_id: &str,
    device_id: &str,
) -> Result<Value> {
    let mut backups = Vec::new();
    for entry in list_payload
        .get("backups")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
    {
        if !is_mls_history_backup(&entry) {
            backups.push(entry);
            continue;
        }
        let active_series = super::selection::active_series_id_for_backup_class(
            list_payload,
            crate::key_backup::BackupKind::MlsHistory.as_str(),
        );
        if entry.get("series_id").and_then(Value::as_str) != active_series {
            continue;
        }
        let backup_id = entry
            .get("backup_id")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("mls_history backup metadata is missing backup_id"))?;
        if entry.get("ciphertext").and_then(Value::as_str).is_some() {
            backups.push(entry);
            continue;
        }
        let signer = crate::event_signer::active_signer();
        let full = crate::key_backup::fetch_key_backup_with_device_unlock_proof(
            api,
            &entry,
            actor_id,
            device_id,
            signer.as_ref(),
        )
        .await
        .map_err(|err| anyhow!("fetch MLS history backup {backup_id} with unlock proof: {err}"))?;
        backups.push(full);
    }

    let mut payload = list_payload.clone();
    payload["backups"] = Value::Array(backups);
    Ok(payload)
}

/// Restore MLS account secret + history from an already-fetched
/// `list_key_backups` payload.
///
/// Network reads must complete before entering this function. Candidate bytes
/// are then committed one at a time through the durable Garth ledger.
pub async fn restore_mls_history_with_passphrase_from_payload(
    list_payload: &Value,
    state_store: &mut crate::state::LocalStateStore,
    secure_store: &dyn crate::secure_key_store::SecureKeyStore,
    authority: &arkret_sdk::AccountId,
    actor_id: &str,
    device_id: &str,
    passphrase: &[u8],
) -> Result<RestoreReport> {
    let mut report = RestoreReport::default();
    observe_active_series_versions(list_payload, state_store, authority, actor_id)?;

    // Step 1: refresh the local account secret from the server backup when it
    // exists. This deliberately runs even if a local secret is present: a
    // previous incomplete bootstrap may have generated a stale/random secret,
    // which would make every history restore fail with a secret mismatch.
    let has_local_secret = crate::mls::runtime::load_device_snapshot_secret(
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
        verify_series_chain(&secret_body, &all_mls_account_secret_backups(list_payload))
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
    if !select_mls_history_backups(list_payload).is_empty() {
        verify_active_backup_series(
            list_payload,
            crate::key_backup::BackupKind::MlsHistory.as_str(),
        )?;
    }

    restore_history_and_sidecar(
        list_payload,
        state_store,
        secure_store,
        authority,
        None,
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
    state_store: &mut crate::state::LocalStateStore,
    secure_store: &dyn crate::secure_key_store::SecureKeyStore,
    authority: &arkret_sdk::AccountId,
    actor_id: &str,
    device_id: &str,
    recovery_private_key: &[u8],
    expected_recovery_policy_ref: (&str, u64),
) -> Result<RestoreReport> {
    let _ = device_id;
    let mut report = RestoreReport::default();
    observe_active_series_versions(list_payload, state_store, authority, actor_id)?;
    verify_active_backup_series(
        list_payload,
        crate::key_backup::BackupKind::SecretStorage.as_str(),
    )?;
    if !select_mls_history_backups(list_payload).is_empty() {
        verify_active_backup_series(
            list_payload,
            crate::key_backup::BackupKind::MlsHistory.as_str(),
        )?;
    }
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

    restore_history_and_sidecar(
        list_payload,
        state_store,
        secure_store,
        authority,
        Some(recovery_private_key),
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
    state_store: &mut crate::state::LocalStateStore,
    secure_store: &dyn crate::secure_key_store::SecureKeyStore,
    authority: &arkret_sdk::AccountId,
    actor_id: &str,
) -> RestoreReport {
    let mut report = RestoreReport::default();
    if let Err(error) =
        observe_active_series_versions(list_payload, state_store, authority, actor_id)
    {
        report.failed = 1;
        report.first_error = Some(error.to_string());
        return report;
    }
    if !select_mls_history_backups(list_payload).is_empty()
        && let Err(error) = verify_active_backup_series(
            list_payload,
            crate::key_backup::BackupKind::MlsHistory.as_str(),
        )
    {
        report.failed = 1;
        report.first_error = Some(error.to_string());
        return report;
    }
    restore_history_and_sidecar(
        list_payload,
        state_store,
        secure_store,
        authority,
        None,
        &mut report,
    )
    .await;
    report
}

/// Shared restore tail (used by both the passphrase and recovery-key entry
/// points): with the account secret already local, restore every `mls_history`
/// backup and the author's `mls_private_plaintext` sidecar. Per-item failures
/// are counted, never abort the rest.
async fn restore_history_and_sidecar(
    list_payload: &Value,
    state_store: &mut crate::state::LocalStateStore,
    secure_store: &dyn crate::secure_key_store::SecureKeyStore,
    authority: &arkret_sdk::AccountId,
    recovery_private_key: Option<&[u8]>,
    report: &mut RestoreReport,
) {
    for body in latest_mls_history_backups_by_scope(list_payload)
        .into_iter()
        .filter(|body| body.get("ciphertext").and_then(Value::as_str).is_some())
    {
        match restore_history_backup(
            &body,
            state_store,
            secure_store,
            authority,
            recovery_private_key,
        )
        .await
        {
            Ok(()) => report.restored += 1,
            Err(error) => {
                report.failed += 1;
                report
                    .first_error
                    .get_or_insert_with(|| format!("portable MLS history restore: {error}"));
            }
        }
    }

    if let Some(sidecar_body) = select_mls_private_plaintext_backup(list_payload) {
        match restore_private_plaintext_sidecar(&sidecar_body, state_store, secure_store, authority)
        {
            Ok(()) => report.private_plaintext_restored = true,
            Err(err) => {
                if report.first_error.is_none() {
                    report.first_error = Some(format!("private plaintext restore: {err}"));
                }
            }
        }
    }
}

async fn restore_history_backup(
    body: &Value,
    state_store: &mut crate::state::LocalStateStore,
    secure_store: &dyn crate::secure_key_store::SecureKeyStore,
    authority: &arkret_sdk::AccountId,
    recovery_private_key: Option<&[u8]>,
) -> Result<()> {
    let plaintext = match mls_history_recipient_method(body) {
        Some(arkret_sdk::KeyBackupRecipientMethod::SecretStorageKey) => {
            let account_secret =
                crate::mls::runtime::load_account_mls_secret(secure_store, authority)
                    .map_err(|error| anyhow!("load account MLS secret: {error}"))?
                    .ok_or_else(|| anyhow!("account MLS secret is unavailable"))?;
            crate::key_backup::open_passphrase_kdf_backup_body(
                account_secret.secret.as_bytes(),
                body,
            )?
        }
        Some(arkret_sdk::KeyBackupRecipientMethod::RecoveryPublicKey) => {
            let private_key = recovery_private_key.ok_or_else(|| {
                anyhow!("recovery-key MLS history backup requires the recovery private key")
            })?;
            crate::key_backup::open_recovery_public_key_backup_body(private_key, body)?
        }
        Some(arkret_sdk::KeyBackupRecipientMethod::PassphraseKdf) => {
            return Err(anyhow!(
                "mls_history backup must use secret_storage_key or recovery_public_key"
            ));
        }
        None => return Err(anyhow!("mls_history backup omits recipient_method")),
    };
    let arkret_models_crypto::KeyBackupKeybag::MlsHistory {
        effective_scope,
        items,
    } = &plaintext.keybag
    else {
        return Err(anyhow!(
            "mls_history envelope opened to a non-history keybag"
        ));
    };
    let first_epoch = items
        .first()
        .map(|item| item.from_epoch)
        .ok_or_else(|| anyhow!("mls_history keybag contains no ranges"))?;
    let scope = arkret_sdk::ScopeRef::from(effective_scope.clone());
    let group_id = effective_scope.canonical_mls_group_id()?;
    let cipher_suite = state_store
        .history_epoch_cipher_suite(&scope, &group_id, first_epoch)
        .ok_or_else(|| {
            anyhow!(
                "dependency_missing: exact winning transition ciphersuite is unavailable for epoch {first_epoch}"
            )
        })?;
    for item in items {
        for epoch in item.from_epoch..=item.to_epoch {
            if state_store
                .history_epoch_cipher_suite(&scope, &group_id, epoch)
                .as_deref()
                != Some(cipher_suite.as_str())
            {
                return Err(anyhow!(
                    "dependency_missing: one portable range is not fully bound to the same replay-derived ciphersuite"
                ));
            }
        }
    }
    let kdf_nh = usize::from(arkret_sdk::registered_mls_ciphersuite_kdf_nh(
        &cipher_suite,
    )?);
    let producer = backup_actor(body)?;
    let candidates = arkret_state::history_backup::restore_history_backup_candidates(
        &plaintext,
        &producer,
        kdf_nh,
        crate::clock::now_utc(),
    )?;
    for candidate in candidates {
        state_store
            .receive_history_candidate(
                secure_store,
                &candidate.secret,
                candidate.attribution,
                crate::clock::now_utc(),
            )
            .await?;
    }
    Ok(())
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
/// Strand:
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
    state_store: &mut crate::state::LocalStateStore,
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

#[cfg(test)]
mod verification_method_shape_tests {
    use super::{active_series_principal_device, active_series_verification_method_matches};

    const ACTOR: &str = "did:webvh:z6mkfixture:alice.example";
    const DEVICE: &str = "ak:device:01904100-0000-7000-8000-000000000001";
    const DID_KEY: &str = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";
    const MULTIKEY: &str = "z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";

    fn principal() -> arkret_sdk::DidCoreId {
        arkret_sdk::project_did_to_core_id(&arkret_sdk::Did::new(ACTOR).unwrap()).unwrap()
    }

    #[test]
    fn resolves_full_did_url_against_stable_principal_without_inventing_a_did() {
        assert_eq!(
            active_series_principal_device(&format!("{ACTOR}#{DEVICE}"), &principal())
                .unwrap()
                .as_str(),
            DEVICE
        );
        for method in [
            format!("{}#{DEVICE}", principal()),
            format!("did:webvh:zOther:alice.example#{DEVICE}"),
            format!("{ACTOR}?versionId=old#{DEVICE}"),
        ] {
            assert!(active_series_principal_device(&method, &principal()).is_none());
        }
    }

    #[test]
    fn accepts_the_three_fragment_bearing_shapes() {
        for candidate in [
            format!("{ACTOR}#{DEVICE}"),
            format!("{DID_KEY}#{MULTIKEY}"),
            format!("{DID_KEY}#device"),
        ] {
            assert!(
                active_series_verification_method_matches(
                    &candidate,
                    &principal(),
                    DEVICE,
                    DID_KEY,
                    MULTIKEY
                ),
                "{candidate} must be accepted"
            );
        }
    }

    /// Negative coverage for the removed bare-DID arm
    /// (`did-usage-and-verification.md` §2.2: a verification method always
    /// carries a `#fragment`).
    #[test]
    fn rejects_the_bare_device_signing_key() {
        assert!(!active_series_verification_method_matches(
            DID_KEY,
            &principal(),
            DEVICE,
            DID_KEY,
            MULTIKEY
        ));
    }

    #[test]
    fn rejects_the_bare_actor_did_and_empty_fragments() {
        for candidate in [
            ACTOR.to_owned(),
            format!("{ACTOR}#"),
            format!("{DID_KEY}#"),
            format!("{ACTOR}#{MULTIKEY}"),
        ] {
            assert!(
                !active_series_verification_method_matches(
                    &candidate,
                    &principal(),
                    DEVICE,
                    DID_KEY,
                    MULTIKEY
                ),
                "{candidate} must be rejected"
            );
        }
    }

    /// The `DidUrl` type is the first line of defence: a bare DID cannot even
    /// be constructed as a verification method any more.
    #[test]
    fn did_url_itself_rejects_a_bare_did() {
        assert!(arkret_sdk::DidUrl::new(DID_KEY.to_owned()).is_err());
        assert!(arkret_sdk::DidUrl::new(format!("{DID_KEY}#device")).is_ok());
    }
}
