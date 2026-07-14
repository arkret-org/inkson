//! Fetch + restore flow: account secret, MLS history, and the private-plaintext
//! sidecar.

use anyhow::{Result, anyhow};
use serde_json::{Value, json};

use super::backup_body::{
    decrypt_mls_account_secret_backup, decrypt_mls_private_plaintext_backup,
    is_mls_account_secret_backup, is_mls_private_plaintext_backup,
    open_mls_account_secret_recovery_public_key_backup,
};
use super::selection::{
    all_mls_account_secret_backups, is_mls_history_backup, mls_account_secret_backup_version,
    mls_history_series_tail_ids, select_mls_account_secret_backup,
    select_mls_account_secret_recovery_public_key_backup, select_mls_history_backups,
    select_mls_private_plaintext_backup, select_preferred_mls_account_secret_backup,
};
use super::series::verify_series_chain;

fn mls_history_backup_needs_restore(
    body: &Value,
    state_store: &crate::state::LocalStateStore,
    local_secret: &str,
) -> bool {
    let Ok(envelope) = crate::mls::runtime::decode_mls_history_backup_envelope(body) else {
        return false;
    };
    // P0 fork guard: verify the local secret can actually open the SERVER's
    // history ciphertext. A new device's Welcome bootstrap mints a fresh random
    // account/device-snapshot secret when none exists yet, then saves a local
    // snapshot encrypted under that random secret. That local snapshot will
    // always self-decrypt, so testing only the local snapshot (as we did below)
    // cannot tell a genuinely-recovered secret apart from a forked random one.
    // If the local secret fails to decrypt this server backup, the device has
    // forked from the account-secret recovery chain and MUST be prompted to
    // unlock/import before it pollutes the chain with its own history backups.
    // (Backups this same device uploaded under the random secret still decrypt,
    // so we rely on `.any()` across the full server set to catch a sibling
    // device's backup made under the real account secret.)
    if crate::mls::persistence::decrypt_envelope(&envelope, local_secret).is_err() {
        return true;
    }
    let Some(local_snapshot) = state_store.mls_snapshot_for(&envelope.realm_id) else {
        return true;
    };
    if local_snapshot.group_id != envelope.group_id || local_snapshot.epoch < envelope.epoch {
        return true;
    }
    crate::mls::persistence::decrypt_envelope(&local_snapshot, local_secret).is_err()
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
    state_store: &crate::state::LocalStateStore,
    secure_store: &dyn crate::secure_key_store::SecureKeyStore,
    actor_id: &str,
    device_id: &str,
) -> bool {
    if select_preferred_mls_account_secret_backup(list_payload).is_none() {
        return false;
    }
    // A local secret may have been generated speculatively by fresh-device
    // bootstrap before backup discovery. Presence alone does not prove that it
    // belongs to the server recovery chain. Only a successful upload/import
    // sets the verified marker; until then the server backup must win.
    if !crate::mls::runtime::account_mls_secret_verified(secure_store, actor_id).unwrap_or(false) {
        return true;
    }
    let local_secret =
        crate::mls::runtime::load_device_snapshot_secret(secure_store, actor_id, device_id).ok();
    let Some(local_secret) = local_secret.filter(|secret| !secret.trim().is_empty()) else {
        return true;
    };
    select_mls_history_backups(list_payload)
        .iter()
        .any(|body| mls_history_backup_needs_restore(body, state_store, &local_secret))
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

/// Pure-fetch helper: list the server's key backups and return the
/// preferred `mls_account_secret` body if one is present (None if absent). No
/// Recovery Key is required — this is the SAFE half that can run at silent boot
/// to *detect* whether account-secret recovery is available.
pub async fn fetch_mls_account_secret_backup(
    api: &crate::transport::TransportClient,
) -> Result<Option<Value>> {
    let payload = serde_json::to_value(
        &api.list_key_backups()
            .await
            .map_err(|err| anyhow!("list key backups: {err}"))?,
    )?;
    Ok(select_preferred_mls_account_secret_backup(&payload))
}

/// Fetch the full key-backup list once for MLS account-secret import +
/// history restore.
///
/// UI callers that hold a Dioxus `SyncSignal<LocalStateStore>` should call this
/// before acquiring `state_store.write()`, then pass the returned payload into
/// [`restore_mls_history_with_passphrase_from_payload`]. That keeps the local
/// state write guard out of the network await.
pub async fn fetch_mls_restore_payload(api: &crate::transport::TransportClient) -> Result<Value> {
    let backups = api
        .list_key_backups()
        .await
        .map_err(|err| anyhow!("list key backups: {err}"))?;
    let mut payload = serde_json::to_value(&backups)?;
    attach_bootstrap_active_series(&mut payload);
    Ok(payload)
}

/// Fresh-device discovery can race the projection of backups uploaded moments
/// earlier by another device. Retry the real LIST read briefly instead of
/// caching the first empty projection for the lifetime of the app session.
pub async fn fetch_mls_restore_payload_after_projection(
    api: &crate::transport::TransportClient,
) -> Result<Value> {
    let mut payload = fetch_mls_restore_payload(api).await?;
    for _ in 0..5 {
        if select_preferred_mls_account_secret_backup(&payload).is_some() {
            break;
        }
        crate::runtime_helpers::sleep_for(std::time::Duration::from_secs(1)).await;
        payload = fetch_mls_restore_payload(api).await?;
    }
    Ok(payload)
}

/// The public LIST carrier intentionally contains metadata only and currently
/// has no field for the verified control-stream active-series records.  Keep
/// the strict selectors fail-closed for arbitrary callers, but bridge the live
/// bootstrap response by selecting the newest actor-authenticated series per
/// class until the transport exposes those records directly.  Rotation safety
/// still comes from `secret_version` first; `series_seq`/`created_at` only
/// order backups with the same secret generation.
fn attach_bootstrap_active_series(payload: &mut Value) {
    if payload
        .get("active_series")
        .and_then(Value::as_array)
        .is_some()
    {
        return;
    }
    let Some(backups) = payload.get("backups").and_then(Value::as_array) else {
        return;
    };
    let mut records = Vec::new();
    for class in ["secret_storage", "mls_history", "did_recovery"] {
        let selected = backups
            .iter()
            .filter(|body| body.get("backup_class").and_then(Value::as_str) == Some(class))
            .filter(|body| class != "secret_storage" || is_mls_account_secret_backup(body))
            .max_by(|a, b| {
                (
                    mls_account_secret_backup_version(a),
                    super::selection::backup_series_seq(a),
                    super::selection::backup_created_at(a),
                )
                    .cmp(&(
                        mls_account_secret_backup_version(b),
                        super::selection::backup_series_seq(b),
                        super::selection::backup_created_at(b),
                    ))
            });
        if let Some(series_id) = selected
            .and_then(|body| body.get("series_id"))
            .and_then(Value::as_str)
            .filter(|series_id| !series_id.is_empty())
        {
            records.push(json!({
                "schema": crate::key_backup::KEY_BACKUP_ACTIVE_SERIES_SCHEMA,
                "backup_class": class,
                "active_series_id": series_id,
            }));
        }
    }
    payload["active_series"] = Value::Array(records);
}

pub async fn fetch_mls_restore_payload_with_unlock_proof(
    api: &crate::transport::TransportClient,
    actor_id: &str,
    device_id: &str,
) -> Result<Value> {
    let payload = fetch_mls_restore_payload(api).await?;
    // §7.10 continuous backup makes mls_history series chains long-lived;
    // restore only needs the TAIL of each series (the tail folds the Realm's
    // recoverable state), so superseded chain links are skipped entirely —
    // both to avoid useless restores and to keep the per-principal 24h
    // full-ciphertext download quota (default 64) from being burned on links.
    let mls_history_tails = mls_history_series_tail_ids(&payload);
    let private_plaintext_tail_id =
        select_mls_private_plaintext_backup(&payload).and_then(|body| {
            body.get("backup_id")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned)
        });
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
        if is_mls_history_backup(&entry) {
            if !mls_history_tails.contains(backup_id.as_str()) {
                continue;
            }
        }
        if is_mls_private_plaintext_backup(&entry)
            && private_plaintext_tail_id.as_deref() != Some(backup_id.as_str())
        {
            continue;
        }
        if entry.get("ciphertext").and_then(Value::as_str).is_some() {
            full_backups.push(entry);
            continue;
        }
        let backup_class = entry
            .get("backup_class")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if !matches!(
            backup_class,
            "secret_storage" | "mls_history" | "did_recovery"
        ) {
            full_backups.push(entry);
            continue;
        }
        let backup_id = if backup_id.is_empty() {
            "(unknown)"
        } else {
            backup_id.as_str()
        };
        let full = crate::key_backup::fetch_key_backup_with_active_unlock_proof(
            api, &entry, actor_id, device_id,
        )
        .await
        .map_err(|err| anyhow!("fetch key backup {backup_id} with unlock proof: {err}"))?;
        full_backups.push(full);
    }
    let mut full_payload = json!({
        "backups": full_backups,
        "active_series": payload.get("active_series").cloned().unwrap_or_else(|| json!([])),
        "next_cursor": payload.get("next_cursor").cloned().unwrap_or(Value::Null),
        "state": payload.get("state").cloned().unwrap_or_else(|| json!("active")),
    });
    attach_bootstrap_active_series(&mut full_payload);
    Ok(full_payload)
}

/// Hydrate only the active MLS-history series tails needed by the silent
/// already-unlocked-device restore path.
///
/// The list endpoint intentionally returns metadata-only summaries. Passing
/// those summaries to the envelope decoder produces a misleading missing-AEAD
/// error. This helper replaces eligible history summaries with full envelopes
/// obtained through the standard unlock-proof endpoint while leaving account
/// recovery metadata available for prompt selection. Private-plaintext
/// sidecars are omitted because their caller fetches the selected tail through
/// its own bounded unlock path.
pub async fn fetch_mls_history_restore_payload_with_unlock_proof(
    api: &crate::transport::TransportClient,
    list_payload: &Value,
    actor_id: &str,
    device_id: &str,
) -> Result<Value> {
    let mls_history_tails = mls_history_series_tail_ids(list_payload);
    let mut backups = Vec::new();
    for entry in list_payload
        .get("backups")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
    {
        if is_mls_private_plaintext_backup(&entry) {
            continue;
        }
        if !is_mls_history_backup(&entry) {
            backups.push(entry);
            continue;
        }
        let backup_id = entry
            .get("backup_id")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("mls_history backup metadata is missing backup_id"))?;
        if !mls_history_tails.contains(backup_id) {
            continue;
        }
        if entry.get("ciphertext").and_then(Value::as_str).is_some() {
            backups.push(entry);
            continue;
        }
        let full = crate::key_backup::fetch_key_backup_with_active_unlock_proof(
            api, &entry, actor_id, device_id,
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
/// This function is deliberately synchronous: it can run inside a short
/// `state_store.write()` critical section after all network awaits have
/// completed.
pub fn restore_mls_history_with_passphrase_from_payload(
    list_payload: &Value,
    state_store: &mut crate::state::LocalStateStore,
    secure_store: &dyn crate::secure_key_store::SecureKeyStore,
    actor_id: &str,
    device_id: &str,
    passphrase: &[u8],
) -> Result<RestoreReport> {
    let mut report = RestoreReport::default();

    // Step 1: refresh the local account secret from the server backup when it
    // exists. This deliberately runs even if a local secret is present: a
    // previous incomplete bootstrap may have generated a stale/random secret,
    // which would make every history restore fail with a secret mismatch.
    let has_local_secret =
        crate::mls::runtime::load_device_snapshot_secret(secure_store, actor_id, device_id).is_ok();
    if let Some(secret_body) = select_mls_account_secret_backup(list_payload) {
        // Fail closed against series rollback / withholding: the selected tail
        // must sit at the end of a complete, digest-linked chain back to genesis
        // before we trust it as the account secret to import.
        verify_series_chain(&secret_body, &all_mls_account_secret_backups(list_payload))?;
        let secret_bytes = decrypt_mls_account_secret_backup(passphrase, &secret_body)?;
        let secret = String::from_utf8(secret_bytes)
            .map_err(|err| anyhow!("account secret is not valid UTF-8: {err}"))?;
        let version = mls_account_secret_backup_version(&secret_body);
        crate::mls::runtime::replace_account_mls_secret_version(
            secure_store,
            actor_id,
            version,
            &secret,
        )
        .map_err(|err| anyhow!("replace account MLS secret: {err}"))?;
        crate::mls::runtime::mark_account_mls_secret_verified(secure_store, actor_id)
            .map_err(|err| anyhow!("mark restored account MLS secret verified: {err}"))?;
        report.account_secret_imported = true;
    } else if !has_local_secret {
        return Err(anyhow!(
            "no mls_account_secret backup on server; cannot recover MLS history"
        ));
    }

    restore_history_and_sidecar(
        list_payload,
        state_store,
        secure_store,
        actor_id,
        device_id,
        &mut report,
    );
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
pub fn restore_mls_history_with_recovery_key_from_payload(
    list_payload: &Value,
    state_store: &mut crate::state::LocalStateStore,
    secure_store: &dyn crate::secure_key_store::SecureKeyStore,
    actor_id: &str,
    device_id: &str,
    recovery_private_key: &[u8],
    expected_recovery_policy_ref: (&str, u64),
) -> Result<RestoreReport> {
    let _ = device_id;
    let mut report = RestoreReport::default();
    let secret_body = select_mls_account_secret_recovery_public_key_backup(list_payload)
        .ok_or_else(|| anyhow!("no recovery_public_key account-secret backup on server"))?;
    let (secret, version) = open_mls_account_secret_recovery_public_key_backup(
        recovery_private_key,
        &secret_body,
        expected_recovery_policy_ref,
    )?;
    crate::mls::runtime::replace_account_mls_secret_version(
        secure_store,
        actor_id,
        version,
        &secret,
    )
    .map_err(|err| anyhow!("replace account MLS secret: {err}"))?;
    crate::mls::runtime::mark_account_mls_secret_verified(secure_store, actor_id)
        .map_err(|err| anyhow!("mark restored account MLS secret verified: {err}"))?;
    report.account_secret_imported = true;

    restore_history_and_sidecar(
        list_payload,
        state_store,
        secure_store,
        actor_id,
        device_id,
        &mut report,
    );
    Ok(report)
}

/// Restore server-side MLS history using the account/device snapshot secret
/// that is already present on this device. This is the no-prompt path for an
/// unlocked device whose local snapshot is stale relative to another device's
/// uploaded `mls_history` backup.
pub fn restore_mls_history_with_local_secret_from_payload(
    list_payload: &Value,
    state_store: &mut crate::state::LocalStateStore,
    secure_store: &dyn crate::secure_key_store::SecureKeyStore,
    actor_id: &str,
    device_id: &str,
) -> RestoreReport {
    let mut report = RestoreReport::default();
    restore_history_and_sidecar(
        list_payload,
        state_store,
        secure_store,
        actor_id,
        device_id,
        &mut report,
    );
    report
}

/// Shared restore tail (used by both the passphrase and recovery-key entry
/// points): with the account secret already local, restore every `mls_history`
/// backup and the author's `mls_private_plaintext` sidecar. Per-item failures
/// are counted, never abort the rest.
fn restore_history_and_sidecar(
    list_payload: &Value,
    state_store: &mut crate::state::LocalStateStore,
    secure_store: &dyn crate::secure_key_store::SecureKeyStore,
    actor_id: &str,
    device_id: &str,
    report: &mut RestoreReport,
) {
    for body in select_mls_history_backups(list_payload) {
        match crate::mls::runtime::restore_mls_history_backup_with_device_snapshot(
            state_store,
            secure_store,
            actor_id,
            device_id,
            &body,
        ) {
            Ok(_) => report.restored += 1,
            Err(err) => {
                report.failed += 1;
                if report.first_error.is_none() {
                    report.first_error = Some(err.user_message());
                }
            }
        }
    }

    if let Some(sidecar_body) = select_mls_private_plaintext_backup(list_payload) {
        match restore_private_plaintext_sidecar(&sidecar_body, state_store, secure_store, actor_id)
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

/// X5.3 — decrypt the `mls_private_plaintext` sidecar backup with the local
/// account secret and merge it into `state_store`. Factored out so the restore
/// step stays readable and so the `?` short-circuit doesn't abort the whole
/// restore.
fn restore_private_plaintext_sidecar(
    sidecar_body: &Value,
    state_store: &mut crate::state::LocalStateStore,
    secure_store: &dyn crate::secure_key_store::SecureKeyStore,
    actor_id: &str,
) -> Result<()> {
    let stored = crate::mls::runtime::load_account_mls_secret(secure_store, actor_id)
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
///   2. List every `mls_history` backup and restore each one via
///      [`crate::mls::runtime::restore_mls_history_backup_with_device_snapshot`].
///
/// This is the function the recovery UI / a future "unlock MLS" prompt calls
/// once the user has supplied the passphrase. Returns per-backup counts.
pub async fn auto_restore_mls_history_with_passphrase(
    api: &crate::transport::TransportClient,
    state_store: &mut crate::state::LocalStateStore,
    secure_store: &dyn crate::secure_key_store::SecureKeyStore,
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
        actor_id,
        device_id,
        passphrase,
    )
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
    actor_id: &str,
    device_id: &str,
) -> bool {
    let _ = device_id;
    if select_preferred_mls_account_secret_backup(list_payload).is_some() {
        return false;
    }
    matches!(
        crate::mls::runtime::load_account_mls_secret(secure_store, actor_id),
        Ok(Some(_))
    )
}
