//! Account-recoverable MLS snapshot secret.
//!
//! The MLS snapshot secret is account-scoped (see [`crate::mls::runtime`]) so
//! every device of an account shares one secret and can therefore decrypt the
//! `mls_history` key-backups uploaded by sibling devices. To make that secret
//! survive a brand-new browser, it is wrapped behind the user's recovery
//! passphrase and uploaded to soland's `secret_storage` endpoint using the same
//! envelope shape as [`crate::key_backup::build_recovery_vault_backup_body`].
//!
//! The account secret plaintext is encrypted with XChaCha20-Poly1305 under an
//! Argon2id-derived KEK (see [`crate::recovery_crypto`]); it is never
//! transmitted in clear.

use anyhow::{Result, anyhow};
use serde_json::Value;

use crate::key_backup::build_recovery_vault_backup_body;
use crate::recovery_crypto::{
    VAULT_ARGON2_M_KIB, VAULT_ARGON2_P, VAULT_ARGON2_T, VaultKek, decrypt_vault, derive_vault_kek,
    encrypt_vault,
};

/// `item_type` carried by the account MLS snapshot secret backup.
///
/// Both soland's validator
/// (`soland/src/routing/identity/key_backup.rs::KEY_BACKUP_CONTENT_TYPES`)
/// and the yougen client validator
/// (`key_backup::item_type_allowed_for_class`) allowlist this dedicated
/// content type under the `secret_storage` class, so it is the primary
/// discriminator for the recovery import path. `secret_id` is still carried
/// for human-readable disambiguation.
pub const MLS_ACCOUNT_SECRET_ITEM_TYPE: &str = "mls_account_secret";
/// `secret_id` carried by the account MLS snapshot secret backup. This is the
/// stable discriminator the recovery import path matches against.
pub const MLS_ACCOUNT_SECRET_SECRET_ID: &str = "yougen_mls_account_secret";

/// Build a `secret_storage` PUT body that wraps the account MLS snapshot secret
/// behind the user's recovery passphrase.
///
/// The envelope shape reuses [`build_recovery_vault_backup_body`] (same
/// `secret_storage` / `passphrase_kdf` / argon2id+xchacha20poly1305 shape that
/// soland already validates). The plaintext account secret is encrypted with a
/// freshly-derived KEK; only the ciphertext, salt and nonce travel on the wire.
/// The `item_type` / `secret_id` are overwritten to the MLS-secret identifiers.
pub fn build_mls_account_secret_backup_body(
    backup_id: &str,
    actor_did: &str,
    device_id: &str,
    account_secret: &str,
) -> Result<Value> {
    let kek =
        derive_vault_kek(account_secret.as_bytes()).map_err(|err| anyhow!("derive KEK: {err}"))?;
    build_mls_account_secret_backup_body_with_kek(
        backup_id,
        actor_did,
        device_id,
        &kek,
        account_secret,
    )
}

/// Variant of [`build_mls_account_secret_backup_body`] that wraps the account
/// secret with an already-derived KEK (used when the passphrase has already been
/// stretched on the recovery setup path so we avoid a second Argon2id pass).
pub fn build_mls_account_secret_backup_body_with_kek(
    backup_id: &str,
    actor_did: &str,
    device_id: &str,
    kek: &VaultKek,
    account_secret: &str,
) -> Result<Value> {
    build_mls_account_secret_backup_body_with_kek_and_version(
        backup_id,
        actor_did,
        device_id,
        kek,
        account_secret,
        crate::mls::runtime::ACCOUNT_MLS_SECRET_CURRENT_VERSION,
    )
}

/// Variant of [`build_mls_account_secret_backup_body_with_kek`] that records
/// the local account-secret version in the backup content metadata.
pub fn build_mls_account_secret_backup_body_with_kek_and_version(
    backup_id: &str,
    actor_did: &str,
    device_id: &str,
    kek: &VaultKek,
    account_secret: &str,
    account_secret_version: u32,
) -> Result<Value> {
    let ct = encrypt_vault(kek, account_secret.as_bytes())
        .map_err(|err| anyhow!("encrypt account secret: {err}"))?;
    // `encrypt_vault` emits base64url (`-`/`_`) natively, which is exactly the
    // charset the key-backup validator requires, so the wire fields go straight
    // into the uploaded body.
    let mut body = build_recovery_vault_backup_body(
        backup_id,
        actor_did,
        device_id,
        &ct.ciphertext_b64,
        &ct.digest_sha256,
        &ct.salt_b64,
        &ct.nonce_b64,
        VAULT_ARGON2_M_KIB,
        VAULT_ARGON2_T,
        VAULT_ARGON2_P,
    );
    // Re-label the single content item from the recovery-vault default
    // (`recovery_secret` / `yougen_recovery_vault_payload`) to the MLS account
    // secret identifiers, then re-attach domain separation so the AAD's
    // `item_types` matches the rewritten contents.
    if let Some(item) = body
        .get_mut("contents")
        .and_then(Value::as_array_mut)
        .and_then(|c| c.first_mut())
        .and_then(Value::as_object_mut)
    {
        item.insert(
            "item_type".to_owned(),
            Value::String(MLS_ACCOUNT_SECRET_ITEM_TYPE.to_owned()),
        );
        item.insert(
            "secret_id".to_owned(),
            Value::String(MLS_ACCOUNT_SECRET_SECRET_ID.to_owned()),
        );
        item.insert(
            "secret_version".to_owned(),
            Value::Number(serde_json::Number::from(account_secret_version)),
        );
    }
    crate::key_backup::attach_key_backup_domain_separation(
        &mut body,
        crate::key_backup::KeyBackupClass::SecretStorage,
        "recovery_vault",
    );
    Ok(body)
}

/// Decrypt a downloaded `mls_account_secret` backup body with the user's
/// recovery passphrase and return the account snapshot secret bytes.
///
/// Mirrors [`decrypt_vault`]: the salt/nonce/ciphertext are read from the
/// envelope and the passphrase is stretched with the same Argon2id parameters.
pub fn decrypt_mls_account_secret_backup(passphrase: &[u8], body: &Value) -> Result<Vec<u8>> {
    let encryption = body
        .get("encryption")
        .ok_or_else(|| anyhow!("backup body missing encryption"))?;
    let salt_b64 = encryption
        .get("kdf")
        .and_then(|kdf| kdf.get("salt"))
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("backup body missing encryption.kdf.salt"))?;
    let nonce_b64 = encryption
        .get("aead")
        .and_then(|aead| aead.get("nonce"))
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("backup body missing encryption.aead.nonce"))?;
    let ciphertext_b64 = body
        .get("ciphertext")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("backup body missing ciphertext"))?;
    // The wire fields are base64url, which is exactly what `decrypt_vault`
    // decodes, so they are fed straight in.
    decrypt_vault(passphrase, salt_b64, nonce_b64, ciphertext_b64)
}

/// True when `body` is an MLS account-secret backup. Matched on the dedicated
/// `mls_account_secret` item type (now allowlisted by both validators);
/// `secret_id` remains as a secondary, human-readable label.
pub fn is_mls_account_secret_backup(body: &Value) -> bool {
    body.get("contents")
        .and_then(Value::as_array)
        .and_then(|c| c.first())
        .and_then(|item| item.get("item_type"))
        .and_then(Value::as_str)
        == Some(MLS_ACCOUNT_SECRET_ITEM_TYPE)
}

/// Iterate the `{"backups": [...]}` payload returned by
/// [`crate::api::ContrixApi::list_key_backups`].
///
/// The selection helpers below are consumed by the async auto-restore helpers
/// (now available on all targets) and their tests.
fn iter_backup_bodies(list_payload: &Value) -> impl Iterator<Item = &Value> {
    list_payload
        .get("backups")
        .and_then(Value::as_array)
        .map(|arr| arr.iter())
        .into_iter()
        .flatten()
}

fn backup_series_seq(body: &Value) -> u64 {
    body.get("series_seq").and_then(Value::as_u64).unwrap_or(0)
}

fn backup_created_at(body: &Value) -> &str {
    body.get("created_at")
        .and_then(Value::as_str)
        .unwrap_or_default()
}

fn backup_secret_version(body: &Value) -> u64 {
    body.get("contents")
        .and_then(Value::as_array)
        .and_then(|c| c.first())
        .and_then(|item| item.get("secret_version"))
        .and_then(Value::as_u64)
        .unwrap_or(0)
}

/// Version recorded in an `mls_account_secret` backup. Legacy backups did not
/// carry this field, so they import at the current default version.
pub fn mls_account_secret_backup_version(body: &Value) -> u32 {
    backup_secret_version(body)
        .try_into()
        .ok()
        .filter(|version| *version > 0)
        .unwrap_or(crate::mls::runtime::ACCOUNT_MLS_SECRET_CURRENT_VERSION)
}

/// Pure body-selection: pick the latest `mls_account_secret` backup from a
/// `list_key_backups`-shaped payload, if present. Newer `series_seq` wins,
/// followed by the local secret version and creation timestamp.
pub fn select_mls_account_secret_backup(list_payload: &Value) -> Option<Value> {
    iter_backup_bodies(list_payload)
        .filter(|body| is_mls_account_secret_backup(body))
        .max_by(|a, b| {
            (
                backup_series_seq(a),
                backup_secret_version(a),
                backup_created_at(a),
            )
                .cmp(&(
                    backup_series_seq(b),
                    backup_secret_version(b),
                    backup_created_at(b),
                ))
        })
        .cloned()
}

/// Pure body-selection: collect every `mls_history` backup body from a
/// `list_key_backups`-shaped payload.
pub fn select_mls_history_backups(list_payload: &Value) -> Vec<Value> {
    iter_backup_bodies(list_payload)
        .filter(|body| {
            body.get("backup_class").and_then(Value::as_str)
                == Some(crate::key_backup::KeyBackupClass::MlsHistory.as_str())
        })
        .cloned()
        .collect()
}

fn mls_history_backup_needs_restore(
    body: &Value,
    state_store: &crate::local_state::LocalStateStore,
    local_secret: &str,
) -> bool {
    let Ok(envelope) = crate::mls::runtime::decode_mls_history_backup_envelope(body) else {
        return false;
    };
    let Some(local_snapshot) = state_store.mls_snapshot_for(&envelope.space_id) else {
        return true;
    };
    if local_snapshot.group_id != envelope.group_id || local_snapshot.epoch < envelope.epoch {
        return true;
    }
    crate::mls::persistence::decrypt_envelope(&local_snapshot, local_secret).is_err()
}

/// Decide whether the app should ask the user for their recovery passphrase to
/// unlock MLS history.
///
/// A local account secret alone is not enough readiness proof: an earlier
/// incomplete bootstrap can leave a stale/random local secret without any
/// usable per-Space MLS snapshot. In that state encrypted writes still fail
/// with `MissingWelcome`, so the prompt must stay available whenever the
/// server has account-secret recovery material and local history is missing,
/// stale, or undecryptable.
pub fn mls_restore_prompt_required(
    list_payload: &Value,
    state_store: &crate::local_state::LocalStateStore,
    secure_store: &dyn crate::secure_key_store::SecureKeyStore,
    actor_did: &str,
    device_id: &str,
) -> bool {
    if select_mls_account_secret_backup(list_payload).is_none() {
        return false;
    }
    let local_secret =
        crate::mls::runtime::load_device_snapshot_secret(secure_store, actor_did, device_id).ok();
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
    /// First restore failure reason, for diagnostics.
    pub first_error: Option<String>,
}

/// Pure-fetch helper: list the server's key backups and return the
/// `mls_account_secret` body if one is present (None if absent). No passphrase
/// is required — this is the SAFE half that can run at silent boot to *detect*
/// whether account-secret recovery is available.
pub async fn fetch_mls_account_secret_backup(
    api: &crate::api::ContrixApi,
) -> Result<Option<Value>> {
    let payload = api
        .list_key_backups()
        .await
        .map_err(|err| anyhow!("list key backups: {err}"))?;
    Ok(select_mls_account_secret_backup(&payload))
}

/// Fetch the full key-backup list once for MLS account-secret import +
/// history restore.
///
/// UI callers that hold a Dioxus `Signal<LocalStateStore>` should call this
/// before acquiring `state_store.write()`, then pass the returned payload into
/// [`restore_mls_history_with_passphrase_from_payload`]. That keeps the local
/// state write guard out of the network await.
pub async fn fetch_mls_restore_payload(api: &crate::api::ContrixApi) -> Result<Value> {
    api.list_key_backups()
        .await
        .map_err(|err| anyhow!("list key backups: {err}"))
}

/// Restore MLS account secret + history from an already-fetched
/// `list_key_backups` payload.
///
/// This function is deliberately synchronous: it can run inside a short
/// `state_store.write()` critical section after all network awaits have
/// completed.
pub fn restore_mls_history_with_passphrase_from_payload(
    list_payload: &Value,
    state_store: &mut crate::local_state::LocalStateStore,
    secure_store: &dyn crate::secure_key_store::SecureKeyStore,
    actor_did: &str,
    device_id: &str,
    passphrase: &[u8],
) -> Result<RestoreReport> {
    let mut report = RestoreReport::default();

    // Step 1: refresh the local account secret from the server backup when it
    // exists. This deliberately runs even if a local secret is present: a
    // previous incomplete bootstrap may have generated a stale/random secret,
    // which would make every history restore fail with a secret mismatch.
    let has_local_secret =
        crate::mls::runtime::load_device_snapshot_secret(secure_store, actor_did, device_id)
            .is_ok();
    if let Some(secret_body) = select_mls_account_secret_backup(list_payload) {
        let secret_bytes = decrypt_mls_account_secret_backup(passphrase, &secret_body)?;
        let secret = String::from_utf8(secret_bytes)
            .map_err(|err| anyhow!("account secret is not valid UTF-8: {err}"))?;
        let version = mls_account_secret_backup_version(&secret_body);
        crate::mls::runtime::replace_account_mls_secret_version(
            secure_store,
            actor_did,
            version,
            &secret,
        )
        .map_err(|err| anyhow!("replace account MLS secret: {err}"))?;
        report.account_secret_imported = true;
    } else if !has_local_secret {
        return Err(anyhow!(
            "no mls_account_secret backup on server; cannot recover MLS history"
        ));
    }

    // Step 2: restore every mls_history backup. A failure on one backup is
    // counted but does not abort the others.
    for body in select_mls_history_backups(list_payload) {
        match crate::mls::runtime::restore_mls_history_backup_with_device_snapshot(
            state_store,
            secure_store,
            actor_did,
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

    Ok(report)
}

/// Auto-restore MLS history for a fresh device using the recovery passphrase.
///
/// Flow:
///   1. Fetch the server's `mls_account_secret` backup when present, decrypt it with `passphrase`,
///      and replace the local account key with it. This also repairs stale local secrets left by
///      incomplete bootstraps.
///   2. List every `mls_history` backup and restore each one via
///      [`crate::mls::runtime::restore_mls_history_backup_with_device_snapshot`].
///
/// This is the function the recovery UI / a future "unlock MLS" prompt calls
/// once the user has supplied the passphrase. Returns per-backup counts.
pub async fn auto_restore_mls_history_with_passphrase(
    api: &crate::api::ContrixApi,
    state_store: &mut crate::local_state::LocalStateStore,
    secure_store: &dyn crate::secure_key_store::SecureKeyStore,
    actor_did: &str,
    device_id: &str,
    passphrase: &[u8],
) -> Result<RestoreReport> {
    // List once and reuse for both the account-secret and history selection.
    let payload = fetch_mls_restore_payload(api).await?;
    restore_mls_history_with_passphrase_from_payload(
        &payload,
        state_store,
        secure_store,
        actor_did,
        device_id,
        passphrase,
    )
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MlsAccountSecretRotationUpload {
    pub rotation: crate::mls::runtime::AccountMlsSecretRotation,
    pub account_secret_backup_id: String,
    pub account_secret_series_seq: u64,
    pub history_backup_ids: Vec<String>,
}

fn apply_next_series(previous: Option<&Value>, body: &mut Value) -> u64 {
    let Some(prev) = previous else {
        return body.get("series_seq").and_then(Value::as_u64).unwrap_or(0);
    };
    let next_seq = prev.get("series_seq").and_then(Value::as_u64).unwrap_or(0) + 1;
    if let Some(series_id) = prev.get("series_id").and_then(Value::as_str) {
        body["series_id"] = Value::String(series_id.to_owned());
    }
    body["series_seq"] = Value::Number(serde_json::Number::from(next_seq));
    next_seq
}

fn passphrase_is_blank(passphrase: &[u8]) -> bool {
    passphrase.is_empty()
        || std::str::from_utf8(passphrase)
            .map(|text| text.trim().is_empty())
            .unwrap_or(false)
}

/// Device-revoke follow-up: rotate the account MLS snapshot secret, upload the
/// new account-secret backup, and upload freshly rewrapped MLS-history backups.
///
/// This deliberately does not mutate local state. Callers should commit
/// `upload.rotation` via
/// [`crate::mls::runtime::commit_account_mls_secret_rotation`] only after this
/// function returns `Ok`, so local snapshots and the local secret advance
/// together.
pub async fn upload_mls_account_secret_rotation_after_device_revoke(
    api: &crate::api::ContrixApi,
    secure_store: &dyn crate::secure_key_store::SecureKeyStore,
    actor_did: &str,
    device_id: &str,
    passphrase: &[u8],
    snapshots: &std::collections::BTreeMap<String, crate::mls::persistence::MlsSnapshotEnvelope>,
) -> Result<MlsAccountSecretRotationUpload> {
    if passphrase_is_blank(passphrase) {
        return Err(anyhow!(
            "recovery passphrase is required to rotate the account MLS secret"
        ));
    }

    let list_payload = fetch_mls_restore_payload(api).await?;
    let previous_account_backup = select_mls_account_secret_backup(&list_payload);
    let account_backup_id = previous_account_backup
        .as_ref()
        .and_then(|body| body.get("backup_id").and_then(Value::as_str))
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| format!("cx:backup:{}", crate::operation::uuid_v7()));

    let rotation = crate::mls::runtime::prepare_account_mls_secret_rotation(
        secure_store,
        actor_did,
        device_id,
        snapshots,
    )
    .map_err(|err| anyhow!(err.user_message()))?;

    let kek = derive_vault_kek(passphrase).map_err(|err| anyhow!("derive KEK: {err}"))?;
    let mut account_body = build_mls_account_secret_backup_body_with_kek_and_version(
        &account_backup_id,
        actor_did,
        device_id,
        &kek,
        &rotation.new_secret,
        rotation.new_version,
    )?;
    let account_secret_series_seq =
        apply_next_series(previous_account_backup.as_ref(), &mut account_body);
    api.put_key_backup(&account_backup_id, account_body)
        .await
        .map_err(|err| anyhow!("upload rotated account MLS secret backup: {err}"))?;

    let mut history_backup_ids = Vec::with_capacity(rotation.rewrapped_snapshots.len());
    for snapshot in rotation.rewrapped_snapshots.values() {
        let backup_id =
            crate::mls::runtime::upload_mls_snapshot_backup(api, snapshot, actor_did, device_id)
                .await
                .map_err(|err| {
                    anyhow!(
                        "upload rewrapped MLS history backup: {}",
                        err.user_message()
                    )
                })?;
        history_backup_ids.push(backup_id);
    }

    Ok(MlsAccountSecretRotationUpload {
        rotation,
        account_secret_backup_id: account_backup_id,
        account_secret_series_seq,
        history_backup_ids,
    })
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
    actor_did: &str,
    device_id: &str,
) -> bool {
    let _ = device_id;
    if select_mls_account_secret_backup(list_payload).is_some() {
        return false;
    }
    matches!(
        crate::mls::runtime::load_account_mls_secret(secure_store, actor_did),
        Ok(Some(_))
    )
}

/// Wrap the local account MLS secret behind a freshly-derived recovery KEK and
/// upload it to soland's `secret_storage` endpoint.
///
/// This is the upload half of the backup-prompt flow (the inverse of
/// [`auto_restore_mls_history_with_passphrase`]). It re-uses any prior
/// account-secret backup's `backup_id`/series so the upload stays in the same
/// rotation series. Returns the `backup_id` it wrote.
pub async fn upload_mls_account_secret_backup_with_passphrase(
    api: &crate::api::ContrixApi,
    secure_store: &dyn crate::secure_key_store::SecureKeyStore,
    actor_did: &str,
    device_id: &str,
    passphrase: &[u8],
) -> Result<String> {
    if passphrase_is_blank(passphrase) {
        return Err(anyhow!(
            "recovery passphrase is required to back up the account MLS secret"
        ));
    }

    let stored = crate::mls::runtime::load_account_mls_secret(secure_store, actor_did)
        .map_err(|err| anyhow!("load account MLS secret: {err}"))?
        .ok_or_else(|| anyhow!("no local account MLS secret to back up"))?;

    let list_payload = fetch_mls_restore_payload(api).await?;
    let previous_account_backup = select_mls_account_secret_backup(&list_payload);
    let account_backup_id = previous_account_backup
        .as_ref()
        .and_then(|body| body.get("backup_id").and_then(Value::as_str))
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| format!("cx:backup:{}", crate::operation::uuid_v7()));

    let kek = derive_vault_kek(passphrase).map_err(|err| anyhow!("derive KEK: {err}"))?;
    let mut account_body = build_mls_account_secret_backup_body_with_kek_and_version(
        &account_backup_id,
        actor_did,
        device_id,
        &kek,
        &stored.secret,
        stored.version,
    )?;
    apply_next_series(previous_account_backup.as_ref(), &mut account_body);
    api.put_key_backup(&account_backup_id, account_body)
        .await
        .map_err(|err| anyhow!("upload account MLS secret backup: {err}"))?;

    Ok(account_backup_id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key_backup::{KeyBackupClass, validate_key_backup_envelope};
    use crate::secure_key_store::MemorySecureKeyStore;

    const BACKUP_ID: &str = "cx:backup:01964137-0000-7000-8000-00000000beef";
    const ACTOR: &str = "did:web:alice.example";
    const DEVICE: &str = "cx:device:01964137-0000-7000-8000-000000000001";
    const PASSPHRASE: &[u8] = b"correct horse battery staple";
    const ACCOUNT_SECRET: &str = "qr6h9rJ8nU0H2pP5w3sLx1A4bC7dE9fG2hI5jK8lM0N";

    fn wrap() -> Value {
        let kek = derive_vault_kek(PASSPHRASE).unwrap();
        build_mls_account_secret_backup_body_with_kek(
            BACKUP_ID,
            ACTOR,
            DEVICE,
            &kek,
            ACCOUNT_SECRET,
        )
        .unwrap()
    }

    fn temp_state_store(name: &str) -> crate::local_state::LocalStateStore {
        let path = std::env::temp_dir().join(format!(
            "yougen-mls-account-recovery-{name}-{}.json",
            crate::operation::uuid_v7()
        ));
        crate::local_state::LocalStateStore::with_path(path)
    }

    fn history_envelope(
        space_id: &str,
        group_id: &str,
        epoch: u64,
        secret: &str,
    ) -> crate::mls::persistence::MlsSnapshotEnvelope {
        crate::mls::persistence::encrypt_state(
            space_id,
            group_id,
            epoch,
            b"opaque sdk state bytes",
            secret,
            b"deterministic-salt",
        )
    }

    fn history_body(envelope: &crate::mls::persistence::MlsSnapshotEnvelope) -> Value {
        envelope.to_key_backup_body(
            "cx:backup:01964137-0000-7000-8000-00000000feed",
            ACTOR,
            DEVICE,
        )
    }

    #[test]
    fn wrap_then_unwrap_round_trips_the_secret() {
        let body = wrap();
        let recovered = decrypt_mls_account_secret_backup(PASSPHRASE, &body).unwrap();
        assert_eq!(recovered, ACCOUNT_SECRET.as_bytes());
    }

    #[test]
    fn wrong_passphrase_fails_to_unwrap() {
        let body = wrap();
        let result = decrypt_mls_account_secret_backup(b"incorrect horse", &body);
        assert!(result.is_err());
    }

    #[test]
    fn put_body_has_expected_item_identifiers() {
        let body = wrap();
        assert!(is_mls_account_secret_backup(&body));
        assert_eq!(
            body["contents"][0]["item_type"].as_str(),
            Some(MLS_ACCOUNT_SECRET_ITEM_TYPE)
        );
        assert_eq!(
            body["contents"][0]["secret_id"].as_str(),
            Some(MLS_ACCOUNT_SECRET_SECRET_ID)
        );
        assert_eq!(body["backup_class"], "secret_storage");
        // item_type must be one both validators' allowlists accept.
        assert_eq!(MLS_ACCOUNT_SECRET_ITEM_TYPE, "mls_account_secret");
        assert_eq!(
            mls_account_secret_backup_version(&body),
            crate::mls::runtime::ACCOUNT_MLS_SECRET_CURRENT_VERSION
        );
    }

    #[test]
    fn put_body_contains_no_plaintext_secret() {
        let body = wrap();
        let serialized = serde_json::to_string(&body).unwrap();
        assert!(!serialized.contains(ACCOUNT_SECRET));
    }

    #[test]
    fn real_encrypt_build_validate_decrypt_round_trips_end_to_end() {
        // No hand-crafted fixtures: this exercises the REAL pipeline —
        // encrypt_vault (which emits base64url) → build the upload body → the
        // SAME key-backup validator the mls_history backup uses → decrypt back
        // to the plaintext secret. encrypt_vault now emits base64url natively,
        // so the validator's base64url charset check on ciphertext/nonce/salt
        // passes for every random ciphertext (no `+`/`/` ever appear).
        let body = wrap();

        // 1. The three wire fields are base64url (only `[A-Za-z0-9-_]`), never STANDARD-base64
        //    `+`/`/`.
        for (label, field) in [
            ("ciphertext", body["ciphertext"].as_str().unwrap()),
            ("salt", body["encryption"]["kdf"]["salt"].as_str().unwrap()),
            (
                "nonce",
                body["encryption"]["aead"]["nonce"].as_str().unwrap(),
            ),
        ] {
            assert!(!field.is_empty(), "{label} must not be empty");
            assert!(
                field
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'),
                "{label} must be base64url (no `+`/`/`/`=`), got: {field}"
            );
        }

        // 2. The body validates under the exact validator soland-mirroring clients run (the same
        //    one `mls_history` backups must pass).
        validate_key_backup_envelope(&body, Some(KeyBackupClass::SecretStorage)).expect(
            "mls_account_secret backup must validate as a secret_storage envelope (base64url-clean)",
        );

        // 3. The full decrypt path recovers the original secret bytes.
        let recovered = decrypt_mls_account_secret_backup(PASSPHRASE, &body).unwrap();
        assert_eq!(recovered, ACCOUNT_SECRET.as_bytes());
    }

    #[test]
    fn round_trips_even_when_random_bytes_would_need_url_safe_alphabet() {
        // Hammer the encode/decode boundary: across many random salts/nonces
        // and ciphertexts, the produced ciphertext WILL contain bytes that
        // STANDARD base64 renders as `+`/`/`. Every one of these must still
        // validate (base64url-clean) and decrypt back to the input.
        for i in 0..32u32 {
            let secret = format!("account-secret-payload-with-entropy-{i:08x}-padding++//");
            let kek = derive_vault_kek(PASSPHRASE).unwrap();
            let body = build_mls_account_secret_backup_body_with_kek(
                BACKUP_ID, ACTOR, DEVICE, &kek, &secret,
            )
            .unwrap();

            for field in [
                body["ciphertext"].as_str().unwrap(),
                body["encryption"]["kdf"]["salt"].as_str().unwrap(),
                body["encryption"]["aead"]["nonce"].as_str().unwrap(),
            ] {
                assert!(
                    field
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'),
                    "iteration {i}: field is not base64url-clean: {field}"
                );
            }

            validate_key_backup_envelope(&body, Some(KeyBackupClass::SecretStorage))
                .unwrap_or_else(|err| panic!("iteration {i}: envelope must validate: {err}"));

            let recovered = decrypt_mls_account_secret_backup(PASSPHRASE, &body).unwrap();
            assert_eq!(recovered, secret.as_bytes(), "iteration {i}: round-trip");
        }
    }

    #[test]
    fn select_account_secret_finds_it_in_a_list_payload() {
        let account_secret_body = wrap();
        // A `list_key_backups`-shaped payload mixing a history backup, an
        // unrelated recovery vault, and the account-secret backup.
        let payload = serde_json::json!({
            "backups": [
                { "backup_id": "cx:backup:a", "backup_class": "mls_history" },
                { "backup_id": "cx:backup:b", "backup_class": "recovery",
                  "contents": [ { "secret_id": "yougen_recovery_vault_payload" } ] },
                account_secret_body.clone(),
            ]
        });
        let found = select_mls_account_secret_backup(&payload).expect("account secret present");
        assert!(is_mls_account_secret_backup(&found));
        // No-account-secret payload returns None.
        let none_payload = serde_json::json!({
            "backups": [ { "backup_id": "cx:backup:a", "backup_class": "mls_history" } ]
        });
        assert!(select_mls_account_secret_backup(&none_payload).is_none());
        // Absent/empty payloads are tolerated.
        assert!(select_mls_account_secret_backup(&serde_json::json!({})).is_none());
    }

    #[test]
    fn select_account_secret_prefers_highest_series_seq() {
        let mut older = wrap();
        older["backup_id"] = serde_json::json!("cx:backup:01964137-0000-7000-8000-00000000bee1");
        older["series_seq"] = serde_json::json!(1);
        let mut newer = wrap();
        newer["backup_id"] = serde_json::json!("cx:backup:01964137-0000-7000-8000-00000000bee2");
        newer["series_seq"] = serde_json::json!(2);
        let payload = serde_json::json!({
            "backups": [newer.clone(), older]
        });

        let found = select_mls_account_secret_backup(&payload).expect("account secret present");

        assert_eq!(found["backup_id"], newer["backup_id"]);
    }

    #[test]
    fn prompt_required_when_local_secret_exists_but_history_is_missing() {
        let store = MemorySecureKeyStore::new();
        crate::mls::runtime::store_account_mls_secret(&store, ACTOR, "stale-local-secret").unwrap();
        let state = temp_state_store("prompt-missing-history");
        let envelope = history_envelope("cx:space:prompt", "group-a", 7, ACCOUNT_SECRET);
        let payload = serde_json::json!({
            "backups": [wrap(), history_body(&envelope)]
        });

        assert!(mls_restore_prompt_required(
            &payload, &state, &store, ACTOR, DEVICE
        ));
    }

    #[test]
    fn prompt_not_required_when_local_history_is_current_and_decryptable() {
        let store = MemorySecureKeyStore::new();
        crate::mls::runtime::store_account_mls_secret(&store, ACTOR, ACCOUNT_SECRET).unwrap();
        let mut state = temp_state_store("prompt-current-history");
        let envelope = history_envelope("cx:space:prompt", "group-a", 7, ACCOUNT_SECRET);
        state.save_mls_snapshot(envelope.space_id.clone(), envelope.clone());
        let payload = serde_json::json!({
            "backups": [wrap(), history_body(&envelope)]
        });

        assert!(!mls_restore_prompt_required(
            &payload, &state, &store, ACTOR, DEVICE
        ));
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn restore_replaces_stale_local_secret_before_history_replay() {
        use contrix_sdk::{ContrixMlsIdentity, DeviceId, Did};

        let device_a = "cx:device:01964137-0000-7000-8000-00000000000a";
        let space = "cx:space:01964137-0000-7000-8000-0000000000ab";
        let identity = ContrixMlsIdentity::new_basic(
            Did::new(ACTOR.to_owned()).unwrap(),
            DeviceId::new(device_a.to_owned()).unwrap(),
        )
        .unwrap();
        let group = identity.create_group(space.as_bytes()).unwrap();
        let record = group.export_state_record().unwrap();
        let envelope = crate::mls::persistence::encrypt_state(
            space,
            &record.group_id,
            record.epoch,
            &serde_json::to_vec(&record).unwrap(),
            ACCOUNT_SECRET,
            b"deterministic-salt",
        );
        let payload = serde_json::json!({
            "backups": [wrap(), history_body(&envelope)]
        });
        let store = MemorySecureKeyStore::new();
        crate::mls::runtime::store_account_mls_secret_version(
            &store,
            ACTOR,
            crate::mls::runtime::ACCOUNT_MLS_SECRET_CURRENT_VERSION + 1,
            "stale-local-secret",
        )
        .unwrap();
        let mut state = temp_state_store("restore-stale-secret");

        let report = restore_mls_history_with_passphrase_from_payload(
            &payload, &mut state, &store, ACTOR, DEVICE, PASSPHRASE,
        )
        .unwrap();

        assert!(report.account_secret_imported);
        assert_eq!(report.restored, 1);
        assert_eq!(report.failed, 0);
        let loaded = crate::mls::runtime::load_account_mls_secret(&store, ACTOR)
            .unwrap()
            .expect("secret present");
        assert_eq!(
            loaded.version,
            crate::mls::runtime::ACCOUNT_MLS_SECRET_CURRENT_VERSION
        );
        assert_eq!(loaded.secret, ACCOUNT_SECRET);
        assert!(state.mls_snapshot_for(space).is_some());
    }

    #[test]
    fn backup_prompt_not_required_when_no_local_secret() {
        // User never used encryption: no local account secret, server has no
        // backup either. Don't nag.
        let store = MemorySecureKeyStore::new();
        let payload = serde_json::json!({ "backups": [] });
        assert!(!mls_backup_prompt_required(&payload, &store, ACTOR, DEVICE));
    }

    #[test]
    fn backup_prompt_required_when_local_secret_and_no_server_backup() {
        // User has used encryption (local secret present) but never backed it
        // up to the server -> prompt them to set a recovery passphrase.
        let store = MemorySecureKeyStore::new();
        crate::mls::runtime::store_account_mls_secret(&store, ACTOR, ACCOUNT_SECRET).unwrap();
        let payload = serde_json::json!({
            "backups": [ { "backup_id": "cx:backup:a", "backup_class": "mls_history" } ]
        });
        assert!(mls_backup_prompt_required(&payload, &store, ACTOR, DEVICE));
    }

    #[test]
    fn backup_prompt_not_required_when_server_backup_present() {
        // Server already holds the account-secret backup: nothing to upload.
        let store = MemorySecureKeyStore::new();
        crate::mls::runtime::store_account_mls_secret(&store, ACTOR, ACCOUNT_SECRET).unwrap();
        let payload = serde_json::json!({ "backups": [wrap()] });
        assert!(!mls_backup_prompt_required(&payload, &store, ACTOR, DEVICE));
    }

    #[test]
    fn select_history_backups_filters_by_class() {
        let payload = serde_json::json!({
            "backups": [
                { "backup_id": "cx:backup:a", "backup_class": "mls_history" },
                { "backup_id": "cx:backup:b", "backup_class": "secret_storage" },
                { "backup_id": "cx:backup:c", "backup_class": "mls_history" },
                { "backup_id": "cx:backup:d" },
            ]
        });
        let histories = select_mls_history_backups(&payload);
        assert_eq!(histories.len(), 2);
        assert!(
            histories
                .iter()
                .all(|b| { b.get("backup_class").and_then(Value::as_str) == Some("mls_history") })
        );
        assert!(select_mls_history_backups(&serde_json::json!({})).is_empty());
    }
}
