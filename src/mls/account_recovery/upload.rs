//! Backup / rotation upload flow and superseded-backup cleanup.

use anyhow::{Result, anyhow};
use serde_json::Value;

use super::backup_body::{
    build_mls_account_secret_backup_body_with_kek_and_version,
    build_mls_account_secret_recovery_public_key_backup,
    build_mls_private_plaintext_backup_body_with_kek, is_mls_account_secret_backup,
};
use super::restore::fetch_mls_restore_payload;
use super::selection::{
    backup_series_id, backup_series_seq, iter_backup_bodies, select_mls_account_secret_backup,
    select_mls_account_secret_recovery_public_key_backup, select_mls_history_tail_for_realm,
    select_mls_private_plaintext_backup,
};
use super::series::{apply_next_series, fresh_backup_id};
use crate::recovery_crypto::derive_vault_kek;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MlsAccountSecretRotationUpload {
    pub rotation: crate::mls::runtime::AccountMlsSecretRotation,
    pub account_secret_backup_id: String,
    pub account_secret_series_seq: u64,
    pub history_backup_ids: Vec<String>,
    /// Phase 4: backup_ids of the OLD (pre-rotation) account-secret + rewrapped
    /// history backups that were deleted from the server after the new series
    /// was confirmed (so a leaked old secret can no longer pull them).
    pub deleted_superseded_backup_ids: Vec<String>,
}

/// Phase 4 (key-management.md §9.1 / §12.2): after a compromise rotation uploads
/// the NEW account-secret + rewrapped history backups (a fresh series under the
/// new secret), the OLD superseded backups MUST be deleted so a leaked old
/// secret can no longer pull old ciphertext off the server.
///
/// Given the PRE-rotation server list and the `keep_backup_ids` just uploaded,
/// return the superseded backup_ids to delete: **every** old `mls_account_secret`
/// backup AND **every** old `mls_history` backup not in `keep_backup_ids`.
///
/// We delete ALL old history, not just the spaces rewrapped locally. Rationale:
/// the rotation imports a single new account secret and restore decrypts ALL
/// history with it (`mls_history_backup_needs_restore` /
/// `restore_mls_history_backup_with_device_snapshot`), so any old history left
/// behind loses its now-deleted old account secret and becomes permanently
/// undecryptable on a fresh device — and it stays readable by whoever holds the
/// rotated-out (compromised) old secret. History for a realm not held locally is
/// re-recoverable via MLS Welcome / re-sync; leaving compromised,
/// soon-to-be-orphaned ciphertext on the server is not acceptable. Anything in
/// `keep_backup_ids` (the freshly uploaded new series) is never selected.
pub fn select_superseded_backup_ids(
    list_payload: &Value,
    keep_backup_ids: &[String],
) -> Vec<String> {
    let keep: std::collections::BTreeSet<&str> =
        keep_backup_ids.iter().map(String::as_str).collect();
    let mls_history = crate::key_backup::KeyBackupClass::MlsHistory.as_str();
    let mut selected: Vec<(String, std::cmp::Reverse<u64>, String)> =
        iter_backup_bodies(list_payload)
            .filter(|body| {
                let id = body
                    .get("backup_id")
                    .and_then(Value::as_str)
                    .unwrap_or_default();
                if keep.contains(id) {
                    return false;
                }
                is_mls_account_secret_backup(body)
                    || body.get("backup_class").and_then(Value::as_str) == Some(mls_history)
            })
            .filter_map(|body| {
                let id = body.get("backup_id").and_then(Value::as_str)?;
                Some((
                    backup_series_id(body).to_owned(),
                    std::cmp::Reverse(backup_series_seq(body)),
                    id.to_owned(),
                ))
            })
            .collect();
    // Per-series tail-first (descending `series_seq`): soland rejects deleting
    // a non-tail chain link (`active_series_non_tail_delete_forbidden`), so
    // a §7.10 continuous-backup chain can only be unwound from the tail down.
    selected.sort();
    selected.into_iter().map(|(_, _, id)| id).collect()
}

/// Delete `backup_ids` from the server (ownership-proof authenticated,
/// best-effort). Returns `(deleted, failed)`. Called AFTER the new series is
/// confirmed uploaded so a delete failure never leaves the user unrecoverable.
pub async fn delete_backups(
    api: &crate::api::CokretApi,
    actor_id: &str,
    backup_ids: &[String],
) -> (Vec<String>, Vec<String>) {
    let mut deleted = Vec::new();
    let mut failed = Vec::new();
    for id in backup_ids {
        match api.delete_key_backup(id, actor_id).await {
            Ok(_) => deleted.push(id.clone()),
            Err(_) => failed.push(id.clone()),
        }
    }
    (deleted, failed)
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
    api: &crate::api::CokretApi,
    secure_store: &dyn crate::secure_key_store::SecureKeyStore,
    actor_id: &str,
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
    // Phase 4 (§9.1): a compromise/revoke rotation opens a NEW series under the
    // new secret (genesis, fresh series_id, seq=0) rather than appending to the
    // old series — so the WHOLE old series can be deleted afterwards without
    // breaking a `supersedes` chain.
    let account_backup_id = fresh_backup_id();

    let rotation = crate::mls::runtime::prepare_account_mls_secret_rotation(
        secure_store,
        actor_id,
        device_id,
        snapshots,
    )
    .map_err(|err| anyhow!(err.user_message()))?;

    let kek = derive_vault_kek(passphrase).map_err(|err| anyhow!("derive KEK: {err}"))?;
    let account_body = build_mls_account_secret_backup_body_with_kek_and_version(
        &account_backup_id,
        actor_id,
        device_id,
        &kek,
        &rotation.new_secret,
        rotation.new_version,
    )?;
    // Genesis of the new series — no `apply_next_series`. `select_*` picks it as
    // canonical via the bumped `secret_version`.
    let account_secret_series_seq = backup_series_seq(&account_body);
    api.put_key_backup(&account_backup_id, account_body)
        .await
        .map_err(|err| anyhow!("upload rotated account MLS secret backup: {err}"))?;

    let mut history_backup_ids = Vec::with_capacity(rotation.rewrapped_snapshots.len());
    for snapshot in rotation.rewrapped_snapshots.values() {
        let backup_id =
            crate::mls::runtime::upload_mls_snapshot_backup(api, snapshot, actor_id, device_id)
                .await
                .map_err(|err| {
                    anyhow!(
                        "upload rewrapped MLS history backup: {}",
                        err.user_message()
                    )
                })?;
        history_backup_ids.push(backup_id);
    }

    // Phase 4 (§9.1 / §12.2): delete ALL superseded OLD account-secret + history
    // backups now that the new series is confirmed uploaded. Best-effort: a
    // delete failure leaves stale-but-harmless old ciphertext, never blocks the
    // rotation. We delete all old history (not just rewrapped Realms) — see
    // `select_superseded_backup_ids` for why leaving half would orphan history
    // under the deleted old secret while keeping it readable by the compromised
    // old secret.
    let mut keep = Vec::with_capacity(history_backup_ids.len() + 1);
    keep.push(account_backup_id.clone());
    keep.extend(history_backup_ids.iter().cloned());
    let superseded = select_superseded_backup_ids(&list_payload, &keep);
    let (deleted_superseded_backup_ids, _failed) = delete_backups(api, actor_id, &superseded).await;

    Ok(MlsAccountSecretRotationUpload {
        rotation,
        account_secret_backup_id: account_backup_id,
        account_secret_series_seq,
        history_backup_ids,
        deleted_superseded_backup_ids,
    })
}

/// Wrap the local account MLS secret behind a freshly-derived recovery KEK and
/// upload it to soland's `secret_storage` endpoint.
///
/// This is the upload half of the backup-prompt strand (the inverse of
/// [`crate::mls::account_recovery::auto_restore_mls_history_with_passphrase`]).
/// It re-uses any prior account-secret backup's `backup_id`/series so the upload
/// stays in the same rotation series. Returns the `backup_id` it wrote.
pub async fn upload_mls_account_secret_backup_with_passphrase(
    api: &crate::api::CokretApi,
    secure_store: &dyn crate::secure_key_store::SecureKeyStore,
    actor_id: &str,
    device_id: &str,
    passphrase: &[u8],
) -> Result<String> {
    if passphrase_is_blank(passphrase) {
        return Err(anyhow!(
            "recovery passphrase is required to back up the account MLS secret"
        ));
    }

    let stored = crate::mls::runtime::load_account_mls_secret(secure_store, actor_id)
        .map_err(|err| anyhow!("load account MLS secret: {err}"))?
        .ok_or_else(|| anyhow!("no local account MLS secret to back up"))?;

    let list_payload = fetch_mls_restore_payload(api).await?;
    let previous_account_backup = match select_mls_account_secret_backup(&list_payload) {
        Some(metadata) => Some(
            crate::key_backup::fetch_key_backup_with_active_unlock_proof(
                api, &metadata, actor_id, device_id,
            )
            .await
            .map_err(|err| anyhow!("fetch previous account MLS secret backup: {err}"))?,
        ),
        None => None,
    };
    // Fresh backup_id per series link (see `apply_next_series`).
    let account_backup_id = fresh_backup_id();

    let kek = derive_vault_kek(passphrase).map_err(|err| anyhow!("derive KEK: {err}"))?;
    let mut account_body = build_mls_account_secret_backup_body_with_kek_and_version(
        &account_backup_id,
        actor_id,
        device_id,
        &kek,
        &stored.secret,
        stored.version,
    )?;
    apply_next_series(previous_account_backup.as_ref(), &mut account_body)?;
    api.put_key_backup(&account_backup_id, account_body)
        .await
        .map_err(|err| anyhow!("upload account MLS secret backup: {err}"))?;

    Ok(account_backup_id)
}

/// Upload an HPKE `recovery_public_key` account-secret backup derived from the
/// user's 24-word Recovery Key.
pub async fn upload_mls_account_secret_backup_with_recovery_key(
    api: &crate::api::CokretApi,
    secure_store: &dyn crate::secure_key_store::SecureKeyStore,
    actor_id: &str,
    device_id: &str,
    recovery_key: &str,
) -> Result<String> {
    let (_recovery_private_key, recovery_public_key) =
        crate::hpke_backup::derive_recovery_keypair_from_recovery_key(recovery_key)
            .map_err(|err| anyhow!("derive recovery HPKE keypair: {err}"))?;
    upload_mls_account_secret_backup_with_recovery_public_key(
        api,
        secure_store,
        actor_id,
        device_id,
        &recovery_public_key,
    )
    .await
}

/// Upload an HPKE `recovery_public_key` account-secret backup using the
/// already-known public recovery key. This path is used after the user has
/// confirmed the 24-word Recovery Key once; future automatic backups only need
/// the public recipient key and must not ask for the words again.
pub async fn upload_mls_account_secret_backup_with_recovery_public_key(
    api: &crate::api::CokretApi,
    secure_store: &dyn crate::secure_key_store::SecureKeyStore,
    actor_id: &str,
    device_id: &str,
    recovery_public_key: &[u8],
) -> Result<String> {
    if recovery_public_key.is_empty() {
        return Err(anyhow!("recovery public key is required"));
    }
    let stored = crate::mls::runtime::load_account_mls_secret(secure_store, actor_id)
        .map_err(|err| anyhow!("load account MLS secret: {err}"))?
        .ok_or_else(|| anyhow!("no local account MLS secret to back up"))?;

    let list_payload = fetch_mls_restore_payload(api).await?;
    let previous_account_backup =
        match select_mls_account_secret_recovery_public_key_backup(&list_payload) {
            Some(metadata) => Some(
                crate::key_backup::fetch_key_backup_with_active_unlock_proof(
                    api, &metadata, actor_id, device_id,
                )
                .await
                .map_err(|err| anyhow!("fetch previous recovery-key account backup: {err}"))?,
            ),
            None => None,
        };

    // SEC-05: stamp the actor's currently-accepted recovery policy into the
    // backup's `recovery_policy_ref` so a fresh-device restore can verify it
    // against the live policy and reject an old-policy / non-frontier replay.
    let active_policy = crate::recovery_strand::fetch_active_recovery_policy(api)
        .await
        .map_err(|err| anyhow!("fetch active recovery policy for backup binding: {err}"))?;
    let recovery_policy_ref = active_policy
        .as_ref()
        .map(|policy| (policy.policy_id.as_str(), policy.version));

    let account_backup_id = fresh_backup_id();
    let recovery_key_ref = format!("{actor_id}#recovery");
    let mut account_body = build_mls_account_secret_recovery_public_key_backup(
        &account_backup_id,
        actor_id,
        device_id,
        recovery_public_key,
        &recovery_key_ref,
        &stored.secret,
        stored.version,
        recovery_policy_ref,
    )?;
    apply_next_series(previous_account_backup.as_ref(), &mut account_body)?;
    api.put_key_backup(&account_backup_id, account_body)
        .await
        .map_err(|err| anyhow!("upload recovery-key account MLS secret backup: {err}"))?;

    Ok(account_backup_id)
}

/// X5.3 — wrap the entire local-plaintext sidecar map behind a KEK derived from
/// the ACCOUNT SECRET and upload it to soland's `secret_storage` endpoint.
///
/// The KEK source is the account secret (already recoverable via the passphrase
/// through the X3 `mls_account_secret` backup), so the restore strand decrypts the
/// sidecar with no second passphrase prompt. Reuses any prior sidecar backup's
/// `backup_id`/series so the upload stays in the same rotation series
/// (`series_seq++` whenever the sidecar changes). Returns the `backup_id` it
/// wrote. Errors if no local account secret exists (the user hasn't used
/// encryption, so there is nothing to wrap the sidecar with).
pub async fn upload_mls_private_plaintext_backup(
    api: &crate::api::CokretApi,
    secure_store: &dyn crate::secure_key_store::SecureKeyStore,
    actor_id: &str,
    device_id: &str,
    sidecar_json: &[u8],
) -> Result<String> {
    let previous_backup = fetch_mls_private_plaintext_backup_body(api, actor_id, device_id).await?;
    let (backup_id, _) = upload_mls_private_plaintext_backup_with_previous(
        api,
        secure_store,
        actor_id,
        device_id,
        sidecar_json,
        previous_backup.as_ref(),
    )
    .await?;
    Ok(backup_id)
}

/// Fetch the current full `mls_private_plaintext` backup body, if any.
///
/// Callers that repeatedly update the sidecar can cache the returned/uploaded
/// body locally and pass it to
/// [`upload_mls_private_plaintext_backup_with_previous`], avoiding a backup-list
/// request for every ordinary encrypted write.
pub async fn fetch_mls_private_plaintext_backup_body(
    api: &crate::api::CokretApi,
    actor_id: &str,
    device_id: &str,
) -> Result<Option<Value>> {
    let list_payload = fetch_mls_restore_payload(api).await?;
    let Some(metadata) = select_mls_private_plaintext_backup(&list_payload) else {
        return Ok(None);
    };
    let body = crate::key_backup::fetch_key_backup_with_active_unlock_proof(
        api, &metadata, actor_id, device_id,
    )
    .await
    .map_err(|err| anyhow!("fetch previous private plaintext backup: {err}"))?;
    Ok(Some(body))
}

/// Upload a sidecar backup successor using a caller-provided predecessor body.
///
/// This is the no-list inner upload path for debounced write-side sidecar
/// syncing. The predecessor body must be the full previous backup envelope
/// selected by `select_mls_private_plaintext_backup` or returned from this
/// function after a successful upload.
pub async fn upload_mls_private_plaintext_backup_with_previous(
    api: &crate::api::CokretApi,
    secure_store: &dyn crate::secure_key_store::SecureKeyStore,
    actor_id: &str,
    device_id: &str,
    sidecar_json: &[u8],
    previous_backup: Option<&Value>,
) -> Result<(String, Value)> {
    let stored = crate::mls::runtime::load_account_mls_secret(secure_store, actor_id)
        .map_err(|err| anyhow!("load account MLS secret: {err}"))?
        .ok_or_else(|| anyhow!("no account secret; cannot back up private plaintext"))?;

    let kek =
        derive_vault_kek(stored.secret.as_bytes()).map_err(|err| anyhow!("derive KEK: {err}"))?;
    // Fresh backup_id per series link (see `apply_next_series`).
    let backup_id = fresh_backup_id();

    let mut body = build_mls_private_plaintext_backup_body_with_kek(
        &backup_id,
        actor_id,
        device_id,
        &kek,
        sidecar_json,
    )?;
    apply_next_series(previous_backup, &mut body)?;
    let (_, sent_body) = api
        .put_key_backup_returning_sent_body(&backup_id, body)
        .await
        .map_err(|err| anyhow!("upload private plaintext backup: {err}"))?;

    Ok((backup_id, sent_body))
}

/// Fetch the FULL body of the current `mls_history` series tail for `realm_id`
/// (or `None` when the Realm has no history backup yet).
///
/// soland's list endpoint redacts `ciphertext` / `key_commitment` /
/// `auth_data.signature`, and `supersedes_digest` must be computed over the
/// full persisted predecessor — so a cache miss costs one unlock-proof read
/// (bounded: once per Realm per session; afterwards the uploader caches the
/// body it just PUT).
pub async fn fetch_mls_history_tail_for_realm(
    api: &crate::api::CokretApi,
    actor_id: &str,
    device_id: &str,
    realm_id: &str,
) -> Result<Option<Value>> {
    let list_payload = fetch_mls_restore_payload(api).await?;
    let Some(tail) = select_mls_history_tail_for_realm(&list_payload, realm_id) else {
        return Ok(None);
    };
    if tail.get("ciphertext").and_then(Value::as_str).is_some() {
        return Ok(Some(tail));
    }
    let full = crate::key_backup::fetch_key_backup_with_active_unlock_proof(
        api, &tail, actor_id, device_id,
    )
    .await
    .map_err(|err| anyhow!("fetch mls_history series tail: {err}"))?;
    Ok(Some(full))
}

/// Build + upload one `mls_history` envelope for `snapshot`, chained as the
/// SUCCESSOR of `previous` when given (key-management.md §7.10 continuous
/// backup; soland enforces `series_seq` strictly +1 with
/// `supersedes`/`supersedes_digest`, and rejects parallel fresh series piling
/// as the read-quota anti-pattern). With `previous == None` this is a series
/// genesis (first backup for the Realm, or a deliberate post-rotation reset).
///
/// The successor mutation happens BEFORE signing matters: `to_key_backup_body`
/// signs the genesis shape, so after `apply_next_series` injects
/// `supersedes`/`supersedes_digest` we re-sign so `auth_data.signed_fields`
/// covers them (they are signed-when-present fields).
///
/// Returns `(backup_id, uploaded_body)`; callers should cache the body as the
/// new series tail for the next chain link.
pub async fn upload_mls_history_backup_with_previous(
    api: &crate::api::CokretApi,
    snapshot: &crate::mls::persistence::MlsSnapshotEnvelope,
    actor_id: &str,
    device_id: &str,
    previous: Option<&Value>,
) -> Result<(String, Value)> {
    let (backup_id, mut body) =
        crate::mls::runtime::build_mls_history_backup_body(snapshot, actor_id, device_id);
    if previous.is_some() {
        apply_next_series(previous, &mut body)?;
        crate::key_backup::sign_key_backup_with_active_device(&mut body, device_id)
            .map_err(|err| anyhow!("re-sign mls_history successor envelope: {err}"))?;
    }
    let (_, sent_body) = api
        .put_key_backup_returning_sent_body(&backup_id, body)
        .await
        .map_err(|err| anyhow!("upload mls_history backup: {err}"))?;
    Ok((backup_id, sent_body))
}
