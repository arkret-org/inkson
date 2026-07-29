//! Backup / rotation upload flow and superseded-backup cleanup.

use anyhow::{Result, anyhow};
use arkret_wire::{BackupRotationKind, Did};
use serde_json::Value;

use super::backup_body::{
    build_mls_account_secret_backup_body_with_kek_and_version,
    build_mls_account_secret_recovery_public_key_backup_in_series,
    build_mls_private_plaintext_backup_body_with_kek,
};
use super::restore::fetch_mls_restore_payload;
use super::selection::{select_mls_history_tail_for_realm, select_mls_private_plaintext_backup};
use super::series::{apply_next_series, fresh_backup_id};
use crate::recovery_crypto::derive_vault_kek;

fn passphrase_is_blank(passphrase: &[u8]) -> bool {
    passphrase.is_empty()
        || std::str::from_utf8(passphrase)
            .map(|text| text.trim().is_empty())
            .unwrap_or(false)
}

async fn ensure_initial_active_series(
    api: &crate::transport::TransportClient,
    actor_id: &str,
    device_id: &str,
    backup_kind: BackupRotationKind,
    series_id: &str,
) -> Result<()> {
    let wire_kind = super::rotation_transaction::wire_backup_kind(backup_kind);
    let payload = fetch_mls_restore_payload(api, actor_id).await?;
    if let Some(active) = super::selection::active_series_id_for_backup_class(&payload, wire_kind) {
        if active == series_id {
            return Ok(());
        }
        return Err(anyhow!(
            "uploaded {wire_kind} envelope does not belong to the authoritative active series"
        ));
    }

    let principal = Did::new(actor_id.to_owned())?;
    let control_realm = arkret_sdk::principal_control_realm_id(&principal);
    let http = api.sdk_http_client()?;
    let submitter = api.event_submitter()?;
    let frontier = submitter
        .events_frontier_realm_seal_view(&control_realm)
        .await?;
    let trust_anchor = super::rotation_transaction::current_controller_backup_trust_anchor(
        &http, actor_id, device_id,
    )
    .await?;
    let event = super::rotation_transaction::build_active_series_event(
        actor_id,
        backup_kind,
        series_id,
        1,
        &[],
        &frontier,
        &trust_anchor,
    )?;
    submitter
        .submit_sdk_events_batch(control_realm.as_str(), vec![event], None)
        .await?;

    let verified = fetch_mls_restore_payload(api, actor_id).await?;
    if super::selection::active_series_id_for_backup_class(&verified, wire_kind) != Some(series_id)
    {
        return Err(anyhow!(
            "accepted {wire_kind} active-series Event did not become authoritative"
        ));
    }
    Ok(())
}

async fn fetch_active_series_tail(
    api: &crate::transport::TransportClient,
    list_payload: &Value,
    actor_id: &str,
    device_id: &str,
    backup_kind: BackupRotationKind,
) -> Result<Option<Value>> {
    let wire_kind = super::rotation_transaction::wire_backup_kind(backup_kind);
    let series_id = match super::selection::active_series_id_for_backup_class(
        list_payload,
        wire_kind,
    ) {
        Some(series_id) => series_id.to_owned(),
        None => {
            let series_ids = super::selection::iter_backup_bodies(list_payload)
                .filter(|body| body.get("backup_kind").and_then(Value::as_str) == Some(wire_kind))
                .filter_map(|body| body.get("series_id").and_then(Value::as_str))
                .collect::<std::collections::BTreeSet<_>>();
            if series_ids.is_empty() {
                return Ok(None);
            }
            if series_ids.len() != 1 {
                return Err(anyhow!(
                    "{wire_kind} backups have multiple series without an authoritative active-series Event"
                ));
            }
            let series_id = *series_ids
                .first()
                .ok_or_else(|| anyhow!("{wire_kind} series inventory changed unexpectedly"))?;
            ensure_initial_active_series(api, actor_id, device_id, backup_kind, series_id).await?;
            (*series_id).to_owned()
        }
    };
    let metadata = super::selection::iter_backup_bodies(list_payload)
        .filter(|body| body.get("backup_kind").and_then(Value::as_str) == Some(wire_kind))
        .filter(|body| body.get("series_id").and_then(Value::as_str) == Some(series_id.as_str()))
        .max_by_key(|body| super::selection::backup_series_seq(body))
        .ok_or_else(|| anyhow!("authoritative {wire_kind} series has no backup envelope"))?;
    if metadata.get("ciphertext").and_then(Value::as_str).is_some() {
        return Ok(Some(metadata.clone()));
    }
    crate::key_backup::fetch_key_backup_with_active_unlock_proof(api, metadata, actor_id, device_id)
        .await
        .map(Some)
        .map_err(|error| anyhow!("fetch active {wire_kind} series tail: {error}"))
}

/// Wrap the local account MLS secret behind a freshly-derived recovery KEK and
/// upload it to soland's `secret_storage` endpoint.
///
/// This is the upload half of the backup-prompt strand (the inverse of
/// [`crate::mls::account_recovery::auto_restore_mls_history_with_passphrase`]).
/// It re-uses any prior account-secret backup's `backup_id`/series so the upload
/// stays in the same rotation series. Returns the `backup_id` it wrote.
pub async fn upload_mls_account_secret_backup_with_passphrase(
    api: &crate::transport::TransportClient,
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

    let list_payload = fetch_mls_restore_payload(api, actor_id).await?;
    let previous_account_backup = fetch_active_series_tail(
        api,
        &list_payload,
        actor_id,
        device_id,
        BackupRotationKind::SecretStorage,
    )
    .await?;
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
    let account_series_id = account_body
        .get("series_id")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("account MLS secret backup omitted series_id"))?
        .to_owned();
    api.put_key_backup(&account_backup_id, account_body)
        .await
        .map_err(|err| anyhow!("upload account MLS secret backup: {err}"))?;
    ensure_initial_active_series(
        api,
        actor_id,
        device_id,
        BackupRotationKind::SecretStorage,
        &account_series_id,
    )
    .await?;
    crate::mls::runtime::mark_account_mls_secret_verified(secure_store, actor_id)
        .map_err(|err| anyhow!("mark uploaded account MLS secret verified: {err}"))?;

    Ok(account_backup_id)
}

/// Upload an HPKE `recovery_public_key` account-secret backup derived from the
/// user's 24-word Recovery Key.
pub async fn upload_mls_account_secret_backup_with_recovery_key(
    api: &crate::transport::TransportClient,
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
    api: &crate::transport::TransportClient,
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

    let list_payload = fetch_mls_restore_payload(api, actor_id).await?;
    let previous_account_backup = fetch_active_series_tail(
        api,
        &list_payload,
        actor_id,
        device_id,
        BackupRotationKind::SecretStorage,
    )
    .await?;

    // SEC-05: stamp the actor's currently-accepted recovery policy into the
    // backup's `recovery_policy_ref` so a fresh-device restore can verify it
    // against the live policy and reject an old-policy / non-frontier replay.
    let active_policy = crate::recovery_strand::fetch_active_recovery_policy(api)
        .await
        .map_err(|err| anyhow!("fetch active recovery policy for backup binding: {err}"))?;
    let active_policy = active_policy
        .as_ref()
        .ok_or_else(|| anyhow!("active recovery policy is required for account-secret backup"))?;
    let recovery_policy_ref = (active_policy.policy_id.as_str(), active_policy.version);

    let account_backup_id = fresh_backup_id();
    let recovery_key_ref = format!("{actor_id}#recovery");
    let account_body = build_mls_account_secret_recovery_public_key_backup_in_series(
        &account_backup_id,
        actor_id,
        device_id,
        recovery_public_key,
        &recovery_key_ref,
        &stored.secret,
        stored.version,
        recovery_policy_ref,
        previous_account_backup.as_ref(),
    )?;
    let account_series_id = account_body
        .get("series_id")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("recovery-key account backup omitted series_id"))?
        .to_owned();
    api.put_key_backup(&account_backup_id, account_body)
        .await
        .map_err(|err| anyhow!("upload recovery-key account MLS secret backup: {err}"))?;
    ensure_initial_active_series(
        api,
        actor_id,
        device_id,
        BackupRotationKind::SecretStorage,
        &account_series_id,
    )
    .await?;
    crate::mls::runtime::mark_account_mls_secret_verified(secure_store, actor_id)
        .map_err(|err| anyhow!("mark uploaded account MLS secret verified: {err}"))?;

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
    api: &crate::transport::TransportClient,
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
    api: &crate::transport::TransportClient,
    actor_id: &str,
    device_id: &str,
) -> Result<Option<Value>> {
    let list_payload = fetch_mls_restore_payload(api, actor_id).await?;
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
    api: &crate::transport::TransportClient,
    secure_store: &dyn crate::secure_key_store::SecureKeyStore,
    actor_id: &str,
    device_id: &str,
    sidecar_json: &[u8],
    _previous_backup: Option<&Value>,
) -> Result<(String, Value)> {
    let stored = crate::mls::runtime::load_account_mls_secret(secure_store, actor_id)
        .map_err(|err| anyhow!("load account MLS secret: {err}"))?
        .ok_or_else(|| anyhow!("no account secret; cannot back up private plaintext"))?;

    let kek =
        derive_vault_kek(stored.secret.as_bytes()).map_err(|err| anyhow!("derive KEK: {err}"))?;
    // Fresh backup_id per series link (see `apply_next_series`).
    let backup_id = fresh_backup_id();

    let list_payload = fetch_mls_restore_payload(api, actor_id).await?;
    let previous_backup = fetch_active_series_tail(
        api,
        &list_payload,
        actor_id,
        device_id,
        BackupRotationKind::SecretStorage,
    )
    .await?;
    let mut body = build_mls_private_plaintext_backup_body_with_kek(
        &backup_id,
        actor_id,
        device_id,
        &kek,
        sidecar_json,
    )?;
    apply_next_series(previous_backup.as_ref(), &mut body)?;
    let (_, sent_body) = api
        .put_key_backup_returning_sent_body(&backup_id, body)
        .await
        .map_err(|err| anyhow!("upload private plaintext backup: {err}"))?;
    let series_id = sent_body
        .get("series_id")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("private plaintext backup omitted series_id"))?;
    ensure_initial_active_series(
        api,
        actor_id,
        device_id,
        BackupRotationKind::SecretStorage,
        series_id,
    )
    .await?;

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
    api: &crate::transport::TransportClient,
    actor_id: &str,
    device_id: &str,
    realm_id: &str,
) -> Result<Option<Value>> {
    let list_payload = fetch_mls_restore_payload(api, actor_id).await?;
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
    api: &crate::transport::TransportClient,
    snapshot: &crate::mls::persistence::MlsSnapshotEnvelope,
    actor_id: &str,
    device_id: &str,
    _previous: Option<&Value>,
) -> Result<(String, Value)> {
    let list_payload = fetch_mls_restore_payload(api, actor_id).await?;
    let previous = fetch_active_series_tail(
        api,
        &list_payload,
        actor_id,
        device_id,
        BackupRotationKind::MlsHistory,
    )
    .await?;
    let (backup_id, mut body) =
        crate::mls::runtime::build_mls_history_backup_body(snapshot, actor_id, device_id)
            .map_err(|error| anyhow!(error.user_message()))?;
    if previous.is_some() {
        apply_next_series(previous.as_ref(), &mut body)?;
        crate::key_backup::sign_key_backup_with_active_device(&mut body, device_id)
            .map_err(|err| anyhow!("re-sign mls_history successor envelope: {err}"))?;
    }
    let (_, sent_body) = api
        .put_key_backup_returning_sent_body(&backup_id, body)
        .await
        .map_err(|err| anyhow!("upload mls_history backup: {err}"))?;
    let series_id = sent_body
        .get("series_id")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("mls_history backup omitted series_id"))?;
    ensure_initial_active_series(
        api,
        actor_id,
        device_id,
        BackupRotationKind::MlsHistory,
        series_id,
    )
    .await?;
    Ok((backup_id, sent_body))
}
