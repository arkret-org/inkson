//! Backup / rotation upload flow and superseded-backup cleanup.

use anyhow::{Result, anyhow};
use arkret_wire::{BackupRotationKind, DidFullId};
use serde_json::Value;

use super::backup_body::{
    build_mls_account_secret_backup_body_with_kek_and_version,
    build_mls_account_secret_backup_successor_body_with_kek_and_version,
    build_mls_account_secret_recovery_public_key_backup_in_series,
    build_mls_private_plaintext_backup_body_with_kek,
    build_mls_private_plaintext_backup_successor_body_with_kek,
};
use super::restore::fetch_mls_restore_payload;
use super::selection::select_mls_private_plaintext_backup;
use super::series::fresh_backup_id;
use crate::recovery_crypto::derive_vault_kek;

fn passphrase_is_blank(passphrase: &[u8]) -> bool {
    passphrase.is_empty()
        || std::str::from_utf8(passphrase)
            .map(|text| text.trim().is_empty())
            .unwrap_or(false)
}

async fn current_backup_frontier_ref(
    api: &crate::transport::TransportClient,
    actor_id: &str,
    device_id: &str,
) -> Result<arkret_sdk::KeyBackupFrontierRef> {
    let principal = DidFullId::new(actor_id.to_owned())?;
    let http = api.sdk_http_client()?;
    let control_realm =
        crate::identity::principal_control::resolve_accepted(&http, &principal).await?;
    let trust_anchor = super::rotation_transaction::current_controller_backup_trust_anchor(
        &http, actor_id, device_id,
    )
    .await?;
    let seal = api
        .event_submitter()?
        .events_frontier_realm_seal_head(control_realm.as_str())
        .await?;
    Ok(arkret_sdk::KeyBackupFrontierRef {
        frontier_digest: seal.control_event_set_root,
        seal_ref: Some(seal.id.to_string()),
        device_generation_ref: trust_anchor.generation_ref,
    })
}

fn typed_backup_predecessor(previous: &Value) -> Result<arkret_sdk::KeyBackup> {
    serde_json::from_value(previous.clone())
        .map_err(|error| anyhow!("typed key backup predecessor: {error}"))
}

// Invariant assertions: each `expect` message names the check that
// establishes it a few lines earlier. Rewriting them as `?` would add
// error paths no caller can reach.
#[allow(clippy::expect_used)]
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

    let principal = DidFullId::new(actor_id.to_owned())?;
    let http = api.sdk_http_client()?;
    let control_realm =
        crate::identity::principal_control::resolve_accepted(&http, &principal).await?;
    let submitter = api.event_submitter()?;
    let frontier = submitter
        .events_frontier_realm_seal_head(control_realm.as_str())
        .await?;
    let trust_anchor = super::rotation_transaction::current_controller_backup_trust_anchor(
        &http, actor_id, device_id,
    )
    .await?;
    let event = super::rotation_transaction::build_active_series_event(
        &control_realm,
        actor_id,
        backup_kind,
        series_id,
        1,
        &[],
        &frontier,
        &trust_anchor,
    )?;
    // The active-series Event id exists once it is authored; the batch submit
    // reports the accepted ids, so the successor Seal binds the Event that was
    // actually accepted.
    let accepted = submitter
        .submit_sdk_events_batch(control_realm.as_str(), vec![event.into_intent()], None)
        .await?;
    let active_series_event_id = accepted
        .accepted
        .first()
        .or_else(|| accepted.duplicate.first())
        .cloned()
        .ok_or_else(|| {
            anyhow::anyhow!("key-backup active-series submit returned no accepted Event id")
        })?;
    let accepted_rows = http
        .events_read_all_pages(control_realm.as_str())
        .await?
        .events;
    let mut accepted = crate::models::require_complete_event_rows(
        &accepted_rows,
        "key-backup active-series successor Seal construction",
    )?
    .into_iter()
    .filter(|event| event.actor_id.as_str() == actor_id)
    .collect::<Vec<_>>();
    accepted.sort_by_key(|event| event.actor_seq);
    if accepted.last().map(|event| &event.event_id) != Some(&active_series_event_id) {
        return Err(anyhow!(
            "accepted {wire_kind} active-series Event is not the actor frontier"
        ));
    }
    let signer = crate::event_signer::active_signer()
        .ok_or_else(|| anyhow!("active device signer is required"))?;
    let hlc =
        crate::signing_stamp::issue_protocol_hlc(actor_id, device_id, control_realm.as_str())?;
    let seal = signer
        .sign_self_principal_linear_successor_seal(&accepted, &frontier, hlc)
        .map_err(|error| anyhow!("sign {wire_kind} active-series successor Seal: {error}"))?;
    let active_series_digest = arkret_sdk::Hash::new(
        accepted
            .last()
            .expect("checked")
            .event_digest_with_digest_suite(arkret_sdk::DigestSuite::Sha256)?,
    )?;
    let seal_outcome = http.events_submit_seal(&seal).await?;
    if !seal_outcome
        .accepted_event_digests
        .iter()
        .any(|digest| digest == &active_series_digest)
    {
        return Err(anyhow!(
            "Principal Server did not seal the {wire_kind} active-series Event"
        ));
    }

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
    let signer = crate::event_signer::active_signer()
        .ok_or_else(|| anyhow!("active device signer is required"))?;
    crate::key_backup::fetch_key_backup_with_device_unlock_proof(
        api,
        metadata,
        actor_id,
        device_id,
        Some(&signer),
    )
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
    // Fresh backup_id per immutable series link.
    let account_backup_id = fresh_backup_id();

    let kek = derive_vault_kek(passphrase).map_err(|err| anyhow!("derive KEK: {err}"))?;
    let signer = crate::event_signer::active_signer()
        .ok_or_else(|| anyhow!("active device signer is required"))?;
    let account_body = if let Some(previous) = previous_account_backup.as_ref() {
        let predecessor = typed_backup_predecessor(previous)?;
        let frontier = current_backup_frontier_ref(api, actor_id, device_id).await?;
        build_mls_account_secret_backup_successor_body_with_kek_and_version(
            &account_backup_id,
            &predecessor,
            &kek,
            &stored.secret,
            stored.version,
            &frontier.frontier_digest,
            frontier.device_generation_ref,
        )?
    } else {
        build_mls_account_secret_backup_body_with_kek_and_version(
            &account_backup_id,
            actor_id,
            device_id,
            &kek,
            &stored.secret,
            stored.version,
        )?
    };
    let account_series_id = account_body.series_id.to_string();
    api.put_key_backup(&account_backup_id, account_body, &signer)
        .await
        .map_err(|err| anyhow!("upload account MLS secret backup: {err}"))?;
    if previous_account_backup.is_some() {
        ensure_initial_active_series(
            api,
            actor_id,
            device_id,
            BackupRotationKind::SecretStorage,
            &account_series_id,
        )
        .await?;
    }
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
    let signer = crate::event_signer::active_signer()
        .ok_or_else(|| anyhow!("active device signer is required"))?;
    let frontier_ref = if previous_account_backup.is_some() {
        Some(current_backup_frontier_ref(api, actor_id, device_id).await?)
    } else {
        None
    };
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
        frontier_ref,
    )?;
    let account_series_id = account_body.series_id.to_string();
    api.put_key_backup(&account_backup_id, account_body, &signer)
        .await
        .map_err(|err| anyhow!("upload recovery-key account MLS secret backup: {err}"))?;
    if previous_account_backup.is_some() {
        ensure_initial_active_series(
            api,
            actor_id,
            device_id,
            BackupRotationKind::SecretStorage,
            &account_series_id,
        )
        .await?;
    }
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
    let signer = crate::event_signer::active_signer()
        .ok_or_else(|| anyhow!("active device signer is required"))?;
    let body = crate::key_backup::fetch_key_backup_with_device_unlock_proof(
        api,
        &metadata,
        actor_id,
        device_id,
        Some(&signer),
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
    // Fresh backup_id per immutable series link.
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
    let signer = crate::event_signer::active_signer()
        .ok_or_else(|| anyhow!("active device signer is required"))?;
    let body = if let Some(previous) = previous_backup.as_ref() {
        let predecessor = typed_backup_predecessor(previous)?;
        let frontier = current_backup_frontier_ref(api, actor_id, device_id).await?;
        build_mls_private_plaintext_backup_successor_body_with_kek(
            &backup_id,
            &predecessor,
            &kek,
            sidecar_json,
            &frontier.frontier_digest,
            frontier.device_generation_ref,
        )?
    } else {
        build_mls_private_plaintext_backup_body_with_kek(
            &backup_id,
            actor_id,
            device_id,
            &kek,
            sidecar_json,
        )?
    };
    let (_, sent_body) = api
        .put_key_backup_returning_sent_body(&backup_id, body, &signer)
        .await
        .map_err(|err| anyhow!("upload private plaintext backup: {err}"))?;
    let series_id = sent_body.series_id.to_string();
    ensure_initial_active_series(
        api,
        actor_id,
        device_id,
        BackupRotationKind::SecretStorage,
        &series_id,
    )
    .await?;

    Ok((backup_id, serde_json::to_value(sent_body)?))
}
