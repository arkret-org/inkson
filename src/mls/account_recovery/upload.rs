//! Backup / rotation upload flow and superseded-backup cleanup.

use anyhow::{Result, anyhow};
use arkret_sdk::BackupRotationKind;
use crate::mls::runtime::{
    active_secret_storage_series_id_for, backup_series_seq_of, select_mls_private_plaintext_backup,
};
use garth::mls::backup_series::fresh_backup_id;
use serde_json::Value;

use super::backup_body::{
    build_mls_account_secret_backup_body_with_kek_and_version,
    build_mls_account_secret_backup_successor_body_with_kek_and_version,
    build_mls_account_secret_recovery_public_key_backup_in_series,
    build_mls_private_plaintext_backup_body_with_kek,
    build_mls_private_plaintext_backup_successor_body_with_kek,
};
use super::restore::fetch_mls_restore_payload;
use crate::recovery_crypto::derive_vault_kek;

fn passphrase_is_blank(passphrase: &[u8]) -> bool {
    passphrase.is_empty()
        || std::str::from_utf8(passphrase)
            .map(|text| text.trim().is_empty())
            .unwrap_or(false)
}

async fn current_backup_frontier_ref(
    api: &crate::transport::TransportClient,
    control_realm: &arkret_sdk::RealmId,
    authority: &arkret_sdk::AccountId,
    device_id: &str,
) -> Result<arkret_sdk::KeyBackupFrontierRef> {
    let http = api.sdk_http_client()?;
    let trust_anchor = super::rotation_transaction::current_controller_backup_trust_anchor(
        &http, authority, device_id,
    )
    .await?;
    let seal = api
        .event_submitter()?
        .seals_frontier_realm_head(control_realm.as_str())
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

fn active_recovery_backup_recipient(
    policy: &arkret_sdk::RecoveryPolicySummary,
    authority: &arkret_sdk::AccountId,
    actor_id: &str,
    recovery_public_key: &[u8],
) -> Result<(String, String, u64)> {
    let actor_id = crate::mls_api_helpers::principal_core_id(actor_id)?;
    if actor_id != authority.principal_id {
        return Err(anyhow!("backup signer does not match the supplied account"));
    }
    if policy.account_id != *authority {
        return Err(anyhow!(
            "active recovery policy belongs to a different account"
        ));
    }
    let body = policy
        .policy
        .as_ref()
        .ok_or_else(|| anyhow!("active recovery policy omitted its signed key configuration"))?;
    body.validate()?;
    if body.policy_id != policy.policy_id
        || body.account_id != policy.account_id
        || body.version != policy.version
    {
        return Err(anyhow!(
            "active recovery policy summary does not match its signed policy body"
        ));
    }
    let raw: &[u8; 32] = recovery_public_key
        .try_into()
        .map_err(|_| anyhow!("recovery public key must contain exactly 32 bytes"))?;
    let multikey = arkret_crypto::identity_root::x25519_public_multikey(raw);
    let now = crate::clock::now_utc();
    let matches = body
        .active_hpke_recipients(now)
        .into_iter()
        .filter(|entry| {
            entry.public_key_multibase.as_str() == multikey
                && entry.not_before <= now
                && now < entry.expires_at
                && entry.revoked_at.is_none_or(|revoked_at| now < revoked_at)
                && entry
                    .hpke_suites
                    .contains(&arkret_sdk::RecoveryHpkeSuite::X25519ChaCha20Poly1305)
        })
        .collect::<Vec<_>>();
    let [agreement] = matches.as_slice() else {
        return Err(anyhow!(
            "recovery public key must uniquely match one active backup-HPKE agreement in the accepted policy"
        ));
    };
    if !body
        .signing_keys()
        .into_iter()
        .any(|entry| entry.backup_hpke.key_agreement_ref == agreement.key_agreement_ref)
    {
        return Err(anyhow!(
            "active backup-HPKE agreement is not paired with a recovery proof key"
        ));
    }
    Ok((
        agreement.key_agreement_ref.to_string(),
        policy.policy_id.to_string(),
        policy.version,
    ))
}

// Invariant assertions: each `expect` message names the check that
// establishes it a few lines earlier. Rewriting them as `?` would add
// error paths no caller can reach.
#[allow(clippy::expect_used)]
async fn ensure_initial_active_series(
    api: &crate::transport::TransportClient,
    control_realm: &arkret_sdk::RealmId,
    authority: &arkret_sdk::AccountId,
    actor_id: &str,
    device_id: &str,
    backup_kind: BackupRotationKind,
    series_id: &str,
) -> Result<()> {
    let wire_kind = super::rotation_transaction::wire_backup_kind(backup_kind);
    let http = api.sdk_http_client()?;
    let current = api
        .list_key_backups_page(&arkret_sdk::KeyBackupsListQuery {
            series_id: None,
            backup_kind: None,
            cursor: None,
            limit: Some(1),
        })
        .await?
        .active_series;
    if current.account_id != *authority || current.control_realm_id != *control_realm {
        return Err(anyhow!(
            "backup pointer response belongs to another account or PCR"
        ));
    }
    let kind = arkret_sdk::BackupKind::try_from(wire_kind).map_err(anyhow::Error::msg)?;
    let active = current.pointer(kind).series_id().map(|id| id.as_str());
    if let Some(active) = active {
        if active == series_id {
            return Ok(());
        }
        return Err(anyhow!(
            "uploaded {wire_kind} envelope does not belong to the authoritative active series"
        ));
    }

    let submitter = api.event_submitter()?;
    // This is a new ordinary PCR Control authoring boundary. A concurrent
    // account reconnect can advance the device-cache epoch after recovery
    // policy publication, invalidating the earlier onboarding snapshot. Read
    // and cache the Station frontier again here instead of borrowing that
    // stale checkpoint for the active-series Event.
    submitter
        .refresh_realm_governance_frontier(control_realm.as_str())
        .await?;
    let frontier = submitter
        .seals_frontier_realm_head(control_realm.as_str())
        .await?;
    let trust_anchor = super::rotation_transaction::current_controller_backup_trust_anchor(
        &http, authority, device_id,
    )
    .await?;
    let event = super::rotation_transaction::build_active_series_event(
        control_realm,
        actor_id,
        authority,
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
    let account_actor = event.actor_id().clone();
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
    let active_series_digest = active_series_event_id.event_digest();
    let seal = crate::event_signer::prepare_and_sign_pcr_successor(
        &http,
        &account_actor,
        control_realm,
        frontier.id.clone(),
        vec![active_series_digest.clone()],
    )
    .await?;
    let seal_outcome = http.events_submit_seal(&seal).await?;
    if seal_outcome.seal_id != seal.id
        || seal_outcome.accepted_event_digests != seal.delta
        || seal_outcome.post_state_root != seal.state_root
    {
        return Err(anyhow!(
            "Station returned a mismatched key-backup active-series Seal outcome"
        ));
    }
    crate::event_signer::clear_prepared_pcr_successor(&seal).await?;
    if !seal_outcome
        .accepted_event_digests
        .iter()
        .any(|digest| digest == &active_series_digest)
    {
        return Err(anyhow!(
            "Station did not seal the {wire_kind} active-series Event"
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
    let class = arkret_sdk::BackupKind::try_from(wire_kind).map_err(|error| anyhow!(error))?;
    let series_id = match active_secret_storage_series_id_for(
        list_payload,
        class,
    ) {
        Some(series_id) => series_id.to_owned(),
        None => {
            let series_ids = crate::mls::runtime::iter_backup_bodies(list_payload)
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
            (*series_ids
                .first()
                .ok_or_else(|| anyhow!("{wire_kind} series inventory changed unexpectedly"))?)
            .to_owned()
        }
    };
    let metadata = crate::mls::runtime::iter_backup_bodies(list_payload)
        .filter(|body| body.get("backup_kind").and_then(Value::as_str) == Some(wire_kind))
        .filter(|body| body.get("series_id").and_then(Value::as_str) == Some(series_id.as_str()))
        .max_by_key(|body| backup_series_seq_of(body))
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
/// This is the upload half of the backup-prompt flow (the inverse of
/// [`crate::mls::account_recovery::auto_restore_mls_history_with_passphrase`]).
/// It re-uses any prior account-secret backup's `backup_id`/series so the upload
/// stays in the same rotation series. Returns the `backup_id` it wrote.
pub async fn upload_mls_account_secret_backup_with_passphrase(
    api: &crate::transport::TransportClient,
    secure_store: &dyn crate::secure_key_store::SecureKeyStore,
    authority: &arkret_sdk::AccountId,
    control_realm: &arkret_sdk::RealmId,
    actor_id: &str,
    device_id: &str,
    passphrase: &[u8],
) -> Result<String> {
    if passphrase_is_blank(passphrase) {
        return Err(anyhow!(
            "recovery passphrase is required to back up the account MLS secret"
        ));
    }

    let stored = crate::mls::runtime::load_account_mls_secret(secure_store, authority)
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
    let creates_initial_series = previous_account_backup.is_none();
    // Fresh backup_id per immutable series link.
    let account_backup_id = fresh_backup_id();

    let kek = derive_vault_kek(passphrase).map_err(|err| anyhow!("derive KEK: {err}"))?;
    let signer = crate::event_signer::active_signer()
        .ok_or_else(|| anyhow!("active device signer is required"))?;
    let account_body = if let Some(previous) = previous_account_backup.as_ref() {
        let predecessor = typed_backup_predecessor(previous)?;
        let frontier =
            current_backup_frontier_ref(api, control_realm, authority, device_id).await?;
        build_mls_account_secret_backup_successor_body_with_kek_and_version(
            &account_backup_id,
            &predecessor,
            device_id,
            &kek,
            &stored.secret,
            stored.version,
            &frontier.frontier_digest,
            frontier.device_generation_ref,
        )?
    } else {
        build_mls_account_secret_backup_body_with_kek_and_version(
            &account_backup_id,
            authority,
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
    if creates_initial_series {
        ensure_initial_active_series(
            api,
            control_realm,
            authority,
            actor_id,
            device_id,
            BackupRotationKind::SecretStorage,
            &account_series_id,
        )
        .await?;
    }
    crate::mls::runtime::mark_account_mls_secret_verified(secure_store, authority)
        .map_err(|err| anyhow!("mark uploaded account MLS secret verified: {err}"))?;

    Ok(account_backup_id)
}

/// Upload an HPKE `recovery_public_key` account-secret backup derived from the
/// user's 24-word Recovery Key.
pub async fn upload_mls_account_secret_backup_with_recovery_key(
    api: &crate::transport::TransportClient,
    secure_store: &dyn crate::secure_key_store::SecureKeyStore,
    authority: &arkret_sdk::AccountId,
    control_realm: &arkret_sdk::RealmId,
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
        authority,
        control_realm,
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
    authority: &arkret_sdk::AccountId,
    control_realm: &arkret_sdk::RealmId,
    actor_id: &str,
    device_id: &str,
    recovery_public_key: &[u8],
) -> Result<String> {
    if crate::mls_api_helpers::principal_core_id(actor_id)? != authority.principal_id {
        return Err(anyhow!("backup signer does not match the supplied account"));
    }
    if recovery_public_key.is_empty() {
        return Err(anyhow!("recovery public key is required"));
    }
    let stored = crate::mls::runtime::load_account_mls_secret(secure_store, authority)
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
    let creates_initial_series = previous_account_backup.is_none();

    // SEC-05: stamp the actor's currently-accepted recovery policy into the
    // backup's `recovery_policy_ref` so a fresh-device restore can verify it
    // against the live policy and reject an old-policy / non-frontier replay.
    let active_policy = crate::recovery_flow::fetch_active_recovery_policy(api)
        .await
        .map_err(|err| anyhow!("fetch active recovery policy for backup binding: {err}"))?;
    let active_policy = active_policy
        .as_ref()
        .ok_or_else(|| anyhow!("active recovery policy is required for account-secret backup"))?;
    let (recovery_key_ref, recovery_policy_id, recovery_policy_version) =
        active_recovery_backup_recipient(active_policy, authority, actor_id, recovery_public_key)?;
    let recovery_policy_ref = (recovery_policy_id.as_str(), recovery_policy_version);

    let account_backup_id = fresh_backup_id();
    let signer = crate::event_signer::active_signer()
        .ok_or_else(|| anyhow!("active device signer is required"))?;
    let frontier_ref = if previous_account_backup.is_some() {
        Some(current_backup_frontier_ref(api, control_realm, authority, device_id).await?)
    } else {
        None
    };
    let account_body = build_mls_account_secret_recovery_public_key_backup_in_series(
        &account_backup_id,
        authority,
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
    if creates_initial_series {
        ensure_initial_active_series(
            api,
            control_realm,
            authority,
            actor_id,
            device_id,
            BackupRotationKind::SecretStorage,
            &account_series_id,
        )
        .await?;
    }
    crate::mls::runtime::mark_account_mls_secret_verified(secure_store, authority)
        .map_err(|err| anyhow!("mark uploaded account MLS secret verified: {err}"))?;

    Ok(account_backup_id)
}

/// X5.3 — wrap the entire local-plaintext sidecar map behind a KEK derived from
/// the ACCOUNT SECRET and upload it to soland's `secret_storage` endpoint.
///
/// The KEK source is the account secret (already recoverable via the passphrase
/// through the X3 `mls_account_secret` backup), so the restore flow decrypts the
/// sidecar with no second passphrase prompt. Reuses any prior sidecar backup's
/// `backup_id`/series so the upload stays in the same rotation series
/// (`series_seq++` whenever the sidecar changes). Returns the `backup_id` it
/// wrote. Errors if no local account secret exists (the user hasn't used
/// encryption, so there is nothing to wrap the sidecar with).
pub async fn upload_mls_private_plaintext_backup(
    api: &crate::transport::TransportClient,
    secure_store: &dyn crate::secure_key_store::SecureKeyStore,
    authority: &arkret_sdk::AccountId,
    control_realm: &arkret_sdk::RealmId,
    actor_id: &str,
    device_id: &str,
    sidecar_json: &[u8],
) -> Result<String> {
    let previous_backup = fetch_mls_private_plaintext_backup_body(api, actor_id, device_id).await?;
    let (backup_id, _) = upload_mls_private_plaintext_backup_with_previous(
        api,
        secure_store,
        authority,
        control_realm,
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
    authority: &arkret_sdk::AccountId,
    control_realm: &arkret_sdk::RealmId,
    actor_id: &str,
    device_id: &str,
    sidecar_json: &[u8],
    previous_backup: Option<&Value>,
) -> Result<(String, Value)> {
    let stored = crate::mls::runtime::load_account_mls_secret(secure_store, authority)
        .map_err(|err| anyhow!("load account MLS secret: {err}"))?
        .ok_or_else(|| anyhow!("no account secret; cannot back up private plaintext"))?;

    let kek =
        derive_vault_kek(stored.secret.as_bytes()).map_err(|err| anyhow!("derive KEK: {err}"))?;
    // Fresh backup_id per immutable series link.
    let backup_id = fresh_backup_id();

    let previous_backup = match previous_backup {
        Some(previous) => Some(previous.clone()),
        None => {
            let list_payload = fetch_mls_restore_payload(api, actor_id).await?;
            fetch_active_series_tail(
                api,
                &list_payload,
                actor_id,
                device_id,
                BackupRotationKind::SecretStorage,
            )
            .await?
        }
    };
    let creates_initial_series = previous_backup.is_none();
    let signer = crate::event_signer::active_signer()
        .ok_or_else(|| anyhow!("active device signer is required"))?;
    let body = if let Some(previous) = previous_backup.as_ref() {
        let predecessor = typed_backup_predecessor(previous)?;
        let frontier =
            current_backup_frontier_ref(api, control_realm, authority, device_id).await?;
        build_mls_private_plaintext_backup_successor_body_with_kek(
            &backup_id,
            &predecessor,
            device_id,
            &kek,
            sidecar_json,
            &frontier.frontier_digest,
            frontier.device_generation_ref,
        )?
    } else {
        build_mls_private_plaintext_backup_body_with_kek(
            &backup_id,
            authority,
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
    if creates_initial_series {
        ensure_initial_active_series(
            api,
            control_realm,
            authority,
            actor_id,
            device_id,
            BackupRotationKind::SecretStorage,
            &series_id,
        )
        .await?;
    }

    Ok((backup_id, serde_json::to_value(sent_body)?))
}
