//! Backup / rotation upload flow and superseded-backup cleanup.

use crate::mls::runtime::{
    active_secret_storage_series_id_for, backup_series_seq_of, select_mls_private_plaintext_backup,
};
use anyhow::{Result, anyhow};
use arkret_sdk::BackupRotationKind;
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

fn key_backup_source_commit_ref(
    realm_commit_id: arkret_sdk::RealmCommitId,
    device_generation_ref: u64,
) -> Result<arkret_sdk::KeyBackupSourceCommitRef> {
    if device_generation_ref == 0 {
        return Err(anyhow!(
            "key backup source_commit_ref device generation must be positive"
        ));
    }
    Ok(arkret_sdk::KeyBackupSourceCommitRef {
        realm_commit_id,
        device_generation_ref,
    })
}

async fn current_backup_source_commit_ref(
    api: &crate::transport::TransportClient,
    control_realm: &arkret_sdk::RealmId,
    authority: &arkret_sdk::AccountId,
    device_id: &str,
) -> Result<arkret_sdk::KeyBackupSourceCommitRef> {
    let http = api.sdk_http_client()?;
    let trust_anchor = super::rotation_transaction::current_controller_backup_trust_anchor(
        &http, authority, device_id,
    )
    .await?;
    let realm_commit_id = api
        .event_submitter()?
        .current_stream_head_for(&arkret_sdk::ScopeRef::Realm {
            realm_id: control_realm.clone(),
        })
        .await?;
    key_backup_source_commit_ref(realm_commit_id, trust_anchor.generation_ref)
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
    policy.validate_shape()?;
    body.validate_shape()?;
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
    if body.not_before.is_some_and(|not_before| now < not_before)
        || body.expires_at.is_some_and(|expires_at| now >= expires_at)
    {
        return Err(anyhow!(
            "active recovery policy is outside its validity interval"
        ));
    }
    let matches = body
        .methods
        .iter()
        .filter_map(|method| match method {
            arkret_sdk::RecoveryMethod::RecoveryUnlock { keys } => Some(keys.as_slice()),
            _ => None,
        })
        .flatten()
        .filter(|entry| {
            let agreement = &entry.backup_hpke;
            entry.not_before <= now
                && now < entry.expires_at
                && entry.revoked_at.is_none_or(|revoked_at| now < revoked_at)
                && agreement.public_key_multibase == multikey
                && agreement.not_before <= now
                && now < agreement.expires_at
                && agreement
                    .revoked_at
                    .is_none_or(|revoked_at| now < revoked_at)
                && agreement
                    .hpke_suites
                    .contains(&arkret_sdk::RecoveryBackupHpkeSuite::X25519AeadChacha20Poly1305V1)
        })
        .collect::<Vec<_>>();
    let [entry] = matches.as_slice() else {
        return Err(anyhow!(
            "recovery public key must uniquely match one active backup-HPKE agreement in the accepted policy"
        ));
    };
    Ok((
        entry.backup_hpke.key_agreement_ref.to_string(),
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
    let active = current.secret_storage.series_id().map(|id| id.as_str());
    if let Some(active) = active {
        if active == series_id {
            return Ok(());
        }
        return Err(anyhow!(
            "uploaded {wire_kind} envelope does not belong to the authoritative active series"
        ));
    }

    let submitter = api.event_submitter()?;
    // This is a new ordinary PCR Control authoring boundary. Resolve the
    // authenticated Realm stream head immediately before authoring so the
    // signed active-series record names the exact RealmCommit checkpoint it
    // observed, rather than carrying a removed Seal/frontier surrogate.
    let source_realm_commit_id = submitter
        .current_stream_head_for(&arkret_sdk::ScopeRef::Realm {
            realm_id: control_realm.clone(),
        })
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
        &source_realm_commit_id,
        &trust_anchor,
    )?;
    let accepted = submitter.submit_sdk_event(&event).await?;
    if !accepted.is_committed() {
        return Err(anyhow!(
            "Station did not commit the {wire_kind} active-series Event"
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
    let series_id = match active_secret_storage_series_id_for(list_payload, class) {
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
    let account_backup_id = fresh_backup_id().map_err(anyhow::Error::from)?;

    let kek = derive_vault_kek(passphrase).map_err(|err| anyhow!("derive KEK: {err}"))?;
    let signer = crate::event_signer::active_signer()
        .ok_or_else(|| anyhow!("active device signer is required"))?;
    let account_body = if let Some(previous) = previous_account_backup.as_ref() {
        let predecessor = typed_backup_predecessor(previous)?;
        let source_commit_ref =
            current_backup_source_commit_ref(api, control_realm, authority, device_id).await?;
        build_mls_account_secret_backup_successor_body_with_kek_and_version(
            account_backup_id.as_str(),
            &predecessor,
            device_id,
            &kek,
            &stored.secret,
            stored.version,
            Some(source_commit_ref),
        )?
    } else {
        build_mls_account_secret_backup_body_with_kek_and_version(
            account_backup_id.as_str(),
            authority,
            device_id,
            &kek,
            &stored.secret,
            stored.version,
            Some(current_backup_source_commit_ref(api, control_realm, authority, device_id).await?),
        )?
    };
    let account_series_id = account_body.series_id.to_string();
    api.put_key_backup(account_backup_id.as_str(), account_body, &signer)
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

    Ok(account_backup_id.to_string())
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

    let account_backup_id = fresh_backup_id().map_err(anyhow::Error::from)?;
    let signer = crate::event_signer::active_signer()
        .ok_or_else(|| anyhow!("active device signer is required"))?;
    let source_commit_ref =
        Some(current_backup_source_commit_ref(api, control_realm, authority, device_id).await?);
    let account_body = build_mls_account_secret_recovery_public_key_backup_in_series(
        account_backup_id.as_str(),
        authority,
        device_id,
        recovery_public_key,
        &recovery_key_ref,
        &stored.secret,
        stored.version,
        recovery_policy_ref,
        previous_account_backup.as_ref(),
        source_commit_ref,
    )?;
    let account_series_id = account_body.series_id.to_string();
    api.put_key_backup(account_backup_id.as_str(), account_body, &signer)
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

    Ok(account_backup_id.to_string())
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
    let backup_id = fresh_backup_id().map_err(anyhow::Error::from)?;

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
        let source_commit_ref =
            current_backup_source_commit_ref(api, control_realm, authority, device_id).await?;
        build_mls_private_plaintext_backup_successor_body_with_kek(
            backup_id.as_str(),
            &predecessor,
            device_id,
            &kek,
            sidecar_json,
            Some(source_commit_ref),
        )?
    } else {
        build_mls_private_plaintext_backup_body_with_kek(
            backup_id.as_str(),
            authority,
            device_id,
            &kek,
            sidecar_json,
            Some(current_backup_source_commit_ref(api, control_realm, authority, device_id).await?),
        )?
    };
    let (_, sent_body) = api
        .put_key_backup_returning_sent_body(backup_id.as_str(), body, &signer)
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

    Ok((backup_id.to_string(), serde_json::to_value(sent_body)?))
}

#[cfg(test)]
mod tests {
    use chrono::{TimeZone as _, Utc};

    use super::active_recovery_backup_recipient;

    #[test]
    fn source_checkpoint_has_one_closed_wire_shape() {
        let source =
            super::key_backup_source_commit_ref(arkret_sdk::RealmCommitId::from_digest([7; 32]), 4)
                .unwrap();
        let wire = serde_json::json!({"source_commit_ref": source});
        assert!(wire.get("source_ref").is_none());
        assert_eq!(wire["source_commit_ref"]["device_generation_ref"], 4);
        assert!(
            wire["source_commit_ref"]
                .get("committed_event_ref")
                .is_none()
        );

        assert!(
            serde_json::from_value::<arkret_sdk::KeyBackupSourceCommitRef>(serde_json::json!({
                "realm_commit_id": arkret_sdk::RealmCommitId::from_digest([7; 32]),
                "device_generation_ref": "4"
            }))
            .is_err()
        );
        assert!(
            serde_json::from_value::<arkret_sdk::KeyBackupSourceCommitRef>(serde_json::json!({
                "committed_event_ref": {
                    "event_id": "ak:event:AcIMom-0qqAXx_hmDJfxxaUJb_oJ64S3ARW1-WKFDCoD"
                },
                "device_generation_ref": 4
            }))
            .is_err()
        );
        assert!(
            super::key_backup_source_commit_ref(arkret_sdk::RealmCommitId::from_digest([7; 32]), 0)
                .is_err()
        );
    }

    fn policy_summary(
        public_key: &[u8; 32],
        signing_revoked: bool,
        suite: arkret_sdk::RecoveryBackupHpkeSuite,
    ) -> (arkret_sdk::RecoveryPolicySummary, arkret_sdk::AccountId) {
        let account_id = arkret_sdk::AccountId::new(
            arkret_sdk::DidCoreId::new("ak:did_core:webvh:z6mkholder").unwrap(),
            arkret_sdk::DidCoreId::new("ak:did_core:web:station.example").unwrap(),
        );
        let policy_id =
            arkret_sdk::PolicyId::new("ak:policy:019b1000-0000-7000-8000-000000000001").unwrap();
        let trust_domain =
            arkret_sdk::TrustDomainId::new("ak:trust_domain:station.example").unwrap();
        let not_before = Utc.timestamp_opt(1_700_000_000, 0).unwrap();
        let expires_at = Utc.timestamp_opt(2_000_000_000, 0).unwrap();
        let methods = vec![arkret_sdk::RecoveryMethod::RecoveryUnlock {
            keys: vec![arkret_sdk::RecoveryKeyEntry {
                verification_method: arkret_sdk::DidUrl::new(
                    "did:webvh:z6mkholder#recovery-proof-1",
                )
                .unwrap(),
                public_key_multibase: "z6MkgYhM6gL4zCv3DEv4bL3TqgH4A5yMSXPKfHKqzrMzqJK8".to_owned(),
                signature_algorithm: arkret_sdk::RecoverySignatureAlgorithm::Ed25519,
                not_before,
                expires_at,
                revoked_at: signing_revoked.then_some(not_before),
                backup_hpke: arkret_sdk::RecoveryKeyAgreementEntry {
                    key_agreement_ref: arkret_sdk::DidUrl::new(
                        "did:webvh:z6mkholder#backup-hpke-1",
                    )
                    .unwrap(),
                    key_agreement_algorithm: arkret_sdk::RecoveryKeyAgreementAlgorithm::X25519,
                    public_key_multibase: arkret_crypto::identity_root::x25519_public_multikey(
                        public_key,
                    ),
                    hpke_suites: vec![suite],
                    r#use: arkret_sdk::RecoveryKeyAgreementUse::BackupHpke,
                    not_before,
                    expires_at,
                    revoked_at: None,
                },
            }],
        }];
        let policy = arkret_sdk::RecoveryPolicy {
            schema: arkret_sdk::SchemaId::RECOVERY_POLICY_V1.to_owned(),
            policy_id: policy_id.clone(),
            account_id: account_id.clone(),
            version: 1,
            supersedes_id: None,
            trust_domain: trust_domain.clone(),
            cooldown_seconds: None,
            issued_at: not_before,
            not_before: Some(not_before),
            expires_at: Some(expires_at),
            auth_data: arkret_sdk::RecoveryPolicyAuthData {
                verification_method: arkret_sdk::DidUrl::new(
                    "did:webvh:z6mkholder#recovery-proof-1",
                )
                .unwrap(),
                signature_algorithm: arkret_sdk::RecoverySignatureAlgorithm::Ed25519,
                signature: arkret_sdk::Base64UrlString::new("AA".to_owned()).unwrap(),
            },
            methods: methods.clone(),
            extra: Default::default(),
        };
        (
            arkret_sdk::RecoveryPolicySummary {
                policy_id,
                account_id: account_id.clone(),
                version: 1,
                acceptance_basis_ref: arkret_sdk::RealmCommitId::from_digest([3; 32]),
                recovery_policy_ref: None,
                trust_domain,
                supersedes_id: None,
                issued_at: not_before,
                expires_at: Some(expires_at),
                accepted_at: Some(not_before),
                policy: Some(policy),
                methods,
            },
            account_id,
        )
    }

    #[test]
    fn recovery_backup_recipient_uses_the_inline_policy_entry() {
        let public_key = [7; 32];
        let (policy, account_id) = policy_summary(
            &public_key,
            false,
            arkret_sdk::RecoveryBackupHpkeSuite::X25519AeadChacha20Poly1305V1,
        );

        let (key_ref, policy_id, version) = active_recovery_backup_recipient(
            &policy,
            &account_id,
            account_id.principal_id.as_str(),
            &public_key,
        )
        .unwrap();

        assert_eq!(key_ref, "did:webvh:z6mkholder#backup-hpke-1");
        assert_eq!(policy_id, "ak:policy:019b1000-0000-7000-8000-000000000001");
        assert_eq!(version, 1);
    }

    #[test]
    fn recovery_backup_recipient_rejects_revoked_proof_key_or_wrong_suite() {
        let public_key = [7; 32];
        let cases = [
            (
                true,
                arkret_sdk::RecoveryBackupHpkeSuite::X25519AeadChacha20Poly1305V1,
            ),
            (
                false,
                arkret_sdk::RecoveryBackupHpkeSuite::X25519AeadAes256GcmV1,
            ),
        ];

        for (signing_revoked, suite) in cases {
            let (policy, account_id) = policy_summary(&public_key, signing_revoked, suite);
            let error = active_recovery_backup_recipient(
                &policy,
                &account_id,
                account_id.principal_id.as_str(),
                &public_key,
            )
            .unwrap_err();
            assert!(error.to_string().contains("uniquely match"));
        }
    }

    #[test]
    fn upload_backup_ids_are_formal_typed_ids() {
        let backup_id = super::fresh_backup_id().unwrap();
        let reparsed = arkret_sdk::BackupId::new(backup_id.to_string()).unwrap();
        assert_eq!(reparsed, backup_id);

        let foreign_namespace = backup_id.as_str().replacen("ak:backup:", "ak:event:", 1);
        assert!(arkret_sdk::BackupId::new(foreign_namespace).is_err());
    }
}
