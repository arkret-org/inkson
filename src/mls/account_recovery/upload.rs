//! Backup / rotation upload flow and superseded-backup cleanup.

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
use crate::mls::runtime::select_mls_private_plaintext_backup;
use crate::recovery_crypto::derive_vault_kek;

fn passphrase_is_blank(passphrase: &[u8]) -> bool {
    passphrase.is_empty()
        || std::str::from_utf8(passphrase)
            .map(|text| text.trim().is_empty())
            .unwrap_or(false)
}

#[cfg(test)]
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
    let basis = super::current_basis::ConfirmedBackupBasis::read(
        api,
        authority,
        control_realm,
        device_id,
        None,
    )
    .await?;
    let current = basis.state()?;
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
    // The holder-private projection provides this observed PCR basis;
    // a collaboration snapshot is not a PCR read surface.
    let source_realm_commit_id = basis.state()?.authority_commit_id.clone();
    let trust_anchor = basis.trust_anchor()?;
    let event = super::rotation_transaction::build_active_series_event(
        control_realm,
        actor_id,
        authority,
        backup_kind,
        series_id,
        1,
        &[],
        &source_realm_commit_id,
        trust_anchor,
    )?;
    basis.check()?;
    let accepted = submitter.submit_sdk_event(&event).await?;
    basis.check()?;
    if !accepted.is_committed() {
        return Err(anyhow!(
            "Station did not commit the {wire_kind} active-series Event"
        ));
    }

    Ok(())
}

fn ordered_active_summaries(
    list: &arkret_sdk::KeysBackupsList,
    backup_kind: arkret_sdk::BackupKind,
) -> Result<Vec<&arkret_sdk::KeyBackupSummary>> {
    let Some(series_id) = list.active_series.secret_storage.series_id() else {
        // Absent is the Station's current result. Orphan inventory cannot
        // select a predecessor or prevent a fresh version-one initialization.
        return Ok(Vec::new());
    };
    anyhow::ensure!(
        !list.has_more && list.next_cursor.is_none(),
        "backup predecessor inventory is incomplete"
    );
    let mut summaries = list
        .backups
        .iter()
        .filter(|row| row.backup_kind == backup_kind && &row.series_id == series_id)
        .collect::<Vec<_>>();
    anyhow::ensure!(
        !summaries.is_empty(),
        "confirmed active backup series has no envelopes"
    );
    anyhow::ensure!(
        summaries.len() <= 4096 && serde_json::to_vec(&summaries)?.len() <= 8 * 1024 * 1024,
        "active backup series exceeds this device's recovery metadata budget"
    );
    summaries.sort_by_key(|row| row.series_seq);
    let actor = arkret_sdk::ActorId::account(list.active_series.account_id.clone());
    let mut ids = std::collections::BTreeSet::new();
    for (index, row) in summaries.iter().enumerate() {
        anyhow::ensure!(
            row.actor_id == actor,
            "backup predecessor has another complete Account actor"
        );
        anyhow::ensure!(
            row.series_seq == index as u64 && ids.insert(row.backup_id.clone()),
            "backup predecessor chain has duplicate sequence, gap or fork"
        );
        if index == 0 {
            anyhow::ensure!(
                row.supersedes_id.clone().flatten().is_none() && row.supersedes_digest.is_none(),
                "backup series root has a predecessor"
            );
        } else {
            anyhow::ensure!(
                row.supersedes_id.clone().flatten().as_ref()
                    == Some(&summaries[index - 1].backup_id)
                    && row.supersedes_digest.is_some(),
                "backup predecessor chain has a broken link"
            );
        }
    }
    Ok(summaries)
}

fn verified_full_tail<'a>(
    bodies: &'a [arkret_sdk::KeyBackup],
    summaries: &[&arkret_sdk::KeyBackupSummary],
) -> Result<&'a arkret_sdk::KeyBackup> {
    anyhow::ensure!(
        bodies.len() == summaries.len() && !bodies.is_empty(),
        "backup full chain is incomplete"
    );
    for (body, summary) in bodies.iter().zip(summaries) {
        anyhow::ensure!(
            crate::key_backup::backup_matches_summary(body, summary),
            "backup full envelope differs from its exact listed summary"
        );
    }
    let tail = bodies
        .last()
        .ok_or_else(|| anyhow!("backup full chain has no tail"))?;
    // The ordered complete candidate set bounds series_seq before the shared
    // verifier walks every canonical supersedes digest back to its root.
    garth::mls::backup_series::verify_series_chain(tail, bodies)?;
    Ok(tail)
}

fn ensure_current_tail_signer(
    signer: &std::sync::Arc<crate::event_signer::InksonEventSigner>,
) -> Result<()> {
    let current = crate::event_signer::active_signer()
        .ok_or_else(|| anyhow!("active backup signer was removed"))?;
    anyhow::ensure!(
        std::sync::Arc::ptr_eq(signer, &current),
        "active backup signer was replaced"
    );
    Ok(())
}

async fn fetch_active_series_tail(
    api: &crate::transport::TransportClient,
    list_payload: &Value,
    actor_id: &str,
    device_id: &str,
    backup_kind: BackupRotationKind,
) -> Result<Option<Value>> {
    let class = arkret_sdk::BackupKind::try_from(super::rotation_transaction::wire_backup_kind(
        backup_kind,
    ))
    .map_err(|error| anyhow!(error))?;
    let list: arkret_sdk::KeysBackupsList = serde_json::from_value(list_payload.clone())?;
    anyhow::ensure!(
        crate::mls_api_helpers::principal_core_id(actor_id)?
            == list.active_series.account_id.principal_id,
        "backup predecessor principal differs from the confirmed Account"
    );
    let http = api.sdk_http_client()?;
    let source = crate::transport::own_station_results::client_for_http(&http).await?;
    super::current_basis::read_list_with_source(
        &http,
        &source,
        &list.active_series.account_id,
        &list.active_series.control_realm_id,
        Some(&list.active_series),
    )
    .await?;
    let summaries = ordered_active_summaries(&list, class)?;
    if summaries.is_empty() {
        return Ok(None);
    }
    let signer = crate::event_signer::active_signer()
        .ok_or_else(|| anyhow!("active device signer is required"))?;
    anyhow::ensure!(
        signer.device_id() == Some(device_id),
        "backup predecessor signer has another device"
    );
    let mut bodies = Vec::with_capacity(summaries.len());
    let mut bytes = 0usize;
    for summary in &summaries {
        source.check_session()?;
        ensure_current_tail_signer(&signer)?;
        let metadata = serde_json::to_value(summary)?;
        let value = crate::key_backup::fetch_key_backup_with_device_unlock_proof_retrying(
            api,
            &metadata,
            actor_id,
            device_id,
            Some(&signer),
        )
        .await?;
        source.check_session()?;
        ensure_current_tail_signer(&signer)?;
        bytes = bytes.saturating_add(serde_json::to_vec(&value)?.len());
        anyhow::ensure!(
            bytes <= 8 * 1024 * 1024,
            "active backup full chain exceeds this device's recovery material budget"
        );
        let body = serde_json::from_value::<arkret_sdk::KeyBackup>(value)?;
        super::current_basis::verify_envelope_source(
            &http,
            &source,
            &list.active_series.account_id,
            &body,
        )
        .await?;
        ensure_current_tail_signer(&signer)?;
        bodies.push(body);
    }
    let tail = verified_full_tail(&bodies, &summaries)?;
    super::current_basis::read_list_with_source(
        &http,
        &source,
        &list.active_series.account_id,
        &list.active_series.control_realm_id,
        Some(&list.active_series),
    )
    .await?;
    source.check_session()?;
    Ok(Some(serde_json::to_value(tail)?))
}

/// Wrap the local account MLS secret behind a freshly-derived recovery KEK and
/// upload it to coland's `secret_storage` endpoint.
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
    let expected_pointer = super::current_basis::state_from_payload(&list_payload)?;
    let basis = super::current_basis::ConfirmedBackupBasis::read(
        api,
        authority,
        control_realm,
        device_id,
        Some(&expected_pointer),
    )
    .await?;
    let signer = crate::event_signer::active_signer()
        .ok_or_else(|| anyhow!("active device signer is required"))?;
    let auth = api.key_backup_auth_binding(authority, &signer).await?;
    basis.check_auth(&auth)?;
    let sign = |bytes: &[u8]| {
        signer.sign_raw(bytes).map_err(|error| {
            arkret_crypto::KeyBackupError::InvalidInput(format!(
                "device key backup signature: {error}"
            ))
        })
    };
    let account_body = if let Some(previous) = previous_account_backup.as_ref() {
        let predecessor = typed_backup_predecessor(previous)?;
        let source_commit_ref = basis.source_commit_ref()?;
        build_mls_account_secret_backup_successor_body_with_kek_and_version(
            account_backup_id.as_str(),
            &predecessor,
            device_id,
            &kek,
            &stored.secret,
            stored.version,
            &auth,
            &sign,
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
            &auth,
            &sign,
            Some(basis.source_commit_ref()?),
        )?
    };
    let account_series_id = account_body.series_id.to_string();
    basis.check()?;
    api.put_key_backup(account_backup_id.as_str(), account_body)
        .await
        .map_err(|err| anyhow!("upload account MLS secret backup: {err}"))?;
    basis.check()?;
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
    basis.check()?;
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
    let expected_pointer = super::current_basis::state_from_payload(&list_payload)?;
    let basis = super::current_basis::ConfirmedBackupBasis::read(
        api,
        authority,
        control_realm,
        device_id,
        Some(&expected_pointer),
    )
    .await?;
    let signer = crate::event_signer::active_signer()
        .ok_or_else(|| anyhow!("active device signer is required"))?;
    let auth = api.key_backup_auth_binding(authority, &signer).await?;
    basis.check_auth(&auth)?;
    let sign = |bytes: &[u8]| {
        signer.sign_raw(bytes).map_err(|error| {
            arkret_crypto::KeyBackupError::InvalidInput(format!(
                "device key backup signature: {error}"
            ))
        })
    };
    let source_commit_ref = Some(basis.source_commit_ref()?);
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
        &auth,
        &sign,
        source_commit_ref,
    )?;
    let account_series_id = account_body.series_id.to_string();
    basis.check()?;
    api.put_key_backup(account_backup_id.as_str(), account_body)
        .await
        .map_err(|err| anyhow!("upload recovery-key account MLS secret backup: {err}"))?;
    basis.check()?;
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
    basis.check()?;
    crate::mls::runtime::mark_account_mls_secret_verified(secure_store, authority)
        .map_err(|err| anyhow!("mark uploaded account MLS secret verified: {err}"))?;

    Ok(account_backup_id.to_string())
}

/// X5.3 — wrap the entire local-plaintext sidecar map behind a KEK derived from
/// the ACCOUNT SECRET and upload it to coland's `secret_storage` endpoint.
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
    let body = crate::key_backup::fetch_key_backup_with_device_unlock_proof_retrying(
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
/// Debounced sidecar writes may provide their previously uploaded envelope.
/// It is revalidated against the complete confirmed active chain and pointer
/// before authoring a successor; a cached envelope is never current authority.
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

    let list_payload = fetch_mls_restore_payload(api, actor_id).await?;
    let confirmed_previous = fetch_active_series_tail(
        api,
        &list_payload,
        actor_id,
        device_id,
        BackupRotationKind::SecretStorage,
    )
    .await?;
    if let Some(cached) = previous_backup {
        anyhow::ensure!(
            confirmed_previous.as_ref() == Some(cached),
            "cached private backup differs from the confirmed full chain tail"
        );
    }
    let previous_backup = confirmed_previous;
    let creates_initial_series = previous_backup.is_none();
    let expected = super::current_basis::state_from_payload(&list_payload)?;
    let basis = super::current_basis::ConfirmedBackupBasis::read(
        api,
        authority,
        control_realm,
        device_id,
        Some(&expected),
    )
    .await?;
    match previous_backup.as_ref() {
        Some(previous) => {
            let predecessor = typed_backup_predecessor(previous)?;
            anyhow::ensure!(
                basis.state()?.secret_storage.series_id() == Some(&predecessor.series_id),
                "cached private backup is not the confirmed active series"
            );
        }
        None => anyhow::ensure!(
            basis.state()?.secret_storage.series_id().is_none(),
            "private backup initialization has a confirmed active series"
        ),
    }
    let signer = crate::event_signer::active_signer()
        .ok_or_else(|| anyhow!("active device signer is required"))?;
    let auth = api.key_backup_auth_binding(authority, &signer).await?;
    basis.check_auth(&auth)?;
    let sign = |bytes: &[u8]| {
        signer.sign_raw(bytes).map_err(|error| {
            arkret_crypto::KeyBackupError::InvalidInput(format!(
                "device key backup signature: {error}"
            ))
        })
    };
    let body = if let Some(previous) = previous_backup.as_ref() {
        let predecessor = typed_backup_predecessor(previous)?;
        let source_commit_ref = basis.source_commit_ref()?;
        build_mls_private_plaintext_backup_successor_body_with_kek(
            backup_id.as_str(),
            &predecessor,
            device_id,
            &kek,
            sidecar_json,
            &auth,
            &sign,
            Some(source_commit_ref),
        )?
    } else {
        build_mls_private_plaintext_backup_body_with_kek(
            backup_id.as_str(),
            authority,
            device_id,
            &kek,
            sidecar_json,
            &auth,
            &sign,
            Some(basis.source_commit_ref()?),
        )?
    };
    basis.check()?;
    let (_, sent_body) = api
        .put_key_backup_returning_sent_body(backup_id.as_str(), body)
        .await
        .map_err(|err| anyhow!("upload private plaintext backup: {err}"))?;
    basis.check()?;
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

    basis.check()?;
    Ok((backup_id.to_string(), serde_json::to_value(sent_body)?))
}

#[cfg(test)]
mod tests {
    use chrono::{TimeZone as _, Utc};

    use super::active_recovery_backup_recipient;

    fn summary(body: &arkret_sdk::KeyBackup) -> arkret_sdk::KeyBackupSummary {
        let mut wire = serde_json::to_value(body).unwrap();
        wire.as_object_mut().unwrap().retain(|key, _| {
            matches!(
                key.as_str(),
                "backup_id"
                    | "actor_id"
                    | "device_id"
                    | "backup_kind"
                    | "backup_version"
                    | "series_id"
                    | "series_seq"
                    | "supersedes_id"
                    | "supersedes_digest"
                    | "expires_at"
                    | "created_at"
                    | "updated_at"
                    | "ciphertext_digest"
                    | "retention"
            )
        });
        wire["encryption"] = serde_json::to_value(arkret_sdk::KeyBackupSummaryEncryption {
            recipient_method: body.encryption.recipient_method,
            recipient_key_ref: body.encryption.recipient_key_ref.clone(),
        })
        .unwrap();
        serde_json::from_value(wire).expect("closed summary of the actual sealed envelope")
    }

    pub(super) fn sealed_chain() -> (Vec<arkret_sdk::KeyBackup>, arkret_sdk::KeysBackupsList) {
        use ed25519_dalek::Signer as _;
        let account = crate::test_support::authority("did:web:alice.example");
        let device = "ak:device:01964137-0000-7000-8000-000000000001";
        let auth = arkret_crypto::backup::KeyBackupAuthBinding {
            device_id: arkret_sdk::DeviceId::new(device).unwrap(),
            verification_method: arkret_sdk::DidUrl::new(format!("did:web:alice.example#{device}"))
                .unwrap(),
            signature_algorithm: arkret_sdk::KeyBackupSignatureAlgorithm::Ed25519,
            device_authorize_event_id: arkret_sdk::EventId::from_digest(
                arkret_sdk::DigestSuite::Sha256,
                [4; 32],
            ),
        };
        let key = ed25519_dalek::SigningKey::from_bytes(&[42; 32]);
        let sign = |bytes: &[u8]| -> Result<Vec<u8>, arkret_crypto::KeyBackupError> {
            Ok(key.sign(bytes).to_bytes().to_vec())
        };
        let kek =
            crate::recovery_crypto::derive_vault_kek(b"correct horse battery staple").unwrap();
        let root = super::super::backup_body::build_mls_account_secret_backup_body_with_kek(
            "ak:backup:01964137-0000-7000-8000-00000000beef",
            &account,
            device,
            &kek,
            "qr6h9rJ8nU0H2pP5w3sLx1A4bC7dE9fG2hI5jK8lM0N",
            &auth,
            &sign,
            None,
        )
        .unwrap();
        let next = super::super::backup_body::build_mls_account_secret_backup_successor_body_with_kek_and_version(
            "ak:backup:01964137-0000-7000-8000-00000000cafe", &root, device, &kek,
            "qr6h9rJ8nU0H2pP5w3sLx1A4bC7dE9fG2hI5jK8lM0N", 1, &auth, &sign, None,
        ).unwrap();
        let bodies = vec![root, next];
        for body in &bodies {
            crate::key_backup::verify_key_backup_auth_data(body, &key.verifying_key()).unwrap();
        }
        let list = arkret_sdk::KeysBackupsList {
            backups: bodies.iter().map(summary).collect(),
            active_series: arkret_sdk::BackupActiveSeriesState {
                account_id: account,
                control_realm_id: arkret_sdk::RealmId::from_event_id(
                    &arkret_sdk::EventId::from_digest(arkret_sdk::DigestSuite::Sha256, [3; 32]),
                ),
                authority_commit_id: arkret_sdk::RealmCommitId::from_digest([7; 32]),
                secret_storage: arkret_sdk::BackupActiveSeriesPointer::Active {
                    active_series_id: bodies[0].series_id.clone(),
                    series_pointer_version: 1,
                },
            },
            next_cursor: None,
            has_more: false,
        };
        (bodies, list)
    }

    #[test]
    fn upload_envelope_verifies_actual_device_signature_and_exact_accepted_authorization() {
        let (bodies, list) = sealed_chain();
        let now = crate::clock::now_utc();
        let key = ed25519_dalek::SigningKey::from_bytes(&[42; 32]);
        let projection = arkret_sdk::VerifiedDeviceProjection {
            device_signing_key_did: arkret_sdk::DidKey::new(format!(
                "did:key:{}",
                arkret_sdk::ed25519_pubkey_to_did_key_multibase(&key.verifying_key().to_bytes())
            ))
            .unwrap(),
            hpke_key: arkret_sdk::NonEmptyString::new("fixture-hpke-key").unwrap(),
            device_authorize_event_id: bodies[0].auth_data.device_authorize_event_id.clone(),
            authorized_generation_ref: 1,
            device_status: arkret_sdk::DeviceStatus::Active,
            attested_at: now - chrono::Duration::seconds(1),
            expires_at: now + chrono::Duration::minutes(1),
            authorization_window: arkret_sdk::DeviceAuthorizationWindow {
                not_before: bodies[0].created_at - chrono::Duration::seconds(1),
                expires_at: None,
            },
        };
        let verify = |body: &arkret_sdk::KeyBackup,
                      projection: &arkret_sdk::VerifiedDeviceProjection| {
            super::super::current_basis::verify_envelope_projection(
                body,
                &list.active_series.account_id,
                projection,
                1,
                now,
            )
        };
        assert!(
            bodies[0].source_commit_ref.is_none(),
            "optional source checkpoint is not invented"
        );
        verify(&bodies[0], &projection)
            .expect("genuine device signature under exact accepted authorization");
        let mut wrong = projection.clone();
        wrong.device_authorize_event_id =
            arkret_sdk::EventId::from_digest(arkret_sdk::DigestSuite::Sha256, [9; 32]);
        assert!(
            verify(&bodies[0], &wrong)
                .unwrap_err()
                .to_string()
                .contains("historical authorization")
        );
        let mut wrong = projection.clone();
        wrong.device_signing_key_did = arkret_sdk::DidKey::new(format!(
            "did:key:{}",
            arkret_sdk::ed25519_pubkey_to_did_key_multibase(
                &ed25519_dalek::SigningKey::from_bytes(&[43; 32])
                    .verifying_key()
                    .to_bytes()
            )
        ))
        .unwrap();
        assert!(
            verify(&bodies[0], &wrong)
                .unwrap_err()
                .to_string()
                .contains("signature is invalid")
        );
        let mut wrong = projection.clone();
        wrong.authorization_window.not_before = bodies[0].created_at + chrono::Duration::seconds(1);
        assert!(
            verify(&bodies[0], &wrong)
                .unwrap_err()
                .to_string()
                .contains("authorization window")
        );
        let mut wrong = bodies[0].clone();
        wrong.auth_data.verification_method = arkret_sdk::DidUrl::new(format!(
            "{}#{}",
            projection.device_signing_key_did,
            projection
                .device_signing_key_did
                .as_str()
                .strip_prefix("did:key:")
                .unwrap()
        ))
        .unwrap();
        assert!(
            verify(&wrong, &projection)
                .unwrap_err()
                .to_string()
                .contains("complete Account/device"),
            "key DID does not alias the Account principal"
        );
        let mut wrong = bodies[0].clone();
        wrong.source_commit_ref = Some(arkret_sdk::KeyBackupSourceCommitRef {
            realm_commit_id: arkret_sdk::RealmCommitId::from_digest([7; 32]),
            device_generation_ref: 2,
        });
        assert!(
            verify(&wrong, &projection)
                .unwrap_err()
                .to_string()
                .contains("historical generation")
        );
    }

    #[test]
    fn upload_chain_uses_complete_signed_envelopes_and_canonical_supersedes_digest() {
        let (bodies, list) = sealed_chain();
        let ordered =
            super::ordered_active_summaries(&list, arkret_sdk::BackupKind::SecretStorage).unwrap();
        assert_eq!(
            super::verified_full_tail(&bodies, &ordered).unwrap(),
            &bodies[1]
        );
        let mut changed = bodies.clone();
        changed[1].supersedes_digest =
            Some(arkret_sdk::Hash::new(format!("sha256:{}", "00".repeat(32))).unwrap());
        let mut changed_list = list.clone();
        changed_list.backups[1] = summary(&changed[1]);
        let ordered =
            super::ordered_active_summaries(&changed_list, arkret_sdk::BackupKind::SecretStorage)
                .unwrap();
        assert!(
            super::verified_full_tail(&changed, &ordered).is_err(),
            "canonical predecessor digest mismatch must reject"
        );
        assert!(
            super::verified_full_tail(&bodies, &ordered)
                .unwrap_err()
                .to_string()
                .contains("exact listed summary")
        );
    }

    #[test]
    fn upload_chain_rejects_fork_gap_huge_sequence_and_wrong_complete_actor() {
        let (_, list) = sealed_chain();
        for sequence in [0, 2, u64::MAX] {
            let mut bad = list.clone();
            bad.backups[1].series_seq = sequence;
            assert!(
                super::ordered_active_summaries(&bad, arkret_sdk::BackupKind::SecretStorage)
                    .unwrap_err()
                    .to_string()
                    .contains("duplicate sequence, gap or fork")
            );
        }
        let mut bad = list.clone();
        bad.backups[1].supersedes_id = Some(Some(
            arkret_sdk::BackupId::new("ak:backup:01964137-0000-7000-8000-00000000ffff").unwrap(),
        ));
        assert!(
            super::ordered_active_summaries(&bad, arkret_sdk::BackupKind::SecretStorage)
                .unwrap_err()
                .to_string()
                .contains("broken link")
        );
        let mut bad = list.clone();
        let mut account = bad.active_series.account_id.clone();
        account.station_id = arkret_sdk::DidCoreId::new("ak:did_core:web:other.example").unwrap();
        bad.backups[1].actor_id = arkret_sdk::ActorId::account(account);
        assert!(
            super::ordered_active_summaries(&bad, arkret_sdk::BackupKind::SecretStorage)
                .unwrap_err()
                .to_string()
                .contains("complete Account")
        );
        let mut absent = list;
        absent.active_series.secret_storage = arkret_sdk::BackupActiveSeriesPointer::Absent {};
        assert!(
            super::ordered_active_summaries(&absent, arkret_sdk::BackupKind::SecretStorage)
                .unwrap()
                .is_empty(),
            "orphan inventory must not infer an active tail"
        );
    }

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
