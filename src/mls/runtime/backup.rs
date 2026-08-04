//! MLS-history backup body construction, decode, and restore.

use serde_json::Value;

use super::{MlsRuntimeError, load_device_snapshot_secret};
use crate::secure_key_store::SecureKeyStore;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MlsHistoryRestoreSummary {
    pub backup_id: Option<String>,
    pub realm_id: String,
    pub group_id: String,
    pub envelope_epoch: u64,
    pub epoch_floor: u64,
}

pub(crate) fn derive_mls_history_backup_key(
    account_secret: &str,
) -> Result<[u8; 32], MlsRuntimeError> {
    arkret_crypto::backup::derive_secret_storage_key(
        account_secret.as_bytes(),
        "mls_group_secrets_backup_key",
    )
    .map_err(|error| MlsRuntimeError::Backup(error.to_string()))
}

pub fn build_mls_history_backup_body(
    snapshot: &crate::mls::persistence::MlsSnapshotEnvelope,
    actor_id: &str,
    device_id: &str,
    signer: crate::key_backup::KeyBackupSigner<'_>,
) -> Result<(String, Value), MlsRuntimeError> {
    let store = crate::secure_key_store::default_secure_key_store("inkson");
    let account_secret = load_device_snapshot_secret(store.as_ref(), actor_id, device_id)
        .map_err(MlsRuntimeError::DeviceSecret)?;
    build_mls_history_backup_body_with_secret(
        snapshot,
        actor_id,
        device_id,
        &account_secret,
        signer,
    )
}

pub fn build_mls_history_backup_body_with_secret(
    snapshot: &crate::mls::persistence::MlsSnapshotEnvelope,
    actor_id: &str,
    device_id: &str,
    account_secret: &str,
    signer: crate::key_backup::KeyBackupSigner<'_>,
) -> Result<(String, Value), MlsRuntimeError> {
    let backup_id = format!("ak:backup:{}", crate::operation::uuid_v7());
    let wrap_key = derive_mls_history_backup_key(account_secret)?;
    let body = snapshot
        .to_key_backup_body(&backup_id, actor_id, device_id, &wrap_key, signer)
        .map_err(|error| MlsRuntimeError::Backup(error.to_string()))?;
    Ok((backup_id, body))
}

pub async fn upload_mls_snapshot_backup(
    api: &crate::transport::TransportClient,
    snapshot: &crate::mls::persistence::MlsSnapshotEnvelope,
    actor_id: &str,
    device_id: &str,
) -> Result<String, MlsRuntimeError> {
    let signer = crate::event_signer::active_signer();
    let (backup_id, body) =
        build_mls_history_backup_body(snapshot, actor_id, device_id, signer.as_ref())?;
    api.put_key_backup(&backup_id, body, signer.as_ref())
        .await
        .map_err(|err| MlsRuntimeError::Backup(err.to_string()))?;
    Ok(backup_id)
}

pub fn parse_mls_history_backup(body: &Value) -> Result<arkret_sdk::KeyBackup, MlsRuntimeError> {
    crate::key_backup::validate_key_backup_envelope(
        body,
        Some(crate::key_backup::BackupKind::MlsHistory),
    )
    .map_err(MlsRuntimeError::BackupDecode)?;
    serde_json::from_value(body.clone()).map_err(|error| {
        MlsRuntimeError::BackupDecode(format!("typed MLS-history backup: {error}"))
    })
}

pub fn decode_mls_history_backup_envelope(
    backup: &arkret_sdk::KeyBackup,
    account_secret: &str,
) -> Result<crate::mls::persistence::MlsSnapshotEnvelope, MlsRuntimeError> {
    if backup.backup_kind != crate::key_backup::BackupKind::MlsHistory {
        return Err(MlsRuntimeError::BackupDecode(
            "typed backup is not mls_history".to_owned(),
        ));
    }
    if backup.encryption.recipient_method != arkret_sdk::KeyBackupRecipientMethod::SecretStorageKey
    {
        return Err(MlsRuntimeError::BackupDecode(format!(
            "local account-secret decoder requires recipient_method=secret_storage_key, got {:?}",
            backup.encryption.recipient_method
        )));
    }
    let wrap_key = derive_mls_history_backup_key(account_secret)
        .map_err(|error| MlsRuntimeError::BackupDecode(error.user_message()))?;
    let aead_aad = serde_json::from_value(
        serde_json::to_value(&backup.domain_separation.aead_aad).map_err(|error| {
            MlsRuntimeError::BackupDecode(format!("key-backup AAD encode: {error}"))
        })?,
    )
    .map_err(|error| MlsRuntimeError::BackupDecode(format!("key-backup AAD: {error}")))?;
    let binding = arkret_crypto::backup::VaultBinding {
        backup_id: backup.backup_id.clone(),
        subdomain: backup.domain_separation.subdomain.clone(),
        aead_aad,
    };
    let nonce = backup.encryption.aead.nonce.as_ref().ok_or_else(|| {
        MlsRuntimeError::BackupDecode(
            "typed secret_storage_key backup invariant violated: nonce is required".to_owned(),
        )
    })?;
    let bytes = arkret_crypto::backup::decrypt_with_secret_storage_key(
        &wrap_key,
        &binding,
        nonce.as_str(),
        &backup.ciphertext,
        &backup.ciphertext_digest,
    )
    .map_err(|error| MlsRuntimeError::BackupDecode(error.to_string()))?;
    let envelope: crate::mls::persistence::MlsSnapshotEnvelope = serde_json::from_slice(&bytes)
        .map_err(|err| MlsRuntimeError::BackupDecode(format!("snapshot envelope json: {err}")))?;

    let Some(group_state) = backup
        .contents
        .iter()
        .find(|item| item.item_kind == "mls_group_state")
    else {
        return Err(MlsRuntimeError::BackupDecode(
            "contents must include mls_group_state".to_owned(),
        ));
    };
    require_backup_str(
        "realm_id",
        group_state.realm_id.as_ref().map(|value| value.as_str()),
        &envelope.realm_id,
    )?;
    require_backup_str(
        "mls_group_id",
        group_state.mls_group_id.as_deref(),
        &envelope.group_id,
    )?;
    require_backup_u64("epoch", group_state.epoch, envelope.epoch)?;
    let public_group_state_event_id = group_state.last_event_id.as_ref().map(ToString::to_string);
    let encrypted_group_state_event_id = envelope
        .group_state_event_id
        .as_ref()
        .map(ToString::to_string);
    if public_group_state_event_id.as_deref() != encrypted_group_state_event_id.as_deref() {
        return Err(MlsRuntimeError::BackupDecode(
            "contents.last_event_id does not match encrypted group-state Event reference"
                .to_owned(),
        ));
    }

    Ok(envelope)
}

pub fn mls_restore_epoch_floor(state_store: &crate::state::LocalStateStore, realm_id: &str) -> u64 {
    let seal_epoch = seal_view_epoch_floor(state_store, realm_id);
    let local_epoch = state_store
        .mls_snapshot_for(realm_id)
        .map(|snapshot| snapshot.epoch)
        .unwrap_or(0);
    seal_epoch.max(local_epoch)
}

/// COR-04: the Realm's Seal-view MLS epoch, used as the `current_epoch_floor`
/// the on-disk snapshot write paths (commit / encrypt / reaction-send) pass to
/// [`crate::mls::persistence::restore_envelope`].
///
/// Unlike [`mls_restore_epoch_floor`] this does NOT `max` in the local
/// snapshot's own epoch: at a write site the snapshot being restored *is* the
/// local snapshot, so folding its epoch back in would make
/// `decrypt_with_epoch_check` a tautology that can never fire. Returning only
/// the independently-sourced Seal-view epoch lets `OutdatedSnapshot` actually
/// trip when a concurrently-overwritten / rolled-back local snapshot has fallen
/// behind the Seal lattice (`persistence.rs` anti-stale-fork design, §2.9).
/// When no Seal view is known yet (`None`) the floor is `0` (no check), matching
/// the first-boot rehydrate semantics.
pub fn seal_view_epoch_floor(state_store: &crate::state::LocalStateStore, realm_id: &str) -> u64 {
    state_store
        .seal_view_for_realm(realm_id)
        .mls_epoch
        .unwrap_or(0)
}

pub fn restore_mls_history_backup_with_device_snapshot(
    state_store: &mut crate::state::LocalStateStore,
    secure_store: &dyn SecureKeyStore,
    actor_id: &str,
    device_id: &str,
    body: &Value,
) -> Result<MlsHistoryRestoreSummary, MlsRuntimeError> {
    let backup = parse_mls_history_backup(body)?;
    let secret = load_device_snapshot_secret(secure_store, actor_id, device_id)
        .map_err(MlsRuntimeError::DeviceSecret)?;
    let envelope = decode_mls_history_backup_envelope(&backup, &secret)?;
    let epoch_floor = mls_restore_epoch_floor(state_store, &envelope.realm_id);
    crate::mls::persistence::restore_envelope(&envelope, &secret, epoch_floor)
        .map_err(|err| MlsRuntimeError::SnapshotRestore(err.to_string()))?;
    let summary = MlsHistoryRestoreSummary {
        backup_id: Some(backup.backup_id.to_string()),
        realm_id: envelope.realm_id.clone(),
        group_id: envelope.group_id.clone(),
        envelope_epoch: envelope.epoch,
        epoch_floor,
    };
    if let Some(group_state_event_id) = envelope.group_state_event_id.clone() {
        state_store
            .record_mls_group_state_ref_for_effective_scope(
                envelope.realm_id.clone(),
                None,
                envelope.group_id.as_str(),
                envelope.epoch,
                group_state_event_id,
            )
            .map_err(MlsRuntimeError::Backup)?;
    }
    state_store.save_mls_snapshot(envelope.realm_id.clone(), envelope);
    Ok(summary)
}

fn require_backup_str(
    key: &str,
    actual: Option<&str>,
    expected: &str,
) -> Result<(), MlsRuntimeError> {
    match actual {
        Some(actual) if actual == expected => Ok(()),
        Some(actual) => Err(MlsRuntimeError::BackupDecode(format!(
            "{key} mismatch: expected {expected} got {actual}"
        ))),
        None => Err(MlsRuntimeError::BackupDecode(format!("{key} is required"))),
    }
}

fn require_backup_u64(
    key: &str,
    actual: Option<u64>,
    expected: u64,
) -> Result<(), MlsRuntimeError> {
    match actual {
        Some(actual) if actual == expected => Ok(()),
        Some(actual) => Err(MlsRuntimeError::BackupDecode(format!(
            "{key} mismatch: expected {expected} got {actual}"
        ))),
        None => Err(MlsRuntimeError::BackupDecode(format!("{key} is required"))),
    }
}
