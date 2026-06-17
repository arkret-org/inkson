//! MLS-history backup body construction, decode, and restore.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
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

pub fn build_mls_history_backup_body(
    snapshot: &crate::mls::persistence::MlsSnapshotEnvelope,
    actor_id: &str,
    device_id: &str,
) -> (String, Value) {
    let backup_id = format!("ck:backup:{}", crate::operation::uuid_v7());
    let body = snapshot.to_key_backup_body(&backup_id, actor_id, device_id);
    (backup_id, body)
}

pub async fn upload_mls_snapshot_backup(
    api: &crate::api::CokretApi,
    snapshot: &crate::mls::persistence::MlsSnapshotEnvelope,
    actor_id: &str,
    device_id: &str,
) -> Result<String, MlsRuntimeError> {
    let (backup_id, body) = build_mls_history_backup_body(snapshot, actor_id, device_id);
    api.put_key_backup(&backup_id, body)
        .await
        .map_err(|err| MlsRuntimeError::Backup(err.to_string()))?;
    Ok(backup_id)
}

pub fn decode_mls_history_backup_envelope(
    body: &Value,
) -> Result<crate::mls::persistence::MlsSnapshotEnvelope, MlsRuntimeError> {
    crate::key_backup::validate_key_backup_envelope(
        body,
        Some(crate::key_backup::KeyBackupClass::MlsHistory),
    )
    .map_err(MlsRuntimeError::BackupDecode)?;
    let ciphertext = body
        .get("ciphertext")
        .and_then(Value::as_str)
        .ok_or_else(|| MlsRuntimeError::BackupDecode("ciphertext is required".to_owned()))?;
    let bytes = URL_SAFE_NO_PAD
        .decode(ciphertext.as_bytes())
        .map_err(|err| MlsRuntimeError::BackupDecode(format!("ciphertext base64url: {err}")))?;
    let envelope: crate::mls::persistence::MlsSnapshotEnvelope = serde_json::from_slice(&bytes)
        .map_err(|err| MlsRuntimeError::BackupDecode(format!("snapshot envelope json: {err}")))?;

    let meta = body
        .get("envelope_meta")
        .ok_or_else(|| MlsRuntimeError::BackupDecode("envelope_meta is required".to_owned()))?;
    require_backup_str(meta, "realm_ref", &envelope.realm_id)?;
    require_backup_str(meta, "group_id", &envelope.group_id)?;
    require_backup_u64(meta, "epoch", envelope.epoch)?;

    let contents = body
        .get("contents")
        .and_then(Value::as_array)
        .ok_or_else(|| MlsRuntimeError::BackupDecode("contents must be an array".to_owned()))?;
    let Some(group_state) = contents
        .iter()
        .find(|item| item.get("item_type").and_then(Value::as_str) == Some("mls_group_state"))
    else {
        return Err(MlsRuntimeError::BackupDecode(
            "contents must include mls_group_state".to_owned(),
        ));
    };
    require_backup_str(group_state, "realm_ref", &envelope.realm_id)?;
    require_backup_str(group_state, "mls_group_id", &envelope.group_id)?;
    require_backup_u64(group_state, "epoch", envelope.epoch)?;

    Ok(envelope)
}

pub fn mls_restore_epoch_floor(
    state_store: &crate::local_state::LocalStateStore,
    realm_id: &str,
) -> u64 {
    let seal_epoch = state_store
        .seal_view_for_realm(realm_id)
        .mls_epoch
        .unwrap_or(0);
    let local_epoch = state_store
        .mls_snapshot_for(realm_id)
        .map(|snapshot| snapshot.epoch)
        .unwrap_or(0);
    seal_epoch.max(local_epoch)
}

pub fn restore_mls_history_backup_with_device_snapshot(
    state_store: &mut crate::local_state::LocalStateStore,
    secure_store: &dyn SecureKeyStore,
    actor_id: &str,
    device_id: &str,
    body: &Value,
) -> Result<MlsHistoryRestoreSummary, MlsRuntimeError> {
    let envelope = decode_mls_history_backup_envelope(body)?;
    let secret = load_device_snapshot_secret(secure_store, actor_id, device_id)
        .map_err(MlsRuntimeError::DeviceSecret)?;
    let epoch_floor = mls_restore_epoch_floor(state_store, &envelope.realm_id);
    crate::mls::persistence::restore_envelope(&envelope, &secret, epoch_floor)
        .map_err(|err| MlsRuntimeError::SnapshotRestore(err.to_string()))?;
    let summary = MlsHistoryRestoreSummary {
        backup_id: body
            .get("backup_id")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned),
        realm_id: envelope.realm_id.clone(),
        group_id: envelope.group_id.clone(),
        envelope_epoch: envelope.epoch,
        epoch_floor,
    };
    state_store.save_mls_snapshot(envelope.realm_id.clone(), envelope);
    Ok(summary)
}

fn require_backup_str(body: &Value, key: &str, expected: &str) -> Result<(), MlsRuntimeError> {
    match body.get(key).and_then(Value::as_str) {
        Some(actual) if actual == expected => Ok(()),
        Some(actual) => Err(MlsRuntimeError::BackupDecode(format!(
            "{key} mismatch: expected {expected} got {actual}"
        ))),
        None => Err(MlsRuntimeError::BackupDecode(format!("{key} is required"))),
    }
}

fn require_backup_u64(body: &Value, key: &str, expected: u64) -> Result<(), MlsRuntimeError> {
    match body.get(key).and_then(Value::as_u64) {
        Some(actual) if actual == expected => Ok(()),
        Some(actual) => Err(MlsRuntimeError::BackupDecode(format!(
            "{key} mismatch: expected {expected} got {actual}"
        ))),
        None => Err(MlsRuntimeError::BackupDecode(format!("{key} is required"))),
    }
}
