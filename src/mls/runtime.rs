//! Shared MLS runtime helpers.
//!
//! Normal Realm/Kanban usage uses a device-scoped secret to wrap local MLS
//! snapshots. The runtime exposes typed readiness errors when a device has not
//! yet received a Welcome or restored an MLS-history backup.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::Value;

use crate::secure_key_store::{SecureKeyStore, SecureKeyStoreError};

const DEVICE_SNAPSHOT_SECRET_PREFIX: &str = "yougen.mls_snapshot.device_secret.v1";
const ACCOUNT_MLS_SECRET_PREFIX: &str = "yougen.mls_snapshot.account_secret.v1";

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MlsRuntimeStatus {
    Ready,
    MissingWelcome,
    MissingDeviceSecret(String),
    SnapshotDecryptFailed(String),
    UnsupportedTarget,
}

impl MlsRuntimeStatus {
    pub fn user_message(&self) -> String {
        match self {
            Self::Ready => "MLS state ready".to_owned(),
            Self::MissingWelcome => {
                "MLS state is not ready on this device yet; wait for an MLS Welcome or restore this device's encrypted MLS history backup.".to_owned()
            }
            Self::MissingDeviceSecret(reason) => {
                format!("device MLS snapshot secret unavailable: {reason}")
            }
            Self::SnapshotDecryptFailed(reason) => {
                format!("stored MLS history could not be decrypted ({reason}); restore your encrypted MLS history with your account recovery passphrase.")
            }
            Self::UnsupportedTarget => {
                "MLS runtime unavailable (internal error)".to_owned()
            }
        }
    }
}

#[derive(Debug)]
pub enum MlsRuntimeError {
    EmptyPlaintext,
    MissingWelcome,
    DeviceSecret(SecureKeyStoreError),
    Identity(String),
    Welcome(String),
    SnapshotRestore(String),
    Commit(String),
    Encrypt(String),
    Backup(String),
    BackupDecode(String),
    Serialize(String),
    Export(String),
    Salt(String),
}

impl MlsRuntimeError {
    pub fn status(&self) -> MlsRuntimeStatus {
        match self {
            Self::EmptyPlaintext => MlsRuntimeStatus::Ready,
            Self::MissingWelcome => MlsRuntimeStatus::MissingWelcome,
            Self::DeviceSecret(err) => MlsRuntimeStatus::MissingDeviceSecret(err.to_string()),
            Self::Identity(reason) | Self::Welcome(reason) => {
                MlsRuntimeStatus::SnapshotDecryptFailed(reason.clone())
            }
            Self::SnapshotRestore(reason) => {
                MlsRuntimeStatus::SnapshotDecryptFailed(reason.clone())
            }
            Self::Commit(_)
            | Self::Encrypt(_)
            | Self::Backup(_)
            | Self::BackupDecode(_)
            | Self::Serialize(_)
            | Self::Export(_)
            | Self::Salt(_) => MlsRuntimeStatus::Ready,
        }
    }

    pub fn user_message(&self) -> String {
        match self {
            Self::EmptyPlaintext => "internal: no MLS plaintext values to encrypt".to_owned(),
            Self::MissingWelcome | Self::DeviceSecret(_) | Self::SnapshotRestore(_) => {
                self.status().user_message()
            }
            Self::Identity(reason) => format!("MLS identity unavailable: {reason}"),
            Self::Welcome(reason) => format!("MLS Welcome could not be applied: {reason}"),
            Self::Commit(reason) => format!("MLS commit failed: {reason}"),
            Self::Encrypt(reason) => format!("MLS payload encryption failed: {reason}"),
            Self::Backup(reason) => format!("MLS history backup failed: {reason}"),
            Self::BackupDecode(reason) => format!("MLS history backup is invalid: {reason}"),
            Self::Serialize(reason) => {
                format!("MLS encrypted payload serialization failed: {reason}")
            }
            Self::Export(reason) => format!("MLS state export failed: {reason}"),
            Self::Salt(reason) => format!("MLS snapshot salt generation failed: {reason}"),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MlsHistoryRestoreSummary {
    pub backup_id: Option<String>,
    pub space_id: String,
    pub group_id: String,
    pub envelope_epoch: u64,
    pub epoch_floor: u64,
}

pub fn build_mls_history_backup_body(
    snapshot: &crate::mls::persistence::MlsSnapshotEnvelope,
    actor_did: &str,
    device_id: &str,
) -> (String, Value) {
    let backup_id = format!("cx:backup:{}", crate::operation::uuid_v7());
    let body = snapshot.to_key_backup_body(&backup_id, actor_did, device_id);
    (backup_id, body)
}

pub async fn upload_mls_snapshot_backup(
    api: &crate::api::ContrixApi,
    snapshot: &crate::mls::persistence::MlsSnapshotEnvelope,
    actor_did: &str,
    device_id: &str,
) -> Result<String, MlsRuntimeError> {
    let (backup_id, body) = build_mls_history_backup_body(snapshot, actor_did, device_id);
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
    require_backup_str(meta, "space_ref", &envelope.space_id)?;
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
    require_backup_str(group_state, "space_ref", &envelope.space_id)?;
    require_backup_str(group_state, "mls_group_id", &envelope.group_id)?;
    require_backup_u64(group_state, "epoch", envelope.epoch)?;

    Ok(envelope)
}

pub fn mls_restore_epoch_floor(
    state_store: &crate::local_state::LocalStateStore,
    space_id: &str,
) -> u64 {
    let anchor_epoch = state_store.anchor_view_for(space_id).mls_epoch.unwrap_or(0);
    let local_epoch = state_store
        .mls_snapshot_for(space_id)
        .map(|snapshot| snapshot.epoch)
        .unwrap_or(0);
    anchor_epoch.max(local_epoch)
}

pub fn restore_mls_history_backup_with_device_snapshot(
    state_store: &mut crate::local_state::LocalStateStore,
    secure_store: &dyn SecureKeyStore,
    actor_did: &str,
    device_id: &str,
    body: &Value,
) -> Result<MlsHistoryRestoreSummary, MlsRuntimeError> {
    let envelope = decode_mls_history_backup_envelope(body)?;
    let secret = load_device_snapshot_secret(secure_store, actor_did, device_id)
        .map_err(MlsRuntimeError::DeviceSecret)?;
    let epoch_floor = mls_restore_epoch_floor(state_store, &envelope.space_id);
    crate::mls::persistence::restore_envelope(&envelope, &secret, epoch_floor)
        .map_err(|err| MlsRuntimeError::SnapshotRestore(err.to_string()))?;
    let summary = MlsHistoryRestoreSummary {
        backup_id: body
            .get("backup_id")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned),
        space_id: envelope.space_id.clone(),
        group_id: envelope.group_id.clone(),
        envelope_epoch: envelope.epoch,
        epoch_floor,
    };
    state_store.save_mls_snapshot(envelope.space_id.clone(), envelope);
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

/// Legacy per-device storage key. Retained only for migration lookups: the
/// snapshot secret is now account-scoped (see [`account_mls_secret_key`]).
pub fn device_snapshot_secret_key(actor_did: &str, device_id: &str) -> String {
    format!(
        "{DEVICE_SNAPSHOT_SECRET_PREFIX}.{}.{}",
        actor_did.trim(),
        device_id.trim()
    )
}

/// Account-scoped storage key for the MLS snapshot secret shared by every
/// device of the account. Recoverable via the user's recovery passphrase.
pub fn account_mls_secret_key(actor_did: &str) -> String {
    format!("{ACCOUNT_MLS_SECRET_PREFIX}.{}", actor_did.trim())
}

/// Store (or overwrite) the account-scoped MLS snapshot secret. Used by the
/// recovery import path after unwrapping the recovery vault.
pub fn store_account_mls_secret(
    store: &dyn SecureKeyStore,
    actor_did: &str,
    secret: &str,
) -> Result<(), SecureKeyStoreError> {
    let actor = actor_did.trim();
    if actor.is_empty() {
        return Err(SecureKeyStoreError::Backend(
            "actor_did is required for MLS snapshot secret".to_owned(),
        ));
    }
    if secret.trim().is_empty() {
        return Err(SecureKeyStoreError::Backend(
            "account MLS secret must not be empty".to_owned(),
        ));
    }
    store.store_secret(&account_mls_secret_key(actor), secret)
}

/// Load (or create) the account-scoped MLS snapshot secret.
///
/// Resolution order:
///   a. an existing account secret is returned as-is;
///   b. otherwise, if a legacy device-scoped secret exists for `(actor,
///      device)`, it is *promoted* to the account key (so single-device users
///      keep their local MLS state) and returned;
///   c. otherwise a fresh random 32-byte secret is generated, stored under the
///      account key, and returned.
pub fn load_or_create_account_mls_secret(
    store: &dyn SecureKeyStore,
    actor_did: &str,
    device_id: &str,
) -> Result<String, SecureKeyStoreError> {
    let actor = actor_did.trim();
    if actor.is_empty() {
        return Err(SecureKeyStoreError::Backend(
            "actor_did is required for MLS snapshot secret".to_owned(),
        ));
    }
    let account_key = account_mls_secret_key(actor);
    // a. existing account secret wins.
    if let Some(existing) = store.get_secret(&account_key)?
        && !existing.trim().is_empty()
    {
        return Ok(existing);
    }
    // b. migrate a legacy device-scoped secret if one exists for this device.
    let device = device_id.trim();
    if !device.is_empty() {
        let device_key = device_snapshot_secret_key(actor, device);
        if let Some(legacy) = store.get_secret(&device_key)?
            && !legacy.trim().is_empty()
        {
            store.store_secret(&account_key, &legacy)?;
            return Ok(legacy);
        }
    }
    // c. generate a fresh account secret.
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes)
        .map_err(|err| SecureKeyStoreError::Backend(format!("getrandom: {err}")))?;
    let secret = URL_SAFE_NO_PAD.encode(bytes);
    store.store_secret(&account_key, &secret)?;
    Ok(secret)
}

/// Load-or-create the snapshot secret for `(actor, device)`.
///
/// The `device_id` parameter is retained for source compatibility and legacy
/// migration only; the secret is account-scoped and shared by every device.
pub fn load_or_create_device_snapshot_secret(
    store: &dyn SecureKeyStore,
    actor_did: &str,
    device_id: &str,
) -> Result<String, SecureKeyStoreError> {
    load_or_create_account_mls_secret(store, actor_did, device_id)
}

/// Load (without creating) the snapshot secret for `(actor, device)`.
///
/// Delegates to the account-scoped secret. As a migration convenience, if no
/// account secret exists yet but a legacy device-scoped secret does, the legacy
/// value is promoted to the account key and returned. `device_id` no longer
/// scopes the stored key.
pub fn load_device_snapshot_secret(
    store: &dyn SecureKeyStore,
    actor_did: &str,
    device_id: &str,
) -> Result<String, SecureKeyStoreError> {
    let actor = actor_did.trim();
    if actor.is_empty() {
        return Err(SecureKeyStoreError::Backend(
            "actor_did is required for MLS snapshot secret".to_owned(),
        ));
    }
    let account_key = account_mls_secret_key(actor);
    if let Some(existing) = store.get_secret(&account_key)?
        && !existing.trim().is_empty()
    {
        return Ok(existing);
    }
    // Migration: promote a legacy device-scoped secret if present.
    let device = device_id.trim();
    if !device.is_empty() {
        let device_key = device_snapshot_secret_key(actor, device);
        if let Some(legacy) = store.get_secret(&device_key)?
            && !legacy.trim().is_empty()
        {
            store.store_secret(&account_key, &legacy)?;
            return Ok(legacy);
        }
    }
    Err(SecureKeyStoreError::NotFound)
}

pub fn collect_welcome_entries(value: &serde_json::Value) -> Vec<serde_json::Value> {
    let mut welcomes = Vec::new();
    let Some(events) = value.get("events").and_then(|v| v.as_array()) else {
        return welcomes;
    };
    for entry in events {
        if entry.get("type").and_then(|t| t.as_str()) == Some("cx.mls.welcome")
            && let Some(content) = entry.get("content")
        {
            welcomes.push(content.clone());
        }
    }
    welcomes
}

pub fn apply_welcome_messages_with_device_snapshot(
    state_store: &mut crate::local_state::LocalStateStore,
    secure_store: &dyn SecureKeyStore,
    space_id: &str,
    actor_did: &str,
    device_id: &str,
    messages_value: &serde_json::Value,
) -> Result<usize, MlsRuntimeError> {
    let welcome_entries = collect_welcome_entries(messages_value);
    if welcome_entries.is_empty() {
        return Ok(0);
    }
    let secret = load_or_create_device_snapshot_secret(secure_store, actor_did, device_id)
        .map_err(MlsRuntimeError::DeviceSecret)?;
    let principal_did = contrix_sdk::Did::new(actor_did.to_owned())
        .map_err(|err| MlsRuntimeError::Identity(format!("{err:?}")))?;
    let device_id_typed = contrix_sdk::DeviceId::new(device_id.to_owned())
        .map_err(|err| MlsRuntimeError::Identity(format!("{err:?}")))?;
    let mut applied = 0usize;
    for welcome_value in welcome_entries {
        let Ok(welcome) = serde_json::from_value::<contrix_sdk::MlsWelcomeEnvelope>(welcome_value)
        else {
            continue;
        };
        let Ok(identity) = contrix_sdk::ContrixMlsIdentity::new_basic(
            principal_did.clone(),
            device_id_typed.clone(),
        ) else {
            continue;
        };
        let Ok(group) = contrix_sdk::ContrixMlsGroup::join_from_welcome(identity, &welcome) else {
            continue;
        };
        let Ok(post_state) = group.export_state_record() else {
            continue;
        };
        let mut salt = [0u8; 16];
        if getrandom::fill(&mut salt).is_err() {
            continue;
        }
        let snapshot = crate::mls::persistence::encrypt_state(
            space_id,
            &post_state.group_id,
            post_state.epoch,
            &post_state.serialized_state,
            &secret,
            &salt,
        );
        state_store.save_mls_snapshot(space_id.to_owned(), snapshot);
        applied += 1;
    }
    Ok(applied)
}

#[allow(clippy::type_complexity)]
pub fn encrypt_values_with_device_snapshot(
    state_store: &mut crate::local_state::LocalStateStore,
    secure_store: &dyn SecureKeyStore,
    space_id: &str,
    actor_did: &str,
    device_id: &str,
    content_type: &str,
    plaintext_values: &[Vec<u8>],
) -> Result<
    (
        contrix_sdk::Hash,
        Vec<contrix_sdk::Did>,
        Vec<serde_json::Value>,
        contrix_sdk::MlsCommitEnvelope,
    ),
    MlsRuntimeError,
> {
    if plaintext_values.is_empty() {
        return Err(MlsRuntimeError::EmptyPlaintext);
    }
    let snapshot = state_store
        .mls_snapshot_for(space_id)
        .ok_or(MlsRuntimeError::MissingWelcome)?;
    let secret = load_device_snapshot_secret(secure_store, actor_did, device_id)
        .map_err(MlsRuntimeError::DeviceSecret)?;
    let mut group = crate::mls::persistence::restore_envelope(&snapshot, &secret, 0)
        .map_err(|err| MlsRuntimeError::SnapshotRestore(err.to_string()))?;
    let commit_envelope = group
        .self_update_commit()
        .map_err(|err| MlsRuntimeError::Commit(err.to_string()))?;
    let mut encrypted_values = Vec::with_capacity(plaintext_values.len());
    for plaintext in plaintext_values {
        let encrypted = group
            .encrypt_payload(content_type, plaintext)
            .map_err(|err| MlsRuntimeError::Encrypt(err.to_string()))?;
        encrypted_values.push(
            serde_json::to_value(&encrypted)
                .map_err(|err| MlsRuntimeError::Serialize(err.to_string()))?,
        );
    }
    let schedule_hash = group.schedule_hash();
    let member_dids = group.member_principal_dids();
    let post_state = group
        .export_state_record()
        .map_err(|err| MlsRuntimeError::Export(err.to_string()))?;
    let mut salt = [0u8; 16];
    getrandom::fill(&mut salt).map_err(|err| MlsRuntimeError::Salt(err.to_string()))?;
    let new_envelope = crate::mls::persistence::encrypt_state(
        space_id,
        &post_state.group_id,
        post_state.epoch,
        &post_state.serialized_state,
        &secret,
        &salt,
    );
    state_store.save_mls_snapshot(space_id.to_owned(), new_envelope);
    Ok((
        schedule_hash,
        member_dids,
        encrypted_values,
        commit_envelope,
    ))
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::secure_key_store::MemorySecureKeyStore;

    fn temp_state_store(name: &str) -> crate::local_state::LocalStateStore {
        let path = std::env::temp_dir().join(format!(
            "yougen-mls-runtime-{name}-{}.json",
            crate::operation::uuid_v7()
        ));
        crate::local_state::LocalStateStore::with_path(path)
    }

    #[test]
    fn device_snapshot_secret_is_created_and_reused() {
        let store = MemorySecureKeyStore::new();
        let first = load_or_create_device_snapshot_secret(
            &store,
            "did:web:alice.example",
            "cx:device:01904100-0000-7000-8000-000000000001",
        )
        .unwrap();
        let second = load_or_create_device_snapshot_secret(
            &store,
            "did:web:alice.example",
            "cx:device:01904100-0000-7000-8000-000000000001",
        )
        .unwrap();
        assert_eq!(first, second);
        assert_eq!(first.len(), 43);
    }

    #[test]
    fn device_snapshot_secret_load_does_not_create() {
        let store = MemorySecureKeyStore::new();
        let missing = load_device_snapshot_secret(
            &store,
            "did:web:alice.example",
            "cx:device:01904100-0000-7000-8000-000000000001",
        )
        .unwrap_err();
        assert!(matches!(missing, SecureKeyStoreError::NotFound));
        assert!(store.is_empty());
    }

    #[test]
    fn device_snapshot_secret_is_scoped_by_actor_and_device() {
        let a = device_snapshot_secret_key("did:web:alice.example", "cx:device:a");
        let b = device_snapshot_secret_key("did:web:bob.example", "cx:device:a");
        let c = device_snapshot_secret_key("did:web:alice.example", "cx:device:b");
        assert_ne!(a, b);
        assert_ne!(a, c);
        assert!(a.starts_with("yougen.mls_snapshot.device_secret.v1."));
    }

    #[test]
    fn account_secret_is_shared_across_devices() {
        let store = MemorySecureKeyStore::new();
        let actor = "did:web:alice.example";
        let from_a = load_or_create_device_snapshot_secret(&store, actor, "cx:device:a").unwrap();
        // A different device of the SAME account must resolve the SAME secret.
        let from_b = load_or_create_device_snapshot_secret(&store, actor, "cx:device:b").unwrap();
        assert_eq!(from_a, from_b);
        // It is stored under the account key, not a device key.
        assert!(
            store
                .get_secret(&account_mls_secret_key(actor))
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn legacy_device_secret_is_promoted_to_account_key() {
        let store = MemorySecureKeyStore::new();
        let actor = "did:web:alice.example";
        let device = "cx:device:legacy";
        // Simulate an existing single-device user with a legacy device secret.
        store
            .store_secret(&device_snapshot_secret_key(actor, device), "legacy-secret")
            .unwrap();
        // load_or_create must promote and return the legacy value unchanged.
        let resolved = load_or_create_device_snapshot_secret(&store, actor, device).unwrap();
        assert_eq!(resolved, "legacy-secret");
        assert_eq!(
            store.get_secret(&account_mls_secret_key(actor)).unwrap(),
            Some("legacy-secret".to_owned())
        );
        // load-only path also resolves the promoted account secret.
        let loaded = load_device_snapshot_secret(&store, actor, device).unwrap();
        assert_eq!(loaded, "legacy-secret");
    }

    #[test]
    fn store_account_mls_secret_round_trips() {
        let store = MemorySecureKeyStore::new();
        let actor = "did:web:alice.example";
        store_account_mls_secret(&store, actor, "recovered-secret").unwrap();
        let loaded = load_device_snapshot_secret(&store, actor, "cx:device:fresh").unwrap();
        assert_eq!(loaded, "recovered-secret");
    }

    #[test]
    fn store_account_mls_secret_rejects_empty() {
        let store = MemorySecureKeyStore::new();
        assert!(store_account_mls_secret(&store, "did:web:alice.example", "  ").is_err());
        assert!(store_account_mls_secret(&store, "  ", "secret").is_err());
    }

    #[test]
    fn missing_welcome_message_points_to_backup_restore() {
        let message = MlsRuntimeStatus::MissingWelcome.user_message();
        assert_eq!(
            message,
            "MLS state is not ready on this device yet; wait for an MLS Welcome or restore this device's encrypted MLS history backup."
        );
    }

    #[test]
    fn mls_history_backup_body_decodes_to_snapshot_envelope() {
        let envelope = crate::mls::persistence::encrypt_state(
            "cx:space:01904100-0000-7000-8000-000000000001",
            "group-a",
            8,
            b"opaque sdk state",
            "device-secret",
            b"deterministic-salt",
        );
        let body = envelope.to_key_backup_body(
            "cx:backup:01904100-0000-7000-8000-000000000002",
            "did:web:alice.example",
            "cx:device:01904100-0000-7000-8000-000000000001",
        );

        let decoded = decode_mls_history_backup_envelope(&body).unwrap();

        assert_eq!(decoded.space_id, envelope.space_id);
        assert_eq!(decoded.group_id, envelope.group_id);
        assert_eq!(decoded.epoch, envelope.epoch);
        assert_eq!(body["backup_class"], "mls_history");
        assert_eq!(
            body["encryption"]["recipient_method"],
            "device_snapshot_secret"
        );
        assert!(body["encryption"].get("kdf").is_none());
        assert!(body.get("plaintext").is_none());
        assert!(body.get("serialized_state").is_none());
    }

    #[test]
    fn mls_history_backup_decode_rejects_metadata_mismatch() {
        let envelope = crate::mls::persistence::encrypt_state(
            "cx:space:01904100-0000-7000-8000-000000000001",
            "group-a",
            8,
            b"opaque sdk state",
            "device-secret",
            b"deterministic-salt",
        );
        let mut body = envelope.to_key_backup_body(
            "cx:backup:01904100-0000-7000-8000-000000000002",
            "did:web:alice.example",
            "cx:device:01904100-0000-7000-8000-000000000001",
        );
        body["envelope_meta"]["epoch"] = json!(7);

        let error = decode_mls_history_backup_envelope(&body).unwrap_err();

        assert!(matches!(error, MlsRuntimeError::BackupDecode(_)));
        assert!(error.user_message().contains("epoch mismatch"));
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn encrypted_write_with_snapshot_requires_existing_device_secret() {
        let mut state = temp_state_store("missing-secret");
        let store = MemorySecureKeyStore::new();
        let envelope = crate::mls::persistence::encrypt_state(
            "cx:space:01904100-0000-7000-8000-000000000001",
            "group-for-missing-secret-test",
            1,
            b"not-a-real-group-state",
            "other-device-secret",
            b"deterministic-salt",
        );
        state.save_mls_snapshot("cx:space:01904100-0000-7000-8000-000000000001", envelope);

        let error = encrypt_values_with_device_snapshot(
            &mut state,
            &store,
            "cx:space:01904100-0000-7000-8000-000000000001",
            "did:web:alice.example",
            "cx:device:01904100-0000-7000-8000-000000000001",
            "text/plain",
            &[b"secret".to_vec()],
        )
        .unwrap_err();

        assert!(matches!(
            error,
            MlsRuntimeError::DeviceSecret(SecureKeyStoreError::NotFound)
        ));
        assert!(store.is_empty());
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn encrypted_write_uses_device_key_snapshot_when_ready() {
        use contrix_sdk::{ContrixMlsIdentity, DeviceId, Did};

        let actor = "did:web:alice.example";
        let device = "cx:device:01904100-0000-7000-8000-000000000001";
        let space = "cx:space:01904100-0000-7000-8000-000000000003";
        let store = MemorySecureKeyStore::new();
        let secret = load_or_create_device_snapshot_secret(&store, actor, device).unwrap();
        let identity = ContrixMlsIdentity::new_basic(
            Did::new(actor.to_owned()).unwrap(),
            DeviceId::new(device.to_owned()).unwrap(),
        )
        .unwrap();
        let group = identity.create_group(space.as_bytes()).unwrap();
        let record = group.export_state_record().unwrap();
        let bytes = serde_json::to_vec(&record).unwrap();
        let envelope = crate::mls::persistence::encrypt_state(
            space,
            &record.group_id,
            record.epoch,
            &bytes,
            &secret,
            b"deterministic-salt",
        );
        let mut state = temp_state_store("ready-encrypt");
        state.save_mls_snapshot(space, envelope);

        let (_schedule_hash, member_dids, encrypted_values, _commit) =
            encrypt_values_with_device_snapshot(
                &mut state,
                &store,
                space,
                actor,
                device,
                "text/plain",
                &[b"secret".to_vec()],
            )
            .unwrap();

        assert_eq!(member_dids.len(), 1);
        assert_eq!(encrypted_values.len(), 1);
        assert!(encrypted_values[0].get("ciphertext").is_some());
        assert!(state.mls_snapshot_for(space).is_some());
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn restore_mls_history_backup_saves_snapshot_when_fresh() {
        use contrix_sdk::{ContrixMlsIdentity, DeviceId, Did};

        let actor = "did:web:alice.example";
        let device = "cx:device:01904100-0000-7000-8000-000000000001";
        let space = "cx:space:01904100-0000-7000-8000-000000000004";
        let store = MemorySecureKeyStore::new();
        let secret = load_or_create_device_snapshot_secret(&store, actor, device).unwrap();
        let identity = ContrixMlsIdentity::new_basic(
            Did::new(actor.to_owned()).unwrap(),
            DeviceId::new(device.to_owned()).unwrap(),
        )
        .unwrap();
        let group = identity.create_group(space.as_bytes()).unwrap();
        let record = group.export_state_record().unwrap();
        let envelope = crate::mls::persistence::encrypt_state(
            space,
            &record.group_id,
            record.epoch,
            &serde_json::to_vec(&record).unwrap(),
            &secret,
            b"deterministic-salt",
        );
        let body = envelope.to_key_backup_body(
            "cx:backup:01904100-0000-7000-8000-000000000002",
            actor,
            device,
        );
        let mut state = temp_state_store("restore-fresh");

        let restored = restore_mls_history_backup_with_device_snapshot(
            &mut state, &store, actor, device, &body,
        )
        .unwrap();

        assert_eq!(restored.space_id, space);
        assert_eq!(restored.envelope_epoch, record.epoch);
        assert_eq!(restored.epoch_floor, 0);
        assert_eq!(state.mls_snapshot_for(space).unwrap().epoch, record.epoch);
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn restore_mls_history_backup_rejects_epoch_rollback() {
        use contrix_sdk::{ContrixMlsIdentity, DeviceId, Did};

        let actor = "did:web:alice.example";
        let device = "cx:device:01904100-0000-7000-8000-000000000001";
        let space = "cx:space:01904100-0000-7000-8000-000000000002";
        let store = MemorySecureKeyStore::new();
        let secret = load_or_create_device_snapshot_secret(&store, actor, device).unwrap();
        let identity = ContrixMlsIdentity::new_basic(
            Did::new(actor.to_owned()).unwrap(),
            DeviceId::new(device.to_owned()).unwrap(),
        )
        .unwrap();
        let group = identity.create_group(space.as_bytes()).unwrap();
        let record = group.export_state_record().unwrap();
        let envelope = crate::mls::persistence::encrypt_state(
            space,
            &record.group_id,
            record.epoch,
            &serde_json::to_vec(&record).unwrap(),
            &secret,
            b"deterministic-salt",
        );
        let body = envelope.to_key_backup_body(
            "cx:backup:01904100-0000-7000-8000-000000000002",
            actor,
            device,
        );
        let mut state = temp_state_store("restore-rollback");
        state.set_anchor_view(
            space,
            crate::local_state::LocalAnchorView {
                mls_epoch: Some(record.epoch + 1),
                ..Default::default()
            },
        );

        let error = restore_mls_history_backup_with_device_snapshot(
            &mut state, &store, actor, device, &body,
        )
        .unwrap_err();

        assert!(error.user_message().contains("outdated snapshot"));
        assert!(state.mls_snapshot_for(space).is_none());
    }
}
