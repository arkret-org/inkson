//! Shared MLS runtime helpers.
//!
//! Normal Realm/Kanban usage uses an account-scoped secret to wrap local MLS
//! snapshots. The runtime exposes typed readiness errors when a device has not
//! yet received a Welcome or restored an MLS-history backup.

use std::collections::BTreeMap;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::Value;

use crate::secure_key_store::{SecureKeyStore, SecureKeyStoreError};

const DEVICE_SNAPSHOT_SECRET_PREFIX: &str = "yougen.mls_snapshot.device_secret.v1";
const ACCOUNT_MLS_SECRET_PREFIX: &str = "yougen.mls_snapshot.account_secret";
pub const ACCOUNT_MLS_SECRET_CURRENT_VERSION: u32 = 2;
const ACCOUNT_MLS_SECRET_MAX_SCAN_VERSION: u32 = 32;

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
    Genesis(String),
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
            Self::Genesis(_)
            | Self::Commit(_)
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
            Self::Genesis(reason) => format!("MLS initial group setup failed: {reason}"),
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

/// Outcome of [`apply_welcome_messages_with_device_snapshot`].
///
/// Lets callers distinguish "no welcomes present" (`applied == 0 && failed ==
/// 0`) from "welcomes present but some/all failed" (`failed > 0`). A failure of
/// one welcome never aborts the others; `first_error` carries the first failure
/// reason for diagnostics.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct WelcomeApplyOutcome {
    pub applied: usize,
    pub failed: usize,
    pub first_error: Option<String>,
}

impl WelcomeApplyOutcome {
    fn record_failure(&mut self, reason: String) {
        self.failed += 1;
        if self.first_error.is_none() {
            self.first_error = Some(reason);
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

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InitialMlsSnapshotSummary {
    pub space_id: String,
    pub group_id: String,
    pub epoch: u64,
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

/// Ensure a Realm/Space creator has the initial local MLS group snapshot.
///
/// The creator does not receive a Welcome for the group they create. Without
/// this genesis snapshot, their first encrypted write would fail with
/// `MissingWelcome` even though there is no Welcome to wait for.
pub fn ensure_creator_mls_snapshot(
    state_store: &mut crate::local_state::LocalStateStore,
    secure_store: &dyn SecureKeyStore,
    space_id: &str,
    actor_did: &str,
    device_id: &str,
) -> Result<Option<InitialMlsSnapshotSummary>, MlsRuntimeError> {
    let space = space_id.trim();
    if space.is_empty() {
        return Err(MlsRuntimeError::Genesis(
            "space_id is required for initial MLS group setup".to_owned(),
        ));
    }
    if state_store.mls_snapshot_for(space).is_some() {
        return Ok(None);
    }

    let secret = load_or_create_device_snapshot_secret(secure_store, actor_did, device_id)
        .map_err(MlsRuntimeError::DeviceSecret)?;
    let principal_did = contrix_sdk::Did::new(actor_did.to_owned())
        .map_err(|err| MlsRuntimeError::Identity(format!("{err:?}")))?;
    let device_id_typed = contrix_sdk::DeviceId::new(device_id.to_owned())
        .map_err(|err| MlsRuntimeError::Identity(format!("{err:?}")))?;
    let identity = contrix_sdk::ContrixMlsIdentity::new_basic(principal_did, device_id_typed)
        .map_err(|err| MlsRuntimeError::Identity(format!("{err:?}")))?;
    let group = identity
        .create_group(space.as_bytes())
        .map_err(|err| MlsRuntimeError::Genesis(format!("create group: {err}")))?;
    let post_state = group
        .export_state_record()
        .map_err(|err| MlsRuntimeError::Genesis(format!("export state: {err}")))?;
    let serialized_state = serde_json::to_vec(&post_state)
        .map_err(|err| MlsRuntimeError::Genesis(format!("serialize state: {err}")))?;
    let mut salt = [0u8; 16];
    getrandom::fill(&mut salt).map_err(|err| MlsRuntimeError::Salt(err.to_string()))?;
    let snapshot = crate::mls::persistence::encrypt_state(
        space,
        &post_state.group_id,
        post_state.epoch,
        &serialized_state,
        &secret,
        &salt,
    );
    let summary = InitialMlsSnapshotSummary {
        space_id: space.to_owned(),
        group_id: post_state.group_id.clone(),
        epoch: post_state.epoch,
    };
    state_store.save_mls_snapshot(space.to_owned(), snapshot);
    Ok(Some(summary))
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

/// Stored account-scoped MLS snapshot secret plus the local key version that
/// carried it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredAccountMlsSecret {
    pub version: u32,
    pub secret: String,
}

/// Local account-scoped secret rotation material. The network upload path uses
/// `new_secret` to wrap the new account-secret backup, then commits this
/// material locally once the server-side backups have landed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccountMlsSecretRotation {
    pub previous_version: u32,
    pub new_version: u32,
    pub new_secret: String,
    pub rewrapped_snapshots: BTreeMap<String, crate::mls::persistence::MlsSnapshotEnvelope>,
}

/// Account-scoped storage key for a specific MLS snapshot-secret version.
pub fn account_mls_secret_key_for_version(actor_did: &str, version: u32) -> String {
    format!(
        "{ACCOUNT_MLS_SECRET_PREFIX}.v{}.{}",
        version,
        actor_did.trim()
    )
}

/// Default write key for the account-scoped MLS snapshot secret shared by every
/// device of the account. Recoverable via the user's recovery passphrase.
pub fn account_mls_secret_key(actor_did: &str) -> String {
    account_mls_secret_key_for_version(actor_did, ACCOUNT_MLS_SECRET_CURRENT_VERSION)
}

fn validate_account_secret_inputs<'a>(
    actor_did: &'a str,
    secret: &str,
) -> Result<&'a str, SecureKeyStoreError> {
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
    Ok(actor)
}

/// Store (or overwrite) a specific version of the account-scoped MLS snapshot
/// secret.
pub fn store_account_mls_secret_version(
    store: &dyn SecureKeyStore,
    actor_did: &str,
    version: u32,
    secret: &str,
) -> Result<(), SecureKeyStoreError> {
    if version == 0 || version > ACCOUNT_MLS_SECRET_MAX_SCAN_VERSION {
        return Err(SecureKeyStoreError::Backend(format!(
            "account MLS secret version {version} is outside the supported scan range"
        )));
    }
    let actor = validate_account_secret_inputs(actor_did, secret)?;
    store.store_secret(&account_mls_secret_key_for_version(actor, version), secret)
}

/// Replace all locally-known account MLS secret versions with one recovered
/// from the server backup.
///
/// Recovery must win over a stale local secret that may have been generated by
/// a previous incomplete bootstrap. Since [`load_account_mls_secret`] picks the
/// highest version, keeping a newer-but-wrong local version would make the
/// recovered backup ineffective.
pub fn replace_account_mls_secret_version(
    store: &dyn SecureKeyStore,
    actor_did: &str,
    version: u32,
    secret: &str,
) -> Result<(), SecureKeyStoreError> {
    if version == 0 || version > ACCOUNT_MLS_SECRET_MAX_SCAN_VERSION {
        return Err(SecureKeyStoreError::Backend(format!(
            "account MLS secret version {version} is outside the supported scan range"
        )));
    }
    let actor = validate_account_secret_inputs(actor_did, secret)?;
    store.store_secret(&account_mls_secret_key_for_version(actor, version), secret)?;
    for existing_version in 1..=ACCOUNT_MLS_SECRET_MAX_SCAN_VERSION {
        if existing_version != version {
            store.delete_secret(&account_mls_secret_key_for_version(actor, existing_version))?;
        }
    }
    Ok(())
}

/// Store (or overwrite) the default/current account-scoped MLS snapshot secret.
/// Used by the recovery import path after unwrapping the recovery vault.
pub fn store_account_mls_secret(
    store: &dyn SecureKeyStore,
    actor_did: &str,
    secret: &str,
) -> Result<(), SecureKeyStoreError> {
    store_account_mls_secret_version(store, actor_did, ACCOUNT_MLS_SECRET_CURRENT_VERSION, secret)
}

/// Load the highest local account-secret version currently present.
pub fn load_account_mls_secret(
    store: &dyn SecureKeyStore,
    actor_did: &str,
) -> Result<Option<StoredAccountMlsSecret>, SecureKeyStoreError> {
    let actor = actor_did.trim();
    if actor.is_empty() {
        return Err(SecureKeyStoreError::Backend(
            "actor_did is required for MLS snapshot secret".to_owned(),
        ));
    }
    for version in (1..=ACCOUNT_MLS_SECRET_MAX_SCAN_VERSION).rev() {
        let key = account_mls_secret_key_for_version(actor, version);
        if let Some(secret) = store.get_secret(&key)?
            && !secret.trim().is_empty()
        {
            return Ok(Some(StoredAccountMlsSecret { version, secret }));
        }
    }
    Ok(None)
}

fn generate_account_mls_secret() -> Result<String, SecureKeyStoreError> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes)
        .map_err(|err| SecureKeyStoreError::Backend(format!("getrandom: {err}")))?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

/// Load (or create) the account-scoped MLS snapshot secret.
///
/// Resolution order:
///   a. the highest existing versioned account secret is returned as-is;
///   b. otherwise, if a legacy device-scoped secret exists for `(actor,
///      device)`, it is *promoted* to the v1 account key (so single-device users
///      keep their local MLS state) and returned;
///   c. otherwise a fresh random 32-byte secret is generated, stored under the
///      current account key, and returned.
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
    // a. existing account secret wins.
    if let Some(existing) = load_account_mls_secret(store, actor)? {
        return Ok(existing.secret);
    }
    // b. migrate a legacy device-scoped secret if one exists for this device.
    let device = device_id.trim();
    if !device.is_empty() {
        let device_key = device_snapshot_secret_key(actor, device);
        if let Some(legacy) = store.get_secret(&device_key)?
            && !legacy.trim().is_empty()
        {
            store_account_mls_secret_version(store, actor, 1, &legacy)?;
            return Ok(legacy);
        }
    }
    // c. generate a fresh account secret.
    let secret = generate_account_mls_secret()?;
    store_account_mls_secret(store, actor, &secret)?;
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
    if let Some(existing) = load_account_mls_secret(store, actor)? {
        return Ok(existing.secret);
    }
    // Migration: promote a legacy device-scoped secret if present.
    let device = device_id.trim();
    if !device.is_empty() {
        let device_key = device_snapshot_secret_key(actor, device);
        if let Some(legacy) = store.get_secret(&device_key)?
            && !legacy.trim().is_empty()
        {
            store_account_mls_secret_version(store, actor, 1, &legacy)?;
            return Ok(legacy);
        }
    }
    Err(SecureKeyStoreError::NotFound)
}

/// Prepare a local account-secret rotation without mutating local state.
///
/// Each persisted MLS snapshot is decrypted with the current account secret and
/// re-encrypted with a newly-generated secret. Callers upload the returned
/// backups first, then call [`commit_account_mls_secret_rotation`] so local
/// state and the secret store advance together.
pub fn prepare_account_mls_secret_rotation(
    store: &dyn SecureKeyStore,
    actor_did: &str,
    device_id: &str,
    snapshots: &BTreeMap<String, crate::mls::persistence::MlsSnapshotEnvelope>,
) -> Result<AccountMlsSecretRotation, MlsRuntimeError> {
    let actor = actor_did.trim();
    if actor.is_empty() {
        return Err(MlsRuntimeError::DeviceSecret(SecureKeyStoreError::Backend(
            "actor_did is required for MLS snapshot secret".to_owned(),
        )));
    }
    let previous_secret =
        match load_account_mls_secret(store, actor).map_err(MlsRuntimeError::DeviceSecret)? {
            Some(secret) => secret,
            None => {
                let _ = load_or_create_account_mls_secret(store, actor, device_id)
                    .map_err(MlsRuntimeError::DeviceSecret)?;
                load_account_mls_secret(store, actor)
                    .map_err(MlsRuntimeError::DeviceSecret)?
                    .ok_or_else(|| MlsRuntimeError::DeviceSecret(SecureKeyStoreError::NotFound))?
            }
        };
    let new_version = previous_secret
        .version
        .saturating_add(1)
        .max(ACCOUNT_MLS_SECRET_CURRENT_VERSION);
    if new_version > ACCOUNT_MLS_SECRET_MAX_SCAN_VERSION {
        return Err(MlsRuntimeError::DeviceSecret(SecureKeyStoreError::Backend(
            format!("account MLS secret version {new_version} exceeds supported scan range"),
        )));
    }
    let new_secret = generate_account_mls_secret().map_err(MlsRuntimeError::DeviceSecret)?;
    let mut rewrapped_snapshots = BTreeMap::new();
    for (space_id, snapshot) in snapshots {
        let plaintext = crate::mls::persistence::decrypt_envelope(
            snapshot,
            &previous_secret.secret,
        )
        .map_err(|err| {
            MlsRuntimeError::SnapshotRestore(format!(
                "could not decrypt MLS snapshot for {space_id} before account-secret rotation: {err}"
            ))
        })?;
        let mut salt = [0u8; 16];
        getrandom::fill(&mut salt).map_err(|err| MlsRuntimeError::Salt(err.to_string()))?;
        let rotated = crate::mls::persistence::encrypt_state(
            &snapshot.space_id,
            &snapshot.group_id,
            snapshot.epoch,
            &plaintext,
            &new_secret,
            &salt,
        );
        rewrapped_snapshots.insert(space_id.clone(), rotated);
    }
    Ok(AccountMlsSecretRotation {
        previous_version: previous_secret.version,
        new_version,
        new_secret,
        rewrapped_snapshots,
    })
}

/// Commit a prepared rotation to local state and the secure store.
pub fn commit_account_mls_secret_rotation(
    state_store: &mut crate::local_state::LocalStateStore,
    secure_store: &dyn SecureKeyStore,
    actor_did: &str,
    rotation: &AccountMlsSecretRotation,
) -> Result<(), SecureKeyStoreError> {
    for (space_id, envelope) in &rotation.rewrapped_snapshots {
        state_store.save_mls_snapshot(space_id.clone(), envelope.clone());
    }
    store_account_mls_secret_version(
        secure_store,
        actor_did,
        rotation.new_version,
        &rotation.new_secret,
    )?;
    for version in 1..rotation.new_version {
        let _ = secure_store.delete_secret(&account_mls_secret_key_for_version(actor_did, version));
    }
    Ok(())
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
) -> Result<WelcomeApplyOutcome, MlsRuntimeError> {
    let welcome_entries = collect_welcome_entries(messages_value);
    // A totally-empty welcome set is a success with nothing to do.
    if welcome_entries.is_empty() {
        return Ok(WelcomeApplyOutcome::default());
    }
    // The snapshot secret / identity are prerequisites for ALL welcomes: if they
    // are unavailable no welcome could possibly apply, so surface them as a hard
    // error (the readiness status machinery keys off these).
    let secret = load_or_create_device_snapshot_secret(secure_store, actor_did, device_id)
        .map_err(MlsRuntimeError::DeviceSecret)?;
    let principal_did = contrix_sdk::Did::new(actor_did.to_owned())
        .map_err(|err| MlsRuntimeError::Identity(format!("{err:?}")))?;
    let device_id_typed = contrix_sdk::DeviceId::new(device_id.to_owned())
        .map_err(|err| MlsRuntimeError::Identity(format!("{err:?}")))?;
    // Per-welcome failures no longer abort the loop or get swallowed: each is
    // counted and the first reason retained so callers can report partial
    // success without failing the whole boot.
    let mut outcome = WelcomeApplyOutcome::default();
    for welcome_value in welcome_entries {
        let welcome = match serde_json::from_value::<contrix_sdk::MlsWelcomeEnvelope>(welcome_value)
        {
            Ok(welcome) => welcome,
            Err(err) => {
                outcome.record_failure(format!("welcome envelope parse: {err}"));
                continue;
            }
        };
        let identity = match contrix_sdk::ContrixMlsIdentity::new_basic(
            principal_did.clone(),
            device_id_typed.clone(),
        ) {
            Ok(identity) => identity,
            Err(err) => {
                outcome.record_failure(format!("identity: {err:?}"));
                continue;
            }
        };
        let group = match contrix_sdk::ContrixMlsGroup::join_from_welcome(identity, &welcome) {
            Ok(group) => group,
            Err(err) => {
                outcome.record_failure(format!("join welcome: {err}"));
                continue;
            }
        };
        let post_state = match group.export_state_record() {
            Ok(post_state) => post_state,
            Err(err) => {
                outcome.record_failure(format!("export state: {err}"));
                continue;
            }
        };
        let serialized_state = match serde_json::to_vec(&post_state) {
            Ok(serialized_state) => serialized_state,
            Err(err) => {
                outcome.record_failure(format!("serialize state: {err}"));
                continue;
            }
        };
        let mut salt = [0u8; 16];
        if let Err(err) = getrandom::fill(&mut salt) {
            outcome.record_failure(format!("salt: {err}"));
            continue;
        }
        let snapshot = crate::mls::persistence::encrypt_state(
            space_id,
            &post_state.group_id,
            post_state.epoch,
            &serialized_state,
            &secret,
            &salt,
        );
        state_store.save_mls_snapshot(space_id.to_owned(), snapshot);
        outcome.applied += 1;
    }
    Ok(outcome)
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
    let member_dids = group.member_principal_ids();
    let post_state = group
        .export_state_record()
        .map_err(|err| MlsRuntimeError::Export(err.to_string()))?;
    let serialized_state = serde_json::to_vec(&post_state)
        .map_err(|err| MlsRuntimeError::Serialize(format!("MLS state record: {err}")))?;
    let mut salt = [0u8; 16];
    getrandom::fill(&mut salt).map_err(|err| MlsRuntimeError::Salt(err.to_string()))?;
    let new_envelope = crate::mls::persistence::encrypt_state(
        space_id,
        &post_state.group_id,
        post_state.epoch,
        &serialized_state,
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

/// Encrypt a single message plaintext under the Space MLS group, binding
/// `aad` into the payload digest, and return the structured
/// [`contrix_sdk::EncryptedPayload`] (not yet wrapped as a wire envelope).
///
/// The caller assembles the spec-canonical `cx.schema.encrypted_envelope.v1`
/// wire shape via [`contrix_sdk::EncryptedEnvelopeV1::from_payload`] once it
/// knows the `cx.mls.commit` event id that bounds this epoch (used as the
/// envelope `key_ref.group_state_ref`). `aad` MUST be the canonical
/// `EncryptedEnvelopeAadV1` value, so the digest verification round-trips.
pub fn encrypt_message_with_device_snapshot(
    state_store: &mut crate::local_state::LocalStateStore,
    secure_store: &dyn SecureKeyStore,
    space_id: &str,
    actor_did: &str,
    device_id: &str,
    content_type: &str,
    aad: serde_json::Value,
    plaintext: &[u8],
) -> Result<
    (
        contrix_sdk::Hash,
        Vec<contrix_sdk::Did>,
        contrix_sdk::EncryptedPayload,
        contrix_sdk::MlsCommitEnvelope,
    ),
    MlsRuntimeError,
> {
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
    let encrypted = group
        .encrypt_payload_with_aad(content_type, Some(aad), plaintext)
        .map_err(|err| MlsRuntimeError::Encrypt(err.to_string()))?;
    let schedule_hash = group.schedule_hash();
    let member_dids = group.member_principal_ids();
    let post_state = group
        .export_state_record()
        .map_err(|err| MlsRuntimeError::Export(err.to_string()))?;
    let serialized_state = serde_json::to_vec(&post_state)
        .map_err(|err| MlsRuntimeError::Serialize(format!("MLS state record: {err}")))?;
    let mut salt = [0u8; 16];
    getrandom::fill(&mut salt).map_err(|err| MlsRuntimeError::Salt(err.to_string()))?;
    let new_envelope = crate::mls::persistence::encrypt_state(
        space_id,
        &post_state.group_id,
        post_state.epoch,
        &serialized_state,
        &secret,
        &salt,
    );
    state_store.save_mls_snapshot(space_id.to_owned(), new_envelope);
    Ok((schedule_hash, member_dids, encrypted, commit_envelope))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

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
            store
                .get_secret(&account_mls_secret_key_for_version(actor, 1))
                .unwrap(),
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
    fn account_secret_load_picks_highest_version() {
        let store = MemorySecureKeyStore::new();
        let actor = "did:web:alice.example";
        store_account_mls_secret_version(&store, actor, 1, "old-secret").unwrap();
        store_account_mls_secret_version(&store, actor, 3, "new-secret").unwrap();

        let loaded = load_account_mls_secret(&store, actor)
            .unwrap()
            .expect("secret present");

        assert_eq!(loaded.version, 3);
        assert_eq!(loaded.secret, "new-secret");
        assert_eq!(
            load_device_snapshot_secret(&store, actor, "cx:device:any").unwrap(),
            "new-secret"
        );
    }

    #[test]
    fn store_account_mls_secret_rejects_empty() {
        let store = MemorySecureKeyStore::new();
        assert!(store_account_mls_secret(&store, "did:web:alice.example", "  ").is_err());
        assert!(store_account_mls_secret(&store, "  ", "secret").is_err());
    }

    #[test]
    fn replace_account_mls_secret_removes_higher_stale_versions() {
        let store = MemorySecureKeyStore::new();
        let actor = "did:web:alice.example";
        store_account_mls_secret_version(&store, actor, 2, "server-secret").unwrap();
        store_account_mls_secret_version(&store, actor, 3, "stale-local-secret").unwrap();

        replace_account_mls_secret_version(&store, actor, 2, "recovered-secret").unwrap();

        let loaded = load_account_mls_secret(&store, actor)
            .unwrap()
            .expect("secret present");
        assert_eq!(loaded.version, 2);
        assert_eq!(loaded.secret, "recovered-secret");
        assert_eq!(
            store
                .get_secret(&account_mls_secret_key_for_version(actor, 3))
                .unwrap(),
            None
        );
    }

    #[test]
    fn missing_welcome_message_points_to_backup_restore() {
        let message = MlsRuntimeStatus::MissingWelcome.user_message();
        assert_eq!(
            message,
            "MLS state is not ready on this device yet; wait for an MLS Welcome or restore this device's encrypted MLS history backup."
        );
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn creator_snapshot_bootstrap_makes_space_encryptable() {
        let mut state = temp_state_store("creator-bootstrap");
        let secure = MemorySecureKeyStore::new();
        let actor = "did:web:alice.example";
        let device = "cx:device:01904100-0000-7000-8000-000000000001";
        let space = "cx:realm:01904100-0000-7000-8000-000000000001";

        let summary =
            ensure_creator_mls_snapshot(&mut state, &secure, space, actor, device).unwrap();

        let summary = summary.expect("missing creator snapshot should be created");
        assert_eq!(summary.space_id, space);
        assert_eq!(summary.epoch, 0);
        assert!(state.mls_snapshot_for(space).is_some());
        let encrypted = encrypt_values_with_device_snapshot(
            &mut state,
            &secure,
            space,
            actor,
            device,
            "application/vnd.contrix.test+json",
            &[br#""private""#.to_vec()],
        )
        .unwrap();
        assert_eq!(encrypted.2.len(), 1);
        assert!(state.mls_snapshot_for(space).unwrap().epoch >= 1);
        let encrypted_again = encrypt_values_with_device_snapshot(
            &mut state,
            &secure,
            space,
            actor,
            device,
            "application/vnd.contrix.test+json",
            &[br#""private-again""#.to_vec()],
        )
        .unwrap();
        assert_eq!(encrypted_again.2.len(), 1);
        assert!(state.mls_snapshot_for(space).unwrap().epoch >= 2);
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

    #[test]
    fn account_secret_rotation_rewraps_backups_old_secret_cannot_decrypt() {
        let actor = "did:web:alice.example";
        let device = "cx:device:01904100-0000-7000-8000-000000000001";
        let space = "cx:space:01904100-0000-7000-8000-000000000009";
        let old_secret = "old-account-secret";
        let plaintext = b"opaque sdk state before revoke";
        let store = MemorySecureKeyStore::new();
        store_account_mls_secret_version(&store, actor, 1, old_secret).unwrap();
        let original = crate::mls::persistence::encrypt_state(
            space,
            "group-after-revoke",
            12,
            plaintext,
            old_secret,
            b"deterministic-salt",
        );
        let snapshots = BTreeMap::from([(space.to_owned(), original)]);

        let rotation =
            prepare_account_mls_secret_rotation(&store, actor, device, &snapshots).unwrap();

        assert_eq!(rotation.previous_version, 1);
        assert_eq!(rotation.new_version, 2);
        assert_ne!(rotation.new_secret, old_secret);
        let rotated = rotation
            .rewrapped_snapshots
            .get(space)
            .expect("rewrapped snapshot");
        let (_backup_id, body) = build_mls_history_backup_body(rotated, actor, device);
        let decoded = decode_mls_history_backup_envelope(&body).unwrap();
        assert!(
            crate::mls::persistence::decrypt_envelope(&decoded, old_secret).is_err(),
            "revoked device's old account secret must not decrypt the new backup"
        );
        let recovered =
            crate::mls::persistence::decrypt_envelope(&decoded, &rotation.new_secret).unwrap();
        assert_eq!(recovered, plaintext);

        let mut state = temp_state_store("rotate-commit");
        commit_account_mls_secret_rotation(&mut state, &store, actor, &rotation).unwrap();
        assert_eq!(
            load_device_snapshot_secret(&store, actor, device).unwrap(),
            rotation.new_secret
        );
        assert!(
            store
                .get_secret(&account_mls_secret_key_for_version(actor, 1))
                .unwrap()
                .is_none()
        );
        assert_eq!(
            state.mls_snapshot_for(space).unwrap().ciphertext_hex,
            rotated.ciphertext_hex
        );
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

    /// End-to-end regression guard for "same account, brand-new browser sees
    /// history" (Option A). Proves cross-device MLS-history recovery works using
    /// ONLY the account-secret backup unwrapped with the recovery passphrase —
    /// device B has NO local random secret of its own.
    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn cross_device_recovery_restores_history_without_local_secret() {
        use contrix_sdk::{ContrixMlsIdentity, DeviceId, Did};

        use crate::mls::account_recovery::{
            build_mls_account_secret_backup_body_with_kek, decrypt_mls_account_secret_backup,
        };
        use crate::recovery_crypto::derive_vault_kek;

        let actor = "did:web:alice.example";
        let device_a = "cx:device:01904100-0000-7000-8000-00000000000a";
        let device_b = "cx:device:01904100-0000-7000-8000-00000000000b";
        let space = "cx:space:01904100-0000-7000-8000-0000000000ab";
        let passphrase: &[u8] = b"correct horse battery staple";

        // --- Device A: account secret + a real MLS group + history backup body.
        let store_a = MemorySecureKeyStore::new();
        let secret_a = load_or_create_account_mls_secret(&store_a, actor, device_a).unwrap();

        let identity = ContrixMlsIdentity::new_basic(
            Did::new(actor.to_owned()).unwrap(),
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
            &secret_a,
            b"deterministic-salt",
        );
        let (_history_backup_id, history_body) =
            build_mls_history_backup_body(&envelope, actor, device_a);

        // Device A wraps the account secret behind the recovery PASSPHRASE
        // (KEK derived from the passphrase, exactly like the recovery setup
        // path), so a sibling device can later unwrap it with that passphrase.
        let setup_kek = derive_vault_kek(passphrase).unwrap();
        let account_secret_body = build_mls_account_secret_backup_body_with_kek(
            "cx:backup:01904100-0000-7000-8000-0000000000ac",
            actor,
            device_a,
            &setup_kek,
            &secret_a,
        )
        .unwrap();

        // --- Device B: a FRESH empty store with NO secret of any kind.
        let store_b = MemorySecureKeyStore::new();
        assert!(
            store_b.is_empty(),
            "device B must start with no local secret"
        );
        // Without the account secret, restore must fail (no local random secret).
        let mut state_b = temp_state_store("xdev-before");
        let pre_restore = restore_mls_history_backup_with_device_snapshot(
            &mut state_b,
            &store_b,
            actor,
            device_b,
            &history_body,
        )
        .unwrap_err();
        assert!(matches!(
            pre_restore,
            MlsRuntimeError::DeviceSecret(SecureKeyStoreError::NotFound)
        ));

        // Recover the account secret with the passphrase and store it on B.
        let recovered = decrypt_mls_account_secret_backup(passphrase, &account_secret_body)
            .expect("correct passphrase unwraps the account secret");
        let recovered_secret = String::from_utf8(recovered).unwrap();
        assert_eq!(recovered_secret, secret_a);
        store_account_mls_secret(&store_b, actor, &recovered_secret).unwrap();

        // Now restore must succeed on B using only the recovered account secret.
        let mut state_b = temp_state_store("xdev-after");
        let summary = restore_mls_history_backup_with_device_snapshot(
            &mut state_b,
            &store_b,
            actor,
            device_b,
            &history_body,
        )
        .expect("restore succeeds once the account secret is recovered");

        // The restored snapshot must match A's group_id / epoch.
        assert_eq!(summary.space_id, space);
        assert_eq!(summary.group_id, record.group_id);
        assert_eq!(summary.envelope_epoch, record.epoch);
        let restored_snapshot = state_b.mls_snapshot_for(space).unwrap();
        assert_eq!(restored_snapshot.group_id, record.group_id);
        assert_eq!(restored_snapshot.epoch, record.epoch);

        // --- Negative: a WRONG passphrase cannot unwrap the account secret, so a
        // fresh device C never gets a usable secret and history stays locked.
        let wrong = decrypt_mls_account_secret_backup(b"incorrect horse", &account_secret_body);
        assert!(wrong.is_err(), "wrong passphrase must fail to unwrap");
        let store_c = MemorySecureKeyStore::new();
        let mut state_c = temp_state_store("xdev-wrong");
        let locked = restore_mls_history_backup_with_device_snapshot(
            &mut state_c,
            &store_c,
            actor,
            device_b,
            &history_body,
        )
        .unwrap_err();
        assert!(matches!(
            locked,
            MlsRuntimeError::DeviceSecret(SecureKeyStoreError::NotFound)
        ));
    }
}

#[cfg(test)]
mod welcome_outcome_tests {
    use serde_json::json;

    use super::*;
    use crate::secure_key_store::MemorySecureKeyStore;

    fn temp_state_store(name: &str) -> crate::local_state::LocalStateStore {
        let path = std::env::temp_dir().join(format!(
            "yougen-mls-welcome-{name}-{}.json",
            crate::operation::uuid_v7()
        ));
        crate::local_state::LocalStateStore::with_path(path)
    }

    #[test]
    fn empty_welcome_set_reports_no_work() {
        let mut state = temp_state_store("empty");
        let store = MemorySecureKeyStore::new();
        let outcome = apply_welcome_messages_with_device_snapshot(
            &mut state,
            &store,
            "cx:space:empty",
            "did:web:alice.example",
            "cx:device:01904100-0000-7000-8000-000000000001",
            &json!({ "events": [] }),
        )
        .unwrap();
        assert_eq!(outcome, WelcomeApplyOutcome::default());
        assert_eq!(outcome.applied, 0);
        assert_eq!(outcome.failed, 0);
        assert!(outcome.first_error.is_none());
        // No welcomes present => no secret was created either.
        assert!(store.is_empty());
    }

    #[test]
    fn malformed_welcome_is_counted_not_swallowed() {
        let mut state = temp_state_store("malformed");
        let store = MemorySecureKeyStore::new();
        // A welcome entry whose content is not a valid MlsWelcomeEnvelope.
        let messages = json!({
            "events": [
                { "type": "cx.mls.welcome", "content": { "not": "a welcome" } }
            ]
        });
        let outcome = apply_welcome_messages_with_device_snapshot(
            &mut state,
            &store,
            "cx:space:malformed",
            "did:web:alice.example",
            "cx:device:01904100-0000-7000-8000-000000000001",
            &messages,
        )
        .unwrap();
        assert_eq!(outcome.applied, 0);
        assert_eq!(outcome.failed, 1);
        assert!(outcome.first_error.is_some());
    }
}
