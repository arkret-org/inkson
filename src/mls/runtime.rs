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
pub const ACCOUNT_MLS_SECRET_CURRENT_VERSION: u32 = 1;
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
    /// SEC-08 — a `minimal_metadata_realm` send tried to use a non-hidden
    /// `aad_visibility`, which `enforce_minimal_metadata_aad` rejects
    /// (`encryption-and-audit.md` §2.9). Fail-closed: the message/reaction is
    /// never emitted with a wider visibility than the profile permits.
    AadPolicy(String),
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
            | Self::Salt(_)
            | Self::AadPolicy(_) => MlsRuntimeStatus::Ready,
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
            Self::AadPolicy(reason) => {
                format!("MLS minimal-metadata AAD policy violation: {reason}")
            }
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
    /// Base64 TLS-serialized ratchet tree of the freshly created group —
    /// used to seed the `ck.mls.genesis` event's `ratchet_tree_digest`.
    pub ratchet_tree: String,
    /// `sha256:<hex>` digest over the group's current key schedule (epoch
    /// authenticator). Used as the genesis `group_info_digest`.
    pub schedule_hash: String,
    /// String form of the MLS ciphersuite the group was created with.
    pub cipher_suite: String,
}

pub fn build_mls_history_backup_body(
    snapshot: &crate::mls::persistence::MlsSnapshotEnvelope,
    actor_did: &str,
    device_id: &str,
) -> (String, Value) {
    let backup_id = format!("ck:backup:{}", crate::operation::uuid_v7());
    let body = snapshot.to_key_backup_body(&backup_id, actor_did, device_id);
    (backup_id, body)
}

pub async fn upload_mls_snapshot_backup(
    api: &crate::api::CokretApi,
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
    let principal_did = cokret_sdk::Did::new(actor_did.to_owned())
        .map_err(|err| MlsRuntimeError::Identity(format!("{err:?}")))?;
    let device_id_typed = cokret_sdk::DeviceId::new(device_id.to_owned())
        .map_err(|err| MlsRuntimeError::Identity(format!("{err:?}")))?;
    let identity = cokret_sdk::CokretMlsIdentity::new_basic(principal_did, device_id_typed)
        .map_err(|err| MlsRuntimeError::Identity(format!("{err:?}")))?;
    let group = identity
        .create_group(space.as_bytes())
        .map_err(|err| MlsRuntimeError::Genesis(format!("create group: {err}")))?;
    let ratchet_tree = group
        .ratchet_tree()
        .map_err(|err| MlsRuntimeError::Genesis(format!("export ratchet tree: {err}")))?;
    let schedule_hash = group.schedule_hash().to_string();
    let cipher_suite = format!("{:?}", cokret_sdk::COKRET_MLS_CIPHERSUITE);
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
        ratchet_tree,
        schedule_hash,
        cipher_suite,
    };
    state_store.save_mls_snapshot(space.to_owned(), snapshot);
    Ok(Some(summary))
}

/// Build the canonical `ck.mls.genesis` payload for a freshly-created creator
/// group.
///
/// `governance_binding` MUST be a realm/circle binding at epoch `0 -> 0`
/// (genesis installs epoch 0); its serialized `effective_scope` is mirrored
/// into the top-level `effective_scope` field so the two stay in lockstep
/// (soland and strict client schema validators both compare them).
///
/// Digest field derivation (deterministic, leak-free):
/// - `group_info_digest`  = the group's `schedule_hash()` (`sha256:` over the RFC 9420 epoch
///   authenticator) — a stable per-epoch group-state digest.
/// - `ratchet_tree_digest` = `sha256:` over the base64 TLS-serialized ratchet tree bytes.
///
/// `created_at` uses the same RFC3339 (seconds, UTC `Z`) format the event
/// builder stamps on `EventEnvelope::created_at`.
pub fn build_mls_genesis_payload(
    summary: &InitialMlsSnapshotSummary,
    actor_did: &str,
    device_id: &str,
    governance_binding: &cokret_sdk::MlsGovernanceBindingPayload,
) -> Result<Value, MlsRuntimeError> {
    let binding_value = serde_json::to_value(governance_binding)
        .map_err(|err| MlsRuntimeError::Genesis(format!("serialize governance binding: {err}")))?;
    let effective_scope = binding_value
        .get("effective_scope")
        .cloned()
        .ok_or_else(|| {
            MlsRuntimeError::Genesis("governance binding missing effective_scope".to_owned())
        })?;
    let ratchet_tree_digest = crate::canonical::sha256_digest(summary.ratchet_tree.as_bytes());
    let created_at = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    Ok(serde_json::json!({
        "mls_group_id": summary.group_id,
        "effective_scope": effective_scope,
        "epoch": 0,
        "creator_principal_id": actor_did,
        "creator_device_id": device_id,
        "cipher_suite": summary.cipher_suite,
        "group_info_digest": summary.schedule_hash,
        "ratchet_tree_digest": ratchet_tree_digest,
        "governance_binding": binding_value,
        "created_at": created_at,
    }))
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
                    .ok_or(MlsRuntimeError::DeviceSecret(SecureKeyStoreError::NotFound))?
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
        // Re-wrapping does not advance the epoch — carry the epoch-start clock
        // so a secret rotation never resets the §2.9 minimal-metadata 1h cap.
        let rotated = crate::mls::persistence::encrypt_state(
            &snapshot.space_id,
            &snapshot.group_id,
            snapshot.epoch,
            &plaintext,
            &new_secret,
            &salt,
        )
        .carry_epoch_started_at(snapshot);
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
        if entry.get("type").and_then(|t| t.as_str()) == Some("ck.mls.welcome")
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
    let principal_did = cokret_sdk::Did::new(actor_did.to_owned())
        .map_err(|err| MlsRuntimeError::Identity(format!("{err:?}")))?;
    let device_id_typed = cokret_sdk::DeviceId::new(device_id.to_owned())
        .map_err(|err| MlsRuntimeError::Identity(format!("{err:?}")))?;
    // Per-welcome failures no longer abort the loop or get swallowed: each is
    // counted and the first reason retained so callers can report partial
    // success without failing the whole boot.
    let mut outcome = WelcomeApplyOutcome::default();
    for welcome_value in welcome_entries {
        let welcome = match serde_json::from_value::<cokret_sdk::MlsWelcomeEnvelope>(welcome_value)
        {
            Ok(welcome) => welcome,
            Err(err) => {
                outcome.record_failure(format!("welcome envelope parse: {err}"));
                continue;
            }
        };
        let identity = match cokret_sdk::CokretMlsIdentity::new_basic(
            principal_did.clone(),
            device_id_typed.clone(),
        ) {
            Ok(identity) => identity,
            Err(err) => {
                outcome.record_failure(format!("identity: {err:?}"));
                continue;
            }
        };
        let group = match cokret_sdk::CokretMlsGroup::join_from_welcome(identity, &welcome) {
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
        cokret_sdk::Hash,
        Vec<cokret_sdk::Did>,
        Vec<serde_json::Value>,
        cokret_sdk::MlsCommitEnvelope,
        crate::mls::persistence::MlsSnapshotEnvelope,
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
    // X14 — persist-on-accept: do NOT save the post-commit snapshot here.
    // The caller MUST call `state_store.save_mls_snapshot(space_id,
    // new_envelope)` ONLY after the server ACCEPTS the corresponding
    // `ck.mls.commit` event. Persisting before acceptance let the local
    // snapshot epoch race ahead of the server's accepted epoch whenever a
    // commit POST failed/was cancelled, so every later write computed
    // `expected_prev_epoch = local_epoch - 1 > server_epoch` and the server
    // rejected it with `mls_epoch_skew` forever. Returning the envelope and
    // letting the caller persist on accept keeps `snapshot.epoch ==
    // server.epoch` in lockstep by construction.
    let new_envelope = crate::mls::persistence::encrypt_state(
        space_id,
        &post_state.group_id,
        post_state.epoch,
        &serialized_state,
        &secret,
        &salt,
    );
    Ok((
        schedule_hash,
        member_dids,
        encrypted_values,
        commit_envelope,
        new_envelope,
    ))
}

/// Encrypt a single message plaintext under the Space MLS group, binding
/// `aad` into the payload digest, and return the structured
/// [`cokret_sdk::EncryptedPayload`] (not yet wrapped as a wire envelope).
///
/// The caller assembles the spec-canonical `ck.schema.encrypted_envelope.v1`
/// wire shape via [`cokret_sdk::EncryptedEnvelopeV1::from_payload`] once it
/// knows the `ck.mls.commit` event id that bounds this epoch (used as the
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
        cokret_sdk::Hash,
        Vec<cokret_sdk::Did>,
        cokret_sdk::EncryptedPayload,
        cokret_sdk::MlsCommitEnvelope,
        crate::mls::persistence::MlsSnapshotEnvelope,
    ),
    MlsRuntimeError,
> {
    let snapshot = state_store
        .mls_snapshot_for(space_id)
        .ok_or(MlsRuntimeError::MissingWelcome)?;
    // SEC-08 (§2.9) — fail-closed: a `minimal_metadata_realm` message MUST use
    // `aad_visibility=hidden`. Enforce before any commit/encrypt so a non-hidden
    // AAD never advances the epoch nor produces ciphertext (mirrors soland's
    // server-side reject). The 1h epoch cap needs no separate force here: every
    // message self-update-commits below, so each message already opens a fresh
    // epoch — the within-epoch frequency window for messages is one message.
    let is_minimal_metadata = state_store.space_projection_is_minimal_metadata(space_id);
    assert_minimal_metadata_aad(&aad_visibility_of(&aad), is_minimal_metadata)?;
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
    // X14 — persist-on-accept: see `encrypt_values_with_device_snapshot`.
    // The caller persists `new_envelope` ONLY after the server accepts the
    // `ck.mls.commit`, keeping `snapshot.epoch == server.epoch` in lockstep
    // and preventing the permanent `mls_epoch_skew` that optimistic
    // pre-accept persistence caused.
    let new_envelope = crate::mls::persistence::encrypt_state(
        space_id,
        &post_state.group_id,
        post_state.epoch,
        &serialized_state,
        &secret,
        &salt,
    );
    Ok((
        schedule_hash,
        member_dids,
        encrypted,
        commit_envelope,
        new_envelope,
    ))
}

/// SEC-08 (`encryption-and-audit.md` §2.9) — pure committer decision: should a
/// send force-advance the MLS epoch *before* riding the current epoch?
///
/// For a `minimal_metadata_realm` Realm the §2.9 epoch-lifetime SHOULD is a MUST
/// of ≤1h. Within-epoch reaction frequency is the observable this bounds, so a
/// send (especially a reaction, which otherwise reuses the current epoch's
/// application key without committing) MUST roll the epoch once the current one
/// has outlived the cap. Non-minimal Realms never force a commit here
/// (`false`), preserving their existing behaviour. Clock skew (`now` earlier
/// than `epoch_started_at`) is never reported as overdue — delegated to the
/// SDK's [`cokret_sdk::minimal_metadata_epoch_overdue`].
pub fn should_force_epoch_advance(
    is_minimal_metadata: bool,
    epoch_started_at: chrono::DateTime<chrono::Utc>,
    now: chrono::DateTime<chrono::Utc>,
) -> bool {
    is_minimal_metadata && cokret_sdk::minimal_metadata_epoch_overdue(epoch_started_at, now)
}

/// SEC-08 — fail-closed committer-side assertion that a `minimal_metadata_realm`
/// send uses `aad_visibility=hidden` (`encryption-and-audit.md` §2.9).
///
/// Thin wrapper over the SDK's [`cokret_sdk::enforce_minimal_metadata_aad`]
/// that maps the SDK protocol error into [`MlsRuntimeError::AadPolicy`] so the
/// runtime's typed error surface stays uniform. This mirrors soland's
/// server-side reject, giving client + server defence in depth: a minimal Realm
/// can never emit a non-hidden AAD, and the server would reject it if it
/// somehow did.
pub fn assert_minimal_metadata_aad(
    visibility: &cokret_sdk::AadVisibility,
    is_minimal_metadata: bool,
) -> Result<(), MlsRuntimeError> {
    cokret_sdk::enforce_minimal_metadata_aad(visibility, is_minimal_metadata)
        .map_err(|err| MlsRuntimeError::AadPolicy(err.to_string()))
}

/// SEC-08 — infer the [`cokret_sdk::AadVisibility`] discriminator from a
/// canonical `ck.schema.encrypted_envelope.v1` AAD value.
///
/// The schema discriminator is structural (`encryption-and-audit.md` §2.9): a
/// `hidden` envelope omits both `event_id` and `event_ref_digest`; an
/// `opaque_id` envelope carries `event_id`; a `routing_digest` envelope carries
/// `event_ref_digest`. Used by [`assert_minimal_metadata_aad`] on the message
/// path so a minimal Realm cannot ship a non-hidden AAD even if a caller
/// constructed one. `event_id` is checked first so a malformed value carrying
/// both fields resolves to the *less* private (and therefore rejected) form.
fn aad_visibility_of(aad: &serde_json::Value) -> cokret_sdk::AadVisibility {
    let has = |key: &str| aad.get(key).is_some_and(|v| !v.is_null());
    if has("event_id") {
        cokret_sdk::AadVisibility::OpaqueId
    } else if has("event_ref_digest") {
        cokret_sdk::AadVisibility::RoutingDigest
    } else {
        cokret_sdk::AadVisibility::Hidden
    }
}

/// MLS exporter label for the v1 reaction routing tag
/// (`encryption-and-audit.md` §2.9). Bound, together with `context =
/// realm_id` and the current group epoch's exporter secret, into the
/// keyed-HMAC routing tag.
pub const REACTION_ROUTING_LABEL_V1: &str = "cokret-reaction-routing-v1";
/// Length (bytes) of the MLS exporter output used as the HMAC key.
pub const REACTION_ROUTING_EXPORT_LEN: usize = 32;
/// Content type for the encrypted real-emoji payload of a reaction.
pub const REACTION_ENCRYPTED_CONTENT_TYPE: &str = "application/vnd.cokret.reaction+json";

/// Result of sealing an E2EE reaction: the plaintext routing tag for the
/// wire `reaction_payload.key`, plus the structured encrypted payload that
/// carries the real emoji.
pub struct EncryptedReaction {
    /// `sha256:<hex>` keyed-HMAC routing tag for `reaction_payload.key`.
    pub routing_tag: String,
    /// MLS application-message payload carrying the real emoji JSON.
    pub encrypted_payload: cokret_sdk::EncryptedPayload,
    /// SEC-08 (`encryption-and-audit.md` §2.9) — present ONLY when this
    /// reaction force-advanced the MLS epoch because the
    /// `minimal_metadata_realm` 1h cap was exceeded. The caller MUST submit
    /// this `ck.mls.commit` and, on server-accept, persist
    /// [`Self::forced_commit_snapshot`] (X14 persist-on-accept). When `None`
    /// the reaction rode the current epoch and its snapshot was already
    /// persisted internally (epoch unchanged ⇒ no epoch-skew risk).
    pub forced_commit: Option<cokret_sdk::MlsCommitEnvelope>,
    /// Post-forced-commit snapshot the caller persists on server-accept. Set
    /// iff [`Self::forced_commit`] is `Some`.
    pub forced_commit_snapshot: Option<crate::mls::persistence::MlsSnapshotEnvelope>,
}

/// Pure derivation of the §2.9 v1 routing tag from an MLS exporter secret.
///
/// `tag = "sha256:" || hex(HMAC-SHA256(exporter_secret, NFC(canonical_emoji)))`.
/// Split out from [`reaction_routing_tag_v1`] so it can be unit-tested with a
/// fixed exporter secret (the MLS half is exercised separately).
pub fn reaction_routing_tag_from_exporter(exporter_secret: &[u8], canonical_emoji: &str) -> String {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    use unicode_normalization::UnicodeNormalization;

    let nfc: String = canonical_emoji.nfc().collect();
    let mut mac = <Hmac<Sha256>>::new_from_slice(exporter_secret)
        .expect("HMAC-SHA256 accepts a key of any length");
    mac.update(nfc.as_bytes());
    let tag = mac.finalize().into_bytes();
    let mut hex = String::with_capacity(7 + tag.len() * 2);
    hex.push_str("sha256:");
    for byte in tag.iter() {
        use std::fmt::Write as _;
        let _ = write!(hex, "{byte:02x}");
    }
    hex
}

/// Restore this device's MLS group for `space_id` and derive the §2.9 v1
/// reaction routing tag for `canonical_emoji` at the current epoch.
///
/// Read-only on the MLS group — it only reads the epoch's exporter secret,
/// so it neither commits, advances the ratchet, nor mutates persisted
/// snapshot state. Returns the `sha256:<hex>` wire form for
/// `reaction_payload.key`.
pub fn reaction_routing_tag_v1(
    state_store: &mut crate::local_state::LocalStateStore,
    secure_store: &dyn SecureKeyStore,
    space_id: &str,
    realm_id: &str,
    actor_did: &str,
    device_id: &str,
    canonical_emoji: &str,
) -> Result<String, MlsRuntimeError> {
    let snapshot = state_store
        .mls_snapshot_for(space_id)
        .ok_or(MlsRuntimeError::MissingWelcome)?;
    let secret = load_device_snapshot_secret(secure_store, actor_did, device_id)
        .map_err(MlsRuntimeError::DeviceSecret)?;
    let group = crate::mls::persistence::restore_envelope(&snapshot, &secret, 0)
        .map_err(|err| MlsRuntimeError::SnapshotRestore(err.to_string()))?;
    let exporter = group
        .export_secret(
            REACTION_ROUTING_LABEL_V1,
            realm_id.as_bytes(),
            REACTION_ROUTING_EXPORT_LEN,
        )
        .map_err(|err| MlsRuntimeError::Export(err.to_string()))?;
    Ok(reaction_routing_tag_from_exporter(
        &exporter,
        canonical_emoji,
    ))
}

/// Seal an E2EE reaction: derive the v1 routing tag and encrypt the real
/// emoji as an MLS application message, both under the current epoch.
///
/// Unlike message send, this does NOT advance the MLS epoch (no commit) —
/// `encryption-and-audit.md` §2.9 reuses the application-key flow, so
/// reactions ride the current epoch and the server deduplicates on the
/// routing tag. The post-encrypt snapshot IS persisted immediately so the
/// sender's application ratchet never reuses a generation; because the epoch
/// is unchanged there is no epoch-skew risk that would require
/// persist-on-accept.
pub fn encrypt_reaction_with_device_snapshot(
    state_store: &mut crate::local_state::LocalStateStore,
    secure_store: &dyn SecureKeyStore,
    space_id: &str,
    realm_id: &str,
    actor_did: &str,
    device_id: &str,
    canonical_emoji: &str,
) -> Result<EncryptedReaction, MlsRuntimeError> {
    let snapshot = state_store
        .mls_snapshot_for(space_id)
        .ok_or(MlsRuntimeError::MissingWelcome)?;
    let secret = load_device_snapshot_secret(secure_store, actor_did, device_id)
        .map_err(MlsRuntimeError::DeviceSecret)?;
    let mut group = crate::mls::persistence::restore_envelope(&snapshot, &secret, 0)
        .map_err(|err| MlsRuntimeError::SnapshotRestore(err.to_string()))?;

    // SEC-08 (§2.9) — fail-closed AAD policy: this path always builds a
    // `hidden` AAD below, but for a `minimal_metadata_realm` Realm the hidden
    // requirement is a MUST. Assert it up front (with the same SDK helper
    // soland rejects with) so any future edit that widens visibility on a
    // minimal Realm fails loudly here instead of leaking message-id metadata.
    let is_minimal_metadata = state_store.space_projection_is_minimal_metadata(space_id);
    assert_minimal_metadata_aad(&cokret_sdk::AadVisibility::Hidden, is_minimal_metadata)?;

    // SEC-08 (§2.9) — minimal-metadata epoch lifetime ≤ 1h. A reaction normally
    // reuses the current epoch (no commit), so on a minimal Realm we MUST roll
    // the epoch once it has outlived the cap, bounding within-epoch reaction
    // frequency to a ≤1h window. The forced `ck.mls.commit` is surfaced to the
    // caller (X14 persist-on-accept) rather than persisted optimistically.
    let now = chrono::Utc::now();
    let forced_commit =
        if should_force_epoch_advance(is_minimal_metadata, snapshot.epoch_started_at, now) {
            Some(
                group
                    .self_update_commit()
                    .map_err(|err| MlsRuntimeError::Commit(err.to_string()))?,
            )
        } else {
            None
        };

    // Routing tag is derived from the post-(optional-commit) epoch exporter
    // secret; the application message below does not change the epoch further.
    let exporter = group
        .export_secret(
            REACTION_ROUTING_LABEL_V1,
            realm_id.as_bytes(),
            REACTION_ROUTING_EXPORT_LEN,
        )
        .map_err(|err| MlsRuntimeError::Export(err.to_string()))?;
    let routing_tag = reaction_routing_tag_from_exporter(&exporter, canonical_emoji);

    // The decrypted plaintext MUST validate as
    // event-payload.schema.json#/$defs/reaction_encrypted_payload_plaintext —
    // a JSON object whose `key` is the real emoji / short tag.
    let plaintext = serde_json::to_vec(&serde_json::json!({ "key": canonical_emoji }))
        .map_err(|err| MlsRuntimeError::Serialize(err.to_string()))?;
    let aad = cokret_sdk::EncryptedEnvelopeAadV1::hidden(realm_id, "ck.reaction.add");
    let aad_value =
        serde_json::to_value(&aad).map_err(|err| MlsRuntimeError::Serialize(err.to_string()))?;
    let encrypted_payload = group
        .encrypt_payload_with_aad(REACTION_ENCRYPTED_CONTENT_TYPE, Some(aad_value), &plaintext)
        .map_err(|err| MlsRuntimeError::Encrypt(err.to_string()))?;

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

    if forced_commit.is_some() {
        // X14 — a forced epoch advance must NOT be persisted before the server
        // accepts the `ck.mls.commit`, or the local epoch races ahead and every
        // later write is rejected with `mls_epoch_skew`. Hand the snapshot back
        // for the caller to persist on accept.
        Ok(EncryptedReaction {
            routing_tag,
            encrypted_payload,
            forced_commit,
            forced_commit_snapshot: Some(new_envelope),
        })
    } else {
        // No epoch change → persist the advanced application ratchet now (no
        // epoch-skew risk, and persisting prevents nonce reuse on the next
        // reaction). Carry the epoch-start clock forward so a stream of
        // reactions can never reset the §2.9 1h cap.
        let new_envelope = new_envelope.carry_epoch_started_at(&snapshot);
        state_store.save_mls_snapshot(space_id.to_owned(), new_envelope);
        Ok(EncryptedReaction {
            routing_tag,
            encrypted_payload,
            forced_commit: None,
            forced_commit_snapshot: None,
        })
    }
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
    fn reaction_routing_tag_is_deterministic_and_wire_shaped() {
        let exporter = [0x11u8; 32];
        let tag = reaction_routing_tag_from_exporter(&exporter, "👍");
        // Stable for the same (exporter, emoji).
        assert_eq!(tag, reaction_routing_tag_from_exporter(&exporter, "👍"));
        // sha256:<64 lowercase hex> wire form.
        let hex = tag.strip_prefix("sha256:").expect("sha256: prefix");
        assert_eq!(hex.len(), 64);
        assert!(
            hex.chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        );
    }

    #[test]
    fn reaction_routing_tag_separates_emoji_and_exporter() {
        let exporter_a = [0x11u8; 32];
        let exporter_b = [0x22u8; 32];
        // Different emoji → different tag under the same exporter.
        assert_ne!(
            reaction_routing_tag_from_exporter(&exporter_a, "👍"),
            reaction_routing_tag_from_exporter(&exporter_a, "🎉"),
        );
        // Same emoji → different tag under a different epoch's exporter secret
        // (this is why the tag does not dedup across epochs).
        assert_ne!(
            reaction_routing_tag_from_exporter(&exporter_a, "👍"),
            reaction_routing_tag_from_exporter(&exporter_b, "👍"),
        );
    }

    #[test]
    fn reaction_routing_tag_normalises_to_nfc() {
        let exporter = [0x33u8; 32];
        // "é" as precomposed U+00E9 vs decomposed "e" + U+0301 must agree
        // after NFC normalisation, so the chosen-emoji privacy + dedup hold
        // regardless of the sender's input form.
        let precomposed = "\u{00E9}";
        let decomposed = "e\u{0301}";
        assert_eq!(
            reaction_routing_tag_from_exporter(&exporter, precomposed),
            reaction_routing_tag_from_exporter(&exporter, decomposed),
        );
    }

    #[test]
    fn force_epoch_advance_only_for_overdue_minimal_metadata_realm() {
        use chrono::{Duration, Utc};
        let started = Utc::now();
        // Non-minimal Realm: never forced, regardless of age.
        assert!(!should_force_epoch_advance(
            false,
            started,
            started + Duration::hours(5)
        ));
        // Minimal Realm under the 1h cap: not forced.
        assert!(!should_force_epoch_advance(
            true,
            started,
            started + Duration::minutes(59)
        ));
        // Exactly 1h is the inclusive cap (overdue is strictly >1h).
        assert!(!should_force_epoch_advance(
            true,
            started,
            started + Duration::hours(1)
        ));
        // Minimal Realm past 1h: forced.
        assert!(should_force_epoch_advance(
            true,
            started,
            started + Duration::hours(1) + Duration::seconds(1)
        ));
        // Clock skew (now < started) is never overdue.
        assert!(!should_force_epoch_advance(
            true,
            started,
            started - Duration::minutes(10)
        ));
    }

    #[test]
    fn minimal_metadata_aad_enforcement_is_fail_closed() {
        use cokret_sdk::AadVisibility;
        // Hidden is always accepted.
        assert_minimal_metadata_aad(&AadVisibility::Hidden, true).unwrap();
        assert_minimal_metadata_aad(&AadVisibility::Hidden, false).unwrap();
        // Non-hidden on a minimal Realm is rejected with the typed policy error.
        for v in [AadVisibility::RoutingDigest, AadVisibility::OpaqueId] {
            let err = assert_minimal_metadata_aad(&v, true).unwrap_err();
            assert!(matches!(err, MlsRuntimeError::AadPolicy(_)));
        }
        // Non-minimal Realm is unaffected by any visibility.
        assert_minimal_metadata_aad(&AadVisibility::RoutingDigest, false).unwrap();
        assert_minimal_metadata_aad(&AadVisibility::OpaqueId, false).unwrap();
    }

    #[test]
    fn aad_visibility_inferred_from_canonical_aad_shape() {
        use cokret_sdk::AadVisibility;
        // hidden() omits both event-id fields ⇒ Hidden.
        let hidden = serde_json::to_value(cokret_sdk::EncryptedEnvelopeAadV1::hidden(
            "ck:realm:r",
            "ck.message.create",
        ))
        .unwrap();
        assert_eq!(aad_visibility_of(&hidden), AadVisibility::Hidden);
        // event_ref_digest present ⇒ RoutingDigest.
        assert_eq!(
            aad_visibility_of(&json!({
                "realm_id": "ck:realm:r",
                "event_kind": "ck.message.create",
                "event_ref_digest": "sha256:aa"
            })),
            AadVisibility::RoutingDigest
        );
        // event_id present ⇒ OpaqueId (checked first / least private).
        assert_eq!(
            aad_visibility_of(&json!({
                "realm_id": "ck:realm:r",
                "event_kind": "ck.message.create",
                "event_id": "ck:event:1"
            })),
            AadVisibility::OpaqueId
        );
        // Null event-id fields are treated as absent ⇒ Hidden.
        assert_eq!(
            aad_visibility_of(&json!({
                "realm_id": "ck:realm:r",
                "event_kind": "ck.message.create",
                "event_id": null,
                "event_ref_digest": null
            })),
            AadVisibility::Hidden
        );
    }

    #[test]
    fn device_snapshot_secret_is_created_and_reused() {
        let store = MemorySecureKeyStore::new();
        let first = load_or_create_device_snapshot_secret(
            &store,
            "did:web:alice.example",
            "ck:device:01904100-0000-7000-8000-000000000001",
        )
        .unwrap();
        let second = load_or_create_device_snapshot_secret(
            &store,
            "did:web:alice.example",
            "ck:device:01904100-0000-7000-8000-000000000001",
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
            "ck:device:01904100-0000-7000-8000-000000000001",
        )
        .unwrap_err();
        assert!(matches!(missing, SecureKeyStoreError::NotFound));
        assert!(store.is_empty());
    }

    #[test]
    fn device_snapshot_secret_is_scoped_by_actor_and_device() {
        let a = device_snapshot_secret_key("did:web:alice.example", "ck:device:a");
        let b = device_snapshot_secret_key("did:web:bob.example", "ck:device:a");
        let c = device_snapshot_secret_key("did:web:alice.example", "ck:device:b");
        assert_ne!(a, b);
        assert_ne!(a, c);
        assert!(a.starts_with("yougen.mls_snapshot.device_secret.v1."));
    }

    #[test]
    fn account_secret_is_shared_across_devices() {
        let store = MemorySecureKeyStore::new();
        let actor = "did:web:alice.example";
        let from_a = load_or_create_device_snapshot_secret(&store, actor, "ck:device:a").unwrap();
        // A different device of the SAME account must resolve the SAME secret.
        let from_b = load_or_create_device_snapshot_secret(&store, actor, "ck:device:b").unwrap();
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
        let device = "ck:device:legacy";
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
        let loaded = load_device_snapshot_secret(&store, actor, "ck:device:fresh").unwrap();
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
            load_device_snapshot_secret(&store, actor, "ck:device:any").unwrap(),
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
        let device = "ck:device:01904100-0000-7000-8000-000000000001";
        let space = "ck:realm:01904100-0000-7000-8000-000000000001";

        let summary =
            ensure_creator_mls_snapshot(&mut state, &secure, space, actor, device).unwrap();

        let summary = summary.expect("missing creator snapshot should be created");
        assert_eq!(summary.space_id, space);
        assert_eq!(summary.epoch, 0);
        assert!(state.mls_snapshot_for(space).is_some());
        // X14: encrypt no longer persists internally — the caller saves the
        // returned envelope on server-accept. Mirror that contract here.
        let encrypted = encrypt_values_with_device_snapshot(
            &mut state,
            &secure,
            space,
            actor,
            device,
            "application/vnd.cokret.test+json",
            &[br#""private""#.to_vec()],
        )
        .unwrap();
        assert_eq!(encrypted.2.len(), 1);
        state.save_mls_snapshot(space, encrypted.4.clone());
        assert!(state.mls_snapshot_for(space).unwrap().epoch >= 1);
        let encrypted_again = encrypt_values_with_device_snapshot(
            &mut state,
            &secure,
            space,
            actor,
            device,
            "application/vnd.cokret.test+json",
            &[br#""private-again""#.to_vec()],
        )
        .unwrap();
        assert_eq!(encrypted_again.2.len(), 1);
        state.save_mls_snapshot(space, encrypted_again.4.clone());
        assert!(state.mls_snapshot_for(space).unwrap().epoch >= 2);
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn minimal_metadata_reaction_forces_commit_when_epoch_overdue() {
        // SEC-08 end-to-end (native): a minimal-metadata Realm whose epoch is
        // older than 1h must force a `ck.mls.commit` (epoch advance) on the next
        // reaction, and MUST NOT persist the advanced snapshot internally
        // (X14 persist-on-accept) — the snapshot is handed back instead.
        let mut state = temp_state_store("minimal-reaction-force");
        let secure = MemorySecureKeyStore::new();
        let actor = "did:web:alice.example";
        let device = "ck:device:01904100-0000-7000-8000-000000000001";
        let space = "ck:realm:01904100-0000-7000-8000-000000000002";

        // Declare the minimal-metadata profile on the cached projection.
        state.save_space_projection(
            space,
            json!({ "active_profiles": [cokret_sdk::mls::MINIMAL_METADATA_REALM_PROFILE] }),
        );
        assert!(state.space_projection_is_minimal_metadata(space));

        ensure_creator_mls_snapshot(&mut state, &secure, space, actor, device).unwrap();
        let base_epoch = state.mls_snapshot_for(space).unwrap().epoch;

        // Backdate the persisted snapshot's epoch clock past the 1h cap.
        let mut overdue = state.mls_snapshot_for(space).unwrap();
        overdue.epoch_started_at = chrono::Utc::now() - chrono::Duration::hours(2);
        state.save_mls_snapshot(space, overdue);

        let sealed = encrypt_reaction_with_device_snapshot(
            &mut state, &secure, space, space, actor, device, "👍",
        )
        .unwrap();

        // A commit was forced and surfaced for persist-on-accept; the stored
        // snapshot epoch did NOT advance yet (caller persists on accept).
        assert!(sealed.forced_commit.is_some());
        let returned = sealed
            .forced_commit_snapshot
            .expect("forced commit returns its snapshot");
        assert!(returned.epoch > base_epoch);
        assert_eq!(state.mls_snapshot_for(space).unwrap().epoch, base_epoch);
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn non_minimal_reaction_never_forces_commit_and_persists_in_place() {
        // Control: a non-minimal Realm with an equally-old epoch never forces a
        // commit; the reaction rides the current epoch and persists immediately.
        let mut state = temp_state_store("non-minimal-reaction");
        let secure = MemorySecureKeyStore::new();
        let actor = "did:web:alice.example";
        let device = "ck:device:01904100-0000-7000-8000-000000000001";
        let space = "ck:realm:01904100-0000-7000-8000-000000000003";

        ensure_creator_mls_snapshot(&mut state, &secure, space, actor, device).unwrap();
        let base_epoch = state.mls_snapshot_for(space).unwrap().epoch;
        let mut overdue = state.mls_snapshot_for(space).unwrap();
        overdue.epoch_started_at = chrono::Utc::now() - chrono::Duration::hours(2);
        state.save_mls_snapshot(space, overdue);

        assert!(!state.space_projection_is_minimal_metadata(space));
        let sealed = encrypt_reaction_with_device_snapshot(
            &mut state, &secure, space, space, actor, device, "👍",
        )
        .unwrap();
        assert!(sealed.forced_commit.is_none());
        assert!(sealed.forced_commit_snapshot.is_none());
        // Same epoch persisted in place (no skew), epoch clock carried forward.
        let after = state.mls_snapshot_for(space).unwrap();
        assert_eq!(after.epoch, base_epoch);
    }

    fn genesis_governance_binding(group_id: &str) -> cokret_sdk::MlsGovernanceBindingPayload {
        let realm_id =
            cokret_sdk::RealmId::new("ck:realm:01904100-0000-7000-8000-000000000001").unwrap();
        let frontier = vec![
            cokret_sdk::EventId::new("ck:event:01904100-0000-7000-8000-0000000000aa").unwrap(),
        ];
        let policy_root = cokret_sdk::Hash::new(
            "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        )
        .unwrap();
        // Genesis installs epoch 0 (governance binding epoch 0 -> 0).
        cokret_sdk::MlsGovernanceBindingPayload::realm(
            realm_id,
            group_id,
            0,
            0,
            frontier,
            policy_root,
        )
        .unwrap()
    }

    #[test]
    fn build_mls_genesis_payload_has_required_fields() {
        let mut state = temp_state_store("genesis-payload");
        let secure = MemorySecureKeyStore::new();
        let actor = "did:web:alice.example";
        let device = "ck:device:01904100-0000-7000-8000-000000000001";
        let space = "ck:realm:01904100-0000-7000-8000-000000000001";

        let summary = ensure_creator_mls_snapshot(&mut state, &secure, space, actor, device)
            .unwrap()
            .expect("creator snapshot should be created");
        let binding = genesis_governance_binding(&summary.group_id);
        let payload = build_mls_genesis_payload(&summary, actor, device, &binding).unwrap();

        // epoch MUST be the literal 0 the schema/reducer require.
        assert_eq!(payload["epoch"].as_u64(), Some(0));
        assert_eq!(payload["creator_principal_id"].as_str(), Some(actor));
        assert_eq!(payload["creator_device_id"].as_str(), Some(device));
        assert_eq!(
            payload["mls_group_id"].as_str(),
            Some(summary.group_id.as_str())
        );
        // cipher_suite is the SDK ciphersuite string form — non-empty.
        assert!(!payload["cipher_suite"].as_str().unwrap_or("").is_empty());
        // governance_binding present and carries the genesis 0 -> 0 epochs.
        assert!(payload.get("governance_binding").is_some());
        assert_eq!(
            payload["governance_binding"]["previous_epoch"].as_u64(),
            Some(0)
        );
        assert_eq!(
            payload["governance_binding"]["next_epoch"].as_u64(),
            Some(0)
        );
        // effective_scope mirrors the governance binding's.
        assert_eq!(
            payload["effective_scope"],
            payload["governance_binding"]["effective_scope"]
        );
        // group_info / ratchet_tree digest fields present and sha256-shaped.
        let group_info_digest = payload["group_info_digest"].as_str().unwrap();
        let ratchet_tree_digest = payload["ratchet_tree_digest"].as_str().unwrap();
        assert!(group_info_digest.starts_with("sha256:"));
        assert!(ratchet_tree_digest.starts_with("sha256:"));
        assert_eq!(group_info_digest, summary.schedule_hash);
        // created_at present.
        assert!(payload["created_at"].as_str().unwrap_or("").contains('T'));

        // Validate against the registered canonical `mls_genesis_payload`
        // schema so the full payload passes strict client/server validation.
        let catalog = cokret_sdk::schema::event_payload_validator_catalog();
        if catalog
            .missing_payload_validators_for(std::iter::once("ck.mls.genesis"))
            .is_empty()
        {
            catalog
                .validate_payload("ck.mls.genesis", &payload)
                .expect("genesis payload must satisfy the registered schema");
        }
    }

    #[test]
    fn mls_genesis_emitted_flag_is_idempotent() {
        let mut state = temp_state_store("genesis-idempotent");
        let space = "ck:realm:01904100-0000-7000-8000-000000000001";
        assert!(!state.mls_genesis_emitted_for(space));
        state.mark_mls_genesis_emitted(space);
        assert!(state.mls_genesis_emitted_for(space));
        // Re-marking is a no-op / stays true.
        state.mark_mls_genesis_emitted(space);
        assert!(state.mls_genesis_emitted_for(space));
    }

    #[test]
    fn mls_history_backup_body_decodes_to_snapshot_envelope() {
        let envelope = crate::mls::persistence::encrypt_state(
            "ck:space:01904100-0000-7000-8000-000000000001",
            "group-a",
            8,
            b"opaque sdk state",
            "device-secret",
            b"deterministic-salt",
        );
        let body = envelope.to_key_backup_body(
            "ck:backup:01904100-0000-7000-8000-000000000002",
            "did:web:alice.example",
            "ck:device:01904100-0000-7000-8000-000000000001",
        );

        let decoded = decode_mls_history_backup_envelope(&body).unwrap();

        assert_eq!(decoded.space_id, envelope.space_id);
        assert_eq!(decoded.group_id, envelope.group_id);
        assert_eq!(decoded.epoch, envelope.epoch);
        assert_eq!(body["backup_class"], "mls_history");
        assert_eq!(body["encryption"]["recipient_method"], "secret_storage_key");
        assert!(body["encryption"].get("kdf").is_none());
        assert!(body.get("plaintext").is_none());
        assert!(body.get("serialized_state").is_none());
    }

    #[test]
    fn mls_history_backup_decode_rejects_metadata_mismatch() {
        let envelope = crate::mls::persistence::encrypt_state(
            "ck:space:01904100-0000-7000-8000-000000000001",
            "group-a",
            8,
            b"opaque sdk state",
            "device-secret",
            b"deterministic-salt",
        );
        let mut body = envelope.to_key_backup_body(
            "ck:backup:01904100-0000-7000-8000-000000000002",
            "did:web:alice.example",
            "ck:device:01904100-0000-7000-8000-000000000001",
        );
        body["envelope_meta"]["epoch"] = json!(7);

        let error = decode_mls_history_backup_envelope(&body).unwrap_err();

        assert!(matches!(error, MlsRuntimeError::BackupDecode(_)));
        assert!(error.user_message().contains("epoch mismatch"));
    }

    #[test]
    fn account_secret_rotation_rewraps_backups_old_secret_cannot_decrypt() {
        let actor = "did:web:alice.example";
        let device = "ck:device:01904100-0000-7000-8000-000000000001";
        let space = "ck:space:01904100-0000-7000-8000-000000000009";
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
            "ck:space:01904100-0000-7000-8000-000000000001",
            "group-for-missing-secret-test",
            1,
            b"not-a-real-group-state",
            "other-device-secret",
            b"deterministic-salt",
        );
        state.save_mls_snapshot("ck:space:01904100-0000-7000-8000-000000000001", envelope);

        let error = encrypt_values_with_device_snapshot(
            &mut state,
            &store,
            "ck:space:01904100-0000-7000-8000-000000000001",
            "did:web:alice.example",
            "ck:device:01904100-0000-7000-8000-000000000001",
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
        use cokret_sdk::{CokretMlsIdentity, DeviceId, Did};

        let actor = "did:web:alice.example";
        let device = "ck:device:01904100-0000-7000-8000-000000000001";
        let space = "ck:space:01904100-0000-7000-8000-000000000003";
        let store = MemorySecureKeyStore::new();
        let secret = load_or_create_device_snapshot_secret(&store, actor, device).unwrap();
        let identity = CokretMlsIdentity::new_basic(
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

        let (_schedule_hash, member_dids, encrypted_values, _commit, _new_envelope) =
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

    /// X14 — persist-on-accept contract: `encrypt_values_with_device_snapshot`
    /// MUST NOT advance the persisted snapshot. The stored snapshot epoch only
    /// moves when the caller saves the returned envelope (which it does ONLY
    /// after the server accepts the `ck.mls.commit`). This is the invariant
    /// that keeps `snapshot.epoch == server.epoch` in lockstep and prevents the
    /// permanent `mls_epoch_skew` that optimistic pre-accept persistence caused.
    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn encrypt_does_not_persist_snapshot_until_caller_saves_on_accept() {
        let actor = "did:web:alice.example";
        let device = "ck:device:01904100-0000-7000-8000-000000000001";
        let secure = MemorySecureKeyStore::new();
        let _ = load_or_create_device_snapshot_secret(&secure, actor, device).unwrap();
        let mut state = temp_state_store("persist-on-accept");
        let space = "ck:realm:01904100-0000-7000-8000-000000000099";

        // Genesis installs the epoch-0 snapshot.
        ensure_creator_mls_snapshot(&mut state, &secure, space, actor, device)
            .unwrap()
            .expect("creator snapshot created");
        let epoch_before = state.mls_snapshot_for(space).unwrap().epoch;

        // Encrypting produces a post-commit envelope at epoch+1 WITHOUT
        // touching the persisted snapshot.
        let result = encrypt_values_with_device_snapshot(
            &mut state,
            &secure,
            space,
            actor,
            device,
            "application/vnd.cokret.test+json",
            &[br#""private""#.to_vec()],
        )
        .unwrap();
        let post_commit_envelope = result.4;
        assert_eq!(
            state.mls_snapshot_for(space).unwrap().epoch,
            epoch_before,
            "encrypt must NOT advance the persisted snapshot (persist-on-accept)"
        );
        assert!(
            post_commit_envelope.epoch > epoch_before,
            "returned envelope carries the post-commit (advanced) epoch"
        );

        // The caller saving the returned envelope (simulating server-accept)
        // is what advances the persisted snapshot.
        state.save_mls_snapshot(space, post_commit_envelope.clone());
        assert_eq!(
            state.mls_snapshot_for(space).unwrap().epoch,
            post_commit_envelope.epoch
        );
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn restore_mls_history_backup_saves_snapshot_when_fresh() {
        use cokret_sdk::{CokretMlsIdentity, DeviceId, Did};

        let actor = "did:web:alice.example";
        let device = "ck:device:01904100-0000-7000-8000-000000000001";
        let space = "ck:space:01904100-0000-7000-8000-000000000004";
        let store = MemorySecureKeyStore::new();
        let secret = load_or_create_device_snapshot_secret(&store, actor, device).unwrap();
        let identity = CokretMlsIdentity::new_basic(
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
            "ck:backup:01904100-0000-7000-8000-000000000002",
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
        use cokret_sdk::{CokretMlsIdentity, DeviceId, Did};

        let actor = "did:web:alice.example";
        let device = "ck:device:01904100-0000-7000-8000-000000000001";
        let space = "ck:space:01904100-0000-7000-8000-000000000002";
        let store = MemorySecureKeyStore::new();
        let secret = load_or_create_device_snapshot_secret(&store, actor, device).unwrap();
        let identity = CokretMlsIdentity::new_basic(
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
            "ck:backup:01904100-0000-7000-8000-000000000002",
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
        use cokret_sdk::{CokretMlsIdentity, DeviceId, Did};

        use crate::mls::account_recovery::{
            build_mls_account_secret_backup_body_with_kek, decrypt_mls_account_secret_backup,
        };
        use crate::recovery_crypto::derive_vault_kek;

        let actor = "did:web:alice.example";
        let device_a = "ck:device:01904100-0000-7000-8000-00000000000a";
        let device_b = "ck:device:01904100-0000-7000-8000-00000000000b";
        let space = "ck:space:01904100-0000-7000-8000-0000000000ab";
        let passphrase: &[u8] = b"correct horse battery staple";

        // --- Device A: account secret + a real MLS group + history backup body.
        let store_a = MemorySecureKeyStore::new();
        let secret_a = load_or_create_account_mls_secret(&store_a, actor, device_a).unwrap();

        let identity = CokretMlsIdentity::new_basic(
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
            "ck:backup:01904100-0000-7000-8000-0000000000ac",
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
            "ck:space:empty",
            "did:web:alice.example",
            "ck:device:01904100-0000-7000-8000-000000000001",
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
                { "type": "ck.mls.welcome", "content": { "not": "a welcome" } }
            ]
        });
        let outcome = apply_welcome_messages_with_device_snapshot(
            &mut state,
            &store,
            "ck:space:malformed",
            "did:web:alice.example",
            "ck:device:01904100-0000-7000-8000-000000000001",
            &messages,
        )
        .unwrap();
        assert_eq!(outcome.applied, 0);
        assert_eq!(outcome.failed, 1);
        assert!(outcome.first_error.is_some());
    }
}
