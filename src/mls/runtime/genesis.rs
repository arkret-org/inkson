//! Creator initial-group setup and the `ck.mls.genesis` event payload.

use serde_json::Value;

use super::{MlsRuntimeError, load_device_snapshot_secret, load_or_create_device_snapshot_secret};
use crate::secure_key_store::SecureKeyStore;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InitialMlsSnapshotSummary {
    pub realm_id: String,
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

/// Ensure a Realm creator has the initial local MLS group snapshot.
///
/// The creator does not receive a Welcome for the group they create. Without
/// this genesis snapshot, their first encrypted write would fail with
/// `MissingWelcome` even though there is no Welcome to wait for.
pub fn ensure_creator_mls_snapshot(
    state_store: &mut crate::local_state::LocalStateStore,
    secure_store: &dyn SecureKeyStore,
    realm_id: &str,
    actor_id: &str,
    device_id: &str,
) -> Result<Option<InitialMlsSnapshotSummary>, MlsRuntimeError> {
    ensure_creator_mls_snapshot_for_effective_scope(
        state_store,
        secure_store,
        realm_id,
        None,
        actor_id,
        device_id,
    )
}

pub fn ensure_creator_mls_snapshot_for_effective_scope(
    state_store: &mut crate::local_state::LocalStateStore,
    secure_store: &dyn SecureKeyStore,
    realm_id: &str,
    circle_id: Option<&str>,
    actor_id: &str,
    device_id: &str,
) -> Result<Option<InitialMlsSnapshotSummary>, MlsRuntimeError> {
    let realm = realm_id.trim();
    if realm.is_empty() {
        return Err(MlsRuntimeError::Genesis(
            "realm_id is required for initial MLS group setup".to_owned(),
        ));
    }
    let circle = circle_id
        .map(str::trim)
        .filter(|circle_id| !circle_id.is_empty());
    if state_store
        .mls_snapshot_for_effective_scope(realm, circle)
        .is_some()
    {
        return Ok(None);
    }

    let secret = load_or_create_device_snapshot_secret(secure_store, actor_id, device_id)
        .map_err(MlsRuntimeError::DeviceSecret)?;
    let principal_did = arkret_sdk::Did::new(actor_id.to_owned())
        .map_err(|err| MlsRuntimeError::Identity(format!("{err:?}")))?;
    let device_id_typed = arkret_sdk::DeviceId::new(device_id.to_owned())
        .map_err(|err| MlsRuntimeError::Identity(format!("{err:?}")))?;
    let identity = arkret_sdk::CokretMlsIdentity::new_basic(principal_did, device_id_typed)
        .map_err(|err| MlsRuntimeError::Identity(format!("{err:?}")))?;
    let group_seed = circle.unwrap_or(realm);
    let group = identity
        .create_group(group_seed.as_bytes())
        .map_err(|err| MlsRuntimeError::Genesis(format!("create group: {err}")))?;
    let ratchet_tree = group
        .ratchet_tree()
        .map_err(|err| MlsRuntimeError::Genesis(format!("export ratchet tree: {err}")))?;
    let schedule_hash = group.schedule_hash().to_string();
    let cipher_suite = arkret_sdk::ARKRET_MLS_CIPHERSUITE_CANONICAL_ID.to_owned();
    let post_state = group
        .export_state_record()
        .map_err(|err| MlsRuntimeError::Genesis(format!("export state: {err}")))?;
    let serialized_state = serde_json::to_vec(&post_state)
        .map_err(|err| MlsRuntimeError::Genesis(format!("serialize state: {err}")))?;
    let mut salt = [0u8; 16];
    getrandom::fill(&mut salt).map_err(|err| MlsRuntimeError::Salt(err.to_string()))?;
    let snapshot = crate::mls::persistence::encrypt_state(
        realm,
        &post_state.group_id,
        post_state.epoch,
        &serialized_state,
        &secret,
        &salt,
    );
    let summary = InitialMlsSnapshotSummary {
        realm_id: realm.to_owned(),
        group_id: post_state.group_id.clone(),
        epoch: post_state.epoch,
        ratchet_tree,
        schedule_hash,
        cipher_suite,
    };
    state_store.save_mls_snapshot_for_effective_scope(realm.to_owned(), circle, snapshot);
    Ok(Some(summary))
}

pub fn initial_mls_snapshot_summary_from_existing(
    state_store: &crate::local_state::LocalStateStore,
    secure_store: &dyn SecureKeyStore,
    realm_id: &str,
    actor_id: &str,
    device_id: &str,
) -> Result<Option<InitialMlsSnapshotSummary>, MlsRuntimeError> {
    initial_mls_snapshot_summary_from_existing_for_effective_scope(
        state_store,
        secure_store,
        realm_id,
        None,
        actor_id,
        device_id,
    )
}

pub fn initial_mls_snapshot_summary_from_existing_for_effective_scope(
    state_store: &crate::local_state::LocalStateStore,
    secure_store: &dyn SecureKeyStore,
    realm_id: &str,
    circle_id: Option<&str>,
    actor_id: &str,
    device_id: &str,
) -> Result<Option<InitialMlsSnapshotSummary>, MlsRuntimeError> {
    let realm = realm_id.trim();
    if realm.is_empty() {
        return Err(MlsRuntimeError::Genesis(
            "realm_id is required for MLS genesis summary restore".to_owned(),
        ));
    }
    let circle = circle_id
        .map(str::trim)
        .filter(|circle_id| !circle_id.is_empty());
    let Some(snapshot) = state_store.mls_snapshot_for_effective_scope(realm, circle) else {
        return Ok(None);
    };
    if snapshot.epoch != 0 {
        return Ok(None);
    }
    let secret = load_device_snapshot_secret(secure_store, actor_id, device_id)
        .map_err(MlsRuntimeError::DeviceSecret)?;
    // COR-04: genesis path — the snapshot is asserted to be epoch 0 just above, so
    // a Seal-view floor would be meaningless; floor 0 is intentional.
    let group = crate::mls::persistence::restore_envelope(&snapshot, &secret, 0)
        .map_err(|err| MlsRuntimeError::Genesis(format!("restore epoch-0 snapshot: {err}")))?;
    let ratchet_tree = group
        .ratchet_tree()
        .map_err(|err| MlsRuntimeError::Genesis(format!("export ratchet tree: {err}")))?;
    Ok(Some(InitialMlsSnapshotSummary {
        realm_id: realm.to_owned(),
        group_id: group.group_id(),
        epoch: group.epoch(),
        ratchet_tree,
        schedule_hash: group.schedule_hash().to_string(),
        cipher_suite: arkret_sdk::ARKRET_MLS_CIPHERSUITE_CANONICAL_ID.to_owned(),
    }))
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
/// builder stamps on SDK events.
pub fn build_mls_genesis_payload(
    summary: &InitialMlsSnapshotSummary,
    actor_id: &str,
    device_id: &str,
    governance_binding: &arkret_sdk::MlsGovernanceBindingPayload,
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
    let created_at = crate::clock::now_rfc3339_secs();
    Ok(serde_json::json!({
        "mls_group_id": summary.group_id,
        "effective_scope": effective_scope,
        "epoch": 0,
        "creator_principal_id": actor_id,
        "creator_device_id": device_id,
        "cipher_suite": summary.cipher_suite,
        "group_info_digest": summary.schedule_hash,
        "ratchet_tree_digest": ratchet_tree_digest,
        "governance_binding": binding_value,
        "created_at": created_at,
    }))
}
