//! Creator initial-group setup and the `ak.mls.genesis` event payload.

use super::{MlsRuntimeError, load_device_snapshot_secret, load_or_create_device_snapshot_secret};
use crate::secure_key_store::SecureKeyStore;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InitialMlsSnapshotSummary {
    pub realm_id: String,
    pub group_id: String,
    pub epoch: u64,
    /// Exact RFC 9420 MLSMessage(GroupInfo) bytes published as a durable,
    /// content-addressed blob before `ak.mls.genesis` is submitted.
    pub group_info_bytes: Vec<u8>,
    /// Exact TLS-serialized external ratchet-tree bytes published alongside
    /// [`Self::group_info_bytes`].
    pub ratchet_tree_bytes: Vec<u8>,
    /// String form of the MLS ciphersuite the group was created with.
    pub cipher_suite: String,
}

/// Ensure a Realm creator has the initial local MLS group snapshot.
///
/// The creator does not receive a Welcome for the group they create. Without
/// this genesis snapshot, their first encrypted write would fail with
/// `MissingWelcome` even though there is no Welcome to wait for.
pub fn ensure_creator_mls_snapshot(
    state_store: &mut crate::state::LocalStateStore,
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
    state_store: &mut crate::state::LocalStateStore,
    secure_store: &dyn SecureKeyStore,
    realm_id: &str,
    circle_id: Option<&str>,
    actor_id: &str,
    device_id: &str,
) -> Result<Option<InitialMlsSnapshotSummary>, MlsRuntimeError> {
    ensure_creator_mls_snapshot_for_effective_scope_with_binding(
        state_store,
        secure_store,
        realm_id,
        circle_id,
        actor_id,
        device_id,
        None,
    )
}

pub fn ensure_creator_mls_snapshot_for_effective_scope_with_binding(
    state_store: &mut crate::state::LocalStateStore,
    secure_store: &dyn SecureKeyStore,
    realm_id: &str,
    circle_id: Option<&str>,
    actor_id: &str,
    device_id: &str,
    sidecar_binding: Option<arkret_sdk::SidecarMlsBinding>,
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
    let identity = arkret_sdk::ArkretMlsIdentity::new_basic(principal_did, device_id_typed)
        .map_err(|err| MlsRuntimeError::Identity(format!("{err:?}")))?;
    let group_seed = circle.unwrap_or(realm);
    let group_id = arkret_sdk::base64url_encode(group_seed.as_bytes());
    let proof_request =
        crate::mls::governance_proof::proof_request(state_store, realm, circle, group_id, 0, 0)
            .map_err(MlsRuntimeError::Genesis)?;
    let governance_binding =
        crate::mls::governance_proof::cached_verified_binding(state_store, &proof_request)
            .map_err(MlsRuntimeError::Genesis)?;
    let governance_binding = match sidecar_binding {
        Some(binding) => governance_binding
            .with_sidecar_binding(binding)
            .map_err(|error| MlsRuntimeError::Genesis(error.to_string()))?,
        None => governance_binding,
    };
    let group = identity
        .create_group_with_governance_binding(group_seed.as_bytes(), &governance_binding)
        .map_err(|err| MlsRuntimeError::Genesis(format!("create group: {err}")))?;
    let (group_info_bytes, ratchet_tree_bytes) = group
        .public_group_state_bytes()
        .map_err(|err| MlsRuntimeError::Genesis(format!("export public group state: {err}")))?;
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
        group_info_bytes,
        ratchet_tree_bytes,
        cipher_suite,
    };
    state_store.save_mls_snapshot_for_effective_scope(realm.to_owned(), circle, snapshot);
    Ok(Some(summary))
}

pub fn initial_mls_snapshot_summary_from_existing(
    state_store: &crate::state::LocalStateStore,
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
    state_store: &crate::state::LocalStateStore,
    secure_store: &dyn SecureKeyStore,
    realm_id: &str,
    circle_id: Option<&str>,
    actor_id: &str,
    device_id: &str,
) -> Result<Option<InitialMlsSnapshotSummary>, MlsRuntimeError> {
    initial_mls_snapshot_summary_from_existing_for_effective_scope_with_binding(
        state_store,
        secure_store,
        realm_id,
        circle_id,
        actor_id,
        device_id,
        None,
    )
}

pub fn initial_mls_snapshot_summary_from_existing_for_effective_scope_with_binding(
    state_store: &crate::state::LocalStateStore,
    secure_store: &dyn SecureKeyStore,
    realm_id: &str,
    circle_id: Option<&str>,
    actor_id: &str,
    device_id: &str,
    sidecar_binding: Option<arkret_sdk::SidecarMlsBinding>,
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
    let group_id = group.group_id();
    let proof_request = crate::mls::governance_proof::proof_request(
        state_store,
        realm,
        circle,
        group_id.clone(),
        0,
        0,
    )
    .map_err(MlsRuntimeError::Genesis)?;
    let expected_binding =
        crate::mls::governance_proof::cached_verified_binding(state_store, &proof_request)
            .map_err(MlsRuntimeError::Genesis)?;
    let expected_binding = match sidecar_binding {
        Some(binding) => expected_binding
            .with_sidecar_binding(binding)
            .map_err(|error| MlsRuntimeError::Genesis(error.to_string()))?,
        None => expected_binding,
    };
    let current_binding = group.current_governance_binding().map_err(|err| {
        MlsRuntimeError::Genesis(format!("read epoch-0 governance binding: {err}"))
    })?;
    if current_binding.as_ref() != Some(&expected_binding) {
        return Err(MlsRuntimeError::Genesis(
            "epoch-0 snapshot governance binding differs from the verified Genesis Seal proof; recreate local MLS state"
                .to_owned(),
        ));
    }
    let (group_info_bytes, ratchet_tree_bytes) = group
        .public_group_state_bytes()
        .map_err(|err| MlsRuntimeError::Genesis(format!("export public group state: {err}")))?;
    Ok(Some(InitialMlsSnapshotSummary {
        realm_id: realm.to_owned(),
        group_id,
        epoch: group.epoch(),
        group_info_bytes,
        ratchet_tree_bytes,
        cipher_suite: arkret_sdk::ARKRET_MLS_CIPHERSUITE_CANONICAL_ID.to_owned(),
    }))
}

/// Build the canonical `ak.mls.genesis` payload for a freshly-created creator
/// group.
///
/// `governance_binding` MUST be a realm/circle binding at epoch `0 -> 0`
/// (genesis installs epoch 0); its serialized `effective_scope` is mirrored
/// into the top-level `effective_scope` field so the two stay in lockstep
/// (soland and strict client schema validators both compare them).
///
/// Ref/digest fields are content addresses over the exact raw RFC 9420 bytes,
/// matching `encryption-and-audit.md` §5.1.1.
///
/// `created_at` uses the same RFC3339 (seconds, UTC `Z`) format the event
/// builder stamps on SDK events.
pub fn build_mls_genesis_payload(
    summary: &InitialMlsSnapshotSummary,
    actor_id: &str,
    device_id: &str,
    governance_binding: &arkret_sdk::MlsGovernanceBindingPayload,
) -> Result<arkret_sdk::MlsGenesisPayload, MlsRuntimeError> {
    let group_info_digest = crate::canonical::sha256_digest(&summary.group_info_bytes);
    let ratchet_tree_digest = crate::canonical::sha256_digest(&summary.ratchet_tree_bytes);
    let group_info_ref = format!("ak:blob:{group_info_digest}");
    let ratchet_tree_ref = format!("ak:blob:{ratchet_tree_digest}");
    let payload = arkret_sdk::MlsGenesisPayload {
        mls_group_id: arkret_sdk::MlsGroupId::new(summary.group_id.clone())
            .map_err(|error| MlsRuntimeError::Genesis(format!("invalid MLS group id: {error}")))?,
        effective_scope: governance_binding.effective_scope().clone(),
        epoch: arkret_sdk::MlsGenesisEpoch,
        creator_principal_id: arkret_sdk::Did::new(actor_id.to_owned()).map_err(|error| {
            MlsRuntimeError::Genesis(format!("invalid creator principal id: {error}"))
        })?,
        creator_device_id: arkret_sdk::DeviceId::new(device_id.to_owned()).map_err(|error| {
            MlsRuntimeError::Genesis(format!("invalid creator device id: {error}"))
        })?,
        cipher_suite: arkret_sdk::NonEmptyString::new(summary.cipher_suite.clone()).map_err(
            |error| MlsRuntimeError::Genesis(format!("invalid MLS cipher suite: {error}")),
        )?,
        group_info_ref: arkret_sdk::BlobRef::new(group_info_ref).map_err(|error| {
            MlsRuntimeError::Genesis(format!("invalid GroupInfo blob ref: {error}"))
        })?,
        group_info_digest: arkret_sdk::Hash::new(group_info_digest).map_err(|error| {
            MlsRuntimeError::Genesis(format!("invalid GroupInfo digest: {error}"))
        })?,
        ratchet_tree_ref: arkret_sdk::BlobRef::new(ratchet_tree_ref).map_err(|error| {
            MlsRuntimeError::Genesis(format!("invalid ratchet-tree blob ref: {error}"))
        })?,
        ratchet_tree_digest: arkret_sdk::Hash::new(ratchet_tree_digest).map_err(|error| {
            MlsRuntimeError::Genesis(format!("invalid ratchet-tree digest: {error}"))
        })?,
        initial_keypackage_refs: None,
        governance_binding: governance_binding.clone(),
        created_at: crate::clock::now_utc_canonical(),
    };
    payload.validate().map_err(|error| {
        MlsRuntimeError::Genesis(format!("invalid MLS genesis payload: {error}"))
    })?;
    Ok(payload)
}

/// Publish the exact public epoch-0 MLS material referenced by a genesis
/// payload. Both uploads are content-address checked before the Event may be
/// submitted, so an accepted genesis can always service the standard
/// group-state-material query.
pub async fn upload_mls_genesis_public_material(
    api: &crate::transport::TransportClient,
    summary: &InitialMlsSnapshotSummary,
) -> Result<(), MlsRuntimeError> {
    for (label, bytes) in [
        ("GroupInfo", &summary.group_info_bytes),
        ("ratchet tree", &summary.ratchet_tree_bytes),
    ] {
        let digest = crate::canonical::sha256_digest(bytes);
        let expected_ref = format!("ak:blob:{digest}");
        let clients = crate::transport::EndpointClients::new(api.clone());
        let outcome = clients
            .blob()
            .upload_bytes_scoped(
                bytes.clone(),
                "application/octet-stream",
                Some(&summary.realm_id),
                None,
            )
            .await
            .map_err(|error| {
                MlsRuntimeError::Genesis(format!("upload MLS {label} material: {error}"))
            })?;
        if outcome.blob_ref.as_str() != expected_ref
            || outcome.content_digest.as_str() != digest
            || outcome.size_bytes != bytes.len() as u64
        {
            return Err(MlsRuntimeError::Genesis(format!(
                "uploaded MLS {label} material does not match its content address"
            )));
        }
    }
    Ok(())
}
