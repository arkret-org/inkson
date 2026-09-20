//! Creator initial-group setup and the `ak.mls.genesis` event payload.

use super::{MlsRuntimeError, load_device_checkpoint_secret, load_or_create_account_mls_secret};
use crate::secure_key_store::SecureKeyStore;

pub(crate) const EPOCH_ZERO_SNAPSHOT_GOVERNANCE_BINDING_MISMATCH: &str = "epoch-0 snapshot governance binding differs from the verified Genesis Seal proof; recreate local MLS state";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InitialMlsCheckpointSummary {
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
pub fn ensure_creator_mls_checkpoint(
    state_store: &mut crate::state::LocalStateStore,
    secure_store: &dyn SecureKeyStore,
    realm_id: &str,
    authority: &arkret_sdk::AccountId,
    device_id: &arkret_sdk::DeviceId,
) -> Result<Option<InitialMlsCheckpointSummary>, MlsRuntimeError> {
    ensure_creator_mls_checkpoint_for_effective_scope(
        state_store,
        secure_store,
        realm_id,
        None,
        authority,
        device_id,
    )
}

pub fn ensure_creator_mls_checkpoint_for_effective_scope(
    state_store: &mut crate::state::LocalStateStore,
    secure_store: &dyn SecureKeyStore,
    realm_id: &str,
    circle_id: Option<&str>,
    authority: &arkret_sdk::AccountId,
    device_id: &arkret_sdk::DeviceId,
) -> Result<Option<InitialMlsCheckpointSummary>, MlsRuntimeError> {
    ensure_creator_mls_checkpoint_for_effective_scope_with_binding(
        state_store,
        secure_store,
        realm_id,
        circle_id,
        authority,
        device_id,
        None,
    )
}

pub fn ensure_creator_mls_checkpoint_for_effective_scope_with_binding(
    state_store: &mut crate::state::LocalStateStore,
    secure_store: &dyn SecureKeyStore,
    realm_id: &str,
    circle_id: Option<&str>,
    authority: &arkret_sdk::AccountId,
    device_id: &arkret_sdk::DeviceId,
    sidecar_id: Option<arkret_sdk::SidecarId>,
) -> Result<Option<InitialMlsCheckpointSummary>, MlsRuntimeError> {
    create_creator_mls_checkpoint_for_effective_scope_with_binding(
        state_store,
        secure_store,
        realm_id,
        circle_id,
        authority,
        device_id,
        sidecar_id,
        false,
    )
}

/// Replace an epoch-0 creator snapshot that never became an accepted Genesis.
///
/// The caller must have independently established that the server has no
/// accepted `ak.mls.genesis`. The local guards below additionally refuse to
/// overwrite any snapshot carrying an accepted transition reference or an
/// emitted marker. This is the recovery path for a create task interrupted
/// after the staged snapshot was persisted but before Genesis submission,
/// while the verified Realm checkpoint subsequently moved forward.
pub(crate) fn recreate_unaccepted_creator_mls_checkpoint(
    state_store: &mut crate::state::LocalStateStore,
    secure_store: &dyn SecureKeyStore,
    realm_id: &str,
    authority: &arkret_sdk::AccountId,
    device_id: &arkret_sdk::DeviceId,
) -> Result<InitialMlsCheckpointSummary, MlsRuntimeError> {
    let snapshot = state_store.mls_checkpoint_for(realm_id).ok_or_else(|| {
        MlsRuntimeError::Genesis(
            "cannot rebase an unaccepted creator snapshot that is missing".to_owned(),
        )
    })?;
    if snapshot.epoch != 0
        || snapshot.group_state_event_id.is_some()
        || state_store.mls_genesis_emitted_for(realm_id)
        || state_store
            .mls_group_state_ref_for_effective_scope(
                realm_id,
                None,
                &snapshot.group_id,
                snapshot.epoch,
            )
            .is_ok()
    {
        return Err(MlsRuntimeError::Genesis(
            "refusing to replace creator MLS state that may already be accepted".to_owned(),
        ));
    }

    create_creator_mls_checkpoint_for_effective_scope_with_binding(
        state_store,
        secure_store,
        realm_id,
        None,
        authority,
        device_id,
        None,
        true,
    )?
    .ok_or_else(|| {
        MlsRuntimeError::Genesis(
            "recreating the unaccepted creator snapshot produced no epoch-0 material".to_owned(),
        )
    })
}

fn create_creator_mls_checkpoint_for_effective_scope_with_binding(
    state_store: &mut crate::state::LocalStateStore,
    secure_store: &dyn SecureKeyStore,
    realm_id: &str,
    circle_id: Option<&str>,
    authority: &arkret_sdk::AccountId,
    device_id: &arkret_sdk::DeviceId,
    sidecar_id: Option<arkret_sdk::SidecarId>,
    replace_unaccepted_epoch_zero: bool,
) -> Result<Option<InitialMlsCheckpointSummary>, MlsRuntimeError> {
    let realm = realm_id.trim();
    if realm.is_empty() {
        return Err(MlsRuntimeError::Genesis(
            "realm_id is required for initial MLS group setup".to_owned(),
        ));
    }
    super::reject_retired_minimal_metadata_realm(state_store, realm)?;
    let circle = circle_id
        .map(str::trim)
        .filter(|circle_id| !circle_id.is_empty());
    let realm_typed = arkret_sdk::RealmId::new(realm.to_owned())
        .map_err(|error| MlsRuntimeError::Genesis(format!("invalid Realm id: {error}")))?;
    let effective_scope = match sidecar_id.as_ref() {
        Some(sidecar_id) => arkret_sdk::ScopeRef::Sidecar {
            realm_id: realm_typed.clone(),
            sidecar_id: sidecar_id.clone(),
        },
        None => match circle {
            Some(circle_id) => arkret_sdk::ScopeRef::Circle {
                realm_id: realm_typed.clone(),
                circle_id: arkret_sdk::CircleId::new(circle_id.to_owned()).map_err(|error| {
                    MlsRuntimeError::Genesis(format!("invalid Circle id: {error}"))
                })?,
            },
            None => arkret_sdk::ScopeRef::Realm {
                realm_id: realm_typed.clone(),
            },
        },
    };
    let group_id = effective_scope
        .canonical_mls_group_id()
        .map_err(|error| MlsRuntimeError::Genesis(error.to_string()))?
        .to_string();
    if state_store
        .mls_checkpoint_for_scope_and_group(&effective_scope, &group_id)
        .is_some()
        && !replace_unaccepted_epoch_zero
    {
        return Ok(None);
    }

    let secret = load_or_create_account_mls_secret(secure_store, authority)
        .map_err(MlsRuntimeError::DeviceSecret)?;
    let identity =
        crate::mls_api_helpers::ordinary_mls_identity(authority.clone(), device_id.clone())
            .map_err(MlsRuntimeError::Identity)?;
    let governance_binding = crate::mls::governance_proof::genesis_binding(&effective_scope)
        .map_err(MlsRuntimeError::Genesis)?;
    let mut group = identity
        .create_group_with_governance_binding(&effective_scope, &governance_binding)
        .map_err(|err| MlsRuntimeError::Genesis(format!("create group: {err}")))?;
    let device_authorize_event_id = match &group.identity().endpoint {
        arkret_sdk::MlsEndpointIdentity::HumanDevice {
            principal_id: _,
            device_id,
        } => Some(
            crate::identity::device_directory::cached_device_authorize_event_id(
                &authority.to_string(),
                device_id.as_str(),
            )
            .ok_or_else(|| {
                MlsRuntimeError::Genesis(
                    "accepted device authorization is unavailable for MLS genesis".to_owned(),
                )
            })?,
        ),
        arkret_sdk::MlsEndpointIdentity::AgentRuntime { .. } => None,
        arkret_sdk::MlsEndpointIdentity::MinimalMetadataPairwise { .. } => {
            return Err(MlsRuntimeError::Identity(
                "retired minimal-metadata endpoint cannot create an MLS group".to_owned(),
            ));
        }
    };
    let creator_actor = arkret_sdk::ActorId::account(authority.clone());
    group
        .install_local_creator_binding(creator_actor, device_authorize_event_id)
        .map_err(|error| MlsRuntimeError::Genesis(format!("bind creator leaf: {error}")))?;
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
    getrandom::fill(&mut salt)
        .map_err(|err| MlsRuntimeError::Genesis(format!("MLS checkpoint salt: {err}")))?;
    let snapshot = crate::mls::persistence::encrypt_state(
        realm,
        &post_state.group_id,
        post_state.epoch,
        &serialized_state,
        &secret,
        &salt,
    );
    let summary = InitialMlsCheckpointSummary {
        realm_id: realm.to_owned(),
        group_id: post_state.group_id.as_str().to_owned(),
        epoch: post_state.epoch,
        group_info_bytes,
        ratchet_tree_bytes,
        cipher_suite,
    };
    state_store
        .save_mls_checkpoint_for_scope(&effective_scope, snapshot)
        .map_err(MlsRuntimeError::Genesis)?;
    Ok(Some(summary))
}

pub fn initial_mls_checkpoint_summary_from_existing(
    state_store: &crate::state::LocalStateStore,
    secure_store: &dyn SecureKeyStore,
    realm_id: &str,
    authority: &arkret_sdk::AccountId,
    device_id: &arkret_sdk::DeviceId,
) -> Result<Option<InitialMlsCheckpointSummary>, MlsRuntimeError> {
    initial_mls_checkpoint_summary_from_existing_for_effective_scope(
        state_store,
        secure_store,
        realm_id,
        None,
        authority,
        device_id,
    )
}

pub fn initial_mls_checkpoint_summary_from_existing_for_effective_scope(
    state_store: &crate::state::LocalStateStore,
    secure_store: &dyn SecureKeyStore,
    realm_id: &str,
    circle_id: Option<&str>,
    authority: &arkret_sdk::AccountId,
    device_id: &arkret_sdk::DeviceId,
) -> Result<Option<InitialMlsCheckpointSummary>, MlsRuntimeError> {
    initial_mls_checkpoint_summary_from_existing_for_effective_scope_with_binding(
        state_store,
        secure_store,
        realm_id,
        circle_id,
        authority,
        device_id,
        None,
    )
}

pub fn initial_mls_checkpoint_summary_from_existing_for_effective_scope_with_binding(
    state_store: &crate::state::LocalStateStore,
    secure_store: &dyn SecureKeyStore,
    realm_id: &str,
    circle_id: Option<&str>,
    authority: &arkret_sdk::AccountId,
    device_id: &arkret_sdk::DeviceId,
    sidecar_id: Option<arkret_sdk::SidecarId>,
) -> Result<Option<InitialMlsCheckpointSummary>, MlsRuntimeError> {
    let realm = realm_id.trim();
    if realm.is_empty() {
        return Err(MlsRuntimeError::Genesis(
            "realm_id is required for MLS genesis summary restore".to_owned(),
        ));
    }
    let circle = circle_id
        .map(str::trim)
        .filter(|circle_id| !circle_id.is_empty());
    let realm_typed = arkret_sdk::RealmId::new(realm.to_owned())
        .map_err(|error| MlsRuntimeError::Genesis(format!("invalid Realm id: {error}")))?;
    let effective_scope = match sidecar_id.as_ref() {
        Some(sidecar_id) => arkret_sdk::ScopeRef::Sidecar {
            realm_id: realm_typed.clone(),
            sidecar_id: sidecar_id.clone(),
        },
        None => match circle {
            Some(circle_id) => arkret_sdk::ScopeRef::Circle {
                realm_id: realm_typed.clone(),
                circle_id: arkret_sdk::CircleId::new(circle_id.to_owned()).map_err(|error| {
                    MlsRuntimeError::Genesis(format!("invalid Circle id: {error}"))
                })?,
            },
            None => arkret_sdk::ScopeRef::Realm {
                realm_id: realm_typed.clone(),
            },
        },
    };
    let expected_group_id = effective_scope
        .canonical_mls_group_id()
        .map_err(|error| MlsRuntimeError::Genesis(error.to_string()))?
        .to_string();
    let Some(snapshot) =
        state_store.mls_checkpoint_for_scope_and_group(&effective_scope, &expected_group_id)
    else {
        return Ok(None);
    };
    if snapshot.epoch != 0 {
        return Ok(None);
    }
    let secret = load_device_checkpoint_secret(secure_store, authority, device_id)
        .map_err(MlsRuntimeError::DeviceSecret)?;
    // COR-04: genesis path — the snapshot is asserted to be epoch 0 just above, so
    // a Seal-view floor would be meaningless; floor 0 is intentional.
    let group = crate::mls::persistence::restore_envelope(&snapshot, &secret, 0)
        .map_err(|err| MlsRuntimeError::Genesis(format!("restore epoch-0 snapshot: {err}")))?;
    let group_id = group.group_id();
    // The epoch-0 group must be the one this scope derives, or the material
    // belongs to another group and must not be described as this scope's
    // Genesis.
    let expected_binding = crate::mls::governance_proof::genesis_binding(&effective_scope)
        .map_err(MlsRuntimeError::Genesis)?;
    if expected_binding
        .mls_group_id()
        .map_err(|error| MlsRuntimeError::Genesis(error.to_string()))?
        != group_id
        || group.epoch() != 0
    {
        return Err(MlsRuntimeError::Genesis(
            EPOCH_ZERO_SNAPSHOT_GOVERNANCE_BINDING_MISMATCH.to_owned(),
        ));
    }
    let (group_info_bytes, ratchet_tree_bytes) = group
        .public_group_state_bytes()
        .map_err(|err| MlsRuntimeError::Genesis(format!("export public group state: {err}")))?;
    Ok(Some(InitialMlsCheckpointSummary {
        realm_id: realm.to_owned(),
        group_id: group_id.as_str().to_owned(),
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
/// Blob refs are content addresses over the exact raw RFC 9420 bytes,
/// matching `encryption-and-audit.md` §5.1.1.
///
/// `created_at` uses the same RFC3339 (seconds, UTC `Z`) format the event
/// builder stamps on SDK events.
pub fn build_mls_genesis_payload(
    summary: &InitialMlsCheckpointSummary,
    governance_binding: &arkret_sdk::MlsGovernanceBindingPayload,
) -> Result<arkret_sdk::MlsGenesisPayload, MlsRuntimeError> {
    let group_info_digest = crate::canonical::sha256_digest(&summary.group_info_bytes);
    let ratchet_tree_digest = crate::canonical::sha256_digest(&summary.ratchet_tree_bytes);
    let group_info_ref = format!("ak:blob:{group_info_digest}");
    let ratchet_tree_ref = format!("ak:blob:{ratchet_tree_digest}");
    if governance_binding
        .mls_group_id()
        .map_err(|error| MlsRuntimeError::Genesis(error.to_string()))?
        .as_str()
        != summary.group_id
    {
        return Err(MlsRuntimeError::Genesis(
            "MLS Genesis material belongs to a different scope-derived group".to_owned(),
        ));
    }
    let payload = arkret_sdk::MlsGenesisPayload {
        cipher_suite: arkret_sdk::NonEmptyString::new(summary.cipher_suite.clone()).map_err(
            |error| MlsRuntimeError::Genesis(format!("invalid MLS cipher suite: {error}")),
        )?,
        group_info_ref: arkret_sdk::BlobRef::new(group_info_ref).map_err(|error| {
            MlsRuntimeError::Genesis(format!("invalid GroupInfo blob ref: {error}"))
        })?,
        ratchet_tree_ref: arkret_sdk::BlobRef::new(ratchet_tree_ref).map_err(|error| {
            MlsRuntimeError::Genesis(format!("invalid ratchet-tree blob ref: {error}"))
        })?,
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
    summary: &InitialMlsCheckpointSummary,
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
        if outcome.blob_ref.as_str() != expected_ref || outcome.size_bytes != bytes.len() as u64 {
            return Err(MlsRuntimeError::Genesis(format!(
                "uploaded MLS {label} material does not match its content address"
            )));
        }
    }
    Ok(())
}
