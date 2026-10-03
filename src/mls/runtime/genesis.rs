//! Creator initial-group setup and the `ak.mls.genesis` event payload.

use super::{MlsRuntimeError, load_device_checkpoint_secret, load_or_create_account_mls_secret};
use crate::secure_key_store::SecureKeyStore;

pub(crate) const EPOCH_ZERO_SNAPSHOT_GOVERNANCE_BINDING_MISMATCH: &str = "epoch-0 snapshot differs from the immutable Genesis scope or group; recover the original material";

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
    /// The sole epoch-0 leaf's verified MLS public key and accepted endpoint
    /// authorization. This is read from the occupied leaf binding, never the
    /// Event signing key.
    pub creator_leaf_authority: arkret_sdk::MlsGenesisCreatorLeafAuthority,
}

fn creator_leaf_authority_from_group(
    group: &arkret_sdk::mls::ArkretMlsGroup,
    authority: &arkret_sdk::AccountId,
) -> Result<arkret_sdk::MlsGenesisCreatorLeafAuthority, MlsRuntimeError> {
    let bindings = group.verified_leaf_bindings().map_err(|error| {
        MlsRuntimeError::Genesis(format!("read verified creator leaf binding: {error}"))
    })?;
    let [creator] = bindings.as_slice() else {
        return Err(MlsRuntimeError::Genesis(
            "MLS Genesis requires exactly one verified epoch-0 creator leaf".to_owned(),
        ));
    };
    if creator.leaf_index != 0
        || creator.actor_id != arkret_sdk::ActorId::account(authority.clone())
    {
        return Err(MlsRuntimeError::Genesis(
            "MLS Genesis creator leaf differs from the local account".to_owned(),
        ));
    }
    let (endpoint, authorization_event_ref) = match &creator.endpoint {
        arkret_sdk::MlsEndpointIdentity::HumanDevice { device_id, .. } => (
            arkret_sdk::MlsWelcomeRecipientEndpoint::Device {
                device_id: device_id.clone(),
            },
            creator.device_authorize_event_id.clone().ok_or_else(|| {
                MlsRuntimeError::Genesis(
                    "verified creator device leaf has no accepted authorization Event".to_owned(),
                )
            })?,
        ),
        arkret_sdk::MlsEndpointIdentity::AgentRuntime {
            verification_method,
            agent_key_authorize_event_id,
            ..
        } => (
            arkret_sdk::MlsWelcomeRecipientEndpoint::AgentRuntime {
                verification_method: verification_method.clone(),
            },
            agent_key_authorize_event_id.clone(),
        ),
        arkret_sdk::MlsEndpointIdentity::MinimalMetadataPairwise { .. } => {
            return Err(MlsRuntimeError::Genesis(
                "retired pairwise endpoint cannot bind an MLS Genesis leaf".to_owned(),
            ));
        }
    };
    let result = arkret_sdk::MlsGenesisCreatorLeafAuthority {
        leaf_signature_key_b64u: creator.signature_key.clone(),
        endpoint,
        authorization_event_ref,
    };
    result.validate().map_err(|error| {
        MlsRuntimeError::Genesis(format!("invalid verified creator leaf authority: {error}"))
    })?;
    Ok(result)
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
    ensure_creator_mls_checkpoint_with_binding_inner(
        state_store,
        secure_store,
        realm_id,
        circle_id,
        authority,
        device_id,
        sidecar_id,
        None,
    )
}

pub(crate) fn ensure_creator_mls_checkpoint_with_pinned_binding(
    state_store: &mut crate::state::LocalStateStore,
    secure_store: &dyn SecureKeyStore,
    realm_id: &str,
    authority: &arkret_sdk::AccountId,
    device_id: &arkret_sdk::DeviceId,
    pinned_binding: Option<&arkret_sdk::MlsGovernanceBindingPayload>,
) -> Result<Option<InitialMlsCheckpointSummary>, MlsRuntimeError> {
    ensure_creator_mls_checkpoint_with_binding_inner(
        state_store,
        secure_store,
        realm_id,
        None,
        authority,
        device_id,
        None,
        pinned_binding,
    )
}

fn ensure_creator_mls_checkpoint_with_binding_inner(
    state_store: &mut crate::state::LocalStateStore,
    secure_store: &dyn SecureKeyStore,
    realm_id: &str,
    circle_id: Option<&str>,
    authority: &arkret_sdk::AccountId,
    device_id: &arkret_sdk::DeviceId,
    sidecar_id: Option<arkret_sdk::SidecarId>,
    pinned_binding: Option<&arkret_sdk::MlsGovernanceBindingPayload>,
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
    let governance_binding = match pinned_binding {
        Some(binding) => {
            binding
                .validate()
                .map_err(|error| MlsRuntimeError::Genesis(error.to_string()))?;
            if binding.effective_scope() != &effective_scope
                || binding.base_group_state_ref().is_some()
                || binding.previous_epoch() != 0
                || binding.next_epoch() != 0
                || binding.key_access_revision() != 0
            {
                return Err(MlsRuntimeError::Genesis(
                    "pinned creator binding differs from the exact epoch-zero scope".into(),
                ));
            }
            binding.clone()
        }
        None => crate::mls::governance_proof::genesis_binding(&effective_scope)
            .map_err(MlsRuntimeError::Genesis)?,
    };

    let existing = if matches!(effective_scope, arkret_sdk::ScopeRef::Sidecar { .. }) {
        state_store.mls_checkpoint_for_scope_and_group(&effective_scope, &group_id)
    } else {
        state_store.mls_checkpoint_for_scope(&effective_scope)
    };
    if let Some(snapshot) = existing {
        if snapshot.group_id != group_id {
            return Err(MlsRuntimeError::Genesis(
                EPOCH_ZERO_SNAPSHOT_GOVERNANCE_BINDING_MISMATCH.to_owned(),
            ));
        }
        return Ok(None);
    }

    let secret = load_or_create_account_mls_secret(secure_store, authority)
        .map_err(MlsRuntimeError::DeviceSecret)?;
    let (snapshot, summary) = generate_creator_epoch_zero(
        &effective_scope,
        authority,
        device_id,
        &governance_binding,
        &secret,
        None,
    )?;
    state_store
        .save_mls_checkpoint_for_scope(&effective_scope, snapshot)
        .map_err(MlsRuntimeError::Genesis)?;
    Ok(Some(summary))
}

/// Pure in-memory generation. The caller commits the entire recovery unit
/// before publishing a blob, signing Genesis or exposing a sendable item.
pub(crate) fn generate_creator_epoch_zero(
    effective_scope: &arkret_sdk::ScopeRef,
    authority: &arkret_sdk::AccountId,
    device_id: &arkret_sdk::DeviceId,
    governance_binding: &arkret_sdk::MlsGovernanceBindingPayload,
    checkpoint_secret: &str,
    pinned_device_authorization: Option<&arkret_sdk::EventId>,
) -> Result<
    (
        crate::mls::persistence::MlsLocalCheckpointEnvelope,
        InitialMlsCheckpointSummary,
    ),
    MlsRuntimeError,
> {
    governance_binding
        .validate()
        .map_err(|error| MlsRuntimeError::Genesis(error.to_string()))?;
    if governance_binding.effective_scope() != effective_scope
        || governance_binding.base_group_state_ref().is_some()
        || governance_binding.previous_epoch() != 0
        || governance_binding.next_epoch() != 0
        || governance_binding.key_access_revision() != 0
    {
        return Err(MlsRuntimeError::Genesis(
            "invalid pinned epoch-zero binding".into(),
        ));
    }
    let identity =
        crate::mls_api_helpers::ordinary_mls_identity(authority.clone(), device_id.clone())
            .map_err(MlsRuntimeError::Identity)?;
    let mut group = identity
        .create_group_with_governance_binding(&effective_scope, &governance_binding)
        .map_err(|err| MlsRuntimeError::Genesis(format!("create group: {err}")))?;
    let device_authorize_event_id = match &group.identity().endpoint {
        arkret_sdk::MlsEndpointIdentity::HumanDevice {
            principal_id: _,
            device_id,
        } => Some(
            pinned_device_authorization
                .cloned()
                .or_else(|| {
                    crate::identity::device_directory::cached_device_authorize_event_id(
                        &authority.to_string(),
                        device_id.as_str(),
                    )
                })
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
        effective_scope.realm_id().as_str(),
        &post_state.group_id,
        post_state.epoch,
        &serialized_state,
        checkpoint_secret,
        &salt,
    );
    let summary = InitialMlsCheckpointSummary {
        realm_id: effective_scope.realm_id().to_string(),
        group_id: post_state.group_id.as_str().to_owned(),
        epoch: post_state.epoch,
        group_info_bytes,
        ratchet_tree_bytes,
        cipher_suite,
        creator_leaf_authority: creator_leaf_authority_from_group(&group, authority)?,
    };
    Ok((snapshot, summary))
}

/// Freeze producer content using the complete Actor carried by the durable
/// intent, without converting it through a UI principal string builder.
pub(crate) fn freeze_creator_genesis_core(
    intent: &arkret_models_collaboration::mls_creator_bootstrap::MlsCreatorBootstrapIntent,
    evidence: &arkret_models_collaboration::mls_creator_bootstrap::MlsCreatorBootstrapGovernanceEvidence,
    summary: &InitialMlsCheckpointSummary,
) -> Result<arkret_sdk::AuthoredEvent, MlsRuntimeError> {
    evidence
        .validate_binding(intent)
        .map_err(|error| MlsRuntimeError::Genesis(error.to_string()))?;
    let payload = build_mls_genesis_payload(summary, evidence.governance_binding())?;
    let created_at = payload.created_at;
    let suite = intent
        .effective_scope()
        .realm_id()
        .digest_suite_code()
        .digest_suite();
    arkret_sdk::TypedEventDraft::<arkret_sdk::event_spec::MlsGenesis>::new(
        intent.effective_scope().clone(),
        intent.owner_actor_id().clone(),
        payload,
    )
    .and_then(|draft| draft.into_intent(created_at))
    .and_then(|draft| draft.author_with_digest_suite(suite))
    .map_err(|error| MlsRuntimeError::Genesis(error.to_string()))
}

/// Decrypt and authenticate the persisted unit with the original device
/// secret. The account checkpoint is a derived cache, never the recovery source.
pub(crate) fn restore_creator_epoch_zero(
    unit: &arkret_models_collaboration::mls_creator_bootstrap::MlsCreatorBootstrapEpochZero,
    intent: &arkret_models_collaboration::mls_creator_bootstrap::MlsCreatorBootstrapIntent,
    checkpoint_secret: &str,
) -> Result<(Vec<u8>, InitialMlsCheckpointSummary), MlsRuntimeError> {
    let snapshot: crate::mls::persistence::MlsLocalCheckpointEnvelope =
        serde_json::from_slice(unit.encrypted_private_state()).map_err(|error| {
            MlsRuntimeError::Genesis(format!("decode creator private envelope: {error}"))
        })?;
    if snapshot.epoch != 0
        || snapshot.admission_epoch != 0
        || snapshot.group_state_event_id.is_some()
        || snapshot.realm_id != intent.effective_scope().realm_id().as_str()
        || snapshot.group_id != intent.mls_group_id().as_str()
    {
        return Err(MlsRuntimeError::Genesis(
            "creator private envelope coordinate mismatch".into(),
        ));
    }
    let group = crate::mls::persistence::restore_envelope(&snapshot, checkpoint_secret, 0)
        .map_err(|error| {
            MlsRuntimeError::Genesis(format!("restore creator private unit: {error}"))
        })?;
    let (group_info, tree) = group
        .public_group_state_bytes()
        .map_err(|error| MlsRuntimeError::Genesis(error.to_string()))?;
    let owner = intent
        .owner_actor_id()
        .as_account_id()
        .ok_or_else(|| MlsRuntimeError::Genesis("Device creator has no account".into()))?;
    let leaf = creator_leaf_authority_from_group(&group, owner)?;
    let payload = unit
        .payload()
        .map_err(|error| MlsRuntimeError::Genesis(error.to_string()))?;
    if group.scope() != intent.effective_scope()
        || group.epoch() != 0
        || group.group_id() != *intent.mls_group_id()
        || group_info != unit.group_info_bytes()
        || tree != unit.ratchet_tree_bytes()
        || leaf != payload.creator_leaf_authority
        || group
            .group_ciphersuite_canonical_id()
            .map_err(|error| MlsRuntimeError::Genesis(error.to_string()))?
            != payload.cipher_suite.as_str()
    {
        return Err(MlsRuntimeError::Genesis(
            "creator private MLS state differs from its frozen public unit".into(),
        ));
    }
    let raw = crate::mls::persistence::decrypt_envelope(&snapshot, checkpoint_secret)
        .map_err(|error| MlsRuntimeError::Genesis(error.to_string()))?;
    Ok((
        raw,
        InitialMlsCheckpointSummary {
            realm_id: snapshot.realm_id,
            group_id: snapshot.group_id,
            epoch: 0,
            group_info_bytes: group_info,
            ratchet_tree_bytes: tree,
            cipher_suite: group
                .group_ciphersuite_canonical_id()
                .map_err(|error| MlsRuntimeError::Genesis(error.to_string()))?
                .to_owned(),
            creator_leaf_authority: leaf,
        },
    ))
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
    initial_mls_checkpoint_summary_with_pinned_binding(
        state_store,
        secure_store,
        realm_id,
        circle_id,
        authority,
        device_id,
        sidecar_id,
        None,
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn initial_mls_checkpoint_summary_with_pinned_binding(
    state_store: &crate::state::LocalStateStore,
    secure_store: &dyn SecureKeyStore,
    realm_id: &str,
    circle_id: Option<&str>,
    authority: &arkret_sdk::AccountId,
    device_id: &arkret_sdk::DeviceId,
    sidecar_id: Option<arkret_sdk::SidecarId>,
    pinned_binding: Option<&arkret_sdk::MlsGovernanceBindingPayload>,
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
    let expected_binding = match pinned_binding {
        Some(binding) if binding.effective_scope() == &effective_scope => binding.clone(),
        Some(_) => {
            return Err(MlsRuntimeError::Genesis(
                EPOCH_ZERO_SNAPSHOT_GOVERNANCE_BINDING_MISMATCH.to_owned(),
            ));
        }
        None => crate::mls::governance_proof::genesis_binding(&effective_scope)
            .map_err(MlsRuntimeError::Genesis)?,
    };
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
    let public = arkret_sdk::mls::MlsPublicGroupTracker::from_external(
        &group_info_bytes,
        &ratchet_tree_bytes,
        &expected_group_id,
        0,
    )
    .map_err(|error| MlsRuntimeError::Genesis(error.to_string()))?;
    if public
        .governance_binding()
        .map_err(|error| MlsRuntimeError::Genesis(error.to_string()))?
        != expected_binding
    {
        return Err(MlsRuntimeError::Genesis(
            EPOCH_ZERO_SNAPSHOT_GOVERNANCE_BINDING_MISMATCH.to_owned(),
        ));
    }
    let creator_leaf_authority = creator_leaf_authority_from_group(&group, authority)?;
    if matches!(effective_scope, arkret_sdk::ScopeRef::Sidecar { .. })
        && creator_leaf_authority.endpoint
            != (arkret_sdk::MlsWelcomeRecipientEndpoint::Device {
                device_id: device_id.clone(),
            })
    {
        return Err(MlsRuntimeError::Genesis(
            "Sidecar epoch-zero material belongs to another creator device; use Welcome or recovery".into(),
        ));
    }
    Ok(Some(InitialMlsCheckpointSummary {
        realm_id: realm.to_owned(),
        group_id: group_id.as_str().to_owned(),
        epoch: group.epoch(),
        group_info_bytes,
        ratchet_tree_bytes,
        cipher_suite: arkret_sdk::ARKRET_MLS_CIPHERSUITE_CANONICAL_ID.to_owned(),
        creator_leaf_authority,
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
        creator_leaf_authority: summary.creator_leaf_authority.clone(),
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
