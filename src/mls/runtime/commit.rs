//! Self-preservation and forced-epoch-advance MLS commit construction.
//!
//! Every builder here stages a commit against the device's installed group and
//! returns the wire `MlsCommitEnvelope` together with the encrypted staged
//! state. The commit is not merged while authoring: OpenMLS keeps it pending,
//! and it becomes this device's epoch only when
//! `ArkretMlsGroup::install_accepted_commit` merges it after the governance
//! Station has committed the `ak.mls.commit` Event into the scope's own stream.
//! Persisting the staged state is therefore mandatory, not optional: a restart
//! between authoring and acceptance must still be able to merge the accepted
//! commit.

use arkret_sdk::{AccountId, DeviceId};

use super::{
    MlsRuntimeError, idle_self_update_jitter_passed, load_device_checkpoint_secret,
    should_force_epoch_advance,
};
use crate::secure_key_store::SecureKeyStore;

/// The staged result of one authored MLS transition.
pub struct StagedMlsCommit {
    /// The wire Commit the `ak.mls.commit` Event carries.
    pub envelope: arkret_sdk::MlsCommitEnvelope,
    /// The encrypted group state holding the pending commit, persisted before
    /// submission so acceptance can always be merged.
    pub staged_checkpoint: crate::mls::persistence::MlsLocalCheckpointEnvelope,
}

fn staged_checkpoint(
    group: &arkret_sdk::ArkretMlsGroup,
    realm_id: &str,
    secret: &str,
) -> Result<crate::mls::persistence::MlsLocalCheckpointEnvelope, MlsRuntimeError> {
    let post_state = group
        .export_state_record()
        .map_err(|err| MlsRuntimeError::Export(err.to_string()))?;
    let serialized_state = serde_json::to_vec(&post_state)
        .map_err(|err| MlsRuntimeError::Serialize(format!("MLS state record: {err}")))?;
    let mut salt = [0_u8; 16];
    getrandom::fill(&mut salt)
        .map_err(|err| MlsRuntimeError::Commit(format!("MLS checkpoint salt: {err}")))?;
    Ok(crate::mls::persistence::encrypt_state(
        realm_id,
        &post_state.group_id,
        post_state.epoch,
        &serialized_state,
        secret,
        &salt,
    ))
}

fn restore_for_commit(
    state_store: &crate::state::LocalStateStore,
    secure_store: &dyn SecureKeyStore,
    effective_scope: &arkret_sdk::ScopeRef,
    realm_id: &str,
    authority: &AccountId,
    device_id: &DeviceId,
) -> Result<(arkret_sdk::ArkretMlsGroup, String), MlsRuntimeError> {
    super::reject_retired_minimal_metadata_realm(state_store, realm_id)?;
    let snapshot = state_store
        .mls_checkpoint_for_scope(effective_scope)
        .ok_or(MlsRuntimeError::MissingWelcome)?;
    let secret = load_device_checkpoint_secret(secure_store, authority, device_id)
        .map_err(MlsRuntimeError::DeviceSecret)?;
    // Bind the commit to the accepted epoch floor so a stale or rolled-back
    // local checkpoint cannot silently fork the group from an outdated epoch.
    let epoch_floor = super::accepted_mls_epoch_floor_for_scope(state_store, effective_scope);
    let group = crate::mls::persistence::restore_envelope(&snapshot, &secret, epoch_floor)
        .map_err(|err| MlsRuntimeError::CheckpointRestore(err.to_string()))?;
    Ok((group, secret))
}

fn scope_for(
    realm_id: &str,
    circle_id: Option<&str>,
    sidecar_id: Option<&arkret_sdk::SidecarId>,
) -> Result<arkret_sdk::ScopeRef, MlsRuntimeError> {
    let realm = arkret_sdk::RealmId::new(realm_id.to_owned())
        .map_err(|error| MlsRuntimeError::Commit(format!("invalid Realm id: {error}")))?;
    if let Some(sidecar_id) = sidecar_id {
        return Ok(arkret_sdk::ScopeRef::Sidecar {
            realm_id: realm,
            sidecar_id: sidecar_id.clone(),
        });
    }
    match circle_id.map(str::trim).filter(|value| !value.is_empty()) {
        Some(circle_id) => Ok(arkret_sdk::ScopeRef::Circle {
            realm_id: realm,
            circle_id: arkret_sdk::CircleId::new(circle_id.to_owned())
                .map_err(|error| MlsRuntimeError::Commit(format!("invalid Circle id: {error}")))?,
        }),
        None => Ok(arkret_sdk::ScopeRef::Realm { realm_id: realm }),
    }
}

/// Operator-forced MLS epoch rotation through a real `self_update_commit`.
///
/// The caller MUST submit the matching `ak.mls.commit` and install the staged
/// state only after the Station accepts it.
pub fn force_epoch_rotation_commit(
    state_store: &crate::state::LocalStateStore,
    secure_store: &dyn SecureKeyStore,
    realm_id: &str,
    authority: &AccountId,
    device_id: &DeviceId,
) -> Result<StagedMlsCommit, MlsRuntimeError> {
    force_epoch_rotation_commit_for_effective_scope(
        state_store,
        secure_store,
        realm_id,
        None,
        authority,
        device_id,
    )
}

pub fn force_epoch_rotation_commit_for_effective_scope(
    state_store: &crate::state::LocalStateStore,
    secure_store: &dyn SecureKeyStore,
    realm_id: &str,
    circle_id: Option<&str>,
    authority: &AccountId,
    device_id: &DeviceId,
) -> Result<StagedMlsCommit, MlsRuntimeError> {
    let effective_scope = scope_for(realm_id, circle_id, None)?;
    let (mut group, secret) = restore_for_commit(
        state_store,
        secure_store,
        &effective_scope,
        realm_id,
        authority,
        device_id,
    )?;
    let governance_binding = crate::mls::governance_proof::binding_for_transition(
        state_store,
        &effective_scope,
        &group.group_id(),
        group.epoch(),
        group.epoch().saturating_add(1),
    )
    .map_err(MlsRuntimeError::Commit)?;
    let envelope = group
        .self_update_commit_with_governance_binding(&governance_binding)
        .map_err(|err| MlsRuntimeError::Commit(err.to_string()))?;
    let staged_checkpoint = staged_checkpoint(&group, realm_id, &secret)?;
    Ok(StagedMlsCommit {
        envelope,
        staged_checkpoint,
    })
}

/// Stage the removal of every leaf belonging to `targets`.
///
/// The removal set is decided locally from the group's own verified leaf
/// bindings: the client removes every leaf of every target actor, and the SDK
/// refuses a target with no leaf, so a partial rotation cannot be committed.
pub(crate) fn build_mls_remove_actors_commit_for_scope(
    state_store: &crate::state::LocalStateStore,
    secure_store: &dyn SecureKeyStore,
    effective_scope: &arkret_sdk::ScopeRef,
    authority: &AccountId,
    device_id: &DeviceId,
    frozen: &crate::circle_mls::MembershipRemovalSnapshot,
) -> Result<(arkret_sdk::MlsRemoveMemberResult, StagedMlsCommit), MlsRuntimeError> {
    frozen
        .ensure_current(state_store)
        .map_err(MlsRuntimeError::Commit)?;
    if &frozen.effective_scope != effective_scope {
        return Err(MlsRuntimeError::Commit(
            "MLS removal scope changed".to_owned(),
        ));
    }
    let realm_id = effective_scope
        .realm_id_opt()
        .ok_or_else(|| MlsRuntimeError::Commit("MLS removal has no Realm scope".to_owned()))?
        .as_str()
        .to_owned();
    let (mut group, secret) = restore_for_commit(
        state_store,
        secure_store,
        effective_scope,
        &realm_id,
        authority,
        device_id,
    )?;
    if group.group_id().as_str() != frozen.mls_group_id || group.epoch() != frozen.epoch {
        return Err(MlsRuntimeError::Commit(
            "MLS removal base group or epoch changed".to_owned(),
        ));
    }
    let governance_binding = crate::mls::governance_proof::binding_for_transition(
        state_store,
        effective_scope,
        &group.group_id(),
        group.epoch(),
        group.epoch().saturating_add(1),
    )
    .map_err(MlsRuntimeError::Commit)?;
    let remove = group
        .remove_members_by_actor_with_governance_binding(&frozen.targets, &governance_binding)
        .map_err(|err| MlsRuntimeError::Commit(err.to_string()))?;
    let envelope = remove.commit.clone();
    let staged_checkpoint = staged_checkpoint(&group, &realm_id, &secret)?;
    Ok((
        remove,
        StagedMlsCommit {
            envelope,
            staged_checkpoint,
        },
    ))
}

pub(crate) fn build_add_member_commit_for_effective_scope(
    state_store: &crate::state::LocalStateStore,
    secure_store: &dyn SecureKeyStore,
    realm_id: &str,
    circle_id: Option<&str>,
    authority: &AccountId,
    device_id: &DeviceId,
    member_key_package: &arkret_sdk::MlsKeyPackageRecord,
    member_authority_hint: &crate::mls::governance_proof::MlsLeafAuthorityHint,
) -> Result<(arkret_sdk::MlsAddMemberResult, StagedMlsCommit), MlsRuntimeError> {
    build_add_member_commit_for_scope(
        state_store,
        secure_store,
        &scope_for(realm_id, circle_id, None)?,
        authority,
        device_id,
        member_key_package,
        std::slice::from_ref(member_authority_hint),
        None,
    )
}

/// Stage the addition of one claimed KeyPackage endpoint.
///
/// `member_authority_hints` carry the checked claim evidence for the leaf this
/// Add occupies; without them the post-transition attribution cannot be
/// installed and the commit fails closed rather than shipping a group whose
/// roster reads are refused.
#[allow(clippy::too_many_arguments)]
pub(crate) fn build_add_member_commit_for_scope(
    state_store: &crate::state::LocalStateStore,
    secure_store: &dyn SecureKeyStore,
    effective_scope: &arkret_sdk::ScopeRef,
    authority: &AccountId,
    device_id: &DeviceId,
    member_key_package: &arkret_sdk::MlsKeyPackageRecord,
    member_authority_hints: &[crate::mls::governance_proof::MlsLeafAuthorityHint],
    member_actor_id: Option<&arkret_sdk::ActorId>,
) -> Result<(arkret_sdk::MlsAddMemberResult, StagedMlsCommit), MlsRuntimeError> {
    let realm_id = effective_scope
        .realm_id_opt()
        .ok_or_else(|| MlsRuntimeError::Commit("MLS Add has no Realm scope".to_owned()))?
        .as_str()
        .to_owned();
    let (mut group, secret) = restore_for_commit(
        state_store,
        secure_store,
        effective_scope,
        &realm_id,
        authority,
        device_id,
    )?;
    let governance_binding = crate::mls::governance_proof::binding_for_transition(
        state_store,
        effective_scope,
        &group.group_id(),
        group.epoch(),
        group.epoch().saturating_add(1),
    )
    .map_err(MlsRuntimeError::Commit)?;
    // A Direct Conversation has exactly two members, so a new endpoint of an
    // actor already in the group replaces that actor's leaf instead of adding
    // a third one.
    let replacement_actor = (state_store.realm_collaboration_role(&realm_id)
        == Some(arkret_sdk::CollaborationRealmRole::DirectConversation))
    .then(|| {
        group.verified_leaf_bindings().ok().and_then(|leaves| {
            leaves
                .into_iter()
                .find(|leaf| leaf.endpoint == member_key_package.endpoint)
                .map(|leaf| leaf.actor_id)
        })
    })
    .flatten();
    let add = if let Some(actor) = replacement_actor {
        group.replace_member_endpoint(member_key_package, &actor, Some(&governance_binding))
    } else {
        group.add_member_with_governance_binding(member_key_package, &governance_binding)
    }
    .map_err(|err| MlsRuntimeError::Commit(err.to_string()))?;
    let staged_checkpoint = staged_checkpoint(&group, &realm_id, &secret)?;
    // The added leaf only becomes attributable once the accepted Commit is
    // merged, so the attribution inputs are validated here and reapplied by the
    // install path.
    if member_authority_hints.is_empty() {
        return Err(MlsRuntimeError::Commit(
            "MLS Add requires verified claim evidence for the added leaf".to_owned(),
        ));
    }
    let _ = member_actor_id;
    let envelope = add.commit.clone();
    Ok((
        add,
        StagedMlsCommit {
            envelope,
            staged_checkpoint,
        },
    ))
}

/// Non-send (idle / receive-only) trigger of the self-preservation Commit.
///
/// Gated by the same two conditions the send path uses:
///
/// 1. [`should_force_epoch_advance`] — the epoch is over the floor, with the normative
///    pending-commit suppression already folded in;
/// 2. [`idle_self_update_jitter_passed`] — this member's deterministic member-order jitter slot has
///    opened.
///
/// Returns `Ok(None)` when not yet due, which is the common case.
pub fn build_idle_self_update_commit(
    state_store: &crate::state::LocalStateStore,
    secure_store: &dyn SecureKeyStore,
    realm_id: &str,
    authority: &AccountId,
    actor_id: &str,
    device_id: &DeviceId,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<Option<StagedMlsCommit>, MlsRuntimeError> {
    super::reject_retired_minimal_metadata_realm(state_store, realm_id)?;
    let snapshot = state_store
        .mls_checkpoint_for(realm_id)
        .ok_or(MlsRuntimeError::MissingWelcome)?;
    if !should_force_epoch_advance(
        snapshot.epoch_started_at,
        now,
        snapshot.app_messages_observed,
        state_store.realm_has_pending_mls_binding(realm_id),
    ) {
        return Ok(None);
    }
    if !idle_self_update_jitter_passed(
        &snapshot.group_id,
        snapshot.epoch,
        actor_id,
        snapshot.epoch_started_at,
        now,
    ) {
        return Ok(None);
    }
    let effective_scope = scope_for(realm_id, None, None)?;
    let (mut group, secret) = restore_for_commit(
        state_store,
        secure_store,
        &effective_scope,
        realm_id,
        authority,
        device_id,
    )?;
    let governance_binding = crate::mls::governance_proof::binding_for_transition(
        state_store,
        &effective_scope,
        &group.group_id(),
        group.epoch(),
        group.epoch().saturating_add(1),
    )
    .map_err(MlsRuntimeError::Commit)?;
    let envelope = group
        .self_update_commit_with_governance_binding(&governance_binding)
        .map_err(|err| MlsRuntimeError::Commit(err.to_string()))?;
    // A forced epoch advance starts a fresh epoch, so the observed-message
    // counter resets: no application message has ridden the new epoch yet.
    let staged_checkpoint =
        staged_checkpoint(&group, realm_id, &secret)?.with_app_messages_observed(0);
    Ok(Some(StagedMlsCommit {
        envelope,
        staged_checkpoint,
    }))
}
