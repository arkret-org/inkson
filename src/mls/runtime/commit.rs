//! §5.6 self-preservation and forced-epoch-advance MLS commit logic.

use arkret_sdk::{AccountId, DeviceId};

use super::{
    MlsRuntimeError, canonical_mls_remove_membership_frontier, idle_self_update_jitter_passed,
    load_device_checkpoint_secret, should_force_epoch_advance,
};
use crate::secure_key_store::SecureKeyStore;

fn current_governance_binding_predecessor(
    group: &arkret_sdk::ArkretMlsGroup,
) -> Result<arkret_sdk::MlsGovernanceBindingPayload, MlsRuntimeError> {
    group
        .current_governance_binding()
        .map_err(|error| MlsRuntimeError::Commit(error.to_string()))?
        .ok_or_else(|| {
            MlsRuntimeError::Commit(
                "MLS commit requires the current governance binding predecessor".to_owned(),
            )
        })
}

/// Operator-forced MLS epoch rotation via a real
/// `self_update_commit`; the spec defines no `POST /_arkret/self/mls/rotate`
/// HTTP endpoint. Restores the Realm group
/// from the local snapshot, performs a self-update commit, and returns
/// the commit envelope plus the encrypted POST-commit snapshot. The
/// caller MUST submit the matching `ak.mls.commit` event and persist the
/// returned snapshot ONLY after the server accepts it (persist-on-accept,
/// same contract as the kanban encrypted-write path).
pub fn force_epoch_rotation_commit(
    state_store: &crate::state::LocalStateStore,
    secure_store: &dyn SecureKeyStore,
    realm_id: &str,
    authority: &AccountId,
    device_id: &DeviceId,
) -> Result<
    (
        arkret_sdk::MlsCommitEnvelope,
        crate::mls::persistence::MlsLocalCheckpointEnvelope,
        arkret_sdk::MlsGovernanceBindingPayload,
    ),
    MlsRuntimeError,
> {
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
) -> Result<
    (
        arkret_sdk::MlsCommitEnvelope,
        crate::mls::persistence::MlsLocalCheckpointEnvelope,
        arkret_sdk::MlsGovernanceBindingPayload,
    ),
    MlsRuntimeError,
> {
    let circle = circle_id
        .map(str::trim)
        .filter(|circle_id| !circle_id.is_empty());
    let snapshot = state_store
        .mls_checkpoint_for_effective_scope(realm_id, circle)
        .ok_or(MlsRuntimeError::MissingWelcome)?;
    let secret = load_device_checkpoint_secret(secure_store, authority, device_id)
        .map_err(MlsRuntimeError::DeviceSecret)?;
    // COR-04: bind the commit to the Seal-view epoch floor so a stale / rolled-back
    // local snapshot can't silently fork the group from an outdated epoch.
    let epoch_floor = super::seal_view_epoch_floor(state_store, realm_id);
    let mut group = crate::mls::persistence::restore_envelope(&snapshot, &secret, epoch_floor)
        .map_err(|err| MlsRuntimeError::CheckpointRestore(err.to_string()))?;
    let previous_governance_binding = current_governance_binding_predecessor(&group)?;
    let proof_request = crate::mls::governance_proof::proof_request(
        state_store,
        realm_id,
        circle,
        group.group_id(),
        group.epoch(),
        group.epoch().saturating_add(1),
        group
            .security_frontier_leaves()
            .map_err(|error| MlsRuntimeError::Commit(error.to_string()))?,
    )
    .map_err(MlsRuntimeError::Commit)?;
    let governance_binding =
        crate::mls::governance_proof::cached_verified_binding(state_store, &proof_request)
            .map_err(MlsRuntimeError::Commit)?;
    let commit_envelope = group
        .update_governance_binding(&governance_binding)
        .map_err(|err| MlsRuntimeError::Commit(err.to_string()))?;
    let post_state = group
        .export_state_record()
        .map_err(|err| MlsRuntimeError::Export(err.to_string()))?;
    let serialized_state = serde_json::to_vec(&post_state)
        .map_err(|err| MlsRuntimeError::Serialize(format!("MLS state record: {err}")))?;
    let mut salt = [0u8; 16];
    getrandom::fill(&mut salt).map_err(|err| MlsRuntimeError::Salt(err.to_string()))?;
    let new_envelope = crate::mls::persistence::encrypt_state(
        realm_id,
        &post_state.group_id,
        post_state.epoch,
        &serialized_state,
        &secret,
        &salt,
    );
    Ok((commit_envelope, new_envelope, previous_governance_binding))
}

pub(crate) fn build_mls_remove_members_commit_for_effective_scope_with_sidecar_binding(
    state_store: &crate::state::LocalStateStore,
    secure_store: &dyn SecureKeyStore,
    realm_id: &str,
    circle_id: Option<&str>,
    authority: &AccountId,
    device_id: &DeviceId,
    target_actor_ids: &[arkret_sdk::ActorId],
    revocation_membership_frontier: &[arkret_sdk::EventId],
    sidecar_binding: Option<arkret_sdk::SidecarMlsBinding>,
) -> Result<
    (
        arkret_sdk::MlsRemoveMemberResult,
        crate::mls::persistence::MlsLocalCheckpointEnvelope,
        arkret_sdk::MlsGovernanceBindingPayload,
    ),
    MlsRuntimeError,
> {
    canonical_mls_remove_membership_frontier(revocation_membership_frontier)?;
    if target_actor_ids.is_empty() {
        return Err(MlsRuntimeError::Commit(
            "MLS Remove commit requires at least one target actor".to_owned(),
        ));
    }
    let circle = circle_id
        .map(str::trim)
        .filter(|circle_id| !circle_id.is_empty());
    let realm = arkret_sdk::RealmId::new(realm_id.to_owned())
        .map_err(|error| MlsRuntimeError::Commit(format!("invalid Realm id: {error}")))?;
    let effective_scope = match sidecar_binding.as_ref() {
        Some(binding) => arkret_sdk::ScopeRef::Sidecar {
            realm_id: realm.clone(),
            sidecar_id: binding.sidecar_id.clone(),
        },
        None => match circle {
            Some(circle_id) => arkret_sdk::ScopeRef::Circle {
                realm_id: realm.clone(),
                circle_id: arkret_sdk::CircleId::new(circle_id.to_owned()).map_err(|error| {
                    MlsRuntimeError::Commit(format!("invalid Circle id: {error}"))
                })?,
            },
            None => arkret_sdk::ScopeRef::Realm { realm_id: realm },
        },
    };
    let snapshot = state_store
        .mls_checkpoint_for_scope(&effective_scope)
        .ok_or(MlsRuntimeError::MissingWelcome)?;
    let secret = load_device_checkpoint_secret(secure_store, authority, device_id)
        .map_err(MlsRuntimeError::DeviceSecret)?;
    // COR-04: bind the commit to the Seal-view epoch floor so a stale / rolled-back
    // local snapshot can't silently fork the group from an outdated epoch.
    let epoch_floor = super::seal_view_epoch_floor(state_store, realm_id);
    let mut group = crate::mls::persistence::restore_envelope(&snapshot, &secret, epoch_floor)
        .map_err(|err| MlsRuntimeError::CheckpointRestore(err.to_string()))?;
    let previous_governance_binding = current_governance_binding_predecessor(&group)?;
    let governance_binding = crate::mls::governance_proof::cached_verified_binding_for_transition(
        state_store,
        &effective_scope,
        group.group_id().as_str(),
        group.epoch(),
        group.epoch().saturating_add(1),
    )
    .map_err(MlsRuntimeError::Commit)?;
    if let Some(binding) = sidecar_binding.as_ref()
        && governance_binding.sidecar_binding() != Some(binding)
    {
        return Err(MlsRuntimeError::Commit(
            "verified Sidecar MLS binding differs from the accepted Sidecar view".to_owned(),
        ));
    }
    let remove = group
        .remove_members_by_actor_with_governance_binding(target_actor_ids, &governance_binding)
        .map_err(|err| MlsRuntimeError::Commit(err.to_string()))?;
    let post_state = group
        .export_state_record()
        .map_err(|err| MlsRuntimeError::Export(err.to_string()))?;
    let serialized_state = serde_json::to_vec(&post_state)
        .map_err(|err| MlsRuntimeError::Serialize(format!("MLS state record: {err}")))?;
    let mut salt = [0u8; 16];
    getrandom::fill(&mut salt).map_err(|err| MlsRuntimeError::Salt(err.to_string()))?;
    let new_envelope = crate::mls::persistence::encrypt_state(
        realm_id,
        &post_state.group_id,
        post_state.epoch,
        &serialized_state,
        &secret,
        &salt,
    );
    Ok((remove, new_envelope, previous_governance_binding))
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
) -> Result<
    (
        arkret_sdk::MlsAddMemberResult,
        crate::mls::persistence::MlsLocalCheckpointEnvelope,
        arkret_sdk::MlsGovernanceBindingPayload,
    ),
    MlsRuntimeError,
> {
    build_add_member_commit_for_effective_scope_with_binding(
        state_store,
        secure_store,
        realm_id,
        circle_id,
        authority,
        device_id,
        member_key_package,
        std::slice::from_ref(member_authority_hint),
        None,
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn build_add_member_commit_for_effective_scope_with_binding(
    state_store: &crate::state::LocalStateStore,
    secure_store: &dyn SecureKeyStore,
    realm_id: &str,
    circle_id: Option<&str>,
    authority: &AccountId,
    device_id: &DeviceId,
    member_key_package: &arkret_sdk::MlsKeyPackageRecord,
    member_authority_hints: &[crate::mls::governance_proof::MlsLeafAuthorityHint],
    sidecar_binding: Option<arkret_sdk::SidecarMlsBinding>,
) -> Result<
    (
        arkret_sdk::MlsAddMemberResult,
        crate::mls::persistence::MlsLocalCheckpointEnvelope,
        arkret_sdk::MlsGovernanceBindingPayload,
    ),
    MlsRuntimeError,
> {
    let circle = circle_id
        .map(str::trim)
        .filter(|circle_id| !circle_id.is_empty());
    let realm = arkret_sdk::RealmId::new(realm_id.to_owned())
        .map_err(|error| MlsRuntimeError::Commit(format!("invalid Realm id: {error}")))?;
    let effective_scope = match sidecar_binding.as_ref() {
        Some(binding) => arkret_sdk::ScopeRef::Sidecar {
            realm_id: realm.clone(),
            sidecar_id: binding.sidecar_id.clone(),
        },
        None => match circle {
            Some(circle_id) => arkret_sdk::ScopeRef::Circle {
                realm_id: realm.clone(),
                circle_id: arkret_sdk::CircleId::new(circle_id.to_owned()).map_err(|error| {
                    MlsRuntimeError::Commit(format!("invalid Circle id: {error}"))
                })?,
            },
            None => arkret_sdk::ScopeRef::Realm { realm_id: realm },
        },
    };
    let snapshot = state_store
        .mls_checkpoint_for_scope(&effective_scope)
        .ok_or(MlsRuntimeError::MissingWelcome)?;
    let secret = load_device_checkpoint_secret(secure_store, authority, device_id)
        .map_err(MlsRuntimeError::DeviceSecret)?;
    // COR-04: bind the commit to the Seal-view epoch floor so a stale / rolled-back
    // local snapshot can't silently fork the group from an outdated epoch.
    let epoch_floor = super::seal_view_epoch_floor(state_store, realm_id);
    let mut group = crate::mls::persistence::restore_envelope(&snapshot, &secret, epoch_floor)
        .map_err(|err| MlsRuntimeError::CheckpointRestore(err.to_string()))?;
    let previous_governance_binding = current_governance_binding_predecessor(&group)?;
    let governance_binding = crate::mls::governance_proof::cached_verified_binding_for_transition(
        state_store,
        &effective_scope,
        group.group_id().as_str(),
        group.epoch(),
        group.epoch().saturating_add(1),
    )
    .map_err(MlsRuntimeError::Commit)?;
    if let Some(binding) = sidecar_binding.as_ref()
        && governance_binding.sidecar_binding() != Some(binding)
    {
        return Err(MlsRuntimeError::Commit(
            "verified Sidecar MLS binding differs from the accepted Sidecar view".to_owned(),
        ));
    }
    let add = group
        .add_member_with_governance_binding(member_key_package, &governance_binding)
        .map_err(|err| MlsRuntimeError::Commit(err.to_string()))?;
    crate::mls::governance_proof::install_cached_transition_leaf_bindings_with_hints(
        state_store,
        &mut group,
        &governance_binding,
        member_authority_hints,
    )
    .map_err(MlsRuntimeError::Commit)?;
    let post_state = group
        .export_state_record()
        .map_err(|err| MlsRuntimeError::Export(err.to_string()))?;
    let serialized_state = serde_json::to_vec(&post_state)
        .map_err(|err| MlsRuntimeError::Serialize(format!("MLS state record: {err}")))?;
    let mut salt = [0u8; 16];
    getrandom::fill(&mut salt).map_err(|err| MlsRuntimeError::Salt(err.to_string()))?;
    let new_envelope = crate::mls::persistence::encrypt_state(
        realm_id,
        &post_state.group_id,
        post_state.epoch,
        &serialized_state,
        &secret,
        &salt,
    );
    Ok((add, new_envelope, previous_governance_binding))
}

/// `encryption-and-audit.md` §5.6 — non-send (idle / receive-only) trigger of
/// the self-preservation Commit. Mirrors [`force_epoch_rotation_commit`]'s
/// `self_update_commit` build but is GATED by the §5.6 SHOULD conditions so a
/// background driver can drive it for every persisted Realm without a send:
///
/// 1. [`should_force_epoch_advance`] — epoch over the §5.6 floor (≥1000 msgs OR ≥7 days for a
///    normal Realm; the §2.9 ≤1h MUST for minimal-metadata), with the normative pending-commit
///    suppression already folded in;
/// 2. [`idle_self_update_jitter_passed`] — this member's deterministic member-order jitter slot has
///    opened (skipped for minimal-metadata, whose 1h MUST leaves no room for staggered delay).
///
/// Returns `Ok(None)` when not yet due (the common case — most idle passes do
/// nothing), or `Ok(Some((commit, snapshot)))` when the caller SHOULD submit
/// the `ak.mls.commit` and, on server-accept, persist the snapshot
/// (persist-on-accept, identical contract to the send path and
/// [`force_epoch_rotation_commit`]).
///
/// Soft failures match the send path: a missing snapshot / device secret is
/// surfaced as a typed error, NOT silently swallowed, so the driver can log
/// once and move on without advancing local state.
pub fn build_idle_self_update_commit(
    state_store: &crate::state::LocalStateStore,
    secure_store: &dyn SecureKeyStore,
    realm_id: &str,
    authority: &AccountId,
    actor_id: &str,
    device_id: &DeviceId,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<
    Option<(
        arkret_sdk::MlsCommitEnvelope,
        crate::mls::persistence::MlsLocalCheckpointEnvelope,
        arkret_sdk::MlsGovernanceBindingPayload,
    )>,
    MlsRuntimeError,
> {
    let snapshot = state_store
        .mls_checkpoint_for(realm_id)
        .ok_or(MlsRuntimeError::MissingWelcome)?;
    let is_minimal_metadata = state_store.realm_projection_is_minimal_metadata(realm_id);
    // §5.6 floor + normative pending-commit suppression (shared with the send
    // path so the two triggers can never disagree about "is a commit due").
    if !should_force_epoch_advance(
        is_minimal_metadata,
        snapshot.epoch_started_at,
        now,
        snapshot.app_messages_observed,
        state_store.realm_has_pending_mls_binding(realm_id),
    ) {
        return Ok(None);
    }
    // Deterministic member-order jitter (§5.6 SHOULD). Minimal-metadata's ≤1h
    // MUST leaves no slack for staggering, so it commits as soon as overdue.
    if !is_minimal_metadata
        && !idle_self_update_jitter_passed(
            &snapshot.group_id,
            snapshot.epoch,
            actor_id,
            snapshot.epoch_started_at,
            now,
        )
    {
        return Ok(None);
    }
    let secret = load_device_checkpoint_secret(secure_store, authority, device_id)
        .map_err(MlsRuntimeError::DeviceSecret)?;
    // COR-04: bind the commit to the Seal-view epoch floor so a stale / rolled-back
    // local snapshot can't silently fork the group from an outdated epoch.
    let epoch_floor = super::seal_view_epoch_floor(state_store, realm_id);
    let mut group = crate::mls::persistence::restore_envelope(&snapshot, &secret, epoch_floor)
        .map_err(|err| MlsRuntimeError::CheckpointRestore(err.to_string()))?;
    let previous_governance_binding = current_governance_binding_predecessor(&group)?;
    let commit_envelope = group
        .self_update_commit()
        .map_err(|err| MlsRuntimeError::Commit(err.to_string()))?;
    let post_state = group
        .export_state_record()
        .map_err(|err| MlsRuntimeError::Export(err.to_string()))?;
    let serialized_state = serde_json::to_vec(&post_state)
        .map_err(|err| MlsRuntimeError::Serialize(format!("MLS state record: {err}")))?;
    let mut salt = [0u8; 16];
    getrandom::fill(&mut salt).map_err(|err| MlsRuntimeError::Salt(err.to_string()))?;
    // Forced epoch advance ⇒ a fresh epoch with the §5.6 counter reset to 0
    // (no application message has ridden the new epoch yet). epoch_started_at
    // is NOT carried — `encrypt_state` stamps it to the snapshot's recorded_at,
    // which is correct for a brand-new epoch.
    let new_envelope = crate::mls::persistence::encrypt_state(
        realm_id,
        &post_state.group_id,
        post_state.epoch,
        &serialized_state,
        &secret,
        &salt,
    )
    .with_app_messages_observed(0);
    Ok(Some((
        commit_envelope,
        new_envelope,
        previous_governance_binding,
    )))
}
