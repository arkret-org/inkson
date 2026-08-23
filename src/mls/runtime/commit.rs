//! §5.6 self-preservation and forced-epoch-advance MLS commit logic.

use arkret_sdk::{DeviceId, PrincipalAuthorityKey};

use super::{MlsRuntimeError, load_device_snapshot_secret};
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

/// YOU-01-009 — operator-forced MLS epoch rotation via a real
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
    authority: &PrincipalAuthorityKey,
    device_id: &DeviceId,
) -> Result<
    (
        arkret_sdk::MlsCommitEnvelope,
        crate::mls::persistence::MlsSnapshotEnvelope,
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
    authority: &PrincipalAuthorityKey,
    device_id: &DeviceId,
) -> Result<
    (
        arkret_sdk::MlsCommitEnvelope,
        crate::mls::persistence::MlsSnapshotEnvelope,
        arkret_sdk::MlsGovernanceBindingPayload,
    ),
    MlsRuntimeError,
> {
    let circle = circle_id
        .map(str::trim)
        .filter(|circle_id| !circle_id.is_empty());
    let snapshot = state_store
        .mls_snapshot_for_effective_scope(realm_id, circle)
        .ok_or(MlsRuntimeError::MissingWelcome)?;
    let secret = load_device_snapshot_secret(secure_store, authority, device_id)
        .map_err(MlsRuntimeError::DeviceSecret)?;
    // COR-04: bind the commit to the Seal-view epoch floor so a stale / rolled-back
    // local snapshot can't silently fork the group from an outdated epoch.
    let epoch_floor = super::seal_view_epoch_floor(state_store, realm_id);
    let mut group = crate::mls::persistence::restore_envelope(&snapshot, &secret, epoch_floor)
        .map_err(|err| MlsRuntimeError::SnapshotRestore(err.to_string()))?;
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
    authority: &PrincipalAuthorityKey,
    device_id: &DeviceId,
    target_principal_ids: &[&str],
    revocation_membership_frontier: &[arkret_sdk::EventId],
    sidecar_binding: Option<arkret_sdk::SidecarMlsBinding>,
) -> Result<
    (
        arkret_sdk::MlsRemoveMemberResult,
        crate::mls::persistence::MlsSnapshotEnvelope,
        arkret_sdk::MlsGovernanceBindingPayload,
    ),
    MlsRuntimeError,
> {
    canonical_mls_remove_membership_frontier(revocation_membership_frontier)?;
    if target_principal_ids.is_empty() {
        return Err(MlsRuntimeError::Commit(
            "MLS Remove commit requires at least one target principal".to_owned(),
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
        .mls_snapshot_for_scope(&effective_scope)
        .ok_or(MlsRuntimeError::MissingWelcome)?;
    let secret = load_device_snapshot_secret(secure_store, authority, device_id)
        .map_err(MlsRuntimeError::DeviceSecret)?;
    let targets: Vec<arkret_sdk::DidCoreId> = target_principal_ids
        .iter()
        .map(|target| {
            crate::mls_api_helpers::principal_core_id(target)
                .map_err(|err| MlsRuntimeError::Identity(format!("{err:?}")))
        })
        .collect::<Result<_, _>>()?;
    // COR-04: bind the commit to the Seal-view epoch floor so a stale / rolled-back
    // local snapshot can't silently fork the group from an outdated epoch.
    let epoch_floor = super::seal_view_epoch_floor(state_store, realm_id);
    let mut group = crate::mls::persistence::restore_envelope(&snapshot, &secret, epoch_floor)
        .map_err(|err| MlsRuntimeError::SnapshotRestore(err.to_string()))?;
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
        .remove_members_by_principal_with_governance_binding(&targets, &governance_binding)
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

/// Canonicalize the governance frontier required for an MLS Remove commit.
///
/// The caller must pass the accepted `ak.device.revoke` event id or the
/// Realm/Circle governance Control Move that imported that revocation. This
/// helper deliberately does not fall back to `LocalSealView.frontier` or
/// `leaves`: those sets are useful for ordinary commit freshness but are not
/// proof that this Remove covers the specific revocation that triggered it.
pub fn canonical_mls_remove_membership_frontier(
    revocation_membership_frontier: &[arkret_sdk::EventId],
) -> Result<Vec<arkret_sdk::EventId>, MlsRuntimeError> {
    if revocation_membership_frontier.is_empty() {
        return Err(MlsRuntimeError::Commit(
            "MLS Remove governance binding requires the accepted ak.device.revoke event \
             or imported revocation Control Move frontier"
                .to_owned(),
        ));
    }
    let mut frontier = revocation_membership_frontier.to_vec();
    frontier.sort();
    frontier.dedup();
    Ok(frontier)
}

pub fn build_add_member_commit_for_effective_scope(
    state_store: &crate::state::LocalStateStore,
    secure_store: &dyn SecureKeyStore,
    realm_id: &str,
    circle_id: Option<&str>,
    authority: &PrincipalAuthorityKey,
    device_id: &DeviceId,
    member_key_package: &arkret_sdk::MlsKeyPackageRecord,
) -> Result<
    (
        arkret_sdk::MlsAddMemberResult,
        crate::mls::persistence::MlsSnapshotEnvelope,
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
        None,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn build_add_member_commit_for_effective_scope_with_binding(
    state_store: &crate::state::LocalStateStore,
    secure_store: &dyn SecureKeyStore,
    realm_id: &str,
    circle_id: Option<&str>,
    authority: &PrincipalAuthorityKey,
    device_id: &DeviceId,
    member_key_package: &arkret_sdk::MlsKeyPackageRecord,
    sidecar_binding: Option<arkret_sdk::SidecarMlsBinding>,
) -> Result<
    (
        arkret_sdk::MlsAddMemberResult,
        crate::mls::persistence::MlsSnapshotEnvelope,
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
        .mls_snapshot_for_scope(&effective_scope)
        .ok_or(MlsRuntimeError::MissingWelcome)?;
    let secret = load_device_snapshot_secret(secure_store, authority, device_id)
        .map_err(MlsRuntimeError::DeviceSecret)?;
    // COR-04: bind the commit to the Seal-view epoch floor so a stale / rolled-back
    // local snapshot can't silently fork the group from an outdated epoch.
    let epoch_floor = super::seal_view_epoch_floor(state_store, realm_id);
    let mut group = crate::mls::persistence::restore_envelope(&snapshot, &secret, epoch_floor)
        .map_err(|err| MlsRuntimeError::SnapshotRestore(err.to_string()))?;
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

#[allow(clippy::too_many_arguments)]
pub fn build_add_members_commit_for_effective_scope_with_binding(
    state_store: &crate::state::LocalStateStore,
    secure_store: &dyn SecureKeyStore,
    realm_id: &str,
    circle_id: Option<&str>,
    authority: &PrincipalAuthorityKey,
    device_id: &DeviceId,
    member_key_packages: &[arkret_sdk::MlsKeyPackageRecord],
    sidecar_binding: Option<arkret_sdk::SidecarMlsBinding>,
) -> Result<
    (
        arkret_sdk::MlsAddMembersResult,
        crate::mls::persistence::MlsSnapshotEnvelope,
        arkret_sdk::MlsGovernanceBindingPayload,
    ),
    MlsRuntimeError,
> {
    if member_key_packages.is_empty() {
        return Err(MlsRuntimeError::Commit(
            "MLS Add commit requires at least one KeyPackage".to_owned(),
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
        .mls_snapshot_for_scope(&effective_scope)
        .ok_or(MlsRuntimeError::MissingWelcome)?;
    let secret = load_device_snapshot_secret(secure_store, authority, device_id)
        .map_err(MlsRuntimeError::DeviceSecret)?;
    // COR-04: bind the commit to the Seal-view epoch floor so a stale / rolled-back
    // local snapshot can't silently fork the group from an outdated epoch.
    let epoch_floor = super::seal_view_epoch_floor(state_store, realm_id);
    let mut group = crate::mls::persistence::restore_envelope(&snapshot, &secret, epoch_floor)
        .map_err(|err| MlsRuntimeError::SnapshotRestore(err.to_string()))?;
    let previous_governance_binding = current_governance_binding_predecessor(&group)?;
    let governance_binding = crate::mls::governance_proof::cached_verified_binding_for_transition(
        state_store,
        &effective_scope,
        group.group_id().as_str(),
        group.epoch(),
        group.epoch().saturating_add(1),
    )
    .map_err(MlsRuntimeError::Commit)?;
    let governance_binding = match sidecar_binding {
        Some(binding) => {
            crate::mls::governance_proof::bind_sidecar_scope(&governance_binding, binding.clone())
                .map_err(|error| MlsRuntimeError::Commit(error.to_string()))?
        }
        None => governance_binding,
    };
    let add = group
        .add_members_with_governance_binding(member_key_packages, &governance_binding)
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
    Ok((add, new_envelope, previous_governance_binding))
}

/// YOU-02-004 (`encryption-and-audit.md` §5.6, normative) — decrypt a remote
/// member's MLS application message AND persist the advanced receive chain.
///
/// "first duty: persist the receive chain": after a successful decrypt the advanced group
/// state (including OpenMLS's bounded skipped-message-key cache) MUST be
/// persisted so the next decrypt never replays the ratchet from an earlier
/// snapshot. Because persisting consumes the per-message ratchet key, the
/// decrypted plaintext is simultaneously cached (keyed by the envelope's
/// canonical `payload_digest`) and re-renders are served from that cache.
///
/// Strand:
///   1. plaintext-cache hit → return without touching MLS state;
///   2. otherwise, under the store's decrypt serialization guard: restore the latest snapshot →
///      `decrypt_payload` → export the advanced state →
///      [`LocalStateStore::advance_mls_receive_chain`] (persists snapshot + plaintext atomically
///      with respect to readers).
///
/// Soft failures (no snapshot, missing device secret, author's own
/// ciphertext — which OpenMLS rejects before advancing any ratchet — or an
/// undecryptable payload) return `None` and leave persisted state untouched.
/// `encryption-and-audit.md` §5.6 — deterministic per-member jitter window
/// (whole hours) over which a large group spreads its self-preservation
/// commits. The spec's example is "hash by member order to assign delay": each eligible
/// committer maps to a stable slot in `[0, JITTER_SLOTS)` derived from
/// `hash(group_id, base_epoch, own_principal_did)`; a member only emits its
/// idle self-update once the epoch has aged past `slot` extra hours beyond the
/// §5.6 trigger floor. With pending-commit suppression (normative) the first
/// member to land its commit advances the epoch and resets every other
/// member's counter/timer, so later slots almost never fire — exactly the goal
/// of preventing large groups from emitting commits simultaneously at the threshold.
pub const SELF_PRESERVATION_JITTER_SLOTS: u64 = 24;

/// §5.6 deterministic jitter — has THIS member's slot opened yet?
///
/// `slot = hash(group_id ‖ base_epoch ‖ own_principal_did) mod
/// SELF_PRESERVATION_JITTER_SLOTS`. The member is cleared to emit once the
/// epoch has lived at least `slot` whole hours *beyond* the moment the §5.6
/// floor ([`should_force_epoch_advance`]) was crossed. We approximate "beyond
/// the floor" with epoch age, which is exact for the age-based trigger and a
/// safe over-delay for the message-count trigger (count-based floors only ever
/// add latency here, never skip the commit, because suppression + the next
/// idle pass re-evaluate). Binding `base_epoch` means the slot reshuffles every
/// epoch, so the same member doesn't always draw the long straw. Member order
/// (the principal-DID set) is read from the live group, matching the spec's
/// "member order".
pub fn idle_self_update_jitter_passed(
    group_id: &str,
    base_epoch: u64,
    own_principal_did: &str,
    epoch_started_at: chrono::DateTime<chrono::Utc>,
    now: chrono::DateTime<chrono::Utc>,
) -> bool {
    use std::hash::{Hash as _, Hasher as _};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    group_id.hash(&mut hasher);
    base_epoch.hash(&mut hasher);
    own_principal_did.hash(&mut hasher);
    let slot = hasher.finish() % SELF_PRESERVATION_JITTER_SLOTS;
    let elapsed = now.signed_duration_since(epoch_started_at);
    // Clock skew (now < epoch_started_at) reads as "no slot open yet"; the
    // committer simply waits, fail-safe identical to should_force_epoch_advance.
    elapsed >= chrono::Duration::hours(slot as i64)
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
    authority: &PrincipalAuthorityKey,
    actor_id: &str,
    device_id: &DeviceId,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<
    Option<(
        arkret_sdk::MlsCommitEnvelope,
        crate::mls::persistence::MlsSnapshotEnvelope,
        arkret_sdk::MlsGovernanceBindingPayload,
    )>,
    MlsRuntimeError,
> {
    let snapshot = state_store
        .mls_snapshot_for(realm_id)
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
    let secret = load_device_snapshot_secret(secure_store, authority, device_id)
        .map_err(MlsRuntimeError::DeviceSecret)?;
    // COR-04: bind the commit to the Seal-view epoch floor so a stale / rolled-back
    // local snapshot can't silently fork the group from an outdated epoch.
    let epoch_floor = super::seal_view_epoch_floor(state_store, realm_id);
    let mut group = crate::mls::persistence::restore_envelope(&snapshot, &secret, epoch_floor)
        .map_err(|err| MlsRuntimeError::SnapshotRestore(err.to_string()))?;
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

/// `encryption-and-audit.md` §5.6 — normal-Realm self-preservation commit
/// SHOULD trigger: epoch has observed at least 1000 application messages
/// (implementations MAY declare a lower threshold).
pub const SELF_PRESERVATION_MAX_EPOCH_APP_MESSAGES: u64 = 1000;
/// §5.6 — normal-Realm self-preservation commit SHOULD trigger: epoch age is
/// at least 7 days (implementations MAY declare a shorter threshold).
pub const SELF_PRESERVATION_MAX_EPOCH_AGE_DAYS: i64 = 7;

/// SEC-08 (§2.9) + YOU-02-004 (§5.6) — pure committer decision: should a
/// send force-advance the MLS epoch *before* riding the current epoch?
///
/// For a `minimal_metadata_realm` Realm the §2.9 epoch-lifetime SHOULD is a
/// MUST of ≤1h (delegated to the SDK's
/// [`arkret_sdk::minimal_metadata_epoch_overdue`], which never reports clock
/// skew as overdue).
///
/// For a normal Realm this implements the §5.6 self-preservation SHOULD: a
/// self-update Commit is due once the current epoch has observed ≥ 1000
/// application messages OR has lived ≥ 7 days. §5.6 duplicate commit suppression
/// (normative): when a pending `ak.mls.commit` for this scope is already in
/// flight (`has_pending_commit`), a new self-preservation commit MUST NOT be
/// initiated — the pending commit will achieve the same epoch advance.
/// Clock skew (`now < epoch_started_at`) never reads as overdue.
pub fn should_force_epoch_advance(
    is_minimal_metadata: bool,
    epoch_started_at: chrono::DateTime<chrono::Utc>,
    now: chrono::DateTime<chrono::Utc>,
    app_messages_observed: u64,
    has_pending_commit: bool,
) -> bool {
    if is_minimal_metadata {
        // §2.9 MUST ≤1h — kept independent of the pending-commit suppression
        // so the stricter profile's fail-safe direction is preserved.
        return arkret_sdk::minimal_metadata_epoch_overdue(epoch_started_at, now);
    }
    if has_pending_commit {
        return false;
    }
    if app_messages_observed >= SELF_PRESERVATION_MAX_EPOCH_APP_MESSAGES {
        return true;
    }
    now.signed_duration_since(epoch_started_at)
        >= chrono::Duration::days(SELF_PRESERVATION_MAX_EPOCH_AGE_DAYS)
}
