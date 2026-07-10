//! MLS group-lifecycle event construction: `ak.mls.genesis` for a creator
//! group and `ak.mls.commit` (self-update / add / remove) with the
//! governance binding, for any effective scope (Realm-wide or Circle).
//!
//! YGN-ARCH-01 step 2 (pure move from `views/kanban/mls_encrypt.rs`, zero
//! behavior change, misleading `kanban_` prefixes dropped): these builders
//! are consumed by `mls::admission`, `circle_mls`, `sync_engine` and several
//! views — core MLS logic, not kanban UI. The canonical-hash fallback inputs
//! intentionally keep their historical `"kanban_mls_*"` kind literals so
//! derived digests stay byte-identical across the move.

use serde_json::{Value, json};

use crate::local_state::{LocalSealView, LocalStateStore};
use crate::operation::{trim_realm_id, uuid_v7};

/// Restrict a state/seal ref to the canonical `sha256:` digest grammar used
/// by this MLS surface (`arkret_sdk::Hash::new` also accepts blake3, which is
/// not a state/seal ref here). Single source — the secure-send path re-exports
/// this instead of forking the digest grammar.
pub(crate) fn mls_sha256_hash_from_ref(value: &str) -> Option<String> {
    if value.starts_with("sha256:") && arkret_sdk::Hash::new(value).is_ok() {
        return Some(value.to_owned());
    }
    for prefix in ["ak:seal:", "ak:state:"] {
        if let Some(rest) = value.strip_prefix(prefix) {
            return mls_sha256_hash_from_ref(rest);
        }
    }
    None
}

/// First non-empty trimmed string at `path` under `value`.
fn json_path_string(value: &Value, path: &[&str]) -> Option<String> {
    let mut current = value;
    for segment in path {
        current = current.get(*segment)?;
    }
    current
        .as_str()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

fn object_ref_from_seal_ref(value: &str) -> Option<String> {
    if value.starts_with("ak:event:") && arkret_sdk::EventId::new(value.to_owned()).is_ok() {
        return Some(value.to_owned());
    }
    if value.starts_with("ak:blob:sha256:")
        && value
            .strip_prefix("ak:blob:")
            .and_then(mls_sha256_hash_from_ref)
            .is_some()
    {
        return Some(value.to_owned());
    }
    if let Some(hash) = mls_sha256_hash_from_ref(value) {
        return Some(hash);
    }
    None
}

fn mls_base_epoch_ref_for_scope(
    seal_view: &LocalSealView,
    realm_id: &str,
    circle_id: Option<&str>,
) -> String {
    seal_view
        .frontier
        .iter()
        .chain(seal_view.leaves.iter())
        .chain(seal_view.state_root.iter())
        .find_map(|value| object_ref_from_seal_ref(value))
        .unwrap_or_else(|| {
            crate::canonical::canonical_sha256(&json!({
                "kind": "kanban_mls_base_epoch",
                "realm_id": realm_id,
                "circle_id": circle_id,
                "epoch": seal_view.mls_epoch.unwrap_or(0),
            }))
            .unwrap_or_else(|_| {
                "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_owned()
            })
        })
}

fn mls_membership_frontier_from_seal_view(
    seal_view: &LocalSealView,
    fallback_event_id: &arkret_sdk::EventId,
) -> Vec<arkret_sdk::EventId> {
    let mut frontier = seal_view
        .frontier
        .iter()
        .chain(seal_view.leaves.iter())
        .filter_map(|value| arkret_sdk::EventId::new(value.clone()).ok())
        .collect::<Vec<_>>();
    if frontier.is_empty() {
        frontier.push(fallback_event_id.clone());
    }
    frontier.sort();
    frontier.dedup();
    frontier
}

fn mls_self_update_membership_frontier(
    base_group_state_ref: &str,
) -> Result<Vec<arkret_sdk::EventId>, String> {
    arkret_sdk::EventId::new(base_group_state_ref.to_owned())
        .map(|event_id| vec![event_id])
        .map_err(|_| {
            "MLS self-update membership_frontier requires a ak:event base group-state ref"
                .to_owned()
        })
}

pub(crate) fn mls_policy_root_from_seal_view(
    seal_view: &LocalSealView,
    realm_id: &str,
) -> Result<arkret_sdk::Hash, String> {
    let hash = seal_view
        .state_root
        .as_deref()
        .and_then(mls_sha256_hash_from_ref)
        .unwrap_or_else(|| {
            crate::canonical::canonical_sha256(&json!({
                "kind": "kanban_mls_policy_root",
                "realm_id": realm_id,
                "frontier": seal_view.frontier,
                "state_root": seal_view.state_root,
            }))
            .unwrap_or_else(|_| {
                "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_owned()
            })
        });
    arkret_sdk::Hash::new(hash).map_err(|err| format!("invalid MLS policy root hash: {err:?}"))
}

/// Resolve the `policy_root` a `ak.mls.commit` MUST declare for this group.
///
/// soland's `apply_commit_epoch` carries the genesis-locked `policy_root`
/// forward unchanged on every epoch advance and rejects any commit whose
/// binding declares a different value (`governance_binding_mismatch`). So a
/// commit MUST reuse the exact bytes `ak.mls.genesis` locked — NOT recompute
/// from the live Seal `state_root`, which advances on every non-policy event
/// and would drift the commit away from genesis. We return the recorded
/// genesis-locked root when present, falling back to the Seal-derived root only
/// for groups created before this value was tracked (`encryption-and-audit.md`
/// §2.5.1, [`crate::local_state::types::PersistedState::mls_genesis_policy_root`]).
fn mls_commit_policy_root(
    state_store: &LocalStateStore,
    seal_view: &LocalSealView,
    realm_id: &str,
    circle_id: Option<&str>,
) -> Result<arkret_sdk::Hash, String> {
    if let Some(stored) = state_store.genesis_policy_root_for_effective_scope(realm_id, circle_id) {
        return arkret_sdk::Hash::new(stored)
            .map_err(|err| format!("stored MLS genesis policy_root invalid: {err:?}"));
    }
    mls_policy_root_from_seal_view(seal_view, realm_id)
}

fn projection_creator_matches_actor(projection: &Value, actor_id: &str) -> bool {
    let actor = actor_id.trim();
    if actor.is_empty() {
        return false;
    }
    for source in [
        projection,
        projection.get("summary").unwrap_or(&Value::Null),
        projection.get("object").unwrap_or(&Value::Null),
        projection.get("realm").unwrap_or(&Value::Null),
        projection.get("metadata").unwrap_or(&Value::Null),
    ] {
        for key in [
            "owner",
            "created_by",
            "created_by_principal",
            "creator",
            "creator_did",
        ] {
            if json_path_string(source, &[key]).as_deref() == Some(actor) {
                return true;
            }
        }
    }
    false
}

fn circle_effective_scope(
    realm_id: &str,
    circle_id: &str,
) -> Result<arkret_sdk::models::EffectiveScope, String> {
    Ok(arkret_sdk::models::EffectiveScope::Circle {
        realm_id: arkret_sdk::RealmId::new(trim_realm_id(realm_id))
            .map_err(|err| format!("invalid Circle scope Realm id: {err:?}"))?,
        circle_id: arkret_sdk::CircleId::new(circle_id.to_owned())
            .map_err(|err| format!("invalid Circle scope Circle id: {err:?}"))?,
    })
}

pub(crate) fn ensure_creator_mls_snapshot_for_encrypted_scope(
    state_store: &mut LocalStateStore,
    secure_store: &dyn crate::secure_key_store::SecureKeyStore,
    realm_id: &str,
    actor_id: &str,
    device_id: &str,
) -> Result<Option<crate::mls::runtime::InitialMlsSnapshotSummary>, String> {
    if state_store.mls_snapshot_for(realm_id).is_some() {
        return Ok(None);
    }
    let state = state_store.load();
    let Some(projection) = crate::security_state::security_projection_for_scope_id(
        &state.realm_tree_projections,
        realm_id,
    ) else {
        return Ok(None);
    };
    if !crate::security_state::realm_projection_is_encrypted(projection)
        || !projection_creator_matches_actor(projection, actor_id)
    {
        return Ok(None);
    }
    crate::mls::runtime::ensure_creator_mls_snapshot(
        state_store,
        secure_store,
        realm_id,
        actor_id,
        device_id,
    )
    .map_err(|err| err.user_message())
}

/// Build the `ak.mls.genesis` SDK event for a creator group that has a
/// local snapshot but whose genesis has not yet been submitted to soland.
///
/// Returns `None` when genesis was already emitted for this Realm (idempotent —
/// see [`LocalStateStore::mls_genesis_emitted_for`]) or when there is no local
/// snapshot. `fresh_summary` carries the just-created group's epoch-0 ratchet
/// tree / schedule hash captured by `ensure_creator_mls_snapshot`; genesis MUST
/// describe the group at epoch 0, so this builder only emits when that fresh
/// epoch-0 material is available (the normal create-then-first-write path).
///
/// The genesis governance binding installs epoch `0 -> 0` and mirrors the
/// commit path's realm_id / membership_frontier / policy_root derivation.
pub(crate) fn build_creator_mls_genesis_event(
    state_store: &mut LocalStateStore,
    realm_id: &str,
    actor_id: &str,
    device_id: &str,
    fresh_summary: Option<&crate::mls::runtime::InitialMlsSnapshotSummary>,
) -> Result<Option<arkret_sdk::Event>, String> {
    build_creator_mls_genesis_event_for_effective_scope(
        state_store,
        realm_id,
        None,
        actor_id,
        device_id,
        fresh_summary,
    )
}

pub(crate) fn build_creator_mls_genesis_event_for_effective_scope(
    state_store: &mut LocalStateStore,
    realm_id: &str,
    circle_id: Option<&str>,
    actor_id: &str,
    device_id: &str,
    fresh_summary: Option<&crate::mls::runtime::InitialMlsSnapshotSummary>,
) -> Result<Option<arkret_sdk::Event>, String> {
    let circle = circle_id
        .map(str::trim)
        .filter(|circle_id| !circle_id.is_empty());
    if state_store.mls_genesis_emitted_for_effective_scope(realm_id, circle) {
        return Ok(None);
    }
    // Genesis describes the group at epoch 0. We can only build a
    // contract-correct genesis from the just-created epoch-0 material; once the
    // group has committed past epoch 0 the epoch-0 ratchet tree is gone. The
    // server lazily defaults a never-seen group to epoch 0 anyway, so missing
    // this window is non-fatal (commits still work).
    let Some(summary) = fresh_summary else {
        return Ok(None);
    };
    if summary.realm_id != realm_id {
        return Ok(None);
    }
    let seal_view = state_store.seal_view_for_realm(realm_id);
    let event_id = format!("ak:event:{}", uuid_v7());
    let event_id_typed = arkret_sdk::EventId::new(event_id.clone())
        .map_err(|err| format!("invalid MLS genesis event id: {err:?}"))?;
    let typed_realm_id = arkret_sdk::RealmId::new(trim_realm_id(realm_id))
        .map_err(|err| format!("invalid MLS genesis Realm id: {err:?}"))?;
    let membership_frontier = mls_membership_frontier_from_seal_view(&seal_view, &event_id_typed);
    let policy_root = mls_policy_root_from_seal_view(&seal_view, realm_id)?;
    // Lock the genesis `policy_root` so every later `ak.mls.commit` reuses these
    // exact bytes instead of recomputing from the moving Seal `state_root`
    // (which drifts the moment the creator does any non-policy work before
    // inviting, getting the add-member commit rejected with
    // `governance_binding_mismatch` — see `mls_genesis_policy_root`).
    state_store.record_genesis_policy_root_for_effective_scope(
        realm_id,
        circle,
        policy_root.as_str(),
    );
    let governance_binding = match circle {
        Some(circle_id) => {
            let typed_circle_id = arkret_sdk::CircleId::new(circle_id.to_owned())
                .map_err(|err| format!("invalid MLS genesis Circle id: {err:?}"))?;
            arkret_sdk::MlsGovernanceBindingPayload::circle(
                typed_realm_id,
                typed_circle_id,
                summary.group_id.clone(),
                0,
                0,
                membership_frontier,
                policy_root,
                arkret_sdk::MLS_GOVERNANCE_BINDING_FULL_PROFILE,
                arkret_sdk::CORE_REDUCER_PROFILE,
            )
        }
        None => arkret_sdk::MlsGovernanceBindingPayload::realm(
            typed_realm_id,
            summary.group_id.clone(),
            0,
            0,
            membership_frontier,
            policy_root,
            arkret_sdk::MLS_GOVERNANCE_BINDING_FULL_PROFILE,
            arkret_sdk::CORE_REDUCER_PROFILE,
        ),
    }
    .map_err(|err| format!("MLS genesis governance binding failed: {err}"))?;
    let payload = crate::mls::runtime::build_mls_genesis_payload(
        summary,
        actor_id,
        device_id,
        &governance_binding,
    )
    .map_err(|err| err.user_message())?;
    let mut event = crate::operation::ak_ops::mls_genesis_with_governance(
        realm_id,
        actor_id,
        &summary.group_id,
        &payload,
    )
    .build_sdk_event("inkson")
    .map(Some)
    .map_err(|err| format!("MLS genesis SDK Event conversion failed: {err}"))?;
    if let Some(event) = event.as_mut() {
        event.event_id = event_id_typed;
        if let Some(circle_id) = circle {
            event.effective_scope = Some(circle_effective_scope(realm_id, circle_id)?);
        }
    }
    Ok(event)
}

// pub(crate): the realm_admin epoch-rotation button (YOU-01-009) reuses
// this builder to wrap a forced `self_update_commit` into the canonical
// `ak.mls.commit` event with the governance binding.
pub(crate) fn mls_commit_event_from_store(
    state_store: &LocalStateStore,
    realm_id: &str,
    actor_id: &str,
    _schedule_hash: &arkret_sdk::Hash,
    commit_envelope: &arkret_sdk::MlsCommitEnvelope,
) -> Result<arkret_sdk::Event, String> {
    mls_commit_event_from_store_for_effective_scope(
        state_store,
        realm_id,
        None,
        actor_id,
        commit_envelope,
    )
}

pub(crate) fn mls_commit_event_from_store_for_effective_scope(
    state_store: &LocalStateStore,
    realm_id: &str,
    circle_id: Option<&str>,
    actor_id: &str,
    commit_envelope: &arkret_sdk::MlsCommitEnvelope,
) -> Result<arkret_sdk::Event, String> {
    mls_commit_event_from_store_for_effective_scope_with_proposal_refs(
        state_store,
        realm_id,
        circle_id,
        actor_id,
        commit_envelope,
        Vec::new(),
    )
}

pub(crate) fn mls_commit_event_from_store_for_effective_scope_with_proposal_refs(
    state_store: &LocalStateStore,
    realm_id: &str,
    circle_id: Option<&str>,
    actor_id: &str,
    commit_envelope: &arkret_sdk::MlsCommitEnvelope,
    proposal_refs: Vec<arkret_sdk::EventId>,
) -> Result<arkret_sdk::Event, String> {
    mls_commit_event_from_store_for_effective_scope_with_membership_frontier(
        state_store,
        realm_id,
        circle_id,
        actor_id,
        commit_envelope,
        proposal_refs,
        None,
    )
}

pub(crate) fn mls_remove_commit_event_from_store_for_effective_scope_with_proposal_refs(
    state_store: &LocalStateStore,
    realm_id: &str,
    circle_id: Option<&str>,
    actor_id: &str,
    commit_envelope: &arkret_sdk::MlsCommitEnvelope,
    proposal_refs: Vec<arkret_sdk::EventId>,
    revocation_membership_frontier: &[arkret_sdk::EventId],
) -> Result<arkret_sdk::Event, String> {
    let membership_frontier = crate::mls::runtime::canonical_mls_remove_membership_frontier(
        revocation_membership_frontier,
    )
    .map_err(|err| err.user_message())?;
    mls_commit_event_from_store_for_effective_scope_with_membership_frontier(
        state_store,
        realm_id,
        circle_id,
        actor_id,
        commit_envelope,
        proposal_refs,
        Some(membership_frontier),
    )
}

fn mls_commit_event_from_store_for_effective_scope_with_membership_frontier(
    state_store: &LocalStateStore,
    realm_id: &str,
    circle_id: Option<&str>,
    actor_id: &str,
    commit_envelope: &arkret_sdk::MlsCommitEnvelope,
    proposal_refs: Vec<arkret_sdk::EventId>,
    explicit_membership_frontier: Option<Vec<arkret_sdk::EventId>>,
) -> Result<arkret_sdk::Event, String> {
    let circle = circle_id
        .map(str::trim)
        .filter(|circle_id| !circle_id.is_empty());
    let seal_view = state_store.seal_view_for_realm(realm_id);
    // `base_epoch` MUST be the SDK group's PRE-commit epoch so the
    // `next_epoch == base_epoch + 1` invariant holds by construction.
    // `commit_envelope.epoch` is the POST-commit epoch (`self_update_commit`
    // merges the pending commit before reading it), so the pre-commit epoch is
    // exactly one less. Deriving `base_epoch` from `seal_view.mls_epoch`
    // instead — which only refreshes on `/sync` — drifts whenever the local
    // snapshot has advanced past the last server-confirmed epoch, which is what
    // tripped `mls_commit_payload.next_epoch must equal base_epoch + 1`.
    let prev_epoch = commit_envelope.epoch.saturating_sub(1);
    let event_id = format!("ak:event:{}", uuid_v7());
    let event_id_typed = arkret_sdk::EventId::new(event_id.clone())
        .map_err(|err| format!("invalid MLS commit event id: {err:?}"))?;
    let typed_realm_id = arkret_sdk::RealmId::new(trim_realm_id(realm_id))
        .map_err(|err| format!("invalid MLS commit Realm id: {err:?}"))?;
    let base_group_state_ref = mls_base_epoch_ref_for_scope(&seal_view, realm_id, circle);
    let membership_frontier = explicit_membership_frontier
        .map(Ok)
        .unwrap_or_else(|| mls_self_update_membership_frontier(&base_group_state_ref))?;
    let policy_root = mls_commit_policy_root(state_store, &seal_view, realm_id, circle)?;
    let governance_binding = match circle {
        Some(circle_id) => {
            let typed_circle_id = arkret_sdk::CircleId::new(circle_id.to_owned())
                .map_err(|err| format!("invalid MLS commit Circle id: {err:?}"))?;
            arkret_sdk::MlsGovernanceBindingPayload::circle(
                typed_realm_id,
                typed_circle_id,
                commit_envelope.group_id.clone(),
                prev_epoch,
                commit_envelope.epoch,
                membership_frontier,
                policy_root,
                arkret_sdk::MLS_GOVERNANCE_BINDING_FULL_PROFILE,
                arkret_sdk::CORE_REDUCER_PROFILE,
            )
        }
        None => arkret_sdk::MlsGovernanceBindingPayload::realm(
            typed_realm_id,
            commit_envelope.group_id.clone(),
            prev_epoch,
            commit_envelope.epoch,
            membership_frontier,
            policy_root,
            arkret_sdk::MLS_GOVERNANCE_BINDING_FULL_PROFILE,
            arkret_sdk::CORE_REDUCER_PROFILE,
        ),
    }
    .map_err(|err| format!("MLS governance binding failed: {err}"))?;
    let payload = arkret_sdk::MlsCommitPayload::new(
        commit_envelope.group_id.clone(),
        prev_epoch,
        base_group_state_ref,
        proposal_refs,
        commit_envelope.epoch,
        commit_envelope.commit_digest.clone(),
        governance_binding,
    )
    .map_err(|err| format!("MLS commit payload failed: {err}"))?;
    let mut event =
        crate::operation::ak_ops::mls_commit_with_governance(realm_id, actor_id, &payload)
            .map_err(|err| format!("MLS commit payload failed: {err}"))?
            .build_sdk_event("inkson")
            .map_err(|err| format!("MLS commit SDK Event conversion failed: {err}"))?;
    event.event_id = event_id_typed;
    if let Some(circle_id) = circle {
        event.effective_scope = Some(circle_effective_scope(realm_id, circle_id)?);
    }
    Ok(event)
}
