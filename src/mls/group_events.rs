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

use crate::operation::{trim_realm_id, uuid_v7};
use crate::state::{LocalSealView, LocalStateStore};

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

pub(crate) fn mls_base_epoch_ref_for_scope(
    state_store: &LocalStateStore,
    realm_id: &str,
    circle_id: Option<&str>,
    group_id: &str,
    epoch: u64,
) -> Result<String, String> {
    state_store
        .mls_group_state_ref_for_effective_scope(realm_id, circle_id, group_id, epoch)
        .map(|event_id| event_id.to_string())
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

/// Whether `actor_id` is the creator (authority-root controller) of
/// `realm_id` according to local state. Single predicate for every creator
/// MLS bootstrap gate. Two projected sources are accepted, in order: explicit
/// creator fields on the security projection (legacy shapes), and the
/// `created_by` of the locally projected accepted `ak.realm.create` — the
/// same create-locked fact the authority-root authorization claim uses;
/// post-P1 realm projections carry no `owner` mirror, so the event-log source
/// is the authoritative one.
pub(crate) fn projected_realm_creator_matches_actor(
    realm_tree_projections: &std::collections::BTreeMap<String, Value>,
    projection: &Value,
    realm_id: &str,
    actor_id: &str,
) -> bool {
    projection_creator_matches_actor(projection, actor_id)
        || crate::security_state::realm_authority_root_controller_for_realm(
            realm_tree_projections,
            realm_id,
        )
        .as_deref()
            == Some(actor_id.trim())
}

pub(crate) fn projection_creator_matches_actor(projection: &Value, actor_id: &str) -> bool {
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

pub(crate) fn circle_effective_scope(
    realm_id: &str,
    circle_id: &str,
) -> Result<arkret_wire::ScopeRef, String> {
    Ok(arkret_wire::ScopeRef::Circle {
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
        // WARN so the wasm console shows it: each of these silent declines
        // leaves the caller on the Welcome-waiting path, which is the wrong
        // answer for a Realm creator and otherwise undiagnosable in the field.
        tracing::warn!(
            realm = %realm_id,
            "creator MLS bootstrap declined: no local realm tree projection for this Realm",
        );
        return Ok(None);
    };
    if !crate::security_state::realm_projection_is_encrypted(projection) {
        tracing::warn!(
            realm = %realm_id,
            "creator MLS bootstrap declined: local projection does not mark the Realm encrypted",
        );
        return Ok(None);
    }
    if !projected_realm_creator_matches_actor(
        &state.realm_tree_projections,
        projection,
        realm_id,
        actor_id,
    ) {
        tracing::warn!(
            realm = %realm_id,
            actor = %actor_id,
            projection_owner = ?projection.get("owner"),
            summary_owner = ?projection.pointer("/summary/owner"),
            created_by = ?projection.get("created_by"),
            projected_create_controller = ?crate::security_state::realm_authority_root_controller_for_realm(
                &state.realm_tree_projections,
                realm_id,
            ),
            "creator MLS bootstrap declined: neither projection fields nor the projected ak.realm.create name the actor as creator",
        );
        return Ok(None);
    }
    // §2.5.1.1 prelude ownership: only `mls::creator_bootstrap` may establish
    // the trust anchor (accepted Seal view refresh → proof fetch → full
    // verification → pin). Creating the epoch-0 group here without that pin
    // would fail deep inside the governance binding with the bare
    // "requires a locally trusted Seal anchor" error; fail early with an
    // actionable message instead, and let the background bootstrap (which
    // retries with backoff) finish the prelude.
    if let Some(pending) = creator_scope_bootstrap_blocker(state_store, realm_id) {
        tracing::warn!(
            realm = %realm_id,
            "creator MLS bootstrap deferred: {pending}",
        );
        return Err(pending);
    }
    tracing::warn!(
        realm = %realm_id,
        "creator MLS bootstrap engaged: creating the epoch-0 group on this device",
    );
    crate::mls::runtime::ensure_creator_mls_snapshot(
        state_store,
        secure_store,
        realm_id,
        actor_id,
        device_id,
    )
    .map_err(|err| err.user_message())
}

/// Why the encrypted-scope path must not create the creator group yet, or
/// `None` when the §2.5.1.1 prelude has completed (governance anchor pinned).
///
/// Single precondition point for every inline creator-group creation; the
/// prelude itself is owned exclusively by
/// [`crate::mls::creator_bootstrap::ensure_creator_realm_mls_genesis`].
pub(crate) fn creator_scope_bootstrap_blocker(
    state_store: &LocalStateStore,
    realm_id: &str,
) -> Option<String> {
    if state_store
        .trusted_mls_governance_anchor(realm_id)
        .is_some()
    {
        return None;
    }
    Some(format!(
        "the Realm's governance anchor is not verified on this device yet \
         (creator MLS bootstrap for {realm_id} is still running in the background); \
         retry in a few seconds"
    ))
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
    build_creator_mls_genesis_event_for_effective_scope_with_binding(
        state_store,
        realm_id,
        circle_id,
        actor_id,
        device_id,
        fresh_summary,
        None,
    )
}

pub(crate) fn build_creator_mls_genesis_event_for_effective_scope_with_binding(
    state_store: &mut LocalStateStore,
    realm_id: &str,
    circle_id: Option<&str>,
    actor_id: &str,
    device_id: &str,
    fresh_summary: Option<&crate::mls::runtime::InitialMlsSnapshotSummary>,
    sidecar_binding: Option<arkret_sdk::SidecarMlsBinding>,
) -> Result<Option<arkret_sdk::Event>, String> {
    let circle = circle_id
        .map(str::trim)
        .filter(|circle_id| !circle_id.is_empty());
    if state_store.mls_genesis_emitted_for_effective_scope(realm_id, circle) {
        return Ok(None);
    }
    // Genesis describes the group at epoch 0. We can only build a
    // contract-correct genesis from durable epoch-0 material. Callers must
    // restore that material after a crash; a group without an accepted genesis
    // is not usable and must remain fail-closed.
    let Some(summary) = fresh_summary else {
        return Ok(None);
    };
    if summary.realm_id != realm_id {
        return Ok(None);
    }
    let event_id = format!("ak:event:{}", uuid_v7());
    let event_id_typed = arkret_sdk::EventId::new(event_id.clone())
        .map_err(|err| format!("invalid MLS genesis event id: {err:?}"))?;
    let request = crate::mls::governance_proof::proof_request(
        state_store,
        realm_id,
        circle,
        summary.group_id.clone(),
        0,
        0,
    )?;
    let governance_binding =
        crate::mls::governance_proof::cached_verified_binding(state_store, &request)?;
    let governance_binding = match sidecar_binding {
        Some(binding) => governance_binding
            .with_sidecar_binding(binding)
            .map_err(|error| format!("invalid Sidecar MLS governance binding: {error}"))?,
        None => governance_binding,
    };
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
            event.scope_ref = circle_effective_scope(realm_id, circle_id)?;
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
    previous_governance_binding: &arkret_sdk::MlsGovernanceBindingPayload,
) -> Result<arkret_sdk::Event, String> {
    mls_commit_event_from_store_for_effective_scope(
        state_store,
        realm_id,
        None,
        actor_id,
        commit_envelope,
        previous_governance_binding,
    )
}

pub(crate) fn mls_commit_event_from_store_for_effective_scope(
    state_store: &LocalStateStore,
    realm_id: &str,
    circle_id: Option<&str>,
    actor_id: &str,
    commit_envelope: &arkret_sdk::MlsCommitEnvelope,
    previous_governance_binding: &arkret_sdk::MlsGovernanceBindingPayload,
) -> Result<arkret_sdk::Event, String> {
    mls_commit_event_from_store_for_effective_scope_with_proposal_refs(
        state_store,
        realm_id,
        circle_id,
        actor_id,
        commit_envelope,
        previous_governance_binding,
        Vec::new(),
    )
}

pub(crate) fn mls_commit_event_from_store_for_effective_scope_with_proposal_refs(
    state_store: &LocalStateStore,
    realm_id: &str,
    circle_id: Option<&str>,
    actor_id: &str,
    commit_envelope: &arkret_sdk::MlsCommitEnvelope,
    previous_governance_binding: &arkret_sdk::MlsGovernanceBindingPayload,
    proposal_refs: Vec<arkret_sdk::EventId>,
) -> Result<arkret_sdk::Event, String> {
    mls_commit_event_from_store_for_effective_scope_with_membership_frontier(
        state_store,
        realm_id,
        circle_id,
        actor_id,
        commit_envelope,
        previous_governance_binding,
        proposal_refs,
        None,
        None,
    )
}

pub(crate) fn mls_commit_event_from_store_for_effective_scope_with_sidecar_binding(
    state_store: &LocalStateStore,
    realm_id: &str,
    circle_id: &str,
    actor_id: &str,
    commit_envelope: &arkret_sdk::MlsCommitEnvelope,
    previous_governance_binding: &arkret_sdk::MlsGovernanceBindingPayload,
    sidecar_binding: arkret_sdk::SidecarMlsBinding,
) -> Result<arkret_sdk::Event, String> {
    mls_commit_event_from_store_for_effective_scope_with_membership_frontier(
        state_store,
        realm_id,
        Some(circle_id),
        actor_id,
        commit_envelope,
        previous_governance_binding,
        Vec::new(),
        None,
        Some(sidecar_binding),
    )
}

pub(crate) fn mls_remove_commit_event_from_store_for_effective_scope_with_proposal_refs(
    state_store: &LocalStateStore,
    realm_id: &str,
    circle_id: Option<&str>,
    actor_id: &str,
    commit_envelope: &arkret_sdk::MlsCommitEnvelope,
    previous_governance_binding: &arkret_sdk::MlsGovernanceBindingPayload,
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
        previous_governance_binding,
        proposal_refs,
        Some(membership_frontier),
        None,
    )
}

pub(crate) fn mls_remove_commit_event_from_store_for_effective_scope_with_sidecar_binding(
    state_store: &LocalStateStore,
    realm_id: &str,
    circle_id: &str,
    actor_id: &str,
    commit_envelope: &arkret_sdk::MlsCommitEnvelope,
    previous_governance_binding: &arkret_sdk::MlsGovernanceBindingPayload,
    proposal_refs: Vec<arkret_sdk::EventId>,
    revocation_membership_frontier: &[arkret_sdk::EventId],
    sidecar_binding: arkret_sdk::SidecarMlsBinding,
) -> Result<arkret_sdk::Event, String> {
    let membership_frontier = crate::mls::runtime::canonical_mls_remove_membership_frontier(
        revocation_membership_frontier,
    )
    .map_err(|err| err.user_message())?;
    mls_commit_event_from_store_for_effective_scope_with_membership_frontier(
        state_store,
        realm_id,
        Some(circle_id),
        actor_id,
        commit_envelope,
        previous_governance_binding,
        proposal_refs,
        Some(membership_frontier),
        Some(sidecar_binding),
    )
}

fn mls_commit_event_from_store_for_effective_scope_with_membership_frontier(
    state_store: &LocalStateStore,
    realm_id: &str,
    circle_id: Option<&str>,
    actor_id: &str,
    commit_envelope: &arkret_sdk::MlsCommitEnvelope,
    previous_governance_binding: &arkret_sdk::MlsGovernanceBindingPayload,
    proposal_refs: Vec<arkret_sdk::EventId>,
    explicit_membership_frontier: Option<Vec<arkret_sdk::EventId>>,
    sidecar_binding: Option<arkret_sdk::SidecarMlsBinding>,
) -> Result<arkret_sdk::Event, String> {
    let circle = circle_id
        .map(str::trim)
        .filter(|circle_id| !circle_id.is_empty());
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
    let base_group_state_ref = mls_base_epoch_ref_for_scope(
        state_store,
        realm_id,
        circle,
        commit_envelope.group_id.as_str(),
        prev_epoch,
    )?;
    let explicit_membership_frontier = explicit_membership_frontier.map(|explicit| {
        explicit
            .into_iter()
            .collect::<std::collections::BTreeSet<_>>()
    });
    if let Some(requested) = explicit_membership_frontier.as_ref()
        && requested.is_empty()
    {
        return Err("MLS Remove governance frontier must not be empty".to_owned());
    }
    let request = crate::mls::governance_proof::proof_request(
        state_store,
        realm_id,
        circle,
        commit_envelope.group_id.clone(),
        prev_epoch,
        commit_envelope.epoch,
    )?;
    let governance_binding =
        crate::mls::governance_proof::cached_verified_binding(state_store, &request)?;
    let governance_binding = match sidecar_binding {
        Some(binding) => governance_binding
            .with_sidecar_binding(binding)
            .map_err(|error| format!("invalid Sidecar MLS governance binding: {error}"))?,
        None => governance_binding,
    };
    let _ = explicit_membership_frontier;
    let payload = arkret_sdk::MlsCommitPayload::new(
        prev_epoch,
        base_group_state_ref,
        proposal_refs,
        commit_envelope,
        governance_binding,
    )
    .map_err(|err| format!("MLS commit payload failed: {err}"))?;
    let mut event =
        crate::operation::ak_ops::mls_commit_with_governance(realm_id, actor_id, &payload)
            .map_err(|err| format!("MLS commit payload failed: {err}"))?
            .build_sdk_event("inkson")
            .map_err(|err| format!("MLS commit SDK Event conversion failed: {err}"))?;
    let trusted_anchor = state_store
        .trusted_mls_governance_anchor(realm_id)
        .ok_or_else(|| "MLS commit requires a pinned governance anchor".to_owned())?;
    event.preconditions = crate::mls::governance::mls_commit_preconditions(
        commit_envelope.group_id.as_str(),
        prev_epoch,
        previous_governance_binding,
        &trusted_anchor,
    )
    .map_err(|err| format!("MLS commit preconditions failed: {err}"))?;
    event.event_id = event_id_typed;
    if let Some(circle_id) = circle {
        event.scope_ref = circle_effective_scope(realm_id, circle_id)?;
    }
    Ok(event)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::state::LocalStateStore;

    const ACTOR: &str = "did:web:alice.example";
    const REALM: &str = "ak:realm:01904100-0000-7000-8000-000000000041";

    fn temp_store(name: &str) -> LocalStateStore {
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        LocalStateStore::with_path(
            std::env::temp_dir().join(format!("inkson-group-events-{name}-{stamp}.json")),
        )
    }

    /// Post-P1 shape: no owner/created_by mirror on the projection; the
    /// creator fact lives only in the projected `ak.realm.create`.
    fn creator_realm_projection() -> serde_json::Value {
        json!({
            "__kind": "realm",
            "content_scheme": "mls_rfc9420",
            "summary": { "title": "Realm", "encryption_profile": "mls_rfc9420" },
            "state": {
                "events": [{
                    "kind": "ak.realm.create",
                    "payload": { "object": { "id": REALM, "created_by": ACTOR } }
                }]
            }
        })
    }

    /// Regression lock (2026-08-01): the encrypted-scope path engaged the
    /// creator group creation without the §2.5.1.1 anchor prelude and died
    /// deep inside the governance binding with the bare "requires a locally
    /// trusted Seal anchor" error. The scope path MUST fail early with an
    /// actionable message and MUST NOT attempt group creation until
    /// `mls::creator_bootstrap` has pinned the anchor.
    #[test]
    fn creator_scope_bootstrap_is_blocked_until_the_governance_anchor_is_pinned() {
        let mut store = temp_store("anchor-gate");
        store.save_realm_tree_projection(REALM, creator_realm_projection());
        assert!(creator_scope_bootstrap_blocker(&store, REALM).is_some());

        let secure = crate::secure_key_store::default_secure_key_store("inkson");
        let error = ensure_creator_mls_snapshot_for_encrypted_scope(
            &mut store,
            secure.as_ref(),
            REALM,
            ACTOR,
            "ak:device:01904100-0000-7000-8000-000000000042",
        )
        .expect_err("group creation must not run before the anchor prelude");
        assert!(error.contains("governance anchor"), "{error}");
        assert!(
            !error.contains("locally trusted Seal anchor"),
            "raw deep governance-binding error resurfaced: {error}"
        );
        assert!(store.mls_snapshot_for(REALM).is_none());
    }

    #[test]
    fn creator_scope_bootstrap_blocker_clears_once_the_anchor_is_pinned() {
        let mut store = temp_store("anchor-pinned");
        store.save_realm_tree_projection(REALM, creator_realm_projection());
        let anchor = arkret_sdk::SealId::new(
            "ak:seal:sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                .to_owned(),
        )
        .expect("seal id");
        store
            .pin_mls_governance_anchor(REALM, &anchor)
            .expect("pin anchor");
        assert!(creator_scope_bootstrap_blocker(&store, REALM).is_none());
    }
}
