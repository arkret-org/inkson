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

use serde_json::Value;

use crate::operation::trim_realm_id;
use crate::state::LocalStateStore;

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

/// Whether `actor_id` is the creator (authority-root controller) of
/// `realm_id` according to local state. Single predicate for every creator
/// MLS bootstrap gate.
///
/// The only source is the envelope `actor_id` of the locally projected
/// accepted `ak.realm.create` — the same create-locked fact the authority-root
/// authorization claim uses. The Realm sync entry itself carries no creator
/// mirror: it deserializes into the closed `RealmSyncEntry`
/// (`joined/invited_member_count` + `heroes` under `summary`, and no `object`
/// / `realm` / `metadata` container at all), so probing it for `owner` /
/// `created_by` / `creator` could never match.
pub(crate) fn projected_realm_creator_matches_actor(
    realm_tree_projections: &std::collections::BTreeMap<String, Value>,
    realm_id: &str,
    actor_id: &str,
) -> bool {
    let Ok(actor_core_id) = crate::mls_api_helpers::principal_core_id(actor_id) else {
        return false;
    };
    crate::security_state::realm_authority_root_controller_for_realm(
        realm_tree_projections,
        realm_id,
    )
    .as_deref()
        == Some(actor_core_id.as_str())
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
    if state_store.mls_genesis_emitted_for(realm_id) {
        return Err(format!(
            "accepted MLS genesis exists for {realm_id}, but the local epoch-0 snapshot is missing; restore the device snapshot before sending"
        ));
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
    if !projected_realm_creator_matches_actor(&state.realm_tree_projections, realm_id, actor_id) {
        tracing::warn!(
            realm = %realm_id,
            actor = %actor_id,
            projected_create_controller = ?crate::security_state::realm_authority_root_controller_for_realm(
                &state.realm_tree_projections,
                realm_id,
            ),
            "creator MLS bootstrap declined: the projected ak.realm.create does not name the actor as creator",
        );
        return Ok(None);
    }
    // §2.5.1.1 prelude ownership: only `mls::creator_bootstrap` may establish
    // the trust anchor (accepted Seal view refresh → proof fetch → full
    // verification → pin). Creating the epoch-0 group here without that pin
    // would fail deep inside the governance binding with the bare
    // "requires a locally verified replay checkpoint" error; fail early with an
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
/// `None` when the §2.5.1.1 prelude has pinned a verified replay checkpoint.
///
/// Single precondition point for every inline creator-group creation; the
/// prelude itself is owned exclusively by
/// [`crate::mls::creator_bootstrap::ensure_creator_realm_mls_genesis`].
pub(crate) fn creator_scope_bootstrap_blocker(
    state_store: &LocalStateStore,
    realm_id: &str,
) -> Option<String> {
    if state_store
        .trusted_mls_governance_checkpoint(realm_id)
        .is_some()
    {
        return None;
    }
    Some(format!(
        "the Realm's governance checkpoint is not verified on this device yet \
         (creator MLS bootstrap for {realm_id} is still running in the background); \
         retry in a few seconds"
    ))
}

/// Build the `ak.mls.genesis` SDK event for a creator group that has a
/// local snapshot but whose genesis has not yet been submitted to soland.
///
/// Returns `None` when genesis was already emitted for this Realm and its exact
/// accepted group-state Event reference is available, or when there is no local
/// snapshot. An emitted flag without that reference is not a completed
/// bootstrap: rebuilding is safe because the submit path resolves a
/// server-side duplicate to the already-accepted Event id. `fresh_summary`
/// carries either the just-created group's epoch-0 material or material restored
/// from its durable epoch-0 snapshot.
///
/// The genesis governance binding installs epoch `0 -> 0` and mirrors the
/// commit path's realm ID and Security Frontier derivation.
pub(crate) fn build_creator_mls_genesis_event(
    state_store: &mut LocalStateStore,
    realm_id: &str,
    actor_id: &str,
    device_id: &str,
    fresh_summary: Option<&crate::mls::runtime::InitialMlsSnapshotSummary>,
) -> Result<Option<crate::operation::LocalOperation>, String> {
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
) -> Result<Option<crate::operation::LocalOperation>, String> {
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
) -> Result<Option<crate::operation::LocalOperation>, String> {
    let circle = circle_id
        .map(str::trim)
        .filter(|circle_id| !circle_id.is_empty());
    let realm = arkret_sdk::RealmId::new(realm_id.to_owned())
        .map_err(|error| format!("invalid MLS Realm id: {error}"))?;
    let effective_scope = match sidecar_binding.as_ref() {
        Some(binding) => arkret_sdk::ScopeRef::Sidecar {
            realm_id: realm.clone(),
            sidecar_id: binding.sidecar_id.clone(),
        },
        None => match circle {
            Some(circle_id) => circle_effective_scope(realm_id, circle_id)?,
            None => arkret_sdk::ScopeRef::Realm {
                realm_id: realm.clone(),
            },
        },
    };
    if state_store.mls_genesis_emitted_for_scope(&effective_scope)
        && let Some(snapshot) = state_store.mls_snapshot_for_scope(&effective_scope)
        && state_store
            .mls_group_state_ref_for_scope(&effective_scope, &snapshot.group_id, snapshot.epoch)
            .is_ok()
    {
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

    let governance_binding = crate::mls::governance_proof::cached_verified_binding_for_transition(
        state_store,
        &effective_scope,
        &summary.group_id,
        0,
        0,
    )?;
    if let Some(binding) = sidecar_binding.as_ref()
        && governance_binding.sidecar_binding() != Some(binding)
    {
        return Err(
            "verified Sidecar MLS binding differs from the accepted Sidecar view".to_owned(),
        );
    }
    let payload = crate::mls::runtime::build_mls_genesis_payload(
        summary,
        actor_id,
        device_id,
        &governance_binding,
    )
    .map_err(|err| err.user_message())?;
    let event = crate::operation::ak_ops::mls_genesis_with_governance(
        realm_id,
        actor_id,
        &summary.group_id,
        &payload,
    )
    .map_err(|err| format!("MLS genesis typed payload conversion failed: {err}"))?
    // Scope narrowing is producer-signed content, so it happens on the intent.
    .effective_scope(effective_scope)
    .build_sdk_event("inkson")
    .map(Some)
    .map_err(|err| format!("MLS genesis SDK Event conversion failed: {err}"))?;
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
) -> Result<crate::operation::LocalOperation, String> {
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
) -> Result<crate::operation::LocalOperation, String> {
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
) -> Result<crate::operation::LocalOperation, String> {
    mls_commit_event_from_store_for_effective_scope_with_options(
        state_store,
        realm_id,
        circle_id,
        actor_id,
        commit_envelope,
        previous_governance_binding,
        proposal_refs,
        None,
    )
}

pub(crate) fn mls_commit_event_from_store_for_sidecar_scope(
    state_store: &LocalStateStore,
    realm_id: &str,
    actor_id: &str,
    commit_envelope: &arkret_sdk::MlsCommitEnvelope,
    previous_governance_binding: &arkret_sdk::MlsGovernanceBindingPayload,
    sidecar_binding: arkret_sdk::SidecarMlsBinding,
) -> Result<crate::operation::LocalOperation, String> {
    mls_commit_event_from_store_for_effective_scope_with_options(
        state_store,
        realm_id,
        None,
        actor_id,
        commit_envelope,
        previous_governance_binding,
        Vec::new(),
        Some(sidecar_binding),
    )
}

/// Everything an `ak.mls.commit` needs from the local store, read once.
///
/// Held as owned values so the commit can be built later, after the proposals it
/// references have been authored — the store cannot be borrowed across that
/// boundary.
pub(crate) struct MlsCommitBasis {
    realm_id: String,
    actor_id: String,
    effective_scope: arkret_sdk::ScopeRef,
    prev_epoch: u64,
    base_group_state_ref: String,
    governance_binding: arkret_sdk::MlsGovernanceBindingPayload,
    commit_envelope: arkret_sdk::MlsCommitEnvelope,
    preconditions: Vec<crate::operation::Precondition>,
}

impl MlsCommitBasis {
    /// Build the commit once the proposals it references are authored.
    pub(crate) fn build(
        self,
        proposal_refs: Vec<arkret_sdk::EventId>,
    ) -> Result<crate::operation::LocalOperation, String> {
        let payload = arkret_sdk::MlsCommitPayload::new(
            self.prev_epoch,
            self.base_group_state_ref,
            proposal_refs,
            &self.commit_envelope,
            self.governance_binding,
        )
        .map_err(|err| format!("MLS commit payload failed: {err}"))?;
        crate::operation::ak_ops::mls_commit_with_governance(
            &self.realm_id,
            &self.actor_id,
            &payload,
        )
        .map_err(|err| format!("MLS commit payload failed: {err}"))?
        .preconditions(self.preconditions)
        .effective_scope(self.effective_scope)
        .build_sdk_event("inkson")
        .map_err(|err| format!("MLS commit SDK Event conversion failed: {err}"))
    }
}

pub(crate) fn mls_commit_basis_from_store(
    state_store: &LocalStateStore,
    realm_id: &str,
    circle_id: Option<&str>,
    actor_id: &str,
    commit_envelope: &arkret_sdk::MlsCommitEnvelope,
    previous_governance_binding: &arkret_sdk::MlsGovernanceBindingPayload,
    sidecar_binding: Option<arkret_sdk::SidecarMlsBinding>,
) -> Result<MlsCommitBasis, String> {
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
    let realm = arkret_sdk::RealmId::new(realm_id.to_owned())
        .map_err(|error| format!("invalid MLS Realm id: {error}"))?;
    let effective_scope = match sidecar_binding.as_ref() {
        Some(binding) => arkret_sdk::ScopeRef::Sidecar {
            realm_id: realm.clone(),
            sidecar_id: binding.sidecar_id.clone(),
        },
        None => match circle {
            Some(circle_id) => circle_effective_scope(realm_id, circle_id)?,
            None => arkret_sdk::ScopeRef::Realm { realm_id: realm },
        },
    };

    let base_group_state_ref = state_store
        .mls_group_state_ref_for_scope(
            &effective_scope,
            commit_envelope.group_id.as_str(),
            prev_epoch,
        )?
        .to_string();
    let governance_binding = crate::mls::governance_proof::cached_verified_binding_for_transition(
        state_store,
        &effective_scope,
        &commit_envelope.group_id,
        prev_epoch,
        commit_envelope.epoch,
    )?;
    let governance_binding = match sidecar_binding {
        Some(binding) => {
            crate::mls::governance_proof::bind_sidecar_scope(&governance_binding, binding.clone())
                .map_err(|error| format!("invalid Sidecar MLS governance binding: {error}"))?
        }
        None => governance_binding,
    };
    let preconditions = crate::mls::governance::mls_commit_preconditions(
        &effective_scope,
        commit_envelope.group_id.as_str(),
        prev_epoch,
        previous_governance_binding,
    )
    .map_err(|err| format!("MLS commit preconditions failed: {err}"))?;
    Ok(MlsCommitBasis {
        realm_id: realm_id.to_owned(),
        actor_id: actor_id.to_owned(),
        effective_scope,
        prev_epoch,
        base_group_state_ref,
        governance_binding,
        commit_envelope: commit_envelope.clone(),
        preconditions,
    })
}

fn mls_commit_event_from_store_for_effective_scope_with_options(
    state_store: &LocalStateStore,
    realm_id: &str,
    circle_id: Option<&str>,
    actor_id: &str,
    commit_envelope: &arkret_sdk::MlsCommitEnvelope,
    previous_governance_binding: &arkret_sdk::MlsGovernanceBindingPayload,
    proposal_refs: Vec<arkret_sdk::EventId>,
    sidecar_binding: Option<arkret_sdk::SidecarMlsBinding>,
) -> Result<crate::operation::LocalOperation, String> {
    mls_commit_basis_from_store(
        state_store,
        realm_id,
        circle_id,
        actor_id,
        commit_envelope,
        previous_governance_binding,
        sidecar_binding,
    )?
    .build(proposal_refs)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::state::LocalStateStore;

    const ACTOR: &str = "did:web:alice.example";
    const REALM: &str = "ak:realm:AUOIeY-cRu4Vmsf-xStVp_Hacq8lfzdbOzYdwA-NGpkX";

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
                    "actor_id": "ak:did_core:web:alice.example",
                    "payload": { "object": { "encryption_profile": "mls_rfc9420" } }
                }]
            }
        })
    }

    /// Regression lock (2026-08-01): the encrypted-scope path engaged the
    /// creator group creation without the §2.5.1.1 anchor prelude and died
    /// deep inside the governance binding with the bare "requires a locally
    /// verified replay checkpoint" error. The scope path MUST fail early with an
    /// actionable message and MUST NOT attempt group creation until
    /// `mls::creator_bootstrap` has pinned a verified replay checkpoint.
    #[test]
    fn creator_scope_bootstrap_is_blocked_until_a_governance_checkpoint_is_pinned() {
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
        assert!(error.contains("governance checkpoint"), "{error}");
        assert!(store.mls_snapshot_for(REALM).is_none());
    }

    #[test]
    fn creator_scope_bootstrap_blocker_clears_once_a_verified_checkpoint_is_pinned() {
        let mut store = temp_store("anchor-pinned");
        store.save_realm_tree_projection(REALM, creator_realm_projection());
        crate::mls::governance_proof::seed_test_governance_proof(
            &mut store,
            REALM,
            None,
            arkret_sdk::base64url_encode(REALM.as_bytes()),
            0,
            0,
        );
        assert!(creator_scope_bootstrap_blocker(&store, REALM).is_none());
    }
}
