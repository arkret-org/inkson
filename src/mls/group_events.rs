//! MLS group-lifecycle event construction: `ak.mls.genesis` for a creator
//! group and `ak.mls.commit` (self-update / add / remove) with the
//! governance binding, for any effective scope (Realm-wide or Circle).
//!
//! Pure move from `views/kanban/mls_encrypt.rs` (zero
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
    let Ok(actor) = crate::mls_api_helpers::local_account_actor_id(actor_id) else {
        return false;
    };
    if garth::realm_authority_root_controller_for_realm(realm_tree_projections, realm_id)
        == Some(actor.clone())
    {
        return true;
    }
    let Some(projection) = realm_tree_projections.get(realm_id) else {
        return false;
    };
    crate::realm_tree::projected_state_event_values(projection).any(|event| {
        event.get("kind").and_then(Value::as_str)
            == Some(arkret_sdk::EventKind::RealmCreate.as_str())
            && event
                .get("actor_id")
                .cloned()
                .and_then(|value| serde_json::from_value::<arkret_sdk::ActorId>(value).ok())
                .as_ref()
                == Some(&actor)
    })
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

#[cfg(test)]
mod creator_authority_tests {
    use super::*;

    #[test]
    fn creator_gate_binds_station_and_actor_id_variant() {
        let principal = "ak:did_core:web:creator.example";
        let local = crate::mls_api_helpers::local_account_actor_id(principal).unwrap();
        let mut remote = local.as_account_id().unwrap().clone();
        remote.station_id = "ak:did_core:web:remote-station.example".parse().unwrap();
        let service = arkret_sdk::ActorId::service(local.signing_principal_id().clone());
        for (controller, expected) in [
            (local, true),
            (arkret_sdk::ActorId::account(remote), false),
            (service, false),
        ] {
            let projections = std::collections::BTreeMap::from([(
                "realm".to_owned(),
                serde_json::json!({
                    "state": {"events": [{"kind": "ak.realm.create", "actor_id": controller}]}
                }),
            )]);
            assert_eq!(
                projected_realm_creator_matches_actor(&projections, "realm", principal),
                expected
            );
        }
    }
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
    fresh_summary: Option<&crate::mls::runtime::InitialMlsCheckpointSummary>,
) -> Result<Option<crate::operation::LocalOperation>, String> {
    build_creator_mls_genesis_event_for_effective_scope(
        state_store,
        realm_id,
        None,
        actor_id,
        fresh_summary,
    )
}

pub(crate) fn build_creator_mls_genesis_event_for_effective_scope(
    state_store: &mut LocalStateStore,
    realm_id: &str,
    circle_id: Option<&str>,
    actor_id: &str,
    fresh_summary: Option<&crate::mls::runtime::InitialMlsCheckpointSummary>,
) -> Result<Option<crate::operation::LocalOperation>, String> {
    build_creator_mls_genesis_event_for_effective_scope_with_binding(
        state_store,
        realm_id,
        circle_id,
        actor_id,
        fresh_summary,
        None,
    )
}

pub(crate) fn build_creator_mls_genesis_event_for_effective_scope_with_binding(
    state_store: &mut LocalStateStore,
    realm_id: &str,
    circle_id: Option<&str>,
    actor_id: &str,
    fresh_summary: Option<&crate::mls::runtime::InitialMlsCheckpointSummary>,
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
        && let Some(snapshot) = state_store.mls_checkpoint_for_scope(&effective_scope)
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
    let payload = crate::mls::runtime::build_mls_genesis_payload(summary, &governance_binding)
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

// pub(crate): the realm_admin epoch-rotation button reuses
// this builder to wrap a forced `self_update_commit` into the canonical
// `ak.mls.commit` event with the governance binding.
pub(crate) async fn mls_commit_event_from_store(
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
    .await
}

pub(crate) async fn mls_commit_event_from_store_for_effective_scope(
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
    .await
}

pub(crate) async fn mls_commit_event_from_store_for_effective_scope_with_proposal_refs(
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
    .await
}

pub(crate) async fn mls_commit_event_from_store_for_sidecar_scope(
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
    .await
}

/// Everything an `ak.mls.commit` needs from the local store, read once.
///
/// Held as owned values so the commit can be built later, after the proposals it
/// references have been authored — the store cannot be borrowed across that
/// boundary.
#[derive(Clone)]
pub(crate) struct MlsCommitBasis {
    realm_id: String,
    actor_id: String,
    effective_scope: arkret_sdk::ScopeRef,
    prev_epoch: u64,
    base_group_state_ref: arkret_sdk::EventId,
    governance_binding: arkret_sdk::MlsGovernanceBindingPayload,
    commit_envelope: arkret_sdk::MlsCommitEnvelope,
    preconditions: Vec<crate::operation::Precondition>,
}

impl MlsCommitBasis {
    pub(crate) fn governance_binding(&self) -> &arkret_sdk::MlsGovernanceBindingPayload {
        &self.governance_binding
    }

    /// Build the commit once the proposals it references are authored.
    pub(crate) fn build(
        self,
        proposal_refs: Vec<arkret_sdk::EventId>,
    ) -> Result<crate::operation::LocalOperation, String> {
        let payload = arkret_sdk::MlsCommitPayload::new(
            self.base_group_state_ref.to_string(),
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

pub(crate) async fn mls_commit_basis_from_store(
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

    let base_group_state_ref = state_store.mls_group_state_ref_for_scope(
        &effective_scope,
        commit_envelope.group_id.as_str(),
        prev_epoch,
    )?;
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
    let previous_epoch_head = crate::mls::governance_proof::station_mls_epoch_head(
        state_store,
        &effective_scope,
        commit_envelope.group_id.as_str(),
    )
    .await?;
    let preconditions = garth::mls_commit_preconditions(
        &effective_scope,
        commit_envelope.group_id.as_str(),
        prev_epoch,
        &base_group_state_ref,
        previous_governance_binding,
        previous_epoch_head,
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

async fn mls_commit_event_from_store_for_effective_scope_with_options(
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
    )
    .await?
    .build(proposal_refs)
}
