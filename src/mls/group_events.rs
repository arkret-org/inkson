//! MLS group-lifecycle Event construction: `ak.mls.genesis` for a creator
//! group and `ak.mls.commit` for any effective scope (Realm-wide, Circle or
//! Sidecar), plus the atomic commit submission that carries the Welcome
//! deliveries the same transition produced.
//!
//! These two are the only shared MLS Events. Proposals travel inline in the
//! Commit bytes, and a Welcome is a producer-signed recipient delivery rather
//! than an Event, so it never gets its own commit.

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

/// Build the `ak.mls.genesis` Event for a creator group that has local
/// epoch-zero material but no accepted Genesis yet.
///
/// Returns `None` when this scope already has an accepted Genesis whose exact
/// Event reference is available, or when there is no local epoch-zero material
/// to describe. An emitted marker without that reference is not a completed
/// bootstrap: rebuilding is safe because the submit path resolves a duplicate
/// to the already-accepted Event.
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
    build_creator_mls_genesis_event_for_scope(
        state_store,
        &effective_scope_for(realm_id, circle_id, None)?,
        realm_id,
        actor_id,
        fresh_summary,
    )
}

pub(crate) fn build_creator_mls_genesis_event_for_sidecar_scope(
    state_store: &mut LocalStateStore,
    realm_id: &str,
    sidecar_id: &arkret_sdk::SidecarId,
    actor_id: &str,
    fresh_summary: Option<&crate::mls::runtime::InitialMlsCheckpointSummary>,
) -> Result<Option<crate::operation::LocalOperation>, String> {
    build_creator_mls_genesis_event_for_scope(
        state_store,
        &effective_scope_for(realm_id, None, Some(sidecar_id))?,
        realm_id,
        actor_id,
        fresh_summary,
    )
}

fn build_creator_mls_genesis_event_for_scope(
    state_store: &mut LocalStateStore,
    effective_scope: &arkret_sdk::ScopeRef,
    realm_id: &str,
    actor_id: &str,
    fresh_summary: Option<&crate::mls::runtime::InitialMlsCheckpointSummary>,
) -> Result<Option<crate::operation::LocalOperation>, String> {
    if state_store.mls_genesis_emitted_for_scope(effective_scope)
        && let Some(snapshot) = state_store.mls_checkpoint_for_scope(effective_scope)
        && state_store
            .mls_group_state_ref_for_scope(effective_scope, &snapshot.group_id, snapshot.epoch)
            .is_ok()
    {
        return Ok(None);
    }
    // Genesis describes the group at epoch zero, and only durable epoch-zero
    // material can produce a contract-correct one. A group without an accepted
    // Genesis is unusable and must stay fail-closed rather than be described
    // from a later epoch.
    let Some(summary) = fresh_summary else {
        return Ok(None);
    };
    if summary.realm_id != realm_id {
        return Ok(None);
    }

    let governance_binding = crate::mls::governance_proof::genesis_binding(effective_scope)?;
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
    .effective_scope(effective_scope.clone())
    .build_sdk_event("inkson")
    .map(Some)
    .map_err(|err| format!("MLS genesis SDK Event conversion failed: {err}"))?;
    Ok(event)
}

fn effective_scope_for(
    realm_id: &str,
    circle_id: Option<&str>,
    sidecar_id: Option<&arkret_sdk::SidecarId>,
) -> Result<arkret_sdk::ScopeRef, String> {
    let realm = arkret_sdk::RealmId::new(trim_realm_id(realm_id))
        .map_err(|error| format!("invalid MLS Realm id: {error}"))?;
    if let Some(sidecar_id) = sidecar_id {
        return Ok(arkret_sdk::ScopeRef::Sidecar {
            realm_id: realm,
            sidecar_id: sidecar_id.clone(),
        });
    }
    match circle_id.map(str::trim).filter(|value| !value.is_empty()) {
        Some(circle_id) => circle_effective_scope(realm_id, circle_id),
        None => Ok(arkret_sdk::ScopeRef::Realm { realm_id: realm }),
    }
}

/// Everything an `ak.mls.commit` needs from the local store, read once.
///
/// Held as owned values so the Event can be built after the group state it
/// describes has been staged; the store cannot be borrowed across that
/// boundary.
#[derive(Clone)]
pub(crate) struct MlsCommitBasis {
    realm_id: String,
    actor_id: String,
    effective_scope: arkret_sdk::ScopeRef,
    base_group_state_ref: arkret_sdk::EventId,
    governance_binding: arkret_sdk::MlsGovernanceBindingPayload,
    commit_envelope: arkret_sdk::MlsCommitEnvelope,
    covers_key_access_revision: u64,
}

impl MlsCommitBasis {
    pub(crate) fn governance_binding(&self) -> &arkret_sdk::MlsGovernanceBindingPayload {
        &self.governance_binding
    }

    pub(crate) fn effective_scope(&self) -> &arkret_sdk::ScopeRef {
        &self.effective_scope
    }

    /// Build the commit Event. Proposals are carried inside the Commit bytes,
    /// so nothing here waits on separately authored Events.
    pub(crate) fn build(self) -> Result<crate::operation::LocalOperation, String> {
        let payload = arkret_sdk::MlsCommitPayload::new(
            self.base_group_state_ref,
            self.covers_key_access_revision,
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
    sidecar_id: Option<&arkret_sdk::SidecarId>,
) -> Result<MlsCommitBasis, String> {
    // `previous_epoch` MUST be the SDK group's PRE-commit epoch so the
    // `next_epoch == previous_epoch + 1` invariant holds by construction.
    // `commit_envelope.epoch` is the POST-commit epoch (the authoring call
    // merges the pending commit before reading it), so the pre-commit epoch is
    // exactly one less. Deriving it from any refreshed view instead drifts
    // whenever the local group has advanced past the last observed epoch.
    let previous_epoch = commit_envelope.epoch.saturating_sub(1);
    let effective_scope = effective_scope_for(realm_id, circle_id, sidecar_id)?;
    let base_group_state_ref = state_store.mls_group_state_ref_for_scope(
        &effective_scope,
        commit_envelope.group_id.as_str(),
        previous_epoch,
    )?;
    let governance_binding = crate::mls::governance_proof::binding_for_transition(
        state_store,
        &effective_scope,
        &commit_envelope.group_id,
        previous_epoch,
        commit_envelope.epoch,
    )?;
    Ok(MlsCommitBasis {
        realm_id: realm_id.to_owned(),
        actor_id: actor_id.to_owned(),
        effective_scope,
        base_group_state_ref,
        covers_key_access_revision: governance_binding.key_access_revision(),
        governance_binding,
        commit_envelope: commit_envelope.clone(),
    })
}

pub(crate) fn mls_commit_event_from_store(
    state_store: &LocalStateStore,
    realm_id: &str,
    actor_id: &str,
    commit_envelope: &arkret_sdk::MlsCommitEnvelope,
) -> Result<crate::operation::LocalOperation, String> {
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
) -> Result<crate::operation::LocalOperation, String> {
    mls_commit_basis_from_store(
        state_store,
        realm_id,
        circle_id,
        actor_id,
        commit_envelope,
        None,
    )?
    .build()
}

pub(crate) fn mls_commit_event_from_store_for_sidecar_scope(
    state_store: &LocalStateStore,
    realm_id: &str,
    actor_id: &str,
    commit_envelope: &arkret_sdk::MlsCommitEnvelope,
    sidecar_id: &arkret_sdk::SidecarId,
) -> Result<crate::operation::LocalOperation, String> {
    mls_commit_basis_from_store(
        state_store,
        realm_id,
        None,
        actor_id,
        commit_envelope,
        Some(sidecar_id),
    )?
    .build()
}

#[cfg(test)]
mod tests {
    use super::*;

    const REALM: &str = "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19";
    const CIRCLE: &str = "ak:circle:ASeIBHNVQyeIcU4aBIt2t2BF_ikuVMH0kNru_HgO_gG1";

    #[test]
    fn an_effective_scope_names_exactly_one_group_partition() {
        let realm = effective_scope_for(REALM, None, None).unwrap();
        let circle = effective_scope_for(REALM, Some(CIRCLE), None).unwrap();
        let sidecar = effective_scope_for(
            REALM,
            Some(CIRCLE),
            Some(
                &arkret_sdk::SidecarId::new(
                    "ak:sidecar:AZEvldDJcWI9IRHqP2BMibDDfc59Ax_LwrbsrQmeD6Ml".to_owned(),
                )
                .unwrap(),
            ),
        )
        .unwrap();
        assert!(matches!(realm, arkret_sdk::ScopeRef::Realm { .. }));
        assert!(matches!(circle, arkret_sdk::ScopeRef::Circle { .. }));
        // A Sidecar binding wins over a Circle hint: a Sidecar group is its own
        // scope with its own independent commit stream.
        assert!(matches!(sidecar, arkret_sdk::ScopeRef::Sidecar { .. }));
        assert_ne!(
            realm.canonical_mls_group_id().unwrap(),
            circle.canonical_mls_group_id().unwrap()
        );
    }
}
