//! Realm-global planning for minimal-metadata endpoint replacement.
//!
//! The plan is deliberately local and contains no invented Welcome carrier.
//! It fences the old actor across every accepted Realm/Circle group and makes
//! Circle Add conditional on an explicit post-parent-join reactivation.

use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PairwiseReplacementGroup {
    pub effective_scope: arkret_sdk::ScopeRef,
    pub mls_group_id: String,
    pub base_epoch: u64,
    pub base_group_state_ref: arkret_sdk::EventId,
    pub action: PairwiseReplacementAction,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PairwiseReplacementAction {
    /// Realm group replacement or a Circle with an explicit reactivation.
    RemoveThenAdd {
        circle_reactivation_ref: Option<arkret_sdk::EventId>,
    },
    /// Parent rejoin never revives a Circle. Remove the old actor, then wait
    /// for an explicit Circle membership reactivation before constructing Add.
    RemoveThenAwaitCircleReactivation,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PairwiseReplacementPlan {
    pub realm_id: arkret_sdk::RealmId,
    pub previous_actor_id: arkret_sdk::DidCoreId,
    pub replacement_actor_id: arkret_sdk::DidCoreId,
    pub groups: Vec<PairwiseReplacementGroup>,
}

/// Build the complete local group plan for one Realm-global replacement.
///
/// `circle_id` is accepted only to reject a Circle-local rotation at the API
/// boundary. Callers provide accepted Circle reactivation Event refs; their
/// absence is a closed remove-only wait state, never an implicit revival.
pub fn plan_pairwise_replacement(
    state_store: &crate::state::LocalStateStore,
    realm_id: arkret_sdk::RealmId,
    circle_id: Option<arkret_sdk::CircleId>,
    previous_actor_id: arkret_sdk::DidCoreId,
    replacement_actor_id: arkret_sdk::DidCoreId,
    circle_reactivations: &BTreeMap<arkret_sdk::CircleId, arkret_sdk::EventId>,
) -> Result<PairwiseReplacementPlan, String> {
    let rotation_scope = match circle_id {
        Some(circle_id) => arkret_policy::history_access::PairwiseRotationScope::CircleLocal {
            realm_id: realm_id.clone(),
            circle_id,
        },
        None => arkret_policy::history_access::PairwiseRotationScope::Realm {
            realm_id: realm_id.clone(),
        },
    };
    arkret_policy::history_access::validate_pairwise_rotation(&rotation_scope)
        .map_err(str::to_owned)?;
    if previous_actor_id == replacement_actor_id {
        return Err("pairwise replacement must change the Realm actor incarnation".to_owned());
    }

    let accepted = state_store.accepted_mls_artifact_snapshot();
    let mut groups = Vec::new();
    let mut seen = BTreeSet::new();
    for event_id in accepted.snapshot.ready_groups.values() {
        let artifact = accepted.snapshot.artifacts.get(event_id).ok_or_else(|| {
            "accepted MLS ready group references a missing replacement base".to_owned()
        })?;
        let scope = accepted_event_scope(&artifact.event)?;
        if scope.realm_id_opt() != Some(&realm_id) {
            continue;
        }
        if !matches!(
            scope,
            arkret_sdk::ScopeRef::Realm { .. } | arkret_sdk::ScopeRef::Circle { .. }
        ) {
            continue;
        }
        let coordinate = (
            scope
                .canonical_effective_scope_key_bytes()
                .map_err(|error| error.to_string())?,
            artifact.snapshot.group_id.clone(),
        );
        if !seen.insert(coordinate) {
            return Err(
                "pairwise replacement found duplicate accepted group coordinates".to_owned(),
            );
        }
        let action = match &scope {
            arkret_sdk::ScopeRef::Realm { .. } => PairwiseReplacementAction::RemoveThenAdd {
                circle_reactivation_ref: None,
            },
            arkret_sdk::ScopeRef::Circle { circle_id, .. } => circle_reactivations
                .get(circle_id)
                .cloned()
                .map(|event_id| PairwiseReplacementAction::RemoveThenAdd {
                    circle_reactivation_ref: Some(event_id),
                })
                .unwrap_or(PairwiseReplacementAction::RemoveThenAwaitCircleReactivation),
            _ => unreachable!("scope was restricted to Realm/Circle"),
        };
        groups.push(PairwiseReplacementGroup {
            effective_scope: scope,
            mls_group_id: artifact.snapshot.group_id.clone(),
            base_epoch: artifact.snapshot.epoch,
            base_group_state_ref: artifact.winning_transition_ref.clone(),
            action,
        });
    }
    groups.sort_by(|left, right| {
        left.effective_scope
            .canonical_effective_scope_key_bytes()
            .unwrap_or_default()
            .cmp(
                &right
                    .effective_scope
                    .canonical_effective_scope_key_bytes()
                    .unwrap_or_default(),
            )
    });
    if !groups
        .iter()
        .any(|group| matches!(group.effective_scope, arkret_sdk::ScopeRef::Realm { .. }))
    {
        return Err("pairwise replacement requires an accepted Realm MLS group".to_owned());
    }
    Ok(PairwiseReplacementPlan {
        realm_id,
        previous_actor_id,
        replacement_actor_id,
        groups,
    })
}

fn accepted_event_scope(event: &arkret_sdk::Event) -> Result<arkret_sdk::ScopeRef, String> {
    let payload = serde_json::to_value(&event.payload).map_err(|error| error.to_string())?;
    match event.kind {
        arkret_sdk::EventKind::MlsGenesis => {
            serde_json::from_value::<arkret_sdk::MlsGenesisPayload>(payload)
                .map(|payload| payload.effective_scope)
                .map_err(|error| error.to_string())
        }
        arkret_sdk::EventKind::MlsCommit => {
            serde_json::from_value::<arkret_sdk::MlsCommitPayload>(payload)
                .map(|payload| payload.governance_binding().effective_scope().clone())
                .map_err(|error| error.to_string())
        }
        arkret_sdk::EventKind::MlsWelcome => {
            serde_json::from_value::<arkret_sdk::MlsWelcomePayload>(payload)
                .map(|payload| payload.governance_binding.effective_scope().clone())
                .map_err(|error| error.to_string())
        }
        _ => Err("pairwise replacement base is not an MLS artifact".to_owned()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn circle_local_rotation_is_rejected_before_state_lookup() {
        let realm_id = arkret_sdk::RealmId::new(
            "ak:realm:AfjSiYTXJZS-0ifVfy1f_uzsmJIBjDyN11_-dxnne50e".to_owned(),
        )
        .unwrap();
        let circle_id = arkret_sdk::CircleId::new(
            "ak:circle:ARIqxK3jWXYxpb544UphWaZm_ti9wclu9_0-eSuyZ2e_".to_owned(),
        )
        .unwrap();
        let previous = arkret_sdk::DidCoreId::new("ak:did_core:key:z6Mkold".to_owned()).unwrap();
        let replacement = arkret_sdk::DidCoreId::new("ak:did_core:key:z6Mknew".to_owned()).unwrap();
        let error = plan_pairwise_replacement(
            &crate::state::LocalStateStore::default(),
            realm_id,
            Some(circle_id),
            previous,
            replacement,
            &BTreeMap::new(),
        )
        .unwrap_err();
        assert!(error.contains("Circle-locally"), "{error}");
    }
}
