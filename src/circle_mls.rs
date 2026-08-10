use crate::secure_key_store::SecureKeyStore;
use crate::state::LocalStateStore;

#[derive(Clone, Debug)]
pub struct CircleScopeRotateDraft {
    pub events: Vec<arkret_sdk::Event>,
    pub post_commit_snapshot: crate::mls::persistence::MlsSnapshotEnvelope,
    pub removed_leaves: Vec<u32>,
    pub removed_principals: Vec<String>,
}

#[derive(Clone, Debug, Default)]
pub struct CircleScopeRotateDrainOutcome {
    pub submitted: Vec<arkret_sdk::CircleScopeRotateOutcome>,
    pub skipped: Vec<CircleScopeRotateDrainSkip>,
    pub failed: Vec<CircleScopeRotateDrainFailure>,
}

#[derive(Clone, Debug)]
pub struct CircleScopeRotateDrainSkip {
    pub circle_id: String,
    pub target_principal_id: Option<String>,
    pub reason: String,
}

#[derive(Clone, Debug)]
pub struct CircleScopeRotateDrainFailure {
    pub circle_id: String,
    pub target_principal_id: String,
    pub reason: String,
}

fn circle_effective_scope(
    realm_id: &str,
    circle_id: &str,
) -> Result<arkret_wire::ScopeRef, String> {
    Ok(arkret_wire::ScopeRef::Circle {
        realm_id: arkret_sdk::RealmId::new(realm_id.to_owned())
            .map_err(|err| format!("invalid Circle scope Realm id: {err:?}"))?,
        circle_id: arkret_sdk::CircleId::new(circle_id.to_owned())
            .map_err(|err| format!("invalid Circle scope Circle id: {err:?}"))?,
    })
}

fn build_remove_proposal_event(
    realm_id: &str,
    effective_scope: Option<&arkret_sdk::ScopeRef>,
    actor_id: &str,
    target_principal_id: &str,
    proposal: &arkret_sdk::MlsProposalEnvelope,
    governance_binding: Option<arkret_sdk::MlsGovernanceBindingPayload>,
) -> Result<arkret_sdk::Event, String> {
    let target_principal = crate::mls_api_helpers::principal_core_id(target_principal_id)
        .map_err(|err| format!("invalid remove target principal id: {err:?}"))?;
    let proposal_payload = arkret_sdk::MlsProposalPayload {
        mls_group_id: arkret_sdk::MlsGroupId::new(proposal.group_id.clone())
            .map_err(|err| format!("invalid MLS group id: {err}"))?,
        base_epoch: proposal.epoch,
        proposal_type: arkret_sdk::MlsProposalType::Remove,
        proposal_message_ref: None,
        proposal_digest: Some(proposal.proposal_digest.clone()),
        target_principal_id: Some(target_principal),
        target_device_id: None,
        governance_binding,
    };
    let mut event = crate::operation::ak_ops::mls_proposal_with_governance(
        realm_id,
        actor_id,
        &proposal.group_id,
        &proposal_payload,
    )
    .map_err(|err| format!("MLS proposal payload failed: {err}"))?
    .build_sdk_event("inkson")
    .map_err(|err| format!("MLS proposal SDK Event conversion failed: {err}"))?;
    if let Some(effective_scope) = effective_scope {
        event.scope_ref = effective_scope.clone();
        event.event_id = event
            .derive_event_id()
            .map_err(|error| format!("derive scoped MLS proposal Event id: {error}"))?;
    }
    Ok(event)
}

fn build_remove_scope_rotate_draft(
    state_store: &LocalStateStore,
    secure_store: &dyn SecureKeyStore,
    realm_id: &str,
    circle_id: Option<&str>,
    actor_id: &str,
    device_id: &str,
    target_principal_ids: &[&str],
    revocation_membership_frontier: &[arkret_sdk::EventId],
    sidecar_binding: Option<arkret_sdk::SidecarMlsBinding>,
) -> Result<CircleScopeRotateDraft, String> {
    let realm = arkret_sdk::RealmId::new(realm_id.to_owned())
        .map_err(|error| format!("invalid MLS Realm id: {error}"))?;
    let effective_scope = match sidecar_binding.as_ref() {
        Some(binding) => arkret_sdk::ScopeRef::Sidecar {
            realm_id: realm.clone(),
            sidecar_id: binding.sidecar_id.clone(),
        },
        None => match circle_id {
            Some(circle_id) => circle_effective_scope(realm_id, circle_id)?,
            None => arkret_sdk::ScopeRef::Realm { realm_id: realm },
        },
    };
    let (remove, post_commit_snapshot, previous_governance_binding) =
        crate::mls::runtime::build_mls_remove_members_commit_for_effective_scope_with_sidecar_binding(
            state_store,
            secure_store,
            realm_id,
            circle_id,
            actor_id,
            device_id,
            target_principal_ids,
            revocation_membership_frontier,
            sidecar_binding.clone(),
        )
        .map_err(|err| err.user_message())?;
    if remove.proposals.is_empty() {
        return Err("OpenMLS remove did not produce durable proposal artifacts".to_owned());
    }
    if remove.proposals.len() != remove.removed_principals.len() {
        return Err(
            "OpenMLS remove proposal artifacts do not align with removed principals".to_owned(),
        );
    }
    let mut events = Vec::with_capacity(remove.proposals.len().saturating_add(1));
    let mut proposal_refs = Vec::with_capacity(remove.proposals.len());
    let request = crate::mls::governance_proof::proof_request_for_scope(
        state_store,
        effective_scope.clone(),
        remove.commit.group_id.clone(),
        remove.commit.epoch.saturating_sub(1),
        remove.commit.epoch,
    )?;
    // Remove proposals and their commit are governed as one epoch transition,
    // so every durable proposal must carry the same verified binding.
    let proposal_governance_binding =
        crate::mls::governance_proof::cached_verified_binding(state_store, &request)?;
    if let Some(sidecar_binding) = sidecar_binding.as_ref() {
        if proposal_governance_binding.sidecar_binding() != Some(sidecar_binding) {
            return Err(
                "verified Sidecar MLS binding differs from the accepted Sidecar view".to_owned(),
            );
        }
    }
    for (proposal, removed_principal) in remove
        .proposals
        .iter()
        .zip(remove.removed_principals.iter())
    {
        let proposal_event = build_remove_proposal_event(
            realm_id,
            Some(&effective_scope),
            actor_id,
            removed_principal.as_str(),
            proposal,
            Some(proposal_governance_binding.clone()),
        )?;
        proposal_refs.push(proposal_event.event_id.clone());
        events.push(proposal_event);
    }
    let commit_event = if let Some(sidecar_binding) = sidecar_binding {
        crate::mls::group_events::mls_commit_event_from_store_for_sidecar_scope_with_proposal_refs(
            state_store,
            realm_id,
            actor_id,
            &remove.commit,
            &previous_governance_binding,
            proposal_refs,
            sidecar_binding,
        )?
    } else {
        crate::mls::group_events::mls_commit_event_from_store_for_effective_scope_with_proposal_refs(
            state_store,
            realm_id,
            circle_id,
            actor_id,
            &remove.commit,
            &previous_governance_binding,
            proposal_refs,
        )?
    };
    events.push(commit_event);
    Ok(CircleScopeRotateDraft {
        events,
        post_commit_snapshot,
        removed_leaves: remove.removed_leaves,
        removed_principals: remove
            .removed_principals
            .into_iter()
            .map(|did| did.to_string())
            .collect(),
    })
}

pub fn build_sidecar_remove_scope_rotate_draft(
    state_store: &LocalStateStore,
    secure_store: &dyn SecureKeyStore,
    realm_id: &str,
    actor_id: &str,
    device_id: &str,
    target_principal_id: &str,
    revocation_membership_frontier: &[arkret_sdk::EventId],
    sidecar_binding: arkret_sdk::SidecarMlsBinding,
) -> Result<CircleScopeRotateDraft, String> {
    build_remove_scope_rotate_draft(
        state_store,
        secure_store,
        realm_id,
        None,
        actor_id,
        device_id,
        &[target_principal_id],
        revocation_membership_frontier,
        Some(sidecar_binding),
    )
}

pub fn build_realm_remove_scope_rotate_draft(
    state_store: &LocalStateStore,
    secure_store: &dyn SecureKeyStore,
    realm_id: &str,
    actor_id: &str,
    device_id: &str,
    target_principal_id: &str,
    revocation_membership_frontier: &[arkret_sdk::EventId],
) -> Result<CircleScopeRotateDraft, String> {
    build_realm_remove_members_scope_rotate_draft(
        state_store,
        secure_store,
        realm_id,
        actor_id,
        device_id,
        &[target_principal_id],
        revocation_membership_frontier,
    )
}

pub fn build_realm_remove_members_scope_rotate_draft(
    state_store: &LocalStateStore,
    secure_store: &dyn SecureKeyStore,
    realm_id: &str,
    actor_id: &str,
    device_id: &str,
    target_principal_ids: &[&str],
    revocation_membership_frontier: &[arkret_sdk::EventId],
) -> Result<CircleScopeRotateDraft, String> {
    build_remove_scope_rotate_draft(
        state_store,
        secure_store,
        realm_id,
        None,
        actor_id,
        device_id,
        target_principal_ids,
        revocation_membership_frontier,
        None,
    )
}

pub fn build_circle_remove_scope_rotate_draft(
    state_store: &LocalStateStore,
    secure_store: &dyn SecureKeyStore,
    realm_id: &str,
    circle_id: &str,
    actor_id: &str,
    device_id: &str,
    target_principal_id: &str,
    revocation_membership_frontier: &[arkret_sdk::EventId],
) -> Result<CircleScopeRotateDraft, String> {
    build_circle_remove_members_scope_rotate_draft(
        state_store,
        secure_store,
        realm_id,
        circle_id,
        actor_id,
        device_id,
        &[target_principal_id],
        revocation_membership_frontier,
    )
}

pub fn build_circle_remove_members_scope_rotate_draft(
    state_store: &LocalStateStore,
    secure_store: &dyn SecureKeyStore,
    realm_id: &str,
    circle_id: &str,
    actor_id: &str,
    device_id: &str,
    target_principal_ids: &[&str],
    revocation_membership_frontier: &[arkret_sdk::EventId],
) -> Result<CircleScopeRotateDraft, String> {
    let circle = circle_id.trim();
    if circle.is_empty() {
        return Err("circle_id is required for Circle MLS scope rotate".to_owned());
    }
    build_remove_scope_rotate_draft(
        state_store,
        secure_store,
        realm_id,
        Some(circle),
        actor_id,
        device_id,
        target_principal_ids,
        revocation_membership_frontier,
        None,
    )
}

pub async fn submit_circle_scope_rotate_draft(
    api: &crate::transport::TransportClient,
    state_store: &mut LocalStateStore,
    realm_id: &str,
    circle_id: &str,
    draft: CircleScopeRotateDraft,
) -> anyhow::Result<arkret_sdk::CircleScopeRotateOutcome> {
    let outcome = crate::transport::circle::submit_circle_scope_rotate_events(
        &api.event_submitter()?,
        circle_id,
        &draft.events,
        None,
    )
    .await?;
    let accepted_commit_ref = draft
        .events
        .iter()
        .find(|event| event.kind.as_str() == "ak.mls.commit")
        .map(|event| event.event_id.clone())
        .ok_or_else(|| anyhow::anyhow!("Circle scope rotate has no MLS commit Event"))?;
    state_store
        .record_mls_group_state_ref_for_effective_scope(
            realm_id.to_owned(),
            Some(circle_id),
            draft.post_commit_snapshot.group_id.as_str(),
            draft.post_commit_snapshot.epoch,
            accepted_commit_ref,
        )
        .map_err(anyhow::Error::msg)?;
    state_store.save_mls_snapshot_for_effective_scope(
        realm_id.to_owned(),
        Some(circle_id),
        draft.post_commit_snapshot,
    );
    Ok(outcome)
}

pub async fn drain_circle_scope_rotate_obligations(
    api: &crate::transport::TransportClient,
    state_store: &mut LocalStateStore,
    secure_store: &dyn SecureKeyStore,
    realm_id: &str,
    actor_id: &str,
    device_id: &str,
) -> anyhow::Result<CircleScopeRotateDrainOutcome> {
    let circles = crate::transport::circle::list_circles(&api.sdk_http_client()?, realm_id).await?;
    let mut outcome = CircleScopeRotateDrainOutcome::default();
    for circle in circles.circles {
        let circle_id = circle.circle_id.to_string();
        if circle.state != arkret_sdk::CircleState::Active {
            outcome.skipped.push(CircleScopeRotateDrainSkip {
                circle_id,
                target_principal_id: None,
                reason: "circle_not_active".to_owned(),
            });
            continue;
        }
        if circle.encryption_profile != arkret_sdk::EncryptionProfile::MlsRfc9420 {
            outcome.skipped.push(CircleScopeRotateDrainSkip {
                circle_id,
                target_principal_id: None,
                reason: "circle_not_mls_backed".to_owned(),
            });
            continue;
        }
        if circle.pending_mls_removals.is_empty() {
            continue;
        }
        if state_store
            .mls_snapshot_for_effective_scope(realm_id, Some(&circle_id))
            .is_none()
        {
            outcome.skipped.push(CircleScopeRotateDrainSkip {
                circle_id,
                target_principal_id: None,
                reason: "missing_circle_mls_snapshot".to_owned(),
            });
            continue;
        }
        let mut target_principal_ids = Vec::new();
        let mut revocation_membership_frontier = Vec::new();
        let mut missing_frontier = false;
        for target in circle.pending_mls_removals {
            let target_principal_id = target.principal_id().to_string();
            if target.membership_frontier().is_empty() {
                missing_frontier = true;
                outcome.skipped.push(CircleScopeRotateDrainSkip {
                    circle_id: circle_id.clone(),
                    target_principal_id: Some(target_principal_id),
                    reason: "missing_removal_membership_frontier".to_owned(),
                });
                continue;
            }
            target_principal_ids.push(target_principal_id);
            revocation_membership_frontier.extend(target.membership_frontier().iter().cloned());
        }
        // The server validates a scope rotation against every pending Remove
        // obligation in that scope. Never submit a partial batch.
        if missing_frontier || target_principal_ids.is_empty() {
            continue;
        }
        revocation_membership_frontier.sort();
        revocation_membership_frontier.dedup();
        let target_refs: Vec<&str> = target_principal_ids.iter().map(String::as_str).collect();
        let draft = match build_circle_remove_members_scope_rotate_draft(
            state_store,
            secure_store,
            realm_id,
            &circle_id,
            actor_id,
            device_id,
            &target_refs,
            &revocation_membership_frontier,
        ) {
            Ok(draft) => draft,
            Err(reason) => {
                for target_principal_id in target_principal_ids {
                    outcome.failed.push(CircleScopeRotateDrainFailure {
                        circle_id: circle_id.clone(),
                        target_principal_id,
                        reason: reason.clone(),
                    });
                }
                continue;
            }
        };
        match submit_circle_scope_rotate_draft(api, state_store, realm_id, &circle_id, draft).await
        {
            Ok(submitted) => outcome.submitted.push(submitted),
            Err(err) => {
                let reason = err.to_string();
                for target_principal_id in target_principal_ids {
                    outcome.failed.push(CircleScopeRotateDrainFailure {
                        circle_id: circle_id.clone(),
                        target_principal_id,
                        reason: reason.clone(),
                    });
                }
            }
        }
    }
    Ok(outcome)
}
