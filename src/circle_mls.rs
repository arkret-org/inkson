use serde_json::json;

use crate::local_state::LocalStateStore;
use crate::secure_key_store::SecureKeyStore;

#[derive(Clone, Debug)]
pub struct CircleScopeRotateDraft {
    pub events: Vec<cokret_sdk::Event>,
    pub post_commit_snapshot: crate::mls::persistence::MlsSnapshotEnvelope,
    pub removed_leaves: Vec<u32>,
    pub removed_principals: Vec<String>,
}

#[derive(Clone, Debug, Default)]
pub struct CircleScopeRotateDrainOutcome {
    pub submitted: Vec<cokret_sdk::CircleScopeRotateOutcome>,
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
) -> Result<cokret_sdk::models::EffectiveScope, String> {
    Ok(cokret_sdk::models::EffectiveScope::Circle {
        realm_id: cokret_sdk::RealmId::new(realm_id.to_owned())
            .map_err(|err| format!("invalid Circle scope Realm id: {err:?}"))?,
        circle_id: cokret_sdk::CircleId::new(circle_id.to_owned())
            .map_err(|err| format!("invalid Circle scope Circle id: {err:?}"))?,
    })
}

fn build_circle_remove_proposal_event(
    realm_id: &str,
    circle_id: &str,
    actor_id: &str,
    target_principal_id: &str,
    proposal: &cokret_sdk::MlsProposalEnvelope,
) -> Result<cokret_sdk::Event, String> {
    let target_principal = cokret_sdk::Did::new(target_principal_id.to_owned())
        .map_err(|err| format!("invalid remove target principal id: {err:?}"))?;
    let proposal_payload = cokret_sdk::MlsProposalPayload {
        mls_group_id: proposal.group_id.clone(),
        base_epoch: proposal.epoch,
        proposal_type: json!(proposal.proposal_type),
        proposal_message_ref: None,
        proposal_digest: Some(proposal.proposal_digest.clone()),
        target_principal_id: Some(target_principal),
        target_device_id: None,
        governance_binding: None,
    };
    let mut event = crate::operation::ck_ops::mls_proposal_with_governance(
        realm_id,
        actor_id,
        &proposal.group_id,
        &proposal_payload,
    )
    .map_err(|err| format!("MLS proposal payload failed: {err}"))?
    .build_sdk_event("yougen")
    .map_err(|err| format!("MLS proposal SDK Event conversion failed: {err}"))?;
    event.effective_scope = Some(circle_effective_scope(realm_id, circle_id)?);
    Ok(event)
}

pub fn build_circle_remove_scope_rotate_draft(
    state_store: &LocalStateStore,
    secure_store: &dyn SecureKeyStore,
    realm_id: &str,
    circle_id: &str,
    actor_id: &str,
    device_id: &str,
    target_principal_id: &str,
) -> Result<CircleScopeRotateDraft, String> {
    let circle = circle_id.trim();
    if circle.is_empty() {
        return Err("circle_id is required for Circle MLS scope rotate".to_owned());
    }
    let (remove, post_commit_snapshot) =
        crate::mls::runtime::build_mls_remove_commit_for_effective_scope(
            state_store,
            secure_store,
            realm_id,
            Some(circle),
            actor_id,
            device_id,
            target_principal_id,
        )
        .map_err(|err| err.user_message())?;
    if remove.proposals.is_empty() {
        return Err("OpenMLS remove did not produce durable proposal artifacts".to_owned());
    }
    let mut events = Vec::with_capacity(remove.proposals.len().saturating_add(1));
    let mut proposal_refs = Vec::with_capacity(remove.proposals.len());
    for proposal in &remove.proposals {
        let proposal_event = build_circle_remove_proposal_event(
            realm_id,
            circle,
            actor_id,
            target_principal_id,
            proposal,
        )?;
        proposal_refs.push(proposal_event.event_id.clone());
        events.push(proposal_event);
    }
    let commit_event =
        crate::views::kanban::kanban_mls_commit_event_from_store_for_effective_scope_with_proposal_refs(
            state_store,
            realm_id,
            Some(circle),
            actor_id,
            &remove.commit,
            proposal_refs,
        )?;
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

pub async fn submit_circle_scope_rotate_draft(
    api: &crate::api::CokretApi,
    state_store: &mut LocalStateStore,
    realm_id: &str,
    circle_id: &str,
    draft: CircleScopeRotateDraft,
) -> anyhow::Result<cokret_sdk::CircleScopeRotateOutcome> {
    let outcome = api
        .submit_circle_scope_rotate_events(circle_id, &draft.events, None)
        .await?;
    if !outcome.accepted.is_empty() || !outcome.duplicate.is_empty() {
        state_store.save_mls_snapshot_for_effective_scope(
            realm_id.to_owned(),
            Some(circle_id),
            draft.post_commit_snapshot,
        );
    }
    Ok(outcome)
}

pub async fn drain_circle_scope_rotate_obligations(
    api: &crate::api::CokretApi,
    state_store: &mut LocalStateStore,
    secure_store: &dyn SecureKeyStore,
    realm_id: &str,
    actor_id: &str,
    device_id: &str,
) -> anyhow::Result<CircleScopeRotateDrainOutcome> {
    let circles = api.list_circles(realm_id).await?;
    let mut outcome = CircleScopeRotateDrainOutcome::default();
    for circle in circles.circles {
        let circle_id = circle.circle_id.to_string();
        if circle.state != cokret_sdk::CircleState::Active {
            outcome.skipped.push(CircleScopeRotateDrainSkip {
                circle_id,
                target_principal_id: None,
                reason: "circle_not_active".to_owned(),
            });
            continue;
        }
        if circle.encryption_profile != cokret_sdk::EncryptionProfile::MlsRfc9420 {
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
        for target in circle.pending_mls_removals {
            let target_principal_id = target.to_string();
            let draft = match build_circle_remove_scope_rotate_draft(
                state_store,
                secure_store,
                realm_id,
                &circle_id,
                actor_id,
                device_id,
                &target_principal_id,
            ) {
                Ok(draft) => draft,
                Err(reason) => {
                    outcome.failed.push(CircleScopeRotateDrainFailure {
                        circle_id: circle_id.clone(),
                        target_principal_id,
                        reason,
                    });
                    continue;
                }
            };
            match submit_circle_scope_rotate_draft(api, state_store, realm_id, &circle_id, draft)
                .await
            {
                Ok(submitted) => outcome.submitted.push(submitted),
                Err(err) => outcome.failed.push(CircleScopeRotateDrainFailure {
                    circle_id: circle_id.clone(),
                    target_principal_id,
                    reason: err.to_string(),
                }),
            }
        }
    }
    Ok(outcome)
}
