use crate::secure_key_store::SecureKeyStore;
use crate::state::LocalStateStore;

/// One-shot: the steps are consumed by authoring, so this plan is neither
/// `Clone` nor `Debug`.
pub struct CircleScopeRotateDraft {
    /// The remove proposals and their commit, in authoring order.
    ///
    /// The commit references the proposals by their FINAL `event_id`
    /// (`proposal_refs`), so it can only be built after they are authored.
    pub steps: Vec<crate::event_submit::EventUnitStep>,
    pub post_commit_snapshot: crate::mls::persistence::MlsSnapshotEnvelope,
    pub removed_leaves: Vec<u32>,
    pub removed_actors: Vec<arkret_sdk::ActorId>,
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
    target_actor_id: &arkret_sdk::ActorId,
    proposal: &arkret_sdk::MlsProposalEnvelope,
    governance_binding: arkret_sdk::MlsGovernanceBindingPayload,
) -> Result<crate::operation::LocalOperation, String> {
    let proposal_payload = arkret_sdk::MlsProposalPayload {
        mls_group_id: arkret_sdk::MlsGroupId::new(proposal.group_id.clone())
            .map_err(|err| format!("invalid MLS group id: {err}"))?,
        base_epoch: proposal.epoch,
        proposal_type: arkret_sdk::MlsProposalType::Remove,
        proposal_bytes_b64: proposal.proposal.clone(),
        proposal_digest: proposal.proposal_digest.clone(),
        target_actor_id: Some(target_actor_id.clone()),
        target_authorization_incarnation: None,
        governance_binding,
    };
    let mut builder = crate::operation::ak_ops::mls_proposal_with_governance(
        realm_id,
        actor_id,
        &proposal.group_id,
        &proposal_payload,
    )
    .map_err(|err| format!("MLS proposal payload failed: {err}"))?;
    if let Some(effective_scope) = effective_scope {
        builder = builder.effective_scope(effective_scope.clone());
    }
    builder
        .build_sdk_event("inkson")
        .map_err(|err| format!("MLS proposal SDK Event conversion failed: {err}"))
}

async fn build_remove_scope_rotate_draft(
    state_store: &LocalStateStore,
    secure_store: &dyn SecureKeyStore,
    realm_id: &str,
    circle_id: Option<&str>,
    authority: &arkret_sdk::AccountId,
    actor_id: &str,
    device_id: &arkret_sdk::DeviceId,
    target_actor_ids: &[arkret_sdk::ActorId],
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
            authority,
            device_id,
            target_actor_ids,
            revocation_membership_frontier,
            sidecar_binding.clone(),
        )
        .map_err(|err| err.user_message())?;
    if remove.proposals.is_empty() {
        return Err("OpenMLS remove did not produce durable proposal artifacts".to_owned());
    }
    if remove.proposals.len() != remove.removed_actors.len() {
        return Err(
            "OpenMLS remove proposal artifacts do not align with removed principals".to_owned(),
        );
    }
    // Remove proposals and their commit are governed as one epoch transition,
    // so every durable proposal must carry the same verified binding.
    let proposal_governance_binding =
        crate::mls::governance_proof::cached_verified_binding_for_transition(
            state_store,
            &effective_scope,
            &remove.commit.group_id,
            remove.commit.epoch.saturating_sub(1),
            remove.commit.epoch,
        )?;
    if let Some(sidecar_binding) = sidecar_binding.as_ref()
        && proposal_governance_binding.sidecar_binding() != Some(sidecar_binding)
    {
        return Err(
            "verified Sidecar MLS binding differs from the accepted Sidecar view".to_owned(),
        );
    }
    let mut proposals = Vec::with_capacity(remove.proposals.len());
    for (proposal, removed_principal) in remove.proposals.iter().zip(remove.removed_actors.iter()) {
        proposals.push(
            build_remove_proposal_event(
                realm_id,
                Some(&effective_scope),
                actor_id,
                removed_principal,
                proposal,
                proposal_governance_binding.clone(),
            )?
            .into_intent(),
        );
    }
    // The commit is built inside the authoring chain: `proposal_refs` are the
    // proposals' final Event ids, which only exist once they are authored. The
    // store is read HERE, into owned values, because the step runs later and
    // cannot borrow this stack frame.
    let commit_basis = crate::mls::group_events::mls_commit_basis_from_store(
        state_store,
        realm_id,
        circle_id,
        actor_id,
        &remove.commit,
        &previous_governance_binding,
        sidecar_binding,
    )
    .await?;
    let commit_step: crate::event_submit::EventUnitStep = Box::new(move |authored| {
        let proposal_refs = authored
            .iter()
            .map(|event| event.event_id().clone())
            .collect::<Vec<_>>();
        let commit = commit_basis
            .build(proposal_refs)
            .map_err(anyhow::Error::msg)?;
        Ok(vec![commit.into_intent()])
    });
    Ok(CircleScopeRotateDraft {
        steps: vec![Box::new(move |_| Ok(proposals)), commit_step],
        post_commit_snapshot,
        removed_leaves: remove.removed_leaves,
        removed_actors: remove.removed_actors,
    })
}

pub async fn build_realm_remove_members_scope_rotate_draft(
    state_store: &LocalStateStore,
    secure_store: &dyn SecureKeyStore,
    realm_id: &str,
    authority: &arkret_sdk::AccountId,
    actor_id: &str,
    device_id: &arkret_sdk::DeviceId,
    target_actor_ids: &[arkret_sdk::ActorId],
    revocation_membership_frontier: &[arkret_sdk::EventId],
) -> Result<CircleScopeRotateDraft, String> {
    build_remove_scope_rotate_draft(
        state_store,
        secure_store,
        realm_id,
        None,
        authority,
        actor_id,
        device_id,
        target_actor_ids,
        revocation_membership_frontier,
        None,
    )
    .await
}

pub async fn build_circle_remove_members_scope_rotate_draft(
    state_store: &LocalStateStore,
    secure_store: &dyn SecureKeyStore,
    realm_id: &str,
    circle_id: &str,
    authority: &arkret_sdk::AccountId,
    actor_id: &str,
    device_id: &arkret_sdk::DeviceId,
    target_actor_ids: &[arkret_sdk::ActorId],
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
        authority,
        actor_id,
        device_id,
        target_actor_ids,
        revocation_membership_frontier,
        None,
    )
    .await
}
