use crate::secure_key_store::SecureKeyStore;
use crate::state::LocalStateStore;

/// One exact local MLS snapshot and its Station reconciliation request.
#[derive(Clone)]
pub(crate) struct MembershipRemovalSnapshot {
    pub request: arkret_sdk::MlsMembershipRemovalRequestBody,
    /// The exact occupied leaves the request digest commits to. They stay
    /// local: only their canonical digest travels to the Station.
    pub local_mls_leaves: Vec<arkret_sdk::MlsSecurityFrontierLeaf>,
    checkpoint_bytes: Vec<u8>,
}
impl MembershipRemovalSnapshot {
    pub(crate) fn capture(
        store: &LocalStateStore,
        scope: arkret_sdk::ScopeRef,
        authority: &arkret_sdk::AccountId,
        device: &arkret_sdk::DeviceId,
    ) -> Result<Self, String> {
        let checkpoint = store
            .mls_checkpoint_for_scope(&scope)
            .ok_or_else(|| "MLS removal requires a local snapshot".to_owned())?;
        let leaves = crate::mls::governance_proof::current_security_frontier_leaves_for_scope(
            store, &scope, authority, device,
        )?;
        let next = checkpoint
            .epoch
            .checked_add(1)
            .ok_or("MLS epoch overflow")?;
        let frontier = crate::mls::governance_proof::frontier_request_for_scope(
            store,
            scope,
            checkpoint.group_id.clone(),
            checkpoint.epoch,
            next,
            leaves,
        )?;
        let local_mls_leaves = frontier.local_mls_leaves;
        let request = arkret_sdk::MlsMembershipRemovalRequestBody::from_local_leaves(
            frontier.effective_scope,
            frontier.mls_group_id,
            frontier.seal_basis,
            frontier
                .base_group_state_ref
                .ok_or("MLS removal has no accepted base")?,
            checkpoint.epoch,
            &local_mls_leaves,
        )
        .map_err(|e| e.to_string())?;
        Ok(Self {
            request,
            local_mls_leaves,
            checkpoint_bytes: serde_json::to_vec(&checkpoint).map_err(|e| e.to_string())?,
        })
    }

    pub(crate) fn ensure_current(&self, store: &LocalStateStore) -> Result<(), String> {
        let scope = &self.request.effective_scope;
        let checkpoint = store
            .mls_checkpoint_for_scope(scope)
            .ok_or_else(|| "MLS removal snapshot disappeared".to_owned())?;
        if serde_json::to_vec(&checkpoint).map_err(|e| e.to_string())? != self.checkpoint_bytes
            || store.mls_group_state_ref_for_scope(
                scope,
                self.request.mls_group_id.as_str(),
                self.request.epoch,
            )? != self.request.base_group_state_ref
        {
            return Err("MLS removal base or local snapshot changed".to_owned());
        }
        let frontier = crate::mls::governance_proof::frontier_request_for_scope(
            store,
            scope.clone(),
            self.request.mls_group_id.to_string(),
            self.request.epoch,
            self.request
                .epoch
                .checked_add(1)
                .ok_or("MLS epoch overflow")?,
            self.local_mls_leaves.clone(),
        )?;
        if frontier.seal_basis != self.request.seal_basis {
            return Err("MLS removal accepted basis changed".to_owned());
        }
        self.request
            .matches_local_leaves(&self.local_mls_leaves)
            .map_err(|e| e.to_string())?;
        Ok(())
    }
}

/// One-shot: the steps are consumed by authoring, so this plan is neither
/// `Clone` nor `Debug`.
pub struct CircleScopeRotateDraft {
    /// The remove proposals and their commit, in authoring order.
    ///
    /// The commit references the proposals by their FINAL `event_id`
    /// (`proposal_refs`), so it can only be built after they are authored.
    pub steps: Vec<crate::event_submit::EventUnitStep>,
    pub post_commit_checkpoint: crate::mls::persistence::MlsLocalCheckpointEnvelope,
    pub removed_leaves: Vec<u32>,
    pub removed_actors: Vec<arkret_sdk::ActorId>,
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

pub(crate) async fn build_remove_scope_rotate_draft(
    state_store: &LocalStateStore,
    secure_store: &dyn SecureKeyStore,
    authority: &arkret_sdk::AccountId,
    actor_id: &str,
    device_id: &arkret_sdk::DeviceId,
    snapshot: &MembershipRemovalSnapshot,
    outcome: &arkret_sdk::MlsMembershipRemovalOutcome,
) -> Result<CircleScopeRotateDraft, String> {
    snapshot.ensure_current(state_store)?;
    outcome
        .validate_for_request(&snapshot.request, authority, &snapshot.local_mls_leaves)
        .map_err(|e| e.to_string())?;
    let effective_scope = snapshot.request.effective_scope.clone();
    let realm_id = effective_scope
        .realm_id_opt()
        .ok_or("MLS removal has no Realm")?
        .as_str();
    let circle_id = match &effective_scope {
        arkret_sdk::ScopeRef::Circle { circle_id, .. } => Some(circle_id.as_str()),
        arkret_sdk::ScopeRef::Realm { .. } => None,
        _ => return Err("MLS membership reconciliation only accepts Realm/Circle".to_owned()),
    };
    let (remove, post_commit_checkpoint, previous_governance_binding) =
        crate::mls::runtime::build_mls_remove_leaves_commit_for_effective_scope(
            state_store,
            secure_store,
            realm_id,
            circle_id,
            authority,
            device_id,
            snapshot,
            outcome,
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
    let mut proposals = Vec::with_capacity(remove.proposals.len());
    if remove.proposals.len() != outcome.remove_leaf_indices.len()
        || remove.removed_leaves != outcome.remove_leaf_indices
    {
        return Err("MLS Remove output differs from the exact Station leaf decision".to_owned());
    }
    for (proposal, index) in remove.proposals.iter().zip(&outcome.remove_leaf_indices) {
        let leaf = snapshot
            .local_mls_leaves
            .iter()
            .find(|leaf| leaf.leaf_index == *index)
            .ok_or("MLS Remove target is not in the frozen local tree")?;
        proposals.push(
            build_remove_proposal_event(
                realm_id,
                Some(&effective_scope),
                actor_id,
                &leaf.actor_id,
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
        None,
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
        post_commit_checkpoint,
        removed_leaves: remove.removed_leaves,
        removed_actors: remove.removed_actors,
    })
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod removal_snapshot_tests {
    use super::*;

    #[test]
    fn removal_snapshot_rejects_changed_ciphertext_basis_base_and_scope() {
        let realm = "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19";
        let scope = arkret_sdk::ScopeRef::Realm {
            realm_id: arkret_sdk::RealmId::new(realm).unwrap(),
        };
        let group_id = scope.canonical_mls_group_id().unwrap();
        let base =
            arkret_sdk::EventId::new("ak:event:AZEvldDJcWI9IRHqP2BMibDDfc59Ax_LwrbsrQmeD6Ml")
                .unwrap();
        let seal = arkret_sdk::SealId::new(format!("ak:seal:sha256:{}", "a".repeat(64))).unwrap();
        let mut store = crate::state::isolated_store_for_tests("removal-snapshot-fence");
        store.set_realm_seal_view(
            realm,
            crate::state::LocalSealView {
                frontier: vec![seal.to_string()],
                ..Default::default()
            },
        );
        let checkpoint = crate::mls::persistence::encrypt_state(
            realm,
            &group_id,
            1,
            b"snapshot-bytes",
            "secret",
            &[1; 16],
        );
        store
            .save_mls_checkpoint_for_scope(&scope, checkpoint)
            .unwrap();
        store
            .record_mls_group_state_ref_for_scope(&scope, &group_id, 1, base.clone())
            .unwrap();
        let checkpoint = store.mls_checkpoint_for_scope(&scope).unwrap();
        let local_mls_leaves = vec![arkret_sdk::MlsSecurityFrontierLeaf {
            leaf_index: 0,
            actor_id: arkret_sdk::ActorId::account(crate::test_support::authority(
                "did:web:alice.example",
            )),
            credential_ref: arkret_sdk::NonEmptyString::new("device-0").unwrap(),
        }];
        let frozen = MembershipRemovalSnapshot {
            request: arkret_sdk::MlsMembershipRemovalRequestBody::from_local_leaves(
                scope.clone(),
                arkret_sdk::Base64UrlString::new(group_id).unwrap(),
                arkret_sdk::SealBasis { leaves: vec![seal] },
                base,
                1,
                &local_mls_leaves,
            )
            .unwrap(),
            local_mls_leaves,
            checkpoint_bytes: serde_json::to_vec(&checkpoint).unwrap(),
        };
        frozen.ensure_current(&store).unwrap();
        // The query commits to the leaf set by digest only; a drifted local
        // tree must not be reconciled against a digest it no longer matches.
        let mut drifted = frozen.clone();
        drifted.local_mls_leaves[0].credential_ref =
            arkret_sdk::NonEmptyString::new("device-1").unwrap();
        assert!(drifted.ensure_current(&store).is_err());
        let mut wrong_base = frozen.clone();
        wrong_base.request.base_group_state_ref =
            arkret_sdk::EventId::from_digest(arkret_sdk::canonical::DigestSuite::Sha256, [7; 32]);
        assert!(wrong_base.ensure_current(&store).is_err());
        let mut wrong_scope = frozen.clone();
        wrong_scope.request.effective_scope = arkret_sdk::ScopeRef::Realm {
            realm_id: arkret_sdk::RealmId::new(
                "ak:realm:ASeIBHNVQyeIcU4aBIt2t2BF_ikuVMH0kNru_HgO_gG1",
            )
            .unwrap(),
        };
        assert!(wrong_scope.ensure_current(&store).is_err());
        let mut wrong_epoch = frozen.clone();
        wrong_epoch.request.epoch = 2;
        assert!(wrong_epoch.ensure_current(&store).is_err());
        let mut changed = checkpoint.clone();
        changed.ciphertext_hex.push_str("00");
        store
            .save_mls_checkpoint_for_scope(&scope, changed)
            .unwrap();
        assert!(frozen.ensure_current(&store).is_err());
        store
            .save_mls_checkpoint_for_scope(&scope, checkpoint)
            .unwrap();
        store.set_realm_seal_view(
            realm,
            crate::state::LocalSealView {
                frontier: vec![format!("ak:seal:sha256:{}", "b".repeat(64))],
                ..Default::default()
            },
        );
        assert!(frozen.ensure_current(&store).is_err());
    }
}
