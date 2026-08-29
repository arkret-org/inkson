//! Host adapter for Garth's checkpoint-proven accepted MLS artifact consumer.

use dioxus::prelude::{ReadableExt, SyncSignal, WritableExt};

#[derive(Clone)]
struct HostArtifactStore {
    state: SyncSignal<crate::state::LocalStateStore>,
}

impl garth::AcceptedMlsArtifactStore for HostArtifactStore {
    fn load_accepted_mls_artifacts(
        &self,
    ) -> garth::Result<garth::VersionedAcceptedMlsArtifactSnapshot> {
        Ok(self.state.read().accepted_mls_artifact_snapshot())
    }

    async fn compare_and_swap_accepted_mls_artifacts(
        &self,
        revision: u64,
        snapshot: &garth::AcceptedMlsArtifactSnapshot,
    ) -> garth::Result<bool> {
        let mut state = self.state;
        let barrier = state
            .write()
            .compare_and_swap_accepted_mls_artifacts(revision, snapshot)
            .map_err(garth::Error::Protocol)?;
        let Some(barrier) = barrier else {
            return Ok(false);
        };
        barrier
            .wait()
            .await
            .map_err(|error| garth::Error::Protocol(error.to_string()))?;
        Ok(true)
    }
}

struct HostArtifactApplicator {
    state: SyncSignal<crate::state::LocalStateStore>,
    authority: arkret_sdk::PrincipalAuthorityKey,
    device_id: arkret_sdk::DeviceId,
    local_authored_commit: Option<LocalAuthoredCommitStaging>,
}

#[derive(Clone)]
struct LocalAuthoredCommitStaging {
    event_id: arkret_sdk::EventId,
    snapshot: garth::QueuedMlsSnapshot,
    proof_leaves: Vec<arkret_sdk::MlsSecurityFrontierLeaf>,
}

fn protocol(error: impl ToString) -> garth::Error {
    garth::Error::Protocol(error.to_string())
}

fn event_payload<T: serde::de::DeserializeOwned>(event: &arkret_sdk::Event) -> garth::Result<T> {
    Ok(serde_json::from_value(serde_json::to_value(
        &event.payload,
    )?)?)
}

fn transition_digest(event: &arkret_sdk::Event) -> garth::Result<arkret_sdk::Hash> {
    match event.kind {
        arkret_sdk::EventKind::MlsGenesis => event_payload::<arkret_sdk::MlsGenesisPayload>(event)?
            .transition_digest()
            .map_err(protocol),
        arkret_sdk::EventKind::MlsCommit => {
            Ok(event_payload::<arkret_sdk::MlsCommitPayload>(event)?
                .commit_digest()
                .clone())
        }
        _ => Err(protocol(
            "accepted MLS history state names a non-transition Event",
        )),
    }
}

fn restore_local_authored_commit(
    staging: &LocalAuthoredCommitStaging,
    event_id: &arkret_sdk::EventId,
    payload: &arkret_sdk::MlsCommitPayload,
    snapshot_secret: &str,
) -> garth::Result<
    Option<(
        arkret_sdk::ScopeRef,
        arkret_sdk::MlsGovernanceBindingPayload,
        arkret_sdk::ArkretMlsGroup,
    )>,
> {
    if &staging.event_id != event_id {
        return Ok(None);
    }
    if staging
        .snapshot
        .group_state_event_id
        .as_ref()
        .is_some_and(|staged_event_id| staged_event_id != event_id)
    {
        return Err(protocol(
            "locally authored MLS staging names a different accepted transition",
        ));
    }
    let scope = payload.governance_binding().effective_scope().clone();
    let realm_id = scope
        .realm_id_opt()
        .ok_or_else(|| protocol("accepted MLS Commit has no Realm scope"))?;
    if staging.snapshot.realm_id != realm_id.as_str()
        || staging.snapshot.group_id != payload.mls_group_id()
        || staging.snapshot.epoch != payload.next_epoch()
    {
        return Err(protocol(
            "locally authored MLS staging differs from the accepted Commit scope, group, or epoch",
        ));
    }
    let mut group = crate::mls::persistence::restore_envelope(
        &crate::mls::persistence::MlsSnapshotEnvelope::from(staging.snapshot.clone()),
        snapshot_secret,
        payload.next_epoch(),
    )
    .map_err(protocol)?;
    if group.current_governance_binding().map_err(protocol)?
        != Some(payload.governance_binding().clone())
    {
        return Err(protocol(
            "locally authored MLS staging differs from the accepted governance binding",
        ));
    }
    if group.security_frontier_leaves().map_err(protocol)? != staging.proof_leaves {
        return Err(protocol(
            "locally authored MLS staging differs from the exact verified proof leaf set",
        ));
    }
    // The committer cannot replay its own wire Commit: OpenMLS keeps the
    // update-path secret in the pending Commit that was merged while
    // authoring. The encrypted post-state is therefore the only executable
    // local input. Retain the entered epoch's history secret before Garth
    // validates and atomically publishes a fresh winner-bound envelope.
    group
        .derive_and_retain_history_secret(realm_id.as_str())
        .map_err(protocol)?;
    Ok(Some((scope, payload.governance_binding().clone(), group)))
}

impl HostArtifactApplicator {
    fn accepted_transition_for_welcome(
        &self,
        payload: &arkret_sdk::MlsWelcomePayload,
    ) -> garth::Result<arkret_sdk::Event> {
        let transition_ref = &payload.commit_ref;
        self.state
            .read()
            .trusted_mls_governance_checkpoint(payload.governance_binding.realm_id().as_str())
            .and_then(|checkpoint| {
                checkpoint
                    .accepted_events
                    .into_iter()
                    .find(|event| &event.event_id == transition_ref)
            })
            .ok_or_else(|| {
                protocol("accepted Welcome winning Commit is absent from its checkpoint")
            })
    }

    fn prepare_group(
        &self,
        event: &arkret_sdk::Event,
        previous: Option<&garth::QueuedMlsSnapshot>,
        snapshot_secret: &str,
    ) -> garth::Result<(
        arkret_sdk::ScopeRef,
        arkret_sdk::MlsGovernanceBindingPayload,
        arkret_sdk::ArkretMlsGroup,
        arkret_sdk::Event,
    )> {
        match event.kind {
            arkret_sdk::EventKind::MlsGenesis => {
                let payload = event_payload::<arkret_sdk::MlsGenesisPayload>(event)?;
                let staged = self
                    .state
                    .read()
                    .staged_mls_snapshot_for_scope_and_group(
                        &payload.effective_scope,
                        payload.mls_group_id.as_str(),
                    )
                    .filter(|snapshot| snapshot.epoch == 0)
                    .ok_or_else(|| {
                        protocol("accepted MLS Genesis has no epoch-zero authoring state")
                    })?;
                let group = crate::mls::persistence::restore_envelope(&staged, snapshot_secret, 0)
                    .map_err(protocol)?;
                Ok((
                    payload.effective_scope,
                    payload.governance_binding,
                    group,
                    event.clone(),
                ))
            }
            arkret_sdk::EventKind::MlsCommit => {
                let payload = event_payload::<arkret_sdk::MlsCommitPayload>(event)?;
                let previous = previous.ok_or_else(|| {
                    protocol("accepted MLS Commit has no Garth ready base snapshot")
                })?;
                if let Some(staging) = self.local_authored_commit.as_ref()
                    && let Some((scope, binding, group)) = restore_local_authored_commit(
                        staging,
                        &event.event_id,
                        &payload,
                        snapshot_secret,
                    )?
                {
                    return Ok((scope, binding, group, event.clone()));
                }
                let mut group = crate::mls::persistence::restore_envelope(
                    &crate::mls::persistence::MlsSnapshotEnvelope::from(previous.clone()),
                    snapshot_secret,
                    0,
                )
                .map_err(protocol)?;
                let scope = payload.governance_binding().effective_scope().clone();
                let realm_id = scope
                    .realm_id_opt()
                    .ok_or_else(|| protocol("accepted MLS Commit has no Realm scope"))?;
                let checkpoint = self
                    .state
                    .read()
                    .trusted_mls_governance_checkpoint(realm_id.as_str())
                    .ok_or_else(|| protocol("accepted MLS Commit has no verified checkpoint"))?;
                for proposal_ref in payload.proposal_refs() {
                    let mut matches = checkpoint
                        .accepted_events
                        .iter()
                        .filter(|candidate| &candidate.event_id == proposal_ref);
                    let proposal_event = matches.next().ok_or_else(|| {
                        protocol("accepted MLS Commit references an unavailable Proposal")
                    })?;
                    if matches.next().is_some()
                        || proposal_event.kind != arkret_sdk::EventKind::MlsProposal
                    {
                        return Err(protocol(
                            "accepted MLS Commit proposal reference is ambiguous or has the wrong kind",
                        ));
                    }
                    let proposal = event_payload::<arkret_sdk::MlsProposalPayload>(proposal_event)?;
                    if proposal.mls_group_id.as_str() != payload.mls_group_id()
                        || proposal.base_epoch != payload.base_epoch()
                    {
                        return Err(protocol(
                            "accepted MLS Commit proposal belongs to another group or epoch",
                        ));
                    }
                    let proposal_type = serde_json::to_value(proposal.proposal_type)?
                        .as_str()
                        .ok_or_else(|| protocol("MLS Proposal type is not a string"))?
                        .to_owned();
                    group
                        .apply_proposal(&arkret_sdk::MlsProposalEnvelope {
                            group_id: proposal.mls_group_id.to_string(),
                            epoch: proposal.base_epoch,
                            proposal_type,
                            proposal: proposal.proposal_bytes_b64,
                            proposal_digest: proposal.proposal_digest,
                            ratchet_tree: None,
                        })
                        .map_err(protocol)?;
                }
                group
                    .apply_commit_and_retain_history_secret(
                        &payload.commit_envelope(),
                        realm_id.as_str(),
                    )
                    .map_err(protocol)?;
                crate::mls::governance_proof::install_cached_transition_leaf_bindings(
                    &self.state.read(),
                    &mut group,
                    payload.governance_binding(),
                )
                .map_err(protocol)?;
                Ok((
                    scope,
                    payload.governance_binding().clone(),
                    group,
                    event.clone(),
                ))
            }
            arkret_sdk::EventKind::MlsWelcome => {
                let payload = event_payload::<arkret_sdk::MlsWelcomePayload>(event)?;
                let secure_store = crate::secure_key_store::default_secure_key_store("inkson");
                super::message::verify_welcome_claim_envelope_signer(&payload).map_err(protocol)?;
                let value = serde_json::to_value(&payload)?;
                let welcome = super::message::decode_welcome_envelope(&value).map_err(protocol)?;
                let private_state = super::load_mls_key_package_identity_state(
                    secure_store.as_ref(),
                    &self.authority,
                    &self.device_id,
                    payload.keypackage_ref.as_str(),
                )
                .map_err(protocol)?
                .ok_or_else(|| {
                    protocol("accepted Welcome KeyPackage private state is unavailable")
                })?;
                let expected_endpoint = super::message::welcome_recipient_endpoint(
                    &payload.recipient_principal_id,
                    payload.recipient.clone(),
                )
                .map_err(protocol)?;
                let identity = arkret_sdk::ArkretMlsIdentity::restore_from_private_state(
                    expected_endpoint.clone(),
                    &private_state,
                )
                .map_err(protocol)?;
                if identity.endpoint_identity() != expected_endpoint {
                    return Err(protocol(
                        "accepted MLS Welcome is not addressed to the locally persisted KeyPackage endpoint",
                    ));
                }
                let mut group = arkret_sdk::ArkretMlsGroup::join_from_welcome(identity, &welcome)
                    .map_err(protocol)?;
                let authority_hints =
                    crate::mls::governance_proof::leaf_authority_hints_from_welcome(&payload)
                        .map_err(protocol)?;
                crate::mls::governance_proof::install_cached_transition_leaf_bindings_with_hints(
                    &self.state.read(),
                    &mut group,
                    &payload.governance_binding,
                    &authority_hints,
                )
                .map_err(protocol)?;
                super::message::verify_welcome_governance_binding(
                    &self.state.read(),
                    payload.governance_binding.realm_id().as_str(),
                    &group,
                    &value,
                )
                .map_err(protocol)?;
                group
                    .derive_and_retain_history_secret(
                        payload.governance_binding.realm_id().as_str(),
                    )
                    .map_err(protocol)?;
                let transition = self.accepted_transition_for_welcome(&payload)?;
                Ok((
                    payload.governance_binding.effective_scope().clone(),
                    payload.governance_binding,
                    group,
                    transition,
                ))
            }
            _ => Err(protocol(
                "accepted artifact applicator received a non-MLS Event",
            )),
        }
    }

    fn prepare_inner(
        &self,
        event: &arkret_sdk::Event,
        previous: Option<&garth::QueuedMlsSnapshot>,
    ) -> garth::Result<garth::PreparedAcceptedMlsArtifact> {
        let secure_store = crate::secure_key_store::default_secure_key_store("inkson");
        let snapshot_secret = super::load_device_snapshot_secret(
            secure_store.as_ref(),
            &self.authority,
            &self.device_id,
        )
        .map_err(protocol)?;
        let (scope, binding, mut group, transition) =
            self.prepare_group(event, previous, &snapshot_secret)?;
        if group.current_governance_binding().map_err(protocol)? != Some(binding.clone()) {
            return Err(protocol(
                "applied MLS state differs from the accepted governance binding",
            ));
        }
        if event.kind != arkret_sdk::EventKind::MlsGenesis {
            crate::mls::governance_proof::install_cached_transition_leaf_bindings(
                &self.state.read(),
                &mut group,
                &binding,
            )
            .map_err(protocol)?;
        }
        let realm_id = scope
            .realm_id_opt()
            .ok_or_else(|| protocol("accepted MLS artifact has no Realm scope"))?;
        if group.epoch() == 0 {
            group
                .derive_and_retain_history_secret(realm_id.as_str())
                .map_err(protocol)?;
        }
        let post_state = group.export_state_record().map_err(protocol)?;
        let mut salt = [0_u8; 16];
        getrandom::fill(&mut salt).map_err(protocol)?;
        let mut snapshot = crate::mls::persistence::encrypt_state(
            realm_id.as_str(),
            &post_state.group_id,
            post_state.epoch,
            &serde_json::to_vec(&post_state)?,
            &snapshot_secret,
            &salt,
        );
        if let Some(previous) = previous {
            snapshot.admission_epoch = previous.admission_epoch;
        }
        snapshot.group_state_event_id = Some(transition.event_id.clone());

        let history_scope = arkret_sdk::HistoryEffectiveScope::try_from(scope).map_err(protocol)?;
        let transition_event_digest =
            arkret_sdk::signed_event_digest_claim(&transition).map_err(protocol)?;
        let local_state_ref = format!(
            "inkson.accepted_mls_snapshot.v1:{}",
            arkret_sdk::canonical::canonical_sha256(&snapshot).map_err(protocol)?
        );
        let history_record = group
            .export_local_authoritative_history_secret(
                &history_scope,
                post_state.epoch,
                &local_state_ref,
                &transition.event_id,
                &transition_event_digest,
                &transition_digest(&transition)?,
            )
            .map_err(protocol)?;
        let mut history_salt = [0_u8; 16];
        getrandom::fill(&mut history_salt).map_err(protocol)?;
        let history_envelope = crate::mls::persistence::encrypt_state(
            history_scope.realm_id().as_str(),
            &post_state.group_id,
            post_state.epoch,
            &serde_json::to_vec(&history_record)?,
            &snapshot_secret,
            &history_salt,
        );
        Ok(garth::PreparedAcceptedMlsArtifact {
            snapshot: snapshot.into_queued(),
            history_secret: garth::QueuedMlsHistorySecret {
                group_id: post_state.group_id,
                epoch: post_state.epoch,
                transition_ref: transition.event_id,
                ciphertext: serde_json::to_vec(&history_envelope)?,
            },
        })
    }
}

impl garth::AcceptedMlsArtifactApplicator for HostArtifactApplicator {
    async fn prepare(
        &self,
        event: &arkret_sdk::Event,
        previous: Option<&garth::QueuedMlsSnapshot>,
    ) -> garth::Result<garth::PreparedAcceptedMlsArtifact> {
        self.prepare_inner(event, previous)
    }
}

fn locally_executable(
    consumer: &garth::AcceptedMlsArtifactConsumer<HostArtifactStore>,
    state: &crate::state::LocalStateStore,
    event: &arkret_sdk::Event,
    authority: &arkret_sdk::PrincipalAuthorityKey,
    device_id: &arkret_sdk::DeviceId,
) -> Result<bool, String> {
    match event.kind {
        arkret_sdk::EventKind::MlsGenesis => {
            let payload = event_payload::<arkret_sdk::MlsGenesisPayload>(event)
                .map_err(|error| error.to_string())?;
            Ok(state
                .staged_mls_snapshot_for_scope_and_group(
                    &payload.effective_scope,
                    payload.mls_group_id.as_str(),
                )
                .is_some())
        }
        arkret_sdk::EventKind::MlsCommit => {
            let payload = event_payload::<arkret_sdk::MlsCommitPayload>(event)
                .map_err(|error| error.to_string())?;
            Ok(consumer
                .ready_snapshot(
                    payload.governance_binding().effective_scope(),
                    payload.mls_group_id(),
                )
                .map_err(|error| error.to_string())?
                .is_some_and(|snapshot| snapshot.epoch == payload.base_epoch()))
        }
        arkret_sdk::EventKind::MlsWelcome => {
            let payload = event_payload::<arkret_sdk::MlsWelcomePayload>(event)
                .map_err(|error| error.to_string())?;
            let local_endpoint = matches!(
                &payload.recipient,
                arkret_sdk::MlsWelcomeRecipient::Device { recipient_device_id }
                    if payload.recipient_principal_id.as_ref() == Some(&authority.principal_id)
                        && recipient_device_id == device_id
            ) || matches!(
                &payload.recipient,
                arkret_sdk::MlsWelcomeRecipient::MinimalMetadataPairwise { .. }
                    if payload.recipient_principal_id.is_none()
            );
            if !local_endpoint {
                return Ok(false);
            }
            let secure_store = crate::secure_key_store::default_secure_key_store("inkson");
            super::load_mls_key_package_identity_state(
                secure_store.as_ref(),
                authority,
                device_id,
                payload.keypackage_ref.as_str(),
            )
            .map(|state| state.is_some())
            .map_err(|error| error.to_string())
        }
        _ => Ok(false),
    }
}

/// Apply all locally executable MLS artifacts in current verified checkpoints.
/// No projection Event or to-device envelope can enter this path directly.
pub(crate) async fn converge_accepted_mls_artifacts(
    state: SyncSignal<crate::state::LocalStateStore>,
    authority: &arkret_sdk::PrincipalAuthorityKey,
    device_id: &arkret_sdk::DeviceId,
) -> Result<usize, String> {
    let frontiers = {
        let local = state.read().load();
        local
            .mls_governance_proofs
            .values()
            .filter_map(|proof| {
                let realm = proof.request.effective_scope.realm_id_opt()?;
                let checkpoint = local.mls_governance_checkpoints.get(realm.as_str())?;
                (checkpoint.basis == proof.proof_target_basis).then(|| {
                    arkret_sdk::VerifiedMlsGovernanceFrontier {
                        proof_target_basis: proof.proof_target_basis.clone(),
                        security_frontier_digest: proof
                            .governance_binding
                            .security_frontier_digest()
                            .clone(),
                        page_digest: proof.bundle.page_digest.clone(),
                        target_checkpoint: checkpoint.clone(),
                    }
                })
            })
            .collect::<Vec<_>>()
    };
    let consumer = garth::AcceptedMlsArtifactConsumer::new(HostArtifactStore { state });
    let applicator = HostArtifactApplicator {
        state,
        authority: authority.clone(),
        device_id: device_id.clone(),
        local_authored_commit: None,
    };
    let mut applied = 0;
    for frontier in frontiers {
        for event in &frontier.target_checkpoint.accepted_events {
            if !garth::is_checkpoint_winning_accepted_mls_artifact(
                &frontier.target_checkpoint,
                &event.event_id,
            )
            .map_err(|error| error.to_string())?
            {
                continue;
            }
            if !locally_executable(&consumer, &state.read(), event, authority, device_id)? {
                continue;
            }
            let committed = consumer
                .consume(&frontier, &event.event_id, &applicator)
                .await
                .map_err(|error| error.to_string())?;
            if committed.outcome == garth::AcceptedMlsArtifactCommitOutcome::Applied {
                applied += 1;
            }
        }
    }
    Ok(applied)
}

/// Materialize one exact locally-authored Commit after its accepted checkpoint
/// and post-transition proof have been verified. Unlike the background
/// best-effort scan, every missing or non-winning input is an error: a durable
/// admission unit must never turn a skipped Commit into a successful no-op.
pub(crate) async fn converge_accepted_local_commit(
    state: SyncSignal<crate::state::LocalStateStore>,
    authority: &arkret_sdk::PrincipalAuthorityKey,
    device_id: &arkret_sdk::DeviceId,
    event_id: &arkret_sdk::EventId,
    staged_snapshot: &garth::QueuedMlsSnapshot,
) -> Result<garth::AcceptedMlsArtifactCommitOutcome, String> {
    let local = state.read().load();
    let checkpoint = local
        .mls_governance_checkpoints
        .get(staged_snapshot.realm_id.as_str())
        .cloned()
        .ok_or_else(|| "locally authored MLS Commit has no pinned checkpoint".to_owned())?;
    let event = checkpoint
        .accepted_events
        .iter()
        .find(|event| &event.event_id == event_id)
        .cloned()
        .ok_or_else(|| {
            "locally authored MLS Commit is absent from its accepted checkpoint".to_owned()
        })?;
    if event.kind != arkret_sdk::EventKind::MlsCommit {
        return Err("locally authored MLS transition is not an ak.mls.commit Event".to_owned());
    }
    let payload =
        event_payload::<arkret_sdk::MlsCommitPayload>(&event).map_err(|error| error.to_string())?;
    let mut proofs = local.mls_governance_proofs.values().filter(|proof| {
        proof.proof_target_basis == checkpoint.basis
            && proof.request.effective_scope == *payload.governance_binding().effective_scope()
            && proof.request.mls_group_id.as_str() == payload.mls_group_id()
            && proof.request.previous_epoch == payload.base_epoch()
            && proof.request.next_epoch == payload.next_epoch()
            && proof.governance_binding == *payload.governance_binding()
    });
    let proof = proofs
        .next()
        .cloned()
        .ok_or_else(|| "locally authored MLS Commit has no exact verified proof".to_owned())?;
    if proofs.next().is_some() {
        return Err("locally authored MLS Commit has multiple exact verified proofs".to_owned());
    }
    let frontier = arkret_sdk::VerifiedMlsGovernanceFrontier {
        proof_target_basis: proof.proof_target_basis,
        security_frontier_digest: proof.governance_binding.security_frontier_digest().clone(),
        page_digest: proof.bundle.page_digest,
        target_checkpoint: checkpoint,
    };
    if !garth::is_checkpoint_winning_accepted_mls_artifact(&frontier.target_checkpoint, event_id)
        .map_err(|error| error.to_string())?
    {
        return Err("locally authored MLS Commit is not the checkpoint winner".to_owned());
    }
    let consumer = garth::AcceptedMlsArtifactConsumer::new(HostArtifactStore { state });
    let applicator = HostArtifactApplicator {
        state,
        authority: authority.clone(),
        device_id: device_id.clone(),
        local_authored_commit: Some(LocalAuthoredCommitStaging {
            event_id: event_id.clone(),
            snapshot: staged_snapshot.clone(),
            proof_leaves: proof.request.local_mls_leaves,
        }),
    };
    consumer
        .consume(&frontier, event_id, &applicator)
        .await
        .map(|committed| committed.outcome)
        .map_err(|error| error.to_string())
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;

    const REALM: &str = "ak:realm:AQSS_m6w3ODdIeq8Yzac2ghmcQVOGLXWA5PXFcSnVcgN";
    const SNAPSHOT_SECRET: &str = "artifact-consumer-local-commit-test-secret";

    fn governance_binding(
        group_id: &str,
        previous_epoch: u64,
        next_epoch: u64,
    ) -> arkret_sdk::MlsGovernanceBindingPayload {
        arkret_sdk::MlsGovernanceBindingPayload::realm(
            arkret_sdk::RealmId::new(REALM.to_owned()).unwrap(),
            group_id,
            previous_epoch,
            next_epoch,
            arkret_sdk::Hash::new(format!("sha256:{}", "a5".repeat(32))).unwrap(),
            arkret_sdk::ContentScheme::MlsExporterAeadV1,
            Some(arkret_sdk::DurabilityPolicy::None),
            arkret_sdk::ProfileId::MLS_GOVERNANCE_BINDING_FULL_V1,
            arkret_sdk::CORE_REDUCER_PROFILE,
        )
        .unwrap()
    }

    #[test]
    fn local_committer_uses_exact_staged_post_state_instead_of_replaying_own_wire_commit() {
        let scope = arkret_sdk::ScopeRef::Realm {
            realm_id: arkret_sdk::RealmId::new(REALM.to_owned()).unwrap(),
        };
        let group_id = scope.canonical_mls_group_id().unwrap();
        let alice = arkret_sdk::ArkretMlsIdentity::new_test_human_device(
            crate::mls_api_helpers::principal_core_id("did:web:alice.example").unwrap(),
            arkret_sdk::DeviceId::new("ak:device:01904100-0000-7000-8000-0000000000a1".to_owned())
                .unwrap(),
        )
        .unwrap();
        let bob = arkret_sdk::ArkretMlsIdentity::new_test_human_device(
            crate::mls_api_helpers::principal_core_id("did:web:bob.example").unwrap(),
            arkret_sdk::DeviceId::new("ak:device:01904100-0000-7000-8000-0000000000b1".to_owned())
                .unwrap(),
        )
        .unwrap();
        let mut author = alice
            .create_group_with_governance_binding(
                REALM.as_bytes(),
                &governance_binding(&group_id, 0, 0),
            )
            .unwrap();
        assert_eq!(author.group_id(), group_id);
        let pre_commit = author.export_state_record().unwrap();
        let accepted_binding = governance_binding(&group_id, 0, 1);
        let add = author
            .add_member_with_governance_binding(
                &bob.key_package_record().unwrap(),
                &accepted_binding,
            )
            .unwrap();

        let mut own_wire_replay =
            arkret_sdk::ArkretMlsGroup::restore_from_state_record(&pre_commit).unwrap();
        let replay_error = own_wire_replay
            .apply_commit_and_retain_history_secret(&add.commit, REALM)
            .unwrap_err();
        assert!(
            format!("{replay_error:?}").contains("CannotDecryptOwnMessage"),
            "unexpected own-wire replay error: {replay_error:?}"
        );

        let post_commit = author.export_state_record().unwrap();
        let envelope = crate::mls::persistence::encrypt_state(
            REALM,
            &post_commit.group_id,
            post_commit.epoch,
            &serde_json::to_vec(&post_commit).unwrap(),
            SNAPSHOT_SECRET,
            &[7; 16],
        );
        let accepted_event_id = arkret_sdk::EventId::new(
            "ak:event:Ab1MMSQPtKZxy5NUsyP7CXJ4OYIrLAaoHAWt8UVrxTjm".to_owned(),
        )
        .unwrap();
        let payload = arkret_sdk::MlsCommitPayload::new(
            0,
            "ak:event:AZEvldDJcWI9IRHqP2BMibDDfc59Ax_LwrbsrQmeD6Ml",
            Vec::new(),
            &add.commit,
            accepted_binding.clone(),
        )
        .unwrap();
        let staging = LocalAuthoredCommitStaging {
            event_id: accepted_event_id.clone(),
            snapshot: envelope.into_queued(),
            proof_leaves: author.security_frontier_leaves().unwrap(),
        };

        let (_, restored_binding, restored) =
            restore_local_authored_commit(&staging, &accepted_event_id, &payload, SNAPSHOT_SECRET)
                .unwrap()
                .expect("exact local staged state must be executable");
        assert_eq!(restored.epoch(), 1);
        assert_eq!(restored_binding, accepted_binding);
        assert_eq!(
            restored.current_governance_binding().unwrap(),
            Some(accepted_binding)
        );
        let restored_state = restored.export_state_record().unwrap();
        let serialized: serde_json::Value =
            serde_json::from_slice(&restored_state.serialized_state).unwrap();
        assert!(
            serialized["history_secrets"].get("1").is_some(),
            "accepted local staged state must retain the entered epoch history secret"
        );

        let other_event_id = arkret_sdk::EventId::new(
            "ak:event:ASgzkry7WbLWf5gfPTpg-EYiBKdx4xN_4rAzNOYM0-6n".to_owned(),
        )
        .unwrap();
        assert!(
            restore_local_authored_commit(&staging, &other_event_id, &payload, SNAPSHOT_SECRET,)
                .unwrap()
                .is_none(),
            "staged authoring state must never override another accepted Commit"
        );

        let mut wrong_leaf_staging = staging.clone();
        wrong_leaf_staging.proof_leaves.clear();
        let wrong_leaf_error = restore_local_authored_commit(
            &wrong_leaf_staging,
            &accepted_event_id,
            &payload,
            SNAPSHOT_SECRET,
        )
        .err()
        .expect("a staged state that differs from the proof leaf set must fail closed");
        assert!(
            wrong_leaf_error
                .to_string()
                .contains("exact verified proof leaf set"),
            "unexpected wrong-leaf rejection: {wrong_leaf_error}"
        );
    }

    #[test]
    fn exact_local_staging_rejects_transition_metadata_drift() {
        let group_id = arkret_sdk::ScopeRef::Realm {
            realm_id: arkret_sdk::RealmId::new(REALM.to_owned()).unwrap(),
        }
        .canonical_mls_group_id()
        .unwrap();
        let event_id = arkret_sdk::EventId::new(
            "ak:event:Ab1MMSQPtKZxy5NUsyP7CXJ4OYIrLAaoHAWt8UVrxTjm".to_owned(),
        )
        .unwrap();
        let commit = arkret_sdk::MlsCommitEnvelope {
            group_id: group_id.clone(),
            epoch: 1,
            commit: arkret_sdk::base64url_encode(b"commit"),
            commit_digest: arkret_sdk::Hash::new(arkret_sdk::canonical::sha256_digest(b"commit"))
                .unwrap(),
            ratchet_tree: None,
        };
        let payload = arkret_sdk::MlsCommitPayload::new(
            0,
            "ak:event:AZEvldDJcWI9IRHqP2BMibDDfc59Ax_LwrbsrQmeD6Ml",
            Vec::new(),
            &commit,
            governance_binding(&group_id, 0, 1),
        )
        .unwrap();
        let staging = LocalAuthoredCommitStaging {
            event_id: event_id.clone(),
            snapshot: garth::QueuedMlsSnapshot {
                realm_id: REALM.to_owned(),
                group_id,
                epoch: 2,
                admission_epoch: 0,
                group_state_event_id: None,
                salt_hex: String::new(),
                ciphertext_hex: String::new(),
                mac_hex: String::new(),
                recorded_at: crate::clock::now_utc(),
                epoch_started_at: crate::clock::now_utc(),
                app_messages_observed: 0,
                aead_version: crate::mls::persistence::AEAD_VERSION_CHACHA20_POLY1305,
            },
            proof_leaves: Vec::new(),
        };

        let error = restore_local_authored_commit(&staging, &event_id, &payload, SNAPSHOT_SECRET)
            .err()
            .expect("transition metadata drift must fail closed");
        assert!(
            error.to_string().contains("scope, group, or epoch"),
            "unexpected exact-staging rejection: {error}"
        );
    }
}
