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
                group
                    .apply_commit_and_retain_history_secret(
                        &payload.commit_envelope(),
                        realm_id.as_str(),
                    )
                    .map_err(protocol)?;
                crate::mls::governance_proof::install_accepted_transition_leaf_bindings(
                    &self.state.read(),
                    realm_id.as_str(),
                    &mut group,
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
                let value = serde_json::to_value(&payload)?;
                super::message::verify_welcome_claim_envelope_signer(&value).map_err(protocol)?;
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
                let identity = arkret_sdk::ArkretMlsIdentity::restore_from_private_state(
                    self.authority.principal_id.clone(),
                    self.device_id.clone(),
                    &private_state,
                )
                .map_err(protocol)?;
                let expected_endpoint = super::message::welcome_recipient_endpoint(
                    &payload.recipient_principal_id,
                    payload.recipient.clone(),
                )
                .map_err(protocol)?;
                if identity.endpoint_identity() != expected_endpoint {
                    return Err(protocol(
                        "accepted MLS Welcome is not addressed to the locally persisted KeyPackage endpoint",
                    ));
                }
                let mut group = arkret_sdk::ArkretMlsGroup::join_from_welcome(identity, &welcome)
                    .map_err(protocol)?;
                crate::mls::governance_proof::install_accepted_transition_leaf_bindings(
                    &self.state.read(),
                    payload.governance_binding.realm_id().as_str(),
                    &mut group,
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
        if group.current_governance_binding().map_err(protocol)? != Some(binding) {
            return Err(protocol(
                "applied MLS state differs from the accepted governance binding",
            ));
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
    };
    let mut applied = 0;
    for frontier in frontiers {
        for event in &frontier.target_checkpoint.accepted_events {
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
