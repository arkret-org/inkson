//! Realm founding-authority facts read from the Realm's own commit stream.
//!
//! The governance-authority protocol has no projected authority cell and no
//! producer-side authorization claim for a Realm owner: the owner authorizes
//! with its own actor identity and the current governance Station evaluates
//! that against the committed Realm projection. What remains here is the small
//! set of immutable facts the Realm genesis Event itself carries.

use super::*;

pub(crate) fn creator_cache_belongs_to_closed_attempt(
    record: &arkret_models_collaboration::mls_creator_bootstrap::MlsCreatorBootstrapRecord,
    cache: &crate::mls::persistence::MlsLocalCheckpointEnvelope,
    emitted: bool,
    public: &[u8],
    tree: &[u8],
) -> anyhow::Result<bool> {
    record.validate()?;
    if cache.epoch != 0
        || cache.admission_epoch != 0
        || cache.group_state_event_id.is_some()
        || emitted
        || cache.group_id != record.intent().mls_group_id().as_str()
        || cache.realm_id != record.intent().effective_scope().realm_id().as_str()
    {
        return Ok(false);
    }
    for closed in record.closed_attempts() {
        if closed.matches_epoch_zero_public_material(public, tree)? {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Authority facts pinned by a Realm's committed `ak.realm.create`.
#[derive(Clone, Debug, PartialEq)]
pub(super) enum RealmCreateAuthority {
    Root {
        controller: arkret_sdk::ActorId,
    },
    /// A Direct Conversation grants its founder no ordinary Realm-owner
    /// authority; the founder only authors the bootstrap actions of
    /// `identity/contact-and-direct-conversation.md` 7.2.
    DirectConversation {
        founder: arkret_sdk::ActorId,
    },
}

pub(super) fn realm_create_authority_cache()
-> &'static Mutex<BTreeMap<String, RealmCreateAuthority>> {
    static CACHE: SyncOnceLock<Mutex<BTreeMap<String, RealmCreateAuthority>>> = SyncOnceLock::new();
    CACHE.get_or_init(|| Mutex::new(BTreeMap::new()))
}

pub(super) fn realm_create_authority_from_events(
    events: &[arkret_sdk::Event],
    realm_id: &str,
) -> Option<RealmCreateAuthority> {
    events.iter().find_map(|event| {
        if event.realm_id.as_str() != realm_id || event.kind != arkret_sdk::EventKind::RealmCreate {
            return None;
        }
        if event
            .payload
            .get("object")
            .and_then(|object| object.get("purpose"))
            .and_then(serde_json::Value::as_str)
            == Some("direct_conversation")
        {
            return Some(RealmCreateAuthority::DirectConversation {
                founder: event.actor_id.clone(),
            });
        }
        Some(RealmCreateAuthority::Root {
            controller: event.actor_id.clone(),
        })
    })
}

pub(super) fn realm_owner_covers_event_kind(kind: &str) -> bool {
    arkret_schema::capability_action(CapabilityActionId::REALM_OWNER)
        .is_some_and(|descriptor| descriptor.target_event_kinds.contains(&kind))
}

/// Verify the original producer using its pinned authorized Device key and
/// the SDK's generated Event preimage contract, which omits Event id/proof.
pub(crate) fn verify_creator_genesis_producer(
    record: &arkret_models_collaboration::mls_creator_bootstrap::MlsCreatorBootstrapRecord,
    accepted: &arkret_models_collaboration::mls_creator_bootstrap::MlsCreatorBootstrapAcceptedGenesis,
) -> anyhow::Result<()> {
    let queued = record
        .queued_genesis()
        .ok_or_else(|| anyhow::anyhow!("accepted creator lost signed original"))?;
    accepted.validate_binding(record.intent(), queued)?;
    let projection = record
        .governance_evidence()
        .ok_or_else(|| anyhow::anyhow!("accepted creator lost its pin"))?
        .creator_device_authority()
        .projection();
    let key = crate::identity::device_directory::public_key_from_directory_value(
        projection.device_signing_key_did.as_str(),
    )
    .ok_or_else(|| anyhow::anyhow!("pinned creator signing key is unavailable"))?;
    let event = &accepted.accepted().event;
    let bytes = arkret_sdk::canonical::canonical_json_bytes(&event.digest_payload()?)?;
    arkret_sdk::signatures::verify_ed25519_detached_jws_proof_with_digest_suite(
        event
            .producer_proof
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("accepted Genesis proof missing"))?,
        &bytes,
        record.intent().owner_actor_id(),
        &key,
        queued.signed_genesis().digest_suite(),
    )?;
    Ok(())
}

pub(crate) fn original_creator_checkpoint_secret(
    record: &arkret_models_collaboration::mls_creator_bootstrap::MlsCreatorBootstrapRecord,
    secure_store: &dyn crate::secure_key_store::SecureKeyStore,
    authority: &arkret_sdk::AccountId,
) -> anyhow::Result<String> {
    let material = crate::secure_key_store::load_signing_seed_for(
        secure_store,
        authority,
        record.intent().creator_device_id(),
    )?
    .ok_or_else(|| anyhow::anyhow!("creator recovery requires its original device key"))?;
    let evidence = record
        .governance_evidence()
        .ok_or_else(|| anyhow::anyhow!("creator recovery has no active pinned authority"))?;
    let public = crate::identity::device_directory::public_key_from_directory_value(
        evidence
            .creator_device_authority()
            .projection()
            .device_signing_key_did
            .as_str(),
    )
    .ok_or_else(|| anyhow::anyhow!("creator original device key is unavailable"))?;
    anyhow::ensure!(
        material.device_public_key() == public.ed25519_bytes()?,
        "creator recovery does not hold its pinned original device key"
    );
    crate::outbound_store::creator_protection::checkpoint_secret(
        secure_store,
        authority,
        record.intent().creator_device_id(),
    )
}

pub(crate) fn restored_creator_artifacts(
    record: &arkret_models_collaboration::mls_creator_bootstrap::MlsCreatorBootstrapRecord,
    secure_store: &dyn crate::secure_key_store::SecureKeyStore,
    authority: &arkret_sdk::AccountId,
) -> anyhow::Result<arkret_models_collaboration::mls_creator_bootstrap::MlsCreatorBootstrapArtifacts>
{
    record.validate()?;
    let secret = original_creator_checkpoint_secret(record, secure_store, authority)?;
    restored_creator_artifacts_with_secret(record, &secret)
}

fn restored_creator_artifacts_with_secret(
    record: &arkret_models_collaboration::mls_creator_bootstrap::MlsCreatorBootstrapRecord,
    secret: &str,
) -> anyhow::Result<arkret_models_collaboration::mls_creator_bootstrap::MlsCreatorBootstrapArtifacts>
{
    use arkret_models_collaboration::mls_creator_bootstrap::{
        MlsCreatorBootstrapArtifactChecks, MlsCreatorBootstrapArtifacts,
    };
    let unit = record
        .epoch_zero()
        .ok_or_else(|| anyhow::anyhow!("creator artifact lost original private unit"))?;
    let (_, summary) =
        crate::mls::runtime::restore_creator_epoch_zero(unit, record.intent(), &secret)
            .map_err(|error| anyhow::anyhow!(error.user_message()))?;
    Ok(MlsCreatorBootstrapArtifacts::new(
        record,
        MlsCreatorBootstrapArtifactChecks {
            effective_scope: record.intent().effective_scope().clone(),
            mls_group_id: arkret_sdk::MlsGroupId::new(summary.group_id)
                .map_err(anyhow::Error::msg)?,
            epoch: summary.epoch,
            cipher_suite: summary.cipher_suite,
            creator_leaf_authority: summary.creator_leaf_authority,
            group_info_bytes: summary.group_info_bytes,
            ratchet_tree_bytes: summary.ratchet_tree_bytes,
        },
    )?)
}

impl EventSubmitter {
    /// Persist the registered accepted-create arrow before any MLS material
    /// is produced. The authority root is independently verified with a fresh
    /// nonce and method-native key history; only a complete signed current
    /// snapshot at that same cut can prove exact-scope Genesis absence.
    pub(crate) async fn persist_creator_realm_acceptance(
        &self,
        scope: &arkret_sdk::ScopeRef,
    ) -> anyhow::Result<()> {
        use arkret_models_collaboration::mls_creator_bootstrap::MlsCreatorBootstrapRecord;
        let owner = arkret_sdk::ActorId::account(self.authority()?.clone());
        let store = self.outbound(OutboundLane::Standard)?.store().clone();
        let Some(record) = store.creator_record(&owner, scope).await? else {
            anyhow::bail!("creator acceptance requires a durable closed intent");
        };
        anyhow::ensure!(
            record.quarantine_diagnostic().is_none(),
            "creator recovery is quarantined; preserve its original recovery material"
        );
        anyhow::ensure!(
            record.superseded_winner().is_none(),
            "creator attempt is superseded; use Welcome, device migration or recovery"
        );
        anyhow::ensure!(
            record.rejection().is_none(),
            "creator attempt is rejected; explicitly retry from a new verified absence"
        );
        if matches!(
            record,
            MlsCreatorBootstrapRecord::RealmAccepted { .. }
                | MlsCreatorBootstrapRecord::GovernanceResultPinned { .. }
                | MlsCreatorBootstrapRecord::Epoch0StatePersisted { .. }
                | MlsCreatorBootstrapRecord::GenesisQueued { .. }
                | MlsCreatorBootstrapRecord::GenesisAccepted { .. }
                | MlsCreatorBootstrapRecord::ArtifactsConverged { .. }
                | MlsCreatorBootstrapRecord::Ready { .. }
        ) {
            // This arrow is immutable and idempotent. The following governance
            // pin must authenticate its own current creator/endpoint cut.
            return Ok(());
        }
        let (accepted, snapshot) = self.read_verified_creator_cut(record.intent()).await?;
        store
            .accept_creator_realm(record, accepted, snapshot)
            .await?;
        Ok(())
    }

    /// Pin the entire verified cut and original proposal before producing any
    /// dependent randomness. Once committed, reads never replace this pin.
    pub(crate) async fn persist_creator_governance_pin(
        &self,
        scope: &arkret_sdk::ScopeRef,
    ) -> anyhow::Result<arkret_sdk::MlsGovernanceBindingPayload> {
        use arkret_models_collaboration::mls_creator_bootstrap::{
            MlsCreatorBootstrapDeviceAuthority, MlsCreatorBootstrapGovernanceEvidence,
        };
        self.persist_creator_realm_acceptance(scope).await?;
        let owner = arkret_sdk::ActorId::account(self.authority()?.clone());
        let store = self.outbound(OutboundLane::Standard)?.store().clone();
        let record = store
            .creator_record(&owner, scope)
            .await?
            .ok_or_else(|| anyhow::anyhow!("creator governance pin requires durable acceptance"))?;
        let intent = record.intent();
        let signer = crate::event_signer::active_signer().ok_or_else(|| {
            anyhow::anyhow!("creator governance pin requires its original signer")
        })?;
        anyhow::ensure!(
            signer.verification_method() == intent.creator_signer_method().as_str()
                && signer.device_id() == Some(intent.creator_device_id().as_str()),
            "creator governance pin cannot take over another signer or device"
        );
        if let Some(evidence) = record.governance_evidence() {
            anyhow::ensure!(
                crate::identity::device_directory::local_signer_matches_device_projection(
                    &signer,
                    self.authority()?,
                    intent.creator_device_id(),
                    evidence.creator_device_authority().projection()
                ),
                "pinned creator authority does not match the local private signer"
            );
            return Ok(evidence.governance_binding().clone());
        }
        anyhow::ensure!(
            matches!(
                intent.creator_endpoint(),
                arkret_sdk::MlsWelcomeRecipientEndpoint::Device { .. }
            ),
            "Agent creator governance pin requires independently verified Agent authorization"
        );
        let keys = crate::transport::keys::query_keys(
            &self.http,
            self.authority()?,
            intent.creator_device_id().as_str(),
        )
        .await?;
        let (accepted, snapshot) = self.read_verified_creator_cut(intent).await?;
        let device = MlsCreatorBootstrapDeviceAuthority::from_self_keys_query(
            intent,
            &keys,
            arkret_sdk::canonical::normalize_timestamp_canonical(chrono::Utc::now()),
        )?;
        anyhow::ensure!(
            crate::identity::device_directory::local_signer_matches_device_projection(
                &signer,
                self.authority()?,
                intent.creator_device_id(),
                device.projection()
            ),
            "current creator authorization does not match the original local signer"
        );
        let evidence =
            MlsCreatorBootstrapGovernanceEvidence::new_device(intent, accepted, snapshot, device)?;
        let binding = evidence.governance_binding().clone();
        store.pin_creator_governance(record, evidence).await?;
        Ok(binding)
    }

    /// Commit the entire MLS output and unsigned core before any observable
    /// material. On restart only the committed recovery unit is restored.
    pub(crate) async fn persist_creator_epoch_zero(
        &self,
        scope: &arkret_sdk::ScopeRef,
        secure_store: &dyn crate::secure_key_store::SecureKeyStore,
    ) -> anyhow::Result<(
        arkret_models_collaboration::mls_creator_bootstrap::MlsCreatorBootstrapRecord,
        crate::mls::runtime::InitialMlsCheckpointSummary,
    )> {
        use arkret_models_collaboration::mls_creator_bootstrap::MlsCreatorBootstrapEpochZero;
        self.persist_creator_governance_pin(scope).await?;
        let owner = arkret_sdk::ActorId::account(self.authority()?.clone());
        let vault = self.outbound(OutboundLane::Standard)?.store().clone();
        let mut record = vault
            .creator_record(&owner, scope)
            .await?
            .ok_or_else(|| anyhow::anyhow!("creator epoch zero lost its durable pin"))?;
        let intent = record.intent();
        let secret = original_creator_checkpoint_secret(&record, secure_store, self.authority()?)?;
        if record.epoch_zero().is_none() {
            let evidence = record
                .governance_evidence()
                .ok_or_else(|| anyhow::anyhow!("creator epoch zero requires a pin"))?;
            let state = self
                .state_store
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("creator epoch zero requires account state"))?;
            anyhow::ensure!(
                !state.read(
                    |store| store.realm_projection_has_retired_minimal_metadata_marker(
                        scope.realm_id().as_str()
                    )
                ),
                "retired Realm cannot create MLS material"
            );
            let (private, summary) = crate::mls::runtime::generate_creator_epoch_zero(
                scope,
                self.authority()?,
                intent.creator_device_id(),
                evidence.governance_binding(),
                &secret,
                Some(
                    &evidence
                        .creator_device_authority()
                        .projection()
                        .device_authorize_event_id,
                ),
            )
            .map_err(|error| anyhow::anyhow!(error.user_message()))?;
            let unsigned =
                crate::mls::runtime::freeze_creator_genesis_core(intent, evidence, &summary)
                    .map_err(|error| anyhow::anyhow!(error.user_message()))?;
            let unit = MlsCreatorBootstrapEpochZero::new(
                intent,
                evidence,
                serde_json::to_vec(&private)?,
                summary.group_info_bytes,
                summary.ratchet_tree_bytes,
                unsigned,
            )?;
            vault
                .persist_creator_epoch_zero(record.clone(), unit)
                .await?;
            record = vault
                .creator_record(&owner, scope)
                .await?
                .ok_or_else(|| anyhow::anyhow!("committed creator epoch zero vanished"))?;
        }
        record.validate()?;
        let unit = record
            .epoch_zero()
            .ok_or_else(|| anyhow::anyhow!("creator epoch-zero commit did not install its unit"))?;
        let (private, summary) =
            match crate::mls::runtime::restore_creator_epoch_zero(unit, record.intent(), &secret) {
                Ok(restored) => restored,
                Err(error) => {
                    self.quarantine_creator_private_failure(&vault, &record, error.user_message())
                        .await?;
                    anyhow::bail!(
                        "creator private recovery is quarantined; original material retained"
                    );
                }
            };
        let account_secret = crate::mls::runtime::load_device_checkpoint_secret(
            secure_store,
            self.authority()?,
            record.intent().creator_device_id(),
        )?;
        let state = self
            .state_store
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("creator recovery requires account state"))?;
        let cache_check = state.read(|store| -> anyhow::Result<bool> {
            if let Some(existing) = store.mls_checkpoint_for_scope(scope) {
                anyhow::ensure!(
                    existing.group_id == record.intent().mls_group_id().as_str(),
                    "creator cache belongs to another group"
                );
                if existing.epoch > 0 {
                    // Never overwrite later accepted private state with epoch zero.
                    anyhow::ensure!(
                        store.mls_genesis_emitted_for_scope(scope)
                            && record.accepted_genesis().is_some_and(|accepted| store
                                .current_mls_group_for_scope(scope)
                                .is_some_and(|current| current.genesis_event_ref
                                    == accepted.accepted().event.event_id)),
                        "advanced creator cache has no accepted Genesis"
                    );
                    return Ok(true);
                }
                let restored =
                    crate::mls::persistence::restore_envelope(&existing, &account_secret, 0)?;
                let (public, tree) = restored.public_group_state_bytes()?;
                if public == unit.group_info_bytes() && tree == unit.ratchet_tree_bytes() {
                    return Ok(true);
                }
                anyhow::ensure!(restored.scope() == scope && restored.epoch() == 0
                    && creator_cache_belongs_to_closed_attempt(&record, &existing,
                        store.mls_genesis_emitted_for_scope(scope), &public, &tree)?,
                    "creator cache differs from the immutable recovery unit and every closed attempt");
                // Only the derived, unaccepted cache of an authenticated closed
                // attempt may be replaced. The new formal unit is already durable.

            }
            Ok(false)
        });
        let already_installed = match cache_check {
            Ok(installed) => installed,
            Err(error) => {
                self.quarantine_creator_private_failure(&vault, &record, error.to_string())
                    .await?;
                anyhow::bail!(
                    "creator private recovery is quarantined; original material retained"
                );
            }
        };
        if !already_installed {
            state.write(|store| -> anyhow::Result<()> {
                let mut salt = [0u8; 16];
                getrandom::fill(&mut salt)?;
                let cache = crate::mls::persistence::encrypt_state(
                    scope.realm_id().as_str(),
                    record.intent().mls_group_id().as_str(),
                    0,
                    &private,
                    &account_secret,
                    &salt,
                );
                store
                    .save_mls_checkpoint_for_scope(scope, cache)
                    .map_err(anyhow::Error::msg)
            })?;
        }
        Ok((record, summary))
    }

    /// Resume the original signed Genesis, or establish its bytes and queue
    /// association atomically from the already committed unsigned core.
    pub(crate) async fn submit_creator_genesis(
        &self,
        mut record: arkret_models_collaboration::mls_creator_bootstrap::MlsCreatorBootstrapRecord,
    ) -> anyhow::Result<SubmitEventResult> {
        let _single_writer = outbound_submit_lock().lock().await;
        let vault = self.outbound(OutboundLane::Standard)?.store().clone();
        let submission = if let Some(queued) = record.queued_genesis() {
            event_submission(queued.signed_genesis())?
        } else {
            let mut signed = record
                .epoch_zero()
                .ok_or_else(|| anyhow::anyhow!("creator signing requires durable epoch zero"))?
                .unsigned_genesis()
                .clone();
            let intent = EventIntent::from_authored(signed.event());
            self.verify_actor_authority(&intent).await?;
            self.ensure_realm_detail_current(signed.realm_id.as_str())
                .await?;
            let signer = crate::event_signer::active_signer()
                .ok_or_else(|| anyhow::anyhow!("creator signing requires the original signer"))?;
            anyhow::ensure!(
                signer.verification_method() == record.intent().creator_signer_method().as_str()
                    && signer.device_id() == Some(record.intent().creator_device_id().as_str()),
                "creator signed original cannot change its signer"
            );
            let proof_context = self.event_proof_context(signed.digest_suite()).await?;
            self.sign_authored_event(&intent, &mut signed, proof_context)?;
            let submission = vault
                .queue_creator_genesis(record.clone(), signed.clone())
                .await?;
            record.queue_genesis(signed)?;
            submission
        };
        let local_operation_id = submission.event_id.to_string();
        let item = self
            .enqueue_and_drive(QueuedWrite {
                lane: OutboundLane::Standard,
                submission,
                local_operation_id,
                post_accept: PostAccept::None,
                retry_scope: InteractiveRetryScope::Ordinary,
            })
            .await?;
        settled_outbound_result(&item)
    }

    /// Each worker attempt must prove absence at a verified exact current cut.
    /// An accepted winner is reconciled by the transaction owner, never by
    /// treating a gate refusal as an authority rejection.
    pub(super) async fn ensure_creator_genesis_replay_gate(
        &self,
        request: &arkret_models_collaboration::authority_commit::SelfAuthoritySubmitRequest,
    ) -> anyhow::Result<
        Option<(
            arkret_sdk::EventId,
            arkret_models_collaboration::mls_creator_bootstrap::MlsCreatorBootstrapVerifiedAbsence,
        )>,
    > {
        let arkret_models_collaboration::authority_commit::SelfAuthoritySubmitRequest::Event(
            submission,
        ) = request
        else {
            return Ok(None);
        };
        let event = &submission.event;
        if event.kind != arkret_sdk::EventKind::MlsGenesis {
            return Ok(None);
        }
        let owner = arkret_sdk::ActorId::account(self.authority()?.clone());
        let vault = self.outbound(OutboundLane::Standard)?.store().clone();
        let Some(record) = vault.creator_record(&owner, &event.scope_ref).await? else {
            return Ok(None);
        };
        let queued = record
            .queued_genesis()
            .ok_or_else(|| anyhow::anyhow!("creator worker has no durable signed original"))?;
        anyhow::ensure!(
            queued.signed_genesis().event() == event,
            "creator worker cannot replace frozen bytes"
        );
        anyhow::ensure!(
            record.accepted_genesis().is_none(),
            "creator Genesis already accepted; stop replay"
        );
        let evidence = record
            .governance_evidence()
            .ok_or_else(|| anyhow::anyhow!("creator worker lost its pin"))?;
        let (bundle, snapshot, accepted) = crate::realm_events_engine::verified_creator_genesis(
            &self.http,
            record.intent(),
            evidence.accepted_create(),
        )
        .await?;
        if let Some(accepted) = accepted {
            if record
                .closed_attempts()
                .iter()
                .any(|closed| closed.event_id() == &accepted.event.event_id)
            {
                self.quarantine_creator_accepted_conflict(&vault, record, accepted, bundle)
                    .await?;
                anyhow::bail!("creator accepted-result contradiction remains stopped");
            }
            anyhow::bail!("creator Genesis winner must be reconciled before replay");
        }
        let pinned = evidence.accepted_create();
        let fresh_create = arkret_models_collaboration::mls_creator_bootstrap::MlsCreatorBootstrapAcceptedCreate::new(
            record.intent(), pinned.accepted_event().clone(), pinned.covering_commit().clone(),
            pinned.digest_suite(), bundle,
        )?;
        let absence = arkret_models_collaboration::mls_creator_bootstrap::MlsCreatorBootstrapVerifiedAbsence::new(
            record.intent(), fresh_create, snapshot,
        )?;
        Ok(Some((event.event_id.clone(), absence)))
    }

    async fn quarantine_creator_accepted_conflict(
        &self,
        vault: &crate::outbound_store::InksonOutboundStore,
        record: arkret_models_collaboration::mls_creator_bootstrap::MlsCreatorBootstrapRecord,
        accepted: arkret_wire::CommittedEventFullView,
        bundle: arkret_wire::RealmAuthorityBundle,
    ) -> anyhow::Result<()> {
        use arkret_models_collaboration::mls_creator_bootstrap::{
            MlsCreatorBootstrapInvariant, MlsCreatorBootstrapKnownGenesis,
        };
        let known =
            MlsCreatorBootstrapKnownGenesis::authenticated_winner(&record, accepted, bundle)?;
        vault.quarantine_creator(record, MlsCreatorBootstrapInvariant::AcceptedResult,
            "independently verified accepted Genesis contradicts a definitely rejected or closed attempt".into(),
            Some(known)).await?;
        anyhow::bail!(
            "creator accepted-result contradiction is quarantined; original material retained"
        )
    }

    pub(crate) async fn reopen_rejected_creator(
        &self,
        scope: &arkret_sdk::ScopeRef,
    ) -> anyhow::Result<()> {
        use arkret_models_collaboration::mls_creator_bootstrap::{
            MlsCreatorBootstrapAcceptedCreate, MlsCreatorBootstrapVerifiedAbsence,
            MlsCreatorBootstrapWinner,
        };
        let vault = self.outbound(OutboundLane::Standard)?.store().clone();
        let owner = arkret_sdk::ActorId::account(self.authority()?.clone());
        let record = vault
            .creator_record(&owner, scope)
            .await?
            .ok_or_else(|| anyhow::anyhow!("creator restart lost its terminal record"))?;
        anyhow::ensure!(
            record.rejection().is_some(),
            "creator restart requires an explicitly rejected attempt"
        );
        let create = record
            .accepted_create()
            .ok_or_else(|| anyhow::anyhow!("creator restart lost accepted scope create"))?;
        let (bundle, snapshot, accepted) = crate::realm_events_engine::verified_creator_genesis(
            &self.http,
            record.intent(),
            create,
        )
        .await?;
        if let Some(accepted) = accepted {
            if record
                .rejection()
                .is_some_and(|rejection| rejection.event_id() == &accepted.event.event_id)
                || record
                    .closed_attempts()
                    .iter()
                    .any(|closed| closed.event_id() == &accepted.event.event_id)
            {
                return self
                    .quarantine_creator_accepted_conflict(&vault, record, accepted, bundle)
                    .await;
            }
            let winner = MlsCreatorBootstrapWinner::new(&record, accepted, bundle)?;
            vault.supersede_creator(record, winner).await?;
            anyhow::bail!(
                "creator restart found another accepted Genesis; use Welcome, migration or recovery"
            );
        }
        let fresh_create = MlsCreatorBootstrapAcceptedCreate::new(
            record.intent(),
            create.accepted_event().clone(),
            create.covering_commit().clone(),
            create.digest_suite(),
            bundle,
        )?;
        let absence =
            MlsCreatorBootstrapVerifiedAbsence::new(record.intent(), fresh_create, snapshot)?;
        vault.reopen_creator(record, absence).await?;
        Ok(())
    }

    /// Reconcile the frozen original before any resend. Only a complete,
    /// authenticated exact query can settle it or prove definite absence.
    pub(crate) async fn reconcile_creator_genesis(
        &self,
        scope: &arkret_sdk::ScopeRef,
    ) -> anyhow::Result<Option<arkret_sdk::EventId>> {
        use arkret_models_collaboration::mls_creator_bootstrap::MlsCreatorBootstrapAcceptedGenesis;
        let vault = self.outbound(OutboundLane::Standard)?.store().clone();
        let owner = arkret_sdk::ActorId::account(self.authority()?.clone());
        let record = vault
            .creator_record(&owner, scope)
            .await?
            .ok_or_else(|| anyhow::anyhow!("creator exact query lost its durable intent"))?;
        anyhow::ensure!(
            record.quarantine_diagnostic().is_none(),
            "creator recovery is quarantined; preserve its original recovery material"
        );
        anyhow::ensure!(
            record.superseded_winner().is_none(),
            "creator attempt is superseded; use Welcome, device migration or recovery"
        );
        anyhow::ensure!(
            record.rejection().is_none(),
            "creator attempt is rejected; explicitly retry from a new verified absence"
        );
        if let Some(accepted) = record.accepted_genesis() {
            record.validate()?;
            return Ok(Some(accepted.accepted().event.event_id.clone()));
        }
        let evidence = record
            .governance_evidence()
            .ok_or_else(|| anyhow::anyhow!("creator exact query requires its original pin"))?;
        let (bundle, _, accepted) = crate::realm_events_engine::verified_creator_genesis(
            &self.http,
            record.intent(),
            evidence.accepted_create(),
        )
        .await?;
        let Some(accepted) = accepted else {
            return Ok(None);
        };
        if record
            .closed_attempts()
            .iter()
            .any(|closed| closed.event_id() == &accepted.event.event_id)
        {
            self.quarantine_creator_accepted_conflict(&vault, record, accepted, bundle)
                .await?;
            anyhow::bail!("creator accepted-result contradiction remains stopped");
        }
        if record
            .queued_genesis()
            .is_none_or(|queued| queued.signed_genesis().event_id() != &accepted.event.event_id)
        {
            let winner =
                arkret_models_collaboration::mls_creator_bootstrap::MlsCreatorBootstrapWinner::new(
                    &record, accepted, bundle,
                )?;
            vault.supersede_creator(record, winner).await?;
            anyhow::bail!(
                "another exact accepted Genesis won; creator attempt is superseded and its loser queue stopped"
            );
        }
        let queued = record.queued_genesis().ok_or_else(|| {
            anyhow::anyhow!(
                "another Genesis already won this scope; creator material cannot be adopted"
            )
        })?;
        let carrier =
            MlsCreatorBootstrapAcceptedGenesis::new(record.intent(), queued, accepted, bundle)?;
        verify_creator_genesis_producer(&record, &carrier)?;
        let id = carrier.accepted().event.event_id.clone();
        vault.accept_creator_genesis(record, carrier).await?;
        Ok(Some(id))
    }

    async fn quarantine_creator_private_failure(
        &self,
        vault: &crate::outbound_store::InksonOutboundStore,
        record: &arkret_models_collaboration::mls_creator_bootstrap::MlsCreatorBootstrapRecord,
        detail: String,
    ) -> anyhow::Result<()> {
        use arkret_models_collaboration::mls_creator_bootstrap::{
            MlsCreatorBootstrapInvariant, MlsCreatorBootstrapKnownGenesis,
        };
        let known =
            record
                .accepted_genesis()
                .map(|accepted| MlsCreatorBootstrapKnownGenesis::Original {
                    acceptance: Box::new(accepted.clone()),
                });
        vault
            .quarantine_creator(
                record.clone(),
                MlsCreatorBootstrapInvariant::PrivateMaterial,
                detail,
                known,
            )
            .await?;
        Ok(())
    }

    pub(crate) async fn restore_creator_artifacts_or_quarantine(
        &self,
        vault: &crate::outbound_store::InksonOutboundStore,
        record: &arkret_models_collaboration::mls_creator_bootstrap::MlsCreatorBootstrapRecord,
        secure_store: &dyn crate::secure_key_store::SecureKeyStore,
    ) -> anyhow::Result<
        arkret_models_collaboration::mls_creator_bootstrap::MlsCreatorBootstrapArtifacts,
    > {
        let secret = original_creator_checkpoint_secret(record, secure_store, self.authority()?)?;
        match restored_creator_artifacts_with_secret(record, &secret) {
            Ok(artifacts) => Ok(artifacts),
            Err(error) => {
                self.quarantine_creator_private_failure(vault, record, error.to_string())
                    .await?;
                anyhow::bail!("creator private recovery is quarantined; original material retained")
            }
        }
    }

    /// Restore the retained winning private unit before its whole artifact
    /// install. This never generates material or changes the accepted Event.
    pub(crate) async fn converge_creator_artifacts(
        &self,
        scope: &arkret_sdk::ScopeRef,
        secure_store: &dyn crate::secure_key_store::SecureKeyStore,
    ) -> anyhow::Result<()> {
        let vault = self.outbound(OutboundLane::Standard)?.store().clone();
        let owner = arkret_sdk::ActorId::account(self.authority()?.clone());
        let record = vault
            .creator_record(&owner, scope)
            .await?
            .ok_or_else(|| anyhow::anyhow!("creator artifact lost its durable acceptance"))?;
        let artifacts = self
            .restore_creator_artifacts_or_quarantine(&vault, &record, secure_store)
            .await?;
        vault.converge_creator_artifacts(record, artifacts).await?;
        Ok(())
    }

    /// Re-read the durable install and restore its private state again; a
    /// previously checked in-memory record cannot stand in for this boundary.
    pub(crate) async fn publish_creator_ready(
        &self,
        scope: &arkret_sdk::ScopeRef,
        secure_store: &dyn crate::secure_key_store::SecureKeyStore,
    ) -> anyhow::Result<()> {
        let vault = self.outbound(OutboundLane::Standard)?.store().clone();
        let owner = arkret_sdk::ActorId::account(self.authority()?.clone());
        let record = vault
            .creator_record(&owner, scope)
            .await?
            .ok_or_else(|| anyhow::anyhow!("creator ready publication lost artifacts"))?;
        let artifacts = self
            .restore_creator_artifacts_or_quarantine(&vault, &record, secure_store)
            .await?;
        if record.artifacts() != Some(&artifacts) {
            self.quarantine_creator_private_failure(
                &vault,
                &record,
                "creator durable artifact/private state mismatch".into(),
            )
            .await?;
            anyhow::bail!("creator private recovery is quarantined; original material retained");
        }
        let state = self
            .state_store
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("creator readiness requires account state"))?;
        let account_secret = crate::mls::runtime::load_device_checkpoint_secret(
            secure_store,
            self.authority()?,
            record.intent().creator_device_id(),
        )?;
        let snapshot = state
            .read(|store| store.durable_mls_checkpoint_for_scope(scope))?
            .ok_or_else(|| anyhow::anyhow!("creator private cache is not durably installed"))?;
        let private_check = (|| -> anyhow::Result<()> {
            let accepted = record
                .accepted_genesis()
                .ok_or_else(|| anyhow::anyhow!("creator readiness lost accepted Genesis"))?;
            if snapshot.epoch == 0 {
                anyhow::ensure!(
                    snapshot.group_state_event_id.as_ref()
                        == Some(&accepted.accepted().event.event_id),
                    "creator private cache has another Genesis ref"
                );
                let group =
                    crate::mls::persistence::restore_envelope(&snapshot, &account_secret, 0)?;
                let (info, tree) = group.public_group_state_bytes()?;
                let unit = record
                    .epoch_zero()
                    .ok_or_else(|| anyhow::anyhow!("creator readiness lost private unit"))?;
                anyhow::ensure!(
                    info == unit.group_info_bytes() && tree == unit.ratchet_tree_bytes(),
                    "creator durable private cache differs from the winning unit"
                );
            }
            Ok(())
        })();
        if let Err(error) = private_check {
            self.quarantine_creator_private_failure(&vault, &record, error.to_string())
                .await?;
            anyhow::bail!("creator private recovery is quarantined; original material retained");
        }
        vault.publish_creator_ready(record).await?;
        state.write(|_| {});
        Ok(())
    }

    async fn read_verified_creator_cut(
        &self,
        intent: &arkret_models_collaboration::mls_creator_bootstrap::MlsCreatorBootstrapIntent,
    ) -> anyhow::Result<(
        arkret_models_collaboration::mls_creator_bootstrap::MlsCreatorBootstrapAcceptedCreate,
        arkret_wire::RealmStateSnapshot,
    )> {
        use arkret_models_collaboration::mls_creator_bootstrap::MlsCreatorBootstrapAcceptedCreate;
        let arkret_sdk::ScopeRef::Realm { realm_id } = intent.effective_scope() else {
            anyhow::bail!("Realm creator acceptance requires an exact Realm scope");
        };
        let authority = garth::AuthorityClient::new(self.http.clone());
        let (bundle, freshness, mut replica) =
            crate::realm_events_engine::fresh_verified_realm(&authority, &self.http, realm_id)
                .await?;
        let snapshot = self.http.realm_state_snapshot_head(realm_id).await?;
        let keys = garth::fetch_historical_station_key_directory(
            &self.http,
            &bundle,
            None,
            Some(&snapshot),
        )
        .await?;
        let freshness = arkret_identity::RealmAuthorityFreshness::new(
            chrono::Utc::now(),
            freshness.expected_nonce,
        );
        replica.install_verified_current_snapshot_heads(&snapshot, &freshness, &keys)?;
        let accepted = MlsCreatorBootstrapAcceptedCreate::new(
            intent,
            bundle.genesis_event.clone(),
            bundle.genesis_commit.clone(),
            realm_id.digest_suite_code().digest_suite(),
            bundle,
        )?;
        Ok((accepted, snapshot))
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn realm_id() -> arkret_sdk::RealmId {
        arkret_sdk::RealmId::new("ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19".to_owned())
            .unwrap()
    }

    fn event(kind: arkret_sdk::EventKind, scope_ref: arkret_sdk::ScopeRef) -> arkret_sdk::Event {
        arkret_sdk::Event {
            event_id: arkret_sdk::EventId::from_digest(arkret_sdk::DigestSuite::Sha256, [7; 32]),
            kind,
            realm_id: realm_id(),
            scope_ref,
            actor_id: arkret_sdk::ActorId::service(
                arkret_sdk::DidCoreId::new("ak:did_core:web:alice.example".to_owned()).unwrap(),
            ),
            executed_by: None,
            authorization_ref: None,
            applet_id: None,
            external_ref: None,
            created_at: chrono::Utc::now(),
            semantic_refs: Vec::new(),
            payload: BTreeMap::from([("object".to_owned(), json!({}))]),
            producer_proof: None,
        }
    }

    #[test]
    fn realm_create_authority_reads_the_founding_actor() {
        let realm_scope = arkret_sdk::ScopeRef::Realm {
            realm_id: realm_id(),
        };
        let create = event(arkret_sdk::EventKind::RealmCreate, realm_scope);
        let expected = create.actor_id.clone();

        assert_eq!(
            realm_create_authority_from_events(&[create], realm_id().as_str()),
            Some(RealmCreateAuthority::Root {
                controller: expected
            })
        );
    }

    #[test]
    fn direct_conversation_purpose_is_not_an_ordinary_realm_owner() {
        let realm_scope = arkret_sdk::ScopeRef::Realm {
            realm_id: realm_id(),
        };
        let mut create = event(arkret_sdk::EventKind::RealmCreate, realm_scope);
        create.payload.insert(
            "object".to_owned(),
            json!({ "purpose": "direct_conversation" }),
        );

        let founder = create.actor_id.clone();
        assert_eq!(
            realm_create_authority_from_events(&[create], realm_id().as_str()),
            Some(RealmCreateAuthority::DirectConversation { founder })
        );
    }
}
