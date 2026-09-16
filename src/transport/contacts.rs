use arkret_sdk::contact_operations::{
    ContactCommitPhase, ContactCommitRequestBody, ContactOperationOutcome,
    ContactOperationRequestBody, ContactPeer, ContactPreparePhase, ContactPrepareRequestBody,
    ContactPreparedOutcome, ContactScope,
};
use arkret_sdk::{IdempotencyKey, PreparedEventDraft, ProtocolOperationId, ReservationHandle};

pub(crate) mod pending;
#[cfg(test)]
mod tests;

pub(crate) const DEFAULT_CONTACT_SCOPE_NAMES: [&str; 5] = [
    "invite",
    "direct_message",
    "voice_call",
    "video_call",
    "presence",
];

pub(crate) fn default_contact_scopes() -> Vec<ContactScope> {
    DEFAULT_CONTACT_SCOPE_NAMES
        .iter()
        .map(|scope| contact_scope(scope).expect("default Contact scopes are registered"))
        .collect()
}

#[cfg(test)]
mod default_scope_tests {
    #[test]
    fn ordinary_contacts_grant_all_five_permissions_in_canonical_order() {
        let scopes = super::default_contact_scopes();
        assert_eq!(
            serde_json::to_value(&scopes).unwrap(),
            serde_json::json!([
                "invite",
                "direct_message",
                "voice_call",
                "video_call",
                "presence"
            ])
        );
        assert!(scopes.windows(2).all(|pair| pair[0] < pair[1]));
    }
}

#[derive(Clone)]
pub(crate) struct ContactSessionFence {
    epoch: u64,
    signer: std::sync::Arc<crate::event_signer::InksonEventSigner>,
    scope: Option<crate::secure_key_store::ActiveDeviceSeedScope>,
}

impl ContactSessionFence {
    pub(crate) fn capture() -> anyhow::Result<Self> {
        Ok(Self {
            epoch: crate::identity::device_directory::cache_epoch(),
            signer: crate::event_signer::active_signer()
                .ok_or_else(|| anyhow::anyhow!("active Contact signer is required"))?,
            scope: crate::secure_key_store::active_device_seed_scope(),
        })
    }

    pub(crate) fn check(&self) -> anyhow::Result<()> {
        let active = crate::event_signer::active_signer();
        anyhow::ensure!(
            self.epoch == crate::identity::device_directory::cache_epoch()
                && self.scope == crate::secure_key_store::active_device_seed_scope()
                && active
                    .as_ref()
                    .is_some_and(|signer| std::sync::Arc::ptr_eq(signer, &self.signer)),
            "Contact operation belongs to a replaced account session or signer"
        );
        Ok(())
    }
}

pub(crate) struct PrincipalSuccessorSealContext {
    actor_id: arkret_sdk::ActorId,
    control_realm: arkret_sdk::RealmId,
    predecessor: arkret_sdk::SealId,
    fence: ContactSessionFence,
    journal: Option<pending::Journal>,
}

pub(crate) async fn prepare_principal_successor_seal(
    http: &arkret_sdk::http_client::Client,
    principal_event: &arkret_sdk::Event,
) -> anyhow::Result<PrincipalSuccessorSealContext> {
    let fence = ContactSessionFence::capture()?;
    let signer = &fence.signer;
    let principal = arkret_sdk::Did::new(signer.signer_did().to_owned())?;
    let principal_id = arkret_sdk::project_did_to_core_id(&principal)?;
    let actor_id = principal_successor_actor(&principal_event.actor_id, &principal_id)?;
    let control_realm = principal_event.realm_id.clone();
    let view = http.seals_frontier(control_realm.clone()).await?.frontier;
    fence.check()?;
    if view.realm_id != control_realm {
        anyhow::bail!("principal control frontier returned a different Realm");
    }
    let predecessor = view.sole_leaf()?.clone();
    Ok(PrincipalSuccessorSealContext {
        actor_id,
        control_realm,
        predecessor,
        fence,
        journal: None,
    })
}

fn principal_successor_actor(
    actor_id: &arkret_sdk::ActorId,
    signer_principal: &arkret_sdk::DidCoreId,
) -> anyhow::Result<arkret_sdk::ActorId> {
    let account = actor_id.as_account_id().ok_or_else(|| {
        anyhow::anyhow!("principal successor Seal requires an account Event actor")
    })?;
    if &account.principal_id != signer_principal {
        anyhow::bail!("prepared principal Event actor does not match the active signer");
    }
    // First enrollment runs before app connect. The signed Event already
    // supplies the exact AccountId; no ambient Station may replace it.
    Ok(actor_id.clone())
}

#[cfg(test)]
mod principal_successor_tests {
    #[test]
    fn successor_preserves_the_signed_account_before_app_connect() {
        let principal = arkret_sdk::DidCoreId::new("ak:did_core:web:alice.example").unwrap();
        let station = arkret_sdk::DidCoreId::new("ak:did_core:web:enrollment.example").unwrap();
        let actor =
            arkret_sdk::ActorId::account(arkret_sdk::AccountId::new(principal.clone(), station));
        assert_eq!(
            super::principal_successor_actor(&actor, &principal).unwrap(),
            actor
        );
        let other = arkret_sdk::DidCoreId::new("ak:did_core:web:bob.example").unwrap();
        assert!(super::principal_successor_actor(&actor, &other).is_err());
    }
}

pub(crate) async fn submit_principal_successor_seal(
    http: &arkret_sdk::http_client::Client,
    context: PrincipalSuccessorSealContext,
    principal_event: &arkret_sdk::Event,
) -> anyhow::Result<()> {
    let outcome = confirm_principal_successor_seal(http, context, principal_event).await?;
    anyhow::ensure!(
        outcome == arkret_sdk::CommandOutcome::Committed,
        "principal command unit was rejected"
    );
    Ok(())
}

async fn confirm_principal_successor_seal(
    http: &arkret_sdk::http_client::Client,
    context: PrincipalSuccessorSealContext,
    principal_event: &arkret_sdk::Event,
) -> anyhow::Result<arkret_sdk::CommandOutcome> {
    context.fence.check()?;
    anyhow::ensure!(
        principal_event.actor_id == context.actor_id
            && principal_event.realm_id == context.control_realm,
        "principal Seal Event differs from the frozen account/Realm"
    );
    let principal_digest = principal_event.event_id.event_digest();
    if let Some(outcome) = principal_event_terminal_outcome(http, principal_event).await? {
        context.fence.check()?;
        return Ok(outcome);
    }
    context.fence.check()?;
    let seal = if let Some(seal) = context.journal.as_ref().and_then(pending::Journal::seal) {
        seal
    } else {
        let device_id = context
            .fence
            .signer
            .device_id()
            .ok_or_else(|| anyhow::anyhow!("PCR signer requires a bound device"))?;
        let request =
            if let Some(request) = context.journal.as_ref().and_then(pending::Journal::request) {
                request
            } else {
                arkret_sdk::SealPrepareRequestBody {
                    realm_id: context.control_realm.clone(),
                    predecessor_ref: context.predecessor.clone(),
                    event_digests: vec![principal_digest.clone()],
                    hlc: crate::signing_stamp::issue_protocol_hlc(
                        context.actor_id.signing_principal_id().as_str(),
                        device_id,
                        context.control_realm.as_str(),
                    )?,
                }
            };
        if let Some(journal) = &context.journal {
            journal.save_request(&request).await?;
            context.fence.check()?;
        }
        let prepared = match http.seals_prepare(&request).await {
            Ok(prepared) => prepared,
            Err(error) => {
                context.fence.check()?;
                if let Some(outcome) =
                    principal_event_terminal_outcome(http, principal_event).await?
                {
                    context.fence.check()?;
                    return Ok(outcome);
                }
                context.fence.check()?;
                if !contact_commit_is_unconfirmed(&error) {
                    return Err(error.into());
                }
                // A lost preparation response must reuse the exact frozen HLC/body.
                http.seals_prepare(&request).await?
            }
        };
        context.fence.check()?;
        let seal =
            context
                .fence
                .signer
                .sign_prepared_pcr_seal(&context.actor_id, &request, &prepared)?;
        crate::event_submit::command_unit_outcome(&seal.command_results, &principal_digest)?;
        if let Some(journal) = &context.journal {
            journal.save_seal(&seal).await?;
            context.fence.check()?;
        }
        seal
    };
    let submitted = http.events_submit_seal(&seal).await;
    context.fence.check()?;
    let outcome = match submitted {
        Ok(outcome) => outcome,
        Err(error) => {
            if let Some(outcome) = principal_event_terminal_outcome(http, principal_event).await? {
                context.fence.check()?;
                return Ok(outcome);
            }
            context.fence.check()?;
            if !contact_commit_is_unconfirmed(&error) {
                return Err(error.into());
            }
            // Never prepare a second candidate after an uncertain submission.
            let retried = http.events_submit_seal(&seal).await;
            context.fence.check()?;
            match retried {
                Ok(outcome) => outcome,
                Err(error) => {
                    if let Some(outcome) =
                        principal_event_terminal_outcome(http, principal_event).await?
                    {
                        context.fence.check()?;
                        return Ok(outcome);
                    }
                    return Err(error.into());
                }
            }
        }
    };
    if outcome.seal_id != seal.id
        || outcome.post_state_root != seal.state_root
        || outcome.accepted_event_digests != seal.delta
    {
        anyhow::bail!("Station returned a mismatched principal successor Seal outcome");
    }
    crate::event_submit::command_unit_outcome(&seal.command_results, &principal_digest)
}

async fn principal_event_terminal_outcome(
    http: &arkret_sdk::http_client::Client,
    event: &arkret_sdk::Event,
) -> anyhow::Result<Option<arkret_sdk::CommandOutcome>> {
    let decision = http
        .read_control_proposal_decision(&arkret_sdk::ControlProposalDecisionReadRequestBody {
            realm_id: event.realm_id.clone(),
            proposal_digest: event.event_id.event_digest(),
        })
        .await?;
    anyhow::ensure!(
        decision.proposal_event_kind == event.kind.as_str(),
        "principal decision returned a different Event kind"
    );
    if decision.proposal_state != arkret_sdk::ControlProposalState::Sealed {
        anyhow::ensure!(
            decision.accepted_seal_id.is_none(),
            "pending principal decision carried a terminal Seal"
        );
        return Ok(None);
    }
    let seal_id = decision
        .accepted_seal_id
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("terminal principal decision omitted its exact Seal"))?;
    let outcome = crate::event_submit::server_command_unit_outcome(
        http,
        &event.realm_id,
        &event.event_id,
        seal_id,
    )
    .await?;
    Ok(Some(outcome))
}

fn contact_commit_is_unconfirmed(error: &arkret_sdk::http_client::Error) -> bool {
    matches!(error, arkret_sdk::http_client::Error::Http(_))
        || matches!(error, arkret_sdk::http_client::Error::Api { status: 503, .. }
            if error.error_code() == Some(arkret_sdk::ErrorCode::TemporarilyUnavailable))
}

pub(crate) async fn finish_contact_commit(
    http: &arkret_sdk::http_client::Client,
    mut context: PrincipalSuccessorSealContext,
    pending: &pending::PendingOperation,
    commit: &impl serde::Serialize,
) -> anyhow::Result<ContactOperationOutcome> {
    let commit: ContactCommitRequestBody = serde_json::from_value(serde_json::to_value(commit)?)?;
    let journal = pending.stage(&mut context, &commit).await?;
    let outcome = run_contact_commit(http, context, &commit).await?;
    pending.fence.check()?;
    journal.clear().await?;
    Ok(outcome)
}

async fn run_contact_commit(
    http: &arkret_sdk::http_client::Client,
    context: PrincipalSuccessorSealContext,
    commit: &ContactCommitRequestBody,
) -> anyhow::Result<ContactOperationOutcome> {
    let endpoint = match commit.signed_event.kind.as_str() {
        arkret_wire::event_kind_str::CONTACT_REQUESTED => "/_arkret/self/contacts/request",
        arkret_wire::event_kind_str::CONTACT_ACCEPTED => "/_arkret/self/contacts/respond",
        arkret_wire::event_kind_str::CONTACT_REJECTED => "/_arkret/self/contacts/reject",
        arkret_wire::event_kind_str::CONTACT_SCOPE_UPDATE => "/_arkret/self/contacts/scope-update",
        arkret_wire::event_kind_str::CONTACT_TOMBSTONE => "/_arkret/self/contacts/tombstone",
        _ => anyhow::bail!("unregistered Contact commit Event"),
    };
    let fence = context.fence.clone();
    let journal = context.journal.clone();
    let result = drive_contact_commit(
        || fence.check(),
        || http.post(endpoint, commit),
        || async {
            confirm_principal_successor_seal(http, context, &commit.signed_event).await?;
            Ok(())
        },
        |outcome| {
            validate_contact_commit_outcome(
                outcome,
                &commit.signed_event,
                &commit.operation_id,
                &fence.signer,
            )
        },
    )
    .await;
    if let Err(error) = &result
        && let Some(transport) = error.downcast_ref::<arkret_sdk::http_client::Error>()
        && matches!(transport, arkret_sdk::http_client::Error::Api { .. })
        && !contact_commit_is_unconfirmed(transport)
        && matches!(
            principal_event_terminal_outcome(http, &commit.signed_event).await,
            Ok(Some(arkret_sdk::CommandOutcome::Rejected))
        )
    {
        fence.check()?;
        if let Some(journal) = &journal {
            journal.clear().await?;
        }
    }
    result
}

async fn drive_contact_commit<F, Fut, C, CFut>(
    check_session: impl Fn() -> anyhow::Result<()>,
    mut submit: F,
    confirm: C,
    validate: impl Fn(&ContactOperationOutcome) -> anyhow::Result<()>,
) -> anyhow::Result<ContactOperationOutcome>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = arkret_sdk::http_client::Result<ContactOperationOutcome>>,
    C: FnOnce() -> CFut,
    CFut: std::future::Future<Output = anyhow::Result<()>>,
{
    check_session()?;
    let mut initial = submit().await;
    check_session()?;
    if matches!(&initial, Err(arkret_sdk::http_client::Error::Http(_))) {
        // Admission itself may not have happened. Retry the identical commit
        // before asking the Station to confirm a possibly absent Event.
        initial = submit().await;
        check_session()?;
    }
    match initial {
        Ok(outcome) => {
            validate(&outcome)?;
            return Ok(outcome);
        }
        Err(error) if contact_commit_is_unconfirmed(&error) => {}
        Err(error) => return Err(error.into()),
    }
    confirm().await?;
    check_session()?;
    let outcome = submit().await?;
    check_session()?;
    validate(&outcome)?;
    Ok(outcome)
}

fn validate_contact_commit_outcome(
    outcome: &ContactOperationOutcome,
    event: &arkret_sdk::Event,
    operation_id: &ProtocolOperationId,
    signer: &crate::event_signer::InksonEventSigner,
) -> anyhow::Result<()> {
    use arkret_sdk::contact_operations::{
        ContactAcceptedOutcome as Accepted, ContactResultKind as Kind,
    };
    let expected = match event.kind.as_str() {
        arkret_wire::event_kind_str::CONTACT_REQUESTED => Kind::Request,
        arkret_wire::event_kind_str::CONTACT_ACCEPTED => Kind::Response,
        arkret_wire::event_kind_str::CONTACT_REJECTED => Kind::Reject,
        arkret_wire::event_kind_str::CONTACT_SCOPE_UPDATE => Kind::ScopeUpdate,
        arkret_wire::event_kind_str::CONTACT_TOMBSTONE => Kind::Tombstone,
        _ => anyhow::bail!("Contact commit uses an unregistered Event kind"),
    };
    let producer = matches!(outcome, ContactOperationOutcome::Accepted { .. })
        .then(|| local_contact_producer(event, signer))
        .transpose()?;
    let check_producer = |returned: &arkret_sdk::contact_operations::ContactProducerSigner,
                          holder: &ContactPeer| {
        returned.validate_for_event(event, holder)?;
        anyhow::ensure!(
            producer
                .as_ref()
                .is_some_and(|(method, key)| returned.verification_method() == method
                    && returned.public_key_b64u() == key),
            "Contact result changed the exact Event producer method or local signing key"
        );
        Ok::<(), anyhow::Error>(())
    };
    let (kind, returned_operation, event_ref) = match outcome {
        ContactOperationOutcome::Accepted { outcome } => match outcome {
            Accepted::Request {
                operation_id,
                request_acceptance_receipt,
            } => {
                check_producer(
                    &request_acceptance_receipt.core.producer_signer,
                    &request_acceptance_receipt.core.holder,
                )?;
                let peer: ContactPeer = serde_json::from_value(
                    event
                        .payload
                        .get("peer")
                        .cloned()
                        .ok_or_else(|| anyhow::anyhow!("Contact request omitted its peer"))?,
                )?;
                anyhow::ensure!(
                    request_acceptance_receipt.core.holder.contact_actor_id() == event.actor_id
                        && request_acceptance_receipt.core.peer == peer
                        && event
                            .actor_id
                            .as_account_id()
                            .is_some_and(|account| account.station_id
                                == request_acceptance_receipt.core.issuer_id),
                    "Contact request receipt changed its full holder, peer or source Station"
                );
                (
                    Kind::Request,
                    operation_id,
                    &request_acceptance_receipt.core.request_event_ref,
                )
            }
            Accepted::Response {
                operation_id,
                normal_response_acceptance_receipt,
                lineage,
                current_proof,
            } => {
                check_producer(
                    &normal_response_acceptance_receipt.producer_signer,
                    &normal_response_acceptance_receipt.request_receipt.core.peer,
                )?;
                check_producer(&lineage.producer_signer, &lineage.issuer)?;
                if normal_response_acceptance_receipt
                    .request_receipt
                    .core
                    .request_event_ref
                    == event.event_id
                {
                    check_producer(
                        &normal_response_acceptance_receipt
                            .request_receipt
                            .core
                            .producer_signer,
                        &normal_response_acceptance_receipt
                            .request_receipt
                            .core
                            .holder,
                    )?;
                }
                anyhow::ensure!(
                    lineage.event_ref == event.event_id,
                    "Contact response projection changed the exact Event"
                );
                validate_contact_current_result(event, lineage, current_proof)?;
                (
                    Kind::Response,
                    operation_id,
                    &normal_response_acceptance_receipt.response_event_ref,
                )
            }
            Accepted::Reject {
                operation_id,
                reject_acceptance_receipt,
            } => {
                check_producer(
                    &reject_acceptance_receipt.producer_signer,
                    &reject_acceptance_receipt.request_receipt.core.peer,
                )?;
                if reject_acceptance_receipt
                    .request_receipt
                    .core
                    .request_event_ref
                    == event.event_id
                {
                    check_producer(
                        &reject_acceptance_receipt
                            .request_receipt
                            .core
                            .producer_signer,
                        &reject_acceptance_receipt.request_receipt.core.holder,
                    )?;
                }
                (
                    Kind::Reject,
                    operation_id,
                    &reject_acceptance_receipt.reject_event_ref,
                )
            }
            Accepted::ScopeUpdate {
                operation_id,
                lineage,
                current_proof,
            } => {
                check_producer(&lineage.producer_signer, &lineage.issuer)?;
                validate_contact_current_result(event, lineage, current_proof)?;
                (Kind::ScopeUpdate, operation_id, &lineage.event_ref)
            }
            Accepted::Tombstone {
                operation_id,
                lineage,
                current_proof,
            } => {
                check_producer(&lineage.producer_signer, &lineage.issuer)?;
                validate_contact_current_result(event, lineage, current_proof)?;
                (Kind::Tombstone, operation_id, &lineage.event_ref)
            }
        },
        ContactOperationOutcome::Failed { outcome } => {
            anyhow::ensure!(
                outcome.operation_id == *operation_id && outcome.result_kind == expected,
                "Contact terminal rejection changed the operation or branch"
            );
            return Ok(());
        }
        ContactOperationOutcome::Prepared { .. } => {
            anyhow::bail!("Contact commit returned another preparation")
        }
    };
    anyhow::ensure!(
        kind == expected && returned_operation == operation_id && event_ref == &event.event_id,
        "Contact accepted result changed the operation, branch or exact Event"
    );
    Ok(())
}

/// Bind the server-trusted result to the original locally authored Event.
/// The frozen signer is a local input, never obtained from the response or an
/// online directory. The enclosing session fence also protects resumed intents.
fn local_contact_producer(
    event: &arkret_sdk::Event,
    signer: &crate::event_signer::InksonEventSigner,
) -> anyhow::Result<(arkret_sdk::DidUrl, arkret_sdk::Base64UrlString)> {
    let [proof] = event.proofs.as_slice() else {
        anyhow::bail!("Contact Event must retain its unique original producer proof");
    };
    let method = signer.verification_method_for_sdk_event(event)?;
    anyhow::ensure!(
        proof.verification_method == method,
        "Contact Event proof differs from the frozen local signer"
    );
    event.validate_proof_bindings_with_digest_suite(
        event.event_id.digest_suite_code().digest_suite(),
    )?;
    let key = arkret_sdk::Base64UrlString::new(
        signer
            .public_key_base64url()
            .ok_or_else(|| anyhow::anyhow!("Contact signer has no local Ed25519 public key"))?,
    )
    .map_err(anyhow::Error::msg)?;
    // The own-Station result supplies the source-authenticated public Agent
    // locator. The client checks its exact actor branch without performing a
    // second Station's historical verification or introducing an online gate.
    arkret_sdk::contact_operations::ContactProducerSigner::direct(method.clone(), key.clone())?;
    Ok((method, key))
}

fn validate_contact_current_result(
    event: &arkret_sdk::Event,
    lineage: &arkret_sdk::contact_operations::ContactLineage,
    current: &arkret_sdk::contact_operations::ContactCurrentProof,
) -> anyhow::Result<()> {
    let account = event
        .actor_id
        .as_account_id()
        .ok_or_else(|| anyhow::anyhow!("Contact actor is not an account"))?;
    let peer: ContactPeer = serde_json::from_value(
        event
            .payload
            .get("peer")
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("Contact Event omitted peer"))?,
    )?;
    anyhow::ensure!(
        lineage.issuer.contact_actor_id() == event.actor_id
            && lineage.peer == peer
            && current.peer == peer
            && current.issuer_id == account.station_id
            && current.contact_round_id == lineage.contact_round_id,
        "Contact current result changed its full actor, peer, issuer or round"
    );
    // The authenticated own Station validates the complete successor chain.
    // A later current head does not alter the exact receipt/lineage being returned.
    Ok(())
}

pub(crate) fn require_contact_success(outcome: ContactOperationOutcome) -> anyhow::Result<()> {
    match outcome {
        ContactOperationOutcome::Accepted { .. } => Ok(()),
        ContactOperationOutcome::Failed { outcome } => {
            anyhow::bail!("Contact operation failed: {:?}", outcome.reason)
        }
        ContactOperationOutcome::Prepared { .. } => {
            anyhow::bail!("Contact commit returned a preparation")
        }
    }
}

fn contact_scope(scope: &str) -> anyhow::Result<ContactScope> {
    match scope.trim() {
        "invite" => Ok(ContactScope::Invite),
        "direct_message" => Ok(ContactScope::DirectMessage),
        "voice_call" => Ok(ContactScope::VoiceCall),
        "video_call" => Ok(ContactScope::VideoCall),
        "presence" => Ok(ContactScope::Presence),
        other => anyhow::bail!("unsupported Contact scope `{other}`"),
    }
}

fn prepared_contact_request(
    outcome: ContactOperationOutcome,
) -> anyhow::Result<(ProtocolOperationId, ReservationHandle, PreparedEventDraft)> {
    match outcome {
        ContactOperationOutcome::Prepared {
            outcome:
                ContactPreparedOutcome::Request {
                    operation_id,
                    reservation_handle,
                    event_draft,
                    ..
                },
        } => Ok((operation_id, reservation_handle, event_draft)),
        ContactOperationOutcome::Failed { outcome } => {
            anyhow::bail!("Contact request prepare was rejected: {:?}", outcome.reason)
        }
        _ => anyhow::bail!("Contact request prepare returned an invalid result kind"),
    }
}

pub(crate) fn sign_prepared_contact_event(
    draft: &PreparedEventDraft,
    expected_kind: &str,
) -> anyhow::Result<arkret_sdk::AuthoredEvent> {
    let mut event = draft.unsigned_event_for_kind(expected_kind)?;
    let signer = crate::event_signer::active_signer()
        .ok_or_else(|| anyhow::anyhow!("active device signer is required for Contact commit"))?;
    let principal =
        arkret_sdk::project_did_to_core_id(&arkret_sdk::Did::new(signer.signer_did().to_owned())?)?;
    principal_successor_actor(&event.actor_id, &principal)?;
    if let Some(scope) = crate::secure_key_store::active_device_seed_scope() {
        anyhow::ensure!(
            event.actor_id == arkret_sdk::ActorId::account(scope.authority)
                && signer.device_id() == Some(scope.device_id.as_str()),
            "prepared Contact Event differs from the active account/device"
        );
    }
    let digest_suite = event.digest_suite();
    let plane = crate::event_signer::event_signer_evidence_plane(
        &event.kind,
        arkret_schema::classify_event_execution(event.event())?,
    )?;
    let proof_context =
        crate::event_signer::cached_active_event_proof_context(digest_suite, plane)?;
    signer.sign_sdk_event_with_context(&mut event, proof_context)?;
    let signed_digest =
        arkret_sdk::Hash::new(event.event_digest_with_digest_suite(event.digest_suite())?)?;
    if signed_digest != draft.event_digest {
        anyhow::bail!("signing changed the prepared Contact Event digest");
    }
    Ok(event)
}

impl crate::transport::TransportClient {
    pub async fn request_contact(&self, target: &str) -> anyhow::Result<ContactOperationOutcome> {
        self.request_contact_scoped(target, "direct_message").await
    }

    pub async fn request_contact_scoped(
        &self,
        target: &str,
        scope: &str,
    ) -> anyhow::Result<ContactOperationOutcome> {
        self.request_contact_with_message(target, &[scope.to_owned()], None)
            .await
    }

    /// Execute the future-only Contact prepare -> local signature -> commit
    /// ceremony. The UI's contact-request surface is explicitly human-only;
    /// Agent contacts require their controller binding and therefore need a
    /// separate typed UX instead of guessing from a DID string.
    pub async fn request_contact_with_message(
        &self,
        target: &str,
        scopes: &[String],
        message: Option<&str>,
    ) -> anyhow::Result<ContactOperationOutcome> {
        let session = ContactSessionFence::capture()?;
        let mut granted_to_peer_scopes = scopes
            .iter()
            .map(|scope| contact_scope(scope))
            .collect::<anyhow::Result<Vec<_>>>()?;
        granted_to_peer_scopes.sort();
        granted_to_peer_scopes.dedup();
        if granted_to_peer_scopes.is_empty() {
            anyhow::bail!("at least one Contact scope is required");
        }
        let http = self.sdk_http_client()?;
        let pending = pending::PendingOperation::begin(Some(serde_json::json!([
            "request",
            target.trim(),
            granted_to_peer_scopes,
            message.map(str::trim)
        ])))
        .await?;
        if let Some(outcome) = pending.resume(&http).await? {
            return Ok(outcome);
        }
        let addressing = self.contact_request_addressing(target).await?;
        let nonce = crate::operation::uuid_v7();
        let operation_id =
            ProtocolOperationId::new(format!("ak:operation:contact.request.{nonce}"))
                .map_err(anyhow::Error::msg)?;
        let idempotency_key = IdempotencyKey::new(nonce).map_err(anyhow::Error::msg)?;
        let prepare = ContactOperationRequestBody::Prepare(ContactPrepareRequestBody {
            phase: ContactPreparePhase::Prepare,
            operation_id: operation_id.clone(),
            idempotency_key: idempotency_key.clone(),
            peer: ContactPeer::Human {
                account_id: addressing.target,
            },
            granted_to_peer_scopes,
            introduction_evidence: addressing.introduction_evidence,
            continuity_evidence: None,
            message: message
                .map(str::trim)
                .filter(|message| !message.is_empty())
                .map(ToOwned::to_owned),
        });
        let (prepared_operation_id, reservation_handle, event_draft) =
            prepared_contact_request(http.contacts_request(&prepare).await?)?;
        session.check()?;
        if prepared_operation_id != operation_id {
            anyhow::bail!("Contact prepare changed operation_id");
        }
        let signed_event = sign_prepared_contact_event(
            &event_draft,
            arkret_wire::event_kind_str::CONTACT_REQUESTED,
        )?;
        let seal_context = prepare_principal_successor_seal(&http, &signed_event).await?;
        session.check()?;
        let commit = ContactOperationRequestBody::Commit(ContactCommitRequestBody {
            phase: ContactCommitPhase::Commit,
            operation_id: operation_id.clone(),
            idempotency_key,
            reservation_handle,
            signed_event: signed_event.event().clone(),
            control_proposal_ack: None,
        });
        finish_contact_commit(&http, seal_context, &pending, &commit).await
    }
}
