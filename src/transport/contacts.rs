use arkret_sdk::contact_operations::{
    ContactCommitPhase, ContactCommitRequestBody, ContactOperationOutcome,
    ContactOperationRequestBody, ContactPeer, ContactPreparePhase, ContactPrepareRequestBody,
    ContactPreparedOutcome, ContactScope,
};
use arkret_sdk::{IdempotencyKey, PreparedEventDraft, ProtocolOperationId, ReservationHandle};

use super::auth::AuthoringSessionFence;

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

pub(crate) fn new_contact_operation_binding()
-> anyhow::Result<(ProtocolOperationId, IdempotencyKey)> {
    let operation = arkret_sdk::OperationId::new_v7_at(crate::clock::now_unix_ms());
    let nonce = operation
        .as_str()
        .strip_prefix("ak:operation:")
        .ok_or_else(|| anyhow::anyhow!("SDK OperationId has an unregistered prefix"))?
        .to_owned();
    Ok((
        ProtocolOperationId::new(operation.into_string()).map_err(anyhow::Error::msg)?,
        IdempotencyKey::new(nonce).map_err(anyhow::Error::msg)?,
    ))
}

pub(crate) fn default_contact_scopes() -> Vec<ContactScope> {
    vec![
        ContactScope::Invite,
        ContactScope::DirectMessage,
        ContactScope::VoiceCall,
        ContactScope::VideoCall,
        ContactScope::Presence,
    ]
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

pub(crate) struct ContactCommitContext {
    actor_id: arkret_sdk::ActorId,
    control_realm: arkret_sdk::RealmId,
    fence: AuthoringSessionFence,
    journal: Option<pending::Journal>,
}

pub(crate) fn freeze_contact_commit_context(
    principal_event: &arkret_sdk::Event,
) -> anyhow::Result<ContactCommitContext> {
    let fence = AuthoringSessionFence::capture()?;
    let signer = &fence.signer;
    let principal = arkret_sdk::Did::new(signer.signer_did().to_owned())?;
    let principal_id = arkret_sdk::project_did_to_core_id(&principal)?;
    let actor_id = contact_commit_actor(&principal_event.actor_id, &principal_id)?;
    let control_realm = principal_event.realm_id.clone();
    Ok(ContactCommitContext {
        actor_id,
        control_realm,
        fence,
        journal: None,
    })
}

fn contact_commit_actor(
    actor_id: &arkret_sdk::ActorId,
    signer_principal: &arkret_sdk::DidCoreId,
) -> anyhow::Result<arkret_sdk::ActorId> {
    let account = actor_id
        .as_account_id()
        .ok_or_else(|| anyhow::anyhow!("Contact commit requires an account Event actor"))?;
    if &account.principal_id != signer_principal {
        anyhow::bail!("prepared principal Event actor does not match the active signer");
    }
    // First enrollment runs before app connect. The signed Event already
    // supplies the exact AccountId; no ambient Station may replace it.
    Ok(actor_id.clone())
}

#[cfg(test)]
mod contact_commit_actor_tests {
    #[test]
    fn successor_preserves_the_signed_account_before_app_connect() {
        let principal = arkret_sdk::DidCoreId::new("ak:did_core:web:alice.example").unwrap();
        let station = arkret_sdk::DidCoreId::new("ak:did_core:web:enrollment.example").unwrap();
        let actor =
            arkret_sdk::ActorId::account(arkret_sdk::AccountId::new(principal.clone(), station));
        assert_eq!(
            super::contact_commit_actor(&actor, &principal).unwrap(),
            actor
        );
        let other = arkret_sdk::DidCoreId::new("ak:did_core:web:bob.example").unwrap();
        assert!(super::contact_commit_actor(&actor, &other).is_err());
    }
}

fn contact_commit_is_unconfirmed(error: &arkret_sdk::http_client::Error) -> bool {
    matches!(error, arkret_sdk::http_client::Error::Http(_))
        || matches!(error, arkret_sdk::http_client::Error::Api { status: 503, .. }
            if error.error_code() == Some(arkret_sdk::ErrorCode::TemporarilyUnavailable))
}

pub(crate) async fn finish_contact_commit(
    http: &arkret_sdk::http_client::Client,
    mut context: ContactCommitContext,
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
    context: ContactCommitContext,
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
    anyhow::ensure!(
        commit.signed_event.actor_id == context.actor_id
            && commit.signed_event.realm_id == context.control_realm,
        "Contact Event differs from the frozen account/Realm"
    );
    let result = drive_contact_commit(
        || fence.check(),
        || http.post(endpoint, commit),
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
    {
        fence.check()?;
        if let Some(journal) = &context.journal {
            journal.clear().await?;
        }
    }
    result
}

async fn drive_contact_commit<F, Fut>(
    check_session: impl Fn() -> anyhow::Result<()>,
    mut submit: F,
    validate: impl Fn(&ContactOperationOutcome) -> anyhow::Result<()>,
) -> anyhow::Result<ContactOperationOutcome>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = arkret_sdk::http_client::Result<ContactOperationOutcome>>,
{
    check_session()?;
    let mut initial = submit().await;
    check_session()?;
    if matches!(&initial, Err(error) if contact_commit_is_unconfirmed(error)) {
        // The governance Station owns RealmCommit admission. Re-submit only
        // the byte-identical Contact commit; there is no client-side Seal or
        // ControlProposal confirmation plane.
        initial = submit().await;
        check_session()?;
    }
    match initial {
        Ok(outcome) => {
            validate(&outcome)?;
            Ok(outcome)
        }
        Err(error) => Err(error.into()),
    }
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
    let Some(proof) = event.producer_proof.as_ref() else {
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
    successful_contact_request(outcome).map(|_| ())
}

fn successful_contact_request(
    outcome: ContactOperationOutcome,
) -> anyhow::Result<ContactOperationOutcome> {
    match outcome {
        accepted @ ContactOperationOutcome::Accepted { .. } => Ok(accepted),
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
    contact_commit_actor(&event.actor_id, &principal)?;
    if let Some(scope) = crate::secure_key_store::active_device_seed_scope() {
        anyhow::ensure!(
            event.actor_id == arkret_sdk::ActorId::account(scope.authority)
                && signer.device_id() == Some(scope.device_id.as_str()),
            "prepared Contact Event differs from the active account/device"
        );
    }
    let digest_suite = event.digest_suite();
    let proof_context = crate::event_signer::cached_active_event_proof_context(digest_suite)?;
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
        let session = AuthoringSessionFence::capture()?;
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
            return successful_contact_request(outcome);
        }
        let addressing = self.contact_request_addressing(target).await?;
        let (operation_id, idempotency_key) = new_contact_operation_binding()?;
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
        let commit_context = freeze_contact_commit_context(&signed_event)?;
        session.check()?;
        let commit = ContactOperationRequestBody::Commit(ContactCommitRequestBody {
            phase: ContactCommitPhase::Commit,
            operation_id: operation_id.clone(),
            idempotency_key,
            reservation_handle,
            signed_event: signed_event.event().clone(),
        });
        successful_contact_request(
            finish_contact_commit(&http, commit_context, &pending, &commit).await?,
        )
    }
}
