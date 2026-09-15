//! The production ordinary-message send path.
//!
//! An ordinary chat message is the one write this client never assembles for
//! itself. The body is encrypted (or, where the target still permits it, left
//! plaintext) before anything leaves the device; the account's own Station then
//! completes the unsigned `ak.message.create`; the shared engine checks that
//! answer against the target, authority and Direct Conversation binding this
//! client already verified; and only then does the device signer add its proof.
//!
//! Everything after that is the existing durable submit queue. A prepared
//! message is enqueued as its own kind of slot ([`garth::QueuedSdkEvent::
//! station_prepared_message`]) so a conflict can never be answered by silently
//! re-authoring locally: the signed bytes are the operation, and a new attempt
//! is a new preparation over the identical body.

use garth::message_authoring::{
    MessageAuthoringFailure, MessageAuthoringIntent, MessageAuthoringRecovery,
    MessageAuthoringSession, MessageAuthoringTarget, MessagePrepareOutcome,
};

use super::*;

/// One attempt at one user-authored message.
///
/// `local_operation_id` is the holder-local identity the optimistic row and the
/// durable queue slot share, and it survives every recovery: a new preparation
/// is still the same operation to the user.
pub(crate) struct MessageSendAttempt {
    pub(crate) session: MessageAuthoringSession,
    pub(crate) local_operation_id: String,
}

/// A fresh preparation identity, ordered by the instant it was minted.
fn fresh_request_id() -> arkret_sdk::RequestId {
    arkret_sdk::RequestId::new_v7_at(crate::clock::now_utc_millis().timestamp_millis().max(0) as u64)
}

fn failure(detail: impl std::fmt::Display) -> MessageAuthoringFailure {
    MessageAuthoringFailure::Refused {
        code: "failed_precondition".to_owned(),
        detail: detail.to_string(),
    }
}

/// Translate a submit error into a send recovery class.
///
/// An error that never carried a server answer is reported as an unknown
/// outcome rather than a refusal: the request may have been accepted before the
/// response was lost, so the only safe recovery is replaying the stored bytes.
pub(crate) fn classify_submit_failure(error: &anyhow::Error) -> MessageAuthoringFailure {
    if crate::api_error::actor_seq_cas_conflict_details(error).is_some() {
        return MessageAuthoringFailure::ActorChainConflict {
            detail: format!("{error:#}"),
        };
    }
    if let Some((status, problem)) = crate::api_error::api_error_status_and_envelope(error) {
        return garth::classify_message_authoring_error(&garth::Error::Api {
            status: status.as_u16(),
            error: Box::new(problem.clone()),
        });
    }
    // No server answer reached this client, so acceptance is genuinely unknown
    // and the exact signed bytes are the only thing that may be sent again.
    MessageAuthoringFailure::SubmissionOutcomeUnknown {
        detail: format!("{error:#}"),
    }
}

impl EventSubmitter {
    /// Freeze one ordinary message against the target this client verified.
    ///
    /// The authority context is the accepted Seal this account's own projection
    /// already confirmed for the Realm, not something the Station gets to
    /// choose: `verify_for_signing` compares its answer with this value and
    /// refuses to expose the Event when they differ.
    pub(crate) fn message_authoring_session(
        &self,
        realm_id: &str,
        scope: arkret_sdk::ScopeRef,
        intent: MessageAuthoringIntent,
        created_at: chrono::DateTime<chrono::Utc>,
    ) -> std::result::Result<MessageAuthoringSession, MessageAuthoringFailure> {
        let account = self.authority().map_err(failure)?.clone();
        let store = self.state_store.as_ref().ok_or_else(|| {
            MessageAuthoringFailure::DependencyUnavailable {
                detail: "message authoring has no verified local authority store".to_owned(),
            }
        })?;
        // A new member is already accepted here long before its authorization is
        // covered by an accepted Seal. That window is the registered not-ready
        // answer, not a refusal, and it has to read that way before the request
        // is even built.
        let authority_ref = store
            .read(|state| state.confirmed_seal_ref_for_realm(realm_id))
            .ok_or_else(|| MessageAuthoringFailure::AuthorizationNotSealed {
                detail: "no accepted Realm authority decision is projected yet".to_owned(),
            })?;
        let digest_suite = store
            .read(|state| state.station_realm_digest_suite(realm_id))
            .ok_or_else(|| MessageAuthoringFailure::DependencyUnavailable {
                detail: "the verified Realm governance checkpoint is unavailable".to_owned(),
            })?;
        let authorization_context = arkret_sdk::AuthContext {
            authority_refs: vec![arkret_sdk::SealId::new(authority_ref).map_err(failure)?],
        };
        // A Direct Conversation message carries exactly one critical binding
        // ref. The value comes from this client's own settled binding, so a
        // Station that answers with another participant's binding is caught
        // before the Event reaches the signer.
        let actor = arkret_sdk::ActorId::account(account.clone());
        let direct_binding = store.read(|state| {
            if state.realm_collaboration_role(realm_id)
                != Some(arkret_sdk::CollaborationRealmRole::DirectConversation)
            {
                return None;
            }
            state
                .direct_message_context(realm_id, &actor)
                .map(|context| context.binding_event_ref)
        });
        MessageAuthoringSession::new(
            fresh_request_id(),
            account,
            arkret_sdk::RealmId::new(realm_id.to_owned()).map_err(failure)?,
            intent,
            created_at,
            None,
            MessageAuthoringTarget {
                scope,
                authorization_context,
                direct_binding,
                // The complete accepted actor frontier is a Station read this
                // path deliberately does not make: the send promise is prepare
                // plus submit. Adding a third request to re-derive what the
                // preparation already binds would buy nothing the exact-intent,
                // scope, authority and EventId checks do not already cover.
                known_frontier: None,
            },
            digest_suite,
        )
        .map_err(failure)
    }

    /// Prepare, verify and sign one ordinary message, then hand the exact bytes
    /// to the durable submit queue.
    ///
    /// The signer only ever adds a proof. Any Station answer that does not
    /// reproduce the closed intent verbatim is refused before the Event reaches
    /// a signer, a queue or a durable record.
    pub(crate) async fn send_authored_message(
        &self,
        attempt: &MessageSendAttempt,
    ) -> std::result::Result<SubmitEventResult, MessageAuthoringFailure> {
        let outcome = attempt.session.prepare(&self.http).await?;
        self.submit_prepared_message(attempt, &outcome).await
    }

    async fn submit_prepared_message(
        &self,
        attempt: &MessageSendAttempt,
        outcome: &MessagePrepareOutcome,
    ) -> std::result::Result<SubmitEventResult, MessageAuthoringFailure> {
        let session = &attempt.session;
        let intent_for_context = {
            let event = outcome
                .draft
                .unsigned_event_for_kind(arkret_sdk::EventKind::MessageCreate.as_str())
                .map_err(failure)?;
            EventIntent::from_authored(event.event())
        };
        let plane = signer_evidence_plane_for_intent(&intent_for_context).map_err(failure)?;
        let suite = outcome.draft.event_digest.digest_suite().map_err(failure)?;
        let proof_context = self
            .event_proof_context(suite, plane)
            .await
            .map_err(failure)?;
        let signer = crate::event_signer::active_signer().ok_or_else(|| {
            failure("the message signing device is unavailable on this device generation")
        })?;
        let submission = session.sign(outcome, crate::clock::now_utc(), move |event| {
            signer
                .sign_sdk_event_with_context(event, proof_context)
                .map_err(|error| garth::Error::Crypto(error.to_string()))
        })?;
        let generation = crate::identity::authoring_generation::resolve_event_authoring_generation(
            &self.http,
            &EventAuthorityFacts::from_intent(&intent_for_context),
        )
        .await
        .map_err(|error| classify_submit_failure(&error))?;
        let queued = QueuedSdkEvent::station_prepared_message(
            garth::StationPreparedMessageRecord {
                request_id: submission.request_id.clone(),
                request_digest: submission.request_digest.clone(),
                expires_at: submission.expires_at,
            },
            submission.event.clone(),
            attempt.local_operation_id.clone(),
            submission.canonical_body_bytes.clone(),
            generation,
        )
        .map_err(failure)?;
        self.enqueue_and_drive_sdk_event(queued, None, true)
            .await
            .map_err(|error| {
                if is_durably_queued_error(&error) {
                    MessageAuthoringFailure::SubmissionOutcomeUnknown {
                        detail: format!("{error:#}"),
                    }
                } else {
                    classify_submit_failure(&error)
                }
            })
    }
}

/// The next attempt this send may make on its own, or `None` when it has to
/// stop and tell the user what happened.
///
/// Only a definite non-acceptance recovers here, and it recovers by preparing
/// again over the identical body. The other classes deliberately stop: a
/// not-ready authorization or an unavailable dependency answers the same way
/// until state this client does not control has converged, so repeating the
/// request immediately only hides the wait; a changed encryption binding has to
/// go back to the MLS engine, which lives above this layer; and an unknown
/// submission result may already be accepted, where the only safe move is
/// replaying the stored bytes rather than authoring anything new.
pub(crate) fn next_message_attempt(
    attempt: &MessageSendAttempt,
    failure: &MessageAuthoringFailure,
) -> anyhow::Result<Option<MessageSendAttempt>> {
    match failure.recovery() {
        MessageAuthoringRecovery::RePrepareSameBody => {
            let session =
                attempt
                    .session
                    .re_prepare(fresh_request_id(), crate::clock::now_utc(), None)?;
            Ok(Some(MessageSendAttempt {
                session,
                local_operation_id: attempt.local_operation_id.clone(),
            }))
        }
        MessageAuthoringRecovery::RetrySameRequest
        | MessageAuthoringRecovery::ReEncrypt
        | MessageAuthoringRecovery::ReplayExactSubmission
        | MessageAuthoringRecovery::FailClosed => Ok(None),
    }
}

/// Drive one user-authored message to an accepted result.
///
/// Every loop turn is a complete attempt: prepare, verify, sign, submit.
/// Nothing in this loop can reach back into the encryption step, so no retry it
/// makes can consume another MLS sender counter — a body that has to change is
/// reported to the caller, whose MLS engine decides to encrypt again.
pub(crate) async fn drive_message_send(
    submitter: &EventSubmitter,
    mut attempt: MessageSendAttempt,
) -> std::result::Result<SubmitEventResult, MessageAuthoringFailure> {
    // One recovery, because there is exactly one thing to recover from without
    // the user: a preparation that expired or lost its chain position between
    // authoring and submitting. A second identical answer is a real state the
    // user has to see, not a loop the client hides.
    const MAX_RECOVERIES: usize = 1;
    let mut last = None;
    for _ in 0..=MAX_RECOVERIES {
        match submitter.send_authored_message(&attempt).await {
            Ok(result) => return Ok(result),
            Err(error) => {
                let next = next_message_attempt(&attempt, &error)
                    .map_err(|error| failure(format!("{error:#}")))?;
                last = Some(error);
                match next {
                    Some(next) => attempt = next,
                    None => break,
                }
            }
        }
    }
    Err(last.unwrap_or_else(|| failure("the message send produced no result")))
}
