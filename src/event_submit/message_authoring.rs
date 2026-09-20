//! The production ordinary-message send path.
//!
//! An ordinary chat message is authored entirely on this device: the body is
//! encrypted (or, where the target still permits it, left plaintext) before
//! anything leaves, the Event is finalized and signed here, and the current
//! governance Station answers with the authority-signed commit that gives the
//! message its place in the scope's stream. There is no preparation round
//! trip: a producer Event has no chain position or basis a Station could have
//! to supply.
//!
//! Everything after authoring is the durable submit queue. Because authoring
//! is one-shot, a retry is always a replay of the exact same frozen bytes —
//! the Station's idempotency record answers instead of a second message
//! appearing.

use garth::message_authoring::{
    MessageAuthoringFailure, MessageAuthoringIntent, MessageAuthoringRecovery,
    MessageSubmitRequestBody,
};

use super::*;

/// One frozen ordinary message, ready to author.
///
/// The content is already final — plaintext the target still permits, or the
/// envelope this device's MLS engine produced — so nothing below this point
/// can change it, and no retry it makes can consume another MLS sender
/// counter.
pub(crate) struct MessageAuthoringPlan {
    realm_id: arkret_sdk::RealmId,
    scope: arkret_sdk::ScopeRef,
    actor_id: arkret_sdk::ActorId,
    intent: MessageAuthoringIntent,
    created_at: chrono::DateTime<chrono::Utc>,
}

/// One attempt at one user-authored message.
///
/// `local_operation_id` is the holder-local identity the optimistic row and
/// the durable queue slot share.
pub(crate) struct MessageSendAttempt {
    pub(crate) session: MessageAuthoringPlan,
    pub(crate) local_operation_id: String,
}

fn failure(detail: impl std::fmt::Display) -> MessageAuthoringFailure {
    MessageAuthoringFailure::Refused {
        code: "failed_precondition".to_owned(),
        detail: detail.to_string(),
    }
}

/// Translate a submit error into a send recovery class.
///
/// An error that never carried a Station answer is reported as an unknown
/// outcome rather than a refusal: the request may have been committed before
/// the response was lost, so the only safe recovery is replaying the stored
/// bytes.
pub(crate) fn classify_submit_failure(error: &anyhow::Error) -> MessageAuthoringFailure {
    if let Some((status, problem)) = crate::api_error::api_error_status_and_envelope(error) {
        return garth::classify_message_authoring_error(&garth::Error::Api {
            status: status.as_u16(),
            error: Box::new(problem.clone()),
        });
    }
    MessageAuthoringFailure::SubmissionOutcomeUnknown {
        detail: format!("{error:#}"),
    }
}

impl EventSubmitter {
    /// Freeze one ordinary message against the target this client verified.
    ///
    /// The Station is not consulted here. A producer Event carries no
    /// authority reference for the sender's membership: the current governance
    /// Station evaluates that against the committed Realm projection when it
    /// decides whether to commit.
    pub(crate) fn message_authoring_session(
        &self,
        realm_id: &str,
        scope: arkret_sdk::ScopeRef,
        intent: MessageAuthoringIntent,
        created_at: chrono::DateTime<chrono::Utc>,
    ) -> std::result::Result<MessageAuthoringPlan, MessageAuthoringFailure> {
        let account = self.authority().map_err(failure)?.clone();
        let realm_id = arkret_sdk::RealmId::new(realm_id.to_owned()).map_err(failure)?;
        if scope.realm_id_opt() != Some(&realm_id) {
            return Err(failure("the message scope belongs to another Realm"));
        }
        Ok(MessageAuthoringPlan {
            realm_id,
            scope,
            actor_id: arkret_sdk::ActorId::account(account),
            intent,
            created_at,
        })
    }

    /// Author, sign and durably submit one ordinary message.
    pub(crate) async fn send_authored_message(
        &self,
        attempt: &MessageSendAttempt,
    ) -> std::result::Result<SubmitEventResult, MessageAuthoringFailure> {
        let plan = &attempt.session;
        let operation = crate::operation::TypedOperationBuilder::new::<
            arkret_sdk::event_spec::MessageCreate,
        >(
            plan.realm_id.as_str(),
            plan.actor_id.signing_principal_id().as_str(),
            plan.intent.payload(),
        )
        .target_ref(plan.intent.strand_id.as_str())
        .build_sdk_event("inkson")
        .map_err(failure)?
        .with_local_operation_id(crate::operation::LocalOperationId::from_holder_key(
            attempt.local_operation_id.clone(),
        ));
        let operation = operation
            .with_effective_scope(plan.scope.clone())
            .map_err(failure)?;
        let event_intent = operation.intent().clone().with_created_at(plan.created_at);
        let event = self
            .author_intent(&event_intent)
            .await
            .map_err(|error| classify_submit_failure(&error))?;
        let request = MessageSubmitRequestBody {
            submission: arkret_wire::EventCommitSubmission {
                event: event.event().clone(),
                approval_signatures: None,
            },
        };
        let submission =
            garth::queue_authored_message(request).map_err(|error| failure(format!("{error}")))?;
        let item = self
            .enqueue_and_drive(QueuedWrite {
                lane: OutboundLane::Standard,
                submission,
                local_operation_id: attempt.local_operation_id.clone(),
                post_accept: PostAccept::None,
                retry_scope: InteractiveRetryScope::Ordinary,
            })
            .await
            .map_err(|error| {
                if is_durably_queued_error(&error) {
                    MessageAuthoringFailure::SubmissionOutcomeUnknown {
                        detail: format!("{error:#}"),
                    }
                } else {
                    classify_submit_failure(&error)
                }
            })?;
        match item.rejection_reason_code() {
            Some(reason_code) => Err(garth::classify_authority_rejection(reason_code)),
            None => Ok(SubmitEventResult::from(&item)),
        }
    }
}

/// Whether this send may try again on its own.
///
/// Only a definite retryable class recovers here, and it recovers by replaying
/// the identical frozen submission — authoring is one-shot, so there is
/// nothing else it could send. A changed encryption binding has to go back to
/// the MLS engine, which lives above this layer.
pub(crate) fn message_attempt_may_retry(failure: &MessageAuthoringFailure) -> bool {
    match failure.recovery() {
        MessageAuthoringRecovery::RetrySameRequest
        | MessageAuthoringRecovery::ReplayExactSubmission => true,
        MessageAuthoringRecovery::ReEncrypt | MessageAuthoringRecovery::FailClosed => false,
    }
}

/// Drive one user-authored message to a committed result.
///
/// Every loop turn replays the same frozen submission. Nothing in this loop
/// can reach back into the encryption step, so no retry it makes can consume
/// another MLS sender counter — a body that has to change is reported to the
/// caller, whose MLS engine decides to encrypt again.
pub(crate) async fn drive_message_send(
    submitter: &EventSubmitter,
    attempt: MessageSendAttempt,
) -> std::result::Result<SubmitEventResult, MessageAuthoringFailure> {
    // One retry, because a second identical answer is a real state the user
    // has to see rather than a loop the client hides.
    const MAX_RETRIES: usize = 1;
    let mut last = None;
    for _ in 0..=MAX_RETRIES {
        match submitter.send_authored_message(&attempt).await {
            Ok(result) => return Ok(result),
            Err(error) => {
                let retry = message_attempt_may_retry(&error);
                last = Some(error);
                if !retry {
                    break;
                }
            }
        }
    }
    Err(last.unwrap_or_else(|| failure("the message send produced no result")))
}
