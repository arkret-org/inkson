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

/// A local pre-submit failure has no frozen request whose acceptance is
/// unknown. Preserve typed Station API refusals; fail closed on local errors.
fn classify_presubmit_failure(error: &anyhow::Error) -> MessageAuthoringFailure {
    #[cfg(all(target_arch = "wasm32", feature = "wasm-localstorage-secrets-test"))]
    tracing::warn!(error = %error, "ordinary message pre-submit gate failed");
    if crate::api_error::api_error_status_and_envelope(error).is_some() {
        classify_submit_failure(error)
    } else {
        failure(format!("{error:#}"))
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
    async fn freeze_authored_message(
        &self,
        attempt: &MessageSendAttempt,
    ) -> std::result::Result<QueuedSubmission, MessageAuthoringFailure> {
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
        self.ensure_recovery_material_ready(&event_intent)
            .await
            .map_err(|error| classify_presubmit_failure(&error))?;
        self.ensure_application_send_gate(&event_intent)
            .await
            .map_err(|error| classify_presubmit_failure(&error))?;
        self.refresh_direct_message_authority(&event_intent, None)
            .await
            .map_err(|error| classify_presubmit_failure(&error))?;
        #[cfg(all(target_arch = "wasm32", feature = "wasm-localstorage-secrets-test"))]
        tracing::warn!(stage = "authoring", "ordinary message pre-submit stage");
        let event = self
            .author_intent(&event_intent)
            .await
            .map_err(|error| classify_presubmit_failure(&error))?;
        event_submission(&event).map_err(|error| failure(format!("{error}")))
    }

    async fn send_frozen_message(
        &self,
        submission: QueuedSubmission,
        local_operation_id: &str,
    ) -> std::result::Result<SubmitEventResult, MessageAuthoringFailure> {
        let item = self
            .enqueue_and_drive(QueuedWrite {
                lane: OutboundLane::Standard,
                submission,
                local_operation_id: local_operation_id.to_owned(),
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
        MessageAuthoringRecovery::PrepareAgain
        | MessageAuthoringRecovery::RefreshGroupAndReEncrypt
        | MessageAuthoringRecovery::WaitForEpochCommit
        | MessageAuthoringRecovery::FailClosed => false,
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
    #[cfg(all(target_arch = "wasm32", feature = "wasm-localstorage-secrets-test"))]
    tracing::warn!(
        stage = "awaiting_writer",
        "ordinary message pre-submit stage"
    );
    let _single_writer = outbound_submit_lock().lock().await;
    #[cfg(all(target_arch = "wasm32", feature = "wasm-localstorage-secrets-test"))]
    tracing::warn!(stage = "freezing", "ordinary message pre-submit stage");
    let submission = submitter.freeze_authored_message(&attempt).await?;
    #[cfg(all(target_arch = "wasm32", feature = "wasm-localstorage-secrets-test"))]
    tracing::warn!(stage = "frozen", "ordinary message pre-submit stage");
    retry_frozen_message(submission, |submission| {
        submitter.send_frozen_message(submission, &attempt.local_operation_id)
    })
    .await
}

pub(crate) async fn retry_frozen_message<F, Fut>(
    submission: QueuedSubmission,
    mut send: F,
) -> std::result::Result<SubmitEventResult, MessageAuthoringFailure>
where
    F: FnMut(QueuedSubmission) -> Fut,
    Fut: std::future::Future<
            Output = std::result::Result<SubmitEventResult, MessageAuthoringFailure>,
        >,
{
    const MAX_RETRIES: usize = 1;
    let mut last = None;
    for _ in 0..=MAX_RETRIES {
        match send(submission.clone()).await {
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

#[cfg(test)]
mod tests {
    use super::*;

    fn problem_failure(problem: arkret_sdk::Problem) -> MessageAuthoringFailure {
        classify_submit_failure(&anyhow::Error::new(arkret_sdk::http_client::Error::Api {
            status: problem.status,
            error: Box::new(problem),
        }))
    }

    #[test]
    fn failures_before_queueing_never_claim_an_unknown_submit_outcome() {
        let local = classify_presubmit_failure(&anyhow::anyhow!("missing active signer"));
        assert!(matches!(local, MessageAuthoringFailure::Refused { .. }));
        assert_eq!(local.recovery(), MessageAuthoringRecovery::FailClosed);
        let transport = classify_submit_failure(&anyhow::anyhow!("connection reset after submit"));
        assert!(matches!(
            transport,
            MessageAuthoringFailure::SubmissionOutcomeUnknown { .. }
        ));
        assert_eq!(
            transport.recovery(),
            MessageAuthoringRecovery::ReplayExactSubmission
        );
    }

    #[tokio::test]
    async fn unknown_submit_result_replays_the_once_signed_frozen_bytes() {
        let intent: EventIntent = serde_json::from_value(serde_json::json!({
            "kind": "ak.message.create",
            "scope_ref": {"kind":"realm","realm_id":"ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19"},
            "actor_id": arkret_sdk::ActorId::account(crate::test_support::authority_at_station(
                "ak:did_core:web:alice.example", crate::test_support::SERVER_STATION_ID)),
            "created_at":"2026-05-19T00:00:00.000Z",
            "payload":{"strand_id":"ak:strand:AT3p9polsnQ_WOix32QZimMdE2zPe62HptJu2PaO3V1h",
                "track_name":"discussion","content":{"kind":"ak.content.text","body":"hello"}}
        })).unwrap();
        let mut event = intent
            .author_with_digest_suite(arkret_sdk::DigestSuite::Sha256)
            .unwrap();
        let signer = crate::event_signer::build_ed25519_device_signer(
            [73; 32],
            "did:web:alice.example",
            "ak:device:01904100-0000-7000-8000-000000000001",
        );
        let mut signs = 0;
        sign_event_through_message_seam(&mut event, |unsigned| {
            signs += 1;
            signer
                .sign_sdk_event_with_context(
                    unsigned,
                    crate::event_signer::ProducerProofContext::new(),
                )
                .map_err(anyhow::Error::from)
        })
        .unwrap();
        let frozen = event_submission(&event).unwrap();
        let bytes = arkret_sdk::canonical::canonical_json_bytes(&frozen.request).unwrap();
        let mut calls = 0;
        let result = retry_frozen_message(frozen, |submission| {
            calls += 1;
            assert_eq!(
                arkret_sdk::canonical::canonical_json_bytes(&submission.request).unwrap(),
                bytes
            );
            let answer = if calls == 1 {
                Err(MessageAuthoringFailure::SubmissionOutcomeUnknown {
                    detail: "response lost".to_owned(),
                })
            } else {
                Ok(SubmitEventResult::queued(submission.event_id.to_string()))
            };
            std::future::ready(answer)
        })
        .await
        .unwrap();
        assert_eq!(signs, 1);
        assert_eq!(calls, 2);
        assert_eq!(result.status, garth::SendQueueStatus::Queued);
        assert!(result.commit.is_none());
    }

    #[test]
    fn mls_send_gate_refusals_never_replay_the_frozen_submission() {
        use arkret_sdk::error_codes::{ErrorCode, ReasonCode};
        let mismatch = problem_failure(arkret_sdk::Problem::from_code(
            ErrorCode::EPOCH_MISMATCH,
            "stale",
        ));
        assert_eq!(
            mismatch.recovery(),
            MessageAuthoringRecovery::RefreshGroupAndReEncrypt
        );
        assert!(!message_attempt_may_retry(&mismatch));

        let pending = problem_failure(
            arkret_sdk::Problem::from_code(ErrorCode::FAILED_PRECONDITION, "uncovered")
                .with_extension(
                    "reason_code",
                    serde_json::Value::String(ReasonCode::EPOCH_UPDATE_REQUIRED.to_owned()),
                ),
        );
        assert_eq!(
            pending.recovery(),
            MessageAuthoringRecovery::WaitForEpochCommit
        );
        assert!(!message_attempt_may_retry(&pending));

        let rejected = garth::classify_authority_rejection(ReasonCode::EPOCH_UPDATE_REQUIRED);
        assert_eq!(
            rejected.recovery(),
            MessageAuthoringRecovery::WaitForEpochCommit
        );
        assert!(!message_attempt_may_retry(&rejected));
    }

    #[test]
    fn inactive_mls_scope_never_retries_but_current_read_fault_replays_exactly() {
        use arkret_sdk::error_codes::ErrorCode;

        let inactive = problem_failure(arkret_sdk::Problem::from_code(
            ErrorCode::FAILED_PRECONDITION,
            "scope has no accepted MLS group",
        ));
        assert_eq!(inactive.recovery(), MessageAuthoringRecovery::FailClosed);
        assert!(!message_attempt_may_retry(&inactive));

        let unavailable = problem_failure(arkret_sdk::Problem::from_code(
            ErrorCode::TEMPORARILY_UNAVAILABLE,
            "current MLS group is temporarily unavailable",
        ));
        assert_eq!(
            unavailable.recovery(),
            MessageAuthoringRecovery::RetrySameRequest
        );
        assert!(message_attempt_may_retry(&unavailable));
    }
}
