//! `EventSubmitter` — the TransportClient-free durable/ephemeral event submission
//! engine. Holds the authenticated SDK http-client plus a lazily-populated,
//! per-instance service-describe cache. The cache lifetime matches the former
//! per-`TransportClient` `OnceCell`: the signing path (`event_proof_context`) fetches
//! `describe` at most once per submitter, and non-signing paths
//! (`submit_signed_*`, ephemeral, frontier, backfill) never fetch it.

use std::collections::BTreeMap;
use std::sync::{Mutex, OnceLock as SyncOnceLock, PoisonError};
use std::time::Duration;

#[cfg(test)]
use arkret_sdk::ErrorEnvelope;
use arkret_sdk::events::{CbaEffectPlane, cba_cell_family_plane};
use arkret_wire::{CapabilityActionId, event_kind_str};
#[cfg(test)]
use garth::ScheduledSendSubmissionState;
use garth::outbound::BoxOutboundFuture;
use garth::{
    MlsAdmissionStage, OutboundEngine, OutboundEngineOutcome, OutboundGenerationFenceDecision,
    OutboundPostAcceptHook, OutboundSubmitOutcome, OutboundSubmitter,
    QueuedAuthoredEventAttempt as AuthoredEventAttempt, QueuedEventIntent,
    QueuedPostAcceptAction as PostAcceptAction, QueuedRealmBootstrap, QueuedRecord, QueuedSdkEvent,
};
#[cfg(test)]
use reqwest::StatusCode;
use serde_json::Value;
use tokio::sync::OnceCell;

#[cfg(test)]
use crate::api_error::TransportClientError;
use crate::ephemeral::{ensure_events_submit_accepted, validate_outgoing_registered_event_payload};
use crate::identity::authoring_generation::EventAuthorityFacts;
use crate::models::{BackfillView, ServiceDescribe, SubmitEventResult};
use crate::operation::{EventIntent, LocalOperation, uuid_v7};

mod authority;
use authority::*;

/// Authenticated durable/ephemeral event submission engine extracted from the
/// former `TransportClient` events surface. Constructed per authenticated call from
/// the shared SDK http-client (see `crate::transport::auth::with_event_submitter`).
pub struct EventSubmitter {
    http: arkret_sdk::http_client::Client,
    /// Exact account authority captured when this submitter is constructed.
    /// Durable queue operations never re-read the process-global active scope.
    authority: Option<arkret_sdk::PrincipalAuthorityKey>,
    describe_cache: OnceCell<ServiceDescribe>,
    state_store: Option<crate::runtime::input::StateStoreHandle>,
}

/// Ordinary Realm and self-principal bootstrap units intentionally publish
/// without per-Event Control Proposal Acks. A managed Agent PCR create is also an
/// anchor unit, but its delegated controller is the founding proposal
/// authority, so it must pass through `standard_initial_submission` to attach
/// that controller's Control Proposal Ack.
fn uses_bare_online_anchor_submission(anchor_unit: bool, event: &arkret_sdk::Event) -> bool {
    anchor_unit && !crate::authorization_lease::is_managed_agent_pcr_genesis(event)
}

/// The write is safely persisted and will be retried.
///
/// It is keyed by the holder-local operation id, not an Event id: at the moment
/// this is raised the write may not have been authored yet, and after a CAS
/// re-author the Event id is not stable while the user's operation is.
#[derive(Debug, thiserror::Error)]
#[error("operation {operation_id} is durably queued for retry")]
pub(crate) struct DurablyQueuedError {
    pub(crate) operation_id: String,
}

#[derive(Clone, Copy)]
struct InksonPostAcceptHook;

impl OutboundPostAcceptHook for InksonPostAcceptHook {
    fn post_accept<'a>(
        &'a self,
        item: &'a garth::SendQueueItem,
        event_id: &'a arkret_sdk::EventId,
        _duplicate: bool,
    ) -> BoxOutboundFuture<'a, ()> {
        Box::pin(async move {
            let _ = (item, event_id);
            Ok(())
        })
    }
}

pub(crate) fn is_durably_queued_error(error: &anyhow::Error) -> bool {
    error.downcast_ref::<DurablyQueuedError>().is_some()
}

/// Whether a prepare pass may make semantic authoring decisions (the
/// authority-root claim) or must reproduce a frozen queued intent verbatim.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SemanticAuthoring {
    Fresh,
    FrozenIntent,
}

/// One stage of an atomic unit, built from the members already authored before
/// it. A stage may yield several intents when they all depend on the same
/// earlier members and on nothing from each other; the actor-chain positions
/// within a stage are still assigned one at a time, in order. See
/// [`EventSubmitter::author_event_unit`].
pub(crate) type EventUnitStep =
    Box<dyn FnOnce(&[arkret_sdk::AuthoredEvent]) -> anyhow::Result<Vec<EventIntent>> + Send>;

/// One authoring attempt at a frozen intent: the finalized, signed Event and
/// the exact transport identity that goes with those bytes.
pub(crate) struct AuthoredAttempt {
    pub(crate) envelope: arkret_sdk::AuthoredEvent,
    pub(crate) transport_idempotency_key: String,
    pub(crate) canonical_body_bytes: Vec<u8>,
}

#[derive(Default)]
struct OutboundAttemptResults {
    accepted: Mutex<BTreeMap<String, SubmitEventResult>>,
    rejected: Mutex<BTreeMap<String, anyhow::Error>>,
}

struct EventOutboundSubmitter<'a> {
    owner: &'a EventSubmitter,
    results: &'a OutboundAttemptResults,
    state_store: Option<crate::runtime::input::StateStoreHandle>,
}

impl EventOutboundSubmitter<'_> {
    async fn submit_mls_admission_unit(
        &self,
        queued: &QueuedSdkEvent,
        commit: &arkret_sdk::AuthoredEvent,
    ) -> anyhow::Result<SubmitEventResult> {
        let Some(PostAcceptAction::MlsAdmission {
            proposal_events,
            stage: MlsAdmissionStage::CommitPending,
            ..
        }) = queued.post_accept.as_ref()
        else {
            anyhow::bail!("MLS admission unit transport requires a commit-pending action");
        };
        let mut unit = proposal_events.clone();
        unit.push(commit.clone());
        let outcome = self
            .owner
            .submit_signed_sdk_events_batch(&unit, Some(commit.event_id().as_str()))
            .await?;
        let accepted = outcome.accepted.contains(commit.event_id());
        let duplicate = outcome.duplicate.contains(commit.event_id());
        if accepted == duplicate {
            anyhow::bail!(
                "MLS admission batch did not classify its Commit exactly once as accepted or duplicate"
            );
        }
        Ok(SubmitEventResult {
            event_id: commit.event_id().to_string(),
            status: if duplicate {
                arkret_sdk::EventsSubmitStatus::Duplicate
            } else {
                arkret_sdk::EventsSubmitStatus::Accepted
            },
            cursor: outcome.cursor.unwrap_or_default(),
            ingress_receipts: outcome.ingress_receipts,
        })
    }

    async fn verify_covering_seal(&self, event: &arkret_sdk::Event) -> anyhow::Result<()> {
        let state_store = self.state_store.as_ref();
        let digest_suite = verify_event_is_covered_by_accepted_seal(
            &self.owner.http,
            event,
            |event, digest_suite, evidence, dependencies| {
                let state_store = state_store.ok_or_else(|| {
                    arkret_sdk::WireError::Protocol(
                        "Native Agent Event verification requires a durable governance trust store"
                            .to_owned(),
                    )
                })?;
                crate::mls::governance_proof::verify_native_agent_history_key(
                    state_store,
                    event,
                    digest_suite,
                    evidence,
                    dependencies,
                )
            },
        )
        .await?;
        let digest = arkret_sdk::Hash::new(event.event_digest_with_digest_suite(digest_suite)?)?;
        let outcome = self
            .owner
            .http
            .events_resolve(&arkret_sdk::EventsResolveRequestBody {
                event_ids: vec![event.event_id.clone()],
                event_digests: vec![digest.clone()],
                include_payload: Some(true),
                history_traversal_access: None,
                max_response_bytes: Some(arkret_sdk::MAX_PEER_RESOLVE_RESPONSE_BYTES),
            })
            .await?;
        let resolved = outcome
            .events
            .iter()
            .find(|candidate| candidate.event_id == event.event_id)
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "Event {} is durable but has no accepted covering Seal yet",
                    event.event_id
                )
            })?;
        if arkret_sdk::canonical::canonical_json_bytes(resolved)?
            != arkret_sdk::canonical::canonical_json_bytes(event)?
            || arkret_sdk::Hash::new(resolved.event_digest_with_digest_suite(digest_suite)?)?
                != digest
        {
            anyhow::bail!(
                "events.resolve returned different canonical bytes for Event {}",
                event.event_id
            );
        }
        Ok(())
    }

    // The `expect` below asserts the queue-record invariant named in its
    // message; a `?` rewrite would add an error path no caller can reach.
    #[allow(clippy::expect_used)]
    async fn resume_mls_admission(
        &self,
        mut queued: QueuedSdkEvent,
    ) -> garth::Result<OutboundSubmitOutcome> {
        let commit = queued
            .authored_attempt
            .as_ref()
            .ok_or_else(|| {
                garth::Error::Protocol("MLS admission lost its authored Commit".to_owned())
            })?
            .envelope
            .clone();
        let stage = match queued.post_accept.as_ref() {
            Some(PostAcceptAction::MlsAdmission { stage, .. }) => *stage,
            _ => {
                return Err(garth::Error::Protocol(
                    "MLS admission resume called for a non-admission item".to_owned(),
                ));
            }
        };

        match stage {
            MlsAdmissionStage::CommitPending => Err(garth::Error::Protocol(
                "commit-pending admission must use the Commit transport path".to_owned(),
            )),
            MlsAdmissionStage::CommitAcceptedWaitingSeal => {
                if let Err(error) = self.verify_covering_seal(&commit).await {
                    return Ok(OutboundSubmitOutcome::RetryAfter {
                        delay: Duration::from_secs(1),
                        reason: format!("MLS Commit finality pending: {error:#}"),
                    });
                }
                let Some(PostAcceptAction::MlsAdmission {
                    stage, welcomes, ..
                }) = queued.post_accept.as_mut()
                else {
                    unreachable!("admission action was matched above")
                };
                let intents = welcomes
                    .pending()
                    .ok_or_else(|| {
                        garth::Error::Protocol(
                            "commit-accepted admission must still hold pending Welcome intents"
                                .to_owned(),
                        )
                    })?
                    .to_vec();
                *welcomes = garth::QueuedMlsWelcomes::Authored {
                    events: self
                        .owner
                        .author_independent_events(intents)
                        .await
                        .map_err(|error| garth::Error::Protocol(error.to_string()))?,
                };
                *stage = MlsAdmissionStage::WelcomesAuthored;
                Ok(OutboundSubmitOutcome::Prepared {
                    record: QueuedRecord::SdkEvent(Box::new(queued)),
                })
            }
            MlsAdmissionStage::WelcomesAuthored => {
                let welcomes = match queued.post_accept.as_ref() {
                    Some(PostAcceptAction::MlsAdmission { welcomes, .. }) => welcomes
                        .authored()
                        .ok_or_else(|| {
                            garth::Error::Protocol(
                                "authored-Welcome stage holds unauthored intents".to_owned(),
                            )
                        })?
                        .to_vec(),
                    _ => unreachable!("admission action was matched above"),
                };
                for welcome in &welcomes {
                    let canonical_body_bytes = arkret_sdk::canonical::canonical_json_bytes(welcome)
                        .map_err(|error| garth::Error::Protocol(error.to_string()))?;
                    let idempotency_key = welcome.event_id().to_string();
                    if let Err(error) = self
                        .owner
                        .post_persisted_signed_sdk_event(
                            welcome,
                            &idempotency_key,
                            &canonical_body_bytes,
                        )
                        .await
                    {
                        return Ok(OutboundSubmitOutcome::RetryAfter {
                            delay: mls_admission_welcome_retry_delay(&error),
                            reason: format!("immutable MLS Welcome remains queued: {error:#}"),
                        });
                    }
                }
                let Some(PostAcceptAction::MlsAdmission { stage, .. }) =
                    queued.post_accept.as_mut()
                else {
                    unreachable!("admission action was matched above")
                };
                *stage = MlsAdmissionStage::WelcomesAcceptedWaitingSeal;
                Ok(OutboundSubmitOutcome::Prepared {
                    record: QueuedRecord::SdkEvent(Box::new(queued)),
                })
            }
            MlsAdmissionStage::WelcomesAcceptedWaitingSeal => {
                let (welcomes, receipts, duplicate) = match queued.post_accept.as_ref() {
                    Some(PostAcceptAction::MlsAdmission {
                        welcomes,
                        commit_ingress_receipts,
                        commit_was_duplicate,
                        ..
                    }) => (
                        welcomes
                            .authored()
                            .ok_or_else(|| {
                                garth::Error::Protocol(
                                    "Welcome finality stage holds unauthored intents".to_owned(),
                                )
                            })?
                            .to_vec(),
                        commit_ingress_receipts.clone(),
                        *commit_was_duplicate,
                    ),
                    _ => unreachable!("admission action was matched above"),
                };
                for welcome in &welcomes {
                    if let Err(error) = self.verify_covering_seal(welcome).await {
                        return Ok(OutboundSubmitOutcome::RetryAfter {
                            delay: Duration::from_secs(1),
                            reason: format!("MLS Welcome finality pending: {error:#}"),
                        });
                    }
                }
                let result = SubmitEventResult {
                    event_id: commit.event_id.to_string(),
                    status: if duplicate {
                        arkret_sdk::EventsSubmitStatus::Duplicate
                    } else {
                        arkret_sdk::EventsSubmitStatus::Accepted
                    },
                    cursor: String::new(),
                    ingress_receipts: receipts.clone(),
                };
                self.results
                    .accepted
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .insert(queued.local_operation_id.clone(), result);
                if duplicate {
                    Ok(OutboundSubmitOutcome::Duplicate {
                        event_id: commit.event_id().clone(),
                        ingress_receipts: receipts,
                    })
                } else {
                    Ok(OutboundSubmitOutcome::Accepted {
                        event_id: commit.event_id().clone(),
                        ingress_receipts: receipts,
                    })
                }
            }
        }
    }

    async fn submit_realm_bootstrap(
        &self,
        item: garth::SendQueueItem,
        queued: QueuedRealmBootstrap,
    ) -> garth::Result<OutboundSubmitOutcome> {
        match queued {
            // A genesis unit is authored as a unit before it is ever enqueued,
            // so there is no preparation stage left: the record already holds
            // the exact bytes it will send.
            QueuedRealmBootstrap::Prepared {
                transport_idempotency_key,
                events,
                ..
            } => {
                let event_id = events[0].event_id().clone();
                match self
                    .owner
                    .submit_signed_sdk_events_batch(&events, Some(&transport_idempotency_key))
                    .await
                {
                    Ok(outcome) => {
                        let duplicate = outcome.duplicate.iter().any(|id| id == &event_id)
                            && !outcome.accepted.iter().any(|id| id == &event_id);
                        if duplicate {
                            Ok(OutboundSubmitOutcome::Duplicate {
                                event_id,
                                ingress_receipts: outcome.ingress_receipts,
                            })
                        } else {
                            Ok(OutboundSubmitOutcome::Accepted {
                                event_id,
                                ingress_receipts: outcome.ingress_receipts,
                            })
                        }
                    }
                    Err(error) => {
                        let reason = format!("{error:#}");
                        if let Some(delay) = outbound_retry_delay(&error) {
                            Ok(OutboundSubmitOutcome::RetryAfter { delay, reason })
                        } else {
                            self.results
                                .rejected
                                .lock()
                                .unwrap_or_else(|poisoned| poisoned.into_inner())
                                .insert(item.transaction_id, error);
                            Ok(OutboundSubmitOutcome::Rejected { reason })
                        }
                    }
                }
            }
            direct @ QueuedRealmBootstrap::DirectConversationPrepared { .. } => {
                let submission = direct.direct_conversation_submission()?.ok_or_else(|| {
                    garth::Error::Protocol(
                        "Direct Conversation queue record lost its frozen submission".to_owned(),
                    )
                })?;
                if let Some(outcome) = direct.direct_conversation_accepted_outcome()? {
                    if !direct
                        .direct_conversation_founding_finality_confirmed()?
                        .unwrap_or(false)
                    {
                        for submitted in &submission.events {
                            if let Err(error) = self.verify_covering_seal(&submitted.event).await {
                                return Ok(OutboundSubmitOutcome::RetryAfter {
                                    delay: Duration::from_secs(2),
                                    reason: format!(
                                        "Direct Conversation founding accepted but not final: {error:#}"
                                    ),
                                });
                            }
                        }
                        let prepared =
                            direct.with_direct_conversation_founding_finality_confirmed()?;
                        return Ok(OutboundSubmitOutcome::Prepared {
                            record: QueuedRecord::RealmBootstrap(Box::new(prepared)),
                        });
                    }
                    let event_id = outcome.event_ids[0].clone();
                    return Ok(match outcome.status {
                        arkret_sdk::direct_conversation_ops::DirectConversationFoundingAcceptanceStatus::Accepted => {
                            OutboundSubmitOutcome::Accepted {
                                event_id,
                                ingress_receipts: Vec::new(),
                            }
                        }
                        arkret_sdk::direct_conversation_ops::DirectConversationFoundingAcceptanceStatus::Duplicate => {
                            OutboundSubmitOutcome::Duplicate {
                                event_id,
                                ingress_receipts: Vec::new(),
                            }
                        }
                    });
                }
                match self
                    .owner
                    .http
                    .direct_conversation_founding_submit(&submission)
                    .await
                {
                    Ok(outcome) => {
                        let prepared = direct.with_direct_conversation_accepted_outcome(outcome)?;
                        Ok(OutboundSubmitOutcome::Prepared {
                            record: QueuedRecord::RealmBootstrap(Box::new(prepared)),
                        })
                    }
                    Err(error) => {
                        let error = anyhow::Error::from(error);
                        let reason = format!("{error:#}");
                        if let Some(delay) = outbound_retry_delay(&error) {
                            Ok(OutboundSubmitOutcome::RetryAfter { delay, reason })
                        } else {
                            self.results
                                .rejected
                                .lock()
                                .unwrap_or_else(PoisonError::into_inner)
                                .insert(item.transaction_id, error);
                            Ok(OutboundSubmitOutcome::Rejected { reason })
                        }
                    }
                }
            }
        }
    }
}

pub(crate) async fn verify_event_is_covered_by_accepted_seal<VerifyNativeAgentHistoryKey>(
    http: &arkret_sdk::http_client::Client,
    event: &arkret_sdk::Event,
    verify_native_agent_history_key: VerifyNativeAgentHistoryKey,
) -> anyhow::Result<arkret_sdk::DigestSuite>
where
    VerifyNativeAgentHistoryKey: Fn(
            &arkret_sdk::Event,
            arkret_sdk::DigestSuite,
            &arkret_sdk::AuthenticatedSignerResolutionEvidence,
            &[arkret_sdk::GovernanceDependency],
        ) -> Result<arkret_sdk::signatures::PublicKeyMaterial, arkret_sdk::WireError>
        + Copy,
{
    let frontier = http.seals_frontier(event.realm_id.clone()).await?.frontier;
    let resolved = crate::mls::governance_acquisition::resolve_mls_governance_checkpoint_with_http(
        http,
        &event.realm_id,
        &frontier.seal_basis,
    )
    .await
    .map_err(anyhow::Error::msg)?;
    let verified = arkret_sdk::verify_mls_governance_closure(
        &event.realm_id,
        &resolved.target_basis,
        &resolved.seals,
        &resolved.events,
        &resolved.dependencies,
        verify_native_agent_history_key,
    )?;
    let digest = arkret_sdk::signed_event_digest_claim(event)?;
    let digest_suite = verified
        .event_digest_suites
        .get(&digest)
        .copied()
        .ok_or_else(|| anyhow::anyhow!("Event {} has no accepted covering Seal", event.event_id))?;
    event.verify_event_id_matches_content_with_digest_suite(digest_suite)?;
    let event_bytes = arkret_sdk::canonical::canonical_json_bytes(event)?;
    let exact_event_is_accepted = verified.checkpoint.accepted_events.iter().any(|accepted| {
        arkret_sdk::canonical::canonical_json_bytes(accepted)
            .is_ok_and(|accepted_bytes| accepted_bytes == event_bytes)
    });
    if !exact_event_is_accepted {
        anyhow::bail!(
            "Event {} is not byte-exact in the verified accepted closure",
            event.event_id
        );
    }
    Ok(digest_suite)
}

impl OutboundSubmitter for EventOutboundSubmitter<'_> {
    fn submit<'a>(
        &'a self,
        item: garth::SendQueueItem,
    ) -> BoxOutboundFuture<'a, OutboundSubmitOutcome> {
        Box::pin(async move {
            let mut queued = match item.record.clone() {
                QueuedRecord::SdkEvent(queued) => *queued,
                QueuedRecord::RealmBootstrap(queued) => {
                    return self.submit_realm_bootstrap(item, *queued).await;
                }
            };
            if queued.mark_scheduled_submission_uncertain() {
                // Persist the uncertainty boundary before the first HTTP write.
                // A crash after this point can only resume the exact signed
                // bytes carried by the record; it cannot consult or rebuild the
                // editable scheduled-send plan.
                return Ok(OutboundSubmitOutcome::Prepared {
                    record: QueuedRecord::SdkEvent(Box::new(queued)),
                });
            }
            if queued.authored_attempt.is_none() {
                let attempt = self
                    .owner
                    .author_frozen_intent(&queued.intent, &queued.local_operation_id)
                    .await
                    .map_err(|error| garth::Error::Protocol(error.to_string()))?;
                queued.authored_attempt = Some(AuthoredEventAttempt {
                    intent_digest: queued.intent_digest.clone(),
                    envelope: attempt.envelope,
                    transport_idempotency_key: attempt.transport_idempotency_key,
                    canonical_body_bytes: attempt.canonical_body_bytes,
                });
                return Ok(OutboundSubmitOutcome::Prepared {
                    record: QueuedRecord::SdkEvent(Box::new(queued)),
                });
            }
            if matches!(
                queued.post_accept.as_ref(),
                Some(PostAcceptAction::MlsAdmission { stage, .. })
                    if *stage != MlsAdmissionStage::CommitPending
            ) {
                return self.resume_mls_admission(queued).await;
            }
            let attempt = queued.authored_attempt.as_ref().ok_or_else(|| {
                garth::Error::Protocol("prepared outbound Event has no authored attempt".to_owned())
            })?;
            let event = &attempt.envelope;
            let submission = if matches!(
                queued.post_accept.as_ref(),
                Some(PostAcceptAction::MlsAdmission {
                    stage: MlsAdmissionStage::CommitPending,
                    ..
                })
            ) {
                self.submit_mls_admission_unit(&queued, event).await
            } else {
                self.owner
                    .submit_sdk_event_direct(
                        event,
                        &attempt.transport_idempotency_key,
                        &attempt.canonical_body_bytes,
                    )
                    .await
            };
            match submission {
                Ok(result) => {
                    // Ingress acceptance is not Commit finality. Freeze this
                    // boundary first, then a later queue pass waits until the
                    // accepted Realm Seal head crosses the Commit basis.
                    if let Some(PostAcceptAction::MlsAdmission {
                        stage,
                        commit_ingress_receipts,
                        commit_was_duplicate,
                        ..
                    }) = queued.post_accept.as_mut()
                    {
                        *stage = MlsAdmissionStage::CommitAcceptedWaitingSeal;
                        *commit_ingress_receipts = result.ingress_receipts.clone();
                        *commit_was_duplicate =
                            result.status == arkret_sdk::EventsSubmitStatus::Duplicate;
                        return Ok(OutboundSubmitOutcome::Prepared {
                            record: QueuedRecord::SdkEvent(Box::new(queued)),
                        });
                    }
                    let event_id =
                        arkret_sdk::EventId::new(result.event_id.clone()).map_err(|error| {
                            garth::Error::Protocol(format!(
                                "server returned invalid accepted event id: {error}"
                            ))
                        })?;
                    let duplicate = result.status == arkret_sdk::EventsSubmitStatus::Duplicate;
                    // The receipts travel with the outcome, not in the untyped
                    // blob: they are the proof the Event landed inside its
                    // authorization-lease window, and the queue refuses an
                    // acceptance that carries none.
                    let ingress_receipts = result.ingress_receipts.clone();
                    self.results
                        .accepted
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner())
                        .insert(item.transaction_id, result);
                    if duplicate {
                        Ok(OutboundSubmitOutcome::Duplicate {
                            event_id,
                            ingress_receipts,
                        })
                    } else {
                        Ok(OutboundSubmitOutcome::Accepted {
                            event_id,
                            ingress_receipts,
                        })
                    }
                }
                Err(error) => {
                    if matches!(
                        queued.post_accept.as_ref(),
                        Some(PostAcceptAction::MlsAdmission { .. })
                    ) {
                        let reason = if crate::api_error::actor_seq_cas_conflict_details(&error)
                            .is_some()
                        {
                            "MLS admission commit frontier changed; the bound Welcome cannot be reauthored independently".to_owned()
                        } else {
                            format!("immutable MLS admission attempt was rejected: {error:#}")
                        };
                        // The queue cannot know whether a previous transport
                        // attempt accepted the Commit before the response was
                        // lost. Preserve the exact Commit/Welcome/snapshot for
                        // duplicate confirmation or explicit repair on every
                        // deterministic response as well as transient errors.
                        return Ok(mls_admission_repair_retry_outcome(&reason));
                    }
                    if let Some(details) = crate::api_error::actor_seq_cas_conflict_details(&error)
                    {
                        if details.current_frontier.realm_id != event.realm_id
                            || details.current_frontier.actor_id != event.actor_id
                        {
                            return Ok(OutboundSubmitOutcome::Terminal {
                                reason: "CAS frontier scope does not match queued Event".to_owned(),
                            });
                        }
                        if queued.scheduled_dispatch.is_some() {
                            let reason = "frozen scheduled dispatch hit an explicit actor frontier conflict; the signed Event is retained and must not be rebuilt from the editable plan".to_owned();
                            self.results
                                .rejected
                                .lock()
                                .unwrap_or_else(|poisoned| poisoned.into_inner())
                                .insert(item.transaction_id, error);
                            return Ok(OutboundSubmitOutcome::Rejected { reason });
                        }
                        let replacement = self
                            .owner
                            .reauthor_after_explicit_cas(&queued)
                            .await
                            .map_err(|error| garth::Error::Protocol(error.to_string()))?;
                        // A CAS re-author is a NEW attempt at the SAME user
                        // operation: it gets its own queue slot keyed by the
                        // Event it actually authored, while
                        // `local_operation_id` stays put so receipt, backfill
                        // and the optimistic row still see one operation.
                        let (transaction_id, realm_id) = replacement
                            .authored_attempt
                            .as_ref()
                            .map(|attempt| {
                                (
                                    attempt.envelope.event_id().to_string(),
                                    attempt.envelope.realm_id.clone(),
                                )
                            })
                            .ok_or_else(|| {
                                garth::Error::Protocol(
                                    "CAS replacement was not authored".to_owned(),
                                )
                            })?;
                        return Ok(OutboundSubmitOutcome::Supersede {
                            transaction_id,
                            realm_id,
                            record: QueuedRecord::SdkEvent(Box::new(replacement)),
                            depends_on: item.depends_on,
                        });
                    }
                    let reason = format!("{error:#}");
                    if let Some(delay) = outbound_retry_delay(&error) {
                        tracing::warn!(
                            event_id = %item.transaction_id,
                            %reason,
                            retry_after_ms = delay.as_millis(),
                            "durable Event submit remains queued after a retryable failure"
                        );
                        return Ok(OutboundSubmitOutcome::RetryAfter { delay, reason });
                    }
                    tracing::warn!(
                        event_id = %item.transaction_id,
                        %reason,
                        "durable Event submit rejected terminally (no retry); queue item cancelled"
                    );
                    self.results
                        .rejected
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner())
                        .insert(item.transaction_id, error);
                    Ok(OutboundSubmitOutcome::Rejected { reason })
                }
            }
        })
    }
}

fn outbound_retry_delay(error: &anyhow::Error) -> Option<Duration> {
    let rendered = format!("{error:#}");
    if crate::api_error::is_auth_expired_error(error)
        || rendered.contains("no active signer configured")
    {
        return Some(Duration::from_secs(1));
    }
    // Browser fetch failures can cross the WASM/runtime-service boundary as a
    // string-only anyhow context, losing the concrete http-client Error in the
    // source chain. Its stable transport prefix still distinguishes a
    // retryable network failure from protocol and admission rejections.
    if rendered.contains("HTTP request failed:") {
        return Some(Duration::from_secs(1));
    }
    if let Some(retry_after_ms) = crate::api_error::rate_limited_retry_after(error) {
        return Some(Duration::from_millis(retry_after_ms.max(1_000)));
    }
    error.chain().find_map(|cause| {
        if let Some(error) = cause.downcast_ref::<arkret_sdk::http_client::Error>() {
            return match error {
                arkret_sdk::http_client::Error::Http(_) => Some(Duration::from_secs(1)),
                arkret_sdk::http_client::Error::Api { status, .. }
                    if *status == 408 || *status == 429 || *status >= 500 =>
                {
                    Some(Duration::from_secs(1))
                }
                _ => None,
            };
        }
        cause
            .downcast_ref::<arkret_sdk::Error>()
            .and_then(|error| match error {
                arkret_sdk::Error::Http(_) => Some(Duration::from_secs(1)),
                arkret_sdk::Error::Api { status, .. }
                    if *status == 408 || *status == 429 || *status >= 500 =>
                {
                    Some(Duration::from_secs(1))
                }
                _ => None,
            })
    })
}

fn mls_admission_welcome_retry_delay(error: &anyhow::Error) -> Duration {
    outbound_retry_delay(error).unwrap_or_else(|| Duration::from_secs(60))
}

fn mls_admission_repair_retry_outcome(reason: &str) -> OutboundSubmitOutcome {
    OutboundSubmitOutcome::RetryAfter {
        delay: Duration::from_secs(60),
        reason: format!("MLS admission repair required: {reason}"),
    }
}

fn verified_recovery_gate_cache() -> &'static Mutex<std::collections::BTreeSet<String>> {
    static CACHE: SyncOnceLock<Mutex<std::collections::BTreeSet<String>>> = SyncOnceLock::new();
    CACHE.get_or_init(|| Mutex::new(std::collections::BTreeSet::new()))
}

pub(crate) fn remember_verified_recovery_gate(authority_principal: &str, device_id: &str) {
    let Some(key) = normalized_recovery_gate_cache_key(authority_principal, device_id) else {
        return;
    };
    let mut cache = verified_recovery_gate_cache()
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    cache.insert(key);
}

fn normalized_recovery_gate_cache_key(
    authority_principal: &str,
    device_id: &str,
) -> Option<String> {
    let principal = arkret_sdk::DidCoreId::new(authority_principal.to_owned())
        .ok()
        .or_else(|| {
            let full = arkret_sdk::DidFullId::new(authority_principal.to_owned()).ok()?;
            arkret_sdk::project_full_id_to_core_id(&full).ok()
        })?;
    let device = arkret_sdk::DeviceId::new(device_id.to_owned()).ok()?;
    Some(format!("{principal}\u{1f}{device}"))
}

fn recovery_gate_cache_key(intent: &EventIntent) -> Option<String> {
    let authority_principal = intent
        .executed_by()
        .unwrap_or_else(|| intent.actor_id())
        .as_str();
    let signer = crate::event_signer::active_signer()?;
    let device_id = signer.device_id()?;
    normalized_recovery_gate_cache_key(authority_principal, device_id)
}

pub(crate) fn reset_verified_recovery_gates() {
    let mut cache = verified_recovery_gate_cache()
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    cache.clear();
}

/// The chain position an accepted frontier reports for one `(realm, actor)`.
///
/// A frontier for a different scope describes a different chain, so authoring
/// against it would claim a position this actor never held. That check has to
/// happen before the position reaches authoring: once the identity is derived
/// from it, a wrong `actor_seq` is signed content.
fn actor_chain_basis_from_frontier(
    realm_id: &arkret_sdk::RealmId,
    actor_id: &str,
    frontier: arkret_sdk::RealmActorFrontierView,
) -> anyhow::Result<(u64, Vec<arkret_sdk::EventId>)> {
    if frontier.actor_id.as_str() != actor_id || &frontier.realm_id != realm_id {
        anyhow::bail!(
            "realm actor frontier mismatch: intent scope ({realm_id}, {actor_id}) but frontier scope ({}, {})",
            frontier.realm_id,
            frontier.actor_id
        );
    }
    frontier.validate()?;
    Ok((frontier.next_actor_seq, frontier.frontier_event_ids))
}

fn actor_frontier_refresh_error(actor_id: &str, error: anyhow::Error) -> anyhow::Error {
    error.context(format!(
        "refresh actor frontier for {actor_id} before submit"
    ))
}

fn pending_chat_local_operation_ids_from_snapshot(
    snapshot: &garth::SendQueueSnapshot,
    realm_id: &str,
    strand_id: &str,
) -> std::collections::BTreeSet<String> {
    use garth::SendQueueStatus;

    snapshot
        .items
        .iter()
        .filter(|item| {
            matches!(
                item.status,
                SendQueueStatus::Queued | SendQueueStatus::Sending | SendQueueStatus::Failed
            )
        })
        .filter_map(|item| match &item.record {
            QueuedRecord::SdkEvent(queued)
                if queued.intent.kind() == &arkret_sdk::EventKind::MessageCreate =>
            {
                Some(queued)
            }
            _ => None,
        })
        .filter(|queued| {
            queued
                .intent
                .realm_id_opt()
                .map(arkret_sdk::RealmId::as_str)
                == Some(realm_id)
                && queued
                    .intent
                    .payload()
                    .get("strand_id")
                    .and_then(serde_json::Value::as_str)
                    == Some(strand_id)
        })
        .map(|queued| queued.local_operation_id.clone())
        .collect()
}

/// Project the holder-local ids of pending chat sends directly from the one
/// durable Garth queue.
///
/// The chat UI uses this snapshot instead of maintaining a second plaintext
/// outbox with separate replay semantics. The ids are holder-local: a queued
/// send has no accepted Message id yet, because the Message is named by the
/// create Event nobody has accepted.
pub(crate) async fn pending_chat_outbound_local_operation_ids(
    authority: &arkret_sdk::PrincipalAuthorityKey,
    realm_id: &str,
    strand_id: &str,
) -> anyhow::Result<std::collections::BTreeSet<String>> {
    let outbound = OutboundEngine::new(crate::outbound_store::InksonOutboundStore::open(
        authority,
        crate::outbound_store::OutboundLane::Standard,
    )?);
    let snapshot = outbound.snapshot().await?;
    Ok(pending_chat_local_operation_ids_from_snapshot(
        &snapshot, realm_id, strand_id,
    ))
}

fn completed_outbound_result(item: &garth::SendQueueItem) -> SubmitEventResult {
    SubmitEventResult {
        event_id: item
            .remote_event_id
            .as_ref()
            .map(ToString::to_string)
            .unwrap_or_default(),
        status: arkret_sdk::EventsSubmitStatus::Accepted,
        cursor: String::new(),
        // The queue is the durable holder of the receipts once an item is
        // Sent; replay them from the item rather than dropping the evidence.
        ingress_receipts: item.ingress_receipts.clone(),
    }
}

fn outbound_store_lane(
    intent: &EventIntent,
    durable_post_accept: bool,
) -> crate::outbound_store::OutboundLane {
    if durable_post_accept {
        crate::outbound_store::OutboundLane::MlsDurablePostAccept
    } else if intent.kind().as_str().starts_with("ak.mls.") {
        // MLS callers that persist their own snapshot after this method
        // returns carry no durable post-accept action; keep them host-only.
        crate::outbound_store::OutboundLane::MlsHostOnly
    } else {
        crate::outbound_store::OutboundLane::Standard
    }
}

/// A browser runtime has multiple outbound triggers: the foreground writer
/// and the account-sync drain. Garth engines opened on the same durable store
/// do not share an in-memory lease, so without a runtime single-writer gate
/// both triggers can prepare and sign the same Event against different actor
/// frontiers. The server then correctly accepts one canonical envelope and
/// rejects the other as `duplicate_conflict`.
fn outbound_submit_lock() -> &'static tokio::sync::Mutex<()> {
    static LOCK: std::sync::OnceLock<tokio::sync::Mutex<()>> = std::sync::OnceLock::new();
    LOCK.get_or_init(|| tokio::sync::Mutex::new(()))
}

impl EventSubmitter {
    pub fn new(http: arkret_sdk::http_client::Client) -> Self {
        Self {
            http,
            authority: crate::secure_key_store::active_device_seed_scope()
                .map(|scope| scope.authority),
            describe_cache: OnceCell::new(),
            state_store: None,
        }
    }

    pub(crate) fn with_state_store(
        mut self,
        state_store: crate::runtime::input::StateStoreHandle,
    ) -> Self {
        self.state_store = Some(state_store);
        self
    }

    pub(crate) fn with_authority(mut self, authority: arkret_sdk::PrincipalAuthorityKey) -> Self {
        self.authority = Some(authority);
        self
    }

    pub(crate) fn authority(&self) -> anyhow::Result<&arkret_sdk::PrincipalAuthorityKey> {
        self.authority.as_ref().ok_or_else(|| {
            anyhow::anyhow!(
                "durable Event submission requires an active PrincipalAuthorityKey captured when the submitter was created"
            )
        })
    }

    pub(crate) fn from_current_session(http: arkret_sdk::http_client::Client) -> Self {
        match dioxus::prelude::try_consume_context::<crate::app::SessionContext>() {
            Some(context) => {
                use dioxus::prelude::ReadableExt as _;
                let authority = context
                    .active_account
                    .peek()
                    .as_ref()
                    .map(|account| account.authority.clone());
                let mut submitter = Self::new(http).with_state_store(
                    crate::app::runtime_adapter::state_store_handle(context.state_store),
                );
                if let Some(authority) = authority {
                    submitter = submitter.with_authority(authority);
                }
                submitter
            }
            None => Self::new(http),
        }
    }

    /// The shared SDK http-client backing this submitter. Event-authoring free
    /// functions that also need a plain transport call (for example the
    /// account-data actor-scope lookup preceding a `ak.account_data.set`) reach
    /// it through here instead of holding a second `Client`.
    pub(crate) fn http(&self) -> &arkret_sdk::http_client::Client {
        &self.http
    }

    /// Author a Realm's complete genesis unit, then submit it through Garth's
    /// durable queue. A retry or process restart consumes the same queue record.
    ///
    /// The unit is authored before it is enqueued because its members name each
    /// other by final identity: every follow-up is scoped to the Realm the create
    /// Event derives. There is no earlier durable checkpoint to take — an
    /// unauthored genesis has no Realm id to file itself under, and the previous
    /// shape only had one by filing itself under a placeholder and retyping the
    /// whole record once authoring produced the real value.
    pub(crate) async fn submit_realm_bootstrap_durable(
        &self,
        steps: Vec<EventUnitStep>,
        local_operation_id: String,
    ) -> anyhow::Result<arkret_sdk::RealmId> {
        let _single_writer = outbound_submit_lock().lock().await;
        let events = self.author_event_unit(steps).await?;
        let first = events
            .first()
            .ok_or_else(|| anyhow::anyhow!("Realm bootstrap unit is empty"))?;
        let actor_id = first.actor_id.clone();
        let realm_id = first.realm_id.clone();
        let transport_idempotency_key = local_operation_id.clone();
        let queued = QueuedRealmBootstrap::prepared(
            local_operation_id.clone(),
            transport_idempotency_key,
            events,
        )?;
        let outbound = OutboundEngine::new(crate::outbound_store::InksonOutboundStore::open(
            self.authority()?,
            crate::outbound_store::OutboundLane::Standard,
        )?);
        outbound
            .enqueue_scoped(
                Some(local_operation_id.clone()),
                realm_id,
                actor_id,
                QueuedRecord::RealmBootstrap(Box::new(queued)),
                Vec::new(),
            )
            .await?;

        let results = OutboundAttemptResults::default();
        let submitter = EventOutboundSubmitter {
            owner: self,
            results: &results,
            state_store: None,
        };
        loop {
            let fence = self.resolve_queue_generation_fence(&outbound).await?;
            match outbound
                .submit_next_with_fence(&submitter, &fence, chrono::Utc::now())
                .await?
            {
                OutboundEngineOutcome::Prepared(_) | OutboundEngineOutcome::Superseded { .. } => {
                    continue;
                }
                OutboundEngineOutcome::Accepted(item) | OutboundEngineOutcome::Duplicate(item)
                    if item.transaction_id == local_operation_id =>
                {
                    let QueuedRecord::RealmBootstrap(queued) = item.record else {
                        anyhow::bail!("Realm bootstrap queue item changed record type");
                    };
                    return Ok(queued.authority_context_event()?.realm_id.clone());
                }
                OutboundEngineOutcome::Rejected { item, reason }
                | OutboundEngineOutcome::Terminal { item, reason }
                | OutboundEngineOutcome::Quarantined { item, reason }
                    if item.transaction_id == local_operation_id =>
                {
                    anyhow::bail!("Realm bootstrap rejected: {reason}");
                }
                OutboundEngineOutcome::RetryAt { item, .. }
                    if item.transaction_id == local_operation_id =>
                {
                    return Err(DurablyQueuedError {
                        operation_id: local_operation_id,
                    }
                    .into());
                }
                OutboundEngineOutcome::Idle => {
                    anyhow::bail!("durable Realm bootstrap disappeared from the outbound queue");
                }
                _ => continue,
            }
        }
    }

    /// Persist a fully signed Direct Conversation first-valid unit before the
    /// first HTTP write and replay its exact canonical body until the source
    /// service returns the slot-closing receipt. The receipt is frozen first;
    /// then every Event must resolve with its exact accepted covering Seal
    /// before the same queue record can become `Sent`.
    // The `expect` below asserts the constructor invariant named in its
    // message; a `?` rewrite would add an error path no caller can reach.
    #[allow(clippy::expect_used)]
    pub(crate) async fn submit_direct_conversation_founding_durable(
        &self,
        submission: arkret_sdk::direct_conversation_ops::DirectConversationFoundingUnitSubmission,
    ) -> anyhow::Result<
        arkret_sdk::direct_conversation_ops::DirectConversationFoundingAcceptanceOutcome,
    > {
        let _single_writer = outbound_submit_lock().lock().await;
        let queued = QueuedRealmBootstrap::direct_conversation_prepared(submission)?;
        let first = queued.authority_context_event()?;
        let actor_id = first.actor_id.clone();
        let realm_id = first.realm_id.clone();
        let local_operation_id = match &queued {
            QueuedRealmBootstrap::DirectConversationPrepared {
                local_operation_id, ..
            } => local_operation_id.clone(),
            _ => unreachable!("constructor returns DirectConversationPrepared"),
        };
        let expected_submission = queued
            .direct_conversation_submission()?
            .expect("constructor stores a Direct Conversation submission");
        let expected_submission_bytes =
            arkret_sdk::canonical::canonical_json_bytes(&expected_submission)?;
        let outbound = OutboundEngine::new(crate::outbound_store::InksonOutboundStore::open(
            self.authority()?,
            crate::outbound_store::OutboundLane::Standard,
        )?);
        let existing = outbound
            .snapshot()
            .await?
            .items
            .into_iter()
            .find(|item| item.transaction_id == local_operation_id);
        if let Some(existing) = existing {
            let QueuedRecord::RealmBootstrap(record) = &existing.record else {
                anyhow::bail!(
                    "Direct Conversation founding idempotency key belongs to another record type"
                );
            };
            let stored_submission = record
                .direct_conversation_submission()?
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "Direct Conversation founding idempotency key belongs to an ordinary Realm bootstrap"
                    )
                })?;
            if arkret_sdk::canonical::canonical_json_bytes(&stored_submission)?
                != expected_submission_bytes
            {
                anyhow::bail!(
                    "Direct Conversation founding idempotency key was reused for different signed bytes"
                );
            }
            if existing.status == garth::SendQueueStatus::Sent {
                return record
                    .direct_conversation_accepted_outcome()?
                    .ok_or_else(|| {
                        anyhow::anyhow!(
                            "sent Direct Conversation founding record lost its acceptance receipt"
                        )
                    });
            }
            if matches!(
                existing.status,
                garth::SendQueueStatus::Cancelled
                    | garth::SendQueueStatus::Superseded
                    | garth::SendQueueStatus::LeaseExpired
            ) {
                anyhow::bail!(
                    "Direct Conversation founding attempt is terminal in the durable queue"
                );
            }
        } else {
            outbound
                .enqueue_scoped(
                    Some(local_operation_id.clone()),
                    realm_id,
                    actor_id,
                    QueuedRecord::RealmBootstrap(Box::new(queued)),
                    Vec::new(),
                )
                .await?;
        }

        let results = OutboundAttemptResults::default();
        let submitter = EventOutboundSubmitter {
            owner: self,
            results: &results,
            state_store: None,
        };
        loop {
            let fence = self.resolve_queue_generation_fence(&outbound).await?;
            match outbound
                .submit_next_with_fence(&submitter, &fence, chrono::Utc::now())
                .await?
            {
                OutboundEngineOutcome::Prepared(_) | OutboundEngineOutcome::Superseded { .. } => {
                    continue;
                }
                OutboundEngineOutcome::Accepted(item) | OutboundEngineOutcome::Duplicate(item)
                    if item.transaction_id == local_operation_id =>
                {
                    let QueuedRecord::RealmBootstrap(record) = item.record else {
                        anyhow::bail!(
                            "Direct Conversation founding queue item changed record type"
                        );
                    };
                    return record
                        .direct_conversation_accepted_outcome()?
                        .ok_or_else(|| {
                            anyhow::anyhow!(
                                "Direct Conversation founding queue lost its accepted receipt"
                            )
                        });
                }
                OutboundEngineOutcome::Rejected { item, reason }
                | OutboundEngineOutcome::Terminal { item, reason }
                | OutboundEngineOutcome::Quarantined { item, reason }
                    if item.transaction_id == local_operation_id =>
                {
                    anyhow::bail!("Direct Conversation founding rejected: {reason}");
                }
                OutboundEngineOutcome::RetryAt { item, .. }
                    if item.transaction_id == local_operation_id =>
                {
                    return Err(DurablyQueuedError {
                        operation_id: local_operation_id,
                    }
                    .into());
                }
                OutboundEngineOutcome::Idle => {
                    anyhow::bail!(
                        "durable Direct Conversation founding disappeared from the outbound queue"
                    );
                }
                _ => continue,
            }
        }
    }

    async fn resolve_queue_generation_fence(
        &self,
        outbound: &OutboundEngine<crate::outbound_store::InksonOutboundStore>,
    ) -> anyhow::Result<crate::identity::authoring_generation::ResolvedQueueGenerationFence> {
        use garth::SendQueueStatus;

        use crate::identity::authoring_generation::CurrentEventAuthoringGeneration;

        let mut decisions = BTreeMap::new();
        for item in outbound.snapshot().await?.items {
            if !matches!(
                item.status,
                SendQueueStatus::Queued | SendQueueStatus::Sending | SendQueueStatus::Failed
            ) {
                continue;
            }
            let queued = match item.record {
                QueuedRecord::SdkEvent(queued) => queued,
                QueuedRecord::RealmBootstrap(_) => {
                    // A Realm bootstrap is an immutable anchor unit. Once its
                    // intent is durable it must either be prepared once or
                    // replay the frozen signed unit; signer-generation changes
                    // must never cause it to be reauthored with a new salt/HLC.
                    decisions.insert(
                        item.transaction_id,
                        OutboundGenerationFenceDecision::Current,
                    );
                    continue;
                }
            };
            if matches!(
                queued.post_accept.as_ref(),
                Some(PostAcceptAction::MlsAdmission { .. })
            ) {
                // An admission item may be resuming after its Commit was
                // accepted but before Welcome/snapshot completion. A later
                // signer generation must not cancel that immutable transcript;
                // submit it again and let the service confirm duplicate or
                // leave it durably repair-required.
                decisions.insert(
                    item.transaction_id,
                    OutboundGenerationFenceDecision::Current,
                );
                continue;
            }
            let decision = match crate::identity::authoring_generation::resolve_current_event_authoring_generation(
                &self.http,
                &EventAuthorityFacts::from_intent(&queued.intent),
            )
            .await?
            {
                CurrentEventAuthoringGeneration::Active(current)
                    if current == queued.authoring_generation =>
                {
                    OutboundGenerationFenceDecision::Current
                }
                CurrentEventAuthoringGeneration::Active(_) => {
                    OutboundGenerationFenceDecision::Quarantine {
                        reason: "authoring_generation_superseded".to_owned(),
                    }
                }
                CurrentEventAuthoringGeneration::Quarantine(reason) => {
                    OutboundGenerationFenceDecision::Quarantine { reason }
                }
            };
            decisions.insert(item.transaction_id, decision);
        }
        Ok(crate::identity::authoring_generation::ResolvedQueueGenerationFence::new(decisions))
    }

    /// Resume queued events for this actor without requiring a new user send.
    /// The account runner calls this after it has rebuilt an authenticated
    /// client, so process/browser restarts eventually drain pending work.
    pub(crate) async fn drain_outbound(&self) -> anyhow::Result<usize> {
        let _single_writer = outbound_submit_lock().lock().await;
        let outbound = OutboundEngine::new(crate::outbound_store::InksonOutboundStore::open(
            self.authority()?,
            crate::outbound_store::OutboundLane::Standard,
        )?);
        let results = OutboundAttemptResults::default();
        let submitter = EventOutboundSubmitter {
            owner: self,
            results: &results,
            state_store: None,
        };
        let mut completed = 0usize;
        loop {
            let fence = self.resolve_queue_generation_fence(&outbound).await?;
            match outbound
                .submit_next_with_fence(&submitter, &fence, chrono::Utc::now())
                .await?
            {
                OutboundEngineOutcome::Accepted(_) | OutboundEngineOutcome::Duplicate(_) => {
                    completed = completed.saturating_add(1);
                }
                OutboundEngineOutcome::Superseded { .. } => continue,
                OutboundEngineOutcome::Prepared(_) => continue,
                OutboundEngineOutcome::Rejected { .. } | OutboundEngineOutcome::Terminal { .. } => {
                    completed = completed.saturating_add(1);
                }
                OutboundEngineOutcome::Quarantined { item, reason } => {
                    tracing::warn!(
                        transaction_id = %item.transaction_id,
                        %reason,
                        "durable outbound item quarantined by authoring-generation fence"
                    );
                    completed = completed.saturating_add(1);
                }
                OutboundEngineOutcome::Idle | OutboundEngineOutcome::RetryAt { .. } => {
                    return Ok(completed);
                }
            }
        }
    }

    /// Resume durable MLS Commit/Welcome admission delivery. Group readiness
    /// is published separately by the checkpoint-proven accepted-artifact
    /// consumer; this queue never installs its staged snapshot.
    pub(crate) async fn drain_mls_outbound(
        &self,
        state_store: crate::runtime::input::StateStoreHandle,
    ) -> anyhow::Result<usize> {
        let _single_writer = outbound_submit_lock().lock().await;
        let outbound = OutboundEngine::new(crate::outbound_store::InksonOutboundStore::open(
            self.authority()?,
            crate::outbound_store::OutboundLane::MlsDurablePostAccept,
        )?);
        let results = OutboundAttemptResults::default();
        let submitter = EventOutboundSubmitter {
            owner: self,
            results: &results,
            state_store: Some(state_store.clone()),
        };
        let hook = InksonPostAcceptHook;
        let mut completed = 0usize;
        loop {
            let fence = self.resolve_queue_generation_fence(&outbound).await?;
            match outbound
                .submit_next_with_fence_and_hook(&submitter, &fence, &hook, chrono::Utc::now())
                .await?
            {
                OutboundEngineOutcome::Accepted(_)
                | OutboundEngineOutcome::Duplicate(_)
                | OutboundEngineOutcome::Rejected { .. }
                | OutboundEngineOutcome::Terminal { .. } => {
                    completed = completed.saturating_add(1);
                }
                OutboundEngineOutcome::Superseded { .. } => continue,
                OutboundEngineOutcome::Prepared(_) => continue,
                OutboundEngineOutcome::Quarantined { item, reason } => {
                    tracing::warn!(
                        transaction_id = %item.transaction_id,
                        %reason,
                        "durable MLS outbound item quarantined by authoring-generation fence"
                    );
                    completed = completed.saturating_add(1);
                }
                OutboundEngineOutcome::Idle | OutboundEngineOutcome::RetryAt { .. } => {
                    return Ok(completed);
                }
            }
        }
    }

    async fn describe(&self) -> anyhow::Result<ServiceDescribe> {
        self.http
            .describe()
            .await
            .map_err(|error| anyhow::anyhow!("server describe: {error}"))
    }

    /// Debug-only freshness diagnostic for a locally mixed server/WASM build.
    ///
    /// Exact build identity is not a protocol compatibility boundary. This
    /// function and every call to it are absent from release builds; production
    /// interoperability is negotiated from protocol/profile/operation/schema
    /// capabilities instead.
    #[cfg(all(debug_assertions, not(test)))]
    async fn diagnose_exact_development_sdk_build(&self) -> anyhow::Result<()> {
        let description = self.describe().await?;
        if description.development_mode {
            description
                .validate_exact_development_build_identity()
                .map_err(|error| {
                    anyhow::anyhow!(
                        "stale or mixed Arkret SDK build; refusing to author Event in this development session: {error}. Rebuild/reload Inkson and restart Soland from the same SDK checkout"
                    )
                })?;
        }
        Ok(())
    }

    async fn ensure_recovery_material_ready(
        &self,
        intent: &EventIntent,
        join_encryption_profile: Option<&arkret_sdk::EncryptionProfile>,
    ) -> anyhow::Result<()> {
        if !self
            .event_enters_post_bootstrap_e2ee_realm(intent, join_encryption_profile)
            .await?
        {
            return Ok(());
        }
        let accepted_principal_control_seal = recovery_gate_cache_key(intent).is_some_and(|key| {
            verified_recovery_gate_cache()
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .contains(&key)
        });
        let policy: arkret_sdk::RecoveryPolicyActiveOutcome = self
            .http
            .get("/_arkret/root/identity/recovery-policy")
            .await
            .map_err(anyhow::Error::from)?;
        match crate::recovery_strand::first_backup_gate_status(
            accepted_principal_control_seal,
            &policy,
        ) {
            crate::recovery_strand::FirstBackupGateStatus::Satisfied => Ok(()),
            crate::recovery_strand::FirstBackupGateStatus::Blocked(reason) => {
                anyhow::bail!("recovery_material_pending blocks E2EE Realm create/join: {reason:?}")
            }
        }
    }

    async fn event_enters_post_bootstrap_e2ee_realm(
        &self,
        intent: &EventIntent,
        join_encryption_profile: Option<&arkret_sdk::EncryptionProfile>,
    ) -> anyhow::Result<bool> {
        fn is_e2ee_create(intent: &EventIntent) -> bool {
            intent.kind() == &arkret_sdk::EventKind::RealmCreate
                && intent
                    .payload()
                    .get("object")
                    .and_then(Value::as_object)
                    .and_then(|object| object.get("encryption_profile"))
                    .and_then(Value::as_str)
                    == Some("mls_rfc9420")
                && !matches!(
                    intent
                        .payload()
                        .get("object")
                        .and_then(Value::as_object)
                        .and_then(|object| object.get("purpose"))
                        .and_then(Value::as_str),
                    Some("principal_control" | "managed_agent_control")
                )
        }

        if intent.kind() == &arkret_sdk::EventKind::RealmCreate {
            return Ok(is_e2ee_create(intent));
        }
        let is_join = intent.kind().as_str() == event_kind_str::INVITE_ACCEPT
            || (intent.kind().as_str() == event_kind_str::MEMBER_STATE
                && intent.payload().get("membership").and_then(Value::as_str) == Some("join"));
        if !is_join {
            return Ok(false);
        }
        if let Some(profile) = join_encryption_profile {
            return Ok(matches!(profile, arkret_sdk::EncryptionProfile::MlsRfc9420));
        }
        let Some(realm_id) = intent.realm_id_opt() else {
            return Ok(false);
        };
        let history = self
            .http
            .events_read_all_pages(realm_id.as_str())
            .await
            .map_err(anyhow::Error::from)?;
        for (index, row) in history.events.iter().enumerate() {
            let accepted = row.event().ok_or_else(|| {
                anyhow::anyhow!(
                    "E2EE admission history requires complete Events; row {index} is redacted or reference-locked"
                )
            })?;
            if is_e2ee_create(&EventIntent::from_authored(accepted)) {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Lazily fetch + cache the service describe for this submitter. Only the
    /// signing path calls this, so a submitter that never signs never fetches.
    async fn describe_cached(&self) -> anyhow::Result<&ServiceDescribe> {
        self.describe_cache
            .get_or_try_init(|| async { self.describe().await })
            .await
    }

    async fn verify_origin_principal_server(&self, intent: &EventIntent) -> anyhow::Result<()> {
        let origin = self.describe_cached().await?.service_id.clone();
        if intent.principal_server_id() != &origin {
            anyhow::bail!(
                "Event-declared origin {} does not match this Principal Server {}",
                intent.principal_server_id(),
                origin
            );
        }
        Ok(())
    }

    pub(crate) async fn service_full_id(&self) -> anyhow::Result<String> {
        Ok(self
            .describe_cached()
            .await?
            .service_resolution
            .full_id
            .to_string())
    }

    /// Resolve and freeze the exact Principal Server signer used as the
    /// single-signer notary for a newly created Realm.
    ///
    /// The descriptor is derived only from independently verified,
    /// content-addressable signer evidence. Describe fields or a separately
    /// fetched current DID document are not authority for Realm genesis.
    pub(crate) async fn current_service_notary(&self) -> anyhow::Result<arkret_sdk::NotaryValue> {
        let service_id = self.describe_cached().await?.service_id.clone();
        let resolution = self
            .http
            .open_service_resolution(&service_id)
            .await
            .map_err(anyhow::Error::from)?;
        let evidence = arkret_identity::service_signer_evidence_from_authenticated_resolution(
            resolution,
            &service_id,
            chrono::Utc::now(),
        )
        .map_err(anyhow::Error::from)?;
        let descriptor = arkret_sdk::ed25519_notary_signer_descriptor_from_evidence(&evidence)
            .map_err(anyhow::Error::from)?;
        Ok(arkret_sdk::NotaryValue::single_signer(descriptor))
    }

    /// Mint a DataEvent `seal_ref` head from the membership-gated Realm Seal
    /// view. Only the CBA data-plane stamping path uses this.
    pub(crate) async fn current_seal_for(&self, realm_id: &str) -> anyhow::Result<String> {
        let view = self.events_frontier_realm_seal_view(realm_id).await?;
        Ok(view.sole_leaf()?.to_string())
    }
    /// Query durable events through the current `/_arkret/self/events` surface,
    /// following pagination to completion (COR-07).
    pub async fn backfill(&self, realm_id: &str) -> anyhow::Result<BackfillView> {
        let outcome = self
            .http
            .events_read_all_pages(realm_id)
            .await
            .map_err(anyhow::Error::from)?;
        Ok(outcome.into())
    }

    pub(crate) async fn find_mls_genesis_event_id(
        &self,
        realm_id: &str,
    ) -> anyhow::Result<Option<arkret_sdk::EventId>> {
        // COR-07: the MLS genesis event may sit past the first page; paginate so
        // it is never silently judged "absent" because of front-page noise.
        let outcome = self
            .http
            .events_read_all_pages(realm_id)
            .await
            .map_err(anyhow::Error::from)?;
        mls_genesis_event_id_from_events(&outcome, realm_id)
    }

    /// Stream the canonical `/_arkret/self/events/subscribe` NDJSON response and
    /// invoke `on_frame` once per parsed frame.
    ///
    /// Send one Signal (`ak.self.signal.command.send`).
    ///
    /// Typing, presence, read receipts and call signalling all travel this one
    /// encrypted rail: the product payload type and its target are AEAD
    /// plaintext inside `encrypted_payload`, and the outer header exposes only
    /// `scope_ref` plus the three-value `signal_class`. There is no plaintext
    /// branch, so a scope whose Signal key material cannot be derived fails
    /// closed here instead of degrading (`signal.md` §3).
    /// [`send_signal`](Self::send_signal) with the Realm-scope header assembled
    /// from the current accepted Seal view.
    ///
    /// `seal_ref` is what the receiver resolves the sending device's live-send
    /// eligibility under, so it is fetched rather than remembered.
    pub async fn send_scope_signal(
        &self,
        scope_ref: arkret_sdk::ScopeRef,
        authority: &arkret_sdk::PrincipalAuthorityKey,
        device_id: &arkret_sdk::DeviceId,
        material: &crate::signal::SignalKeyMaterial,
        payload: &crate::signal::SignalPayload,
        state_store: &crate::runtime::input::StateStoreHandle,
    ) -> anyhow::Result<arkret_sdk::SignalSubmitOutcome> {
        let seal_ref = self.current_seal_for(scope_ref.realm_id().as_str()).await?;
        let header = crate::signal::SignalHeader::new(
            scope_ref,
            authority.principal_id.clone(),
            device_id.clone(),
            arkret_sdk::SealId::new(seal_ref)
                .map_err(|error| anyhow::anyhow!("invalid signal seal_ref: {error}"))?,
            payload.signal_class(),
            crate::clock::now_utc(),
        );
        self.send_signal(authority, header, material, payload, state_store)
            .await
    }

    /// Seal and submit one Signal.
    ///
    /// `state_store` is not optional plumbing: the AEAD nonce counter lives in
    /// the persisted MLS snapshot and `encoding.md` §10.1 requires it to be
    /// durably burnt before the envelope leaves this device. A caller that
    /// cannot supply mutable persisted state cannot send a Signal at all —
    /// v1 has no plaintext branch to fall back to.
    pub async fn send_signal(
        &self,
        authority: &arkret_sdk::PrincipalAuthorityKey,
        header: crate::signal::SignalHeader,
        material: &crate::signal::SignalKeyMaterial,
        payload: &crate::signal::SignalPayload,
        state_store: &crate::runtime::input::StateStoreHandle,
    ) -> anyhow::Result<arkret_sdk::SignalSubmitOutcome> {
        // Realm id and send time are no longer arguments: `signal.md` §1.1
        // forbids a plaintext restating what the signed envelope already
        // carries, so the closed profiles do not have fields for them.
        let sequence = crate::signal::next_signal_sequence(
            state_store,
            &header.sender_device_id,
            &header.scope_ref,
        )
        .await?;
        let plaintext = payload.to_plaintext(&header.sender_actor_id, sequence)?;
        let secure_store = crate::secure_key_store::default_secure_key_store("inkson");
        let encrypted_payload = state_store.write(|store| {
            crate::signal::encrypt_signal_payload_with_store(
                store,
                secure_store.as_ref(),
                authority,
                &header,
                material,
                &plaintext,
            )
        })?;
        let envelope = crate::signal::seal_signal_envelope(header, encrypted_payload)?;
        self.submit_signal_envelope(&envelope).await
    }

    /// `QUERY /_arkret/self/seals/frontier` — complete accepted Realm Seal
    /// antichain.
    ///
    /// This is the spec-registered account-client sourcing for minting a
    /// single-leaf Control Move `seal_basis` (`view.seal_basis()`) and a
    /// DataEvent `seal_ref` (`view.seal_id`) — SPEC-SOL-003 resolution.
    /// Fails closed (never fabricates a basis) when the server cannot
    /// serve the view or answers for a different Realm.
    pub async fn events_frontier_realm_seal_view(
        &self,
        realm_id: &str,
    ) -> anyhow::Result<arkret_sdk::RealmSealFrontierView> {
        let (view, _) = self.events_frontier_realm_state(realm_id).await?;
        Ok(view)
    }

    /// Resolve the accepted Seal named by the single-leaf Realm frontier.
    ///
    /// `event-auth-state-resolution.md` forbids treating any service-derived
    /// root hint as authority, so callers that need the frontier's signed roots
    /// resolve the leaf Seal itself through `ak.self.seals.read.resolve`.
    pub async fn events_frontier_realm_seal_head(
        &self,
        realm_id: &str,
    ) -> anyhow::Result<arkret_sdk::Seal> {
        let view = self.events_frontier_realm_seal_view(realm_id).await?;
        let leaf = view.sole_leaf()?.clone();
        let outcome = self
            .http
            .seals_resolve(&arkret_sdk::SelfSealResolveRequestBody {
                realm_id: view.realm_id.clone(),
                seal_refs: vec![leaf.clone()],
                history_traversal_access: None,
            })
            .await?;
        outcome
            .seals
            .into_iter()
            .find(|seal| seal.id == leaf)
            .ok_or_else(|| anyhow::anyhow!("accepted Realm Seal frontier leaf did not resolve"))
    }

    async fn events_frontier_realm_state(
        &self,
        realm_id: &str,
    ) -> anyhow::Result<(
        arkret_sdk::RealmSealFrontierView,
        Vec<arkret_sdk::ManagedAgentPcrSealHeadReceipt>,
    )> {
        let state = self
            .http
            .seals_frontier(arkret_sdk::RealmId::new(realm_id.to_owned())?)
            .await
            .map_err(anyhow::Error::from)?;
        let view = state.frontier;
        if view.realm_id.as_str() != realm_id {
            anyhow::bail!(
                "seals/frontier answered for realm {} instead of {realm_id}",
                view.realm_id
            );
        }
        Ok((view, state.receipts))
    }

    /// Return the accepted head needed to author the next managed Agent PCR
    /// Seal. The head can intentionally lag accepted Events. It is accepted
    /// only when its exact bytes occur in the locally replayed checkpoint.
    pub(crate) async fn events_frontier_managed_agent_seal_head<
        S: crate::mls::governance_proof::GovernanceProofStateStore,
    >(
        &self,
        realm_id: &str,
        _controller_id: &arkret_sdk::DidFullId,
        state_store: S,
    ) -> anyhow::Result<(arkret_sdk::RealmSealFrontierView, arkret_sdk::Seal)> {
        let (view, receipts) = self.events_frontier_realm_state(realm_id).await?;
        let receipt = receipts.first().ok_or_else(|| {
            anyhow::anyhow!("seals/frontier omitted the accepted managed Agent PCR Seal head")
        })?;
        let seal = receipt.seal.clone();
        let checkpoint = state_store
            .with_read(|store| store.trusted_mls_governance_checkpoint(realm_id))
            .ok_or_else(|| {
                anyhow::anyhow!("managed Agent PCR has no verified governance checkpoint")
            })?;
        if !checkpoint
            .accepted_seals
            .iter()
            .any(|accepted| accepted == &seal)
        {
            anyhow::bail!(
                "managed Agent PCR Seal head is not byte-exact in the verified checkpoint"
            );
        }
        // The frontier view carries no service-derived roots: the resolved
        // Seal's own signed roots are the only authority, so only identity is
        // cross-checked here.
        if seal.realm_id != view.realm_id || Some(&seal.id) != view.sole_leaf().ok() {
            anyhow::bail!("managed Agent PCR Seal head differs from its frontier view");
        }
        Ok((view, seal))
    }

    /// `QUERY /_arkret/self/events/frontier` — the
    /// `(realm_id, actor_id)` frontier used for Event authoring.
    pub async fn events_frontier_actor(
        &self,
        actor_id: &str,
        realm_id: &str,
    ) -> anyhow::Result<arkret_sdk::RealmActorFrontierView> {
        let selector = arkret_sdk::EventsFrontierSelector::RealmActor {
            actor_id: crate::mls_api_helpers::principal_core_id(actor_id)?,
            realm_id: arkret_sdk::RealmId::new(realm_id.to_owned())?,
        };
        let state = self
            .http
            .events_frontier(&selector)
            .await
            .map_err(anyhow::Error::from)?;
        let arkret_sdk::EventsFrontierView::RealmActor(view) = state.frontier else {
            anyhow::bail!(
                "events/frontier for actor_id={actor_id}, realm_id={realm_id} did not return a realm_actor frontier"
            );
        };
        Ok(view)
    }

    /// `QUERY /_arkret/self/events/describe` — spec binds the response to the
    /// canonical `ServiceDescribe` shape (OpenAPI `ak.self.events.read.describe`).
    /// YOU-01-016: the former soland-private `SolandEventsDescribeResBody`
    /// mirror (with its non-spec `capabilities` blob) was removed.
    pub async fn events_describe(&self) -> anyhow::Result<arkret_sdk::ServiceDescribe> {
        self.http
            .events_describe()
            .await
            .map_err(|error| anyhow::anyhow!("events describe: {error}"))
    }

    pub(crate) fn event_proof_context(
        &self,
        digest_suite: arkret_sdk::DigestSuite,
    ) -> crate::event_signer::EventProofContext {
        // Durable Event envelopes are portable Realm facts. Binding their
        // proof to the authoring Principal Server would make the original
        // signature unverifiable after federation to another Realm host.
        crate::event_signer::EventProofContext::new().with_digest_suite(digest_suite)
    }

    fn trusted_digest_suite_for_intent(
        &self,
        intent: &EventIntent,
        explicit_prejoin_suite: Option<arkret_sdk::DigestSuite>,
        state_store: Option<&crate::runtime::input::StateStoreHandle>,
    ) -> anyhow::Result<arkret_sdk::DigestSuite> {
        let digest_suite = if intent.kind() == &arkret_sdk::EventKind::RealmCreate {
            serde_json::from_value::<arkret_sdk::RealmCreatePayload>(serde_json::to_value(
                intent.payload(),
            )?)
            .map_err(|error| anyhow::anyhow!("decode Realm genesis digest suite: {error}"))?
            .object
            .digest_algorithm
        } else if let Some(digest_suite) = explicit_prejoin_suite {
            digest_suite
        } else {
            let realm_id = intent.realm_id_opt().ok_or_else(|| {
                anyhow::anyhow!(
                    "{} needs a verified Realm digest suite but carries no Realm scope",
                    intent.kind().as_str()
                )
            })?;
            let state_store = state_store.or(self.state_store.as_ref()).ok_or_else(|| {
                anyhow::anyhow!(
                    "{} authoring requires the durable verified Realm governance checkpoint",
                    intent.kind().as_str()
                )
            })?;
            let checkpoint = state_store
                .read(|store| store.trusted_mls_governance_checkpoint(realm_id.as_str()))
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "Realm {} has no durable verified governance checkpoint",
                        realm_id
                    )
                })?;
            checkpoint.validate_checkpoint().map_err(|error| {
                anyhow::anyhow!("invalid trusted governance checkpoint: {error}")
            })?;
            if checkpoint.realm_id != *realm_id {
                anyhow::bail!("trusted governance checkpoint belongs to another Realm");
            }
            checkpoint.live_digest_suite
        };
        Ok(digest_suite)
    }

    async fn post_persisted_signed_sdk_event(
        &self,
        signed: &arkret_sdk::AuthoredEvent,
        idempotency_key: &str,
        canonical_body_bytes: &[u8],
    ) -> anyhow::Result<SubmitEventResult> {
        validate_signed_sdk_event_for_submit(signed.event(), signed.digest_suite())?;
        if arkret_sdk::canonical::canonical_json_bytes(signed)? != canonical_body_bytes {
            anyhow::bail!("persisted signed Event bytes do not match the queued Event");
        }
        // What is persisted is the signed Event, which is what the receiver
        // dedupes on. The publication wrapper is rebuilt on every attempt: the
        // lease is not part of the Event and it can expire while the write is
        // queued, and an Event first published after its lease expired is
        // permanently rejected (`offline-publication.md` §2). Replaying a
        // stale wrapper would hide that from the user instead of prompting a
        // re-authorization.
        let submission = crate::authorization_lease::standard_initial_submission(
            &self.http,
            signed,
            signed.digest_suite(),
        )
        .await?;
        let response: arkret_sdk::EventsSubmitOutcome = self
            .http
            .post_with_options(
                "/_arkret/self/events",
                &submission,
                &arkret_sdk::http_client::ClientRequestOptions::new()
                    .request_id(idempotency_key)
                    .idempotency_key(idempotency_key),
            )
            .await
            .map_err(|error| {
                tracing::warn!(
                    event_id = %signed.event_id,
                    error = %error,
                    "events.submit POST rejected by server"
                );
                anyhow::Error::from(error)
            })?;
        tracing::warn!(
            event_id = %signed.event_id,
            status = ?response.status,
            accepted = response.accepted.len(),
            rejected = response.rejected.len(),
            quarantine = response.quarantine.len(),
            "events.submit response received"
        );
        ensure_events_submit_accepted(&response)?;
        Ok(SubmitEventResult::from(response))
    }

    /// Submit one user write, authoring and signing it inside the durable
    /// queue rather than at the call site.
    pub(crate) async fn submit_sdk_event(
        &self,
        operation: &LocalOperation,
    ) -> anyhow::Result<SubmitEventResult> {
        self.submit_sdk_event_queued(operation, None, None, None, None)
            .await
    }

    /// Submit a pre-join Event using the profile bound into the resolved join
    /// candidate. The invitee cannot read membership-gated Realm history.
    pub(crate) async fn submit_sdk_event_via_join_candidate(
        &self,
        operation: &LocalOperation,
        encryption_profile: &arkret_sdk::EncryptionProfile,
        digest_suite: arkret_sdk::DigestSuite,
    ) -> anyhow::Result<SubmitEventResult> {
        self.submit_sdk_event_queued(
            operation,
            None,
            None,
            Some(encryption_profile),
            Some(digest_suite),
        )
        .await
    }

    async fn submit_sdk_event_queued(
        &self,
        operation: &LocalOperation,
        post_accept: Option<PostAcceptAction>,
        state_store: Option<crate::runtime::input::StateStoreHandle>,
        join_encryption_profile: Option<&arkret_sdk::EncryptionProfile>,
        explicit_prejoin_digest_suite: Option<arkret_sdk::DigestSuite>,
    ) -> anyhow::Result<SubmitEventResult> {
        let _single_writer = outbound_submit_lock().lock().await;
        let intent = operation.intent();
        self.ensure_recovery_material_ready(intent, join_encryption_profile)
            .await?;
        // `authorization_ref` is a bound member of the semantic intent, so the
        // authority-root claim must be decided BEFORE the intent freezes. The
        // authoring-time stamp then finds the claim already present and leaves
        // it alone, which keeps every attempt's envelope equal to its intent.
        let intent = self.stamp_realm_authority_root_claim(intent.clone()).await;
        // The issuer attestation is part of the capability artifact itself,
        // hence part of the immutable semantic intent.
        validate_capability_grant_payload(&intent)?;
        let local_operation_id = operation.local_operation_id().to_string();
        tracing::warn!(
            local_operation_id = %local_operation_id,
            kind = %intent.kind().as_str(),
            realm = ?intent.realm_id_opt().map(arkret_sdk::RealmId::as_str),
            authorization_ref = ?intent.authorization_ref(),
            "submit intent frozen; enqueueing durable Event"
        );
        let authoring_generation =
            match crate::identity::authoring_generation::resolve_event_authoring_generation(
                &self.http,
                &EventAuthorityFacts::from_intent(&intent),
            )
            .await
            {
                Ok(generation) => generation,
                Err(error) if outbound_retry_delay(&error).is_some() => {
                    match crate::identity::authoring_generation::cached_event_authoring_generation(
                        &EventAuthorityFacts::from_intent(&intent),
                    )? {
                        Some(generation) => generation,
                        None => {
                            return Err(error.context(
                                "retryable authoring-generation lookup failed without a verified cache entry",
                            ));
                        }
                    }
                }
                Err(error) => return Err(error),
            };
        let digest_suite = self.trusted_digest_suite_for_intent(
            &intent,
            explicit_prejoin_digest_suite,
            state_store.as_ref(),
        )?;
        let queued_intent = if explicit_prejoin_digest_suite.is_some() {
            QueuedEventIntent::with_pinned_cba_basis(intent, digest_suite)
        } else {
            QueuedEventIntent::new(intent, digest_suite)
        };
        self.enqueue_and_drive_sdk_event(
            QueuedSdkEvent::unauthored(
                queued_intent,
                local_operation_id.clone(),
                local_operation_id,
                None,
                authoring_generation,
                post_accept,
            )?,
            state_store,
        )
        .await
    }

    /// Freezes and durably persists a fully signed scheduled message before
    /// any submission I/O. The caller must pass the authoring generation used
    /// to produce `signed_event`; resolving or editing the plan after this
    /// boundary is forbidden.
    pub(crate) async fn submit_scheduled_send_event(
        &self,
        scheduled_send_id: arkret_identifiers::ScheduledSendId,
        signed_event: arkret_sdk::AuthoredEvent,
        authoring_generation: crate::identity::authoring_generation::AuthoringGeneration,
    ) -> anyhow::Result<SubmitEventResult> {
        let _single_writer = outbound_submit_lock().lock().await;
        let queued = QueuedSdkEvent::scheduled_authored(
            scheduled_send_id,
            signed_event,
            authoring_generation,
        )?;
        self.enqueue_and_drive_sdk_event(queued, None).await
    }

    /// Persist an MLS Add commit together with the exact signed Welcome(s) and
    /// post-commit snapshot before the first network write. Garth only marks the
    /// commit item sent after the post-accept hook has delivered every Welcome
    /// and durably installed the snapshot, so a reload at any await boundary can
    /// resume the same immutable admission saga.
    pub(crate) async fn submit_mls_admission_with_snapshot(
        &self,
        commit: &crate::mls::admission::MlsAdmissionAuthoringPlan,
        welcomes: Vec<crate::mls::admission::WelcomeIntentStep>,
        realm_id: String,
        actor_id: String,
        device_id: String,
        snapshot: crate::mls::persistence::MlsSnapshotEnvelope,
        state_store: crate::runtime::input::StateStoreHandle,
    ) -> anyhow::Result<SubmitEventResult> {
        if welcomes.is_empty() {
            anyhow::bail!("MLS admission requires at least one Welcome");
        }
        let _single_writer = outbound_submit_lock().lock().await;
        let mut authored = self.author_event_unit(commit.authoring_steps()).await?;
        let authored_commit = authored
            .pop()
            .ok_or_else(|| anyhow::anyhow!("MLS admission unit produced no Commit"))?;
        if authored_commit.kind != arkret_sdk::EventKind::MlsCommit || authored.is_empty() {
            anyhow::bail!("MLS admission unit did not produce Add proposal Events then one Commit");
        }
        let intent = EventIntent::from_authored(&authored_commit);
        self.ensure_recovery_material_ready(&intent, None).await?;
        let local_operation_id = commit
            .transaction_id()
            .map_err(anyhow::Error::msg)?
            .to_owned();
        let authoring_generation =
            match crate::identity::authoring_generation::resolve_event_authoring_generation(
                &self.http,
                &EventAuthorityFacts::from_intent(&intent),
            )
            .await
            {
                Ok(generation) => generation,
                Err(error) if outbound_retry_delay(&error).is_some() => {
                    crate::identity::authoring_generation::cached_event_authoring_generation(
                        &EventAuthorityFacts::from_intent(&intent),
                    )?
                    .ok_or_else(|| {
                        error.context(
                            "retryable admission authoring-generation lookup failed without a verified cache entry",
                        )
                    })?
                }
                Err(error) => return Err(error),
            };
        // The Commit is authored here because a Welcome names it by its FINAL
        // `event_id`. Building the Welcomes from that value is what makes the
        // reference real; the old path authored both against a draft id and then
        // rewrote the Welcomes when the Commit's id moved.
        let digest_suite = authored_commit.digest_suite();
        let canonical_body_bytes = arkret_sdk::canonical::canonical_json_bytes(&authored_commit)?;
        let transport_idempotency_key = authored_commit.event_id().to_string();
        let welcome_intents = welcomes
            .into_iter()
            .map(|step| step(authored_commit.event_id()).map_err(anyhow::Error::msg))
            .collect::<anyhow::Result<Vec<_>>>()?;
        self.enqueue_and_drive_sdk_event(
            QueuedSdkEvent::authored(
                QueuedEventIntent::new(intent, digest_suite),
                authored_commit,
                local_operation_id,
                transport_idempotency_key,
                canonical_body_bytes,
                None,
                authoring_generation,
                Some(PostAcceptAction::MlsAdmission {
                    realm_id,
                    actor_id,
                    device_id,
                    proposal_events: authored,
                    stage: MlsAdmissionStage::CommitPending,
                    commit_ingress_receipts: Vec::new(),
                    commit_was_duplicate: false,
                    // Welcomes stay semantic intents until the Commit is final:
                    // an unsigned envelope with an id nobody has committed to is
                    // exactly the shape that used to need rewriting.
                    welcomes: garth::QueuedMlsWelcomes::Pending {
                        intents: welcome_intents,
                    },
                    snapshot: snapshot.into_queued(),
                }),
            )?,
            Some(state_store),
        )
        .await
    }

    async fn enqueue_and_drive_sdk_event(
        &self,
        queued: QueuedSdkEvent,
        state_store: Option<crate::runtime::input::StateStoreHandle>,
    ) -> anyhow::Result<SubmitEventResult> {
        let mut transaction_id = queued.local_operation_id.clone();
        let durable_post_accept = queued.post_accept.is_some();
        let actor_id = queued.intent.actor_id().clone();
        let realm_id = queued.intent.realm_id_opt().cloned().ok_or_else(|| {
            anyhow::anyhow!(
                "{} is a Realm genesis; it belongs in the bootstrap unit lane",
                queued.intent.kind().as_str()
            )
        })?;
        let outbound = OutboundEngine::new(crate::outbound_store::InksonOutboundStore::open(
            self.authority()?,
            outbound_store_lane(&queued.intent, durable_post_accept),
        )?);
        let existing = outbound
            .snapshot()
            .await?
            .items
            .into_iter()
            .find(|item| item.transaction_id == transaction_id);
        if let Some(existing) = existing {
            if matches!(existing.status, garth::SendQueueStatus::Sent) {
                return Ok(completed_outbound_result(&existing));
            }
            let previous = match &existing.record {
                QueuedRecord::SdkEvent(previous) => Some(previous.clone()),
                QueuedRecord::RealmBootstrap(_) => {
                    anyhow::bail!(
                        "outbound transaction {transaction_id} is already bound to a Realm bootstrap unit"
                    );
                }
            };
            if let Some(previous) = &previous {
                // Slot identity is the holder-local operation plus the frozen
                // semantic intent. There is deliberately no Event id in this
                // comparison: before authoring there is none, and inventing one
                // from an unauthored envelope is what produced two objects for
                // one create.
                let same_event_identity = previous.local_operation_id == queued.local_operation_id
                    && previous.intent_digest == queued.intent_digest;
                if !same_event_identity {
                    anyhow::bail!(
                        "outbound transaction {} is already bound to a different immutable Event intent",
                        transaction_id
                    );
                }
            }
            let same_semantic_intent = previous
                .as_ref()
                .is_some_and(|previous| previous.intent_digest == queued.intent_digest);
            match existing.status {
                garth::SendQueueStatus::Sent => {
                    return Ok(completed_outbound_result(&existing));
                }
                garth::SendQueueStatus::Cancelled | garth::SendQueueStatus::Superseded
                    if same_semantic_intent
                        && previous.as_ref().is_some_and(|previous| {
                            previous.authored_attempt.as_ref().is_some_and(|attempt| {
                                attempt.transport_idempotency_key != previous.local_operation_id
                            })
                        }) =>
                {
                    // A deterministic response can cancel an item after its
                    // immutable signed bytes are already durable. A later
                    // retry of the same semantic Event must replay those exact
                    // bytes instead of signing a different transcript under
                    // the same Event id (which the queue correctly rejects as
                    // an idempotency conflict).
                    let attempt = previous
                        .as_ref()
                        .and_then(|previous| previous.authored_attempt.as_ref())
                        .ok_or_else(|| {
                            anyhow::anyhow!(
                                "terminal outbound Event retry lost its authored attempt"
                            )
                        })?;
                    tracing::warn!(
                        local_operation_id = %queued.local_operation_id,
                        status = ?existing.status,
                        "replaying terminal outbound Event bytes for an immutable retry"
                    );
                    return self
                        .submit_sdk_event_direct(
                            &attempt.envelope,
                            &attempt.transport_idempotency_key,
                            &attempt.canonical_body_bytes,
                        )
                        .await;
                }
                garth::SendQueueStatus::Cancelled | garth::SendQueueStatus::Superseded => {
                    // The caller repaired the semantic intent after a
                    // deterministic rejection (for example, by binding the
                    // Event to the correct capability grant). Terminal queue
                    // history is safe to compact because the server did not
                    // accept that attempt; active dependencies remain
                    // protected by SendQueue::prune_terminal_before.
                    outbound
                        .compact_terminal_before(chrono::Utc::now() + chrono::Duration::seconds(1))
                        .await?;
                    let mut repaired = queued.clone();
                    repaired.authoring_idempotency_key =
                        format!("{}:repair:{}", transaction_id, uuid_v7());
                    outbound
                        .enqueue_scoped(
                            Some(transaction_id.clone()),
                            realm_id.clone(),
                            actor_id.clone(),
                            QueuedRecord::SdkEvent(Box::new(repaired)),
                            Vec::new(),
                        )
                        .await?;
                }
                _ => {
                    // Queued / Sending / Failed items already carry the
                    // authoritative signed attempt. Let the durable engine
                    // resume that item below; do not enqueue newly-authored
                    // bytes for the same transaction identity.
                }
            }
        } else {
            outbound
                .enqueue_scoped(
                    Some(transaction_id.clone()),
                    realm_id.clone(),
                    actor_id.clone(),
                    QueuedRecord::SdkEvent(Box::new(queued)),
                    Vec::new(),
                )
                .await?;
        }

        let results = OutboundAttemptResults::default();
        let submitter = EventOutboundSubmitter {
            owner: self,
            results: &results,
            state_store: state_store.clone(),
        };
        let hook = InksonPostAcceptHook;
        loop {
            let fence = match self.resolve_queue_generation_fence(&outbound).await {
                Ok(fence) => fence,
                Err(error) if outbound_retry_delay(&error).is_some() => {
                    tracing::warn!(
                        %transaction_id,
                        error = %format!("{error:#}"),
                        "durable Event generation fence refresh failed; keeping Event queued"
                    );
                    return Err(DurablyQueuedError {
                        operation_id: transaction_id,
                    }
                    .into());
                }
                Err(error) => return Err(error),
            };
            match outbound
                .submit_next_with_fence_and_hook(&submitter, &fence, &hook, chrono::Utc::now())
                .await?
            {
                OutboundEngineOutcome::Accepted(item) | OutboundEngineOutcome::Duplicate(item)
                    if item.transaction_id == transaction_id =>
                {
                    if let Some(result) = results
                        .accepted
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner())
                        .remove(&transaction_id)
                    {
                        return Ok(result);
                    }
                    return Ok(completed_outbound_result(&item));
                }
                OutboundEngineOutcome::Accepted(_) | OutboundEngineOutcome::Duplicate(_) => {}
                OutboundEngineOutcome::Prepared(_) => continue,
                OutboundEngineOutcome::Superseded {
                    previous,
                    replacement,
                } if previous.transaction_id == transaction_id => {
                    tracing::info!(
                        previous_event_id = %previous.transaction_id,
                        replacement_event_id = %replacement.transaction_id,
                        local_operation_id = %replacement.local_operation_id,
                        "explicit actor CAS superseded an unaccepted immutable Event attempt"
                    );
                    transaction_id = replacement.transaction_id;
                }
                OutboundEngineOutcome::Superseded { .. } => {}
                OutboundEngineOutcome::RetryAt { item, at }
                    if item.transaction_id == transaction_id =>
                {
                    tracing::debug!(%transaction_id, %at, "event remains in durable outbound queue");
                    return Err(DurablyQueuedError {
                        operation_id: transaction_id,
                    }
                    .into());
                }
                OutboundEngineOutcome::RetryAt { .. } => {}
                OutboundEngineOutcome::Rejected { item, .. }
                | OutboundEngineOutcome::Terminal { item, .. }
                    if item.transaction_id == transaction_id =>
                {
                    if let Some(error) = results
                        .rejected
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner())
                        .remove(&transaction_id)
                    {
                        return Err(error);
                    }
                    anyhow::bail!("queued operation {transaction_id} reached a terminal state");
                }
                OutboundEngineOutcome::Rejected { .. } | OutboundEngineOutcome::Terminal { .. } => {
                }
                OutboundEngineOutcome::Quarantined { item, reason }
                    if item.transaction_id == transaction_id =>
                {
                    anyhow::bail!(
                        "queued operation {transaction_id} quarantined by authoring-generation fence: {reason}"
                    );
                }
                OutboundEngineOutcome::Quarantined { .. } => {}
                OutboundEngineOutcome::Idle => {
                    let snapshot = outbound.snapshot().await?;
                    if let Some(item) = snapshot
                        .items
                        .iter()
                        .find(|item| item.transaction_id == transaction_id)
                        && item.remote_event_id.is_some()
                    {
                        return Ok(completed_outbound_result(item));
                    }
                    return Err(DurablyQueuedError {
                        operation_id: transaction_id,
                    }
                    .into());
                }
            }
        }
    }

    async fn submit_sdk_event_direct(
        &self,
        event: &arkret_sdk::AuthoredEvent,
        idempotency_key: &str,
        canonical_body_bytes: &[u8],
    ) -> anyhow::Result<SubmitEventResult> {
        self.post_persisted_signed_sdk_event(event, idempotency_key, canonical_body_bytes)
            .await
    }

    /// Re-author the same operation against the refreshed actor frontier.
    ///
    /// A re-author legitimately changes the envelope (`actor_seq`, `prev_refs`,
    /// `hlc`), so the derived identity changes with it — that is what makes it a
    /// distinct Event rather than a byte-identical resubmit. The holder-local
    /// operation identity does NOT change: this is one user operation trying
    /// again, and receipt, backfill and the optimistic row must keep seeing it
    /// that way.
    async fn reauthor_after_explicit_cas(
        &self,
        previous: &QueuedSdkEvent,
    ) -> anyhow::Result<QueuedSdkEvent> {
        let previous_event_id = previous
            .authored_attempt
            .as_ref()
            .map(|attempt| attempt.envelope.event_id().clone());
        let attempt = self
            .author_frozen_intent(&previous.intent, &previous.local_operation_id)
            .await?;
        Ok(QueuedSdkEvent::authored(
            previous.intent.clone(),
            attempt.envelope,
            previous.local_operation_id.clone(),
            attempt.transport_idempotency_key,
            attempt.canonical_body_bytes,
            previous_event_id,
            previous.authoring_generation.clone(),
            previous.post_accept.clone(),
        )?)
    }

    /// The single producer-authoring boundary.
    ///
    /// Everything the producer signs is completed on the [`EventIntent`] here;
    /// `event_id` is derived exactly once, at the end, from that finished
    /// content. Nothing before this point holds an Event identity, and nothing
    /// after it changes one: the signer only verifies.
    async fn author_intent(
        &self,
        intent: &EventIntent,
        local_operation_id: &str,
        authoring: SemanticAuthoring,
        digest_suite: arkret_sdk::DigestSuite,
    ) -> anyhow::Result<AuthoredAttempt> {
        #[cfg(all(debug_assertions, not(test)))]
        self.diagnose_exact_development_sdk_build().await?;
        self.verify_origin_principal_server(intent).await?;
        let mut intent = intent.clone();
        // The authority-root claim is a producer-signed envelope member and a
        // SEMANTIC decision: a fresh submission may resolve one, while a replay
        // of a frozen intent must reproduce that intent's choice verbatim.
        // Stamping a claim the frozen intent does not carry would make the
        // authored envelope diverge from its intent, and the queue's semantic
        // guard would (correctly) cancel the item.
        if authoring == SemanticAuthoring::Fresh {
            intent = self.stamp_realm_authority_root_claim(intent).await;
        }
        validate_capability_grant_payload(&intent)?;
        intent = self.stamp_cba_basis_for_intent(intent).await?;
        let (actor_seq, prev_refs) = self.resolve_actor_chain_basis(&intent).await?;
        intent = intent.with_prev_refs(prev_refs);
        let hlc = self.issue_intent_hlc(&intent).await?;
        let proof_context = self.event_proof_context(digest_suite);
        let mut event = intent
            .clone()
            .author_with_digest_suite(actor_seq, hlc, proof_context.digest_suite)
            .map_err(|error| anyhow::anyhow!("author Event: {error}"))?;
        validate_projected_cba_plane(&event)?;
        // Holder-local reconciliation only. `unsigned` is outside the digest
        // preimage, so this cannot move the identity derived above.
        event.insert_unsigned(
            crate::operation::LOCAL_OPERATION_IDEMPOTENCY_ALIAS,
            Value::String(local_operation_id.to_owned()),
        );
        self.sign_sdk_event_for_intent(&intent, &mut event, proof_context)?;
        let canonical_body_bytes = arkret_sdk::canonical::canonical_json_bytes(&event)?;
        Ok(AuthoredAttempt {
            // Per-attempt transport identity. A byte-identical retry authors the
            // same content and therefore reuses this key, which is exactly
            // idempotent-resubmit; a CAS re-author changes the content and gets
            // a new one. The holder-local operation id, which joins the receipt
            // back to its optimistic row, deliberately does NOT move.
            transport_idempotency_key: event.event_id().to_string(),
            envelope: event,
            canonical_body_bytes,
        })
    }

    fn sign_sdk_event_for_intent(
        &self,
        intent: &EventIntent,
        event: &mut arkret_sdk::AuthoredEvent,
        proof_context: crate::event_signer::EventProofContext,
    ) -> anyhow::Result<()> {
        let minimal_metadata = intent.realm_id_opt().is_some_and(|realm_id| {
            self.state_store.as_ref().is_some_and(|store| {
                store.read(|state| state.realm_projection_is_minimal_metadata(realm_id.as_str()))
            })
        });
        if !minimal_metadata {
            return crate::event_signer::sign_sdk_event_with_active_context(event, proof_context)
                .map_err(|error| anyhow::anyhow!("sign SDK Event: {error}"));
        }
        let realm_id = intent
            .realm_id_opt()
            .ok_or_else(|| anyhow::anyhow!("minimal-metadata Event has no Realm scope"))?;
        let authority = self.authority.as_ref().ok_or_else(|| {
            anyhow::anyhow!("minimal-metadata Event has no captured account authority")
        })?;
        let active = crate::event_signer::active_signer()
            .ok_or_else(|| anyhow::anyhow!("active endpoint signer is unavailable"))?;
        let device_id = arkret_sdk::DeviceId::new(
            active
                .device_id()
                .ok_or_else(|| anyhow::anyhow!("active endpoint signer has no device id"))?
                .to_owned(),
        )?;
        let material = crate::mls::pairwise_identity::derive_pairwise_signing_material(
            authority, &device_id, realm_id,
        )
        .map_err(anyhow::Error::msg)?;
        if intent.actor_id() != &material.actor_id {
            return Err(anyhow::anyhow!(
                "minimal-metadata queued intent actor does not equal the Realm pairwise actor"
            ));
        }
        material
            .signer
            .sign_sdk_event_with_context(event, proof_context)
            .map_err(|error| anyhow::anyhow!("sign minimal-metadata SDK Event: {error}"))
    }

    /// Author and sign one write for a protocol endpoint that carries the Event
    /// in its own request body rather than going through the durable submit
    /// queue (`account.update_profile`, `moderation.report`,
    /// `recovery-policy.publish`).
    pub(crate) async fn author_for_direct_submission(
        &self,
        operation: &LocalOperation,
    ) -> anyhow::Result<arkret_sdk::AuthoredEvent> {
        let digest_suite = self.trusted_digest_suite_for_intent(
            operation.intent(),
            None,
            self.state_store.as_ref(),
        )?;
        Ok(self
            .author_intent(
                operation.intent(),
                operation.local_operation_id().as_str(),
                SemanticAuthoring::Fresh,
                digest_suite,
            )
            .await?
            .envelope)
    }

    /// [`Self::author_intent`] for a frozen durable-queue intent.
    pub(crate) async fn author_frozen_intent(
        &self,
        intent: &QueuedEventIntent,
        local_operation_id: &str,
    ) -> anyhow::Result<AuthoredAttempt> {
        self.author_intent(
            &intent.intent,
            local_operation_id,
            SemanticAuthoring::FrozenIntent,
            intent.digest_suite,
        )
        .await
    }

    /// Resolve the CBA basis this attempt authors against.
    ///
    /// A basis the producer already pinned on the intent is left alone: a
    /// pre-join `ak.invite.accept` carries the only Seal view its author could
    /// read, and re-resolving it would need membership the invitee lacks.
    async fn stamp_cba_basis_for_intent(&self, intent: EventIntent) -> anyhow::Result<EventIntent> {
        if intent.seal_ref().is_some()
            || intent.auth_context().is_some()
            || intent.seal_basis().is_some()
            || cba_exempt_reducer_kind(intent.kind())
        {
            return Ok(intent);
        }
        cba_effect_plane_for_intent(intent.kind())?;
        if !intent.kind().is_control_plane() && !intent.kind().is_data_plane() {
            return Ok(intent);
        }
        let realm_id = intent.realm_id_opt().cloned().ok_or_else(|| {
            anyhow::anyhow!(
                "{} needs a CBA basis but carries no Realm scope",
                intent.kind().as_str()
            )
        })?;
        let intent = if intent.kind().is_control_plane() {
            let seal_view = self
                .events_frontier_realm_seal_view(realm_id.as_str())
                .await?;
            intent.with_seal_basis(seal_view.seal_basis())
        } else {
            if !intent.preconditions().is_empty() {
                anyhow::bail!(
                    "DataEvent {} carries preconditions; CBA DataEvents must use seal_ref + auth_context only",
                    intent.kind().as_str()
                );
            }
            let seal = self.current_seal_for(realm_id.as_str()).await?;
            let auth_context = data_event_auth_context(&intent)?;
            intent
                .with_seal_ref(
                    arkret_sdk::SealId::new(seal)
                        .map_err(|err| anyhow::anyhow!("current seal id is invalid: {err}"))?,
                )
                .with_auth_context(auth_context)
        };
        tracing::warn!(
            kind = %intent.kind().as_str(),
            seal_ref = ?intent.seal_ref().map(arkret_sdk::SealId::as_str),
            has_seal_basis = intent.seal_basis().is_some(),
            authorization_ref = ?intent.authorization_ref(),
            "authored CBA basis for submit attempt"
        );
        Ok(intent)
    }

    /// Stamp the registered authority-root claim on an Event the Realm's root
    /// controller authors directly.
    ///
    /// Best-effort by design: a resolution failure leaves the Event unstamped,
    /// so a member's ordinary grant path is never blocked by a transient
    /// lookup error, and a wrongly-claimed root can only fail closed at
    /// admission (`realm_authority_controller_mismatch`), never widen.
    async fn stamp_realm_authority_root_claim(&self, intent: EventIntent) -> EventIntent {
        if intent.authorization_ref().is_some()
            || intent.executed_by().is_some()
            || intent.applet_id().is_some()
            || !realm_owner_covers_event_kind(intent.kind().as_str())
        {
            return intent;
        }
        let Some(realm_id) = intent.realm_id_opt().cloned() else {
            return intent;
        };
        let authority = match self.realm_create_authority(realm_id.as_str()).await {
            Ok(authority) => authority,
            Err(error) => {
                tracing::warn!(
                    realm = %realm_id,
                    kind = %intent.kind().as_str(),
                    error = %error,
                    "realm authority-root lookup failed; submitting without a root claim",
                );
                None
            }
        };
        // WARN so the wasm console shows it: the browser tracing layer caps at
        // WARN (`main.rs` `set_max_level`), and this decision is the first
        // thing to check whenever an owner write is rejected. The negative is
        // debug-only — it fires on every member-authored event.
        if let Some(reference) = realm_authority_root_claim(&intent, authority.as_ref()) {
            tracing::warn!(
                realm = %realm_id,
                kind = %intent.kind().as_str(),
                "stamped realm authority-root claim on owner-authored event",
            );
            intent.with_authorization_ref(reference)
        } else {
            tracing::debug!(
                realm = %realm_id,
                kind = %intent.kind().as_str(),
                resolved = authority.is_some(),
                "no realm authority-root claim for this event; ordinary grant path",
            );
            intent
        }
    }

    /// The Realm's create-locked authority facts, resolved from the head of
    /// the ascending accepted log and cached for the process lifetime.
    async fn realm_create_authority(
        &self,
        realm_id: &str,
    ) -> anyhow::Result<Option<RealmCreateAuthority>> {
        if let Some(cached) = realm_create_authority_cache()
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(realm_id)
        {
            return Ok(Some(cached.clone()));
        }
        let outcome = self
            .http
            .events_read_outcome(
                realm_id,
                None,
                None,
                None,
                Some(REALM_CREATE_AUTHORITY_QUERY_LIMIT),
                None,
            )
            .await
            .map_err(anyhow::Error::from)?;
        let complete_events = crate::models::require_complete_event_rows(
            &outcome.events,
            "Realm create authority resolution",
        )?;
        let resolved = realm_create_authority_from_events(&complete_events, realm_id);
        if let Some(authority) = &resolved {
            realm_create_authority_cache()
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .insert(realm_id.to_owned(), authority.clone());
        }
        // Absence is not cached: the Realm may simply not be queryable yet
        // (sealed moments ago), and a compacted log may start past genesis
        // (`snapshot_bootstrap`) — the claim is skipped rather than guessed
        // until snapshot state is wired as a second source.
        Ok(resolved)
    }

    /// The actor-chain position this attempt authors at.
    async fn resolve_actor_chain_basis(
        &self,
        intent: &EventIntent,
    ) -> anyhow::Result<(u64, Vec<arkret_sdk::EventId>)> {
        // A Realm genesis creates its own `(realm_id, actor_id)` chain. The
        // Realm does not exist yet, so a remote frontier lookup cannot
        // distinguish genesis from an invisible Realm and MUST NOT be used.
        //
        // The pre-join `ak.invite.accept` case is the same shape for a
        // different reason: a pre-join principal cannot query the
        // membership-gated actor frontier, and v1 defines the first chain
        // position as seq=0 with no predecessors. The receiver still rejects an
        // incorrect claim if an accepted pre-join chain already exists.
        let Some(realm_id) = intent.realm_id_opt() else {
            return Ok((0, Vec::new()));
        };
        if intent.kind() == &arkret_sdk::EventKind::InviteAccept && intent.seal_basis().is_some() {
            return Ok((0, Vec::new()));
        }
        let actor_id = intent.actor_id().as_str().to_owned();
        match self
            .events_frontier_actor(&actor_id, realm_id.as_str())
            .await
        {
            Ok(frontier) => actor_chain_basis_from_frontier(realm_id, &actor_id, frontier),
            Err(error) => Err(actor_frontier_refresh_error(&actor_id, error)),
        }
    }

    async fn issue_intent_hlc(&self, intent: &EventIntent) -> anyhow::Result<arkret_sdk::Hlc> {
        Ok(
            crate::signing_stamp::issue_event_stamp_for(intent.actor_id(), intent.realm_id_opt())
                .await?
                .hlc,
        )
    }

    /// `ak.self.events.command.submit` in batch form over typed envelopes. Spec binds
    /// events.submit to `POST /_arkret/self/events` and distinguishes the three
    /// accepted body shapes (single envelope,
    /// [`arkret_sdk::EventsSubmitBatchRequestBody`],
    /// [`arkret_sdk::EventsSubmitFederationRequestBody`]) by JSON shape, not
    /// by URL suffix. The federation shape is S2S only and inkson MUST
    /// NEVER serialise it.
    ///
    /// SDK Events MUST already be signed by the caller (typically via
    /// `event_signer::sign_sdk_event_with_active_context`) — the batch path
    /// does not auto-sign because callers commonly need an atomic seal_ref +
    /// sign sequence the per-event helper cannot replicate.
    pub(crate) async fn submit_signed_sdk_events_batch(
        &self,
        sdk_events: &[arkret_sdk::AuthoredEvent],
        idempotency_key: Option<&str>,
    ) -> anyhow::Result<arkret_sdk::EventsSubmitOutcome> {
        let first_event = sdk_events
            .first()
            .ok_or_else(|| anyhow::anyhow!("events.submit batch must not be empty"))?;
        self.ensure_recovery_material_ready(&EventIntent::from_authored(first_event), None)
            .await?;
        // YOU-01-016: the former `capabilities.batch_submit` probe (a
        // non-spec soland capability field) was removed. The batch request
        // body is one of the three spec-defined `ak.self.events.command.submit`
        // shapes (distinguished by JSON shape), so it is sent
        // unconditionally — no capability negotiation exists in the spec.
        for sdk_event in sdk_events {
            validate_signed_sdk_event_for_submit(sdk_event.event(), sdk_event.digest_suite())?;
        }
        // `idempotency_key` is not a body field in v1: it travels only in the
        // `Idempotency-Key` header.
        let anchor_unit = first_event.kind == arkret_sdk::EventKind::RealmCreate;
        let mut submissions = Vec::with_capacity(sdk_events.len());
        for event in sdk_events {
            let submission = if uses_bare_online_anchor_submission(anchor_unit, event) {
                let submission = arkret_wire::EventInitialSubmission::online(event.event().clone());
                submission
                    .validate_structural_in_context(
                        arkret_wire::EventSubmitContext::AnchorUnit,
                        event.digest_suite(),
                    )
                    .map_err(anyhow::Error::from)?;
                submission
            } else {
                crate::authorization_lease::standard_initial_submission(
                    &self.http,
                    event,
                    event.digest_suite(),
                )
                .await?
            };
            submissions.push(submission);
        }
        let body = arkret_wire::EventsSubmitBatchRequestBody {
            events: submissions,
        };
        let idem = idempotency_key
            .map(ToOwned::to_owned)
            .unwrap_or_else(uuid_v7);
        let response: arkret_sdk::EventsSubmitOutcome = self
            .http
            .post_with_options(
                "/_arkret/self/events",
                &body,
                &arkret_sdk::http_client::ClientRequestOptions::new()
                    .request_id(idem.clone())
                    .idempotency_key(idem),
            )
            .await
            .map_err(anyhow::Error::from)?;
        ensure_events_submit_accepted(&response)?;
        Ok(response)
    }

    pub(crate) async fn submit_sdk_events_batch(
        &self,
        _realm_id: &str,
        intents: Vec<EventIntent>,
        idempotency_key: Option<&str>,
    ) -> anyhow::Result<arkret_sdk::EventsSubmitOutcome> {
        if intents
            .first()
            .is_some_and(|intent| intent.kind() == &arkret_sdk::EventKind::RealmCreate)
            && intents
                .get(1)
                .is_some_and(|intent| intent.kind() == &arkret_sdk::EventKind::CapabilityGrant)
        {
            crate::identity::authoring_generation::resolve_event_authoring_generation(
                &self.http,
                &EventAuthorityFacts::from_intent(&intents[0]),
            )
            .await?;
        }
        let events = self.author_independent_events(intents).await?;
        self.submit_signed_sdk_events_batch(&events, idempotency_key)
            .await
    }

    /// Author an atomic unit of writes in dependency order.
    ///
    /// A unit's later members name earlier members by their FINAL `event_id` —
    /// a Realm genesis follow-up is scoped to the Realm the create Event
    /// derives, a PCR device-authorize descends from the create — so the unit
    /// arrives as a chain of steps rather than a finished list. Step `n`
    /// receives everything steps `0..n` authored, which is what makes the
    /// forward references real instead of placeholders that a later pass has to
    /// rewrite.
    pub(crate) async fn author_event_unit(
        &self,
        steps: Vec<EventUnitStep>,
    ) -> anyhow::Result<Vec<arkret_sdk::AuthoredEvent>> {
        #[cfg(all(debug_assertions, not(test)))]
        self.diagnose_exact_development_sdk_build().await?;
        let mut authored: Vec<arkret_sdk::AuthoredEvent> = Vec::with_capacity(steps.len());
        let mut chain = UnitAuthoringChain::default();
        for step in steps {
            for mut intent in step(&authored)? {
                self.verify_origin_principal_server(&intent).await?;
                validate_capability_grant_payload(&intent)?;
                chain.observe(&intent, authored.is_empty())?;
                let (actor_seq, prev_refs) = match chain.basis_within_unit(&intent)? {
                    Some(basis) => basis,
                    None => self.resolve_actor_chain_basis(&intent).await?,
                };
                if !chain.is_genesis_unit() {
                    intent = self.stamp_cba_basis_for_intent(intent).await?;
                }
                intent = intent.with_prev_refs(prev_refs);
                let hlc = self.issue_intent_hlc(&intent).await?;
                let proof_context = match (
                    intent.kind() == &arkret_sdk::EventKind::RealmCreate,
                    chain.genesis_digest_suite(),
                ) {
                    // The Realm create Event is the SHA-256 bootstrap identity.
                    // Other founding Events use the live suite declared by its
                    // payload before the first Seal exists.
                    (true, Some(_)) => self.event_proof_context(arkret_sdk::DigestSuite::Sha256),
                    (false, Some(digest_suite)) => self.event_proof_context(digest_suite),
                    (_, None) => {
                        let digest_suite = self.trusted_digest_suite_for_intent(
                            &intent,
                            None,
                            self.state_store.as_ref(),
                        )?;
                        self.event_proof_context(digest_suite)
                    }
                };
                let mut event = intent
                    .clone()
                    .author_with_digest_suite(actor_seq, hlc, proof_context.digest_suite)
                    .map_err(|error| anyhow::anyhow!("author unit Event: {error}"))?;
                if !chain.is_genesis_unit() {
                    validate_projected_cba_plane(&event)?;
                }
                self.sign_sdk_event_for_intent(&intent, &mut event, proof_context)?;
                chain.record(&event);
                authored.push(event);
            }
        }
        self.validate_authored_unit_shape(&authored)?;
        Ok(authored)
    }

    /// Author an independent batch: every member stands alone, so no member
    /// names another and the order only fixes the actor-chain positions.
    pub(crate) async fn author_independent_events(
        &self,
        intents: Vec<EventIntent>,
    ) -> anyhow::Result<Vec<arkret_sdk::AuthoredEvent>> {
        self.author_event_unit(vec![Box::new(move |_| Ok(intents))])
            .await
    }

    /// Re-run the cross-Event unit shapes on the authored result.
    ///
    /// These validators exist because a unit is admitted atomically: they check
    /// the relationships between members, which only hold once every member
    /// carries its final identity.
    fn validate_authored_unit_shape(
        &self,
        authored: &[arkret_sdk::AuthoredEvent],
    ) -> anyhow::Result<()> {
        if authored
            .first()
            .is_none_or(|event| event.kind != arkret_sdk::EventKind::RealmCreate)
        {
            return Ok(());
        }
        let events = authored
            .iter()
            .map(arkret_sdk::AuthoredEvent::event)
            .cloned()
            .collect::<Vec<_>>();
        let refs = events.iter().collect::<Vec<_>>();
        if events.len() == 2 && events[1].kind == arkret_sdk::EventKind::DeviceAuthorize {
            return arkret_bootstrap::validate_self_principal_pcr_genesis_unit(
                &events[0],
                &events[1],
                &|event| {
                    crate::operation::cell_write_projector(event, arkret_sdk::DigestSuite::Sha256)
                },
            )
            .map(|_| ())
            .map_err(|error| anyhow::anyhow!("prepared self-principal PCR unit: {error}"));
        }
        if events.len() == 1
            && arkret_bootstrap::materialize_managed_agent_pcr_control(&events, &|event| {
                crate::operation::cell_write_projector(event, arkret_sdk::DigestSuite::Sha256)
            })
            .is_ok()
        {
            return Ok(());
        }
        if events.len() == 4
            && let Ok(exact) = <[&arkret_sdk::Event; 4]>::try_from(refs.as_slice())
            && arkret_sdk::DirectConversationFoundingPlan::from_events(exact).is_ok()
        {
            return Ok(());
        }
        arkret_policy::realm_bootstrap::validate_realm_bootstrap_unit(&events)
            .map(|_| ())
            .map_err(|error| anyhow::anyhow!(error.reason_code()))
    }

    pub(crate) async fn prepare_initial_submissions(
        &self,
        events: &[arkret_sdk::AuthoredEvent],
    ) -> anyhow::Result<Vec<arkret_wire::EventInitialSubmission>> {
        let mut submissions = Vec::with_capacity(events.len());
        for event in events {
            submissions.push(
                crate::authorization_lease::standard_initial_submission(
                    &self.http,
                    event,
                    event.digest_suite(),
                )
                .await?,
            );
        }
        Ok(submissions)
    }

    /// `POST /_arkret/self/signal` — `ak.self.signal.command.send`.
    ///
    /// The Signal Extension rail is encrypted-only: the exact signal kind and
    /// target live inside `encrypted_payload` and are never on the outer
    /// header, so this method can only re-check the structural envelope. The
    /// plaintext ephemeral rail (`POST /_arkret/self/ephemeral`) does not exist
    /// in v1 and a Signal MUST NOT travel via `ak.self.events.command.submit`.
    pub async fn submit_signal_envelope(
        &self,
        envelope: &arkret_wire::SignalEnvelope,
    ) -> anyhow::Result<arkret_sdk::SignalSubmitOutcome> {
        // Defensive re-validation. The builder already enforced this, but a
        // caller could mutate a raw envelope in place between build and submit.
        // `validate_structural` carries the per-class TTL ceilings
        // (setup 120s / moderation 60s / session 30s) and the AAD binding.
        envelope
            .validate_structural()
            .map_err(|error| anyhow::anyhow!("signal submit rejected locally: {error}"))?;
        self.http
            .signal_send(envelope)
            .await
            .map_err(anyhow::Error::from)
    }

    /// `POST /_arkret/gate/account/agent-key-pair` —
    /// `ak.gate.account.command.pair_agent_key`. The runtime generated the
    /// key and PoP; the controller signs `authorize_event` locally before this
    /// method submits the pairing request.
    pub(crate) async fn agent_key_pair(
        &self,
        body: &arkret_models_collaboration::agent_operations::AgentKeyPairRequestBody,
    ) -> anyhow::Result<arkret_models_collaboration::agent_operations::AgentKeyPairOutcome> {
        let principal_server_url = self.http.base_url().as_str();
        let authority =
            crate::identity::account_auth::AuthorityResolver::discover(principal_server_url)
                .await?;
        let gate_account_base = url::Url::parse(&authority.gate_account_base)?;
        let authority_origin = gate_account_base.origin().ascii_serialization();
        let authority_http = account_authority_http_client(&authority_origin)?;
        authority_http
            .agent_key_pair(body)
            .await
            .map_err(anyhow::Error::from)
    }
}

fn account_authority_http_client(
    authority_origin: &str,
) -> anyhow::Result<arkret_sdk::http_client::Client> {
    let base_url = url::Url::parse(authority_origin)?;
    arkret_sdk::http_client::ClientBuilder::new(base_url)
        // Account enrollment and refresh already use the same exception. It
        // is restricted by the SDK to loopback hosts, so production HTTP
        // origins remain rejected while the joint local stack can complete
        // the controller-approved Agent runtime pairing flow.
        .allow_insecure_localhost()
        .build()
        .map_err(anyhow::Error::from)
}

/// Validate the inner capability artifact before the outer Event is signed.
/// The Event envelope proof is the sole durable issuer signature; nested grant
/// proofs are intentionally absent from the v1 wire shape.
/// The issuer attestation lives inside the capability artifact, so it is part
/// of the immutable semantic intent rather than something an attempt adds.
/// v1 carries no second durable proof on the grant body, so this reduces to
/// proving the artifact names the Event's own actor as issuer.
pub(crate) fn validate_capability_grant_payload(intent: &EventIntent) -> anyhow::Result<()> {
    if intent.kind() != &arkret_sdk::EventKind::CapabilityGrant {
        return Ok(());
    }
    let payload: arkret_sdk::CapabilityGrantPayload = serde_json::from_value(
        serde_json::to_value(intent.payload())
            .map_err(|error| anyhow::anyhow!("encode capability grant payload: {error}"))?,
    )
    .map_err(|error| anyhow::anyhow!("decode capability grant payload: {error}"))?;
    if &payload.grant.issuer != intent.actor_id() {
        anyhow::bail!("capability grant issuer must equal the Event actor");
    }
    Ok(())
}

fn validate_signed_sdk_event_for_submit(
    event: &arkret_sdk::Event,
    digest_suite: arkret_sdk::DigestSuite,
) -> anyhow::Result<()> {
    let [arkret_sdk::EventProof::Producer(_)] = event.proofs.as_slice() else {
        anyhow::bail!(
            "submit requires exactly one producer proof and forbids caller-supplied admission proofs (event_id={}, kind={})",
            event.event_id,
            event.kind.as_str()
        );
    };
    event
        .validate_proof_bindings_with_digest_suite(digest_suite)
        .map_err(|err| {
            anyhow::anyhow!("event proof binding invalid for {}: {err}", event.event_id)
        })?;
    validate_outgoing_registered_event_payload(event.kind.as_str(), &event.payload)
}

fn mls_genesis_event_id_from_events(
    outcome: &arkret_sdk::EventsQueryOutcome,
    realm_id: &str,
) -> anyhow::Result<Option<arkret_sdk::EventId>> {
    let events = crate::models::require_complete_event_rows(&outcome.events, "MLS genesis lookup")?;
    Ok(events
        .iter()
        .find(|event| {
            event.realm_id.as_str() == realm_id && event.kind == arkret_sdk::EventKind::MlsGenesis
        })
        .map(|event| event.event_id.clone()))
}

fn cba_exempt_reducer_kind(kind: &arkret_sdk::events::kinds::EventKind) -> bool {
    matches!(kind, arkret_sdk::EventKind::RealmCreate)
}

/// The actor chain a single authoring unit builds as it goes.
///
/// A unit's members share one `(realm_id, actor_id)` chain, so member `n+1` takes
/// its position from what member `n` actually authored rather than from a remote
/// frontier that cannot yet see it. Genesis is what forces this to be one type: a
/// registered genesis unit CREATES its chain, so a remote lookup cannot tell
/// genesis apart from an invisible Realm and must not be consulted at all.
#[derive(Default)]
struct UnitAuthoringChain {
    frontiers: BTreeMap<(arkret_sdk::RealmId, arkret_sdk::DidCoreId), (u64, arkret_sdk::EventId)>,
    genesis_digest_suite: Option<arkret_sdk::canonical::DigestSuite>,
}

impl UnitAuthoringChain {
    /// Take from `intent` whatever the chain has to know before it is authored.
    ///
    /// Only a unit's first member can open a Realm, so `first` is what separates
    /// this unit's genesis from an ordinary nested `ak.realm.create`.
    fn observe(&mut self, intent: &EventIntent, first: bool) -> anyhow::Result<()> {
        if !(first && intent.kind() == &arkret_sdk::EventKind::RealmCreate) {
            return Ok(());
        }
        self.genesis_digest_suite = Some(
            serde_json::from_value::<arkret_sdk::RealmCreatePayload>(serde_json::to_value(
                intent.payload(),
            )?)
            .map_err(|error| anyhow::anyhow!("decode Realm genesis digest suite: {error}"))?
            .object
            .digest_algorithm,
        );
        Ok(())
    }

    /// This unit's genesis digest suite, if it authors a Realm into existence.
    fn genesis_digest_suite(&self) -> Option<arkret_sdk::canonical::DigestSuite> {
        self.genesis_digest_suite
    }

    fn is_genesis_unit(&self) -> bool {
        self.genesis_digest_suite.is_some()
    }

    /// The chain position this unit already determines on its own, or `None` when
    /// the caller has to resolve it against the accepted actor frontier.
    fn basis_within_unit(
        &self,
        intent: &EventIntent,
    ) -> anyhow::Result<Option<(u64, Vec<arkret_sdk::EventId>)>> {
        let scope = intent
            .realm_id_opt()
            .cloned()
            .map(|realm_id| (realm_id, intent.actor_id().clone()));
        match scope.as_ref().and_then(|scope| self.frontiers.get(scope)) {
            Some((actor_seq, event_id)) => {
                let next_actor_seq = actor_seq
                    .checked_add(1)
                    .ok_or_else(|| anyhow::anyhow!("actor sequence exhausted for batch scope"))?;
                Ok(Some((next_actor_seq, vec![event_id.clone()])))
            }
            None if self.is_genesis_unit() => Ok(Some((0, Vec::new()))),
            None => Ok(None),
        }
    }

    /// Advance the chain past a member this unit just authored.
    fn record(&mut self, event: &arkret_sdk::AuthoredEvent) {
        self.frontiers.insert(
            (event.realm_id.clone(), event.actor_id.clone()),
            (event.actor_seq, event.event_id().clone()),
        );
    }
}

/// Run an authoring unit without a transport, for a unit test.
///
/// Drives the same [`UnitAuthoringChain`] production drives, so the ordering
/// contract — step `n` sees the final identities of everything steps `0..n`
/// authored, and genesis opens its own chain at `actor_seq` 0 under the suite its
/// payload declares — is exercised here rather than restated. Only the two inputs
/// a test cannot obtain are pinned: the accepted actor frontier and the durable
/// signing stamp. Test-only: nothing in production may author against a pinned
/// chain.
#[cfg(test)]
pub(crate) fn author_event_unit_for_test(
    steps: Vec<EventUnitStep>,
) -> anyhow::Result<Vec<arkret_sdk::AuthoredEvent>> {
    let mut authored: Vec<arkret_sdk::AuthoredEvent> = Vec::with_capacity(steps.len());
    let mut chain = UnitAuthoringChain::default();
    for step in steps {
        for intent in step(&authored)? {
            chain.observe(&intent, authored.is_empty())?;
            // The one position the unit cannot determine for itself is its first
            // member's, when that member continues a chain the frontier owns.
            let (actor_seq, prev_refs) =
                chain.basis_within_unit(&intent)?.unwrap_or((1, Vec::new()));
            let intent = intent.with_prev_refs(prev_refs);
            let hlc = crate::operation::test_authoring_hlc_at_seq(actor_seq);
            let event = match chain.genesis_digest_suite() {
                Some(digest_suite) => intent.author_with_digest_suite(actor_seq, hlc, digest_suite),
                None => {
                    intent.author_with_digest_suite(actor_seq, hlc, arkret_sdk::DigestSuite::Sha256)
                }
            }
            .map_err(|error| anyhow::anyhow!("author unit Event: {error}"))?;
            chain.record(&event);
            authored.push(event);
        }
    }
    Ok(authored)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn recovery_gate_cache_key_normalizes_full_and_core_principal_ids() {
        let device_id = "ak:device:01964137-0000-7000-8000-0000000000a1";
        assert_eq!(
            normalized_recovery_gate_cache_key("did:web:alice.example", device_id),
            normalized_recovery_gate_cache_key("ak:did_core:web:alice.example", device_id)
        );
    }

    fn decode_queued_sdk_event(value: Value) -> garth::Result<QueuedSdkEvent> {
        let queued: QueuedSdkEvent = serde_json::from_value(value)?;
        queued.validate()?;
        Ok(queued)
    }

    fn test_authoring_generation() -> crate::identity::authoring_generation::AuthoringGeneration {
        crate::identity::authoring_generation::AuthoringGeneration {
            authority_model:
                crate::identity::authoring_generation::AuthoringAuthorityModel::AcceptedDevice,
            authority_principal_id: "did:web:alice.example".to_owned(),
            generation_ref: "1-QmCurrent".to_owned(),
        }
    }

    fn fixture_event_id(event_id: &str) -> arkret_sdk::EventId {
        arkret_sdk::EventId::new(event_id).unwrap()
    }

    /// A locally built write, as an intent.
    ///
    /// The fixture cannot invent an `event_id`, an `actor_seq` or an HLC because
    /// an intent has nowhere to put them: they belong to authoring, which has
    /// not happened yet.
    fn sdk_intent_with_kind(realm_id: &str, kind: &str, actor_id: &str) -> EventIntent {
        let actor_id = crate::mls_api_helpers::principal_core_id(actor_id).unwrap();
        serde_json::from_value(json!({
            "kind": kind,
            "scope_ref": {"kind": "realm", "realm_id": realm_id},
            "actor_id": actor_id,
            "principal_server_id": "ak:did_core:web:principal.example",
            "created_at": "2026-05-19T00:00:00.000Z",
            "payload": {}
        }))
        .unwrap()
    }

    /// The queue slot a locally built write occupies.
    fn fixture_queued_intent(intent: EventIntent) -> QueuedEventIntent {
        QueuedEventIntent::new(intent, arkret_sdk::DigestSuite::Sha256)
    }

    #[test]
    fn account_authority_client_allows_only_insecure_loopback() {
        assert!(account_authority_http_client("http://localhost:8787").is_ok());
        assert!(account_authority_http_client("http://127.0.0.1:8787").is_ok());
        assert!(account_authority_http_client("http://accounts.example").is_err());
    }

    #[test]
    fn managed_agent_pcr_genesis_does_not_bypass_control_proposal_ack_authoring() {
        let mut managed = realm_create_sdk_event(
            "ak:event:Af2HCFbsrVezIXsZGcgB3mjkpqGK-C4DmteWaG3H0Xbh",
            "did:web:agent.example",
            None,
        );
        managed.executed_by =
            Some(arkret_sdk::DidCoreId::new("ak:did_core:web:alice.example").unwrap());
        managed.authorization_ref = Some(
            arkret_sdk::AuthorizationRef::new("did:web:agent.example#managed-controller").unwrap(),
        );

        assert!(crate::authorization_lease::is_managed_agent_pcr_genesis(
            &managed
        ));
        assert!(!uses_bare_online_anchor_submission(true, &managed));

        let ordinary = realm_create_sdk_event(
            "ak:event:Ab0jbIKlPZ-M3WbarZlCPLYtkCWggYwWZeRDlW-ShdQ9",
            "did:web:alice.example",
            None,
        );
        assert!(uses_bare_online_anchor_submission(true, &ordinary));
    }

    #[test]
    fn queued_event_rejects_pre_generation_shape() {
        let event = sdk_event_without_proof("did:web:alice.example");
        let mut encoded = serde_json::to_value(
            QueuedSdkEvent::unauthored(
                fixture_queued_intent(EventIntent::from_authored(&event)),
                "local-operation-1".to_owned(),
                "attempt-1".to_owned(),
                None,
                test_authoring_generation(),
                None,
            )
            .unwrap(),
        )
        .unwrap();
        encoded
            .as_object_mut()
            .unwrap()
            .remove("authoring_generation");
        let error = decode_queued_sdk_event(encoded).unwrap_err();
        assert!(error.to_string().contains("authoring_generation"));
    }

    #[test]
    fn scheduled_dispatch_crash_retry_preserves_exact_signed_event_bytes() {
        let event: arkret_sdk::Event = serde_json::from_value(json!({
            "event_id": "ak:event:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19",
            "kind": "ak.message.create",
            "realm_id": "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19",
            "scope_ref": {
                "kind": "realm",
                "realm_id": "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19"
            },
            "actor_id": "ak:did_core:web:alice.example",
            "principal_server_id": "ak:did_core:web:principal.example",
            "actor_seq": 7,
            "created_at": "2026-08-07T00:00:00.000Z",
            "hlc": "01986f440000-0001-a13f9c2e",
            "prev_refs": [],
            "payload": {
                "strand_id": "ak:strand:ASeIBHNVQyeIcU4aBIt2t2BF_ikuVMH0kNru_HgO_gG1",
                "track_name": "discussion",
                "content": {"kind": "ak.content.text", "body": "frozen scheduled text"}
            },
            "proofs": []
        }))
        .unwrap();
        // The scheduler stores exact authored bytes, so the fixture has to reach
        // it the way production does: finalized, then signed.
        let mut event = arkret_sdk::AuthoredEvent::finalize_with_digest_suite(
            event,
            arkret_sdk::canonical::DigestSuite::Sha256,
        )
        .unwrap();
        let signer = crate::event_signer::build_ed25519_device_signer(
            [73; 32],
            "did:web:alice.example",
            "ak:device:01904100-0000-7000-8000-000000000001",
        );
        signer
            .sign_sdk_event_with_context(
                &mut event,
                crate::event_signer::EventProofContext::default(),
            )
            .unwrap();

        let scheduled_send_id = arkret_identifiers::ScheduledSendId::new(
            "ak:scheduled_send:01904100-0000-7000-8000-000000000003".to_owned(),
        )
        .unwrap();
        let queued = QueuedSdkEvent::scheduled_authored(
            scheduled_send_id.clone(),
            event.clone(),
            test_authoring_generation(),
        )
        .unwrap();
        let frozen_bytes = queued
            .scheduled_dispatch
            .as_ref()
            .unwrap()
            .canonical_signed_event_bytes
            .clone();

        // Simulate the durable record being reopened after scheduler handoff.
        let persisted = serde_json::to_value(&queued).unwrap();
        let mut reopened = decode_queued_sdk_event(persisted).unwrap();
        assert!(reopened.mark_scheduled_submission_uncertain());

        // The Prepared outcome is persisted before HTTP. A crash with an
        // unknown submission result reopens this exact record, and a retry may
        // not transition or author it again.
        let prepared = serde_json::to_value(&reopened).unwrap();
        let mut retry = decode_queued_sdk_event(prepared).unwrap();
        assert!(!retry.mark_scheduled_submission_uncertain());
        let dispatch = retry.scheduled_dispatch.as_ref().unwrap();
        assert_eq!(dispatch.scheduled_send_id, scheduled_send_id);
        assert_eq!(&dispatch.event_id, event.event_id());
        assert_eq!(
            dispatch.message_id,
            arkret_sdk::MessageId::from_event_id(event.event_id())
        );
        assert_eq!(
            dispatch.submission_state,
            ScheduledSendSubmissionState::SubmissionUncertain
        );
        assert_eq!(dispatch.canonical_signed_event_bytes, frozen_bytes);
        assert_eq!(
            retry
                .authored_attempt
                .as_ref()
                .unwrap()
                .canonical_body_bytes,
            frozen_bytes
        );
    }

    /// Every retry re-reads the authoring position and mints a fresh transport
    /// key, so neither may move the queue slot's semantic identity.
    #[test]
    fn queued_intent_survives_a_reauthored_attempt_at_a_new_chain_position() {
        let intent = EventIntent::from_authored(&sdk_event_without_proof("did:web:alice.example"));
        let queued = fixture_queued_intent(intent.clone());

        let first = intent
            .clone()
            .author_with_digest_suite(
                1,
                crate::operation::test_authoring_hlc_at_seq(1),
                arkret_sdk::DigestSuite::Sha256,
            )
            .unwrap();
        let mut second = intent
            .with_prev_refs(vec![fixture_event_id(
                "ak:event:AXBcp13trH3bPXvj0eHppCpGqJZWL9yqE3cf2Tl43vyk",
            )])
            .author_with_digest_suite(
                42,
                crate::operation::test_authoring_hlc_at_seq(42),
                arkret_sdk::DigestSuite::Sha256,
            )
            .unwrap();
        second.insert_unsigned(
            crate::operation::LOCAL_OPERATION_IDEMPOTENCY_ALIAS,
            Value::String("attempt-two".to_owned()),
        );

        // Two attempts at one operation: different identities and transport
        // keys, one unchanged semantic key, and both still express the intent.
        assert_ne!(first.event_id(), second.event_id());
        assert!(queued.authored_envelope_matches(first.event()));
        assert!(queued.authored_envelope_matches(second.event()));
        assert_eq!(
            queued.digest().unwrap(),
            fixture_queued_intent(EventIntent::from_authored(second.event()))
                .digest()
                .unwrap()
        );
    }

    #[test]
    fn event_intent_digest_changes_with_semantic_payload() {
        let first = sdk_event_without_proof("did:web:alice.example");
        let mut second = first.clone();
        second
            .payload
            .insert("state".to_owned(), Value::String("away".to_owned()));

        let first = fixture_queued_intent(EventIntent::from_authored(&first));
        let second = fixture_queued_intent(EventIntent::from_authored(&second));
        assert_ne!(first, second);
        assert_ne!(first.digest().unwrap(), second.digest().unwrap());
    }

    /// The grant's issuer signature is the Event envelope proof: no nested grant
    /// proof exists on the wire, and validating the payload must not add one or
    /// otherwise move what the queue froze.
    #[test]
    fn capability_payload_validation_does_not_mutate_queue_intent() {
        let operation = crate::operation::ak_ops::capability_grant_actions(
            "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19",
            "did:web:alice.example",
            "did:web:bob.example",
            &["ak.message.create"],
            None,
            Value::Null,
            crate::operation::ak_ops::IssuerRootBasis::default(),
        )
        .unwrap()
        .build_sdk_event("inkson")
        .unwrap();
        let frozen = QueuedSdkEvent::unauthored(
            fixture_queued_intent(operation.intent().clone()),
            "capability-operation".to_owned(),
            "capability-attempt".to_owned(),
            None,
            test_authoring_generation(),
            None,
        )
        .unwrap();
        validate_capability_grant_payload(&frozen.intent).unwrap();
        assert_eq!(
            frozen.intent,
            fixture_queued_intent(operation.intent().clone())
        );
        assert!(frozen.intent.payload()["grant"].get("proofs").is_none());

        // A later attempt re-authors from that same frozen intent, and the
        // validator still accepts the result without having touched it.
        let attempt = crate::operation::author_intent_for_test(operation.into_intent());
        validate_capability_grant_payload(&EventIntent::from_authored(attempt.event())).unwrap();
        assert!(frozen.intent.authored_envelope_matches(attempt.event()));
        assert!(attempt.payload["grant"].get("proofs").is_none());
    }

    #[test]
    fn frontier_context_preserves_retryable_transport_error() {
        let error = actor_frontier_refresh_error(
            "did:web:alice.example",
            arkret_sdk::http_client::Error::Http("browser offline".to_owned()).into(),
        );

        assert_eq!(outbound_retry_delay(&error), Some(Duration::from_secs(1)));
        assert!(format!("{error:#}").contains("browser offline"));
    }

    #[test]
    fn wasm_string_only_transport_error_remains_retryable() {
        let error = anyhow::anyhow!(
            "resolve authoring generation: HTTP request failed: error sending request"
        );

        assert_eq!(outbound_retry_delay(&error), Some(Duration::from_secs(1)));
    }

    #[test]
    fn accepted_admission_commit_never_discards_welcome_on_protocol_rejection() {
        let error = anyhow::anyhow!("welcome rejected with deterministic policy error");

        assert_eq!(outbound_retry_delay(&error), None);
        assert_eq!(
            mls_admission_welcome_retry_delay(&error),
            Duration::from_secs(60)
        );
    }

    #[test]
    fn admission_cas_conflict_keeps_exact_saga_queued_for_repair() {
        let outcome = mls_admission_repair_retry_outcome("frontier changed");

        match outcome {
            OutboundSubmitOutcome::RetryAfter { delay, reason } => {
                assert_eq!(delay, Duration::from_secs(60));
                assert!(reason.contains("repair required"));
            }
            other => panic!("admission CAS conflict must remain retryable, got {other:?}"),
        }
    }

    #[test]
    fn pending_chat_projection_ignores_sent_items_and_other_conversations() {
        let realm = arkret_sdk::RealmId::new(
            "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19".to_owned(),
        )
        .unwrap();
        let actor = "did:web:alice.example";
        let mut queue = garth::SendQueue::new();
        let pending = sdk_event_with_kind(
            "ak:event:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19",
            realm.as_str(),
            "ak.message.create",
            actor,
        );
        let mut pending = pending;
        // A queued `ak.message.create` carries no Message id: the Message is
        // named by the create Event, which nothing has accepted yet.
        pending.payload = serde_json::from_value(json!({
            "strand_id": "ak:strand:AT3p9polsnQ_WOix32QZimMdE2zPe62HptJu2PaO3V1h"
        }))
        .unwrap();
        queue
            .enqueue(
                Some("pending-operation".to_owned()),
                realm.clone(),
                QueuedRecord::SdkEvent(Box::new(
                    QueuedSdkEvent::unauthored(
                        fixture_queued_intent(EventIntent::from_authored(&pending)),
                        "pending-operation".to_owned(),
                        "pending-attempt".to_owned(),
                        None,
                        test_authoring_generation(),
                        None,
                    )
                    .unwrap(),
                )),
                Vec::new(),
            )
            .unwrap();

        let mut other_conversation = sdk_event_with_kind(
            "ak:event:AcsFZ3o2tOdN3EFpNceeLV-aI3jZkB9S34_4YIwJ5DLy",
            realm.as_str(),
            "ak.message.create",
            actor,
        );
        other_conversation.payload = serde_json::from_value(json!({
            "strand_id": "ak:strand:AXBcp13trH3bPXvj0eHppCpGqJZWL9yqE3cf2Tl43vyk"
        }))
        .unwrap();
        queue
            .enqueue(
                Some("other-operation".to_owned()),
                realm.clone(),
                QueuedRecord::SdkEvent(Box::new(
                    QueuedSdkEvent::unauthored(
                        fixture_queued_intent(EventIntent::from_authored(&other_conversation)),
                        "other-operation".to_owned(),
                        "other-attempt".to_owned(),
                        None,
                        test_authoring_generation(),
                        None,
                    )
                    .unwrap(),
                )),
                Vec::new(),
            )
            .unwrap();

        let sent = sdk_event_with_kind(
            "ak:event:ASeIBHNVQyeIcU4aBIt2t2BF_ikuVMH0kNru_HgO_gG1",
            realm.as_str(),
            "ak.message.create",
            actor,
        );
        let sent_transaction = "sent-operation".to_owned();
        queue
            .enqueue(
                Some(sent_transaction.clone()),
                realm.clone(),
                QueuedRecord::SdkEvent(Box::new(
                    QueuedSdkEvent::unauthored(
                        fixture_queued_intent(EventIntent::from_authored(&sent)),
                        "sent-operation".to_owned(),
                        "sent-attempt".to_owned(),
                        None,
                        test_authoring_generation(),
                        None,
                    )
                    .unwrap(),
                )),
                Vec::new(),
            )
            .unwrap();
        // An acceptance now has to carry its ingress receipts: they are the
        // only evidence the Event landed inside its authorization-lease window,
        // and the queue refuses a `Sent` transition without them.
        let issued_at = chrono::Utc::now();
        let lease = crate::authorization_lease::test_support::lease(
            realm.clone(),
            actor,
            "ak.message.create",
            issued_at,
            issued_at + chrono::Duration::hours(1),
        );
        queue
            .mark_sent(
                &sent_transaction,
                arkret_sdk::EventId::new(
                    "ak:event:AXBcp13trH3bPXvj0eHppCpGqJZWL9yqE3cf2Tl43vyk".to_owned(),
                )
                .unwrap(),
                vec![crate::authorization_lease::test_support::receipt(
                    &lease,
                    issued_at + chrono::Duration::minutes(1),
                )],
            )
            .unwrap();

        // Only the still-queued send in this strand, reported by the
        // holder-local key its optimistic row also carries.
        assert_eq!(
            pending_chat_local_operation_ids_from_snapshot(
                &queue.snapshot(),
                realm.as_str(),
                "ak:strand:AT3p9polsnQ_WOix32QZimMdE2zPe62HptJu2PaO3V1h",
            ),
            std::collections::BTreeSet::from(["pending-operation".to_owned()])
        );
    }

    fn sdk_event_without_proof(actor_id: &str) -> arkret_sdk::Event {
        let actor_id = crate::mls_api_helpers::principal_core_id(actor_id).unwrap();
        serde_json::from_value(json!({
            "event_id": "ak:event:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19",
            "kind": "ak.presence",
            "realm_id": "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19",
            "scope_ref": {"kind": "realm", "realm_id": "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19"},
            "actor_id": actor_id,
            "principal_server_id": "ak:did_core:web:principal.example",
            "actor_seq": 1,
            "created_at": "2026-05-19T00:00:00.000Z",
            "hlc": "01970e589d21-0001-a13f9c2e",
            "prev_refs": [],
            "payload": {
                "actor_id": actor_id,
                "state": "online"
            },
            "proofs": []
        }))
        .unwrap()
    }

    fn sdk_event_with_kind(
        event_id: &str,
        realm_id: &str,
        kind: &str,
        actor_id: &str,
    ) -> arkret_sdk::Event {
        let actor_id = crate::mls_api_helpers::principal_core_id(actor_id).unwrap();
        serde_json::from_value(json!({
            "event_id": event_id,
            "kind": kind,
            "realm_id": realm_id,
            "scope_ref": {"kind": "realm", "realm_id": realm_id},
            "actor_id": actor_id,
            "principal_server_id": "ak:did_core:web:principal.example",
            "actor_seq": 1,
            "created_at": "2026-05-19T00:00:00.000Z",
            "hlc": "01970e589d21-0001-a13f9c2e",
            "prev_refs": [],
            "payload": {},
            "proofs": []
        }))
        .unwrap()
    }

    /// A genesis `ak.realm.create` carries no `realm_id` and no
    /// `payload.object.id`: both are derived from `event_id`, so the caller
    /// picks the Event id and reads the Realm id back off the envelope.
    fn realm_create_sdk_event(
        event_id: &str,
        created_by: &str,
        registry_digest: Option<&str>,
    ) -> arkret_sdk::Event {
        let created_by = crate::mls_api_helpers::principal_core_id(created_by).unwrap();
        let mut event: arkret_sdk::Event = serde_json::from_value(json!({
            "event_id": event_id,
            "kind": "ak.realm.create",
            "scope_ref": {"kind": "realm_genesis"},
            "actor_id": created_by,
            "principal_server_id": "ak:did_core:web:principal.example",
            "actor_seq": 1,
            "created_at": "2026-05-19T00:00:00.000Z",
            "hlc": "01970e589d21-0001-a13f9c2e",
            "prev_refs": [],
            "payload": {},
            "proofs": []
        }))
        .unwrap();
        let mut object = json!({});
        if let Some(digest) = registry_digest {
            object["capability_action_registry_digest"] = json!(digest);
        }
        event.payload.insert("object".to_owned(), object);
        event
    }

    const AUTHORITY_GENESIS_EVENT: &str = "ak:event:ASgi2U7PbVyNs4UpiQAoXKoHv84g07gpBvuddCGiMMG1";
    /// Any well-formed Realm id: used by the non-genesis events below, which
    /// still carry `realm_id` on the wire.
    const AUTHORITY_REALM: &str = "ak:realm:ATOz4l-vKJUCGZDmS_knGS9TjZ64pkOzx-HNGAgY5RGJ";
    const AUTHORITY_CONTROLLER: &str = "did:web:alice.example";
    const AUTHORITY_CONTROLLER_CORE: &str = "ak:did_core:web:alice.example";
    const AUTHORITY_DIGEST: &str =
        "sha256:0000000000000000000000000000000000000000000000000000000000000000";

    #[test]
    fn realm_create_authority_resolves_the_root_controller() {
        let events = [realm_create_sdk_event(
            AUTHORITY_GENESIS_EVENT,
            AUTHORITY_CONTROLLER,
            Some(AUTHORITY_DIGEST),
        )];
        let realm_id = events[0].realm_id.to_string();
        assert_eq!(
            realm_create_authority_from_events(&events, &realm_id),
            Some(RealmCreateAuthority::Root {
                controller_id: AUTHORITY_CONTROLLER_CORE.to_owned()
            })
        );
    }

    #[test]
    fn realm_create_without_registry_digest_has_no_authority_root() {
        // Pre-authority-root creates never carried the create-locked digest;
        // such a Realm has no root cell and must not be claimed.
        let events = [realm_create_sdk_event(
            AUTHORITY_GENESIS_EVENT,
            AUTHORITY_CONTROLLER,
            None,
        )];
        let realm_id = events[0].realm_id.to_string();
        assert_eq!(
            realm_create_authority_from_events(&events, &realm_id),
            Some(RealmCreateAuthority::NoAuthorityRoot)
        );
    }

    #[test]
    fn realm_create_authority_ignores_other_realms_and_kinds() {
        // A create for a *different* Realm: a different genesis Event id, so a
        // different derived Realm id.
        let other_realm = realm_create_sdk_event(
            "ak:event:ASyFf0qTUQ55a2qZp5fuTXRnIgf3ovKChQZ_XSkxdIPK",
            "did:web:mallory.example",
            Some(AUTHORITY_DIGEST),
        );
        let authority_realm = realm_create_sdk_event(
            AUTHORITY_GENESIS_EVENT,
            AUTHORITY_CONTROLLER,
            Some(AUTHORITY_DIGEST),
        )
        .realm_id
        .to_string();
        let other_kind = sdk_event_with_kind(
            "ak:event:AZpUEIyW7TNKR7LXG3WwW7XhlXVKyRQXiuhWXSw19pzj",
            &authority_realm,
            "ak.strand.create",
            AUTHORITY_CONTROLLER,
        );
        assert_eq!(
            realm_create_authority_from_events(&[other_realm, other_kind], &authority_realm),
            None
        );
    }

    #[test]
    fn realm_owner_coverage_gates_the_root_claim() {
        // `ak.strand.create` is in the owner aggregate's registry-derived
        // operational coverage; `ak.realm.create` is deliberately excluded
        // (creating another Realm is not a capability inside this one).
        assert!(realm_owner_covers_event_kind("ak.strand.create"));
        assert!(realm_owner_covers_event_kind("ak.space.create"));
        assert!(realm_owner_covers_event_kind("ak.mls.genesis"));
        assert!(realm_owner_covers_event_kind("ak.message.create"));
        assert!(!realm_owner_covers_event_kind("ak.realm.create"));
        assert!(!realm_owner_covers_event_kind("ak.not.a.kind"));
    }

    #[test]
    fn realm_authority_root_claim_stamps_only_the_matching_controller() {
        let root = RealmCreateAuthority::Root {
            controller_id: AUTHORITY_CONTROLLER_CORE.to_owned(),
        };
        let event = |actor: &str| sdk_intent_with_kind(AUTHORITY_REALM, "ak.strand.create", actor);

        assert_eq!(
            realm_authority_root_claim(&event(AUTHORITY_CONTROLLER), Some(&root)),
            Some(
                arkret_sdk::AuthorizationRef::new(arkret_wire::REALM_AUTHORITY_ROOT_CELL).unwrap()
            )
        );
        assert_eq!(
            realm_authority_root_claim(&event("did:web:bob.example"), Some(&root)),
            None
        );
        assert_eq!(
            realm_authority_root_claim(
                &event(AUTHORITY_CONTROLLER),
                Some(&RealmCreateAuthority::NoAuthorityRoot)
            ),
            None
        );
        assert_eq!(
            realm_authority_root_claim(&event(AUTHORITY_CONTROLLER), None),
            None
        );
    }

    #[test]
    fn realm_authority_root_claim_defers_to_producer_chosen_authorization() {
        let root = RealmCreateAuthority::Root {
            controller_id: AUTHORITY_CONTROLLER_CORE.to_owned(),
        };
        let with_grant =
            sdk_intent_with_kind(AUTHORITY_REALM, "ak.strand.create", AUTHORITY_CONTROLLER)
                .with_authorization_ref(
                    arkret_sdk::AuthorizationRef::new(
                        "ak:grant:AbrgMKK4KXMpRsGsFrsEQEsjo207metUd4zt8yjzB-UH",
                    )
                    .unwrap(),
                );
        assert_eq!(realm_authority_root_claim(&with_grant, Some(&root)), None);

        let executed_by_service =
            sdk_intent_with_kind(AUTHORITY_REALM, "ak.strand.create", AUTHORITY_CONTROLLER)
                .with_executed_by(
                    arkret_sdk::DidCoreId::new("ak:did_core:web:service.example").unwrap(),
                );
        assert_eq!(
            realm_authority_root_claim(&executed_by_service, Some(&root)),
            None
        );
    }

    fn dead_endpoint_submitter() -> EventSubmitter {
        EventSubmitter::new(
            arkret_sdk::http_client::Client::builder("http://127.0.0.1:9/".parse().unwrap())
                .allow_insecure_localhost()
                .build()
                .unwrap(),
        )
        .with_authority(test_authority())
    }

    fn test_authority() -> arkret_sdk::PrincipalAuthorityKey {
        arkret_sdk::PrincipalAuthorityKey::new(
            arkret_sdk::DidCoreId::new("ak:did_core:web:alice.example".to_owned()).unwrap(),
            arkret_sdk::DidCoreId::new("ak:did_core:web:server.example".to_owned()).unwrap(),
        )
    }

    #[tokio::test]
    async fn stamp_realm_authority_root_claim_stamps_from_cached_create_facts() {
        // Unique Realm id: the create-facts cache is process-global and tests
        // run in parallel.
        let realm = "ak:realm:AZEvldDJcWI9IRHqP2BMibDDfc59Ax_LwrbsrQmeD6Ml";
        realm_create_authority_cache()
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(
                realm.to_owned(),
                RealmCreateAuthority::Root {
                    controller_id: AUTHORITY_CONTROLLER_CORE.to_owned(),
                },
            );
        let intent = dead_endpoint_submitter()
            .stamp_realm_authority_root_claim(sdk_intent_with_kind(
                realm,
                "ak.strand.create",
                AUTHORITY_CONTROLLER,
            ))
            .await;
        assert_eq!(
            intent
                .authorization_ref()
                .map(arkret_sdk::AuthorizationRef::as_str),
            Some(arkret_wire::REALM_AUTHORITY_ROOT_CELL)
        );
    }

    /// Regression lock (2026-08-01): Events queued while the session was dead
    /// froze their intents with `authorization_ref = None` (the authority
    /// lookup 401ed). A post-re-login replay used the fresh-authoring prepare,
    /// stamped the claim onto the envelope, diverged from the frozen intent
    /// and the queue's semantic guard cancelled the item — the discussion
    /// message could never send. Frozen-intent re-authoring MUST reproduce
    /// the intent's authorization choice verbatim even when the claim is now
    /// resolvable.
    #[tokio::test]
    async fn frozen_intent_replay_must_not_upgrade_the_authorization_claim() {
        let realm = "ak:realm:Aa9ST4mV9PwPifTwudPs8hENCT9iNyCpkWSVDjEH7hJ_";
        realm_create_authority_cache()
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(
                realm.to_owned(),
                RealmCreateAuthority::Root {
                    controller_id: AUTHORITY_CONTROLLER_CORE.to_owned(),
                },
            );
        // Outage-era intent: owner-authored kind, but no claim was resolvable
        // at enqueue time.
        let frozen = sdk_intent_with_kind(realm, "ak.message.create", AUTHORITY_CONTROLLER);
        assert!(frozen.authorization_ref().is_none());

        // Fresh authoring would stamp (the claim is resolvable from cache)…
        let freshly_authored = dead_endpoint_submitter()
            .stamp_realm_authority_root_claim(frozen.clone())
            .await;
        assert!(freshly_authored.authorization_ref().is_some());

        // …but a replay of the frozen intent must reproduce its choice verbatim,
        // or the authored envelope diverges from the intent it is bound to.
        let frozen_queued = fixture_queued_intent(frozen.clone());
        let replayed = dead_endpoint_submitter()
            .author_frozen_intent(&frozen_queued, "frozen-operation")
            .await;
        // The dead endpoint fails the attempt later, at the seal fetch; what
        // this test pins down is that the claim decision was never revisited.
        assert!(replayed.is_err());
        assert!(
            fixture_queued_intent(frozen.clone())
                .authorization_ref()
                .is_none(),
            "frozen-intent replay stamped a claim the intent does not carry"
        );
    }

    #[tokio::test]
    async fn stamp_realm_authority_root_claim_swallows_lookup_failures() {
        // Unknown Realm + unreachable endpoint: the claim must be skipped, not
        // fail the submit — a member's ordinary grant path stays usable when
        // the create lookup is unavailable.
        let intent = dead_endpoint_submitter()
            .stamp_realm_authority_root_claim(sdk_intent_with_kind(
                "ak:realm:ARKSHgBichO7ZjwprTMf4UrKn7x1GHkl16zz6U4xm586",
                "ak.strand.create",
                AUTHORITY_CONTROLLER,
            ))
            .await;
        assert!(intent.authorization_ref().is_none());
    }

    #[test]
    fn stamped_intent_round_trips_through_authoring_without_semantic_drift() {
        // Reproduce the queued-submit lifecycle for a kanban card create:
        // freeze a stamped intent, author the envelope from it the way the
        // outbound drive does, and require `EventIntent` equality — the exact
        // check `decode_queued_sdk_event` enforces on the persisted attempt.
        let realm = "ak:realm:AU2D21msYuLaXwOH8_eGJzFL4TqkaJ0gxxClWY-3IywJ";
        realm_create_authority_cache()
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(
                realm.to_owned(),
                RealmCreateAuthority::Root {
                    controller_id: AUTHORITY_CONTROLLER_CORE.to_owned(),
                },
            );
        let operation = crate::operation::ak_ops::kanban_card_strand_create(
            realm,
            AUTHORITY_CONTROLLER,
            "ak:space:Aa5chVG-4dxTy5sBQLuc7faYg5r3Odrl_3Q7uLf7FY_Y",
            "ak:space:ARO6sshXyY_8aIrsd0F5-zoAcfxTRnG5n7zA6tFwGX2l",
            "probe card",
            "a0",
        )
        .unwrap()
        .build_sdk_event("inkson")
        .unwrap();

        // Mirror the enqueue-side stamp: the authority-root claim is a semantic
        // choice, so it is part of what the queue freezes.
        let intent = operation.into_intent().with_authorization_ref(
            realm_authority_root_claim(
                &sdk_intent_with_kind(realm, "ak.strand.create", AUTHORITY_CONTROLLER),
                Some(&RealmCreateAuthority::Root {
                    controller_id: AUTHORITY_CONTROLLER_CORE.to_owned(),
                }),
            )
            .expect("claim must stamp"),
        );
        let queued = QueuedSdkEvent::unauthored(
            fixture_queued_intent(intent.clone()),
            "local-op".to_owned(),
            "authoring-key".to_owned(),
            None,
            test_authoring_generation(),
            None,
        )
        .unwrap();

        // Mirror one attempt by the outbound drive: an actor-chain position, the
        // CBA basis it resolved for this attempt, and the holder-local alias.
        // None of those is part of the operation, so none may make the attempt
        // stop expressing the intent it is bound to.
        let mut authored = intent
            .with_prev_refs(vec![fixture_event_id(
                "ak:event:AdymfEYKFegRsXpyi5Or3ormR7igvbwtXIp8HyMfOvWE",
            )])
            .with_seal_ref(
                arkret_sdk::SealId::new(
                    "ak:seal:sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                        .to_owned(),
                )
                .unwrap(),
            )
            .with_auth_context(arkret_sdk::AuthContext {
                key_id: arkret_sdk::OpaqueLocalId::new("device").unwrap(),
                key_epoch: 0,
                credential_epoch: None,
            })
            .author_with_digest_suite(
                7,
                crate::operation::test_authoring_hlc_at_seq(7),
                arkret_sdk::DigestSuite::Sha256,
            )
            .unwrap();
        authored.insert_unsigned(
            crate::operation::LOCAL_OPERATION_IDEMPOTENCY_ALIAS,
            Value::String("authoring-key".to_owned()),
        );

        if !queued.intent.authored_envelope_matches(authored.event()) {
            let left = serde_json::to_value(authored.event()).unwrap();
            let right = serde_json::to_value(&queued.intent).unwrap();
            panic!(
                "authored envelope drifted from bound intent:\nauthored: {left:#}\nintent:   {right:#}"
            );
        }
    }

    #[test]
    fn queued_mls_admission_round_trips_exact_welcome_material() {
        let realm_id = "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19";
        // The admission Commit ships as exact authored bytes, and the Welcomes
        // name it by its FINAL id — so the Commit is authored first and the
        // Welcome is only then authorable at all.
        let proposal_intent =
            sdk_intent_with_kind(realm_id, "ak.mls.proposal", "did:web:alice.example");
        let mut proposal = crate::operation::author_intent_for_test_at_seq(proposal_intent, 1);
        {
            use crate::operation::AuthoredEventExt;
            proposal
                .sign_ed25519(
                    "did:web:alice.example",
                    "did:web:alice.example#device",
                    &ed25519_dalek::SigningKey::from_bytes(&[30_u8; 32]),
                )
                .expect("the Proposal signs");
        }
        let commit_intent = serde_json::from_value::<EventIntent>(json!({
            "kind": "ak.mls.commit",
            "scope_ref": {"kind": "realm", "realm_id": realm_id},
            "actor_id": "ak:did_core:web:alice.example",
            "principal_server_id": "ak:did_core:web:principal.example",
            "created_at": "2026-05-19T00:00:00.000Z",
            "payload": {"proposal_refs": [proposal.event_id()]}
        }))
        .unwrap();
        let commit = crate::operation::author_intent_for_test_at_seq(commit_intent.clone(), 2);
        let mut welcome = crate::operation::author_intent_for_test_at_seq(
            serde_json::from_value::<EventIntent>(json!({
                "kind": "ak.mls.welcome",
                "scope_ref": {"kind": "realm", "realm_id": realm_id},
                "actor_id": "ak:did_core:web:alice.example",
                "principal_server_id": "ak:did_core:web:principal.example",
                "created_at": "2026-05-19T00:00:00.000Z",
                "payload": {
                    "commit_ref": commit.event_id(),
                    "recipient_principal_id": "ak:did_core:web:bob.example"
                }
            }))
            .unwrap(),
            2,
        );
        // An `Authored` Welcome is one that is ready to ship, so it carries its
        // producer proof; the queue refuses the pair otherwise.
        {
            use crate::operation::AuthoredEventExt;
            welcome
                .sign_ed25519(
                    "did:web:alice.example",
                    "did:web:alice.example#device",
                    &ed25519_dalek::SigningKey::from_bytes(&[31_u8; 32]),
                )
                .expect("the Welcome signs");
        }
        let snapshot = crate::mls::persistence::MlsSnapshotEnvelope {
            realm_id: realm_id.to_owned(),
            group_id: "010203".to_owned(),
            epoch: 1,
            admission_epoch: 0,
            group_state_event_id: None,
            salt_hex: "00".repeat(16),
            ciphertext_hex: "11".repeat(32),
            mac_hex: "22".repeat(12),
            recorded_at: chrono::Utc::now(),
            epoch_started_at: chrono::Utc::now(),
            app_messages_observed: 0,
            aead_version: crate::mls::persistence::AEAD_VERSION_CHACHA20_POLY1305,
        };
        let queued = QueuedSdkEvent::authored(
            fixture_queued_intent(commit_intent),
            commit.clone(),
            "mls-admission-operation".to_owned(),
            commit.event_id().to_string(),
            arkret_sdk::canonical::canonical_json_bytes(&commit).unwrap(),
            None,
            test_authoring_generation(),
            Some(PostAcceptAction::MlsAdmission {
                realm_id: realm_id.to_owned(),
                actor_id: "did:web:alice.example".to_owned(),
                device_id: "ak:device:01904100-0000-7000-8000-000000000001".to_owned(),
                proposal_events: vec![proposal],
                stage: MlsAdmissionStage::WelcomesAuthored,
                commit_ingress_receipts: Vec::new(),
                commit_was_duplicate: false,
                welcomes: garth::QueuedMlsWelcomes::Authored {
                    events: vec![welcome.clone()],
                },
                snapshot: snapshot.into_queued(),
            }),
        )
        .unwrap();

        let decoded = decode_queued_sdk_event(serde_json::to_value(&queued).unwrap()).unwrap();
        let Some(PostAcceptAction::MlsAdmission { welcomes, .. }) = decoded.post_accept else {
            panic!("queued admission action was not preserved");
        };
        // Restoring the record re-proves each Welcome's identity against its own
        // content: a durable record is not a trusted source of identity.
        assert_eq!(welcomes.authored(), Some([welcome].as_slice()));
        assert_eq!(
            decoded
                .authored_attempt
                .as_ref()
                .unwrap()
                .canonical_body_bytes,
            queued
                .authored_attempt
                .as_ref()
                .unwrap()
                .canonical_body_bytes
        );
    }

    /// The accepted frontier is an authoring input: the position it reports lands
    /// on the envelope through `author`, not through a later write.
    #[test]
    fn the_accepted_frontier_positions_the_authored_envelope() {
        let intent = EventIntent::from_authored(&sdk_event_without_proof("did:web:alice.example"));
        let frontier_event_id =
            arkret_sdk::EventId::new("ak:event:ASeIBHNVQyeIcU4aBIt2t2BF_ikuVMH0kNru_HgO_gG1")
                .unwrap();
        let frontier = arkret_sdk::RealmActorFrontierView::new(
            intent.realm_id_opt().unwrap().clone(),
            arkret_sdk::DidCoreId::new("ak:did_core:web:alice.example").unwrap(),
            8,
            vec![frontier_event_id.clone()],
            arkret_sdk::canonical::DigestSuite::Sha256,
        )
        .unwrap();
        frontier.validate().unwrap();

        let authored = intent
            .with_prev_refs(frontier.frontier_event_ids.clone())
            .author_with_digest_suite(
                frontier.next_actor_seq,
                crate::operation::test_authoring_hlc_at_seq(frontier.next_actor_seq),
                arkret_sdk::DigestSuite::Sha256,
            )
            .unwrap();

        assert_eq!(authored.actor_seq, 8);
        assert_eq!(authored.prev_refs, vec![frontier_event_id]);
        authored.verify_identity().unwrap();
    }

    /// `contract-registry.json` (`event_kind_registry.registry_rules`) closes
    /// the question the old version of this test guessed at: *every*
    /// `ordered_log` append MUST project `issuer_seq` from `envelope.actor_seq`
    /// exactly, and a registry row MUST NOT declare a cell-local constant. A
    /// genesis append is not special-cased into slot zero, so the frontier
    /// stamp is required to carry into `ak.realm.create`'s create-log append —
    /// while every other registered write of that Event, none of which reads
    /// `actor_seq`, must come out byte-identical.
    #[test]
    fn actor_frontier_stamp_carries_into_the_ordered_log_issuer_seq() {
        let intent = crate::event_builders::build_realm_create_event(
            arkret_sdk::GenesisSalt::new("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA").unwrap(),
            "did:web:alice.example",
            crate::event_builders::test_single_signer_notary("did:web:alice.example").unwrap(),
            "Frontier",
            None,
            "invite_only",
            "invite",
            "since_join",
            // `encryption_profile` is the closed realm-genesis schema enum
            // {none, mls_rfc9420, external}; "plaintext" was never a member and
            // only survived here because the object used to be hand-built JSON.
            "none",
            "standard",
            "open",
            "sha256",
            "ak:trust_domain:did.web.example",
            None,
        )
        .unwrap()
        .into_intent();
        let create_log_issuer_seq = |event: &arkret_sdk::Event| {
            crate::operation::direct_registered_cell_writes(event, arkret_sdk::DigestSuite::Sha256)
                .unwrap()
                .into_iter()
                .find(|write| write.cell.as_str() == arkret_bootstrap::REALM_CREATE_CELL)
                .expect("realm.create projects the create-log append")
                .op
                .issuer_seq
        };
        let other_writes = |event: &arkret_sdk::Event| {
            crate::operation::direct_registered_cell_writes(event, arkret_sdk::DigestSuite::Sha256)
                .unwrap()
                .into_iter()
                .filter(|write| write.cell.as_str() != arkret_bootstrap::REALM_CREATE_CELL)
                .collect::<Vec<_>>()
        };

        // Genesis opens its own chain at 0; the same intent authored at an
        // ordinary chain position must move `issuer_seq` with it and leave every
        // other registered write of that Event byte-identical.
        let at_genesis = crate::operation::author_intent_for_test_at_seq(intent.clone(), 0);
        assert_eq!(create_log_issuer_seq(&at_genesis), Some(0));
        let before_other = other_writes(&at_genesis);

        let frontier = arkret_sdk::RealmActorFrontierView::new(
            at_genesis.realm_id.clone(),
            at_genesis.actor_id.clone(),
            8,
            vec![
                arkret_sdk::EventId::new("ak:event:ASeIBHNVQyeIcU4aBIt2t2BF_ikuVMH0kNru_HgO_gG1")
                    .unwrap(),
            ],
            arkret_sdk::canonical::DigestSuite::Sha256,
        )
        .unwrap();
        let at_frontier = crate::operation::author_intent_for_test_at_seq(
            intent.with_prev_refs(frontier.frontier_event_ids.clone()),
            frontier.next_actor_seq,
        );

        assert_eq!(at_frontier.actor_seq, 8);
        assert_eq!(create_log_issuer_seq(&at_frontier), Some(8));
        assert_eq!(other_writes(&at_frontier), before_other);
    }

    #[test]
    fn a_frontier_for_another_actor_is_not_a_chain_basis() {
        let intent = EventIntent::from_authored(&sdk_event_without_proof("did:web:alice.example"));
        let realm_id = intent.realm_id_opt().unwrap().clone();
        let mismatched = arkret_sdk::RealmActorFrontierView::new(
            realm_id.clone(),
            arkret_sdk::DidCoreId::new("ak:did_core:web:bob.example").unwrap(),
            8,
            vec![
                arkret_sdk::EventId::new("ak:event:ASeIBHNVQyeIcU4aBIt2t2BF_ikuVMH0kNru_HgO_gG1")
                    .unwrap(),
            ],
            arkret_sdk::canonical::DigestSuite::Sha256,
        )
        .unwrap();

        let error =
            actor_chain_basis_from_frontier(&realm_id, intent.actor_id().as_str(), mismatched)
                .unwrap_err()
                .to_string();

        assert!(error.contains("realm actor frontier mismatch"), "{error}");
    }

    #[test]
    fn an_empty_frontier_authors_the_first_chain_position() {
        let intent = EventIntent::from_authored(&sdk_event_without_proof("did:web:alice.example"));
        let frontier = arkret_sdk::RealmActorFrontierView::new(
            intent.realm_id_opt().unwrap().clone(),
            arkret_sdk::DidCoreId::new("ak:did_core:web:alice.example").unwrap(),
            0,
            vec![],
            arkret_sdk::canonical::DigestSuite::Sha256,
        )
        .unwrap();
        frontier.validate().unwrap();

        let authored = crate::operation::author_intent_for_test_at_seq(
            intent.with_prev_refs(frontier.frontier_event_ids.clone()),
            frontier.next_actor_seq,
        );

        assert_eq!(authored.actor_seq, 0);
        assert!(authored.prev_refs.is_empty());
    }

    #[tokio::test]
    async fn realm_bootstrap_preparation_requires_a_described_principal_server() {
        crate::operation::set_authoring_principal_server_id(Some(
            arkret_sdk::DidCoreId::new("ak:did_core:web:server.example").unwrap(),
        ));
        let _signer = crate::event_signer::ActiveSignerTestGuard::replace(Some(
            std::sync::Arc::new(crate::event_signer::build_ed25519_device_signer(
                [42_u8; 32],
                "did:web:alice.example",
                "ak:device:01904100-0000-7000-8000-a11ce0000001",
            )),
        ));
        let steps = crate::event_builders::build_realm_bootstrap_steps(
            arkret_sdk::GenesisSalt::new("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA").unwrap(),
            "did:web:alice.example",
            "did:web:server.example",
            crate::event_builders::test_single_signer_notary("did:web:server.example").unwrap(),
            "https://server.example",
            "Engineering",
            Some("Realm genesis must not query its own nonexistent frontier"),
            "listed",
            "invite",
            "since_join",
            "mls_rfc9420",
            "standard",
            "restricted",
            "sha256",
            "ak:trust_domain:server.example",
            &[],
            &["did:web:server.example".to_owned()],
            None,
            None,
        )
        .unwrap();
        let http = arkret_sdk::http_client::Client::builder("http://127.0.0.1:9/".parse().unwrap())
            .allow_insecure_localhost()
            .build()
            .unwrap();

        let previous_proof_mode = crate::operation::current_proof_mode();
        crate::operation::set_proof_mode(crate::operation::ProofMode::RealEd25519);
        let error = EventSubmitter::new(http)
            .with_authority(test_authority())
            .author_event_unit(steps)
            .await
            .expect_err("authoring must resolve the selected Principal Server");
        crate::operation::set_proof_mode(previous_proof_mode);
        assert!(format!("{error:#}").contains("server describe"));
    }

    #[tokio::test]
    async fn ordinary_event_preparation_requires_describe_before_remote_frontier() {
        crate::operation::set_authoring_principal_server_id(Some(
            arkret_sdk::DidCoreId::new("ak:did_core:web:principal.example").unwrap(),
        ));
        let intent = EventIntent::from_authored(&sdk_event_without_proof("did:web:alice.example"));
        let http = arkret_sdk::http_client::Client::builder("http://127.0.0.1:9/".parse().unwrap())
            .allow_insecure_localhost()
            .build()
            .unwrap();

        let error = EventSubmitter::new(http)
            .with_authority(test_authority())
            .author_independent_events(vec![intent])
            .await
            .expect_err("ordinary Realm Event must refresh its combined actor frontier");

        let detail = format!("{error:#}");
        assert!(
            detail.contains("server describe"),
            "unexpected preparation error: {detail}"
        );
    }

    #[test]
    fn actor_seq_cas_conflict_classifier_is_narrow() {
        let current_frontier = arkret_sdk::RealmActorFrontierView::new(
            arkret_sdk::RealmId::new("ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19")
                .unwrap(),
            arkret_sdk::DidCoreId::new("ak:did_core:web:alice.example").unwrap(),
            0,
            vec![],
            arkret_sdk::canonical::DigestSuite::Sha256,
        )
        .unwrap();
        let details = arkret_sdk::EventsActorCasConflictProblem {
            accepted: false,
            current_frontier,
        };
        let details = serde_json::to_value(details).unwrap();
        let cas: anyhow::Error = TransportClientError {
            status: StatusCode::CONFLICT,
            error: ErrorEnvelope::new(
                "cas_conflict",
                "actor_seq is older than the accepted actor frontier",
            )
            .with_detail("accepted", details["accepted"].clone())
            .with_detail("current_frontier", details["current_frontier"].clone()),
        }
        .into();
        assert!(crate::api_error::is_actor_seq_cas_conflict_error(&cas));

        let different_conflict: anyhow::Error = TransportClientError {
            status: StatusCode::CONFLICT,
            error: ErrorEnvelope::new("cas_conflict", "expected head mismatch"),
        }
        .into();
        assert!(!crate::api_error::is_actor_seq_cas_conflict_error(
            &different_conflict
        ));
    }

    #[test]
    fn mls_genesis_event_lookup_filters_kind_and_realm() {
        let realm = "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19";
        let other_realm = "ak:realm:AXBcp13trH3bPXvj0eHppCpGqJZWL9yqE3cf2Tl43vyk";
        let expected =
            arkret_sdk::EventId::new("ak:event:AcsFZ3o2tOdN3EFpNceeLV-aI3jZkB9S34_4YIwJ5DLy")
                .unwrap();
        let outcome = arkret_sdk::EventsQueryOutcome {
            events: vec![
                sdk_event_with_kind(
                    "ak:event:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19",
                    realm,
                    "ak.message.create",
                    "did:web:alice.example",
                )
                .into(),
                sdk_event_with_kind(
                    "ak:event:ASeIBHNVQyeIcU4aBIt2t2BF_ikuVMH0kNru_HgO_gG1",
                    other_realm,
                    "ak.mls.genesis",
                    "did:web:alice.example",
                )
                .into(),
                sdk_event_with_kind(
                    expected.as_str(),
                    realm,
                    "ak.mls.genesis",
                    "did:web:alice.example",
                )
                .into(),
            ],
            snapshot_bootstrap: None,
            next_cursor: None,
            prev_cursor: None,
            has_more: false,
            range_completeness: None,
        };

        assert_eq!(
            mls_genesis_event_id_from_events(&outcome, realm).unwrap(),
            Some(expected)
        );
        assert_eq!(
            mls_genesis_event_id_from_events(
                &outcome,
                "ak:realm:AfXCJ1DUe3g7MVHuVBpMsl89749WyrXAJP7EvoU9mwBH"
            )
            .unwrap(),
            None
        );
    }
}
