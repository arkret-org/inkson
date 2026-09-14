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
use arkret_sdk::Problem;
use arkret_sdk::events::{CbsEffectPlane, cbs_cell_family_plane};
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

mod authoring_unit;
mod authority;

#[cfg(test)]
pub(crate) use authoring_unit::author_event_unit_for_test;
use authoring_unit::{UnitAuthoringChain, validate_authored_unit_shape};
use authority::*;

/// Authenticated durable/ephemeral event submission engine extracted from the
/// former `TransportClient` events surface. Constructed per authenticated call from
/// the shared SDK http-client (see `crate::transport::auth::with_event_submitter`).
pub struct EventSubmitter {
    http: arkret_sdk::http_client::Client,
    /// Exact account authority captured when this submitter is constructed.
    /// Durable queue operations never re-read the process-global active scope.
    authority: Option<arkret_sdk::AccountId>,
    describe_cache: OnceCell<ServiceDescribe>,
    state_store: Option<crate::runtime::input::StateStoreHandle>,
    /// A freshly accepted Realm has no complete demand-sync projection yet,
    /// but its setup flow must append the deterministic default-Strand
    /// follow-ups and, for an encrypted Realm, its creator MLS Genesis. This
    /// only bypasses the local-detail freshness guard for that exact Realm;
    /// accepted creator authority, governance-frontier verification, signing,
    /// and server admission remain mandatory.
    founding_realm: Option<arkret_sdk::RealmId>,
}

/// Realm bootstrap units intentionally publish without per-Event Control
/// Proposal Acks. Their signer-material context is still branch-specific:
/// ordinary Realm Events retain portable signer evidence, while only the
/// exact human PCR create/authorize unit uses native unit-local evidence. A
/// Agent PCR create is also basis-free, but its delegated controller is the
/// founding proposal authority, so it must pass through
/// `standard_initial_submission` to attach that controller's Ack.
fn validate_prepared_join_signing_scope(
    prepared_account: &arkret_sdk::AccountId,
    captured_account: &arkret_sdk::AccountId,
    before: &crate::secure_key_store::ActiveDeviceSeedScope,
    after: Option<&crate::secure_key_store::ActiveDeviceSeedScope>,
    signer_device_id: Option<&str>,
) -> anyhow::Result<()> {
    if prepared_account != captured_account
        || &before.authority != captured_account
        || after != Some(before)
        || signer_device_id != Some(before.device_id.as_str())
    {
        anyhow::bail!("prepared join account or signing device changed before signing");
    }
    Ok(())
}

fn bare_online_bootstrap_context(
    realm_bootstrap_unit: bool,
    native_anchor_unit: bool,
    event: &arkret_sdk::Event,
) -> Option<arkret_wire::EventSubmitContext> {
    if !realm_bootstrap_unit || crate::authorization_lease::is_agent_pcr_genesis(event) {
        return None;
    }
    Some(if native_anchor_unit {
        arkret_wire::EventSubmitContext::AnchorUnit
    } else {
        arkret_wire::EventSubmitContext::RealmBootstrap
    })
}

/// The write is safely persisted and will be retried.
///
/// It is keyed by the holder-local operation id, not an Event id: at the moment
/// this is raised the write may not have been authored yet, and after a CAS
/// re-author the Event id is not stable while the user's operation is.
#[derive(Debug, thiserror::Error)]
#[error(
    "operation {operation_id} is durably queued for retry{detail}",
    detail = reason
        .as_deref()
        .map(|reason| format!(": {reason}"))
        .unwrap_or_default()
)]
pub(crate) struct DurablyQueuedError {
    pub(crate) operation_id: String,
    pub(crate) reason: Option<String>,
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
    retryable: Mutex<BTreeMap<String, String>>,
}

struct EventOutboundSubmitter<'a> {
    owner: &'a EventSubmitter,
    results: &'a OutboundAttemptResults,
    accepted_mls_state_store: Option<crate::runtime::input::StateStoreHandle>,
}

impl EventOutboundSubmitter<'_> {
    async fn converge_finalized_mls_admission(
        &self,
        state_store: &crate::runtime::input::StateStoreHandle,
        realm_id: &str,
        device_id: &arkret_sdk::DeviceId,
        commit: &arkret_sdk::AuthoredEvent,
        staged_snapshot: &garth::QueuedMlsLocalCheckpoint,
    ) -> Result<(), String> {
        let seal_view = self
            .owner
            .seals_frontier_realm_view(realm_id)
            .await
            .map_err(|error| format!("refresh accepted Seal view after MLS admission: {error}"))?;
        state_store.write(|store| {
            store.set_realm_seal_view(
                realm_id.to_owned(),
                crate::state::LocalSealView {
                    frontier: seal_view
                        .seal_basis
                        .leaves
                        .iter()
                        .map(ToString::to_string)
                        .collect(),
                    state_root: None,
                    ..Default::default()
                },
            );
        });

        let api = crate::transport::TransportClient::from_http(
            self.owner.http.clone(),
            crate::transport::RequestContext::new(""),
        );
        let payload = serde_json::from_value::<arkret_sdk::MlsCommitPayload>(
            serde_json::to_value(&commit.event().payload).map_err(|error| error.to_string())?,
        )
        .map_err(|error| error.to_string())?;
        let authority = self.owner.authority().map_err(|error| error.to_string())?;
        crate::mls::accepted_artifact::fetch(&api, state_store.clone(), commit.event())
            .await
            .map_err(|error| error.to_string())?;
        crate::mls::runtime::converge_accepted_local_commit(
            state_store,
            authority,
            device_id,
            commit.event_id(),
            staged_snapshot,
        )
        .await?;

        let accepted = state_store
            .read(|store| {
                store.mls_checkpoint_for_scope(payload.governance_binding().effective_scope())
            })
            .is_some_and(|snapshot| {
                snapshot.group_id == payload.mls_group_id()
                    && snapshot.epoch == payload.next_epoch()
                    && snapshot.group_state_event_id.as_ref() == Some(commit.event_id())
            });
        if !accepted {
            return Err(
                "checkpoint-proven MLS Commit did not materialize its accepted local state"
                    .to_owned(),
            );
        }
        Ok(())
    }

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
        let digest_suite = require_server_sealed_event(&self.owner.http, event).await?;
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
        if !accepted_event_preserves_authored_envelope(resolved, event, digest_suite)? {
            anyhow::bail!(
                "events.resolve did not preserve the exact producer-authored envelope for Event {}",
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
                    tracing::warn!(
                        event_id = %commit.event_id,
                        %error,
                        "durable MLS admission Commit finality verification remains pending"
                    );
                    return Ok(OutboundSubmitOutcome::RetryAfter {
                        delay: Duration::from_secs(1),
                        reason: format!("MLS Commit finality pending: {error:#}"),
                    });
                }
                let Some(PostAcceptAction::MlsAdmission { stage, .. }) =
                    queued.post_accept.as_mut()
                else {
                    unreachable!("admission action was matched above")
                };
                *stage = MlsAdmissionStage::WelcomesAuthored;
                Ok(OutboundSubmitOutcome::Prepared {
                    record: QueuedRecord::SdkEvent(Box::new(queued)),
                })
            }
            MlsAdmissionStage::WelcomesAuthored => {
                let welcomes = match queued.post_accept.as_ref() {
                    Some(PostAcceptAction::MlsAdmission { welcomes, .. }) => {
                        welcomes.authored().to_vec()
                    }
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
                let (welcomes, receipts, duplicate, realm_id, device_id, staged_snapshot) =
                    match queued.post_accept.as_ref() {
                        Some(PostAcceptAction::MlsAdmission {
                            welcomes,
                            commit_ingress_receipts,
                            commit_was_duplicate,
                            realm_id,
                            device_id,
                            snapshot,
                            ..
                        }) => (
                            welcomes.authored().to_vec(),
                            commit_ingress_receipts.clone(),
                            *commit_was_duplicate,
                            realm_id.clone(),
                            device_id.clone(),
                            snapshot.clone(),
                        ),
                        _ => unreachable!("admission action was matched above"),
                    };
                for welcome in &welcomes {
                    if let Err(error) = self.verify_covering_seal(welcome).await {
                        tracing::warn!(
                            event_id = %welcome.event_id,
                            %error,
                            "durable MLS admission Welcome finality verification remains pending"
                        );
                        return Ok(OutboundSubmitOutcome::RetryAfter {
                            delay: Duration::from_secs(1),
                            reason: format!("MLS Welcome finality pending: {error:#}"),
                        });
                    }
                }
                let state_store = match accepted_mls_state_store_for_finalization(
                    self.accepted_mls_state_store.as_ref(),
                ) {
                    Ok(state_store) => state_store,
                    Err(outcome) => return Ok(outcome),
                };
                let device_id = arkret_sdk::DeviceId::new(device_id)
                    .map_err(|error| garth::Error::Protocol(error.to_string()))?;
                if let Err(error) = self
                    .converge_finalized_mls_admission(
                        state_store,
                        &realm_id,
                        &device_id,
                        &commit,
                        &staged_snapshot,
                    )
                    .await
                {
                    tracing::warn!(
                        realm = %realm_id,
                        event_id = %commit.event_id,
                        %error,
                        "accepted MLS admission artifact convergence remains pending"
                    );
                    return Ok(OutboundSubmitOutcome::RetryAfter {
                        delay: Duration::from_secs(1),
                        reason: format!("accepted MLS admission artifacts remain pending: {error}"),
                    });
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
                            self.results
                                .retryable
                                .lock()
                                .unwrap_or_else(PoisonError::into_inner)
                                .insert(item.transaction_id.clone(), reason.clone());
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
                            self.results
                                .retryable
                                .lock()
                                .unwrap_or_else(PoisonError::into_inner)
                                .insert(item.transaction_id.clone(), reason.clone());
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

/// Consume the authenticated Account Station's exact durable acceptance
/// result. This checks local signing intent, not foreign governance history.
pub(crate) async fn require_server_sealed_event(
    http: &arkret_sdk::http_client::Client,
    event: &arkret_sdk::Event,
) -> anyhow::Result<arkret_sdk::DigestSuite> {
    let digest_suite = event.event_id.digest_suite_code().digest_suite();
    event.verify_event_id_matches_content_with_digest_suite(digest_suite)?;
    let request = arkret_sdk::ControlProposalDecisionReadRequestBody {
        realm_id: event.realm_id.clone(),
        proposal_digest: event.event_id.event_digest(),
    };
    let outcome = http.read_control_proposal_decision(&request).await?;
    if outcome.proposal_event_kind != event.kind.as_str()
        || outcome.proposal_state != arkret_sdk::ControlProposalState::Sealed
        || outcome.accepted_seal_id.is_none()
    {
        anyhow::bail!(
            "Event {} has no server-confirmed covering Seal",
            event.event_id
        );
    }
    require_server_committed_unit(
        http,
        &event.realm_id,
        &event.event_id,
        outcome.accepted_seal_id.as_ref().expect("checked above"),
    )
    .await?;
    Ok(digest_suite)
}

/// Inspect the exact terminal unit reported by the authenticated Station.
/// A sealed rejection is final but must never install a staged success.
pub(crate) async fn require_server_committed_unit(
    http: &arkret_sdk::http_client::Client,
    realm_id: &arkret_sdk::RealmId,
    event_id: &arkret_sdk::EventId,
    seal_id: &arkret_sdk::SealId,
) -> anyhow::Result<()> {
    let outcome = server_command_unit_outcome(http, realm_id, event_id, seal_id).await?;
    anyhow::ensure!(
        outcome == arkret_sdk::CommandOutcome::Committed,
        "terminal command unit was rejected"
    );
    Ok(())
}

pub(crate) async fn server_command_unit_outcome(
    http: &arkret_sdk::http_client::Client,
    realm_id: &arkret_sdk::RealmId,
    event_id: &arkret_sdk::EventId,
    seal_id: &arkret_sdk::SealId,
) -> anyhow::Result<arkret_sdk::CommandOutcome> {
    let seals = http
        .seals_resolve(&arkret_sdk::SelfSealResolveRequestBody {
            realm_id: realm_id.clone(),
            selection: arkret_sdk::SealResolveSelection::SealRefs {
                seal_refs: vec![seal_id.clone()],
            },
            history_traversal_access: None,
        })
        .await?
        .into_seals()?;
    anyhow::ensure!(
        seals.len() == 1 && seals[0].id == *seal_id && seals[0].realm_id == *realm_id,
        "terminal command Seal did not resolve exactly"
    );
    let seal = &seals[0];
    seal.validate_structural()?;
    seal.validate_id(seal.state_root.digest_suite()?)?;
    command_unit_outcome(&seal.command_results, &event_id.event_digest())
}

pub(crate) fn command_unit_outcome(
    results: &[arkret_sdk::SealCommandOutcome],
    event_digest: &arkret_sdk::Hash,
) -> anyhow::Result<arkret_sdk::CommandOutcome> {
    let mut matching = results
        .iter()
        .filter(|result| result.unit_event_digests.contains(event_digest));
    let result = matching
        .next()
        .ok_or_else(|| anyhow::anyhow!("terminal Seal omits the requested command unit"))?;
    anyhow::ensure!(
        matching.next().is_none(),
        "terminal Seal repeats a command unit member"
    );
    Ok(result.outcome)
}

/// Compare a producer-authored Event with its accepted projection.
///
/// Ordinary acceptance retains the exact producer envelope. The receiver does
/// not append an admission proof or rewrite any signed field.
pub(crate) fn accepted_event_preserves_authored_envelope(
    accepted: &arkret_sdk::Event,
    authored: &arkret_sdk::Event,
    digest_suite: arkret_sdk::DigestSuite,
) -> anyhow::Result<bool> {
    Ok(accepted.event_id == authored.event_id
        && arkret_sdk::Hash::new(accepted.event_digest_with_digest_suite(digest_suite)?)?
            == arkret_sdk::Hash::new(authored.event_digest_with_digest_suite(digest_suite)?)?
        && accepted == authored)
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
                let attempt = match self
                    .owner
                    .author_frozen_intent(&queued.intent, &queued.local_operation_id)
                    .await
                {
                    Ok(attempt) => attempt,
                    Err(error) => {
                        let reason = format!("author queued Event: {error:#}");
                        self.results
                            .retryable
                            .lock()
                            .unwrap_or_else(PoisonError::into_inner)
                            .insert(item.transaction_id.clone(), reason.clone());
                        return Err(garth::Error::Protocol(reason));
                    }
                };
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
                        tracing::warn!(
                            event_id = %item.transaction_id,
                            local_operation_id = %queued.local_operation_id,
                            %reason,
                            "immutable MLS admission attempt remains durably queued"
                        );
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
                        let prepared_join = event.kind == arkret_sdk::EventKind::InviteAccept
                            || (event.kind == arkret_sdk::EventKind::MemberState
                                && event
                                    .payload
                                    .get("membership")
                                    .and_then(serde_json::Value::as_str)
                                    .is_some_and(|state| matches!(state, "join" | "knock")));
                        if queued.scheduled_dispatch.is_some() || prepared_join {
                            let reason = "frozen Event hit an actor frontier conflict; prepare a new authorized attempt without rewriting the signed Event".to_owned();
                            self.results
                                .rejected
                                .lock()
                                .unwrap_or_else(|poisoned| poisoned.into_inner())
                                .insert(item.transaction_id, error);
                            return Ok(OutboundSubmitOutcome::Rejected { reason });
                        }
                        let replacement = self
                            .owner
                            .reauthor_after_actor_frontier_conflict(&queued)
                            .await
                            .map_err(|error| garth::Error::Protocol(error.to_string()))?;
                        // A frontier-conflict re-author is a new attempt at the same user
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
                        self.results
                            .retryable
                            .lock()
                            .unwrap_or_else(PoisonError::into_inner)
                            .insert(item.transaction_id.clone(), reason.clone());
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

fn accepted_mls_state_store_for_finalization<T>(
    state_store: Option<T>,
) -> Result<T, OutboundSubmitOutcome> {
    state_store.ok_or_else(|| OutboundSubmitOutcome::RetryAfter {
        delay: Duration::from_secs(1),
        reason: "accepted MLS admission snapshot convergence requires an accepted-state store"
            .to_owned(),
    })
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
            let did = arkret_sdk::Did::new(authority_principal.to_owned()).ok()?;
            arkret_sdk::project_did_to_core_id(&did).ok()
        })?;
    let device = arkret_sdk::DeviceId::new(device_id.to_owned()).ok()?;
    Some(format!("{principal}\u{1f}{device}"))
}

fn recovery_gate_cache_key(intent: &EventIntent) -> Option<String> {
    let authority_principal = intent
        .executed_by()
        .unwrap_or_else(|| intent.actor_id())
        .signing_principal_id()
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
    actor_id: &arkret_sdk::ActorId,
    frontier: arkret_sdk::RealmActorFrontierView,
) -> anyhow::Result<(u64, Vec<arkret_sdk::EventId>)> {
    if &frontier.actor_id != actor_id || &frontier.realm_id != realm_id {
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

fn pending_mls_admission_for_realm_from_snapshot(
    snapshot: &garth::SendQueueSnapshot,
    realm_id: &str,
) -> bool {
    snapshot
        .items
        .iter()
        .any(|item| is_unfinished_mls_admission_record(item.status, &item.record, realm_id))
}

fn durable_mls_genesis_for_realm_from_snapshot(
    snapshot: &garth::SendQueueSnapshot,
    realm_id: &str,
) -> bool {
    use garth::SendQueueStatus;

    snapshot.items.iter().any(|item| {
        matches!(
            item.status,
            SendQueueStatus::Queued
                | SendQueueStatus::Sending
                | SendQueueStatus::Sent
                | SendQueueStatus::Failed
        ) && matches!(
            &item.record,
            QueuedRecord::SdkEvent(queued)
                if queued.intent.kind() == &arkret_sdk::EventKind::MlsGenesis
                    && queued.intent.realm_id_opt().map(arkret_sdk::RealmId::as_str)
                        == Some(realm_id)
        )
    })
}

fn is_unfinished_mls_admission_record(
    status: garth::SendQueueStatus,
    record: &QueuedRecord,
    realm_id: &str,
) -> bool {
    use garth::SendQueueStatus;

    matches!(
        status,
        SendQueueStatus::Queued | SendQueueStatus::Sending | SendQueueStatus::Failed
    ) && matches!(
        record,
        QueuedRecord::SdkEvent(queued)
            if matches!(
                queued.post_accept.as_ref(),
                Some(PostAcceptAction::MlsAdmission {
                    realm_id: queued_realm_id,
                    ..
                }) if queued_realm_id == realm_id
            )
    )
}

fn is_mls_admission_snapshot_finalization_record(
    status: garth::SendQueueStatus,
    record: &QueuedRecord,
) -> bool {
    use garth::SendQueueStatus;

    matches!(
        status,
        SendQueueStatus::Queued | SendQueueStatus::Sending | SendQueueStatus::Failed
    ) && matches!(
        record,
        QueuedRecord::SdkEvent(queued)
            if matches!(
                queued.post_accept.as_ref(),
                Some(PostAcceptAction::MlsAdmission {
                    stage: MlsAdmissionStage::WelcomesAcceptedWaitingSeal,
                    ..
                })
            )
    )
}

fn mls_outbound_requires_accepted_state_store(snapshot: &garth::SendQueueSnapshot) -> bool {
    snapshot
        .items
        .iter()
        .any(|item| is_mls_admission_snapshot_finalization_record(item.status, &item.record))
}

/// Project the holder-local ids of pending chat sends directly from the one
/// durable Garth queue.
///
/// The chat UI uses this snapshot instead of maintaining a second plaintext
/// outbox with separate replay semantics. The ids are holder-local: a queued
/// send has no accepted Message id yet, because the Message is named by the
/// create Event nobody has accepted.
pub(crate) async fn pending_chat_outbound_local_operation_ids(
    authority: &arkret_sdk::AccountId,
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

/// Join a durable outbound receipt back to the optimistic operation that
/// authored it.
///
/// The queue may reach `Sent` after the HTTP request was accepted but before
/// the component-owned future that initiated it gets to process the response.
/// `local_operation_id` is the stable holder-local identity across retries and
/// actor-frontier re-authoring, while `remote_event_id` is the content-bound identity the
/// server assigned. Replaying this join from the durable queue makes receipt
/// reconciliation restart-safe and independent of the originating UI scope.
fn reconcile_sent_outbound_item(
    state_store: &mut crate::state::LocalStateStore,
    item: &garth::SendQueueItem,
) -> bool {
    if item.status != garth::SendQueueStatus::Sent {
        return false;
    }
    let Some(event_id) = item.remote_event_id.as_ref() else {
        return false;
    };
    state_store.update_raw_operation_write_state(
        &item.local_operation_id,
        "accepted",
        Some(event_id.to_string()),
        None,
    )
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

fn local_detail_blocks_control_authoring(
    founding_realm: Option<&arkret_sdk::RealmId>,
    realm_id: &str,
    invalidated_without_checkpoint: bool,
) -> bool {
    !founding_realm.is_some_and(|founding| founding.as_str() == realm_id)
        && invalidated_without_checkpoint
}

impl EventSubmitter {
    fn ensure_realm_detail_current(&self, realm_id: &str) -> anyhow::Result<()> {
        let invalidated_without_checkpoint = self.state_store.as_ref().is_some_and(|store| {
            store.read(|store| {
                store.realm_detail_invalidated(realm_id)
                    && store.station_realm_digest_suite(realm_id).is_none()
            })
        });
        if local_detail_blocks_control_authoring(
            self.founding_realm.as_ref(),
            realm_id,
            invalidated_without_checkpoint,
        ) {
            return Err(anyhow::Error::new(arkret_sdk::Error::Http(
                "Realm current state is refreshing after an account invalidation and no verified governance checkpoint is available"
                    .to_owned(),
            )));
        }
        Ok(())
    }
    pub fn new(http: arkret_sdk::http_client::Client) -> Self {
        Self {
            http,
            authority: crate::secure_key_store::active_device_seed_scope()
                .map(|scope| scope.authority),
            describe_cache: OnceCell::new(),
            state_store: None,
            founding_realm: None,
        }
    }

    pub(crate) fn with_state_store(
        mut self,
        state_store: crate::runtime::input::StateStoreHandle,
    ) -> Self {
        self.state_store = Some(state_store);
        self
    }

    pub(crate) fn with_authority(mut self, authority: arkret_sdk::AccountId) -> Self {
        self.authority = Some(authority);
        self
    }

    /// Confirm the immutable creator of an already-accepted Realm through the
    /// Station's exact founding-Event resolver. This is the asynchronous
    /// fallback for freshly created/cold-loaded Realms whose bounded current
    /// projection has not installed the authority-root cell yet.
    pub(crate) async fn accepted_realm_creator_matches_account(
        &self,
        realm_id: &str,
        authority: &arkret_sdk::AccountId,
    ) -> anyhow::Result<bool> {
        let actor = arkret_sdk::ActorId::account(authority.clone());
        let founding = self
            .realm_create_authority(realm_id)
            .await?
            .ok_or_else(|| anyhow::anyhow!("accepted Realm founding authority is not available"))?;
        Ok(matches!(founding, RealmCreateAuthority::Root { controller } if controller == actor))
    }

    /// Resolve the immutable encryption choice from the Station-accepted Realm
    /// founding Event. A missing/cold local projection must never downgrade an
    /// encrypted Realm to plaintext or suppress creator MLS bootstrap.
    pub(crate) async fn accepted_realm_is_encrypted(&self, realm_id: &str) -> anyhow::Result<bool> {
        let realm = arkret_sdk::RealmId::new(realm_id.to_owned())?;
        let create_id = arkret_sdk::EventId::new(format!(
            "ak:event:{}",
            realm.as_str().trim_start_matches("ak:realm:")
        ))?;
        let outcome = self
            .http
            .events_resolve(&arkret_sdk::EventsResolveRequestBody {
                event_ids: vec![create_id.clone()],
                event_digests: Vec::new(),
                include_payload: Some(true),
                history_traversal_access: None,
                max_response_bytes: Some(8 * 1024 * 1024),
            })
            .await?;
        anyhow::ensure!(
            outcome
                .events
                .iter()
                .all(|event| event.event_id == create_id
                    && event.realm_id == realm
                    && event.kind == arkret_sdk::EventKind::RealmCreate),
            "Station returned a different Realm founding Event"
        );
        realm_create_is_encrypted_from_events(&outcome.events, realm_id).ok_or_else(|| {
            anyhow::anyhow!("accepted Realm founding encryption profile is not available")
        })
    }

    /// Recover an interrupted pre-Genesis proposal from the complete accepted
    /// founding Event set, but only for the one legacy Inkson combination that
    /// is uniquely implied by its accepted history facet.
    pub(crate) async fn accepted_legacy_creator_genesis_proposal(
        &self,
        realm_id: &str,
    ) -> anyhow::Result<Option<arkret_sdk::ProposedMlsGroupGenesisBinding>> {
        let outcome = self
            .http
            .events_read_all_pages(realm_id)
            .await
            .map_err(anyhow::Error::from)?;
        let events = crate::models::require_complete_event_rows(
            &outcome.events,
            "legacy creator MLS Genesis recovery",
        )?;
        Ok(legacy_creator_genesis_proposal_from_events(
            &events, realm_id,
        ))
    }

    pub(crate) fn for_founding_realm(mut self, realm_id: arkret_sdk::RealmId) -> Self {
        self.founding_realm = Some(realm_id);
        self
    }

    /// Whether this holder already owns an unfinished durable MLS admission
    /// for the Realm. A queued admission freezes one Commit, its Welcomes and
    /// the resulting snapshot as a single retry unit. Authoring another Add
    /// while that unit waits for Seal finality would consume a second
    /// one-time KeyPackage and race the predecessor epoch.
    pub(crate) async fn has_pending_mls_admission_for_realm(
        &self,
        realm_id: &str,
    ) -> anyhow::Result<bool> {
        let outbound = OutboundEngine::new(crate::outbound_store::InksonOutboundStore::open(
            self.authority()?,
            crate::outbound_store::OutboundLane::MlsDurablePostAccept,
        )?);
        let snapshot = outbound.snapshot().await?;
        Ok(pending_mls_admission_for_realm_from_snapshot(
            &snapshot, realm_id,
        ))
    }

    /// Whether the standard durable lane already owns an immutable Genesis
    /// attempt for this Realm that is active or accepted at ingress. A `Sent`
    /// item remains authoritative while its accepted Event is still crossing
    /// the Seal/current-projection boundary; treating that propagation window
    /// as absence would author a second Genesis transaction.
    pub(crate) async fn has_durable_mls_genesis_for_realm(
        &self,
        realm_id: &str,
    ) -> anyhow::Result<bool> {
        let outbound = OutboundEngine::new(crate::outbound_store::InksonOutboundStore::open(
            self.authority()?,
            crate::outbound_store::OutboundLane::Standard,
        )?);
        let snapshot = outbound.snapshot().await?;
        Ok(durable_mls_genesis_for_realm_from_snapshot(
            &snapshot, realm_id,
        ))
    }

    pub(crate) fn authority(&self) -> anyhow::Result<&arkret_sdk::AccountId> {
        self.authority.as_ref().ok_or_else(|| {
            anyhow::anyhow!(
                "durable Event submission requires an active AccountId captured when the submitter was created"
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
                crate::clock::now_utc(),
            )
            .await?;

        let results = OutboundAttemptResults::default();
        let submitter = EventOutboundSubmitter {
            owner: self,
            results: &results,
            accepted_mls_state_store: None,
        };
        loop {
            let fence = self.resolve_queue_generation_fence(&outbound).await?;
            match outbound
                .submit_next_with_fence(&submitter, &fence, crate::clock::now_utc())
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
                        reason: results
                            .retryable
                            .lock()
                            .unwrap_or_else(PoisonError::into_inner)
                            .remove(&item.transaction_id),
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
                    crate::clock::now_utc(),
                )
                .await?;
        }
        let results = OutboundAttemptResults::default();
        let submitter = EventOutboundSubmitter {
            owner: self,
            results: &results,
            accepted_mls_state_store: None,
        };
        loop {
            let fence = self.resolve_queue_generation_fence(&outbound).await?;
            match outbound
                .submit_next_with_fence(&submitter, &fence, crate::clock::now_utc())
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
                        reason: results
                            .retryable
                            .lock()
                            .unwrap_or_else(PoisonError::into_inner)
                            .remove(&item.transaction_id),
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
            let facts = EventAuthorityFacts::from_intent(&queued.intent);
            let current = crate::identity::authoring_generation::cached_event_authoring_generation(
                &facts,
            )?
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "frontier_unavailable: no locally verified device authoring authority is available"
                )
            })?;
            let decision = if current == queued.authoring_generation {
                OutboundGenerationFenceDecision::Current
            } else {
                OutboundGenerationFenceDecision::Quarantine {
                    reason: "authoring_generation_superseded".to_owned(),
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
        // A previous UI task can be dropped after Garth durably records the
        // ingress receipt but before the caller updates its optimistic row.
        // Sent items are terminal and will not be submitted again, so replay
        // their stable local-operation -> Event-id join before draining active
        // work. This also repairs rows left queued across a browser restart.
        if let Some(state_store) = self.state_store.as_ref() {
            let snapshot = outbound.snapshot().await?;
            state_store.write(|store| {
                for item in &snapshot.items {
                    reconcile_sent_outbound_item(store, item);
                }
            });
        }
        let results = OutboundAttemptResults::default();
        let submitter = EventOutboundSubmitter {
            owner: self,
            results: &results,
            accepted_mls_state_store: None,
        };
        let mut completed = 0usize;
        loop {
            let fence = self.resolve_queue_generation_fence(&outbound).await?;
            match outbound
                .submit_next_with_fence(&submitter, &fence, crate::clock::now_utc())
                .await?
            {
                OutboundEngineOutcome::Accepted(item) | OutboundEngineOutcome::Duplicate(item) => {
                    if let Some(state_store) = self.state_store.as_ref() {
                        state_store.write(|store| {
                            reconcile_sent_outbound_item(store, &item);
                        });
                    }
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

    /// Resume durable MLS Commit/Welcome admission delivery from sync paths
    /// that already drive accepted-artifact convergence after cursor advance.
    pub(crate) async fn drain_mls_outbound(&self) -> anyhow::Result<usize> {
        self.drain_mls_outbound_inner(None).await
    }

    /// Resume durable MLS admission delivery and explicitly converge accepted
    /// artifacts once Commit and Welcome have checkpoint finality. The queued
    /// staged snapshot is never trusted as group readiness by itself.
    pub(crate) async fn drain_mls_outbound_with_accepted_store(
        &self,
        state_store: crate::runtime::input::StateStoreHandle,
    ) -> anyhow::Result<usize> {
        self.drain_mls_outbound_inner(Some(state_store)).await
    }

    async fn drain_mls_outbound_inner(
        &self,
        accepted_mls_state_store: Option<crate::runtime::input::StateStoreHandle>,
    ) -> anyhow::Result<usize> {
        let _single_writer = outbound_submit_lock().lock().await;
        let outbound = OutboundEngine::new(crate::outbound_store::InksonOutboundStore::open(
            self.authority()?,
            crate::outbound_store::OutboundLane::MlsDurablePostAccept,
        )?);
        let has_accepted_state_store = accepted_mls_state_store.is_some();
        let results = OutboundAttemptResults::default();
        let submitter = EventOutboundSubmitter {
            owner: self,
            results: &results,
            accepted_mls_state_store,
        };
        let hook = InksonPostAcceptHook;
        let mut completed = 0usize;
        loop {
            // The account-sync drainer may advance immutable Commit/Welcome
            // transport and finality, but it cannot publish the accepted local
            // snapshot. Yield before the outbound engine claims a finalization
            // record: claiming it only to return RetryAfter moves retry_at and
            // can indefinitely stay one step ahead of the UI/store-aware
            // drainer that is capable of completing the durable transition.
            if !has_accepted_state_store
                && mls_outbound_requires_accepted_state_store(&outbound.snapshot().await?)
            {
                return Ok(completed);
            }
            let fence = self.resolve_queue_generation_fence(&outbound).await?;
            match outbound
                .submit_next_with_fence_and_hook(&submitter, &fence, &hook, crate::clock::now_utc())
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
        match crate::recovery_flow::first_backup_gate_status(
            accepted_principal_control_seal,
            &policy,
        ) {
            crate::recovery_flow::FirstBackupGateStatus::Satisfied => Ok(()),
            crate::recovery_flow::FirstBackupGateStatus::Blocked(reason) => {
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
                    Some("principal_control" | "agent_control")
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
        crate::transport::describe_cache::cached_service_describe(&self.http, &self.describe_cache)
            .await
    }

    async fn verify_actor_authority(&self, intent: &EventIntent) -> anyhow::Result<()> {
        // The captured authority is the exact AccountId this submitter was
        // created for. Reject an account actor that substitutes another hosted
        // account while retaining the authenticated principal.
        if let (Some(authority), Some(actor_account)) =
            (self.authority.as_ref(), intent.actor_id().as_account_id())
            && actor_account.principal_id == authority.principal_id
            && actor_account.station_id != authority.station_id
        {
            anyhow::bail!(
                "Event actor names Station {} but the authenticated account is hosted at {}",
                actor_account.station_id,
                authority.station_id
            );
        }
        Ok(())
    }

    pub(crate) async fn service_did(&self) -> anyhow::Result<String> {
        Ok(self
            .describe_cached()
            .await?
            .service_resolution
            .did
            .to_string())
    }

    /// Resolve and freeze the exact Station signer used as the
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
        let now = chrono::Utc::now();
        let current = crate::media::service_route::fetch_current_service_document(
            &reqwest::Client::new(),
            &resolution.normalized_did_document.id,
        )
        .await?;
        arkret_identity::verify_current_service_resolution(
            &resolution,
            &service_id,
            "station",
            &current,
            now,
        )?;
        let document =
            arkret_identity::authenticated_service_document_at(&resolution, &service_id, now)?;
        // This client selects the Station deployment's notary method, not its
        // Account Authority method. Other authorized assertion methods may
        // coexist; the exact selected method still requires authenticated
        // historical evidence before its key is frozen into Realm genesis.
        let method = arkret_sdk::DidUrl::new(format!("{}#notary-key", document.id))
            .map_err(anyhow::Error::msg)?;
        let evidence =
            arkret_identity::service_signer_evidence_for_method_from_authenticated_resolution(
                resolution,
                &service_id,
                method,
                now,
            )
            .map_err(anyhow::Error::from)?;
        let descriptor = arkret_sdk::ed25519_notary_signer_descriptor_from_evidence(&evidence)
            .map_err(anyhow::Error::from)?;
        arkret_sdk::NotaryValue::new(descriptor, 1_000).map_err(anyhow::Error::from)
    }

    /// Resolve the current Seal required by an ephemeral Signal envelope.
    async fn current_signal_seal_for(&self, realm_id: &str) -> anyhow::Result<String> {
        let view = self.seals_frontier_realm_view(realm_id).await?;
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
    /// Send one Signal (`ak.self.signal.command.send.v1`).
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
        authority: &arkret_sdk::AccountId,
        device_id: &arkret_sdk::DeviceId,
        material: &crate::signal::SignalKeyMaterial,
        payload: &crate::signal::SignalPayload,
        state_store: &crate::runtime::input::StateStoreHandle,
    ) -> anyhow::Result<arkret_sdk::SignalSubmitOutcome> {
        let seal_ref = self
            .current_signal_seal_for(scope_ref.realm_id().as_str())
            .await?;
        let header = crate::signal::SignalHeader::new(
            scope_ref,
            arkret_sdk::ActorId::account(authority.clone()),
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
        authority: &arkret_sdk::AccountId,
        header: crate::signal::SignalHeader,
        material: &crate::signal::SignalKeyMaterial,
        payload: &crate::signal::SignalPayload,
        state_store: &crate::runtime::input::StateStoreHandle,
    ) -> anyhow::Result<arkret_sdk::SignalSubmitOutcome> {
        // Realm id and send time are no longer arguments: `signal.md` §1.1
        // forbids a plaintext restating what the signed envelope already
        // carries, so the closed profiles do not have fields for them.
        if header.sender_actor_id.as_account_id() != Some(authority) {
            anyhow::bail!("Signal sender does not match the encryption authority");
        }
        let sequence = crate::signal::next_signal_sequence(
            state_store,
            &header.sender_actor_id,
            &header.sender_device_id,
            &header.scope_ref,
        )
        .await?;
        let plaintext = payload.to_plaintext(&header.sender_actor_id, sequence)?;
        let secure_store = crate::secure_key_store::default_secure_key_store("inkson");
        let encrypted_payload = state_store.write(|store| {
            store.signal_sequence_store_context(&header.sender_actor_id)?;
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
    /// This is the account-client source for the exact accepted Seal basis of
    /// a safety Control Move. Ordinary Events do not query this frontier.
    /// Fails closed (never fabricates a basis) when the server cannot
    /// serve the view or answers for a different Realm.
    pub async fn seals_frontier_realm_view(
        &self,
        realm_id: &str,
    ) -> anyhow::Result<arkret_sdk::RealmSealFrontierView> {
        let (view, _) = self.seals_frontier_realm_state(realm_id).await?;
        Ok(view)
    }

    /// Resolve the accepted Seal named by the single-leaf Realm frontier.
    ///
    /// `event-auth-state-resolution.md` forbids treating any service-derived
    /// root hint as authority, so callers that need the frontier's signed roots
    /// resolve the leaf Seal itself through `ak.self.seals.read.resolve.v1`.
    pub async fn seals_frontier_realm_head(
        &self,
        realm_id: &str,
    ) -> anyhow::Result<arkret_sdk::Seal> {
        let view = self.seals_frontier_realm_view(realm_id).await?;
        let leaf = view.sole_leaf()?.clone();
        let outcome = self
            .http
            .seals_resolve(&arkret_sdk::SelfSealResolveRequestBody {
                realm_id: view.realm_id.clone(),
                selection: arkret_sdk::SealResolveSelection::SealRefs {
                    seal_refs: vec![leaf.clone()],
                },
                history_traversal_access: None,
            })
            .await?;
        outcome
            .into_seals()?
            .into_iter()
            .find(|seal| seal.id == leaf)
            .ok_or_else(|| anyhow::anyhow!("accepted Realm Seal frontier leaf did not resolve"))
    }

    async fn seals_frontier_realm_state(
        &self,
        realm_id: &str,
    ) -> anyhow::Result<(
        arkret_sdk::RealmSealFrontierView,
        Vec<arkret_sdk::AgentPcrSealHeadReceipt>,
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

    /// Consume the exact accepted PCR head returned by the Account Station.
    pub(crate) async fn seals_frontier_agent_head(
        &self,
        realm_id: &str,
    ) -> anyhow::Result<(arkret_sdk::RealmSealFrontierView, arkret_sdk::Seal)> {
        let (view, receipts) = self.seals_frontier_realm_state(realm_id).await?;
        let leaf = view.sole_leaf()?;
        let seal = receipts
            .into_iter()
            .find(|receipt| &receipt.seal.id == leaf)
            .ok_or_else(|| {
                anyhow::anyhow!("seals/frontier omitted the accepted Agent PCR Seal head")
            })?
            .seal;
        anyhow::ensure!(
            seal.realm_id == view.realm_id,
            "Agent PCR head has the wrong Realm binding"
        );
        Ok((view, seal))
    }

    /// `QUERY /_arkret/self/events/frontier` — the
    /// `(realm_id, actor_id)` frontier used for Event authoring.
    pub async fn events_frontier_actor(
        &self,
        actor_id: &arkret_sdk::ActorId,
        realm_id: &arkret_sdk::RealmId,
    ) -> anyhow::Result<arkret_sdk::RealmActorFrontierView> {
        let selector = arkret_sdk::EventsFrontierSelector::RealmActor {
            actor_id: actor_id.clone(),
            realm_id: realm_id.clone(),
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
    /// canonical `ServiceDescribe` shape (OpenAPI `ak.self.events.read.describe.v1`).
    /// the former soland-private `SolandEventsDescribeResBody`
    /// mirror (with its non-spec `capabilities` blob) was removed.
    pub async fn events_describe(&self) -> anyhow::Result<arkret_sdk::ServiceDescribe> {
        self.http
            .events_describe()
            .await
            .map_err(|error| anyhow::anyhow!("events describe: {error}"))
    }

    pub(crate) async fn event_proof_context(
        &self,
        digest_suite: arkret_sdk::DigestSuite,
        plane: arkret_sdk::CbsEffectPlane,
    ) -> anyhow::Result<crate::event_signer::ProducerProofContext> {
        // Durable Event envelopes are portable Realm facts. Binding their
        // proof to the authoring Station would make the original
        // signature unverifiable after federation to another Realm host.
        let authority = self.authority()?;
        let signer = crate::event_signer::active_signer()
            .ok_or_else(|| anyhow::anyhow!("active endpoint signer is unavailable"))?;
        let device_id = signer
            .device_id()
            .ok_or_else(|| anyhow::anyhow!("active endpoint signer has no device id"))?;
        let actor = authority.to_string();
        let signer_key = signer
            .public_key_multibase()
            .as_deref()
            .and_then(crate::identity::device_directory::public_key_from_directory_value)
            .ok_or_else(|| anyhow::anyhow!("active endpoint signer public key is invalid"))?;
        let (retained_key, evidence_ref) = crate::identity::device_directory::retained_device_authoring_evidence(
            &actor,
            device_id,
            plane,
        )
        .ok_or_else(|| {
                    anyhow::anyhow!(
                        "frontier_unavailable: verified {} signer-resolution evidence is unavailable for the active device",
                        plane.as_str()
                    )
                })?;
        if retained_key != signer_key {
            anyhow::bail!(
                "frontier_unavailable: retained device evidence does not bind the active signer"
            );
        }
        Ok(crate::event_signer::ProducerProofContext::new()
            .with_digest_suite(digest_suite)
            .with_signer_resolution_evidence_ref(evidence_ref))
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
            state_store
                .read(|store| store.station_realm_digest_suite(realm_id.as_str()))
                .ok_or_else(|| {
                    anyhow::anyhow!("Realm {realm_id} has no current Station digest suite")
                })?
        };
        Ok(digest_suite)
    }

    pub(crate) async fn refresh_realm_governance_frontier(
        &self,
        realm_id: &str,
    ) -> anyhow::Result<arkret_sdk::DigestSuite> {
        let state_store = self.state_store.clone().ok_or_else(|| {
            anyhow::anyhow!("Realm authoring requires a local governance checkpoint store")
        })?;
        crate::mls::governance_proof::refresh_realm_frontier_with_http(
            &self.http,
            state_store,
            realm_id,
        )
        .await
        .map_err(anyhow::Error::msg)
    }

    async fn post_persisted_signed_sdk_event(
        &self,
        signed: &arkret_sdk::AuthoredEvent,
        idempotency_key: &str,
        canonical_body_bytes: &[u8],
    ) -> anyhow::Result<SubmitEventResult> {
        validate_signed_sdk_event_for_submit(signed.event(), signed.digest_suite())?;
        // Authoring already failed closed on an invalid Realm detail and froze
        // the exact governance/CAS basis into these bytes. A notification can
        // invalidate the local projection between signing and this POST; doing
        // the same local check again here would starve writes on an active
        // Realm. The receiver remains authoritative and rejects a stale
        // frontier, which the durable queue can then handle explicitly.
        if arkret_sdk::canonical::canonical_json_bytes(signed)? != canonical_body_bytes {
            anyhow::bail!("persisted signed Event bytes do not match the queued Event");
        }
        // These canonical bytes bind the holder-local AuthoredEvent record,
        // including its digest suite and frozen MLS leaf input. They are not
        // the HTTP request body. The receiver dedupes on the signed Event.
        // The publication wrapper is rebuilt on every attempt: the
        // lease is not part of the Event and it can expire while the write is
        // queued, and an Event first published after its lease expired is
        // permanently rejected (`offline-publication.md` §2). Replaying a
        // stale wrapper would hide that from the user instead of prompting a
        // re-authorization.
        let submission = crate::authorization_lease::standard_initial_submission_with_publication(
            &self.http,
            signed,
            signed.digest_suite(),
            signed.mls_frontier_leaves(),
            signed.publication_event(),
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
        tracing::debug!(
            event_id = %signed.event_id,
            status = ?response.status,
            accepted = response.accepted.len(),
            rejected = response.rejections.len(),
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
        self.submit_sdk_event_queued(operation, None, None).await
    }

    /// Submit a pre-join Event using the facts verified by the account's own
    /// Station. The invitee cannot read membership-gated Realm history.
    pub(crate) async fn submit_prepared_join_event(
        &self,
        prepared: &arkret_sdk::RealmJoinPrepareOutcome,
    ) -> anyhow::Result<SubmitEventResult> {
        let _single_writer = outbound_submit_lock().lock().await;
        prepared.validate_structural()?;
        if prepared.expires_at <= crate::clock::now_utc() {
            anyhow::bail!("prepared join expired before signing");
        }
        let captured_account = self.authority()?.clone();
        let captured_scope = crate::secure_key_store::active_device_seed_scope()
            .ok_or_else(|| anyhow::anyhow!("prepared join requires an installed device scope"))?;
        if prepared.account_id != captured_account || captured_scope.authority != captured_account {
            anyhow::bail!("prepared join does not belong to the captured complete AccountId");
        }
        let envelope = prepared.unsigned_event.to_event()?;
        let intent = EventIntent::from_authored(&envelope);
        self.ensure_recovery_material_ready(
            &intent,
            Some(&prepared.governance_facts.encryption_profile),
        )
        .await?;
        let generation = crate::identity::authoring_generation::AuthoringGeneration {
            authority_model:
                crate::identity::authoring_generation::AuthoringAuthorityModel::AcceptedDevice,
            authority_principal_id: prepared.account_id.principal_id.clone(),
            generation_ref: prepared.authoring_device_generation_ref.to_string(),
        };
        if let Some(known) =
            crate::identity::authoring_generation::cached_event_authoring_generation(
                &EventAuthorityFacts::from_intent(&intent),
            )?
        {
            if known.authority_principal_id != generation.authority_principal_id
                || known
                    .generation_ref
                    .parse::<u64>()
                    .ok()
                    .is_some_and(|known| known > prepared.authoring_device_generation_ref)
            {
                anyhow::bail!("prepared join contradicts a locally known device generation");
            }
        }
        let suite = prepared.governance_facts.digest_algorithm;
        let mut event =
            arkret_sdk::AuthoredEvent::from_verified_with_digest_suite(envelope, suite)?;
        let current_scope = crate::secure_key_store::active_device_seed_scope();
        let signer = crate::event_signer::active_signer()
            .ok_or_else(|| anyhow::anyhow!("prepared join signing device is unavailable"))?;
        validate_prepared_join_signing_scope(
            &prepared.account_id,
            &captured_account,
            &captured_scope,
            current_scope.as_ref(),
            signer.device_id(),
        )?;
        if prepared.expires_at <= crate::clock::now_utc() {
            anyhow::bail!("prepared join expired while checking signing prerequisites");
        }
        signer
            .sign_sdk_event_with_context(
                &mut event,
                self.event_proof_context(suite, signer_evidence_plane_for_intent(&intent)?)
                    .await?,
            )
            .map_err(|e| anyhow::anyhow!("sign prepared join Event: {e}"))?;
        let canonical_body_bytes = arkret_sdk::canonical::canonical_json_bytes(&event)?;
        let key = prepared.request_id.to_string();
        let queued = QueuedSdkEvent::authored(
            QueuedEventIntent::with_pinned_cbs_basis(intent, suite),
            event,
            key.clone(),
            key,
            canonical_body_bytes,
            None,
            generation,
            None,
        )?;
        self.enqueue_and_drive_sdk_event(queued, None, false).await
    }

    async fn submit_sdk_event_queued(
        &self,
        operation: &LocalOperation,
        post_accept: Option<PostAcceptAction>,
        state_store: Option<crate::runtime::input::StateStoreHandle>,
    ) -> anyhow::Result<SubmitEventResult> {
        let intent = operation.intent();
        anyhow::ensure!(
            (intent.kind() == &arkret_sdk::EventKind::AgentActionApprove)
                == operation.publication_event().is_some(),
            "a complete publication Event is required exactly for Agent action approval"
        );
        self.ensure_recovery_material_ready(intent, None).await?;
        self.refresh_direct_message_authority(intent, state_store.as_ref())
            .await?;
        // `authorization_ref` is a bound member of the semantic intent, so the
        // authority-root claim must be decided BEFORE the intent freezes. The
        // authoring-time stamp then finds the claim already present and leaves
        // it alone, which keeps every attempt's envelope equal to its intent.
        let intent = self
            .stamp_realm_authority_root_claim(intent.clone(), state_store.as_ref())
            .await;
        // The issuer attestation is part of the capability artifact itself,
        // hence part of the immutable semantic intent.
        validate_capability_grant_payload(&intent)?;
        let local_operation_id = operation.local_operation_id().to_string();
        // Freezing and enqueueing is the normal durable-submit path; keep its
        // correlation fields available without presenting success as a browser
        // warning.
        tracing::debug!(
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
        if cbs_effect_plane_for_intent(&intent)? == Some(CbsEffectPlane::Control)
            && intent.kind() != &arkret_sdk::EventKind::RealmCreate
        {
            let realm_id = intent.realm_id_opt().ok_or_else(|| {
                anyhow::anyhow!(
                    "{} needs a verified Realm checkpoint but carries no Realm scope",
                    intent.kind().as_str()
                )
            })?;
            let checkpoint_store = state_store
                .clone()
                .or_else(|| self.state_store.clone())
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "{} authoring requires a local governance checkpoint store",
                        intent.kind().as_str()
                    )
                })?;
            crate::mls::governance_proof::refresh_realm_frontier_with_http(
                &self.http,
                checkpoint_store,
                realm_id.as_str(),
            )
            .await
            .map_err(anyhow::Error::msg)?;
        }
        let digest_suite =
            self.trusted_digest_suite_for_intent(&intent, None, state_store.as_ref())?;
        tracing::warn!(
            local_operation_id = %local_operation_id,
            kind = %intent.kind().as_str(),
            "submit prerequisites resolved; waiting for durable outbound writer"
        );
        let mut queued_intent = QueuedEventIntent::new(intent, digest_suite);
        queued_intent.publication_event = operation.publication_event().cloned();
        self.enqueue_and_drive_sdk_event(
            QueuedSdkEvent::unauthored(
                queued_intent,
                local_operation_id.clone(),
                local_operation_id,
                None,
                authoring_generation,
                post_accept,
            )?,
            None,
            true,
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
        self.enqueue_and_drive_sdk_event(queued, None, false).await
    }

    /// Persist an MLS Add commit together with the exact signed Welcome(s) and
    /// staged post-commit material before the first network write. Garth only
    /// marks the outbound item sent after every Welcome reaches finality and the
    /// accepted-artifact consumer has independently proven the winning
    /// checkpoint and atomically published the snapshot/history secret. A reload
    /// at any await boundary resumes the same immutable admission saga.
    pub(crate) async fn submit_mls_admission_with_snapshot(
        &self,
        commit: &crate::mls::admission::MlsAdmissionAuthoringPlan,
        welcomes: Vec<crate::mls::admission::WelcomeIntentStep>,
        realm_id: String,
        actor_id: String,
        device_id: String,
        snapshot: crate::mls::persistence::MlsLocalCheckpointEnvelope,
        state_store: &crate::runtime::input::StateStoreHandle,
    ) -> anyhow::Result<SubmitEventResult> {
        if welcomes.is_empty() {
            anyhow::bail!("MLS admission requires at least one Welcome");
        }
        let _single_writer = outbound_submit_lock().lock().await;
        let welcome_count = welcomes.len();
        let mut authoring_steps = commit.authoring_steps();
        authoring_steps.push(Box::new(move |authored| {
            let authored_commit = authored
                .last()
                .filter(|event| event.kind == arkret_sdk::EventKind::MlsCommit)
                .ok_or_else(|| {
                    anyhow::anyhow!("MLS Welcome authoring requires the final Commit")
                })?;
            welcomes
                .into_iter()
                .map(|step| step(authored_commit.event_id()).map_err(anyhow::Error::msg))
                .collect()
        }));
        let mut authored = self.author_event_unit(authoring_steps).await?;
        if authored.len() <= welcome_count {
            anyhow::bail!("MLS admission unit produced no proposal Events or Commit");
        }
        let authored_welcomes = authored.split_off(authored.len() - welcome_count);
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
        // The Welcome names the Commit by its FINAL `event_id` and occupies the
        // next position in the same actor chain. Authoring it in a second unit
        // would read the pre-Commit remote frontier and freeze a stale
        // `actor_seq`, even though transport correctly submits it after Commit.
        let digest_suite = authored_commit.digest_suite();
        let canonical_body_bytes = arkret_sdk::canonical::canonical_json_bytes(&authored_commit)?;
        let transport_idempotency_key = authored_commit.event_id().to_string();
        for welcome in &authored_welcomes {
            let accepted_candidate = welcome.event().clone();
            let accepted_bytes = arkret_sdk::canonical::canonical_json_bytes(&accepted_candidate)?;
            if accepted_bytes.len() > arkret_sdk::MAX_EVENT_ENVELOPE_BYTES {
                anyhow::bail!(
                    "payload_too_large: MLS Welcome accepted Event candidate is {} bytes; maximum is {}",
                    accepted_bytes.len(),
                    arkret_sdk::MAX_EVENT_ENVELOPE_BYTES
                );
            }
        }
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
                    welcomes: garth::QueuedMlsWelcomes {
                        events: authored_welcomes,
                    },
                    snapshot: snapshot.into_queued(),
                }),
            )?,
            Some(state_store.clone()),
            false,
        )
        .await
    }

    async fn enqueue_and_drive_sdk_event(
        &self,
        queued: QueuedSdkEvent,
        accepted_mls_state_store: Option<crate::runtime::input::StateStoreHandle>,
        manage_single_writer: bool,
    ) -> anyhow::Result<SubmitEventResult> {
        // Most callers already hold the runtime-wide writer gate while they
        // author a multi-step unit. Ordinary single-Event submissions acquire
        // it here so a RetryAt wait can yield to account-sync convergence and
        // reacquire before touching the durable engine again.
        let mut single_writer = if manage_single_writer {
            let guard = outbound_submit_lock().lock().await;
            tracing::debug!(
                transaction_id = %queued.local_operation_id,
                kind = %queued.intent.kind().as_str(),
                "durable outbound writer acquired"
            );
            Some(guard)
        } else {
            None
        };
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
                        .compact_terminal_before(
                            crate::clock::now_utc() + chrono::Duration::seconds(1),
                        )
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
                            crate::clock::now_utc(),
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
                    crate::clock::now_utc(),
                )
                .await?;
        }

        let results = OutboundAttemptResults::default();
        let submitter = EventOutboundSubmitter {
            owner: self,
            results: &results,
            accepted_mls_state_store,
        };
        let hook = InksonPostAcceptHook;
        let mut interactive_retry_count = 0_u8;
        loop {
            let fence = match self.resolve_queue_generation_fence(&outbound).await {
                Ok(fence) => fence,
                Err(error)
                    if outbound_retry_delay(&error).is_some() && interactive_retry_count < 4 =>
                {
                    interactive_retry_count += 1;
                    drop(single_writer.take());
                    crate::runtime_helpers::sleep_for(Duration::from_millis(1_100)).await;
                    if manage_single_writer {
                        single_writer = Some(outbound_submit_lock().lock().await);
                    }
                    continue;
                }
                Err(error) if outbound_retry_delay(&error).is_some() => {
                    tracing::warn!(
                        %transaction_id,
                        error = %format!("{error:#}"),
                        "durable Event generation fence refresh failed; keeping Event queued"
                    );
                    return Err(DurablyQueuedError {
                        operation_id: transaction_id,
                        reason: None,
                    }
                    .into());
                }
                Err(error) => return Err(error),
            };
            match outbound
                .submit_next_with_fence_and_hook(&submitter, &fence, &hook, crate::clock::now_utc())
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
                OutboundEngineOutcome::RetryAt { item, at } => {
                    let retry_transaction_id = item.transaction_id.clone();
                    tracing::debug!(
                        %transaction_id,
                        %retry_transaction_id,
                        %at,
                        "event remains in durable outbound queue"
                    );
                    let retry_limit = if self.state_store.as_ref().is_some_and(|store| {
                        store.read(|state| state.realm_detail_invalidated(item.realm_id.as_str()))
                    }) {
                        // Demand-sync invalidations normally converge in a few
                        // seconds, including multi-frame detail baselines. Keep
                        // this foreground action attached long enough to report
                        // the accepted result, while unrelated transport errors
                        // retain the short interactive retry budget below.
                        24
                    } else {
                        4
                    };
                    if interactive_retry_count < retry_limit {
                        interactive_retry_count += 1;
                        let delay = (at - crate::clock::now_utc())
                            .to_std()
                            .unwrap_or_default()
                            .saturating_add(Duration::from_millis(25));
                        drop(single_writer.take());
                        crate::runtime_helpers::sleep_for(delay).await;
                        if manage_single_writer {
                            single_writer = Some(outbound_submit_lock().lock().await);
                        }
                        continue;
                    }
                    let reason = results
                        .retryable
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner)
                        .remove(&retry_transaction_id);
                    return Err(DurablyQueuedError {
                        operation_id: transaction_id.clone(),
                        reason: reason.map(|reason| {
                            if retry_transaction_id == transaction_id {
                                reason
                            } else {
                                format!(
                                    "blocked by earlier operation {retry_transaction_id}: {reason}"
                                )
                            }
                        }),
                    }
                    .into());
                }
                OutboundEngineOutcome::Rejected { item, reason }
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
                    anyhow::bail!("queued operation {transaction_id} was rejected: {reason}");
                }
                OutboundEngineOutcome::Terminal { item, reason }
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
                    results
                        .retryable
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner)
                        .remove(&transaction_id);
                    anyhow::bail!(
                        "queued operation {transaction_id} reached a terminal state: {reason}"
                    );
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
                        reason: None,
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
    async fn reauthor_after_actor_frontier_conflict(
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
        let effect_plane = signer_evidence_plane_for_intent(intent)?;
        if effect_plane == CbsEffectPlane::Control
            && let Some(realm_id) = intent.realm_id_opt()
        {
            self.ensure_realm_detail_current(realm_id.as_str())?;
        }
        self.verify_actor_authority(intent).await?;
        let mut intent = intent.clone();
        // The authority-root claim is a producer-signed envelope member and a
        // SEMANTIC decision: a fresh submission may resolve one, while a replay
        // of a frozen intent must reproduce that intent's choice verbatim.
        // Stamping a claim the frozen intent does not carry would make the
        // authored envelope diverge from its intent, and the queue's semantic
        // guard would (correctly) cancel the item.
        if authoring == SemanticAuthoring::Fresh {
            intent = self.stamp_realm_authority_root_claim(intent, None).await;
        }
        validate_capability_grant_payload(&intent)?;
        intent = self.stamp_cbs_basis_for_intent(intent).await?;
        let (actor_seq, prev_refs) = self.resolve_actor_chain_basis(&intent).await?;
        intent = intent.with_prev_refs(prev_refs);
        let hlc = self.issue_intent_hlc(&intent).await?;
        let proof_context = self.event_proof_context(digest_suite, effect_plane).await?;
        let mut event = intent
            .clone()
            .author_with_digest_suite(actor_seq, hlc, proof_context.digest_suite)
            .map_err(|error| anyhow::anyhow!("author Event: {error}"))?;
        validate_projected_cbs_plane(&event)?;
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
            // idempotent-resubmit; a frontier re-author changes the content and gets
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
        proof_context: crate::event_signer::ProducerProofContext,
    ) -> anyhow::Result<()> {
        if matches!(
            event.kind,
            arkret_sdk::EventKind::MlsGenesis | arkret_sdk::EventKind::MlsCommit
        ) && event.mls_frontier_leaves().is_none()
        {
            let state = self.state_store.as_ref().ok_or_else(|| {
                anyhow::anyhow!("MLS authoring requires its captured state store")
            })?;
            let leaves = state
                .read(|store| store.mls_frontier_input_for_authored_event(event.event()))
                .map_err(anyhow::Error::msg)?;
            event.bind_mls_frontier_leaves(leaves)?;
        }
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
        if intent.actor_id().signing_principal_id() != &material.actor_id {
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
        let mut attempt = self
            .author_intent(
                &intent.intent,
                local_operation_id,
                SemanticAuthoring::FrozenIntent,
                intent.digest_suite,
            )
            .await?;
        if let Some(publication) = &intent.publication_event {
            attempt
                .envelope
                .bind_publication_event(publication.clone())?;
            attempt.canonical_body_bytes =
                arkret_sdk::canonical::canonical_json_bytes(&attempt.envelope)?;
        }
        Ok(attempt)
    }

    /// Resolve the CBS basis this attempt authors against.
    ///
    /// A basis the producer already pinned on the intent is left alone: a
    /// pre-join `ak.invite.accept` carries the only Seal view its author could
    /// read, and re-resolving it would need membership the invitee lacks.
    async fn stamp_cbs_basis_for_intent(&self, intent: EventIntent) -> anyhow::Result<EventIntent> {
        if cbs_exempt_reducer_kind(intent.kind()) {
            return Ok(intent);
        }
        let Some(plane) = cbs_effect_plane_for_intent(&intent)? else {
            return Ok(intent);
        };
        if (plane == CbsEffectPlane::Control && intent.seal_basis().is_some())
            || (plane == CbsEffectPlane::Data
                && intent.auth_context().is_some()
                && intent.data_basis().is_some())
        {
            return Ok(intent);
        }
        let realm_id = intent.realm_id_opt().cloned().ok_or_else(|| {
            anyhow::anyhow!(
                "{} needs a CBS basis but carries no Realm scope",
                intent.kind().as_str()
            )
        })?;
        let intent = if plane == CbsEffectPlane::Control {
            let seal_view = self.seals_frontier_realm_view(realm_id.as_str()).await?;
            intent.with_seal_basis(seal_view.seal_basis())
        } else {
            let data_basis = match intent.data_basis().cloned() {
                Some(data_basis) => data_basis,
                None => {
                    let store = self.state_store.as_ref().ok_or_else(|| {
                        anyhow::anyhow!(
                            "frontier_unavailable: {} authoring has no verified local authority store",
                            intent.kind().as_str()
                        )
                    })?;
                    let authority_ref = store
                        .read(|state| state.confirmed_seal_ref_for_realm(realm_id.as_str()))
                        .ok_or_else(|| {
                            anyhow::anyhow!(
                                "frontier_unavailable: {} authoring has no unique verified authority decision",
                                intent.kind().as_str()
                            )
                        })?;
                    arkret_sdk::SealId::new(authority_ref).map_err(|error| {
                        anyhow::anyhow!("verified authority reference is invalid: {error}")
                    })?
                }
            };
            let intent = intent.with_data_basis(data_basis.clone());
            if intent.auth_context().is_some() {
                intent
            } else {
                let auth_context = ordinary_event_auth_context(&intent, vec![data_basis])?;
                intent.with_auth_context(auth_context)
            }
        };
        // This is routine authoring telemetry. Ordinary Events carry verified
        // authority evidence in AuthContext and name the open Seal publication
        // window in data_basis; optional preconditions are evaluated against
        // their signed causal basis.
        tracing::debug!(
            kind = %intent.kind().as_str(),
            has_seal_basis = intent.seal_basis().is_some(),
            authorization_ref = ?intent.authorization_ref(),
            "authored CBS basis for submit attempt"
        );
        Ok(intent)
    }

    /// Refresh before freezing the semantic intent. A service-observed binding
    /// closes bootstrap but never substitutes for a locally verified Seal.
    async fn refresh_direct_message_authority(
        &self,
        intent: &EventIntent,
        state_store: Option<&crate::runtime::input::StateStoreHandle>,
    ) -> anyhow::Result<()> {
        if intent.kind() != &arkret_sdk::EventKind::MessageCreate {
            return Ok(());
        }
        let Some(realm) = intent.realm_id_opt() else {
            return Ok(());
        };
        let store = state_store.or(self.state_store.as_ref()).ok_or_else(|| {
            anyhow::anyhow!("Direct Conversation requires an account state store")
        })?;
        if store.read(|state| state.realm_collaboration_role(realm.as_str()))
            != Some(arkret_sdk::CollaborationRealmRole::DirectConversation)
        {
            return Ok(());
        }
        let authority = self
            .authority
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Direct Conversation requires an account"))?;
        if store.read(|state| {
            state
                .direct_message_context(realm.as_str(), intent.actor_id())
                .is_some()
        }) {
            return Ok(());
        }
        let epoch = crate::identity::device_directory::cache_epoch();
        let peer = store
            .read(|state| state.direct_conversation_peer(realm.as_str()))
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "Open the Direct Conversation to refresh its exact peer coordinates"
                )
            })?;
        let query_sequence = crate::mls::direct_binding::begin_query(authority, &peer)?;
        let outcome = self
            .http
            .direct_conversation_resolve(
                &arkret_sdk::direct_conversation_ops::DirectConversationResolveRequestBody {
                    peer: peer.clone(),
                },
            )
            .await?;
        anyhow::ensure!(
            outcome
                .coordinates()
                .is_some_and(|coordinates| coordinates.realm_id == *realm),
            "Direct Conversation resolver returned another Realm"
        );
        crate::mls::direct_binding::install_resolved_message_context(
            &self.http,
            store,
            authority,
            epoch,
            query_sequence,
            peer,
            &outcome,
        )
        .await?;
        anyhow::ensure!(
            store.read(|state| state
                .direct_message_context(realm.as_str(), intent.actor_id())
                .is_some()),
            "Direct Conversation authoring is not ready"
        );
        Ok(())
    }

    /// Stamp the registered authority-root claim on an Event the Realm's root
    /// controller authors directly.
    ///
    /// Best-effort by design: a resolution failure leaves the Event unstamped,
    /// so a member's ordinary grant path is never blocked by a transient
    /// lookup error, and a wrongly-claimed root can only fail closed at
    /// admission (`realm_authority_controller_mismatch`), never widen.
    async fn stamp_realm_authority_root_claim(
        &self,
        intent: EventIntent,
        state_store: Option<&crate::runtime::input::StateStoreHandle>,
    ) -> EventIntent {
        let state_store = state_store.or(self.state_store.as_ref());
        if intent.authorization_ref().is_some()
            || intent.executed_by().is_some()
            || intent.applet_id().is_some()
            || !realm_authority_root_covers_event_kind(intent.kind().as_str())
        {
            return intent;
        }
        let Some(realm_id) = intent.realm_id_opt().cloned() else {
            return intent;
        };
        let local_direct_conversation = state_store.is_some_and(|store| {
            store.read(|state| state.realm_collaboration_role(realm_id.as_str()))
                == Some(arkret_sdk::CollaborationRealmRole::DirectConversation)
        });
        if intent.kind() == &arkret_sdk::EventKind::MessageCreate && local_direct_conversation {
            if let Some(context) = state_store.and_then(|store| {
                store.read(|state| {
                    state.direct_message_context(realm_id.as_str(), intent.actor_id())
                })
            }) {
                return intent
                    .with_authorization_ref(
                        arkret_sdk::AuthorizationRef::new(
                            arkret_wire::AuthoritySourceId::DIRECT_CONVERSATION_PARTICIPANT_V1,
                        )
                        .expect("registered Direct Conversation authority source"),
                    )
                    .with_ref(arkret_sdk::EventRef::new(
                        context.binding_event_ref.to_string(),
                        "direct_conversation_binding",
                    ));
            }
            return intent;
        }
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
        if matches!(authority, Some(RealmCreateAuthority::DirectConversation)) {
            if matches!(
                intent.kind(),
                arkret_sdk::EventKind::MlsProposal
                    | arkret_sdk::EventKind::MlsCommit
                    | arkret_sdk::EventKind::MlsWelcome
            ) {
                let bound = self
                    .http
                    .contacts_list()
                    .await
                    .ok()
                    .is_some_and(|contacts| {
                        contacts
                            .contacts
                            .into_iter()
                            .filter_map(|row| row.direct_conversation)
                            .any(|binding| binding.realm_id == realm_id)
                    });
                if !bound {
                    let founding_ref = format!(
                        "ak:event:{}",
                        realm_id.as_str().trim_start_matches("ak:realm:")
                    );
                    return intent.with_authorization_ref(arkret_sdk::AuthorizationRef::new(
                        arkret_wire::AuthoritySourceId::DIRECT_CONVERSATION_BOOTSTRAP_PARTICIPANT_V1,
                    ).expect("registered bootstrap authority source"))
                        .with_ref(arkret_sdk::EventRef::new(founding_ref, "direct_conversation_founding_unit"));
                }
            }
            return intent;
        }
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

    /// Read the immutable founding Event through the Account Station's exact resolver.
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
        let realm = arkret_sdk::RealmId::new(realm_id.to_owned())?;
        let create_id = arkret_sdk::EventId::new(format!(
            "ak:event:{}",
            realm.as_str().trim_start_matches("ak:realm:")
        ))?;
        let outcome = self
            .http
            .events_resolve(&arkret_sdk::EventsResolveRequestBody {
                event_ids: vec![create_id.clone()],
                event_digests: Vec::new(),
                include_payload: Some(true),
                history_traversal_access: None,
                max_response_bytes: Some(8 * 1024 * 1024),
            })
            .await?;
        anyhow::ensure!(
            outcome
                .events
                .iter()
                .all(|event| event.event_id == create_id
                    && event.realm_id == realm
                    && event.kind == arkret_sdk::EventKind::RealmCreate),
            "Station returned a different Realm founding Event"
        );
        let resolved = realm_create_authority_from_events(&outcome.events, realm_id);
        if let Some(authority) = &resolved {
            realm_create_authority_cache()
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .insert(realm_id.to_owned(), authority.clone());
        }
        // A temporarily unavailable or unreadable founding Event is not cached.
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
        let Some(realm_id) = intent.realm_id_opt() else {
            return Ok((0, Vec::new()));
        };
        let actor_id = intent.actor_id();
        match self.events_frontier_actor(actor_id, realm_id).await {
            Ok(frontier) => actor_chain_basis_from_frontier(realm_id, actor_id, frontier),
            Err(error) => Err(actor_frontier_refresh_error(&actor_id.to_string(), error)),
        }
    }

    async fn issue_intent_hlc(&self, intent: &EventIntent) -> anyhow::Result<arkret_sdk::Hlc> {
        Ok(
            crate::signing_stamp::issue_event_stamp_for(intent.actor_id(), intent.realm_id_opt())
                .await?
                .hlc,
        )
    }

    /// `ak.self.events.command.submit.v1` in batch form over typed envelopes. Spec binds
    /// events.submit to `POST /_arkret/self/events` and distinguishes the three
    /// accepted body shapes (single envelope,
    /// [`arkret_sdk::EventsSubmitBatchRequestBody`],
    /// [`arkret_sdk::EventsSubmitFederationRequestBody`]) by JSON shape, not
    /// by URL suffix. The federation shape is S2S only and inkson MUST
    /// NEVER serialise it.
    ///
    /// SDK Events MUST already be signed by the caller (typically via
    /// `event_signer::sign_sdk_event_with_active_context`) — the batch path
    /// does not auto-sign because callers may need to bind a dependent unit
    /// before the per-event helper can submit it.
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
        // The former `capabilities.batch_submit` probe (a
        // non-spec soland capability field) was removed. The batch request
        // body is one of the three spec-defined `ak.self.events.command.submit.v1`
        // shapes (distinguished by JSON shape), so it is sent
        // unconditionally — no capability negotiation exists in the spec.
        for sdk_event in sdk_events {
            if arkret_schema::classify_event_execution(sdk_event.event())?
                == Some(CbsEffectPlane::Control)
            {
                self.ensure_realm_detail_current(sdk_event.realm_id.as_str())?;
            }
            validate_signed_sdk_event_for_submit(sdk_event.event(), sdk_event.digest_suite())?;
        }
        // `idempotency_key` is not a body field in v1: it travels only in the
        // `Idempotency-Key` header.
        let realm_bootstrap_unit = first_event.kind == arkret_sdk::EventKind::RealmCreate;
        let native_anchor_unit = realm_bootstrap_unit
            && sdk_events.len() == 2
            && sdk_events[1].kind == arkret_sdk::EventKind::DeviceAuthorize;
        let mut submissions = Vec::with_capacity(sdk_events.len());
        for event in sdk_events {
            let submission = if let Some(context) = bare_online_bootstrap_context(
                realm_bootstrap_unit,
                native_anchor_unit,
                event.event(),
            ) {
                let submission = arkret_wire::EventInitialSubmission::online(event.event().clone());
                submission
                    .validate_structural_in_context(context, event.digest_suite())
                    .map_err(anyhow::Error::from)?;
                submission
            } else {
                crate::authorization_lease::standard_initial_submission_with_publication(
                    &self.http,
                    event,
                    event.digest_suite(),
                    event.mls_frontier_leaves(),
                    event.publication_event(),
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
        let mut authored: Vec<arkret_sdk::AuthoredEvent> = Vec::with_capacity(steps.len());
        let mut chain = UnitAuthoringChain::default();
        for step in steps {
            for mut intent in step(&authored)? {
                self.verify_actor_authority(&intent).await?;
                validate_capability_grant_payload(&intent)?;
                chain.observe(&intent, authored.is_empty())?;
                let (actor_seq, prev_refs) = match chain.basis_within_unit(&intent)? {
                    Some(basis) => basis,
                    None => self.resolve_actor_chain_basis(&intent).await?,
                };
                if !chain.is_genesis_unit() {
                    intent = self.stamp_cbs_basis_for_intent(intent).await?;
                }
                intent = intent.with_prev_refs(prev_refs);
                let hlc = self.issue_intent_hlc(&intent).await?;
                let effect_plane = signer_evidence_plane_for_intent(&intent)?;
                let proof_context = match (
                    intent.kind() == &arkret_sdk::EventKind::RealmCreate,
                    chain.genesis_digest_suite(),
                ) {
                    // The Realm create Event is the SHA-256 bootstrap identity.
                    // Other founding Events use the live suite declared by its
                    // payload before the first Seal exists.
                    (true, Some(_)) => {
                        self.event_proof_context(arkret_sdk::DigestSuite::Sha256, effect_plane)
                            .await?
                    }
                    (false, Some(digest_suite)) => {
                        self.event_proof_context(digest_suite, effect_plane).await?
                    }
                    (_, None) => {
                        let digest_suite = self.trusted_digest_suite_for_intent(
                            &intent,
                            None,
                            self.state_store.as_ref(),
                        )?;
                        self.event_proof_context(digest_suite, effect_plane).await?
                    }
                };
                let mut event = intent
                    .clone()
                    .author_with_digest_suite(actor_seq, hlc, proof_context.digest_suite)
                    .map_err(|error| anyhow::anyhow!("author unit Event: {error}"))?;
                if !chain.is_genesis_unit() {
                    validate_projected_cbs_plane(&event)?;
                }
                self.sign_sdk_event_for_intent(&intent, &mut event, proof_context)?;
                chain.record(&event);
                authored.push(event);
            }
        }
        validate_authored_unit_shape(&authored)?;
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

    pub(crate) async fn prepare_initial_submissions(
        &self,
        events: &[arkret_sdk::AuthoredEvent],
    ) -> anyhow::Result<Vec<arkret_wire::EventInitialSubmission>> {
        let mut submissions = Vec::with_capacity(events.len());
        for event in events {
            submissions.push(
                crate::authorization_lease::standard_initial_submission_with_publication(
                    &self.http,
                    event,
                    event.digest_suite(),
                    event.mls_frontier_leaves(),
                    event.publication_event(),
                )
                .await?,
            );
        }
        Ok(submissions)
    }

    /// Prepare the single online submission used by an authority-authored
    /// human self-PCR aggregate operation (for example Agent provisioning).
    /// The accepted create comes from verified durable bootstrap evidence;
    /// ordinary PCR history scans are not an authority-discovery surface.
    pub(crate) fn prepare_authority_authored_self_principal_submission(
        &self,
        event: &arkret_sdk::AuthoredEvent,
        accepted_create: &arkret_sdk::Event,
    ) -> anyhow::Result<arkret_wire::EventInitialSubmission> {
        crate::authorization_lease::standard_authority_authored_self_principal_submission(
            event,
            event.digest_suite(),
            accepted_create,
        )
    }

    /// `POST /_arkret/self/signal` — `ak.self.signal.command.send.v1`.
    ///
    /// The Signal Extension rail is encrypted-only: the exact signal kind and
    /// target live inside `encrypted_payload` and are never on the outer
    /// header, so this method can only re-check the structural envelope. The
    /// plaintext ephemeral rail (`POST /_arkret/self/ephemeral`) does not exist
    /// in v1 and a Signal MUST NOT travel via `ak.self.events.command.submit.v1`.
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
    /// `ak.gate.account.command.pair_agent_key.v1`. The runtime generated the
    /// key and PoP; the controller signs `authorize_event` locally before this
    /// method submits the pairing request.
    pub(crate) async fn agent_key_pair(
        &self,
        body: &arkret_models_collaboration::agent_operations::AgentKeyPairRequestBody,
    ) -> anyhow::Result<arkret_models_collaboration::agent_operations::AgentKeyPairOutcome> {
        let station_url = self.http.base_url().as_str();
        let authority =
            crate::identity::account_auth::AuthorityResolver::discover(station_url).await?;
        let gate_account_base_url = url::Url::parse(&authority.gate_account_base_url)?;
        let authority_origin = gate_account_base_url.origin().ascii_serialization();
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
    if &payload.grant.issuer_id != intent.actor_id() {
        anyhow::bail!("capability grant issuer must equal the Event actor");
    }
    Ok(())
}

fn validate_signed_sdk_event_for_submit(
    event: &arkret_sdk::Event,
    digest_suite: arkret_sdk::DigestSuite,
) -> anyhow::Result<()> {
    let [_producer] = event.proofs.as_slice() else {
        anyhow::bail!(
            "submit requires exactly one producer proof (event_id={}, kind={})",
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

fn cbs_exempt_reducer_kind(kind: &arkret_sdk::events::kinds::EventKind) -> bool {
    matches!(kind, arkret_sdk::EventKind::RealmCreate)
}

#[cfg(test)]
#[path = "event_submit/tests.rs"]
mod tests;
