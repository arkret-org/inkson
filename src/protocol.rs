//! Inkson's clean-break authority-commit state machine.
//!
//! Producer Events deliberately have no predecessor field. Ordering starts at
//! the governance Station: every Realm, Circle, and Sidecar has an independent
//! [`RealmCommit`] stream whose only link is the same-stream
//! `previous_commit_ref`.

use std::collections::BTreeMap;

use arkret_identifiers::{DidCoreId, EventId, RealmId};
use arkret_wire::{
    AuthoredEvent, AuthorityBundleRequest, AuthorityCommitStatus, AuthorityHandoffRequest,
    AuthorityRejectionStatus, AuthoritySubmitOutcome, AuthoritySubmitRequest, CommitStreamHead,
    CommitStreamRef, DetachedSignatureContext, EventCommitSubmission, MlsCommitSubmission,
    MlsWelcomeDelivery, RealmAuthorityBundle, RealmCommit, RealmStateSnapshot, StreamScanOutcome,
    StreamScanRequest,
};
use chrono::{DateTime, Utc};
use serde_json::Value;
use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ClientProtocolError {
    #[error("wire contract violation: {0}")]
    Wire(String),
    #[error("event is already queued")]
    DuplicateEvent,
    #[error("event is not queued")]
    UnknownEvent,
    #[error("submission already reached a terminal state")]
    TerminalSubmission,
    #[error("bootstrap snapshot or stream tail does not match the current authority bundle")]
    InvalidBootstrap,
    #[error("stream tail does not continue the local same-stream cursor")]
    InvalidStreamTail,
}

fn wire<T>(result: arkret_wire::Result<T>) -> Result<T, ClientProtocolError> {
    result.map_err(|error| ClientProtocolError::Wire(error.to_string()))
}

#[derive(Clone, Debug, PartialEq)]
pub enum SubmissionState {
    Queued,
    Retryable {
        reason_code: String,
    },
    Committed {
        status: AuthorityCommitStatus,
        commit: Box<RealmCommit>,
    },
    Rejected {
        reason_code: String,
    },
}

impl SubmissionState {
    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Committed { .. } | Self::Rejected { .. })
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct QueuedSubmission {
    pub request: AuthoritySubmitRequest,
    pub state: SubmissionState,
}

impl QueuedSubmission {
    pub fn event_id(&self) -> &EventId {
        match &self.request {
            AuthoritySubmitRequest::Event(request) => &request.event.event_id,
            AuthoritySubmitRequest::MlsCommit(request) => &request.commit_event.event_id,
        }
    }
}

/// Durable intent queue. It stores author-signed requests, never an invented
/// local acceptance record.
#[derive(Clone, Debug, Default)]
pub struct SubmissionQueue {
    submissions: Vec<QueuedSubmission>,
    installed_mls_commits: Vec<EventId>,
    welcome_deliveries: Vec<MlsWelcomeDelivery>,
}

impl SubmissionQueue {
    pub fn submissions(&self) -> &[QueuedSubmission] {
        &self.submissions
    }

    pub fn enqueue_event(&mut self, event: AuthoredEvent) -> Result<(), ClientProtocolError> {
        self.enqueue(AuthoritySubmitRequest::Event(EventCommitSubmission {
            event: event.into_event(),
        }))
    }

    /// Stage an MLS Commit and its Welcome deliveries atomically for Station
    /// submission. Neither the MLS state nor the deliveries become active here.
    pub fn enqueue_mls_commit(
        &mut self,
        submission: MlsCommitSubmission,
    ) -> Result<(), ClientProtocolError> {
        self.enqueue(AuthoritySubmitRequest::MlsCommit(submission))
    }

    fn enqueue(&mut self, request: AuthoritySubmitRequest) -> Result<(), ClientProtocolError> {
        wire(request.validate())?;
        let event_id = match &request {
            AuthoritySubmitRequest::Event(request) => &request.event.event_id,
            AuthoritySubmitRequest::MlsCommit(request) => &request.commit_event.event_id,
        };
        if self
            .submissions
            .iter()
            .any(|submission| submission.event_id() == event_id)
        {
            return Err(ClientProtocolError::DuplicateEvent);
        }
        self.submissions.push(QueuedSubmission {
            request,
            state: SubmissionState::Queued,
        });
        Ok(())
    }

    /// Apply the Station's answer. An MLS Commit is installed, and its Welcome
    /// deliveries released, only on an accepted/duplicate commit outcome.
    pub fn apply_outcome(
        &mut self,
        event_id: &EventId,
        outcome: &AuthoritySubmitOutcome,
    ) -> Result<(), ClientProtocolError> {
        let submission = self
            .submissions
            .iter_mut()
            .find(|submission| submission.event_id() == event_id)
            .ok_or(ClientProtocolError::UnknownEvent)?;
        if submission.state.is_terminal() {
            return Err(ClientProtocolError::TerminalSubmission);
        }
        wire(outcome.validate_for_request(&submission.request))?;

        match outcome {
            AuthoritySubmitOutcome::Accepted { status, commit } => {
                if let AuthoritySubmitRequest::MlsCommit(request) = &submission.request {
                    self.installed_mls_commits
                        .push(request.commit_event.event_id.clone());
                    self.welcome_deliveries.extend(request.welcomes.clone());
                }
                submission.state = SubmissionState::Committed {
                    status: *status,
                    commit: Box::new(commit.clone()),
                };
            }
            AuthoritySubmitOutcome::Rejected {
                status: AuthorityRejectionStatus::RetryableUnavailable,
                reason_code,
            } => {
                submission.state = SubmissionState::Retryable {
                    reason_code: reason_code.clone(),
                };
            }
            AuthoritySubmitOutcome::Rejected {
                status: AuthorityRejectionStatus::Rejected,
                reason_code,
            } => {
                submission.state = SubmissionState::Rejected {
                    reason_code: reason_code.clone(),
                };
            }
        }
        Ok(())
    }

    pub fn mls_commit_is_installed(&self, event_id: &EventId) -> bool {
        self.installed_mls_commits.contains(event_id)
    }

    /// Take delivery work independently of MLS state installation. A consumer
    /// may retry transport without replaying or rolling back the committed MLS
    /// state transition.
    pub fn take_welcome_deliveries(&mut self, event_id: &EventId) -> Vec<MlsWelcomeDelivery> {
        let mut selected = Vec::new();
        self.welcome_deliveries.retain(|delivery| {
            if &delivery.commit_event_ref == event_id {
                selected.push(delivery.clone());
                false
            } else {
                true
            }
        });
        selected
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct StreamTail {
    pub request: StreamScanRequest,
    pub outcome: StreamScanOutcome,
}

#[derive(Clone, Debug, PartialEq)]
pub struct CurrentAuthority {
    pub realm_id: RealmId,
    pub generation: u64,
    pub service_id: DidCoreId,
    pub route_record: Value,
}

/// Host-provided cryptographic verification boundary. Shape validation alone
/// is never sufficient to select a governance Station: implementations must
/// resolve the advertised verification methods through an authenticated route
/// record and verify every detached signature fail-closed.
pub trait AuthorityMaterialVerifier {
    fn verify_authority_bundle(
        &self,
        bundle: &RealmAuthorityBundle,
    ) -> Result<(), ClientProtocolError>;

    fn verify_snapshot(
        &self,
        snapshot: &RealmStateSnapshot,
        current_service_id: &DidCoreId,
    ) -> Result<(), ClientProtocolError>;

    fn verify_handoff_install(
        &self,
        request: &AuthorityHandoffRequest,
    ) -> Result<(), ClientProtocolError>;
}

/// Join material returned by the authenticated current governance Station.
/// The inviter and the genesis Station are not trust anchors for this package.
#[derive(Clone, Debug, PartialEq)]
pub struct JoinBootstrap {
    pub authority_bundle: RealmAuthorityBundle,
    pub snapshot: RealmStateSnapshot,
    pub stream_tails: Vec<StreamTail>,
}

impl JoinBootstrap {
    pub fn validate<V: AuthorityMaterialVerifier>(
        &self,
        authority_request: &AuthorityBundleRequest,
        now: DateTime<Utc>,
        verifier: &V,
    ) -> Result<CurrentAuthority, ClientProtocolError> {
        wire(
            self.authority_bundle
                .validate_for_request(authority_request, now),
        )?;
        verifier.verify_authority_bundle(&self.authority_bundle)?;

        let heads = &self.snapshot.visible_stream_heads;
        let snapshot_valid = self.snapshot.realm_id == self.authority_bundle.realm_id
            && self.snapshot.authority_generation == self.authority_bundle.current_generation
            && self.snapshot.signature.context == DetachedSignatureContext::RealmSnapshot
            && !heads.is_empty()
            && heads
                .windows(2)
                .all(|pair| pair[0].stream_ref < pair[1].stream_ref)
            && heads.iter().all(|head| {
                head.stream_ref.realm_id() == &self.snapshot.realm_id
                    && head.stream_ref.realm_id() == &authority_request.realm_id
            })
            && self.stream_tails.len() == heads.len();
        if !snapshot_valid {
            return Err(ClientProtocolError::InvalidBootstrap);
        }
        verifier.verify_snapshot(&self.snapshot, &self.authority_bundle.current_service_id)?;

        for (head, tail) in heads.iter().zip(&self.stream_tails) {
            if tail.request.realm_id != self.snapshot.realm_id
                || tail.request.stream_ref != head.stream_ref
                || tail.request.after_position != Some(head.stream_position)
            {
                return Err(ClientProtocolError::InvalidBootstrap);
            }
            wire(tail.outcome.validate_for_request(&tail.request))?;
            if let Some(first) = tail.outcome.commits.first()
                && (first.commit.previous_commit_ref.as_ref() != Some(&head.commit_id)
                    || first.commit.stream_position != head.stream_position.saturating_add(1))
            {
                return Err(ClientProtocolError::InvalidBootstrap);
            }
        }

        Ok(CurrentAuthority {
            realm_id: self.authority_bundle.realm_id.clone(),
            generation: self.authority_bundle.current_generation,
            service_id: self.authority_bundle.current_service_id.clone(),
            route_record: self.authority_bundle.current_route_record.clone(),
        })
    }
}

/// Per-stream cursors. There is intentionally no Realm-global sequence or
/// comparison function between entries in this map.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct StreamCursorBook {
    heads: BTreeMap<CommitStreamRef, CommitStreamHead>,
}

impl StreamCursorBook {
    pub fn from_snapshot(snapshot: &RealmStateSnapshot) -> Result<Self, ClientProtocolError> {
        let mut heads = BTreeMap::new();
        for head in &snapshot.visible_stream_heads {
            if head.stream_ref.realm_id() != &snapshot.realm_id
                || heads
                    .insert(head.stream_ref.clone(), head.clone())
                    .is_some()
            {
                return Err(ClientProtocolError::InvalidBootstrap);
            }
        }
        Ok(Self { heads })
    }

    pub fn head(&self, stream_ref: &CommitStreamRef) -> Option<&CommitStreamHead> {
        self.heads.get(stream_ref)
    }

    pub fn apply_tail(&mut self, tail: &StreamTail) -> Result<(), ClientProtocolError> {
        wire(tail.outcome.validate_for_request(&tail.request))?;
        let current = self
            .heads
            .get(&tail.request.stream_ref)
            .ok_or(ClientProtocolError::InvalidStreamTail)?;
        if tail.request.after_position != Some(current.stream_position) {
            return Err(ClientProtocolError::InvalidStreamTail);
        }
        if let Some(first) = tail.outcome.commits.first()
            && first.commit.previous_commit_ref.as_ref() != Some(&current.commit_id)
        {
            return Err(ClientProtocolError::InvalidStreamTail);
        }
        if let Some(last) = tail.outcome.commits.last() {
            self.heads.insert(
                tail.request.stream_ref.clone(),
                CommitStreamHead {
                    stream_ref: last.commit.stream_ref.clone(),
                    stream_position: last.commit.stream_position,
                    commit_id: last.commit.commit_id.clone(),
                },
            );
        }
        Ok(())
    }
}

/// Validate the old-to-new Station transfer package before any local routing
/// change. The SDK binds the signed handoff, complete per-stream head manifest,
/// snapshot, and public authority bundle.
pub fn validate_handoff_install<V: AuthorityMaterialVerifier>(
    request: &AuthorityHandoffRequest,
    verifier: &V,
) -> Result<(), ClientProtocolError> {
    wire(request.validate_shape())?;
    verifier.verify_handoff_install(request)
}

#[cfg(test)]
mod tests {
    use arkret_canonical::DigestSuite;
    use arkret_identifiers::{CircleId, EventId, RealmCommitId, RealmId, SidecarId};

    use super::*;

    fn event_id(byte: u8) -> EventId {
        EventId::from_digest(DigestSuite::Sha256, [byte; 32])
    }

    #[test]
    fn realm_circle_and_sidecar_are_distinct_stream_keys() {
        let realm_id = RealmId::from_event_id(&event_id(1));
        let circle_id = CircleId::from_event_id(&event_id(2));
        let sidecar_id = SidecarId::from_event_id(&event_id(3));
        let streams = [
            CommitStreamRef::Realm {
                realm_id: realm_id.clone(),
            },
            CommitStreamRef::Circle {
                realm_id: realm_id.clone(),
                circle_id,
            },
            CommitStreamRef::Sidecar {
                realm_id,
                sidecar_id,
            },
        ];
        let distinct = streams.iter().collect::<std::collections::BTreeSet<_>>();
        assert_eq!(distinct.len(), 3);
    }

    #[test]
    fn cursor_book_keeps_independent_positions() {
        let realm_id = RealmId::from_event_id(&event_id(4));
        let realm_stream = CommitStreamRef::Realm {
            realm_id: realm_id.clone(),
        };
        let circle_stream = CommitStreamRef::Circle {
            realm_id,
            circle_id: CircleId::from_event_id(&event_id(5)),
        };
        let realm_head = CommitStreamHead {
            stream_ref: realm_stream.clone(),
            stream_position: 7,
            commit_id: RealmCommitId::from_digest([7; 32]),
        };
        let circle_head = CommitStreamHead {
            stream_ref: circle_stream.clone(),
            stream_position: 19,
            commit_id: RealmCommitId::from_digest([19; 32]),
        };
        let book = StreamCursorBook {
            heads: BTreeMap::from([
                (realm_stream.clone(), realm_head.clone()),
                (circle_stream.clone(), circle_head.clone()),
            ]),
        };
        assert_eq!(book.head(&realm_stream), Some(&realm_head));
        assert_eq!(book.head(&circle_stream), Some(&circle_head));
        assert_ne!(
            book.head(&realm_stream).map(|head| head.stream_position),
            book.head(&circle_stream).map(|head| head.stream_position)
        );
    }

    #[test]
    fn retryable_submission_is_not_terminal() {
        assert!(
            !SubmissionState::Retryable {
                reason_code: "station_temporarily_unavailable".to_owned(),
            }
            .is_terminal()
        );
        assert!(
            SubmissionState::Rejected {
                reason_code: "policy_denied".to_owned(),
            }
            .is_terminal()
        );
    }
}
