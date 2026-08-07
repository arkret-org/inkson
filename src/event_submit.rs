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
use garth::outbound::BoxOutboundFuture;
use garth::{
    OutboundEngine, OutboundEngineOutcome, OutboundGenerationFenceDecision, OutboundPostAcceptHook,
    OutboundSubmitOutcome, OutboundSubmitter,
};
#[cfg(test)]
use reqwest::StatusCode;
use serde::Deserialize as _;
use serde_json::Value;
use tokio::sync::OnceCell;

#[cfg(test)]
use crate::api_error::TransportClientError;
use crate::ephemeral::{ensure_events_submit_accepted, validate_outgoing_registered_event_payload};
use crate::models::{BackfillView, ServiceDescribe, SubmitEventResult};
use crate::operation::uuid_v7;

/// Authenticated durable/ephemeral event submission engine extracted from the
/// former `TransportClient` events surface. Constructed per authenticated call from
/// the shared SDK http-client (see `crate::transport::auth::with_event_submitter`).
pub struct EventSubmitter {
    http: arkret_sdk::http_client::Client,
    describe_cache: OnceCell<ServiceDescribe>,
}

/// Ordinary Realm and self-principal bootstrap units intentionally publish
/// without per-Event Control Proposal Acks. A managed Agent PCR create is also an
/// anchor unit, but its delegated controller is the founding proposal
/// authority, so it must pass through `standard_initial_submission` to attach
/// that controller's Control Proposal Ack.
fn uses_bare_online_anchor_submission(anchor_unit: bool, event: &arkret_sdk::Event) -> bool {
    anchor_unit && !crate::authorization_lease::is_managed_agent_pcr_genesis(event)
}

#[derive(Debug, thiserror::Error)]
#[error("event {event_id} is durably queued for retry")]
pub(crate) struct DurablyQueuedError {
    pub(crate) event_id: String,
}

#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct EventIntent {
    pub(crate) event_id: arkret_sdk::EventId,
    pub(crate) kind: arkret_sdk::events::EventKind,
    pub(crate) realm_id: arkret_sdk::RealmId,
    pub(crate) scope_ref: arkret_sdk::ScopeRef,
    pub(crate) actor_id: arkret_sdk::Did,
    pub(crate) executed_by: Option<arkret_sdk::Did>,
    pub(crate) authorization_ref: Option<arkret_sdk::AuthorizationRef>,
    pub(crate) applet_id: Option<arkret_sdk::AppletId>,
    pub(crate) external_ref: Option<BTreeMap<String, Value>>,
    pub(crate) actor_kind: Option<arkret_sdk::EnvelopeActorKind>,
    pub(crate) created_at: chrono::DateTime<chrono::Utc>,
    pub(crate) refs: Vec<arkret_sdk::EventRef>,
    pub(crate) causal_refs: Vec<arkret_sdk::Hash>,
    pub(crate) preconditions: Vec<arkret_sdk::Precondition>,
    pub(crate) seal_basis: Option<arkret_sdk::SealBasis>,
    pub(crate) payload: BTreeMap<String, Value>,
    pub(crate) redacts: Option<arkret_sdk::EventId>,
    pub(crate) unsigned: BTreeMap<String, Value>,
    pub(crate) requirements: arkret_sdk::EventRequirements,
}

impl EventIntent {
    fn from_event(event: arkret_sdk::Event) -> Self {
        let arkret_sdk::Event {
            event_id,
            kind,
            realm_id,
            scope_ref,
            actor_id,
            executed_by,
            authorization_ref,
            applet_id,
            external_ref,
            actor_kind,
            actor_seq: _,
            created_at,
            hlc: _,
            prev_refs: _,
            refs,
            causal_refs,
            preconditions,
            seal_ref: _,
            auth_context: _,
            seal_basis,
            payload,
            redacts,
            mut unsigned,
            proofs: _,
            requirements,
        } = event;
        unsigned.remove("local_operation_idempotency_alias");
        let seal_basis = (kind.as_str() == "ak.invite.accept")
            .then_some(seal_basis)
            .flatten();
        Self {
            event_id,
            kind,
            realm_id,
            scope_ref,
            actor_id,
            executed_by,
            authorization_ref,
            applet_id,
            external_ref,
            actor_kind,
            created_at,
            refs,
            causal_refs,
            preconditions,
            seal_basis,
            payload,
            redacts,
            unsigned,
            requirements,
        }
    }

    fn to_unauthored_event(&self) -> arkret_sdk::Event {
        arkret_sdk::Event {
            event_id: self.event_id.clone(),
            kind: self.kind.clone(),
            realm_id: self.realm_id.clone(),
            scope_ref: self.scope_ref.clone(),
            actor_id: self.actor_id.clone(),
            executed_by: self.executed_by.clone(),
            authorization_ref: self.authorization_ref.clone(),
            applet_id: self.applet_id.clone(),
            external_ref: self.external_ref.clone(),
            actor_kind: self.actor_kind,
            actor_seq: 0,
            created_at: self.created_at,
            hlc: None,
            prev_refs: Vec::new(),
            refs: self.refs.clone(),
            causal_refs: self.causal_refs.clone(),
            preconditions: self.preconditions.clone(),
            seal_ref: None,
            auth_context: None,
            seal_basis: self.seal_basis.clone(),
            payload: self.payload.clone(),
            redacts: self.redacts.clone(),
            unsigned: self.unsigned.clone(),
            proofs: Vec::new(),
            requirements: self.requirements.clone(),
        }
    }

    fn digest(&self) -> arkret_sdk::Result<arkret_sdk::Hash> {
        Ok(arkret_sdk::Hash::new(
            arkret_sdk::canonical::canonical_sha256(self)?,
        )?)
    }
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AuthoredEventAttempt {
    pub(crate) intent_digest: arkret_sdk::Hash,
    pub(crate) envelope: arkret_sdk::Event,
    pub(crate) transport_idempotency_key: String,
    pub(crate) canonical_body_bytes: Vec<u8>,
}

/// Durable, all-or-nothing Realm bootstrap authoring record.
///
/// The first form is persisted before any HLC/frontier allocation or signing.
/// Its create payload already contains the one CSPRNG `genesis_salt` owned by
/// this intent. The prepared form freezes the complete signed unit and its
/// canonical bytes before the first HTTP request, so recovery never rebuilds
/// a bootstrap or generates another salt.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
enum QueuedRealmBootstrap {
    Intent {
        local_operation_id: String,
        transport_idempotency_key: String,
        intent_digest: arkret_sdk::Hash,
        events: Vec<arkret_sdk::Event>,
    },
    Prepared {
        local_operation_id: String,
        transport_idempotency_key: String,
        intent_digest: arkret_sdk::Hash,
        events: Vec<arkret_sdk::Event>,
        canonical_signed_unit_bytes: Vec<u8>,
    },
}

impl QueuedRealmBootstrap {
    fn intent(
        local_operation_id: String,
        transport_idempotency_key: String,
        events: Vec<arkret_sdk::Event>,
    ) -> arkret_sdk::Result<Self> {
        validate_realm_bootstrap_intent(&events)?;
        let intent_digest =
            arkret_sdk::Hash::new(arkret_sdk::canonical::canonical_sha256(&events)?)?;
        Ok(Self::Intent {
            local_operation_id,
            transport_idempotency_key,
            intent_digest,
            events,
        })
    }

    fn authority_context_event(&self) -> &arkret_sdk::Event {
        match self {
            Self::Intent { events, .. } | Self::Prepared { events, .. } => &events[0],
        }
    }
}

fn validate_realm_bootstrap_intent(events: &[arkret_sdk::Event]) -> arkret_sdk::Result<()> {
    let create = events.first().ok_or_else(|| {
        arkret_sdk::Error::Protocol("queued Realm bootstrap unit is empty".to_owned())
    })?;
    if create.kind.as_str() != arkret_sdk::EventKind::REALM_CREATE {
        return Err(arkret_sdk::Error::Protocol(
            "queued Realm bootstrap must begin with ak.realm.create".to_owned(),
        ));
    }
    let payload: arkret_sdk::RealmCreatePayload = serde_json::from_value(
        serde_json::to_value(&create.payload)
            .map_err(|error| arkret_sdk::Error::Protocol(error.to_string()))?,
    )
    .map_err(|error| arkret_sdk::Error::Protocol(format!("decode Realm genesis: {error}")))?;
    payload.object.validate()?;
    if payload.object.genesis_salt.is_none() {
        return Err(arkret_sdk::Error::Protocol(
            "event-derived Realm bootstrap intent must persist genesis_salt".to_owned(),
        ));
    }
    arkret_policy::realm_bootstrap::validate_realm_bootstrap_unit(events)
        .map_err(|error| arkret_sdk::Error::Protocol(error.reason_code().to_owned()))?;
    Ok(())
}

fn decode_queued_realm_bootstrap(content: Value) -> arkret_sdk::Result<QueuedRealmBootstrap> {
    let queued: QueuedRealmBootstrap = serde_json::from_value(content).map_err(|error| {
        arkret_sdk::Error::Protocol(format!("decode queued Realm bootstrap: {error}"))
    })?;
    let (intent_digest, events) = match &queued {
        QueuedRealmBootstrap::Intent {
            intent_digest,
            events,
            ..
        }
        | QueuedRealmBootstrap::Prepared {
            intent_digest,
            events,
            ..
        } => (intent_digest, events),
    };
    validate_realm_bootstrap_intent(events)?;
    match &queued {
        QueuedRealmBootstrap::Intent { .. } => {
            let computed = arkret_sdk::Hash::new(arkret_sdk::canonical::canonical_sha256(events)?)?;
            if &computed != intent_digest {
                return Err(arkret_sdk::Error::Protocol(
                    "queued Realm bootstrap intent digest mismatch".to_owned(),
                ));
            }
        }
        QueuedRealmBootstrap::Prepared {
            canonical_signed_unit_bytes,
            ..
        } => {
            if events.iter().any(|event| event.proofs.is_empty()) {
                return Err(arkret_sdk::Error::Protocol(
                    "prepared Realm bootstrap contains an unsigned Event".to_owned(),
                ));
            }
            let canonical = arkret_sdk::canonical::canonical_json_bytes(events)?;
            if &canonical != canonical_signed_unit_bytes {
                return Err(arkret_sdk::Error::Protocol(
                    "prepared Realm bootstrap canonical bytes mismatch".to_owned(),
                ));
            }
        }
    }
    Ok(queued)
}

/// Frozen scheduler-to-transport handoff persisted inside the durable outbound
/// queue. Once this record exists, retries are driven exclusively from these
/// bytes; the editable account-data plan is no longer an authoring source.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ScheduledSendSubmissionState {
    Ready,
    SubmissionUncertain,
}

#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ScheduledSendDispatchRecord {
    pub(crate) scheduled_send_id: arkret_identifiers::ScheduledSendId,
    pub(crate) event_id: arkret_sdk::EventId,
    pub(crate) message_id: arkret_sdk::MessageId,
    pub(crate) canonical_signed_event_bytes: Vec<u8>,
    pub(crate) submission_state: ScheduledSendSubmissionState,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct QueuedSdkEvent {
    pub(crate) intent: EventIntent,
    pub(crate) intent_digest: arkret_sdk::Hash,
    pub(crate) local_operation_id: String,
    pub(crate) authoring_idempotency_key: String,
    #[serde(deserialize_with = "deserialize_required_nullable")]
    pub(crate) authored_attempt: Option<AuthoredEventAttempt>,
    #[serde(deserialize_with = "deserialize_required_nullable")]
    pub(crate) supersedes_event_id: Option<arkret_sdk::EventId>,
    pub(crate) authoring_generation: crate::identity::authoring_generation::AuthoringGeneration,
    #[serde(deserialize_with = "deserialize_required_nullable")]
    pub(crate) post_accept: Option<PostAcceptAction>,
    #[serde(deserialize_with = "deserialize_required_nullable")]
    pub(crate) scheduled_dispatch: Option<ScheduledSendDispatchRecord>,
}

impl QueuedSdkEvent {
    fn unauthored(
        event: arkret_sdk::Event,
        local_operation_id: String,
        authoring_idempotency_key: String,
        supersedes_event_id: Option<arkret_sdk::EventId>,
        authoring_generation: crate::identity::authoring_generation::AuthoringGeneration,
        post_accept: Option<PostAcceptAction>,
    ) -> arkret_sdk::Result<Self> {
        let intent = EventIntent::from_event(event);
        let intent_digest = intent.digest()?;
        Ok(Self {
            intent,
            intent_digest,
            local_operation_id,
            authoring_idempotency_key,
            authored_attempt: None,
            supersedes_event_id,
            authoring_generation,
            post_accept,
            scheduled_dispatch: None,
        })
    }

    fn authored(
        envelope: arkret_sdk::Event,
        local_operation_id: String,
        transport_idempotency_key: String,
        canonical_body_bytes: Vec<u8>,
        supersedes_event_id: Option<arkret_sdk::EventId>,
        authoring_generation: crate::identity::authoring_generation::AuthoringGeneration,
        post_accept: Option<PostAcceptAction>,
    ) -> arkret_sdk::Result<Self> {
        let intent = EventIntent::from_event(envelope.clone());
        let intent_digest = intent.digest()?;
        Ok(Self {
            intent,
            intent_digest: intent_digest.clone(),
            local_operation_id,
            authoring_idempotency_key: transport_idempotency_key.clone(),
            authored_attempt: Some(AuthoredEventAttempt {
                intent_digest,
                envelope,
                transport_idempotency_key,
                canonical_body_bytes,
            }),
            supersedes_event_id,
            authoring_generation,
            post_accept,
            scheduled_dispatch: None,
        })
    }

    fn scheduled_authored(
        scheduled_send_id: arkret_identifiers::ScheduledSendId,
        envelope: arkret_sdk::Event,
        authoring_generation: crate::identity::authoring_generation::AuthoringGeneration,
    ) -> arkret_sdk::Result<Self> {
        if envelope.kind.as_str() != arkret_sdk::events::EventKind::MESSAGE_CREATE {
            return Err(arkret_sdk::Error::Protocol(
                "scheduled dispatch must contain ak.message.create".to_owned(),
            ));
        }
        if envelope.proofs.is_empty() {
            return Err(arkret_sdk::Error::Protocol(
                "scheduled dispatch Event must already be signed".to_owned(),
            ));
        }
        let derived_event_id = envelope.derive_event_id()?;
        if derived_event_id != envelope.event_id {
            return Err(arkret_sdk::Error::Protocol(
                "scheduled dispatch Event id does not match its canonical content".to_owned(),
            ));
        }
        let event_id = envelope.event_id.clone();
        let message_id = arkret_sdk::MessageId::from_event_id(&event_id);
        let canonical_signed_event_bytes = arkret_sdk::canonical::canonical_json_bytes(&envelope)?;
        let intent = EventIntent::from_event(envelope.clone());
        let intent_digest = intent.digest()?;
        Ok(Self {
            intent,
            intent_digest: intent_digest.clone(),
            local_operation_id: scheduled_send_id.to_string(),
            authoring_idempotency_key: event_id.to_string(),
            authored_attempt: Some(AuthoredEventAttempt {
                intent_digest,
                envelope,
                transport_idempotency_key: event_id.to_string(),
                canonical_body_bytes: canonical_signed_event_bytes.clone(),
            }),
            supersedes_event_id: None,
            authoring_generation,
            post_accept: None,
            scheduled_dispatch: Some(ScheduledSendDispatchRecord {
                scheduled_send_id,
                event_id,
                message_id,
                canonical_signed_event_bytes,
                submission_state: ScheduledSendSubmissionState::Ready,
            }),
        })
    }

    fn event_for_authority_context(&self) -> arkret_sdk::Event {
        self.authored_attempt
            .as_ref()
            .map(|attempt| attempt.envelope.clone())
            .unwrap_or_else(|| self.intent.to_unauthored_event())
    }

    fn mark_scheduled_submission_uncertain(&mut self) -> bool {
        let Some(dispatch) = self.scheduled_dispatch.as_mut() else {
            return false;
        };
        if dispatch.submission_state != ScheduledSendSubmissionState::Ready {
            return false;
        }
        dispatch.submission_state = ScheduledSendSubmissionState::SubmissionUncertain;
        true
    }
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub(crate) enum PostAcceptAction {
    MlsSnapshot {
        realm_id: String,
        snapshot: crate::mls::persistence::MlsSnapshotEnvelope,
    },
    /// Durable admission saga. The Add commit is the queued Event; only after
    /// that Event is accepted (or confirmed duplicate) may the exact signed
    /// Welcome(s) be submitted. Keeping the Welcome material inside the same
    /// durable queue item closes the browser-unload gap between the two writes.
    MlsAdmission {
        realm_id: String,
        actor_id: String,
        device_id: String,
        welcomes: Vec<arkret_sdk::Event>,
        snapshot: crate::mls::persistence::MlsSnapshotEnvelope,
    },
}

fn deserialize_required_nullable<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: serde::Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer)
}

/// Classification of a persisted outbound queue record.
///
/// A record's content is immutable, so a decode/validation failure can never
/// heal on retry ("poisoned" — e.g. persisted by an older build with different
/// intent semantics). The single policy for poisoned records lives here: they
/// are cancelled through the consumer's own channel and MUST NOT wedge the
/// per-actor queue or fail an unrelated submission. Consumers map this to
/// their mechanism — the outbound submitter returns a `Terminal` outcome, the
/// generation fence quarantines the record in preflight, and the same-
/// transaction retry path compacts terminal history before re-enqueueing.
enum QueuedRecordState {
    Event(Box<QueuedSdkEvent>),
    RealmBootstrap(Box<QueuedRealmBootstrap>),
    Poisoned { reason: String },
}

fn classify_queued_record(transaction_id: &str, content: Value) -> QueuedRecordState {
    if let Ok(queued) = decode_queued_sdk_event(content.clone()) {
        return QueuedRecordState::Event(Box::new(queued));
    }
    match decode_queued_realm_bootstrap(content) {
        Ok(queued) => QueuedRecordState::RealmBootstrap(Box::new(queued)),
        Err(error) => {
            tracing::warn!(
                event_id = %transaction_id,
                error = %error,
                "queued outbound record failed decode; poisoned record will be cancelled, not retried"
            );
            QueuedRecordState::Poisoned {
                reason: format!("poisoned queued item cancelled: {error}"),
            }
        }
    }
}

fn decode_queued_sdk_event(content: Value) -> arkret_sdk::Result<QueuedSdkEvent> {
    let queued: QueuedSdkEvent = serde_json::from_value(content).map_err(|error| {
        arkret_sdk::Error::Protocol(format!("decode queued Inkson SDK event: {error}"))
    })?;
    let computed_intent_digest = queued.intent.digest()?;
    if computed_intent_digest != queued.intent_digest {
        return Err(arkret_sdk::Error::Protocol(
            "queued Inkson SDK event intent_digest does not match intent".to_owned(),
        ));
    }
    if let Some(attempt) = queued.authored_attempt.as_ref() {
        if attempt.intent_digest != queued.intent_digest {
            return Err(arkret_sdk::Error::Protocol(
                "queued Inkson SDK authored attempt is bound to a different intent".to_owned(),
            ));
        }
        if attempt.transport_idempotency_key.is_empty() || attempt.canonical_body_bytes.is_empty() {
            return Err(arkret_sdk::Error::Protocol(
                "queued Inkson SDK authored attempt must carry immutable transport identity and bytes"
                    .to_owned(),
            ));
        }
        let canonical = arkret_sdk::canonical::canonical_json_bytes(&attempt.envelope)?;
        if canonical != attempt.canonical_body_bytes {
            return Err(arkret_sdk::Error::Protocol(
                "queued Inkson SDK authored attempt canonical bytes do not match envelope"
                    .to_owned(),
            ));
        }
        if EventIntent::from_event(attempt.envelope.clone()) != queued.intent {
            return Err(arkret_sdk::Error::Protocol(
                "queued Inkson SDK authored envelope changes the bound semantic intent".to_owned(),
            ));
        }
    }
    if let Some(dispatch) = queued.scheduled_dispatch.as_ref() {
        let attempt = queued.authored_attempt.as_ref().ok_or_else(|| {
            arkret_sdk::Error::Protocol(
                "scheduled dispatch record requires a frozen authored attempt".to_owned(),
            )
        })?;
        if queued.local_operation_id != dispatch.scheduled_send_id.as_str()
            || queued.intent.kind.as_str() != arkret_sdk::events::EventKind::MESSAGE_CREATE
            || queued.intent.event_id != dispatch.event_id
            || attempt.envelope.event_id != dispatch.event_id
            || arkret_sdk::MessageId::from_event_id(&dispatch.event_id) != dispatch.message_id
            || attempt.canonical_body_bytes != dispatch.canonical_signed_event_bytes
        {
            return Err(arkret_sdk::Error::Protocol(
                "scheduled dispatch record does not match its immutable authored Event".to_owned(),
            ));
        }
    }
    Ok(queued)
}

#[derive(Clone, Default)]
struct InksonPostAcceptHook {
    state_store: Option<crate::runtime::input::StateStoreHandle>,
}

impl OutboundPostAcceptHook for InksonPostAcceptHook {
    fn post_accept<'a>(
        &'a self,
        item: &'a garth::SendQueueItem,
        event_id: &'a arkret_sdk::EventId,
        _duplicate: bool,
    ) -> BoxOutboundFuture<'a, ()> {
        Box::pin(async move {
            let queued = decode_queued_sdk_event(item.content.clone())
                .map_err(|error| garth::Error::Protocol(error.to_string()))?;
            let Some(action) = queued.post_accept else {
                return Ok(());
            };
            // Admission persistence runs inside the submitter so failures can
            // use the unbounded durable RetryAfter path. Garth's generic hook
            // error policy is intentionally bounded and must not terminally
            // cancel an accepted Commit's only staged state after eight tries.
            if matches!(action, PostAcceptAction::MlsAdmission { .. }) {
                return Ok(());
            }
            persist_post_accept_action(self.state_store.as_ref(), action, event_id.clone()).await
        })
    }
}

async fn persist_post_accept_action(
    state_store: Option<&crate::runtime::input::StateStoreHandle>,
    action: PostAcceptAction,
    accepted_event_id: arkret_sdk::EventId,
) -> Result<(), garth::Error> {
    let store = state_store.ok_or_else(|| {
        garth::Error::Protocol(
            "queued post-accept action has no host state-store adapter".to_owned(),
        )
    })?;
    let (realm_id, snapshot, retain_history_for) = match action {
        PostAcceptAction::MlsSnapshot { realm_id, snapshot } => (realm_id, snapshot, None),
        PostAcceptAction::MlsAdmission {
            realm_id,
            actor_id,
            device_id,
            welcomes: _,
            snapshot,
        } => (realm_id, snapshot, Some((actor_id, device_id))),
    };
    let snapshot_realm_id = realm_id.clone();
    let barrier = store.write(|store| {
        store
            .record_mls_group_state_ref_for_effective_scope(
                snapshot_realm_id.clone(),
                None,
                snapshot.group_id.as_str(),
                snapshot.epoch,
                accepted_event_id,
            )
            .map_err(garth::Error::Protocol)?;
        store.save_mls_snapshot(snapshot_realm_id, snapshot);
        store.begin_durable_flush().map_err(|error| {
            garth::Error::Protocol(format!(
                "begin durable MLS post-accept snapshot persist: {error}"
            ))
        })
    })?;
    barrier.wait().await.map_err(|error| {
        garth::Error::Protocol(format!("persist MLS post-accept snapshot: {error}"))
    })?;
    if let Some((actor_id, device_id)) = retain_history_for {
        let secure_store = crate::secure_key_store::default_secure_key_store("inkson");
        let derived = store
            .read(|store| {
                crate::mls::runtime::derive_and_retain_realm_history_secret(
                    store,
                    secure_store.as_ref(),
                    &realm_id,
                    &actor_id,
                    &device_id,
                )
            })
            .map_err(|error| garth::Error::Protocol(error.user_message()))?;
        if let Some((_epoch, _secret, pending)) = derived {
            pending
                .persist(secure_store.as_ref())
                .await
                .map_err(|error| garth::Error::Protocol(error.to_string()))?;
            store.write(|store| store.publish_history_secrets(pending));
        }
    }
    Ok(())
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
    async fn submit_realm_bootstrap(
        &self,
        item: garth::SendQueueItem,
        queued: QueuedRealmBootstrap,
    ) -> garth::Result<OutboundSubmitOutcome> {
        match queued {
            QueuedRealmBootstrap::Intent {
                local_operation_id,
                transport_idempotency_key,
                intent_digest,
                events,
            } => {
                let events = self
                    .owner
                    .prepare_sdk_events_batch(events)
                    .await
                    .map_err(|error| garth::Error::Protocol(error.to_string()))?;
                let canonical_signed_unit_bytes =
                    arkret_sdk::canonical::canonical_json_bytes(&events)
                        .map_err(|error| garth::Error::Protocol(error.to_string()))?;
                let prepared = QueuedRealmBootstrap::Prepared {
                    local_operation_id,
                    transport_idempotency_key,
                    intent_digest,
                    events,
                    canonical_signed_unit_bytes,
                };
                Ok(OutboundSubmitOutcome::Prepared {
                    content: serde_json::to_value(prepared)
                        .map_err(|error| garth::Error::Protocol(error.to_string()))?,
                })
            }
            QueuedRealmBootstrap::Prepared {
                transport_idempotency_key,
                events,
                ..
            } => {
                let event_id = events[0].event_id.clone();
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
        }
    }
}

impl OutboundSubmitter for EventOutboundSubmitter<'_> {
    fn submit<'a>(
        &'a self,
        item: garth::SendQueueItem,
    ) -> BoxOutboundFuture<'a, OutboundSubmitOutcome> {
        Box::pin(async move {
            let mut queued =
                match classify_queued_record(&item.transaction_id, item.content.clone()) {
                    QueuedRecordState::Event(queued) => *queued,
                    QueuedRecordState::RealmBootstrap(queued) => {
                        return self.submit_realm_bootstrap(item, *queued).await;
                    }
                    QueuedRecordState::Poisoned { reason } => {
                        return Ok(OutboundSubmitOutcome::Terminal { reason });
                    }
                };
            if queued.mark_scheduled_submission_uncertain() {
                // Persist the uncertainty boundary before the first HTTP write.
                // A crash after this point can only resume the exact signed
                // bytes carried by the record; it cannot consult or rebuild the
                // editable scheduled-send plan.
                return Ok(OutboundSubmitOutcome::Prepared {
                    content: serde_json::to_value(queued).map_err(|error| {
                        garth::Error::Protocol(format!(
                            "encode frozen scheduled dispatch record: {error}"
                        ))
                    })?,
                });
            }
            if queued.authored_attempt.is_none() {
                let mut event = queued.intent.to_unauthored_event();
                event.unsigned.insert(
                    "local_operation_idempotency_alias".to_owned(),
                    Value::String(queued.authoring_idempotency_key.clone()),
                );
                let (event, transport_idempotency_key) = self
                    .owner
                    .prepare_frozen_intent_for_submit(&event)
                    .await
                    .map_err(|error| garth::Error::Protocol(error.to_string()))?;
                let canonical_body_bytes = arkret_sdk::canonical::canonical_json_bytes(&event)
                    .map_err(|error| garth::Error::Protocol(error.to_string()))?;
                queued.authored_attempt = Some(AuthoredEventAttempt {
                    intent_digest: queued.intent_digest.clone(),
                    envelope: event,
                    transport_idempotency_key,
                    canonical_body_bytes,
                });
                return Ok(OutboundSubmitOutcome::Prepared {
                    content: serde_json::to_value(queued)
                        .map_err(|error| garth::Error::Protocol(error.to_string()))?,
                });
            }
            let attempt = queued.authored_attempt.as_ref().ok_or_else(|| {
                garth::Error::Protocol("prepared outbound Event has no authored attempt".to_owned())
            })?;
            let event = &attempt.envelope;
            match self
                .owner
                .submit_sdk_event_direct(
                    event,
                    &attempt.transport_idempotency_key,
                    &attempt.canonical_body_bytes,
                )
                .await
            {
                Ok(result) => {
                    // The admission queue item is not accepted until every
                    // bound Welcome has also been delivered. A failure here
                    // leaves the same immutable commit + Welcome material in
                    // Garth; retry confirms the commit as duplicate and resumes
                    // the Welcome before the post-accept snapshot is installed.
                    if let Some(action @ PostAcceptAction::MlsAdmission { welcomes, .. }) =
                        queued.post_accept.as_ref()
                    {
                        for welcome in welcomes {
                            let canonical_body_bytes =
                                arkret_sdk::canonical::canonical_json_bytes(welcome)
                                    .map_err(|error| garth::Error::Protocol(error.to_string()))?;
                            let idempotency_key = welcome.event_id.to_string();
                            if let Err(error) = self
                                .owner
                                .post_persisted_signed_sdk_event(
                                    welcome,
                                    &idempotency_key,
                                    &canonical_body_bytes,
                                )
                                .await
                            {
                                let reason = format!("{error:#}");
                                // The Commit is already accepted and cannot be
                                // rolled back. Never terminally discard its
                                // exact Welcome material: even a deterministic
                                // rejection must remain durably diagnosable and
                                // retryable after server/policy repair, or the
                                // sender would be stranded on the old epoch.
                                let delay = mls_admission_welcome_retry_delay(&error);
                                return Ok(OutboundSubmitOutcome::RetryAfter { delay, reason });
                            }
                        }
                        let accepted_event_id = arkret_sdk::EventId::new(result.event_id.clone())
                            .map_err(|error| {
                            garth::Error::Protocol(format!(
                                "accepted MLS commit Event id is invalid: {error}"
                            ))
                        })?;
                        if let Err(error) = persist_post_accept_action(
                            self.state_store.as_ref(),
                            action.clone(),
                            accepted_event_id,
                        )
                        .await
                        {
                            return Ok(OutboundSubmitOutcome::RetryAfter {
                                delay: Duration::from_secs(60),
                                reason: format!(
                                    "MLS admission state persistence remains repairable: {error}"
                                ),
                            });
                        }
                    }
                    let event_id =
                        arkret_sdk::EventId::new(result.event_id.clone()).map_err(|error| {
                            garth::Error::Protocol(format!(
                                "server returned invalid accepted event id: {error}"
                            ))
                        })?;
                    let duplicate = result.status == "duplicate";
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
                        return Ok(OutboundSubmitOutcome::Supersede {
                            transaction_id: replacement.intent.event_id.to_string(),
                            realm_id: replacement.intent.realm_id.clone(),
                            kind: item.kind,
                            content: serde_json::to_value(replacement).map_err(|error| {
                                garth::Error::Protocol(format!(
                                    "encode semantic Event replacement: {error}"
                                ))
                            })?,
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
    if authority_principal.trim().is_empty() || device_id.trim().is_empty() {
        return;
    }
    let mut cache = verified_recovery_gate_cache()
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    cache.insert(format!("{authority_principal}\u{1f}{device_id}"));
}

fn recovery_gate_cache_key(event: &arkret_sdk::Event) -> Option<String> {
    let authority_principal = event
        .executed_by
        .as_ref()
        .unwrap_or(&event.actor_id)
        .as_str();
    let signer = crate::event_signer::active_signer()?;
    let device_id = signer.device_id()?;
    Some(format!("{authority_principal}\u{1f}{device_id}"))
}

pub(crate) fn reset_verified_recovery_gates() {
    let mut cache = verified_recovery_gate_cache()
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    cache.clear();
}

fn actor_frontier_refresh_error(actor_id: &str, error: anyhow::Error) -> anyhow::Error {
    error.context(format!(
        "refresh actor frontier for {actor_id} before submit"
    ))
}

fn pending_chat_message_ids_from_snapshot(
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
        .filter(|item| {
            matches!(
                &item.kind,
                garth::SendQueueItemKind::Custom { kind }
                    if kind == "ak.message.create"
            )
        })
        .filter_map(|item| decode_queued_sdk_event(item.content.clone()).ok())
        .filter(|queued| {
            queued.intent.realm_id.as_str() == realm_id
                && queued
                    .intent
                    .payload
                    .get("strand_id")
                    .and_then(serde_json::Value::as_str)
                    == Some(strand_id)
        })
        .map(|queued| {
            arkret_sdk::MessageId::from_event_id(&queued.intent.event_id)
                .as_str()
                .to_owned()
        })
        .collect()
}

/// Project pending chat message ids directly from the one durable Garth queue.
/// The chat UI uses this snapshot instead of maintaining a second plaintext
/// outbox with separate replay semantics.
pub(crate) async fn pending_chat_outbound_message_ids(
    actor_id: &str,
    realm_id: &str,
    strand_id: &str,
) -> anyhow::Result<std::collections::BTreeSet<String>> {
    let outbound = OutboundEngine::new(crate::outbound_store::InksonOutboundStore::open(actor_id)?);
    let snapshot = outbound.snapshot().await?;
    Ok(pending_chat_message_ids_from_snapshot(
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
        status: "accepted".to_owned(),
        cursor: String::new(),
        receipt: Value::Null,
        // The queue is the durable holder of the receipts once an item is
        // Sent; replay them from the item rather than dropping the evidence.
        ingress_receipts: item.ingress_receipts.clone(),
    }
}

fn outbound_store_scope(event: &arkret_sdk::Event, durable_post_accept: bool) -> String {
    let actor = event.actor_id.as_str();
    if durable_post_accept {
        format!("{actor}\u{1f}mls-durable-post-accept")
    } else if event.kind.as_str().starts_with("ak.mls.") {
        // Legacy MLS callers still persist their snapshot after this method
        // returns. Keep them host-only until they adopt the durable action.
        format!("{actor}\u{1f}mls-host-only")
    } else {
        actor.to_owned()
    }
}

fn durable_mls_store_scope(actor_id: &str) -> String {
    format!("{actor_id}\u{1f}mls-durable-post-accept")
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
            describe_cache: OnceCell::new(),
        }
    }

    /// The shared SDK http-client backing this submitter. Event-authoring free
    /// functions that also need a plain transport call (for example the
    /// account-data actor-scope lookup preceding a `ak.account_data.set`) reach
    /// it through here instead of holding a second `Client`.
    pub(crate) fn http(&self) -> &arkret_sdk::http_client::Client {
        &self.http
    }

    /// Persist a Realm creation intent before authoring, then freeze and
    /// submit its complete signed bootstrap unit through Garth's durable
    /// queue. A retry or process restart consumes the same queue record.
    pub(crate) async fn submit_realm_bootstrap_durable(
        &self,
        events: Vec<arkret_sdk::Event>,
        local_operation_id: String,
    ) -> anyhow::Result<arkret_sdk::RealmId> {
        let _single_writer = outbound_submit_lock().lock().await;
        let first = events
            .first()
            .ok_or_else(|| anyhow::anyhow!("Realm bootstrap unit is empty"))?;
        let actor_id = first.actor_id.clone();
        let draft_realm_id = first.realm_id.clone();
        let transport_idempotency_key = local_operation_id.clone();
        let queued = QueuedRealmBootstrap::intent(
            local_operation_id.clone(),
            transport_idempotency_key,
            events,
        )?;
        let outbound = OutboundEngine::new(crate::outbound_store::InksonOutboundStore::open(
            actor_id.as_str(),
        )?);
        outbound
            .enqueue_scoped(
                Some(local_operation_id.clone()),
                draft_realm_id,
                actor_id,
                garth::SendQueueItemKind::Custom {
                    kind: "ak.realm.bootstrap".to_owned(),
                },
                serde_json::to_value(queued)?,
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
                    let queued = decode_queued_realm_bootstrap(item.content)?;
                    return Ok(queued.authority_context_event().realm_id.clone());
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
                        event_id: local_operation_id,
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
            let queued = match classify_queued_record(&item.transaction_id, item.content.clone()) {
                QueuedRecordState::Event(queued) => *queued,
                QueuedRecordState::RealmBootstrap(_) => {
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
                QueuedRecordState::Poisoned { reason } => {
                    decisions.insert(
                        item.transaction_id,
                        OutboundGenerationFenceDecision::Quarantine { reason },
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
            let event = queued.event_for_authority_context();
            let decision = match crate::identity::authoring_generation::resolve_current_event_authoring_generation(
                &self.http,
                &event,
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
    pub(crate) async fn drain_outbound(&self, actor_id: &str) -> anyhow::Result<usize> {
        let _single_writer = outbound_submit_lock().lock().await;
        let outbound =
            OutboundEngine::new(crate::outbound_store::InksonOutboundStore::open(actor_id)?);
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

    /// Resume MLS commits that carry their encrypted post-accept snapshot.
    /// The hook commits the snapshot before Garth marks the item sent; hook
    /// failure leaves the event retryable, so a later duplicate response can
    /// finish the same idempotent action.
    pub(crate) async fn drain_mls_outbound(
        &self,
        actor_id: &str,
        state_store: crate::runtime::input::StateStoreHandle,
    ) -> anyhow::Result<usize> {
        let _single_writer = outbound_submit_lock().lock().await;
        let outbound = OutboundEngine::new(crate::outbound_store::InksonOutboundStore::open(
            &durable_mls_store_scope(actor_id),
        )?);
        let results = OutboundAttemptResults::default();
        let submitter = EventOutboundSubmitter {
            owner: self,
            results: &results,
            state_store: Some(state_store.clone()),
        };
        let hook = InksonPostAcceptHook {
            state_store: Some(state_store),
        };
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

    /// A dev server can be restarted against a newer shared SDK while this
    /// browser keeps an older WASM bundle alive. The Rust types are shared in
    /// both builds, but they are not necessarily the same build. Refuse to
    /// author or sign an Event across that boundary.
    async fn ensure_development_sdk_build_matches(&self) -> anyhow::Result<()> {
        #[cfg(all(debug_assertions, not(test)))]
        {
            let description = self.describe().await?;
            if description.development_mode {
                description
                    .validate_current_arkret_build_identity()
                    .map_err(|error| {
                        anyhow::anyhow!(
                            "stale or mixed Arkret SDK build; refusing to author Event: {error}. Rebuild/reload Inkson and restart Soland from the same SDK checkout"
                        )
                    })?;
            }
        }
        Ok(())
    }

    async fn ensure_recovery_material_ready(
        &self,
        event: &arkret_sdk::Event,
    ) -> anyhow::Result<()> {
        let cache_key = recovery_gate_cache_key(event);
        let verification = async {
            let policy: arkret_sdk::RecoveryPolicyActiveOutcome = self
                .http
                .get("/_arkret/root/identity/recovery-policy")
                .await
                .map_err(anyhow::Error::from)?;
            let backups = self
                .http
                .list_key_backups(&arkret_sdk::KeyBackupsListQuery {
                    series_id: None,
                    backup_kind: Some(arkret_sdk::BackupKind::DidRecovery),
                    cursor: None,
                    limit: None,
                })
                .await
                .map_err(anyhow::Error::from)?;
            match crate::recovery_strand::first_backup_gate_status_from_payloads(
                &serde_json::to_value(policy)?,
                &serde_json::to_value(backups)?,
            ) {
                crate::recovery_strand::FirstBackupGateStatus::Satisfied { .. } => Ok(()),
                crate::recovery_strand::FirstBackupGateStatus::Blocked(reason) => anyhow::bail!(
                    "recovery_material_pending blocks post-bootstrap persistent write: {reason:?}"
                ),
            }
        }
        .await;

        match verification {
            Ok(()) => {
                if let Some(cache_key) = cache_key {
                    verified_recovery_gate_cache()
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner)
                        .insert(cache_key);
                }
                Ok(())
            }
            Err(error)
                if outbound_retry_delay(&error).is_some()
                    && cache_key.as_ref().is_some_and(|cache_key| {
                        verified_recovery_gate_cache()
                            .lock()
                            .unwrap_or_else(PoisonError::into_inner)
                            .contains(cache_key)
                    }) =>
            {
                Ok(())
            }
            Err(error) if outbound_retry_delay(&error).is_some() => Err(error.context(
                format!(
                    "retryable recovery-material verification failed without a verified cache entry (cache_key={}, entries={})",
                    cache_key.is_some(),
                    verified_recovery_gate_cache()
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner)
                        .len(),
                ),
            )),
            Err(error) => Err(error),
        }
    }

    /// Lazily fetch + cache the service describe for this submitter. Only the
    /// signing path calls this, so a submitter that never signs never fetches.
    async fn describe_cached(&self) -> anyhow::Result<&ServiceDescribe> {
        self.describe_cache
            .get_or_try_init(|| async { self.describe().await })
            .await
    }

    pub(crate) async fn service_id(&self) -> anyhow::Result<String> {
        Ok(self.describe_cached().await?.service_id.to_string())
    }

    /// Mint a DataEvent `seal_ref` head from the membership-gated Realm Seal
    /// view. Only the CBA data-plane stamping path uses this.
    pub(crate) async fn current_seal_for(&self, realm_id: &str) -> anyhow::Result<String> {
        let view = self.events_frontier_realm_seal_view(realm_id).await?;
        Ok(view.seal_id.to_string())
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
        Ok(mls_genesis_event_id_from_events(&outcome, realm_id))
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
        actor_id: &str,
        device_id: &str,
        material: &crate::signal::SignalKeyMaterial,
        payload: &crate::signal::SignalPayload,
        state_store: &crate::runtime::input::StateStoreHandle,
    ) -> anyhow::Result<arkret_sdk::SignalSubmitOutcome> {
        let seal_ref = self.current_seal_for(scope_ref.realm_id().as_str()).await?;
        let header = crate::signal::SignalHeader::new(
            scope_ref,
            arkret_sdk::Did::new(actor_id)
                .map_err(|error| anyhow::anyhow!("invalid signal actor_id: {error}"))?,
            arkret_sdk::DeviceId::new(device_id)
                .map_err(|error| anyhow::anyhow!("invalid signal device_id: {error}"))?,
            arkret_sdk::SealId::new(seal_ref)
                .map_err(|error| anyhow::anyhow!("invalid signal seal_ref: {error}"))?,
            payload.signal_class(),
            crate::clock::now_utc(),
        );
        self.send_signal(header, material, payload, state_store)
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
                &header,
                material,
                &plaintext,
            )
        })?;
        let envelope = crate::signal::seal_signal_envelope(header, encrypted_payload)?;
        self.submit_signal_envelope(&envelope).await
    }

    /// `QUERY /_arkret/self/events/frontier` — Realm Seal view
    /// `{realm_id, seal_id, control_event_set_root, state_root, hlc?}`.
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

    async fn events_frontier_realm_state(
        &self,
        realm_id: &str,
    ) -> anyhow::Result<(
        arkret_sdk::RealmSealFrontierView,
        Vec<arkret_sdk::ManagedAgentPcrSealHeadReceipt>,
    )> {
        let selector = arkret_sdk::EventsFrontierSelector::RealmSeal {
            realm_id: arkret_sdk::RealmId::new(realm_id.to_owned())?,
        };
        let state = self
            .http
            .events_frontier(&selector)
            .await
            .map_err(anyhow::Error::from)?;
        let arkret_sdk::EventsFrontierView::RealmSeal(view) = state.frontier else {
            anyhow::bail!(
                "events/frontier for realm_id={realm_id} did not return a Realm Seal view — \
                 cannot mint seal_basis / seal_ref"
            );
        };
        if view.realm_id.as_str() != realm_id {
            anyhow::bail!(
                "events/frontier answered for realm {} instead of {realm_id}",
                view.realm_id
            );
        }
        Ok((view, state.receipts))
    }

    /// Return the accepted controller-signed head needed to author the next
    /// managed Agent PCR Seal. The head can intentionally lag accepted Events.
    /// DID-P2-B: `state_store` carries the account-level accepted-binding set
    /// down to the controller-device-key prefetch, so a frontier read outside
    /// the sync loop reuses (and contributes to) durable bindings instead of
    /// resolving into a scratch cache that is dropped immediately.
    pub(crate) async fn events_frontier_managed_agent_seal_head<
        S: crate::mls::governance_proof::GovernanceProofStateStore,
    >(
        &self,
        realm_id: &str,
        controller_id: &arkret_sdk::Did,
        state_store: S,
    ) -> anyhow::Result<(arkret_sdk::RealmSealFrontierView, arkret_sdk::Seal)> {
        let (view, receipts) = self.events_frontier_realm_state(realm_id).await?;
        let receipt = receipts.first().ok_or_else(|| {
            anyhow::anyhow!("events/frontier omitted the accepted managed Agent PCR Seal head")
        })?;
        let seal = receipt.seal.clone();
        crate::mls::governance_proof::prefetch_managed_agent_pcr_seal_head_device_key(
            &self.http,
            &seal,
            controller_id,
            state_store,
        )
        .await
        .map_err(|error| {
            anyhow::anyhow!("resolve managed Agent PCR Seal head device key: {error}")
        })?;
        crate::mls::governance_proof::verify_managed_agent_pcr_seal_head(&seal, controller_id)
            .map_err(|error| anyhow::anyhow!("invalid managed Agent PCR Seal head: {error}"))?;
        if seal.realm_id != view.realm_id
            || seal.id != view.seal_id
            || seal.control_event_set_root != view.control_event_set_root
            || seal.state_root != view.state_root
        {
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
            actor_id: arkret_sdk::Did::new(actor_id.to_owned())?,
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

    pub(crate) async fn event_proof_context(
        &self,
        event: &arkret_sdk::Event,
    ) -> anyhow::Result<crate::event_signer::EventProofContext> {
        // Durable Event envelopes are portable Realm facts. Binding their
        // proof to the authoring Principal Server would make the original
        // signature unverifiable after federation to another Realm host.
        let digest_suite = if event.kind.as_str() == arkret_sdk::EventKind::REALM_CREATE {
            serde_json::from_value::<arkret_sdk::RealmCreatePayload>(serde_json::to_value(
                &event.payload,
            )?)
            .map_err(|error| anyhow::anyhow!("decode Realm genesis digest suite: {error}"))?
            .object
            .digest_algorithm
        } else {
            let frontier = self
                .events_frontier_realm_seal_view(event.realm_id.as_str())
                .await?;
            crate::event_signer::digest_suite_from_trusted_hash(&frontier.state_root)?
        };
        Ok(crate::event_signer::EventProofContext::new().with_digest_suite(digest_suite))
    }

    /// Wire-submit a fully-prepared, already-signed SDK [`arkret_sdk::Event`].
    /// This is the only single-event HTTP tail that serialises onto
    /// `POST /_arkret/self/events`.
    async fn post_signed_sdk_event(
        &self,
        signed: &arkret_sdk::Event,
        idempotency_key: String,
    ) -> anyhow::Result<SubmitEventResult> {
        validate_signed_sdk_event_for_submit(signed)?;
        let submission =
            crate::authorization_lease::standard_initial_submission(&self.http, signed).await?;
        let response: arkret_sdk::EventsSubmitOutcome = self
            .http
            .events_submit_with_options(
                &submission,
                &arkret_sdk::http_client::ClientRequestOptions::new()
                    .request_id(idempotency_key.clone())
                    .idempotency_key(idempotency_key),
            )
            .await
            .map_err(anyhow::Error::from)?;
        ensure_events_submit_accepted(&response)?;
        Ok(SubmitEventResult::from(response))
    }

    async fn post_persisted_signed_sdk_event(
        &self,
        signed: &arkret_sdk::Event,
        idempotency_key: &str,
        canonical_body_bytes: &[u8],
    ) -> anyhow::Result<SubmitEventResult> {
        validate_signed_sdk_event_for_submit(signed)?;
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
        let submission =
            crate::authorization_lease::standard_initial_submission(&self.http, signed).await?;
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

    /// Submit a fully-prepared, already-signed SDK [`arkret_sdk::Event`]
    /// without passing through the local builder path.
    ///
    /// This is for service-returned Events that are already the authoritative
    /// wire object, such as account-authority device enrollment. It does not
    /// stamp `seal_ref` or attach proofs because either change would mutate the
    /// signed transcript.
    pub(crate) async fn submit_signed_sdk_event(
        &self,
        signed: &arkret_sdk::Event,
    ) -> anyhow::Result<SubmitEventResult> {
        self.ensure_recovery_material_ready(signed).await?;
        self.post_signed_sdk_event(signed, uuid_v7()).await
    }

    /// Submit a SDK-typed Event, signing it with the active signer when needed.
    pub(crate) async fn submit_sdk_event(
        &self,
        event: &arkret_sdk::Event,
    ) -> anyhow::Result<SubmitEventResult> {
        self.submit_sdk_event_queued(event, None, None).await
    }

    pub(crate) async fn submit_mls_event_with_snapshot(
        &self,
        event: &arkret_sdk::Event,
        realm_id: String,
        snapshot: crate::mls::persistence::MlsSnapshotEnvelope,
        state_store: crate::runtime::input::StateStoreHandle,
    ) -> anyhow::Result<SubmitEventResult> {
        self.submit_sdk_event_queued(
            event,
            Some(PostAcceptAction::MlsSnapshot { realm_id, snapshot }),
            Some(state_store),
        )
        .await
    }

    async fn submit_sdk_event_queued(
        &self,
        event: &arkret_sdk::Event,
        post_accept: Option<PostAcceptAction>,
        state_store: Option<crate::runtime::input::StateStoreHandle>,
    ) -> anyhow::Result<SubmitEventResult> {
        let _single_writer = outbound_submit_lock().lock().await;
        self.ensure_recovery_material_ready(event).await?;
        let mut intent = event.clone();
        intent.actor_seq = 0;
        intent.prev_refs.clear();
        intent.proofs.clear();
        intent.seal_ref = None;
        // A pre-join invitee cannot read the membership-gated Realm Seal
        // view. `accept_realm_invite` therefore resolves and stamps the
        // current join-candidate basis before enqueueing; preserve that basis
        // while all ordinary member-authored events continue to re-author it.
        if intent.kind.as_str() != "ak.invite.accept" {
            intent.seal_basis = None;
        }
        intent.auth_context = None;
        // `authorization_ref` is a member of the bound semantic intent
        // (`EventIntent::from_event`), so the authority-root claim must be
        // decided before the intent freezes. The authoring-time stamp in
        // `stamp_cba_basis_for_sdk_event` then finds the claim already
        // present and leaves it untouched, keeping every attempt's authored
        // envelope equal to its intent.
        self.stamp_realm_authority_root_claim(&mut intent).await;
        // The issuer attestation is part of the capability artifact itself,
        // hence part of the immutable semantic intent. Finalize it before the
        // durable queue freezes that intent; adding it during an authored
        // attempt would correctly trip the queue's mutation guard.
        attach_capability_grant_payload_proof(&mut intent)?;
        tracing::warn!(
            event_id = %intent.event_id,
            kind = %intent.kind.as_str(),
            realm = %intent.realm_id,
            authorization_ref = ?intent.authorization_ref,
            "submit intent frozen; enqueueing durable Event"
        );
        let local_operation_id = intent
            .unsigned
            .get("local_operation_idempotency_alias")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned)
            .unwrap_or_else(|| intent.event_id.to_string());
        intent.unsigned.insert(
            "local_operation_idempotency_alias".to_owned(),
            Value::String(local_operation_id.clone()),
        );
        let authoring_generation =
            match crate::identity::authoring_generation::resolve_event_authoring_generation(
                &self.http, &intent,
            )
            .await
            {
                Ok(generation) => generation,
                Err(error) if outbound_retry_delay(&error).is_some() => {
                    match crate::identity::authoring_generation::cached_event_authoring_generation(
                        &intent,
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
        self.enqueue_and_drive_sdk_event(
            event,
            QueuedSdkEvent::unauthored(
                intent,
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
    #[allow(dead_code)] // Scheduler UI is not wired yet; this is its durable transport boundary.
    pub(crate) async fn submit_scheduled_send_event(
        &self,
        scheduled_send_id: arkret_identifiers::ScheduledSendId,
        signed_event: arkret_sdk::Event,
        authoring_generation: crate::identity::authoring_generation::AuthoringGeneration,
    ) -> anyhow::Result<SubmitEventResult> {
        let _single_writer = outbound_submit_lock().lock().await;
        let queued = QueuedSdkEvent::scheduled_authored(
            scheduled_send_id,
            signed_event.clone(),
            authoring_generation,
        )?;
        self.enqueue_and_drive_sdk_event(&signed_event, queued, None)
            .await
    }

    /// Persist an MLS Add commit together with the exact signed Welcome(s) and
    /// post-commit snapshot before the first network write. Garth only marks the
    /// commit item sent after the post-accept hook has delivered every Welcome
    /// and durably installed the snapshot, so a reload at any await boundary can
    /// resume the same immutable admission saga.
    pub(crate) async fn submit_mls_admission_with_snapshot(
        &self,
        commit: arkret_sdk::Event,
        welcomes: Vec<arkret_sdk::Event>,
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
        self.ensure_recovery_material_ready(&commit).await?;
        let mut unit = Vec::with_capacity(1 + welcomes.len());
        unit.push(commit);
        unit.extend(welcomes);
        let mut prepared = self.prepare_sdk_events_batch(unit).await?;
        let signed_commit = prepared.remove(0);
        let local_operation_id = signed_commit
            .unsigned
            .get("local_operation_idempotency_alias")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned)
            .unwrap_or_else(|| signed_commit.event_id.to_string());
        let authoring_generation =
            match crate::identity::authoring_generation::resolve_event_authoring_generation(
                &self.http,
                &signed_commit,
            )
            .await
            {
                Ok(generation) => generation,
                Err(error) if outbound_retry_delay(&error).is_some() => {
                    crate::identity::authoring_generation::cached_event_authoring_generation(
                        &signed_commit,
                    )?
                    .ok_or_else(|| {
                        error.context(
                            "retryable admission authoring-generation lookup failed without a verified cache entry",
                        )
                    })?
                }
                Err(error) => return Err(error),
            };
        let canonical_body_bytes = arkret_sdk::canonical::canonical_json_bytes(&signed_commit)?;
        let transport_idempotency_key = signed_commit.event_id.to_string();
        self.enqueue_and_drive_sdk_event(
            &signed_commit,
            QueuedSdkEvent::authored(
                signed_commit.clone(),
                local_operation_id,
                transport_idempotency_key,
                canonical_body_bytes,
                None,
                authoring_generation,
                Some(PostAcceptAction::MlsAdmission {
                    realm_id,
                    actor_id,
                    device_id,
                    welcomes: prepared,
                    snapshot,
                }),
            )?,
            Some(state_store),
        )
        .await
    }

    async fn enqueue_and_drive_sdk_event(
        &self,
        event: &arkret_sdk::Event,
        queued: QueuedSdkEvent,
        state_store: Option<crate::runtime::input::StateStoreHandle>,
    ) -> anyhow::Result<SubmitEventResult> {
        let mut transaction_id = queued.local_operation_id.clone();
        let durable_post_accept = queued.post_accept.is_some();
        let outbound = OutboundEngine::new(crate::outbound_store::InksonOutboundStore::open(
            &outbound_store_scope(event, durable_post_accept),
        )?);
        let queued_value = serde_json::to_value(&queued)?;
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
            let previous = match classify_queued_record(
                &existing.transaction_id,
                existing.content.clone(),
            ) {
                QueuedRecordState::Event(previous) => Some(*previous),
                QueuedRecordState::RealmBootstrap(_) => {
                    anyhow::bail!(
                        "outbound transaction {transaction_id} is already bound to a Realm bootstrap unit"
                    );
                }
                QueuedRecordState::Poisoned { reason } => {
                    if !matches!(
                        existing.status,
                        garth::SendQueueStatus::Cancelled | garth::SendQueueStatus::Superseded
                    ) {
                        // The generation fence quarantine-cancels it on the
                        // next queue drive; the retry after that lands in
                        // the terminal repair branch below.
                        anyhow::bail!(
                            "outbound transaction {transaction_id} is blocked by a {reason}"
                        );
                    }
                    None
                }
            };
            if let Some(previous) = &previous {
                let same_event_identity = previous.local_operation_id == queued.local_operation_id
                    && previous.intent.event_id == queued.intent.event_id
                    && previous.intent.realm_id == queued.intent.realm_id
                    && previous.intent.actor_id == queued.intent.actor_id
                    && previous.intent.kind == queued.intent.kind;
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
                        event_id = %event.event_id,
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
                            event.realm_id.clone(),
                            event.actor_id.clone(),
                            garth::SendQueueItemKind::Custom {
                                kind: event.kind.to_string(),
                            },
                            serde_json::to_value(repaired)?,
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
                    event.realm_id.clone(),
                    event.actor_id.clone(),
                    garth::SendQueueItemKind::Custom {
                        kind: event.kind.to_string(),
                    },
                    queued_value,
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
        let hook = InksonPostAcceptHook { state_store };
        loop {
            let fence = match self.resolve_queue_generation_fence(&outbound).await {
                Ok(fence) => fence,
                Err(error) if outbound_retry_delay(&error).is_some() => {
                    tracing::warn!(
                        event_id = %event.event_id,
                        error = %format!("{error:#}"),
                        "durable Event generation fence refresh failed; keeping Event queued"
                    );
                    return Err(DurablyQueuedError {
                        event_id: event.event_id.to_string(),
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
                    tracing::debug!(event_id = %event.event_id, %at, "event remains in durable outbound queue");
                    return Err(DurablyQueuedError {
                        event_id: event.event_id.to_string(),
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
                    anyhow::bail!("queued event {} reached a terminal state", event.event_id);
                }
                OutboundEngineOutcome::Rejected { .. } | OutboundEngineOutcome::Terminal { .. } => {
                }
                OutboundEngineOutcome::Quarantined { item, reason }
                    if item.transaction_id == transaction_id =>
                {
                    anyhow::bail!(
                        "queued event {} quarantined by authoring-generation fence: {}",
                        event.event_id,
                        reason
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
                        event_id: event.event_id.to_string(),
                    }
                    .into());
                }
            }
        }
    }

    async fn submit_sdk_event_direct(
        &self,
        event: &arkret_sdk::Event,
        idempotency_key: &str,
        canonical_body_bytes: &[u8],
    ) -> anyhow::Result<SubmitEventResult> {
        self.post_persisted_signed_sdk_event(event, idempotency_key, canonical_body_bytes)
            .await
    }

    async fn reauthor_after_explicit_cas(
        &self,
        previous: &QueuedSdkEvent,
    ) -> anyhow::Result<QueuedSdkEvent> {
        let mut replacement = previous.intent.to_unauthored_event();
        let previous_event_id = replacement.event_id.clone();
        // A re-author changes the envelope (actor_seq, prev_refs, hlc), so the
        // derived id changes with it. Choosing a fresh random id is no longer
        // possible — and no longer needed: identical content keeps its
        // identity, which is exactly the idempotent-resubmit semantics.
        replacement.event_id = replacement.derive_event_id()?;
        let replacement_transport_key = replacement.event_id.to_string();
        replacement.unsigned.insert(
            "local_operation_idempotency_alias".to_owned(),
            Value::String(replacement_transport_key),
        );
        let (event, transport_idempotency_key) =
            self.prepare_frozen_intent_for_submit(&replacement).await?;
        let canonical_body_bytes = arkret_sdk::canonical::canonical_json_bytes(&event)?;
        Ok(QueuedSdkEvent::authored(
            event,
            previous.local_operation_id.clone(),
            transport_idempotency_key,
            canonical_body_bytes,
            Some(previous_event_id),
            previous.authoring_generation.clone(),
            previous.post_accept.clone(),
        )?)
    }

    pub(crate) async fn prepare_sdk_event_for_submit(
        &self,
        event: &arkret_sdk::Event,
    ) -> anyhow::Result<(arkret_sdk::Event, String)> {
        self.prepare_sdk_event_inner(event, SemanticAuthoring::Fresh)
            .await
    }

    /// [`Self::prepare_sdk_event_for_submit`] for re-authoring a FROZEN queued
    /// intent. `authorization_ref` is a bound member of the semantic intent
    /// (`EventIntent`), so a replay attempt MUST reproduce it verbatim —
    /// stamping a claim the frozen intent does not carry would make the
    /// authored envelope diverge from its intent and the queue's semantic
    /// guard would (correctly) cancel the item. This is exactly what happened
    /// to Events queued while the session was dead: their intents froze
    /// without the claim, and a post-re-login replay must not "upgrade" them.
    pub(crate) async fn prepare_frozen_intent_for_submit(
        &self,
        event: &arkret_sdk::Event,
    ) -> anyhow::Result<(arkret_sdk::Event, String)> {
        self.prepare_sdk_event_inner(event, SemanticAuthoring::FrozenIntent)
            .await
    }

    async fn prepare_sdk_event_inner(
        &self,
        event: &arkret_sdk::Event,
        authoring: SemanticAuthoring,
    ) -> anyhow::Result<(arkret_sdk::Event, String)> {
        self.ensure_development_sdk_build_matches().await?;
        let mut signed = event.clone();
        self.refresh_unsigned_sdk_event_actor_frontier(&mut signed)
            .await?;
        self.stamp_cba_basis_for_sdk_event_inner(&mut signed, authoring)
            .await?;
        // Fresh single-Event submission finalizes this proof before freezing
        // the durable intent. Keep this idempotent call for direct preparation
        // and batch callers, which do not pass through that queue boundary.
        attach_capability_grant_payload_proof(&mut signed)?;
        if signed.proofs.is_empty() {
            let proof_context = self.event_proof_context(&signed).await?;
            crate::event_signer::sign_sdk_event_with_active_context(&mut signed, proof_context)
                .map_err(|err| {
                    anyhow::anyhow!(
                        "no active signer configured \u{2014} cannot submit unsigned SDK Event: {err}"
                    )
                })?;
        }
        let idempotency_key = signed
            .unsigned
            .get("local_operation_idempotency_alias")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned)
            .unwrap_or_else(uuid_v7);
        Ok((signed, idempotency_key))
    }

    pub(crate) async fn stamp_cba_basis_for_sdk_event(
        &self,
        event: &mut arkret_sdk::Event,
    ) -> anyhow::Result<()> {
        self.stamp_cba_basis_for_sdk_event_inner(event, SemanticAuthoring::Fresh)
            .await
    }

    async fn stamp_cba_basis_for_sdk_event_inner(
        &self,
        event: &mut arkret_sdk::Event,
        authoring: SemanticAuthoring,
    ) -> anyhow::Result<()> {
        if event.seal_ref.is_some()
            || event.auth_context.is_some()
            || event.seal_basis.is_some()
            || cba_exempt_reducer_kind(&event.kind)
        {
            return Ok(());
        }
        let Some(plane) = cba_effect_plane_for_event(event)? else {
            return Ok(());
        };
        // The authority-root claim is a signed envelope member, so it must be
        // in place before the proof is attached; admission resolves it the
        // same way on both planes. It is a SEMANTIC decision though: replays
        // of a frozen intent must reproduce the intent's choice verbatim.
        if authoring == SemanticAuthoring::Fresh {
            self.stamp_realm_authority_root_claim(event).await;
        }
        match plane {
            CbaEffectPlane::Control => {
                let seal_view = self
                    .events_frontier_realm_seal_view(event.realm_id.as_str())
                    .await?;
                event.seal_basis = Some(seal_view.seal_basis());
            }
            CbaEffectPlane::Data => {
                if !event.preconditions.is_empty() {
                    anyhow::bail!(
                        "DataEvent {} carries preconditions; CBA DataEvents must use seal_ref + auth_context only",
                        event.event_id
                    );
                }
                let seal = self.current_seal_for(event.realm_id.as_str()).await?;
                event.seal_ref = Some(
                    arkret_sdk::SealId::new(seal)
                        .map_err(|err| anyhow::anyhow!("current seal id is invalid: {err}"))?,
                );
                event.auth_context = Some(data_event_auth_context(event)?);
            }
        }
        tracing::warn!(
            event_id = %event.event_id,
            kind = %event.kind.as_str(),
            seal_ref = ?event.seal_ref.as_ref().map(|seal| seal.as_str()),
            has_seal_basis = event.seal_basis.is_some(),
            authorization_ref = ?event.authorization_ref,
            "authored CBA basis for submit attempt"
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
    async fn stamp_realm_authority_root_claim(&self, event: &mut arkret_sdk::Event) {
        if event.authorization_ref.is_some()
            || event.executed_by.is_some()
            || event.applet_id.is_some()
            || !realm_owner_covers_event_kind(event.kind.as_str())
        {
            return;
        }
        let authority = match self.realm_create_authority(event.realm_id.as_str()).await {
            Ok(authority) => authority,
            Err(error) => {
                tracing::warn!(
                    realm = %event.realm_id,
                    kind = %event.kind.as_str(),
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
        if let Some(reference) = realm_authority_root_claim(event, authority.as_ref()) {
            tracing::warn!(
                realm = %event.realm_id,
                kind = %event.kind.as_str(),
                "stamped realm authority-root claim on owner-authored event",
            );
            event.authorization_ref = Some(reference);
        } else {
            tracing::debug!(
                realm = %event.realm_id,
                kind = %event.kind.as_str(),
                resolved = authority.is_some(),
                "no realm authority-root claim for this event; ordinary grant path",
            );
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
        let resolved = realm_create_authority_from_events(&outcome.events, realm_id);
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

    async fn refresh_unsigned_sdk_event_actor_frontier(
        &self,
        event: &mut arkret_sdk::Event,
    ) -> anyhow::Result<()> {
        if !event.proofs.is_empty() {
            return Ok(());
        }
        let actor_id = event.actor_id.as_str().to_owned();
        let realm_id = event.realm_id.as_str();
        match self.events_frontier_actor(&actor_id, realm_id).await {
            Ok(frontier) => {
                apply_actor_frontier_to_sdk_event(event, &frontier)?;
            }
            Err(error) => return Err(actor_frontier_refresh_error(&actor_id, error)),
        }
        let stamp = crate::signing_stamp::issue_event_stamp(event).await?;
        event.hlc = Some(stamp.hlc);
        Ok(())
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
        sdk_events: &[arkret_sdk::Event],
        idempotency_key: Option<&str>,
    ) -> anyhow::Result<arkret_sdk::EventsSubmitOutcome> {
        let first_event = sdk_events
            .first()
            .ok_or_else(|| anyhow::anyhow!("events.submit batch must not be empty"))?;
        self.ensure_recovery_material_ready(first_event).await?;
        // YOU-01-016: the former `capabilities.batch_submit` probe (a
        // non-spec soland capability field) was removed. The batch request
        // body is one of the three spec-defined `ak.self.events.command.submit`
        // shapes (distinguished by JSON shape), so it is sent
        // unconditionally — no capability negotiation exists in the spec.
        for sdk_event in sdk_events {
            validate_signed_sdk_event_for_submit(sdk_event)?;
        }
        // `idempotency_key` is not a body field in v1: it travels only in the
        // `Idempotency-Key` header.
        let anchor_unit = first_event.kind.as_str() == arkret_sdk::EventKind::REALM_CREATE;
        let mut submissions = Vec::with_capacity(sdk_events.len());
        for event in sdk_events {
            let submission = if uses_bare_online_anchor_submission(anchor_unit, event) {
                let submission = arkret_wire::EventInitialSubmission::online(event.clone());
                submission
                    .validate_structural_in_context(arkret_wire::EventSubmitContext::AnchorUnit)
                    .map_err(anyhow::Error::from)?;
                submission
            } else {
                crate::authorization_lease::standard_initial_submission(&self.http, event).await?
            };
            submissions.push(submission);
        }
        let body = arkret_sdk::EventsSubmitBatchRequestBody {
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
        events: Vec<arkret_sdk::Event>,
        idempotency_key: Option<&str>,
    ) -> anyhow::Result<arkret_sdk::EventsSubmitOutcome> {
        if events
            .first()
            .is_some_and(|event| event.kind.as_str() == arkret_sdk::EventKind::REALM_CREATE)
            && events
                .get(1)
                .is_some_and(|event| event.kind.as_str() == arkret_sdk::EventKind::CAPABILITY_GRANT)
        {
            crate::identity::authoring_generation::resolve_event_authoring_generation(
                &self.http, &events[0],
            )
            .await?;
        }
        let events = self.prepare_sdk_events_batch(events).await?;
        self.submit_signed_sdk_events_batch(&events, idempotency_key)
            .await
    }

    pub(crate) async fn prepare_sdk_events_batch(
        &self,
        mut events: Vec<arkret_sdk::Event>,
    ) -> anyhow::Result<Vec<arkret_sdk::Event>> {
        self.ensure_development_sdk_build_matches().await?;
        let first_is_realm_create = events
            .first()
            .is_some_and(|event| event.kind.as_str() == arkret_sdk::EventKind::REALM_CREATE);
        let is_identity_anchor_unit = first_is_realm_create
            && events.len() == 2
            && events.get(1).is_some_and(|event| {
                event.kind.as_str() == arkret_sdk::EventKind::DEVICE_AUTHORIZE
            })
            && arkret_bootstrap::validate_self_principal_bootstrap_unit(
                &events[0],
                &events[1],
                &crate::operation::cell_write_projector,
            )
            .is_ok();
        let is_managed_agent_pcr_create = first_is_realm_create
            && events.len() == 1
            && arkret_bootstrap::materialize_managed_agent_pcr_control(
                &events,
                &crate::operation::cell_write_projector,
            )
            .is_ok();
        let is_ordinary_realm_bootstrap =
            if first_is_realm_create && !is_identity_anchor_unit && !is_managed_agent_pcr_create {
                arkret_policy::realm_bootstrap::validate_realm_bootstrap_unit(&events)
                    .map_err(|error| anyhow::anyhow!(error.reason_code()))?;
                true
            } else {
                false
            };
        let is_genesis_unit =
            is_ordinary_realm_bootstrap || is_identity_anchor_unit || is_managed_agent_pcr_create;
        for event in &mut events {
            attach_capability_grant_payload_proof(event)?;
        }
        let genesis_digest_suite = events
            .first()
            .filter(|event| event.kind.as_str() == arkret_sdk::EventKind::REALM_CREATE)
            .map(|event| {
                serde_json::from_value::<arkret_sdk::RealmCreatePayload>(serde_json::to_value(
                    &event.payload,
                )?)
                .map(|payload| payload.object.digest_algorithm)
                .map_err(|error| anyhow::anyhow!("decode Realm genesis digest suite: {error}"))
            })
            .transpose()?;
        let mut batch_frontiers =
            BTreeMap::<(arkret_sdk::RealmId, arkret_sdk::Did), (u64, arkret_sdk::EventId)>::new();
        let mut rewritten_event_ids = BTreeMap::<arkret_sdk::EventId, arkret_sdk::EventId>::new();
        let mut genesis_realm_rebind = None::<(arkret_sdk::RealmId, arkret_sdk::RealmId)>;
        let mut proof_contexts = Vec::with_capacity(events.len());
        for (index, event) in events.iter_mut().enumerate() {
            if let Some((old_realm, new_realm)) = &genesis_realm_rebind {
                rebind_bootstrap_realm(event, old_realm, new_realm);
            }
            rewrite_event_id_references(event, &rewritten_event_ids);
            let old_event_id = event.event_id.clone();
            let old_realm_id = event.realm_id.clone();
            if event.proofs.is_empty() {
                let scope = (event.realm_id.clone(), event.actor_id.clone());
                if let Some((actor_seq, event_id)) = batch_frontiers.get(&scope) {
                    let next_actor_seq = actor_seq.checked_add(1).ok_or_else(|| {
                        anyhow::anyhow!("actor sequence exhausted for batch scope")
                    })?;
                    apply_actor_chain_basis_to_sdk_event(
                        event,
                        next_actor_seq,
                        std::slice::from_ref(event_id),
                    );
                    let stamp = crate::signing_stamp::issue_event_stamp(event).await?;
                    event.hlc = Some(stamp.hlc);
                } else if index == 0 && is_genesis_unit {
                    // A registered Realm/identity genesis unit creates its own
                    // `(realm_id, actor_id)` chain. The Realm does not exist yet,
                    // so a remote frontier lookup cannot distinguish genesis from
                    // an invisible Realm and MUST NOT be used to author this unit.
                    apply_actor_chain_basis_to_sdk_event(event, 0, &[]);
                    let stamp = crate::signing_stamp::issue_event_stamp(event).await?;
                    event.hlc = Some(stamp.hlc);
                } else {
                    self.refresh_unsigned_sdk_event_actor_frontier(event)
                        .await?;
                }
                if !is_genesis_unit {
                    self.stamp_cba_basis_for_sdk_event(event).await?;
                }
                let proof_context = if let Some(digest_suite) = genesis_digest_suite {
                    crate::event_signer::EventProofContext::new().with_digest_suite(digest_suite)
                } else {
                    self.event_proof_context(event).await?
                };
                crate::operation::rederive_event_identity_with_digest_suite(
                    event,
                    proof_context.digest_suite,
                )?;
                if index == 0 && first_is_realm_create && event.realm_id != old_realm_id {
                    genesis_realm_rebind = Some((old_realm_id.clone(), event.realm_id.clone()));
                }
                if event.event_id != old_event_id {
                    rewritten_event_ids.insert(old_event_id, event.event_id.clone());
                }
                proof_contexts.push(Some(proof_context));
            } else {
                proof_contexts.push(None);
            }
            let scope = (event.realm_id.clone(), event.actor_id.clone());
            batch_frontiers.insert(scope, (event.actor_seq, event.event_id.clone()));
        }
        if is_ordinary_realm_bootstrap {
            arkret_policy::realm_bootstrap::validate_realm_bootstrap_unit(&events)
                .map_err(|error| anyhow::anyhow!(error.reason_code()))?;
        }
        for (index, event) in events.iter_mut().enumerate() {
            if event.proofs.is_empty() {
                let proof_context = proof_contexts[index]
                    .clone()
                    .expect("unsigned Event has a prepared proof context");
                crate::event_signer::sign_sdk_event_with_active_context(
                    event,
                    proof_context,
                )
                .map_err(|err| {
                    anyhow::anyhow!(
                        "no active signer configured \u{2014} cannot submit SDK Event batch: {err}"
                    )
                })?;
            }
        }
        Ok(events)
    }

    pub(crate) async fn prepare_initial_submissions(
        &self,
        events: Vec<arkret_sdk::Event>,
    ) -> anyhow::Result<Vec<arkret_wire::EventInitialSubmission>> {
        let events = self.prepare_sdk_events_batch(events).await?;
        let mut submissions = Vec::with_capacity(events.len());
        for event in &events {
            submissions.push(
                crate::authorization_lease::standard_initial_submission(&self.http, event).await?,
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
pub(crate) fn attach_capability_grant_payload_proof(
    event: &mut arkret_sdk::Event,
) -> anyhow::Result<()> {
    if event.kind.as_str() != arkret_sdk::EventKind::CAPABILITY_GRANT {
        return Ok(());
    }
    validate_capability_grant_payload(event)
}

#[cfg(test)]
pub(crate) fn attach_capability_grant_payload_proof_with_signer(
    event: &mut arkret_sdk::Event,
    _signer: &crate::event_signer::InksonEventSigner,
) -> anyhow::Result<()> {
    validate_capability_grant_payload(event)
}

fn validate_capability_grant_payload(event: &arkret_sdk::Event) -> anyhow::Result<()> {
    if event.kind.as_str() != arkret_sdk::EventKind::CAPABILITY_GRANT {
        return Ok(());
    }
    let payload: arkret_sdk::CapabilityGrantPayload = serde_json::from_value(
        serde_json::to_value(&event.payload)
            .map_err(|error| anyhow::anyhow!("encode capability grant payload: {error}"))?,
    )
    .map_err(|error| anyhow::anyhow!("decode capability grant payload: {error}"))?;
    if payload.grant.issuer != event.actor_id {
        anyhow::bail!("capability grant issuer must equal the Event actor");
    }
    Ok(())
}

fn validate_signed_sdk_event_for_submit(event: &arkret_sdk::Event) -> anyhow::Result<()> {
    if event.proofs.is_empty() {
        anyhow::bail!(
            "submit refuses unsigned SDK Event (event_id={}, kind={})",
            event.event_id,
            event.kind.as_str()
        );
    }
    event.validate_proof_bindings().map_err(|err| {
        anyhow::anyhow!("event proof binding invalid for {}: {err}", event.event_id)
    })?;
    validate_outgoing_registered_event_payload(event.kind.as_str(), &event.payload)
}

fn apply_actor_frontier_to_sdk_event(
    event: &mut arkret_sdk::Event,
    frontier: &arkret_sdk::RealmActorFrontierView,
) -> anyhow::Result<()> {
    if frontier.actor_id != event.actor_id || frontier.realm_id != event.realm_id {
        anyhow::bail!(
            "realm actor frontier mismatch: event scope ({}, {}) but frontier scope ({}, {})",
            event.realm_id,
            event.actor_id,
            frontier.realm_id,
            frontier.actor_id
        );
    }
    frontier.validate()?;
    apply_actor_chain_basis_to_sdk_event(
        event,
        frontier.next_actor_seq,
        &frontier.frontier_event_ids,
    );
    Ok(())
}

fn apply_actor_chain_basis_to_sdk_event(
    event: &mut arkret_sdk::Event,
    next_actor_seq: u64,
    frontier_event_ids: &[arkret_sdk::EventId],
) {
    event.actor_seq = next_actor_seq;
    event.prev_refs = frontier_event_ids.to_vec();
}

fn rebind_bootstrap_realm(
    event: &mut arkret_sdk::Event,
    old_realm: &arkret_sdk::RealmId,
    new_realm: &arkret_sdk::RealmId,
) {
    if &event.realm_id == old_realm {
        event.realm_id = new_realm.clone();
    }
    match &mut event.scope_ref {
        arkret_sdk::ScopeRef::Realm { realm_id }
        | arkret_sdk::ScopeRef::Circle { realm_id, .. }
            if realm_id == old_realm =>
        {
            *realm_id = new_realm.clone();
        }
        _ => {}
    }
    for value in event.payload.values_mut() {
        replace_exact_string_in_value(value, old_realm.as_str(), new_realm.as_str());
    }
}

fn rewrite_event_id_references(
    event: &mut arkret_sdk::Event,
    rewrites: &BTreeMap<arkret_sdk::EventId, arkret_sdk::EventId>,
) {
    if rewrites.is_empty() {
        return;
    }
    for event_ref in &mut event.refs {
        if let Some((_, replacement)) = rewrites
            .iter()
            .find(|(candidate, _)| candidate.as_str() == event_ref.id)
        {
            event_ref.id = replacement.to_string();
        }
    }
    if let Some(redacts) = &mut event.redacts
        && let Some(replacement) = rewrites.get(redacts)
    {
        *redacts = replacement.clone();
    }
    for value in event.payload.values_mut() {
        rewrite_event_ids_in_value(value, rewrites);
    }
    for precondition in &mut event.preconditions {
        if let Some(value) = &mut precondition.predicate.value {
            rewrite_event_ids_in_value(value, rewrites);
        }
        if let Some(values) = &mut precondition.predicate.values {
            for value in values {
                rewrite_event_ids_in_value(value, rewrites);
            }
        }
    }
}

fn rewrite_event_ids_in_value(
    value: &mut serde_json::Value,
    rewrites: &BTreeMap<arkret_sdk::EventId, arkret_sdk::EventId>,
) {
    match value {
        serde_json::Value::String(current) => {
            if let Some((_, replacement)) = rewrites
                .iter()
                .find(|(candidate, _)| candidate.as_str() == current)
            {
                *current = replacement.to_string();
            }
        }
        serde_json::Value::Array(values) => {
            for value in values {
                rewrite_event_ids_in_value(value, rewrites);
            }
        }
        serde_json::Value::Object(object) => {
            for value in object.values_mut() {
                rewrite_event_ids_in_value(value, rewrites);
            }
        }
        _ => {}
    }
}

fn replace_exact_string_in_value(value: &mut serde_json::Value, old: &str, new: &str) {
    match value {
        serde_json::Value::String(current) if current == old => *current = new.to_owned(),
        serde_json::Value::Array(values) => {
            for value in values {
                replace_exact_string_in_value(value, old, new);
            }
        }
        serde_json::Value::Object(object) => {
            for value in object.values_mut() {
                replace_exact_string_in_value(value, old, new);
            }
        }
        _ => {}
    }
}

fn mls_genesis_event_id_from_events(
    outcome: &arkret_sdk::EventsQueryOutcome,
    realm_id: &str,
) -> Option<arkret_sdk::EventId> {
    outcome
        .events
        .iter()
        .find(|event| {
            event.realm_id.as_str() == realm_id
                && event.kind.as_str() == arkret_sdk::EventKind::MLS_GENESIS
        })
        .map(|event| event.event_id.clone())
}

fn cba_exempt_reducer_kind(kind: &arkret_sdk::events::kinds::EventKind) -> bool {
    matches!(kind, arkret_sdk::EventKind::RealmCreate)
}

/// Authority facts pinned by a Realm's accepted `ak.realm.create`.
///
/// `ak.realm.create` is the only registered writer of
/// `ak.component.realm.authority_root.v1` in v1, and its registered
/// `value_projection` derives `controller_id` from `payload.object.created_by`.
/// Both members are create-locked, so a resolved value never changes and is
/// cached per process. (`ak.realm.owner.transfer` will move the controller in
/// a later protocol phase; admission re-validates the claim against the
/// Event's own Seal basis either way, so a stale cache can only fail closed,
/// never over-claim.)
#[derive(Clone, Debug, PartialEq)]
enum RealmCreateAuthority {
    /// The create carries the create-locked
    /// `capability_action_registry_digest`, so the registered reducer
    /// contract materialized the authority-root cell.
    Root { controller_id: String },
    /// The accepted create predates the authority-root contract: the Realm
    /// has no root cell, and claiming root authority there can only fail
    /// closed at admission (`realm_authority_root_missing`).
    NoAuthorityRoot,
}

fn realm_create_authority_cache() -> &'static Mutex<BTreeMap<String, RealmCreateAuthority>> {
    static CACHE: SyncOnceLock<Mutex<BTreeMap<String, RealmCreateAuthority>>> = SyncOnceLock::new();
    CACHE.get_or_init(|| Mutex::new(BTreeMap::new()))
}

/// The first page of the ascending Realm log is the genesis unit, whose head
/// is the `ak.realm.create` itself; the margin only covers interleaved
/// bootstrap follow-ups so the lookup never paginates.
const REALM_CREATE_AUTHORITY_QUERY_LIMIT: u32 = 16;

fn realm_create_authority_from_events(
    events: &[arkret_sdk::Event],
    realm_id: &str,
) -> Option<RealmCreateAuthority> {
    events.iter().find_map(|event| {
        if event.realm_id.as_str() != realm_id
            || event.kind.as_str() != arkret_sdk::EventKind::REALM_CREATE
        {
            return None;
        }
        let object = event.payload.get("object")?;
        let controller_id = object.get("created_by")?.as_str()?.trim();
        if controller_id.is_empty() {
            return None;
        }
        let has_authority_root_contract = object
            .get("capability_action_registry_digest")
            .and_then(Value::as_str)
            .is_some_and(|digest| !digest.trim().is_empty());
        Some(if has_authority_root_contract {
            RealmCreateAuthority::Root {
                controller_id: controller_id.to_owned(),
            }
        } else {
            RealmCreateAuthority::NoAuthorityRoot
        })
    })
}

/// Whether `ak.realm.owner` may author `kind` directly (its registry-derived
/// operational coverage). A root claim on a kind outside this set would turn
/// the ordinary grant search into a hard `capability_denied` at admission.
fn realm_owner_covers_event_kind(kind: &str) -> bool {
    arkret_schema::capability_action("ak.realm.owner")
        .is_some_and(|descriptor| descriptor.target_event_kinds.contains(&kind))
}

/// The `authorization_ref` a directly-authoring Realm root controller must
/// carry, or `None` when this Event must keep the ordinary grant path.
///
/// `capabilities.md` §3.2: owner operational authorization exists only as the
/// registered authority-root claim — the receiver MUST NOT infer it from
/// `created_by` / membership — and Realm bootstrap issues no grants at all,
/// so an unclaimed owner Event fails
/// `no capability at seal_ref covers action …` even for the creator.
/// Producer-chosen authorization stays untouched: an Event that already names
/// an `authorization_ref` (applet delegation, literal grant) or that a
/// service executes on someone's behalf keeps its own authorization story.
fn realm_authority_root_claim(
    event: &arkret_sdk::Event,
    authority: Option<&RealmCreateAuthority>,
) -> Option<arkret_sdk::AuthorizationRef> {
    if event.authorization_ref.is_some()
        || event.executed_by.is_some()
        || event.applet_id.is_some()
        || !realm_owner_covers_event_kind(event.kind.as_str())
    {
        return None;
    }
    match authority? {
        RealmCreateAuthority::Root { controller_id }
            if controller_id == event.actor_id.as_str() =>
        {
            Some(
                arkret_sdk::AuthorizationRef::new(arkret_wire::REALM_AUTHORITY_ROOT_CELL)
                    .expect("realm authority-root constant must be valid"),
            )
        }
        _ => None,
    }
}

/// CBA plane this Event's registered contract routes it through.
///
/// v1 reads the plane from the event-kind registry instead of scanning a
/// producer-supplied `effects[]` array: the plane is a property of the kind,
/// and letting a producer imply it by choosing cells was exactly the
/// reducer-instruction channel v1 removed. `None` means the kind is not a
/// reducer input and needs no CBA basis at all.
///
/// The derived cell families are still cross-checked against the registry's
/// per-family plane, so a registry row whose kind plane and cell-family plane
/// disagree fails closed here rather than at the receiver.
fn cba_effect_plane_for_event(event: &arkret_sdk::Event) -> anyhow::Result<Option<CbaEffectPlane>> {
    let Some(descriptor) = event.kind.descriptor().filter(|row| row.reducer_input) else {
        return Ok(None);
    };
    let plane = match descriptor.plane {
        Some("control") => CbaEffectPlane::Control,
        Some("data") => CbaEffectPlane::Data,
        other => anyhow::bail!(
            "reducer-input kind {} declares no known CBA plane ({other:?})",
            event.kind.as_str()
        ),
    };
    for write in crate::operation::project_registered_cell_writes(event)
        .map_err(|error| anyhow::anyhow!("cell-write projection failed: {error}"))?
    {
        let cell = arkret_sdk::CellId::from_ref(&write.cell)
            .map_err(|error| anyhow::anyhow!("projected cell is invalid: {error}"))?;
        let cell_plane = cba_cell_family_plane(cell.component()).ok_or_else(|| {
            anyhow::anyhow!(
                "projected cell references unknown cell family {}",
                cell.component()
            )
        })?;
        if cell_plane != plane {
            anyhow::bail!(
                "event {} projects a {cell_plane:?} cell on the {plane:?} plane",
                event.event_id
            );
        }
    }
    Ok(Some(plane))
}

/// The `auth_context` a DataEvent pins alongside `seal_ref`.
///
/// It names the signing DID and key epoch the receiver verifies authorization
/// with **at `seal_ref`** — nothing more. `models/event-and-patch.md` §75 lists
/// `effects`, `conflict_keys_digest` and producer-selected
/// `auth_context.capability_refs` together as members that are NOT v1 wire
/// fields and that a receiver MUST reject with `schema_violation`. Effective
/// capabilities are derived from the accepted governance basis, so a producer
/// that listed its own grants would be selecting the authorization it is
/// supposed to be constrained by.
fn data_event_auth_context(event: &arkret_sdk::Event) -> anyhow::Result<arkret_sdk::AuthContext> {
    let did = event
        .executed_by
        .clone()
        .unwrap_or_else(|| event.actor_id.clone());
    let key_id = data_event_key_id_for(event);
    Ok(arkret_sdk::AuthContext {
        did,
        key_id,
        key_epoch: 0,
        credential_epoch: None,
    })
}

fn data_event_key_id_for(event: &arkret_sdk::Event) -> String {
    let controller = event
        .executed_by
        .as_ref()
        .map(|did| did.as_str())
        .unwrap_or_else(|| event.actor_id.as_str());
    let Some(signer) = crate::event_signer::active_signer() else {
        return "device".to_owned();
    };
    if let Some(device_id) = signer.device_id() {
        return device_id.to_owned();
    }
    let method = signer.verification_method();
    let method_without_query = method
        .split_once('?')
        .map(|(head, _)| head)
        .unwrap_or(method);
    let Some((method_controller, fragment)) = method_without_query.split_once('#') else {
        return "device".to_owned();
    };
    if method_controller == controller && !fragment.is_empty() {
        fragment.to_owned()
    } else {
        "device".to_owned()
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::operation::EventExt;

    fn test_authoring_generation() -> crate::identity::authoring_generation::AuthoringGeneration {
        crate::identity::authoring_generation::AuthoringGeneration {
            authority_model:
                crate::identity::authoring_generation::AuthoringAuthorityModel::EnrollmentAuthority,
            authority_principal_id: "did:web:alice.example".to_owned(),
            generation_ref: "1-QmCurrent".to_owned(),
        }
    }

    fn fixture_event_id(event_id: &str) -> arkret_sdk::EventId {
        arkret_sdk::EventId::new(event_id).unwrap()
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
        managed.executed_by = Some(arkret_sdk::Did::new("did:web:alice.example").unwrap());
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
                event,
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
        let mut event: arkret_sdk::Event = serde_json::from_value(json!({
            "event_id": "ak:event:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19",
            "kind": "ak.message.create",
            "realm_id": "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19",
            "scope_ref": {
                "kind": "realm",
                "realm_id": "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19"
            },
            "actor_id": "did:web:alice.example",
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
        event.refresh_content_bound_identity().unwrap();
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
        assert_eq!(dispatch.event_id, event.event_id);
        assert_eq!(
            dispatch.message_id,
            arkret_sdk::MessageId::from_event_id(&event.event_id)
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

    #[test]
    fn event_intent_digest_ignores_authoring_freshness_fields() {
        let mut first = sdk_event_without_proof("did:web:alice.example");
        first.unsigned.insert(
            "local_operation_idempotency_alias".to_owned(),
            Value::String("attempt-one".to_owned()),
        );
        let mut second = first.clone();
        second.actor_seq = 42;
        second.hlc = None;
        second.prev_refs = vec![fixture_event_id(
            "ak:event:AXBcp13trH3bPXvj0eHppCpGqJZWL9yqE3cf2Tl43vyk",
        )];
        second.unsigned.insert(
            "local_operation_idempotency_alias".to_owned(),
            Value::String("attempt-two".to_owned()),
        );

        let first = EventIntent::from_event(first);
        let second = EventIntent::from_event(second);
        assert_eq!(first, second);
        assert_eq!(first.digest().unwrap(), second.digest().unwrap());
    }

    #[test]
    fn event_intent_digest_changes_with_semantic_payload() {
        let first = sdk_event_without_proof("did:web:alice.example");
        let mut second = first.clone();
        second
            .payload
            .insert("state".to_owned(), Value::String("away".to_owned()));

        let first = EventIntent::from_event(first);
        let second = EventIntent::from_event(second);
        assert_ne!(first, second);
        assert_ne!(first.digest().unwrap(), second.digest().unwrap());
    }

    #[test]
    fn capability_payload_validation_does_not_mutate_queue_intent() {
        let mut event = crate::operation::ak_ops::capability_grant_actions(
            "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19",
            "did:web:alice.example",
            "did:web:bob.example",
            &["ak.message.create"],
            None,
            Value::Null,
        )
        .unwrap()
        .build_sdk_event("inkson")
        .unwrap();
        let unsigned_intent = EventIntent::from_event(event.clone());
        let signer = crate::event_signer::build_ed25519_device_signer(
            [42_u8; 32],
            "did:web:alice.example",
            "ak:device:01904100-0000-7000-8000-a11ce0000001",
        );

        attach_capability_grant_payload_proof_with_signer(&mut event, &signer).unwrap();
        let frozen = QueuedSdkEvent::unauthored(
            event,
            "capability-operation".to_owned(),
            "capability-attempt".to_owned(),
            None,
            test_authoring_generation(),
            None,
        )
        .unwrap();
        assert_eq!(frozen.intent, unsigned_intent);
        assert!(frozen.intent.payload["grant"].get("proofs").is_none());

        let mut authored_attempt = frozen.intent.to_unauthored_event();
        attach_capability_grant_payload_proof_with_signer(&mut authored_attempt, &signer).unwrap();
        assert_eq!(EventIntent::from_event(authored_attempt), frozen.intent);
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
        pending.payload = serde_json::from_value(json!({
            "message_id": "ak:message:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19",
            "strand_id": "ak:strand:AT3p9polsnQ_WOix32QZimMdE2zPe62HptJu2PaO3V1h"
        }))
        .unwrap();
        queue
            .enqueue(
                Some(pending.event_id.to_string()),
                realm.clone(),
                garth::SendQueueItemKind::Custom {
                    kind: "ak.message.create".to_owned(),
                },
                serde_json::to_value(
                    QueuedSdkEvent::unauthored(
                        pending,
                        "pending-operation".to_owned(),
                        "pending-attempt".to_owned(),
                        None,
                        test_authoring_generation(),
                        None,
                    )
                    .unwrap(),
                )
                .unwrap(),
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
            "message_id": "ak:message:AcsFZ3o2tOdN3EFpNceeLV-aI3jZkB9S34_4YIwJ5DLy",
            "strand_id": "ak:strand:AXBcp13trH3bPXvj0eHppCpGqJZWL9yqE3cf2Tl43vyk"
        }))
        .unwrap();
        queue
            .enqueue(
                Some(other_conversation.event_id.to_string()),
                realm.clone(),
                garth::SendQueueItemKind::Custom {
                    kind: "ak.message.create".to_owned(),
                },
                serde_json::to_value(
                    QueuedSdkEvent::unauthored(
                        other_conversation,
                        "other-operation".to_owned(),
                        "other-attempt".to_owned(),
                        None,
                        test_authoring_generation(),
                        None,
                    )
                    .unwrap(),
                )
                .unwrap(),
                Vec::new(),
            )
            .unwrap();

        let sent = sdk_event_with_kind(
            "ak:event:ASeIBHNVQyeIcU4aBIt2t2BF_ikuVMH0kNru_HgO_gG1",
            realm.as_str(),
            "ak.message.create",
            actor,
        );
        let sent_transaction = sent.event_id.to_string();
        queue
            .enqueue(
                Some(sent_transaction.clone()),
                realm.clone(),
                garth::SendQueueItemKind::Custom {
                    kind: "ak.message.create".to_owned(),
                },
                serde_json::to_value(
                    QueuedSdkEvent::unauthored(
                        sent,
                        "sent-operation".to_owned(),
                        "sent-attempt".to_owned(),
                        None,
                        test_authoring_generation(),
                        None,
                    )
                    .unwrap(),
                )
                .unwrap(),
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

        assert_eq!(
            pending_chat_message_ids_from_snapshot(
                &queue.snapshot(),
                realm.as_str(),
                "ak:strand:AT3p9polsnQ_WOix32QZimMdE2zPe62HptJu2PaO3V1h",
            ),
            std::collections::BTreeSet::from([
                "ak:message:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19".to_owned()
            ])
        );
    }

    fn sdk_event_without_proof(actor_id: &str) -> arkret_sdk::Event {
        serde_json::from_value(json!({
            "event_id": "ak:event:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19",
            "kind": "ak.presence",
            "realm_id": "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19",
            "scope_ref": {"kind": "realm", "realm_id": "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19"},
            "actor_id": actor_id,
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
        serde_json::from_value(json!({
            "event_id": event_id,
            "kind": kind,
            "realm_id": realm_id,
            "scope_ref": {"kind": "realm", "realm_id": realm_id},
            "actor_id": actor_id,
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
        let mut event: arkret_sdk::Event = serde_json::from_value(json!({
            "event_id": event_id,
            "kind": "ak.realm.create",
            "scope_ref": {"kind": "realm_genesis"},
            "actor_id": created_by,
            "actor_seq": 1,
            "created_at": "2026-05-19T00:00:00.000Z",
            "hlc": "01970e589d21-0001-a13f9c2e",
            "prev_refs": [],
            "payload": {},
            "proofs": []
        }))
        .unwrap();
        let mut object = json!({ "created_by": created_by });
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
                controller_id: AUTHORITY_CONTROLLER.to_owned()
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
        assert!(!realm_owner_covers_event_kind("ak.realm.create"));
        assert!(!realm_owner_covers_event_kind("ak.not.a.kind"));
    }

    #[test]
    fn realm_authority_root_claim_stamps_only_the_matching_controller() {
        let root = RealmCreateAuthority::Root {
            controller_id: AUTHORITY_CONTROLLER.to_owned(),
        };
        let event = |actor: &str| {
            sdk_event_with_kind(
                "ak:event:AZMiGxiOThkUT3Dwv05wKz3ho14d39lB0b9ep3sMSDrM",
                AUTHORITY_REALM,
                "ak.strand.create",
                actor,
            )
        };

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
            controller_id: AUTHORITY_CONTROLLER.to_owned(),
        };
        let mut with_grant = sdk_event_with_kind(
            "ak:event:ARqNvcWYATpece6_sbb4Q7uWv69NgLVVEdYxo8OrmqyW",
            AUTHORITY_REALM,
            "ak.strand.create",
            AUTHORITY_CONTROLLER,
        );
        with_grant.authorization_ref = Some(
            arkret_sdk::AuthorizationRef::new("ak:grant:AbrgMKK4KXMpRsGsFrsEQEsjo207metUd4zt8yjzB-UH")
                .unwrap(),
        );
        assert_eq!(realm_authority_root_claim(&with_grant, Some(&root)), None);

        let mut executed_by_service = sdk_event_with_kind(
            "ak:event:AT3p9polsnQ_WOix32QZimMdE2zPe62HptJu2PaO3V1h",
            AUTHORITY_REALM,
            "ak.strand.create",
            AUTHORITY_CONTROLLER,
        );
        executed_by_service.executed_by =
            Some(arkret_sdk::Did::new("did:web:service.example".to_owned()).unwrap());
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
                    controller_id: AUTHORITY_CONTROLLER.to_owned(),
                },
            );
        let mut event = sdk_event_with_kind(
            "ak:event:AU2FuZ5Cmuwsb0J0xuJwH47SCEL34D7oJWb4JivTH934",
            realm,
            "ak.strand.create",
            AUTHORITY_CONTROLLER,
        );
        dead_endpoint_submitter()
            .stamp_realm_authority_root_claim(&mut event)
            .await;
        assert_eq!(
            event.authorization_ref.as_deref(),
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
                    controller_id: AUTHORITY_CONTROLLER.to_owned(),
                },
            );
        // Outage-era intent: owner-authored kind, but no claim was resolvable
        // at enqueue time.
        let mut event = sdk_event_with_kind(
            "ak:event:AfYjtj18lO9CeLkb1-l4BiiXSDtfZT21Z_Ez69OUDDEK",
            realm,
            "ak.message.create",
            AUTHORITY_CONTROLLER,
        );
        assert!(event.authorization_ref.is_none());

        // Fresh authoring would stamp (the claim is resolvable from cache)…
        let mut freshly_authored = event.clone();
        dead_endpoint_submitter()
            .stamp_realm_authority_root_claim(&mut freshly_authored)
            .await;
        assert!(freshly_authored.authorization_ref.is_some());

        // …but the frozen-intent pipeline must leave the intent's choice
        // untouched so the authored envelope still equals its bound intent.
        let outcome = dead_endpoint_submitter()
            .stamp_cba_basis_for_sdk_event_inner(&mut event, SemanticAuthoring::FrozenIntent)
            .await;
        // The dead endpoint fails later at the seal fetch; the claim decision
        // happens before that and is what this test pins down.
        let _ = outcome;
        assert!(
            event.authorization_ref.is_none(),
            "frozen-intent replay stamped a claim the intent does not carry"
        );
    }

    #[tokio::test]
    async fn stamp_realm_authority_root_claim_swallows_lookup_failures() {
        // Unknown Realm + unreachable endpoint: the claim must be skipped, not
        // fail the submit — a member's ordinary grant path stays usable when
        // the create lookup is unavailable.
        let mut event = sdk_event_with_kind(
            "ak:event:AUg3kgXpMvW4kMuGtTepFkRVooX03jTSKInIfDj4dDvu",
            "ak:realm:ARKSHgBichO7ZjwprTMf4UrKn7x1GHkl16zz6U4xm586",
            "ak.strand.create",
            AUTHORITY_CONTROLLER,
        );
        dead_endpoint_submitter()
            .stamp_realm_authority_root_claim(&mut event)
            .await;
        assert!(event.authorization_ref.is_none());
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
                    controller_id: AUTHORITY_CONTROLLER.to_owned(),
                },
            );
        let event = crate::operation::ak_ops::kanban_card_strand_create(
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

        // Mirror `submit_sdk_event_queued`'s intent normalization + stamp.
        let mut intent = event.clone();
        intent.actor_seq = 0;
        intent.prev_refs.clear();
        intent.proofs.clear();
        intent.seal_ref = None;
        intent.seal_basis = None;
        intent.auth_context = None;
        intent.authorization_ref = realm_authority_root_claim(
            &intent,
            Some(&RealmCreateAuthority::Root {
                controller_id: AUTHORITY_CONTROLLER.to_owned(),
            }),
        );
        assert!(intent.authorization_ref.is_some(), "claim must stamp");
        let queued = QueuedSdkEvent::unauthored(
            intent,
            "local-op".to_owned(),
            "authoring-key".to_owned(),
            None,
            test_authoring_generation(),
            None,
        )
        .unwrap();

        // Mirror the outbound drive's authoring mutations (transport-level
        // members only; `EventIntent::from_event` must discard all of them).
        let mut authored = queued.intent.to_unauthored_event();
        authored.unsigned.insert(
            "local_operation_idempotency_alias".to_owned(),
            Value::String("authoring-key".to_owned()),
        );
        authored.actor_seq = 7;
        authored.prev_refs = vec![fixture_event_id(
            "ak:event:AdymfEYKFegRsXpyi5Or3ormR7igvbwtXIp8HyMfOvWE",
        )];
        authored.hlc = Some(arkret_sdk::Hlc::new("01970e589d21-0001-a13f9c2e").unwrap());
        authored.seal_ref = Some(
            arkret_sdk::SealId::new(
                "ak:seal:sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                    .to_owned(),
            )
            .unwrap(),
        );
        authored.auth_context = Some(arkret_sdk::AuthContext {
            did: authored.actor_id.clone(),
            key_id: "device".to_owned(),
            key_epoch: 0,
            credential_epoch: None,
        });

        let reconstructed = EventIntent::from_event(authored);
        if reconstructed != queued.intent {
            let left = serde_json::to_value(&reconstructed).unwrap();
            let right = serde_json::to_value(&queued.intent).unwrap();
            panic!(
                "authored envelope drifted from bound intent:\nauthored: {left:#}\nintent:   {right:#}"
            );
        }
    }

    /// Live probe against the local dev stack; ignored by default. Run with:
    /// `cargo test --lib live_owner_kanban_writes_against_dev_soland -- --ignored --nocapture`
    ///
    /// Exercises the real client pipeline — `create_realm` genesis batch →
    /// Seal wait → board/list `ak.space.create` → card `ak.strand.create`,
    /// with the authority-root claim stamped by `prepare_sdk_event_for_submit`
    /// — against `http://127.0.0.1:8698` using dev-login and the SDK's
    /// deterministic development signer.
    #[cfg(not(target_arch = "wasm32"))]
    #[tokio::test]
    #[ignore = "requires the local dev soland (SOLAND_DEVELOPMENT_MODE=true) on 127.0.0.1:8698"]
    async fn live_owner_kanban_writes_against_dev_soland() {
        const BASE: &str = "http://127.0.0.1:8698/";
        let unique = uuid_v7();
        let suffix = unique
            .rsplit('-')
            .next()
            .expect("uuid has segments")
            .to_owned();
        let actor = format!("did:web:probe-{suffix}.local.host");
        let device = format!("ak:device:{}", uuid_v7());

        let login: Value = reqwest::Client::new()
            .post(format!("{BASE}_soland/gate/auth/dev-login"))
            .json(&serde_json::json!({ "actor": actor, "device_id": device }))
            .send()
            .await
            .expect("dev-login request")
            .error_for_status()
            .expect("dev-login status")
            .json()
            .await
            .expect("dev-login body");
        let token = login["session_credential"]
            .as_str()
            .expect("session_credential")
            .to_owned();

        // The signer must be device-bound for the submit pipeline (HLC
        // stamping), but the proof fragment must NOT parse as an
        // `ak:device:*` id: that routes verification to the device signing
        // directory (`device-lifecycle.md` §5.4), which this un-enrolled
        // probe device cannot satisfy. A literal `device` fragment keeps the
        // dev-mode deterministic-key fallback reachable, and dev-mode soland
        // derives the expected key from the exact emitted string
        // `{actor}#device`.
        let verification_method = format!("{actor}#device");
        let _signer = crate::event_signer::ActiveSignerTestGuard::replace(Some(
            std::sync::Arc::new(crate::event_signer::build_ed25519_device_signer(
                arkret_signatures::development_signing_key_seed(&verification_method),
                actor.clone(),
                "device",
            )),
        ));
        let previous_proof_mode = crate::operation::current_proof_mode();
        crate::operation::set_proof_mode(crate::operation::ProofMode::RealEd25519);

        let sdk = arkret_sdk::http_client::ClientBuilder::new(BASE.parse().unwrap())
            .allow_insecure_localhost()
            .auth(arkret_sdk::http_client::Auth::Bearer(token.clone()))
            .build()
            .expect("sdk client");
        let submitter = EventSubmitter::new(sdk.clone());

        let outcome = async {
            // Manual genesis batch: the probe principal has no principal
            // control realm, so the queued submit paths' client-side recovery
            // gate cannot be satisfied. The real browser flow satisfies it at
            // onboarding; it is not what this probe tests, so use the same
            // prepare + lease + submit primitives without the durable queue.
            let notary_did = submitter
                .service_id()
                .await
                .map_err(|error| format!("service describe failed: {error:#}"))?;
            let (_draft_realm_id, bootstrap) = crate::event_builders::build_realm_bootstrap_events(
                arkret_sdk::GenesisSalt::new("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
                    .unwrap(),
                &actor,
                &notary_did,
                "root-claim live probe",
                Some("authority-root claim end-to-end probe"),
                "listed",
                "invite",
                "shared",
                "mls_rfc9420",
                "standard",
                "restricted",
                "single_did",
                "sha256",
                "ak:trust_domain:local.host",
                &[],
                std::slice::from_ref(&notary_did),
                None,
                None,
            )
            .map_err(|error| format!("bootstrap build failed: {error:#}"))?;
            let prepared = submitter
                .prepare_sdk_events_batch(bootstrap)
                .await
                .map_err(|error| format!("bootstrap prepare failed: {error:#}"))?;
            let realm_id = prepared
                .first()
                .map(|event| event.realm_id.to_string())
                .ok_or_else(|| "prepared bootstrap is empty".to_owned())?;
            for event in &prepared {
                for proof in &event.proofs {
                    println!(
                        "prepared {} proof vm={:?} kind={:?}",
                        event.kind.as_str(),
                        proof.verification_method,
                        proof.kind,
                    );
                    // Local replica of the server's dev-mode verification
                    // (`verify_ed25519_detached_jws_proof` + deterministic key)
                    // to split "bad signature" from "server key selection".
                    let digest_payload = event
                        .digest_payload()
                        .map_err(|error| format!("digest payload: {error:#}"))?;
                    let envelope_bytes =
                        arkret_sdk::canonical::canonical_json_bytes(&digest_payload)
                            .map_err(|error| format!("canonical bytes: {error:#}"))?;
                    let vm = proof.verification_method.as_str();
                    let material = arkret_signatures::PublicKeyMaterial::Ed25519Raw {
                        bytes: arkret_signatures::development_verifying_key(vm)
                            .to_bytes()
                            .to_vec(),
                    };
                    let local = arkret_signatures::verify_ed25519_detached_jws_proof(
                        proof,
                        &envelope_bytes,
                        &event.actor_id,
                        &material,
                    );
                    println!("  local dev-key verify: {local:?}");
                }
            }
            let submissions = sdk
                .prepare_initial_submissions(&prepared)
                .await
                .map_err(|error| format!("bootstrap lease issuance rejected: {error:#}"))?;
            sdk.events_submit_batch(&submissions)
                .await
                .map_err(|error| format!("bootstrap events.submit rejected: {error:#}"))?;
            crate::mls::creator_bootstrap::wait_for_realm_seal_view(&submitter, &realm_id)
                .await
                .map_err(|error| format!("realm never sealed: {error:#}"))?;

            let mut accepted = Vec::new();
            let board = crate::operation::ak_ops::space_create(
                &realm_id,
                &actor,
                "board",
                "probe board",
                None,
                None,
            )
            .and_then(|builder| builder.build_sdk_event("inkson"))
            .map_err(|error| format!("board event build failed: {error:#}"))?;
            // Both container Spaces are named by their own create Events.
            let board_space_id = board
                .local_target_ref()
                .ok_or_else(|| "board event carries no derived Space id".to_owned())?
                .to_owned();
            let list = crate::operation::ak_ops::space_create(
                &realm_id,
                &actor,
                "list",
                "probe list",
                None,
                Some("a0"),
            )
            .and_then(|builder| builder.build_sdk_event("inkson"))
            .map_err(|error| format!("list event build failed: {error:#}"))?;
            let list_space_id = list
                .local_target_ref()
                .ok_or_else(|| "list event carries no derived Space id".to_owned())?
                .to_owned();
            let card = crate::operation::ak_ops::kanban_card_strand_create(
                &realm_id,
                &actor,
                &board_space_id,
                &list_space_id,
                "probe card",
                "a0",
            )
            .and_then(|builder| builder.build_sdk_event("inkson"))
            .map_err(|error| format!("card event build failed: {error:#}"))?;

            for (label, event) in [("board", board), ("list", list), ("card", card)] {
                let (signed, _idempotency) =
                    submitter
                        .prepare_sdk_event_for_submit(&event)
                        .await
                        .map_err(|error| format!("{label} prepare failed: {error:#}"))?;
                if signed.authorization_ref.as_deref()
                    != Some(arkret_wire::REALM_AUTHORITY_ROOT_CELL)
                {
                    return Err(format!(
                        "{label} was not stamped with the authority-root claim: {:?}",
                        signed.authorization_ref
                    ));
                }
                let submissions = sdk
                    .prepare_initial_submissions(std::slice::from_ref(&signed))
                    .await
                    .map_err(|error| format!("{label} lease issuance rejected: {error:#}"))?;
                let submission = submissions
                    .into_iter()
                    .next()
                    .ok_or_else(|| format!("{label} lease outcome is empty"))?;
                let result = sdk
                    .events_submit(&submission)
                    .await
                    .map_err(|error| format!("{label} events.submit rejected: {error:#}"))?;
                accepted.push(format!("{label} accepted: {:?}", result));
            }
            Ok::<Vec<String>, String>(accepted)
        }
        .await;
        crate::operation::set_proof_mode(previous_proof_mode);
        match outcome {
            Ok(accepted) => {
                for line in accepted {
                    println!("{line}");
                }
            }
            Err(message) => panic!("live probe failed: {message}"),
        }
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[tokio::test]
    async fn mls_post_accept_hook_persists_snapshot_idempotently() {
        use std::sync::{Arc, Mutex};

        use garth::OutboundPostAcceptHook;

        let path = std::env::temp_dir().join(format!(
            "inkson-mls-post-accept-{}-{}.json",
            std::process::id(),
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));
        let store = Arc::new(Mutex::new(crate::state::LocalStateStore::with_path(&path)));
        let read_store = Arc::clone(&store);
        let write_store = Arc::clone(&store);
        let handle = crate::runtime::input::StateStoreHandle::new(
            move |read| read(&read_store.lock().unwrap()),
            move |write| write(&mut write_store.lock().unwrap()),
        );
        let hook = InksonPostAcceptHook {
            state_store: Some(handle),
        };
        let realm_id = "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19";
        let event = sdk_event_with_kind(
            "ak:event:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19",
            realm_id,
            "ak.mls.commit",
            "did:web:alice.example",
        );
        let snapshot = crate::mls::persistence::MlsSnapshotEnvelope {
            realm_id: realm_id.to_owned(),
            group_id: "010203".to_owned(),
            epoch: 7,
            group_state_event_id: None,
            salt_hex: "00".repeat(16),
            ciphertext_hex: "11".repeat(32),
            mac_hex: "22".repeat(12),
            recorded_at: chrono::Utc::now(),
            epoch_started_at: chrono::Utc::now(),
            app_messages_observed: 1,
            aead_version: crate::mls::persistence::AEAD_VERSION_CHACHA20_POLY1305,
        };
        let content = serde_json::to_value(
            QueuedSdkEvent::unauthored(
                event,
                "mls-operation".to_owned(),
                "mls-attempt".to_owned(),
                None,
                test_authoring_generation(),
                Some(PostAcceptAction::MlsSnapshot {
                    realm_id: realm_id.to_owned(),
                    snapshot,
                }),
            )
            .unwrap(),
        )
        .unwrap();
        let realm = arkret_sdk::RealmId::new(realm_id).unwrap();
        let mut queue = garth::SendQueue::new();
        let item = queue
            .enqueue(
                Some("txn-mls-hook".to_owned()),
                realm,
                garth::SendQueueItemKind::Custom {
                    kind: "ak.mls.commit".to_owned(),
                },
                content,
                Vec::new(),
            )
            .unwrap();
        let event_id =
            arkret_sdk::EventId::new("ak:event:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19")
                .unwrap();

        hook.post_accept(&item, &event_id, false).await.unwrap();
        hook.post_accept(&item, &event_id, true).await.unwrap();
        assert_eq!(
            store
                .lock()
                .unwrap()
                .mls_snapshot_for(realm_id)
                .unwrap()
                .epoch,
            7
        );
        drop(store);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn queued_mls_admission_round_trips_exact_welcome_material() {
        let realm_id = "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19";
        let commit = sdk_event_with_kind(
            "ak:event:AT3p9polsnQ_WOix32QZimMdE2zPe62HptJu2PaO3V1h",
            realm_id,
            "ak.mls.commit",
            "did:web:alice.example",
        );
        let mut welcome = sdk_event_with_kind(
            "ak:event:AU2FuZ5Cmuwsb0J0xuJwH47SCEL34D7oJWb4JivTH934",
            realm_id,
            "ak.mls.welcome",
            "did:web:alice.example",
        );
        welcome.payload = serde_json::from_value(json!({
            "commit_ref": commit.event_id,
            "recipient_principal_id": "did:web:bob.example"
        }))
        .unwrap();
        let snapshot = crate::mls::persistence::MlsSnapshotEnvelope {
            realm_id: realm_id.to_owned(),
            group_id: "010203".to_owned(),
            epoch: 1,
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
            commit.clone(),
            "mls-admission-operation".to_owned(),
            commit.event_id.to_string(),
            arkret_sdk::canonical::canonical_json_bytes(&commit).unwrap(),
            None,
            test_authoring_generation(),
            Some(PostAcceptAction::MlsAdmission {
                realm_id: realm_id.to_owned(),
                actor_id: "did:web:alice.example".to_owned(),
                device_id: "ak:device:01904100-0000-7000-8000-000000000001".to_owned(),
                welcomes: vec![welcome.clone()],
                snapshot,
            }),
        )
        .unwrap();

        let decoded = decode_queued_sdk_event(serde_json::to_value(&queued).unwrap()).unwrap();
        let Some(PostAcceptAction::MlsAdmission { welcomes, .. }) = decoded.post_accept else {
            panic!("queued admission action was not preserved");
        };
        assert_eq!(welcomes, vec![welcome]);
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

    #[cfg(not(target_arch = "wasm32"))]
    #[tokio::test]
    async fn mls_admission_persistence_installs_snapshot_before_reporting_completion() {
        use std::sync::{Arc, Mutex};

        let path = std::env::temp_dir().join(format!(
            "inkson-mls-admission-post-accept-{}-{}.json",
            std::process::id(),
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));
        let store = Arc::new(Mutex::new(crate::state::LocalStateStore::with_path(&path)));
        let read_store = Arc::clone(&store);
        let write_store = Arc::clone(&store);
        let handle = crate::runtime::input::StateStoreHandle::new(
            move |read| read(&read_store.lock().unwrap()),
            move |write| write(&mut write_store.lock().unwrap()),
        );
        let realm_id = "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19";
        let welcome = sdk_event_with_kind(
            "ak:event:AU2FuZ5Cmuwsb0J0xuJwH47SCEL34D7oJWb4JivTH934",
            realm_id,
            "ak.mls.welcome",
            "did:web:alice.example",
        );
        let snapshot = crate::mls::persistence::MlsSnapshotEnvelope {
            realm_id: realm_id.to_owned(),
            group_id: "010203".to_owned(),
            epoch: 1,
            group_state_event_id: None,
            salt_hex: "00".repeat(16),
            ciphertext_hex: "11".repeat(32),
            mac_hex: "22".repeat(12),
            recorded_at: chrono::Utc::now(),
            epoch_started_at: chrono::Utc::now(),
            app_messages_observed: 0,
            aead_version: crate::mls::persistence::AEAD_VERSION_CHACHA20_POLY1305,
        };
        let action = PostAcceptAction::MlsAdmission {
            realm_id: realm_id.to_owned(),
            actor_id: "did:web:alice.example".to_owned(),
            device_id: "ak:device:01904100-0000-7000-8000-000000000001".to_owned(),
            welcomes: vec![welcome],
            snapshot,
        };

        let error = persist_post_accept_action(
            Some(&handle),
            action,
            arkret_sdk::EventId::new("ak:event:AXBcp13trH3bPXvj0eHppCpGqJZWL9yqE3cf2Tl43vyk")
                .unwrap(),
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("snapshot secret unavailable"));
        assert!(store.lock().unwrap().mls_snapshot_for(realm_id).is_some());
        drop(store);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn apply_actor_frontier_stamps_next_sequence_and_predecessor() {
        let mut event = sdk_event_without_proof("did:web:alice.example");
        let frontier_event_id =
            arkret_sdk::EventId::new("ak:event:ASeIBHNVQyeIcU4aBIt2t2BF_ikuVMH0kNru_HgO_gG1")
                .unwrap();
        let frontier = arkret_sdk::RealmActorFrontierView::new(
            event.realm_id.clone(),
            arkret_sdk::Did::new("did:web:alice.example").unwrap(),
            8,
            vec![frontier_event_id.clone()],
            arkret_sdk::canonical::DigestSuite::Sha256,
        )
        .unwrap();

        apply_actor_frontier_to_sdk_event(&mut event, &frontier).unwrap();

        assert_eq!(event.actor_seq, 8);
        assert_eq!(event.prev_refs, vec![frontier_event_id]);
    }

    /// The envelope `actor_seq` and a cell-local `ordered_log` `issuer_seq`
    /// are different sequences. v1 has no producer `effects[]` for the frontier
    /// stamp to overwrite, so the invariant is now asserted where the value
    /// actually comes from: the registered projection, which pins
    /// `ak.realm.create`'s create-log append at `issuer_seq 0` regardless of
    /// how far the actor chain has advanced.
    #[test]
    fn actor_frontier_stamp_does_not_move_cell_local_ordered_log_sequence() {
        let mut event = crate::event_builders::build_realm_create_event(
            arkret_sdk::GenesisSalt::new("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA").unwrap(),
            "did:web:alice.example",
            "did:web:alice.example",
            "Frontier",
            None,
            "invite_only",
            "invite",
            "shared",
            // `encryption_profile` is the closed realm-genesis schema enum
            // {none, mls_rfc9420, external}; "plaintext" was never a member and
            // only survived here because the object used to be hand-built JSON.
            "none",
            "standard",
            "open",
            "single_did",
            "sha256",
            "ak:trust_domain:did.web.example",
            None,
        )
        .unwrap();
        let before = crate::operation::direct_registered_cell_writes(&event).unwrap();
        let create_log = before
            .iter()
            .find(|write| write.cell.as_str() == arkret_bootstrap::REALM_CREATE_CELL)
            .expect("realm.create projects the create-log append");
        assert_eq!(create_log.op.issuer_seq, Some(0));

        let frontier = arkret_sdk::RealmActorFrontierView::new(
            event.realm_id.clone(),
            event.actor_id.clone(),
            8,
            vec![
                arkret_sdk::EventId::new("ak:event:ASeIBHNVQyeIcU4aBIt2t2BF_ikuVMH0kNru_HgO_gG1")
                    .unwrap(),
            ],
            arkret_sdk::canonical::DigestSuite::Sha256,
        )
        .unwrap();
        apply_actor_frontier_to_sdk_event(&mut event, &frontier).unwrap();

        assert_eq!(event.actor_seq, 8);
        assert_eq!(
            crate::operation::direct_registered_cell_writes(&event).unwrap(),
            before
        );
    }

    #[test]
    fn apply_empty_actor_frontier_stamps_genesis_sequence_without_predecessor() {
        let mut event = sdk_event_without_proof("did:web:alice.example");
        let frontier = arkret_sdk::RealmActorFrontierView::new(
            event.realm_id.clone(),
            arkret_sdk::Did::new("did:web:alice.example").unwrap(),
            0,
            vec![],
            arkret_sdk::canonical::DigestSuite::Sha256,
        )
        .unwrap();

        apply_actor_frontier_to_sdk_event(&mut event, &frontier).unwrap();

        assert_eq!(event.actor_seq, 0);
        assert!(event.prev_refs.is_empty());
    }

    #[tokio::test]
    async fn realm_bootstrap_preparation_authors_genesis_without_remote_frontier() {
        let _signer = crate::event_signer::ActiveSignerTestGuard::replace(Some(
            std::sync::Arc::new(crate::event_signer::build_ed25519_device_signer(
                [42_u8; 32],
                "did:web:alice.example",
                "ak:device:01904100-0000-7000-8000-a11ce0000001",
            )),
        ));
        let (draft_realm_id, events) = crate::event_builders::build_realm_bootstrap_events(
            arkret_sdk::GenesisSalt::new("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA").unwrap(),
            "did:web:alice.example",
            "did:web:server.example",
            "Engineering",
            Some("Realm genesis must not query its own nonexistent frontier"),
            "listed",
            "invite",
            "shared",
            "mls_rfc9420",
            "standard",
            "restricted",
            "single_did",
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
        let prepared = EventSubmitter::new(http)
            .prepare_sdk_events_batch(events)
            .await;
        crate::operation::set_proof_mode(previous_proof_mode);
        let prepared =
            prepared.expect("validated Realm bootstrap must be authored from local genesis");

        assert!(!prepared.is_empty());
        let final_realm_id = prepared[0].realm_id.clone();
        assert_ne!(final_realm_id.as_str(), draft_realm_id);
        for (index, event) in prepared.iter().enumerate() {
            assert_eq!(event.realm_id, final_realm_id);
            assert_eq!(event.actor_seq, index as u64);
            if index == 0 {
                assert!(event.prev_refs.is_empty());
            } else {
                assert_eq!(event.prev_refs, vec![prepared[index - 1].event_id.clone()]);
            }
            assert!(!event.proofs.is_empty());
            event
                .verify_event_id_matches_content_with_digest_suite(
                    arkret_sdk::canonical::DigestSuite::Sha256,
                )
                .unwrap();
            event.validate_proof_bindings().unwrap();
        }
    }

    #[tokio::test]
    async fn ordinary_event_preparation_still_requires_remote_frontier() {
        let event = sdk_event_without_proof("did:web:alice.example");
        let http = arkret_sdk::http_client::Client::builder("http://127.0.0.1:9/".parse().unwrap())
            .allow_insecure_localhost()
            .build()
            .unwrap();

        let error = EventSubmitter::new(http)
            .prepare_sdk_events_batch(vec![event])
            .await
            .expect_err("ordinary Realm Event must refresh its combined actor frontier");

        assert!(
            format!("{error:#}")
                .contains("refresh actor frontier for did:web:alice.example before submit")
        );
    }

    #[test]
    fn apply_actor_frontier_rejects_wrong_actor() {
        let mut event = sdk_event_without_proof("did:web:alice.example");
        let frontier = arkret_sdk::RealmActorFrontierView::new(
            event.realm_id.clone(),
            arkret_sdk::Did::new("did:web:bob.example").unwrap(),
            8,
            vec![
                arkret_sdk::EventId::new("ak:event:ASeIBHNVQyeIcU4aBIt2t2BF_ikuVMH0kNru_HgO_gG1")
                    .unwrap(),
            ],
            arkret_sdk::canonical::DigestSuite::Sha256,
        )
        .unwrap();

        let error = apply_actor_frontier_to_sdk_event(&mut event, &frontier)
            .unwrap_err()
            .to_string();

        assert!(error.contains("realm actor frontier mismatch"));
    }

    #[test]
    fn actor_seq_cas_conflict_classifier_is_narrow() {
        let current_frontier = arkret_sdk::RealmActorFrontierView::new(
            arkret_sdk::RealmId::new("ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19")
                .unwrap(),
            arkret_sdk::Did::new("did:web:alice.example").unwrap(),
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
                ),
                sdk_event_with_kind(
                    "ak:event:ASeIBHNVQyeIcU4aBIt2t2BF_ikuVMH0kNru_HgO_gG1",
                    other_realm,
                    "ak.mls.genesis",
                    "did:web:alice.example",
                ),
                sdk_event_with_kind(
                    expected.as_str(),
                    realm,
                    "ak.mls.genesis",
                    "did:web:alice.example",
                ),
            ],
            snapshot_bootstrap: None,
            next_cursor: None,
            prev_cursor: None,
            has_more: false,
            range_completeness: None,
        };

        assert_eq!(
            mls_genesis_event_id_from_events(&outcome, realm),
            Some(expected)
        );
        assert_eq!(
            mls_genesis_event_id_from_events(
                &outcome,
                "ak:realm:AfXCJ1DUe3g7MVHuVBpMsl89749WyrXAJP7EvoU9mwBH"
            ),
            None
        );
    }
}
