//! Moderation control-event to local raw-operation extraction.
//!
//! Moderation decisions and appeal lifecycle events are sealed control-plane
//! cells. They still need a durable client-side event log so appellant and
//! reviewer projections can rebuild after reload and react to realm-stream
//! delivery that occurs after the initial account snapshot.

use std::marker::PhantomData;

use arkret_sdk::EventPayloadExt as _;
use serde::de::Error as _;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::state::RawOperationRecord;

#[derive(Clone, Debug)]
pub(crate) enum LocalModerationEvent {
    Decision(arkret_sdk::ModerationDecisionPayload),
    DecisionLift(arkret_sdk::ModerationDecisionLiftPayload),
    AppealSubmit(arkret_sdk::AppealSubmitPayload),
    AppealReview(arkret_sdk::AppealReviewPayload),
    AppealDecision(arkret_sdk::AppealDecisionPayload),
    AppealClose(arkret_sdk::AppealClosePayload),
}

impl LocalModerationEvent {
    pub(crate) fn from_sdk_event(event: &arkret_sdk::Event) -> Option<Self> {
        Some(match &event.kind {
            arkret_sdk::EventKind::ModerationDecision => Self::Decision(
                event
                    .typed_payload::<arkret_wire::event_spec::ModerationDecision>()
                    .ok()?,
            ),
            arkret_sdk::EventKind::ModerationDecisionLift => Self::DecisionLift(
                event
                    .typed_payload::<arkret_wire::event_spec::ModerationDecisionLift>()
                    .ok()?,
            ),
            arkret_sdk::EventKind::ModerationAppealSubmit => Self::AppealSubmit(
                event
                    .typed_payload::<arkret_wire::event_spec::ModerationAppealSubmit>()
                    .ok()?,
            ),
            arkret_sdk::EventKind::ModerationAppealReview => Self::AppealReview(
                event
                    .typed_payload::<arkret_wire::event_spec::ModerationAppealReview>()
                    .ok()?,
            ),
            arkret_sdk::EventKind::ModerationAppealDecision => Self::AppealDecision(
                event
                    .typed_payload::<arkret_wire::event_spec::ModerationAppealDecision>()
                    .ok()?,
            ),
            arkret_sdk::EventKind::ModerationAppealClose => Self::AppealClose(
                event
                    .typed_payload::<arkret_wire::event_spec::ModerationAppealClose>()
                    .ok()?,
            ),
            _ => return None,
        })
    }

    fn record_value(&self, metadata: &LocalModerationMetadata) -> Option<Value> {
        macro_rules! serialize_record {
            ($kind:ident, $payload:expr) => {
                serde_json::to_value(LocalModerationRecord {
                    kind: arkret_sdk::EventKind::$kind,
                    operation_id: &metadata.operation_id,
                    event_id: &metadata.event_id,
                    actor_id: &metadata.actor_id,
                    created_at: &metadata.created_at,
                    write_state: "synced",
                    body: $payload,
                })
                .ok()
            };
        }
        match self {
            Self::Decision(payload) => serialize_record!(ModerationDecision, payload),
            Self::DecisionLift(payload) => serialize_record!(ModerationDecisionLift, payload),
            Self::AppealSubmit(payload) => serialize_record!(ModerationAppealSubmit, payload),
            Self::AppealReview(payload) => serialize_record!(ModerationAppealReview, payload),
            Self::AppealDecision(payload) => serialize_record!(ModerationAppealDecision, payload),
            Self::AppealClose(payload) => serialize_record!(ModerationAppealClose, payload),
        }
    }
}

#[derive(Serialize)]
struct LocalModerationRecord<'a, T> {
    kind: arkret_sdk::EventKind,
    operation_id: &'a str,
    event_id: &'a str,
    actor_id: &'a str,
    created_at: &'a str,
    write_state: &'static str,
    body: &'a T,
}

struct LocalModerationMetadata {
    operation_id: String,
    event_id: String,
    actor_id: String,
    created_at: String,
}

#[derive(Clone, Debug)]
pub(crate) struct ModerationEvent {
    pub(crate) event_id: String,
    pub(crate) realm_id: String,
    pub(crate) payload: LocalModerationEvent,
}

impl ModerationEvent {
    pub(crate) fn from_sdk_event(event: &arkret_sdk::Event) -> Option<Self> {
        Some(Self {
            event_id: event.event_id.as_str().to_owned(),
            realm_id: event.realm_id.as_str().to_owned(),
            payload: LocalModerationEvent::from_sdk_event(event)?,
        })
    }
}

struct ExpectedEventKind<K>(PhantomData<K>);

impl<'de, K: arkret_sdk::EventSpec> Deserialize<'de> for ExpectedEventKind<K> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let kind = arkret_sdk::EventKind::deserialize(deserializer)?;
        if kind != K::KIND {
            return Err(D::Error::custom(
                "event kind does not match its typed payload",
            ));
        }
        Ok(Self(PhantomData))
    }
}

#[derive(Deserialize)]
#[serde(bound(deserialize = "K::Payload: Deserialize<'de>"))]
struct StoredModerationRecord<K: arkret_sdk::EventSpec> {
    /// Deserialization-time discriminator: the `untagged` enum below picks a
    /// variant by whether this member parses as the expected kind. Nothing reads
    /// it afterwards, so it is named for what it is instead of being silenced.
    #[serde(rename = "kind")]
    _kind: ExpectedEventKind<K>,
    #[serde(default)]
    event_id: Option<String>,
    body: K::Payload,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum StoredModerationEvent {
    Decision(StoredModerationRecord<arkret_wire::event_spec::ModerationDecision>),
    DecisionLift(StoredModerationRecord<arkret_wire::event_spec::ModerationDecisionLift>),
    AppealSubmit(StoredModerationRecord<arkret_wire::event_spec::ModerationAppealSubmit>),
    AppealReview(StoredModerationRecord<arkret_wire::event_spec::ModerationAppealReview>),
    AppealDecision(StoredModerationRecord<arkret_wire::event_spec::ModerationAppealDecision>),
    AppealClose(StoredModerationRecord<arkret_wire::event_spec::ModerationAppealClose>),
}

pub(crate) fn moderation_event_from_local_record(
    realm_id: &str,
    value: &Value,
) -> Option<ModerationEvent> {
    let stored = serde_json::from_value::<StoredModerationEvent>(value.clone()).ok()?;
    let (event_id, payload) = match stored {
        StoredModerationEvent::Decision(record) => (
            record.event_id.unwrap_or_default(),
            LocalModerationEvent::Decision(record.body),
        ),
        StoredModerationEvent::DecisionLift(record) => (
            record.event_id.unwrap_or_default(),
            LocalModerationEvent::DecisionLift(record.body),
        ),
        StoredModerationEvent::AppealSubmit(record) => (
            record.event_id.unwrap_or_default(),
            LocalModerationEvent::AppealSubmit(record.body),
        ),
        StoredModerationEvent::AppealReview(record) => (
            record.event_id.unwrap_or_default(),
            LocalModerationEvent::AppealReview(record.body),
        ),
        StoredModerationEvent::AppealDecision(record) => (
            record.event_id.unwrap_or_default(),
            LocalModerationEvent::AppealDecision(record.body),
        ),
        StoredModerationEvent::AppealClose(record) => (
            record.event_id.unwrap_or_default(),
            LocalModerationEvent::AppealClose(record.body),
        ),
    };
    Some(ModerationEvent {
        event_id,
        realm_id: realm_id.to_owned(),
        payload,
    })
}

pub(crate) fn moderation_operations_from_events(
    _realm_id: &str,
    events: &[arkret_sdk::Event],
) -> Vec<RawOperationRecord> {
    events
        .iter()
        .filter_map(moderation_operation_from_event)
        .collect()
}

fn moderation_operation_from_event(event: &arkret_sdk::Event) -> Option<RawOperationRecord> {
    let local_event = LocalModerationEvent::from_sdk_event(event)?;
    let event_id = event.event_id.as_str().to_owned();
    let metadata = LocalModerationMetadata {
        operation_id: event_id.clone(),
        event_id: event_id.clone(),
        actor_id: event.actor_id.signing_principal_id().as_str().to_owned(),
        created_at: arkret_sdk::canonical::format_timestamp_canonical(event.created_at),
    };
    let payload = local_event.record_value(&metadata)?;
    Some(RawOperationRecord {
        operation_id: event_id,
        realm_id: Some(event.realm_id.as_str().to_owned()),
        received_at: event.created_at,
        payload,
    })
}

pub(crate) fn moderation_operations_from_client_events(
    events: &[garth::ClientEvent],
) -> Vec<RawOperationRecord> {
    events
        .iter()
        .filter_map(|client_event| match client_event {
            garth::ClientEvent::Message(message) => Some(&message.event),
            garth::ClientEvent::Event(event) => Some(event),
            _ => None,
        })
        .filter_map(moderation_operation_from_event)
        .collect()
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn extracts_only_moderation_lifecycle_events_in_projection_shape() {
        let realm_id = "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19";
        let realm_scope = || arkret_sdk::ScopeRef::Realm {
            realm_id: arkret_sdk::RealmId::new(realm_id).unwrap(),
        };
        let mut decision = arkret_wire::test_support::raw_event(
            arkret_sdk::EventKind::ModerationDecision.as_str(),
            realm_scope(),
            arkret_sdk::DidCoreId::new("ak:did_core:web:moderator.example").unwrap(),
            arkret_sdk::DidCoreId::new("ak:did_core:web:principal.example").unwrap(),
            1,
            arkret_sdk::Hlc::new("019f73a34c00-0000-12345678").unwrap(),
            json!({
                "target_ref": "ak:message:AXh0mpVGb536xVxbSPfM4Wc_1WuXAxTYgmtXEncKM9T0",
                "decision": "quarantine",
                "issuer_id": "ak:did_core:web:moderator.example",
                "request_canonical_digest": "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
            }),
        )
        .unwrap();
        decision.event_id =
            arkret_sdk::EventId::new("ak:event:AfqXI4jyBJWA5HRhSr3SdFP5Qb_2V210Q00mFqUjA7_z")
                .unwrap();
        let message = arkret_wire::test_support::raw_event(
            arkret_sdk::EventKind::MessageCreate.as_str(),
            realm_scope(),
            arkret_sdk::DidCoreId::new("ak:did_core:web:moderator.example").unwrap(),
            arkret_sdk::DidCoreId::new("ak:did_core:web:principal.example").unwrap(),
            2,
            arkret_sdk::Hlc::new("019f73a34c00-0001-12345678").unwrap(),
            json!({}),
        )
        .unwrap();
        let records = moderation_operations_from_events(realm_id, &[decision, message]);

        assert_eq!(records.len(), 1);
        assert_eq!(records[0].realm_id.as_deref(), Some(realm_id));
        assert_eq!(records[0].payload["kind"], "ak.moderation.decision");
        assert_eq!(
            records[0].payload["body"]["target_ref"],
            "ak:message:AXh0mpVGb536xVxbSPfM4Wc_1WuXAxTYgmtXEncKM9T0"
        );
    }
}
