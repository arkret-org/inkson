//! Moderation control-event to local raw-operation extraction.
//!
//! Moderation decisions are sealed control-plane cells. They still need a
//! durable client-side event log so management projections can rebuild after reload and react to
//! realm-stream delivery that occurs after the initial account snapshot.

use arkret_sdk::EventPayloadExt as _;
use serde::Serialize;
use serde_json::Value;

use crate::state::RawOperationRecord;

#[derive(Clone, Debug)]
pub(crate) enum LocalModerationEvent {
    Decision(arkret_sdk::ModerationDecisionPayload),
    DecisionLift(arkret_sdk::ModerationDecisionLiftPayload),
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
            garth::ClientEvent::Event(event) => Some(event.as_ref()),
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
            json!({}),
        )
        .unwrap();
        let records = moderation_operations_from_client_events(&[
            garth::ClientEvent::Event(Box::new(decision)),
            garth::ClientEvent::Event(Box::new(message)),
        ]);

        assert_eq!(records.len(), 1);
        assert_eq!(records[0].realm_id.as_deref(), Some(realm_id));
        assert_eq!(records[0].payload["kind"], "ak.moderation.decision");
        assert_eq!(
            records[0].payload["body"]["target_ref"],
            "ak:message:AXh0mpVGb536xVxbSPfM4Wc_1WuXAxTYgmtXEncKM9T0"
        );
    }
}
