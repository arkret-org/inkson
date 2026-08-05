//! Moderation control-event to local raw-operation extraction.
//!
//! Moderation decisions and appeal lifecycle events are sealed control-plane
//! cells. They still need a durable client-side event log so appellant and
//! reviewer projections can rebuild after reload and react to realm-stream
//! delivery that occurs after the initial account snapshot.

use serde_json::{Value, json};

use crate::state::RawOperationRecord;

fn moderation_kind(kind: &str) -> bool {
    matches!(
        kind,
        "ak.moderation.decision"
            | "ak.moderation.decision.lift"
            | "ak.moderation.appeal.submit"
            | "ak.moderation.appeal.review"
            | "ak.moderation.appeal.decision"
            | "ak.moderation.appeal.close"
    )
}

fn string(value: &Value, key: &str) -> Option<String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

fn moderation_operation_from_event(
    fallback_realm_id: &str,
    event: &Value,
) -> Option<RawOperationRecord> {
    let kind = string(event, "kind").or_else(|| string(event, "event_kind"))?;
    if !moderation_kind(&kind) {
        return None;
    }
    let event_id = string(event, "event_id").or_else(|| string(event, "id"))?;
    let operation_id = string(event, "operation_id").unwrap_or_else(|| event_id.clone());
    let realm_id = string(event, "realm_id").unwrap_or_else(|| fallback_realm_id.to_owned());
    let actor_id = string(event, "actor_id").unwrap_or_default();
    let created_at = string(event, "created_at").unwrap_or_default();
    let received_at = chrono::DateTime::parse_from_rfc3339(&created_at)
        .map(|timestamp| timestamp.with_timezone(&chrono::Utc))
        .unwrap_or_else(|_| chrono::Utc::now());
    let body = event
        .get("payload")
        .or_else(|| event.get("content"))
        .cloned()
        .unwrap_or(Value::Null);

    Some(RawOperationRecord {
        operation_id: operation_id.clone(),
        realm_id: Some(realm_id),
        received_at,
        payload: json!({
            "kind": kind,
            "operation_id": operation_id,
            "event_id": event_id,
            "actor_id": actor_id,
            "created_at": created_at,
            "write_state": "synced",
            "body": body,
        }),
    })
}

pub(crate) fn moderation_operations_from_events(
    realm_id: &str,
    events: &[Value],
) -> Vec<RawOperationRecord> {
    events
        .iter()
        .filter_map(|event| moderation_operation_from_event(realm_id, event))
        .collect()
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
        .filter(|event| moderation_kind(event.kind.as_str()))
        .map(|event| {
            let event_id = event.event_id.as_str().to_owned();
            RawOperationRecord {
                operation_id: event_id.clone(),
                realm_id: Some(event.realm_id.as_str().to_owned()),
                received_at: event.created_at,
                payload: json!({
                    "kind": event.kind.as_str(),
                    "operation_id": event_id,
                    "event_id": event.event_id.as_str(),
                    "actor_id": event.actor_id.as_str(),
                    "created_at": arkret_sdk::canonical::format_timestamp_canonical(
                        event.created_at
                    ),
                    "write_state": "synced",
                    "body": event.payload,
                }),
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn extracts_only_moderation_lifecycle_events_in_projection_shape() {
        let realm_id = "ak:realm:01904100-0000-8000-8000-000000000001";
        let records = moderation_operations_from_events(
            realm_id,
            &[
                json!({
                    "event_id": "ak:event:01904100-0000-8000-8000-000000000101",
                    "kind": "ak.moderation.decision",
                    "realm_id": realm_id,
                    "actor_id": "did:web:moderator.example",
                    "created_at": "2026-07-19T00:00:00.000Z",
                    "payload": {
                        "target_ref": "ak:message:01904100-0000-8000-8000-000000000201",
                        "decision": "quarantine"
                    }
                }),
                json!({
                    "event_id": "ak:event:01904100-0000-8000-8000-000000000102",
                    "kind": "ak.message.create",
                    "realm_id": realm_id,
                    "payload": {}
                }),
            ],
        );

        assert_eq!(records.len(), 1);
        assert_eq!(records[0].realm_id.as_deref(), Some(realm_id));
        assert_eq!(records[0].payload["kind"], "ak.moderation.decision");
        assert_eq!(
            records[0].payload["body"]["target_ref"],
            "ak:message:01904100-0000-8000-8000-000000000201"
        );
    }
}
