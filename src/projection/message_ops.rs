//! Message-event → `RawOperationRecord` extraction (the sync engine's
//! discussion-message ingest step) plus the nested-envelope candidate
//! walkers it is built on.
//!
//! YGN-ARCH-01 step 3 (pure move from `views/chat/model/events.rs`, zero
//! behavior change): consumed by `sync_engine::ingest_message_events` and the
//! chat view model (which re-exports these helpers).

use serde_json::Value;

use crate::local_state::RawOperationRecord;

pub(crate) fn value_string_at<'a>(value: &'a Value, keys: &[&str]) -> Option<&'a str> {
    keys.iter()
        .find_map(|key| value.get(*key).and_then(Value::as_str))
}

pub(crate) fn collect_message_candidates<'a>(
    value: &'a Value,
    out: &mut Vec<&'a Value>,
    depth: usize,
) {
    if depth > 4 || !value.is_object() {
        return;
    }
    out.push(value);
    for key in [
        "event",
        "envelope",
        "operation",
        "raw",
        "record",
        "payload",
        "body",
        "content",
        "data",
    ] {
        if let Some(child) = value.get(key).filter(|child| child.is_object()) {
            collect_message_candidates(child, out, depth + 1);
        }
    }
}

pub(crate) fn message_candidates(event: &Value) -> Vec<&Value> {
    let mut candidates = Vec::new();
    collect_message_candidates(event, &mut candidates, 0);
    candidates
}

pub(crate) fn first_string_in_candidates<'a>(
    candidates: &[&'a Value],
    keys: &[&str],
) -> Option<&'a str> {
    candidates
        .iter()
        .find_map(|candidate| value_string_at(candidate, keys))
}

pub(crate) fn message_actor_from_candidates<'a>(candidates: &[&'a Value]) -> Option<&'a str> {
    first_string_in_candidates(candidates, &["actor_id", "sender_actor_id", "actor"])
}

fn discussion_event_kind(value: &Value) -> Option<&str> {
    value_string_at(
        value,
        &["kind", "event_kind", "type", "op_type", "event_type"],
    )
}

pub(crate) fn message_kind_is_create(value: &Value) -> bool {
    discussion_event_kind(value) == Some("ck.message.create")
}

pub(crate) fn message_kind_is_revise(value: &Value) -> bool {
    discussion_event_kind(value) == Some("ck.message.revise")
}

fn discussion_kind_is_raw_operation(kind: &str) -> bool {
    matches!(
        kind,
        "ck.message.create"
            | "ck.message.revise"
            | "ck.message.redact"
            | "ck.reaction.add"
            | "ck.reaction.remove"
            | "ck.pin.add"
            | "ck.pin.remove"
            | "ck.pin.reorder"
    )
}

pub(crate) fn message_operations_from_events(
    realm_id: &str,
    events: &[Value],
) -> Vec<RawOperationRecord> {
    events
        .iter()
        .filter_map(|event| message_raw_operation_from_event(realm_id, event))
        .collect()
}

fn message_event_is_ingestable(event: &Value) -> bool {
    let candidates = message_candidates(event);
    candidates.iter().any(|candidate| {
        discussion_event_kind(candidate).is_some_and(discussion_kind_is_raw_operation)
    })
}

fn message_raw_operation_from_event(realm_id: &str, event: &Value) -> Option<RawOperationRecord> {
    if let Some(record) = typed_message_raw_operation_from_event(event) {
        return Some(record);
    }
    if !message_event_is_ingestable(event) {
        return None;
    }
    let candidates = message_candidates(event);
    // Dedup key: the canonical event id. Server-folded redaction/expiry
    // tombstones that carry the same `event_id` upsert over the create, while
    // independent `ck.message.redact` events keep their own record and are
    // folded by the chat projector.
    let operation_id = value_string_at(event, &["event_id", "id"])
        .or_else(|| first_string_in_candidates(&candidates, &["event_id", "message_id", "id"]))?
        .trim()
        .to_owned();
    if operation_id.is_empty() {
        return None;
    }
    let record_realm_id = first_string_in_candidates(&candidates, &["realm_id"])
        .unwrap_or(realm_id)
        .to_owned();
    let received_at = first_string_in_candidates(&candidates, &["created_at"])
        .and_then(|created_at| chrono::DateTime::parse_from_rfc3339(created_at).ok())
        .map(|timestamp| timestamp.with_timezone(&chrono::Utc))
        .unwrap_or_else(chrono::Utc::now);
    Some(RawOperationRecord {
        operation_id,
        realm_id: Some(record_realm_id),
        received_at,
        payload: event.clone(),
    })
}

fn typed_message_raw_operation_from_event(event: &Value) -> Option<RawOperationRecord> {
    let sdk_event: cokret_sdk::Event = serde_json::from_value(event.clone()).ok()?;
    let decoded = cokret_client::InboundDecoder::new()
        .try_decode_event(sdk_event)
        .ok()?;
    let cokret_client::DecodedInbound::Message(message) = decoded else {
        return None;
    };
    Some(RawOperationRecord {
        operation_id: message.event.event_id.as_str().to_owned(),
        realm_id: Some(message.event.realm_id.as_str().to_owned()),
        received_at: message.event.created_at,
        payload: event.clone(),
    })
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn typed_event(kind: &str, payload: Value) -> cokret_sdk::Event {
        let mut event = cokret_sdk::Event::new(
            kind,
            cokret_sdk::RealmId::new("ck:realm:01904100-0000-7000-8000-000000000001").unwrap(),
            cokret_sdk::Did::new("did:webvh:z6mkfixture:alice.example").unwrap(),
            1,
            cokret_sdk::Hlc::new("01970e589d21-0004-a13f9c2e").unwrap(),
            payload,
        )
        .unwrap();
        event.event_id =
            cokret_sdk::EventId::new("ck:event:01904100-0000-7000-8000-000000000101").unwrap();
        event.created_at = "2026-07-08T00:00:00Z".parse().unwrap();
        event
    }

    #[test]
    fn typed_message_raw_operation_uses_client_core_decoder() {
        let event = typed_event(
            cokret_sdk::events::kinds::MESSAGE_CREATE,
            json!({
                "strand_id": "ck:strand:01904100-0000-7000-8000-000000000201",
                "track_name": "discussion",
                "content": {"kind": "ck.content.text", "body": "hello"}
            }),
        );
        let value = serde_json::to_value(&event).unwrap();

        let record = typed_message_raw_operation_from_event(&value).unwrap();

        assert_eq!(
            record.operation_id,
            "ck:event:01904100-0000-7000-8000-000000000101"
        );
        assert_eq!(
            record.realm_id.as_deref(),
            Some("ck:realm:01904100-0000-7000-8000-000000000001")
        );
        assert_eq!(record.received_at, event.created_at);
        assert_eq!(record.payload, value);
    }

    #[test]
    fn typed_message_raw_operation_ignores_non_message_events() {
        let event = typed_event(
            cokret_sdk::events::kinds::PRESENCE,
            json!({"state": "online"}),
        );
        let value = serde_json::to_value(&event).unwrap();

        assert!(typed_message_raw_operation_from_event(&value).is_none());
    }
}
