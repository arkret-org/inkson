//! Message-event → `RawOperationRecord` extraction (the sync engine's
//! discussion-message ingest step) plus the nested-envelope candidate
//! walkers it is built on.
//!
//! YGN-ARCH-01 step 3 (pure move from `views/chat/model/events.rs`, zero
//! behavior change): consumed by `sync_engine::ingest_message_events` and the
//! chat view model (which re-exports these helpers).

use serde_json::Value;

use crate::state::RawOperationRecord;

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
    discussion_event_kind(value) == Some("ak.message.create")
}

pub(crate) fn message_kind_is_revise(value: &Value) -> bool {
    discussion_event_kind(value) == Some("ak.message.revise")
}

fn discussion_kind_is_raw_operation(kind: &str) -> bool {
    matches!(
        kind,
        "ak.message.create"
            | "ak.message.revise"
            | "ak.message.redact"
            | "ak.agent.sidecar.exchange.control"
            | "ak.reaction.add"
            | "ak.reaction.remove"
            | "ak.pin.add"
            | "ak.pin.remove"
            | "ak.pin.reorder"
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

pub(crate) fn message_operations_from_client_events(
    realm_id: &str,
    events: &[garth::ClientEvent],
) -> Vec<RawOperationRecord> {
    events
        .iter()
        .filter_map(|event| match event {
            garth::ClientEvent::Message(message) => {
                typed_message_raw_operation(realm_id, &message.event)
            }
            garth::ClientEvent::Event(event) => typed_message_raw_operation(realm_id, event),
            _ => None,
        })
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
    // independent `ak.message.redact` events keep their own record and are
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
    let sdk_event: arkret_sdk::Event = serde_json::from_value(event.clone()).ok()?;
    typed_message_raw_operation("", &sdk_event)
}

fn typed_message_raw_operation(
    fallback_realm_id: &str,
    event: &arkret_sdk::Event,
) -> Option<RawOperationRecord> {
    if !discussion_kind_is_raw_operation(event.kind.as_str()) {
        return None;
    }
    let payload = serde_json::to_value(event).ok()?;
    Some(RawOperationRecord {
        operation_id: event.event_id.as_str().to_owned(),
        realm_id: Some(if event.realm_id.as_str().is_empty() {
            fallback_realm_id.to_owned()
        } else {
            event.realm_id.as_str().to_owned()
        }),
        received_at: event.created_at,
        payload,
    })
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn typed_event(kind: &str, payload: Value) -> arkret_sdk::Event {
        let mut event = arkret_sdk::Event::new(
            kind,
            arkret_sdk::ScopeRef::Realm {
                realm_id: arkret_sdk::RealmId::new("ak:realm:01904100-0000-7000-8000-000000000001")
                    .unwrap(),
            },
            arkret_sdk::Did::new("did:webvh:z6mkfixture:alice.example").unwrap(),
            1,
            arkret_sdk::Hlc::new("01970e589d21-0004-a13f9c2e").unwrap(),
            payload,
        )
        .unwrap();
        event.event_id =
            arkret_sdk::EventId::new("ak:event:01904100-0000-7000-8000-000000000101").unwrap();
        event.created_at = "2026-07-08T00:00:00.000Z".parse().unwrap();
        event
    }

    #[test]
    fn typed_message_raw_operation_uses_client_core_decoder() {
        let event = typed_event(
            arkret_sdk::EventKind::MESSAGE_CREATE,
            json!({
                "strand_id": "ak:strand:01904100-0000-7000-8000-000000000201",
                "track_name": "discussion",
                "content": {"kind": "ak.content.text", "body": "hello"}
            }),
        );
        let value = serde_json::to_value(&event).unwrap();

        let record = typed_message_raw_operation_from_event(&value).unwrap();

        assert_eq!(
            record.operation_id,
            "ak:event:01904100-0000-7000-8000-000000000101"
        );
        assert_eq!(
            record.realm_id.as_deref(),
            Some("ak:realm:01904100-0000-7000-8000-000000000001")
        );
        assert_eq!(record.received_at, event.created_at);
        assert_eq!(record.payload, value);
    }

    #[test]
    fn typed_message_raw_operation_keeps_sidecar_control_and_ignores_unrelated_events() {
        let sidecar_control = typed_event(
            arkret_sdk::EventKind::AGENT_SIDECAR_EXCHANGE_CONTROL,
            json!({
                "strand_id": "ak:strand:01904100-0000-7000-8000-000000000201",
                "encrypted_payload": {
                    "schema": "ak.schema.encrypted_envelope.v1",
                    "suite": "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519",
                    "key_ref": {
                        "kind": "mls_group",
                        "group_id": "AQIDBA",
                        "epoch": 1,
                        "group_state_ref": "ak:event:01904100-0000-7000-8000-000000000102"
                    },
                    "aad_visibility": "hidden",
                    "ciphertext": "AQIDBA"
                }
            }),
        );
        assert!(
            typed_message_raw_operation_from_event(
                &serde_json::to_value(&sidecar_control).unwrap()
            )
            .is_some()
        );

        // The pre-v1 fixture used `ak.presence`, which is not an Event kind at
        // all any more — presence is Signal ciphertext. Any durable kind
        // outside the discussion allow-list makes the same point.
        let event = typed_event(
            arkret_sdk::EventKind::MEMBER_STATE,
            json!({"state": "join"}),
        );
        let value = serde_json::to_value(&event).unwrap();

        assert!(typed_message_raw_operation_from_event(&value).is_none());
    }

    #[test]
    fn client_event_path_keeps_the_typed_event_boundary() {
        let event = typed_event(
            arkret_sdk::EventKind::MESSAGE_CREATE,
            json!({
                "strand_id": "ak:strand:01904100-0000-7000-8000-000000000002",
                "track_name": "discussion",
                "content": {"kind": "ak.content.text", "body": "typed"}
            }),
        );
        let decoded = garth::InboundDecoder::new()
            .try_decode_event(event)
            .unwrap();
        let client_event = match decoded {
            garth::DecodedInbound::Message(message) => garth::ClientEvent::Message(*message),
            other => panic!("expected message, got {other:?}"),
        };

        let records = message_operations_from_client_events(
            "ak:realm:01904100-0000-7000-8000-000000000001",
            &[client_event],
        );

        assert_eq!(records.len(), 1);
        assert_eq!(
            records[0].operation_id,
            "ak:event:01904100-0000-7000-8000-000000000101"
        );
    }
}
