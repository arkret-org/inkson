//! Message-event → `RawOperationRecord` extraction (the sync engine's
//! discussion-message ingest step) plus the nested-envelope candidate
//! walkers it is built on.
//!
//! YGN-ARCH-01 step 3 (pure move from `views/chat/model/events.rs`, zero
//! behavior change): consumed by `sync_engine::ingest_message_events` and the
//! chat view model (which re-exports these helpers).

use serde_json::Value;

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

pub(crate) fn message_kind_is_create(value: &Value) -> bool {
    value_string_at(value, &["kind", "type", "op_type", "event_type"]) == Some("ck.message.create")
}

pub(crate) fn message_operations_from_events(
    realm_id: &str,
    events: &[Value],
) -> Vec<crate::local_state::RawOperationRecord> {
    events
        .iter()
        .filter_map(|event| message_raw_operation_from_event(realm_id, event))
        .collect()
}

fn message_event_is_ingestable(event: &Value) -> bool {
    let candidates = message_candidates(event);
    candidates
        .iter()
        .any(|candidate| message_kind_is_create(candidate))
}

fn message_raw_operation_from_event(
    realm_id: &str,
    event: &Value,
) -> Option<crate::local_state::RawOperationRecord> {
    if !message_event_is_ingestable(event) {
        return None;
    }
    let candidates = message_candidates(event);
    // Dedup key: the canonical event id. A later redaction/expiry tombstone
    // carrying the same `event_id` upserts over the create, so the local-first
    // render folds the tombstone (not the original body).
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
    Some(crate::local_state::RawOperationRecord {
        operation_id,
        realm_id: Some(record_realm_id),
        received_at,
        payload: event.clone(),
    })
}
