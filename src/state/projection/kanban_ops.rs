//! Kanban realm-event → `RawOperationRecord` extraction (the sync engine's
//! kanban ingest funnel).
//!
//! YGN-ARCH-01 step 3 (pure move from `views/kanban/model/{board_projection,
//! overlays}.rs`, zero behavior change): consumed by
//! `sync_engine::ingest_kanban_events` and the kanban view model.

use serde_json::{Value, json};

use super::json_path_string;
use crate::state::RawOperationRecord;

/// Every kanban-relevant event kind the client folds into the board.
pub(crate) const KANBAN_EVENT_KINDS: &[&str] = &[
    "ak.space.create",
    "ak.space.update",
    "ak.space.archive",
    "ak.space.restore",
    "ak.strand.create",
    "ak.strand.update",
    "ak.strand.move",
    "ak.strand.reorder",
    "ak.strand.archive",
    "ak.strand.restore",
    "ak.relation.create",
    "ak.relation.tombstone",
];

/// Normalize a batch of canonical realm events (from `backfill` /
/// `events/subscribe`) into [`RawOperationRecord`]s for EVERY kanban-relevant
/// kind — the single ingest funnel that replaces the old per-kind extractors.
pub(crate) fn kanban_operations_from_events(events: &[Value]) -> Vec<RawOperationRecord> {
    events
        .iter()
        .filter_map(kanban_operation_from_event)
        .collect()
}

pub(crate) fn kanban_operations_from_client_events(
    events: &[garth::ClientEvent],
) -> Vec<RawOperationRecord> {
    events
        .iter()
        .filter_map(|event| match event {
            garth::ClientEvent::Message(message) => kanban_operation_from_typed(&message.event),
            garth::ClientEvent::Event(event) => kanban_operation_from_typed(event),
            _ => None,
        })
        .collect()
}

fn kanban_operation_from_typed(event: &arkret_sdk::Event) -> Option<RawOperationRecord> {
    let kind = event.kind.as_str();
    if !KANBAN_EVENT_KINDS.contains(&kind) {
        return None;
    }
    let operation_id = event.event_id.as_str().to_owned();
    Some(RawOperationRecord {
        operation_id: operation_id.clone(),
        realm_id: Some(event.realm_id.as_str().to_owned()),
        received_at: event.created_at,
        payload: json!({
            "kind": kind,
            "operation_id": operation_id,
            "actor_id": event.actor_id.as_str(),
            "created_at": arkret_sdk::canonical::format_timestamp_canonical(event.created_at),
            "write_state": "synced",
            "body": event.payload,
        }),
    })
}

fn kanban_operation_from_event(event: &Value) -> Option<RawOperationRecord> {
    let kind = json_path_string(Some(event), &["event_kind"])
        .or_else(|| json_path_string(Some(event), &["kind"]))?;
    if !KANBAN_EVENT_KINDS.contains(&kind.as_str()) {
        return None;
    }
    raw_operation_from_event(event, &kind)
}

pub(crate) fn raw_operation_from_event(
    event: &Value,
    expected_kind: &str,
) -> Option<RawOperationRecord> {
    let kind = json_path_string(Some(event), &["event_kind"])
        .or_else(|| json_path_string(Some(event), &["kind"]))?;
    if kind != expected_kind {
        return None;
    }
    let body = event.get("payload")?.clone();
    let operation_id = json_path_string(Some(event), &["operation_id"])
        .or_else(|| json_path_string(Some(event), &["event_id"]))
        .unwrap_or_else(|| format!("remote-{expected_kind}"));
    // Canonical envelopes expose `actor_id` / `sender_actor_id` only;
    // forbidden `sender` fields are not accepted.
    let actor_id = json_path_string(Some(event), &["actor_id"])
        .or_else(|| json_path_string(Some(event), &["sender_actor_id"]))
        .or_else(|| json_path_string(Some(&body), &["actor_id"]))
        .or_else(|| json_path_string(Some(&body), &["sender_actor_id"]))
        .unwrap_or_default();
    let created_at = json_path_string(Some(event), &["created_at"])
        .or_else(|| json_path_string(Some(&body), &["created_at"]))
        .unwrap_or_default();
    let received_at = chrono::DateTime::parse_from_rfc3339(&created_at)
        .map(|timestamp| timestamp.with_timezone(&chrono::Utc))
        .unwrap_or_else(|_| chrono::Utc::now());

    Some(RawOperationRecord {
        operation_id: operation_id.clone(),
        realm_id: json_path_string(Some(event), &["realm_id"])
            .or_else(|| json_path_string(Some(&body), &["object", "realm_id"])),
        received_at,
        payload: json!({
            "kind": kind,
            "operation_id": operation_id,
            "actor_id": actor_id,
            "created_at": created_at,
            "write_state": "synced",
            "body": body,
        }),
    })
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn client_event_path_projects_without_reparsing_the_envelope() {
        let mut event = arkret_sdk::Event::new(
            arkret_sdk::EventKind::STRAND_UPDATE,
            arkret_sdk::ScopeRef::Realm {
                realm_id: arkret_sdk::RealmId::new("ak:realm:01904100-0000-8000-8000-000000000001")
                    .unwrap(),
            },
            arkret_sdk::Did::new("did:web:alice.example").unwrap(),
            1,
            arkret_sdk::Hlc::new("01970e589d21-0004-a13f9c2e").unwrap(),
            json!({
                "strand_id": "ak:strand:01904100-0000-8000-8000-000000000002",
                "patch": {"title": {"$op": "set", "value": "Updated"}}
            }),
        )
        .unwrap();
        event.event_id =
            arkret_sdk::EventId::new("ak:event:01904100-0000-8000-8000-000000000101").unwrap();

        let records = kanban_operations_from_client_events(&[garth::ClientEvent::Event(event)]);

        assert_eq!(records.len(), 1);
        assert_eq!(records[0].payload["kind"], "ak.strand.update");
        assert_eq!(
            records[0].payload["body"]["strand_id"],
            "ak:strand:01904100-0000-8000-8000-000000000002"
        );
    }
}
