//! Kanban realm-event → `RawOperationRecord` extraction (the sync engine's
//! kanban ingest funnel).
//!
//! YGN-ARCH-01 step 3 (pure move from `views/kanban/model/{board_projection,
//! overlays}.rs`, zero behavior change): consumed by
//! `sync_engine::ingest_kanban_events` and the kanban view model.

use serde_json::{Value, json};

use super::json_path_string;
use crate::local_state::RawOperationRecord;

/// Every kanban-relevant event kind the client folds into the board.
pub(crate) const KANBAN_EVENT_KINDS: &[&str] = &[
    "ck.space.create",
    "ck.space.update",
    "ck.space.archive",
    "ck.space.restore",
    "ck.strand.create",
    "ck.strand.update",
    "ck.strand.move",
    "ck.strand.reorder",
    "ck.strand.archive",
    "ck.strand.restore",
    "ck.relation.create",
    "ck.relation.tombstone",
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

