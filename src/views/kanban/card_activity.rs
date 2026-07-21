use serde_json::Value;

use super::model::*;
use super::{compact_timestamp_label, json_path_string};
use crate::state::RawOperationRecord;
use crate::views::helpers::short_protocol_id;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum CardActivityStatus {
    Info,
    Pending,
    Accepted,
    Failed,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct CardActivityItem {
    pub key: String,
    pub title: String,
    pub detail: Option<String>,
    pub status: CardActivityStatus,
}

impl CardActivityItem {
    pub(super) fn class_name(&self) -> &'static str {
        match self.status {
            CardActivityStatus::Info => "card-detail-activity-item",
            CardActivityStatus::Pending => "card-detail-activity-item pending",
            CardActivityStatus::Accepted => "card-detail-activity-item accepted",
            CardActivityStatus::Failed => "card-detail-activity-item failed",
        }
    }
}

pub(super) fn card_activity_items(
    card: &KanbanCard,
    raw_operations: &[RawOperationRecord],
    actor_label: &impl Fn(&str) -> String,
) -> Vec<CardActivityItem> {
    let mut records = raw_operations
        .iter()
        .filter(|record| raw_operation_targets_card(&record.payload, card))
        .collect::<Vec<_>>();
    records.sort_by_key(|record| std::cmp::Reverse(record.received_at));
    let mut items = records
        .into_iter()
        .filter_map(|record| card_activity_item_from_raw_operation(record, card, actor_label))
        .take(5)
        .collect::<Vec<_>>();
    if items.is_empty() {
        items = projection_card_activity_items(card, actor_label);
    }
    if items.is_empty() {
        items.push(CardActivityItem {
            key: "empty".to_owned(),
            title: "No visible activity yet".to_owned(),
            detail: Some("Recent server events are not loaded in this view.".to_owned()),
            status: CardActivityStatus::Info,
        });
    }
    items
}

pub(super) fn projection_card_activity_items(
    card: &KanbanCard,
    actor_label: &impl Fn(&str) -> String,
) -> Vec<CardActivityItem> {
    let mut items = Vec::new();
    if !card.updated_at.trim().is_empty() {
        items.push(CardActivityItem {
            key: "projection-updated".to_owned(),
            title: "Last updated".to_owned(),
            detail: Some(compact_timestamp_label(&card.updated_at)),
            status: CardActivityStatus::Info,
        });
    }
    if !card.created_at.trim().is_empty() {
        let mut detail = compact_timestamp_label(&card.created_at);
        if !card.created_by.trim().is_empty() {
            detail.push_str(" · ");
            detail.push_str(&actor_label(&card.created_by));
        }
        items.push(CardActivityItem {
            key: "projection-created".to_owned(),
            title: "Created".to_owned(),
            detail: Some(detail),
            status: CardActivityStatus::Info,
        });
    }
    items
}

pub(super) fn raw_operation_targets_card(payload: &Value, card: &KanbanCard) -> bool {
    let ids = [card.id.trim(), card.primary_strand_id.trim()];
    for path in [
        &["assignment_strand_id"][..],
        &["strand_id"][..],
        &["target_ref"][..],
        &["body", "strand_id"][..],
        &["body", "target_ref"][..],
        &["body", "from_ref"][..],
        &["body", "object", "id"][..],
        &["payload", "strand_id"][..],
        &["payload", "target_ref"][..],
        &["payload", "from_ref"][..],
        &["payload", "object", "id"][..],
    ] {
        if let Some(value) = json_path_string(Some(payload), path)
            && ids.iter().any(|id| !id.is_empty() && *id == value)
        {
            return true;
        }
    }
    false
}

pub(super) fn card_activity_item_from_raw_operation(
    record: &RawOperationRecord,
    card: &KanbanCard,
    actor_label: &impl Fn(&str) -> String,
) -> Option<CardActivityItem> {
    let payload = &record.payload;
    let kind = json_path_string(Some(payload), &["kind"])
        .or_else(|| json_path_string(Some(payload), &["wire_kind"]))?;
    let status = activity_status_from_payload(payload);
    let title = json_path_string(Some(payload), &["activity_summary"])
        .unwrap_or_else(|| activity_title_from_operation(&kind, payload, card, actor_label));
    let detail = raw_operation_activity_detail(&kind, payload, record, actor_label);
    Some(CardActivityItem {
        key: json_path_string(Some(payload), &["operation_id"])
            .unwrap_or_else(|| record.operation_id.clone()),
        title,
        detail: Some(detail),
        status,
    })
}

pub(super) fn activity_status_from_payload(payload: &Value) -> CardActivityStatus {
    match json_path_string(Some(payload), &["write_state"])
        .unwrap_or_else(|| "queued".to_owned())
        .as_str()
    {
        "queued" | "submitted" | "optimistic" => CardActivityStatus::Pending,
        "accepted" => CardActivityStatus::Accepted,
        "failed" | "soft_failed" | "quarantined" | "conflict" => CardActivityStatus::Failed,
        _ => CardActivityStatus::Info,
    }
}

pub(super) fn activity_status_label(payload: &Value) -> &'static str {
    match json_path_string(Some(payload), &["write_state"])
        .unwrap_or_else(|| "queued".to_owned())
        .as_str()
    {
        "queued" => "queued",
        "submitted" => "submitted",
        "accepted" => "accepted",
        "failed" => "failed",
        "soft_failed" => "soft failed",
        "quarantined" => "quarantined",
        "conflict" => "conflict",
        _ => "local",
    }
}

pub(super) fn raw_operation_activity_detail(
    kind: &str,
    payload: &Value,
    record: &RawOperationRecord,
    actor_label: &impl Fn(&str) -> String,
) -> String {
    let timestamp = json_path_string(Some(payload), &["created_at"])
        .unwrap_or_else(|| arkret_sdk::canonical::format_timestamp_canonical(record.received_at));
    let mut parts = vec![
        kind.to_owned(),
        activity_status_label(payload).to_owned(),
        compact_timestamp_label(&timestamp),
    ];
    if let Some(actor) = json_path_string(Some(payload), &["actor_id"])
        .or_else(|| json_path_string(Some(payload), &["body", "actor_id"]))
    {
        parts.push(actor_label(&actor));
    }
    if let Some(event_id) = json_path_string(Some(payload), &["event_id"]) {
        parts.push(short_protocol_id(&event_id));
    }
    parts.join(" · ")
}

pub(super) fn activity_title_from_operation(
    kind: &str,
    payload: &Value,
    _card: &KanbanCard,
    actor_label: &impl Fn(&str) -> String,
) -> String {
    match kind {
        "ak.relation.create" => {
            let relation_kind = json_path_string(Some(payload), &["body", "kind"])
                .or_else(|| json_path_string(Some(payload), &["body", "relation_kind"]));
            if relation_kind.as_deref() == Some("assigned_to") {
                let actor = json_path_string(Some(payload), &["assignment_actor_id"])
                    .or_else(|| json_path_string(Some(payload), &["body", "to_ref"]))
                    .map(|actor| actor_label(&actor))
                    .unwrap_or_else(|| "actor".to_owned());
                format!("Assignee added: {actor}")
            } else {
                "Relation added".to_owned()
            }
        }
        "ak.relation.tombstone" => {
            if let Some(actor) = json_path_string(Some(payload), &["assignment_actor_id"]) {
                format!("Assignee removed: {}", actor_label(&actor))
            } else {
                "Relation removed".to_owned()
            }
        }
        "ak.strand.update" => strand_update_activity_title(payload),
        "ak.strand.move" => "Card moved".to_owned(),
        "ak.strand.reorder" => "Card reordered".to_owned(),
        "ak.strand.create" => "Card created".to_owned(),
        _ => kind.to_owned(),
    }
}

pub(super) fn strand_update_activity_title(payload: &Value) -> String {
    let patch = payload
        .get("body")
        .and_then(|body| body.get("patch"))
        .or_else(|| payload.get("payload").and_then(|body| body.get("patch")));
    if let Some(patch) = patch.and_then(Value::as_object) {
        let fields = patch
            .get("metadata.fields")
            .or_else(|| patch.get("fields"))
            .and_then(|op| {
                (op.get("$op").and_then(Value::as_str) == Some("set"))
                    .then(|| op.get("value"))
                    .flatten()
            })
            .and_then(Value::as_object);
        if let Some(fields) = fields {
            if let Some(due) = fields
                .get("due_at")
                .or_else(|| fields.get("due"))
                .and_then(Value::as_str)
                .filter(|due| !due.trim().is_empty())
            {
                return format!("Due date set to {due}");
            }
            return "Card fields updated".to_owned();
        }
        if patch.contains_key("metadata.title") || patch.contains_key("title") {
            return "Title updated".to_owned();
        }
        if patch.contains_key("metadata.summary") || patch.contains_key("summary") {
            return "Summary updated".to_owned();
        }
        if patch.contains_key("body") || patch.contains_key("synthesis") {
            return "Card content updated".to_owned();
        }
    }
    "Card updated".to_owned()
}
