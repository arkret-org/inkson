use std::collections::{BTreeMap, BTreeSet};

use serde_json::Value;

use super::json_path_string;
use super::model::*;
use crate::operation::trim_realm_id;
use crate::state::{LocalStateStore, RawOperationRecord};
use crate::views::helpers::actor_display_label;
#[cfg(test)]
pub(super) use crate::views::member_display::member_label;
#[cfg(test)]
pub(super) use crate::views::member_display::verified_inline_handle;
pub(super) use crate::views::member_display::{
    RealmMemberRow, owned_agent_slug, realm_member_roster,
};

pub(super) fn card_member_is_current_account(row: &RealmMemberRow, principal_id: &str) -> bool {
    actor_is_current_account(&row.actor_id, principal_id)
        || row
            .subject_id
            .as_deref()
            .is_some_and(|subject_id| actor_is_current_account(subject_id, principal_id))
}

pub(super) fn member_roster_realm_context(
    selected_realm_id: &str,
    projection_realm_id: &str,
    projection: Option<&Value>,
) -> String {
    let raw = projection
        .and_then(|body| {
            json_path_string(Some(body), &["realm_id"])
                .or_else(|| json_path_string(Some(body), &["summary", "realm_id"]))
        })
        .or_else(|| {
            let trimmed = projection_realm_id.trim();
            (!trimmed.is_empty()).then(|| trimmed.to_owned())
        })
        .unwrap_or_else(|| selected_realm_id.to_owned());
    trim_realm_id(&raw)
}

#[derive(Clone, Copy)]
pub(super) struct CardAuthorDisplayContext<'a> {
    pub realm_id: &'a str,
    pub member_rows: &'a [RealmMemberRow],
}

#[cfg(test)]
#[derive(Clone, Debug, Default, PartialEq)]
pub(super) struct RealmRosterPagination {
    pub member_roster_entries_limited: bool,
    pub member_roster_entries_next_cursor: Option<String>,
}

#[cfg(test)]
impl RealmRosterPagination {
    pub fn from_projection(projection: Option<&Value>) -> Self {
        let Some(root) = projection else {
            return Self::default();
        };
        let limited = root
            .get("member_roster_entries_limited")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let cursor = root
            .get("member_roster_entries_next_cursor")
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(ToOwned::to_owned);
        Self {
            member_roster_entries_limited: limited,
            member_roster_entries_next_cursor: cursor,
        }
    }
}

/// Collect a deduped list of actor IDs that have authored *any*
/// queued / accepted raw operation that targets the given strand id
/// (matched against `target_ref`, `strand_id`, or `object.id`). This
/// gives the "who's interacted with this Strand" list shown on the
/// sidebar's Participants tab even before the server returns a
/// canonical discussion-roster projection.
pub(super) fn strand_participant_ids(
    raw_operations: &[RawOperationRecord],
    strand_id: &str,
) -> Vec<String> {
    let strand_id = strand_id.trim();
    if strand_id.is_empty() {
        return Vec::new();
    }
    let mut actor_ids: BTreeSet<String> = BTreeSet::new();
    for op in raw_operations {
        let payload = &op.payload;
        let target = json_path_string(Some(payload), &["body", "target_ref"])
            .or_else(|| json_path_string(Some(payload), &["body", "strand_id"]))
            .or_else(|| json_path_string(Some(payload), &["body", "object", "id"]))
            .or_else(|| json_path_string(Some(payload), &["payload", "target_ref"]))
            .or_else(|| json_path_string(Some(payload), &["payload", "strand_id"]));
        if target.as_deref() != Some(strand_id) {
            continue;
        }
        for actor in [
            payload.pointer("/body/actor_id"),
            payload.pointer("/body/sender_actor_id"),
            payload.pointer("/payload/actor_id"),
            payload.get("actor_id"),
        ]
        .into_iter()
        .flatten()
        {
            if let Some(actor_id) =
                crate::state::projection::message_ops::actor_principal_from_value(actor)
            {
                actor_ids.insert(actor_id);
            }
        }
    }
    let mut out: Vec<String> = actor_ids.into_iter().collect();
    out.sort();
    out
}

pub(super) fn card_author_display_label(
    state_store: &LocalStateStore,
    author_context: Option<CardAuthorDisplayContext<'_>>,
    actor_id: &str,
) -> String {
    let actor_id = actor_id.trim();
    if actor_id.is_empty() {
        return "Unknown author".to_owned();
    }
    if let Some(label) = member_display_label_for_actor(state_store, author_context, actor_id) {
        return label;
    }
    actor_display_label(state_store, actor_id)
}

pub(super) fn member_display_label_for_actor(
    state_store: &LocalStateStore,
    author_context: Option<CardAuthorDisplayContext<'_>>,
    actor_id: &str,
) -> Option<String> {
    let actor_id = actor_id.trim();
    let context = author_context?;
    let realm_id = context.realm_id.trim();
    if actor_id.is_empty() || realm_id.is_empty() {
        return None;
    }
    let row = context.member_rows.iter().find(|row| {
        row.actor_id.trim() == actor_id
            || row
                .subject_id
                .as_deref()
                .map(str::trim)
                .is_some_and(|subject| subject == actor_id)
    })?;
    Some(crate::views::member_display::resolve_member_display(state_store, realm_id, row).label)
}

pub(super) fn bare_member_row(actor_id: String) -> RealmMemberRow {
    RealmMemberRow {
        actor_id,
        membership: None,
        identity_event_ids: Vec::new(),
        member_display_state_digest: None,
        subject_id: None,
        handle_claims: Vec::new(),
        handle_claims_limited: false,
    }
}

pub(super) fn assignment_picker_roster(
    member_rows: &[RealmMemberRow],
    card: &KanbanCard,
) -> Vec<RealmMemberRow> {
    let mut rows = BTreeMap::<String, RealmMemberRow>::new();
    for row in member_rows {
        rows.entry(row.actor_id.clone())
            .or_insert_with(|| row.clone());
    }
    for actor_id in card_assigned_actor_ids(card) {
        rows.entry(actor_id.clone())
            .or_insert_with(|| bare_member_row(actor_id));
    }
    rows.into_values().collect()
}

pub(super) fn assignee_label_for_actor(
    state_store: &LocalStateStore,
    realm_context: &str,
    member_rows: &[RealmMemberRow],
    actor_id: &str,
) -> String {
    let context = CardAuthorDisplayContext {
        realm_id: realm_context,
        member_rows,
    };
    member_display_label_for_actor(state_store, Some(context), actor_id)
        .unwrap_or_else(|| actor_display_label(state_store, actor_id))
}

pub(super) fn assignee_filter_matches(filter: &str, label: &str, actor_id: &str) -> bool {
    let filter = filter.trim().to_lowercase();
    if filter.is_empty() {
        return true;
    }
    label.to_lowercase().contains(&filter) || actor_id.to_lowercase().contains(&filter)
}
