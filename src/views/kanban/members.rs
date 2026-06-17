use std::collections::{BTreeMap, BTreeSet};

use serde_json::Value;

use super::json_path_string;
use super::model::*;
use crate::local_state::{LocalStateStore, RawOperationRecord};
use crate::operation::trim_realm_id;
use crate::views::helpers::{display_name_for_did, handle_display_from_did, short_protocol_id};

/// Per-member entry harvested from a cached Realm projection.
///
/// R3.2 (cokret-spec @ b56cab1) — roster entries MUST NOT carry raw
/// handle / display fields. Identity resolution happens by following
/// `identity_event_ids[]` (or inline `identity_events[]`) and applying
/// the SDK's `effective_identity_events` helper. Handle strings only ever
/// appear inside signed `ck.schema.handle_claim.v1` evidence.
///
/// `actor_id` is the actor DID. `membership` is `join` / `invite` /
/// `knock`. `identity_event_ids` are the effective
/// `ck.member.identity.update` event ids (after replacement edges).
/// `member_display_state_digest` is the roster display cache key (R3.2
/// rename of the prior `identity_state_digest`; now folds the visible
/// handle-claim digest set). `subject_id` is the disclosed principal DID
/// — present only when the server disclosed it (gates the handle-claim
/// evidence fields per the R3.2 roster dependentRequired rule).
#[derive(Clone, Debug, PartialEq)]
pub(super) struct RealmMemberRow {
    /// Actor DID.
    pub actor_id: String,
    pub membership: Option<String>,
    pub identity_event_ids: Vec<String>,
    pub member_display_state_digest: Option<String>,
    /// R3.2 roster — disclosed principal/holder DID. `None` when the
    /// server did not disclose it (then the handle-claim fields are also
    /// absent). Drives §3.2.1 primary-handle selection + the
    /// "Why am I seeing this handle?" panel.
    pub subject_id: Option<String>,
    pub handle_claims: Vec<Value>,
    pub handle_claims_limited: bool,
}

/// Pick the best UI label for a roster row.
///
/// R3.2: prefer visible handle-claim evidence, then a fresh
/// `list_handles_for_subject` cache entry, then a materialized subject DID
/// display fallback. If no handle-shaped label is available, use the
/// resolved [`MemberIdentity`] display (via the SDK's effective-set
/// helper), then a compact actor-DID fallback so long `did:webvh:...`
/// strings don't overflow.
///
/// `identity` is the current effective [`MemberIdentity`] for this row
/// (when one has been decrypted + verified). [`None`] means the row is
/// `decryption_pending` or no identity event has been observed yet — in
/// either case we render the compact DID instead of a raw `did:...`.
pub(super) fn member_display_label(
    row: &RealmMemberRow,
    identity: Option<&cokret_sdk::MemberIdentity>,
    cached_primary_handle: Option<&str>,
) -> String {
    if let Some(handle) = member_inline_handle_label(row) {
        return handle;
    }
    if let Some(handle) = cached_primary_handle.and_then(crate::identity_handle::parse_user_handle)
    {
        return handle.display;
    }
    if let Some(handle) = member_fallback_handle_label(row) {
        return handle;
    }
    if let Some(identity) = identity {
        // R3.2: `MemberIdentity` no longer carries handle fields. The
        // verified handle (if any) comes from running §3.2.1 over the
        // roster handle-claim set; that resolution happens in the mention
        // / member-detail render path (see `render_member_handle`). The
        // roster row label falls back to the disclosed display name.
        let name = identity.display_profile.display_name.trim();
        if !name.is_empty() {
            return name.to_owned();
        }
    }
    short_protocol_id(&row.actor_id)
}

pub(super) fn member_inline_handle_label(row: &RealmMemberRow) -> Option<String> {
    let subject = row.subject_id.as_deref().unwrap_or(row.actor_id.as_str());
    row.handle_claims.iter().find_map(|claim| {
        let claim_subject = json_path_string(Some(claim), &["subject"])
            .or_else(|| json_path_string(Some(claim), &["subject_id"]))?;
        if claim_subject.trim() != subject {
            return None;
        }
        let binding_state = json_path_string(Some(claim), &["binding_state"])
            .unwrap_or_else(|| "verified".to_owned());
        if !matches!(binding_state.as_str(), "verified" | "active") {
            return None;
        }
        json_path_string(Some(claim), &["handle"])
            .and_then(|raw| crate::identity_handle::parse_user_handle(&raw).map(|h| h.display))
    })
}

pub(super) fn member_fallback_handle_label(row: &RealmMemberRow) -> Option<String> {
    row.subject_id
        .as_deref()
        .and_then(handle_display_from_did)
        .or_else(|| handle_display_from_did(&row.actor_id))
}

pub(super) fn member_handle_lookup_subject(
    row: &RealmMemberRow,
    identity: Option<&cokret_sdk::MemberIdentity>,
) -> Option<String> {
    if let Some(subject) = row
        .subject_id
        .as_deref()
        .map(str::trim)
        .filter(|subject| subject.starts_with("did:"))
        .filter(|subject| !subject.is_empty())
    {
        return Some(subject.to_owned());
    }
    if let Some(identity) = identity {
        return Some(identity.subject_id.as_str().to_owned());
    }
    // The roster may omit `subject_id` while the current server still uses
    // the visible actor DID as the principal DID. This lookup is
    // Realm-scoped, display-only, and Directory-enforced; if the actor is a
    // pairwise/private DID the response should simply be empty and cached
    // briefly as a negative display lookup.
    let actor = row.actor_id.trim();
    actor.starts_with("did:").then(|| actor.to_owned())
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

pub(super) fn member_handle_fetch_key(
    realm_id: &str,
    subject_id: &str,
    digest: Option<&str>,
) -> String {
    format!(
        "{}\u{1f}{}\u{1f}{}",
        realm_id.trim(),
        subject_id.trim(),
        digest.unwrap_or("")
    )
}

#[derive(Clone, Copy)]
pub(super) struct CardAuthorDisplayContext<'a> {
    pub realm_id: &'a str,
    pub member_rows: &'a [RealmMemberRow],
}

/// Collect the sorted roster of realm members from a cached space
/// projection. R3.2 roster wire shape per
/// `account-subscribe-frame.schema.json#/$defs/member_roster_entry`:
/// `{actor_id, membership, subject_id?, identity_event_ids?,
/// member_display_state_digest?, identity_events?, handle_claim_digests?,
/// handle_claims?, handle_claims_limited?}`. The four handle-claim /
/// identity-event evidence fields are disclosure-gated on `subject_id`;
/// when the server omits `subject_id` it omits them all (we just treat
/// them as `None`).
pub(super) fn realm_member_roster(projection: Option<&Value>) -> Vec<RealmMemberRow> {
    let Some(root) = projection else {
        return Vec::new();
    };
    let mut rows: BTreeMap<String, RealmMemberRow> = BTreeMap::new();
    let sources: [&Value; 2] = [root, root.get("summary").unwrap_or(root)];
    for source in sources {
        for key in [
            "members",
            "participants",
            "owners",
            "admins",
            "admin_dids",
            "owner",
            "created_by",
            "creator",
        ] {
            collect_member_rows(source.get(key), &mut rows);
        }
    }
    rows.into_values().collect()
}

pub(super) fn collect_member_rows(
    value: Option<&Value>,
    out: &mut BTreeMap<String, RealmMemberRow>,
) {
    let Some(value) = value else { return };
    match value {
        Value::Array(items) => {
            for item in items {
                collect_member_rows(Some(item), out);
            }
        }
        Value::Object(map) => {
            let actor_id = map
                .get("actor_id")
                .and_then(|child| child.as_str())
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(ToOwned::to_owned);
            let membership = map
                .get("membership")
                .and_then(|child| child.as_str())
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(ToOwned::to_owned);
            let identity_event_ids: Vec<String> = map
                .get("identity_event_ids")
                .and_then(|child| child.as_array())
                .map(|items| {
                    items
                        .iter()
                        .filter_map(|item| item.as_str().map(str::trim).filter(|s| !s.is_empty()))
                        .map(ToOwned::to_owned)
                        .collect()
                })
                .unwrap_or_default();
            // R3.2 roster rename: `identity_state_digest` →
            // `member_display_state_digest` (no pre-R3.2 compat).
            let member_display_state_digest = map
                .get("member_display_state_digest")
                .and_then(|child| child.as_str())
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(ToOwned::to_owned);
            // R3.2 roster: disclosed principal/holder DID. Gates the
            // inline handle-claim evidence. dependentRequired is enforced
            // server-side; here we simply read what was disclosed.
            let subject_id = map
                .get("subject_id")
                .and_then(|child| child.as_str())
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(ToOwned::to_owned);
            let handle_claims = map
                .get("handle_claims")
                .and_then(Value::as_array)
                .map(|items| items.to_vec())
                .unwrap_or_default();
            let handle_claims_limited = map
                .get("handle_claims_limited")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            if let Some(actor_id) = actor_id {
                let candidate = RealmMemberRow {
                    actor_id: actor_id.clone(),
                    membership: membership.clone(),
                    identity_event_ids: identity_event_ids.clone(),
                    member_display_state_digest: member_display_state_digest.clone(),
                    subject_id: subject_id.clone(),
                    handle_claims: handle_claims.clone(),
                    handle_claims_limited,
                };
                match out.entry(actor_id) {
                    std::collections::btree_map::Entry::Vacant(entry) => {
                        entry.insert(candidate);
                    }
                    std::collections::btree_map::Entry::Occupied(mut entry) => {
                        let existing = entry.get_mut();
                        if existing.membership.is_none() {
                            existing.membership = membership;
                        }
                        if existing.identity_event_ids.is_empty() {
                            existing.identity_event_ids = identity_event_ids;
                        }
                        if existing.member_display_state_digest.is_none() {
                            existing.member_display_state_digest = member_display_state_digest;
                        }
                        if existing.subject_id.is_none() {
                            existing.subject_id = subject_id;
                        }
                        if existing.handle_claims.is_empty() {
                            existing.handle_claims = handle_claims;
                        }
                        existing.handle_claims_limited |= handle_claims_limited;
                    }
                }
            }
        }
        _ => {}
    }
}

#[cfg(test)]
#[derive(Clone, Debug, Default, PartialEq)]
pub(super) struct RealmRosterPagination {
    pub members_limited: bool,
    pub members_next_cursor: Option<String>,
}

#[cfg(test)]
impl RealmRosterPagination {
    pub fn from_projection(projection: Option<&Value>) -> Self {
        let Some(root) = projection else {
            return Self::default();
        };
        let limited = root
            .get("members_limited")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let cursor = root
            .get("members_next_cursor")
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(ToOwned::to_owned);
        Self {
            members_limited: limited,
            members_next_cursor: cursor,
        }
    }
}

/// Collect a deduped list of actor DIDs that have authored *any*
/// queued / accepted raw operation that targets the given strand id
/// (matched against `target_ref`, `strand_id`, or `object.id`). This
/// gives the "who's interacted with this Strand" list shown on the
/// sidebar's Participants tab even before the server returns a
/// canonical discussion-roster projection.
pub(super) fn strand_participant_dids(
    raw_operations: &[RawOperationRecord],
    strand_id: &str,
) -> Vec<String> {
    let strand_id = strand_id.trim();
    if strand_id.is_empty() {
        return Vec::new();
    }
    let mut dids: BTreeSet<String> = BTreeSet::new();
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
        for path in [
            // Read canonical `actor_id` / `sender_actor_id` only; forbidden
            // `sender` / `author` / `created_by` keys are not accepted.
            &["body", "actor_id"][..],
            &["body", "sender_actor_id"][..],
            &["payload", "actor_id"][..],
            &["actor_id"][..],
        ] {
            if let Some(did) = json_path_string(Some(payload), path) {
                dids.insert(did);
            }
        }
    }
    let mut out: Vec<String> = dids.into_iter().collect();
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
    display_name_for_did(state_store, actor_id)
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
    let identity = state_store.resolved_member_identity(realm_id, &row.actor_id);
    let cached_handle =
        member_handle_lookup_subject(row, identity.as_ref()).and_then(|subject_id| {
            state_store
                .cached_member_handle_lookup(
                    &subject_id,
                    Some(realm_id),
                    row.member_display_state_digest.as_deref(),
                )
                .and_then(|entry| entry.primary_handle)
        });
    Some(member_display_label(
        row,
        identity.as_ref(),
        cached_handle.as_deref(),
    ))
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
        .unwrap_or_else(|| display_name_for_did(state_store, actor_id))
}

pub(super) fn assignee_avatar_initial(label: &str) -> String {
    label
        .chars()
        .find(|ch| ch.is_alphanumeric())
        .map(|ch| ch.to_uppercase().collect::<String>())
        .unwrap_or_else(|| "?".to_owned())
}

pub(super) fn assignee_filter_matches(filter: &str, label: &str, actor_id: &str) -> bool {
    let filter = filter.trim().to_lowercase();
    if filter.is_empty() {
        return true;
    }
    label.to_lowercase().contains(&filter) || actor_id.to_lowercase().contains(&filter)
}
