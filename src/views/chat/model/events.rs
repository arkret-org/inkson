use std::collections::BTreeMap;

use arkret_wire::event_kind_str;

use super::*;
#[cfg(test)]
pub(crate) use crate::state::projection::message_ops::message_operations_from_events;
// The message-candidate walkers + raw-operation
// extraction moved to `crate::state::projection::message_ops` (they are the sync
// engine's ingest step, not chat rendering). Re-exported so every existing
// chat-model consumer keeps resolving through this module.
pub(crate) use crate::state::projection::message_ops::{
    actor_principal_from_value, first_string_in_candidates, message_actor_from_candidates,
    message_candidates, message_kind_is_create, message_kind_is_revise, value_string_at,
};

pub(crate) fn chat_reply_quote_preview(
    messages: &[ChatMessage],
    reply_id: &str,
    principal_id: &str,
    account_display_name: &str,
    participants: &[SpaceParticipant],
) -> Option<(String, String)> {
    let quoted = messages.iter().find(|m| m.id == reply_id)?;
    let name = sender_display_label(
        &quoted.sender,
        principal_id,
        account_display_name,
        participants,
    );
    let body = if quoted.redacted {
        "[Message redacted]".to_owned()
    } else {
        quoted.body.clone()
    };
    Some((name, body))
}

pub(crate) fn watch_level_label_key(level: WatchLevel) -> &'static str {
    match level {
        WatchLevel::MentionsOnly => "chat.watch_level.mentions_only",
        WatchLevel::Participating => "chat.watch_level.participating",
        WatchLevel::All => "chat.watch_level.all",
        WatchLevel::Muted => "chat.watch_level.muted",
    }
}

pub(crate) fn watch_level_wire_value(level: WatchLevel) -> &'static str {
    level.as_wire()
}

#[cfg(test)]
pub(crate) fn watch_level_from_wire(value: &str) -> WatchLevel {
    if value == "none" {
        WatchLevel::Muted
    } else {
        WatchLevel::from_wire(value).unwrap_or(WatchLevel::All)
    }
}

/// Detect the per-message redaction tombstone surfaced by soland on the sync
/// timeline (spec strand-and-message.md §9). The server folds a redacted
/// `ak.message.create` into a tombstone form carrying `redacted: true` /
/// `state: "redacted"`, so a receiver rebuilding the timeline renders the
/// tombstone instead of either dropping the row or leaking the plaintext.
pub(crate) fn message_is_redaction_tombstone(candidates: &[&Value]) -> bool {
    candidates.iter().any(|candidate| {
        candidate.get("redacted").and_then(Value::as_bool) == Some(true)
            || value_string_at(candidate, &["state"]) == Some("redacted")
    })
}

pub(crate) fn local_redaction_tombstone_for_message(
    message: &ChatMessage,
    redacted_at: chrono::DateTime<chrono::Utc>,
    redaction_ref: Option<&str>,
) -> Value {
    let actor_id = message.actor_id.clone();
    let mut event = json!({
        "kind": event_kind_str::MESSAGE_CREATE,
        "event_id": message.id.clone(),
        "realm_id": message.realm_id.clone(),
        "strand_id": message.strand_id.clone(),
        "actor_id": actor_id,
        "created_at": arkret_sdk::canonical::format_timestamp_canonical(redacted_at),
    });
    if let Some(message_id) = message
        .protocol_message_id
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        && let Some(object) = event.as_object_mut()
    {
        object.insert(
            "message_id".to_owned(),
            Value::String(message_id.to_owned()),
        );
    }
    arkret_sdk::events::redaction_tombstone_message_value(&mut event, redacted_at, redaction_ref);
    event
}

#[derive(Clone, Debug)]
struct MessageRedactionMarker {
    target_ref: String,
    redacted_at: chrono::DateTime<chrono::Utc>,
    redaction_ref: Option<String>,
}

fn redaction_payload_candidate(event: &Value) -> &Value {
    event
        .get("payload")
        .or_else(|| event.get("content"))
        .or_else(|| event.get("body"))
        .unwrap_or(event)
}

fn message_redaction_marker_from_event(event: &Value) -> Option<MessageRedactionMarker> {
    let candidates = message_candidates(event);
    let kind = candidates
        .iter()
        .find_map(|candidate| value_string_at(candidate, &["kind", "event_kind", "type"]))?;
    if kind != event_kind_str::MESSAGE_REDACT && kind != event_kind_str::REDACTION {
        return None;
    }
    let payload = redaction_payload_candidate(event);
    // Each redaction payload class registers exactly one target carrier:
    // `message_redact_payload.message_id` and
    // `cross_object_redaction_payload.target_ref`. The two member names are
    // disjoint, so this is a per-kind lookup, not a fallback chain.
    let target_ref = ["message_id", "target_ref"]
        .into_iter()
        .find_map(|key| payload.get(key).and_then(Value::as_str))
        .map(str::trim)
        .filter(|value| {
            !value.is_empty()
                && (value.starts_with("ak:event:") || value.starts_with("ak:message:"))
        })?
        .to_owned();
    let redaction_ref = value_string_at(event, &["event_id", "id"])
        .or_else(|| value_string_at(payload, &["event_id", "id"]))
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned);
    let redacted_at = first_string_in_candidates(&candidates, &["created_at"])
        .and_then(|created_at| chrono::DateTime::parse_from_rfc3339(created_at).ok())
        .map(|timestamp| timestamp.with_timezone(&chrono::Utc))
        .unwrap_or_else(chrono::Utc::now);
    Some(MessageRedactionMarker {
        target_ref,
        redacted_at,
        redaction_ref,
    })
}

fn redaction_targets_message(marker: &MessageRedactionMarker, message: &ChatMessage) -> bool {
    marker.target_ref == message.id
        || message
            .protocol_message_id
            .as_deref()
            .is_some_and(|message_id| marker.target_ref == message_id)
}

fn apply_redaction_marker_to_message(message: &mut ChatMessage, marker: &MessageRedactionMarker) {
    let tombstone = local_redaction_tombstone_for_message(
        message,
        marker.redacted_at,
        marker.redaction_ref.as_deref(),
    );
    if let Some(redacted) = chat_message_from_event(&message.realm_id, &tombstone) {
        *message = redacted;
    } else {
        message.body.clear();
        message.redacted = true;
        message.reactions.clear();
        message.mentions.clear();
        message.crypto_state = MessageCryptoState::Plaintext;
    }
}

fn apply_message_redactions(messages: &mut [ChatMessage], events: &[Value]) {
    let redactions = events
        .iter()
        .filter_map(message_redaction_marker_from_event)
        .collect::<Vec<_>>();
    if redactions.is_empty() {
        return;
    }
    for message in messages {
        if let Some(marker) = redactions
            .iter()
            .find(|marker| redaction_targets_message(marker, message))
        {
            apply_redaction_marker_to_message(message, marker);
        }
    }
}

fn push_reaction_member(reactions: &mut Vec<(String, Vec<String>)>, key: &str, actor: &str) {
    let key = key.trim();
    let actor = actor.trim();
    if key.is_empty() || actor.is_empty() {
        return;
    }
    if let Some((_, senders)) = reactions.iter_mut().find(|(existing, _)| existing == key) {
        if !senders.iter().any(|existing| existing == actor) {
            senders.push(actor.to_owned());
        }
    } else {
        reactions.push((key.to_owned(), vec![actor.to_owned()]));
    }
}

fn remove_reaction_member(reactions: &mut Vec<(String, Vec<String>)>, key: &str, actor: &str) {
    let key = key.trim();
    let actor = actor.trim();
    if key.is_empty() || actor.is_empty() {
        return;
    }
    if let Some((_, senders)) = reactions.iter_mut().find(|(existing, _)| existing == key) {
        senders.retain(|existing| existing != actor);
    }
    reactions.retain(|(_, senders)| !senders.is_empty());
}

fn sort_reactions(reactions: &mut Vec<(String, Vec<String>)>) {
    for (_, senders) in reactions.iter_mut() {
        senders.sort();
        senders.dedup();
    }
    reactions.retain(|(_, senders)| !senders.is_empty());
    reactions.sort_by(|left, right| left.0.cmp(&right.0));
}

fn reaction_actor_from_value(value: &Value) -> Option<String> {
    value
        .as_str()
        .map(ToOwned::to_owned)
        .or_else(|| value.get("actor_id").and_then(actor_principal_from_value))
}

fn push_reaction_summary_value(reactions: &mut Vec<(String, Vec<String>)>, value: &Value) {
    if let Some(object) = value.as_object() {
        for (key, members_value) in object {
            let members = members_value
                .as_array()
                .or_else(|| members_value.get("members").and_then(Value::as_array));
            let Some(members) = members else {
                continue;
            };
            for member in members {
                if let Some(actor) = reaction_actor_from_value(member) {
                    push_reaction_member(reactions, key, &actor);
                }
            }
        }
        return;
    }

    if let Some(items) = value.as_array() {
        for item in items {
            let Some(key) = value_string_at(item, &["key", "reaction", "reaction_key"]) else {
                continue;
            };
            let Some(members) = item.get("members").and_then(Value::as_array) else {
                continue;
            };
            for member in members {
                if let Some(actor) = reaction_actor_from_value(member) {
                    push_reaction_member(reactions, key, &actor);
                }
            }
        }
    }
}

fn push_reaction_list_value(reactions: &mut Vec<(String, Vec<String>)>, value: &Value) {
    let Some(items) = value.as_array() else {
        return;
    };
    for item in items {
        if item.get("active").and_then(Value::as_bool) == Some(false) {
            continue;
        }
        let Some(key) = value_string_at(item, &["key", "reaction", "reaction_key"]) else {
            continue;
        };
        let Some(actor) = value_string_at(item, &["actor_id"]) else {
            continue;
        };
        push_reaction_member(reactions, key, actor);
    }
}

fn reactions_from_candidates(candidates: &[&Value]) -> Vec<(String, Vec<String>)> {
    let mut reactions = Vec::new();
    for candidate in candidates {
        if let Some(summary) = candidate.get("reaction_summary") {
            push_reaction_summary_value(&mut reactions, summary);
        }
        if let Some(items) = candidate.get("reactions") {
            push_reaction_list_value(&mut reactions, items);
        }
    }
    sort_reactions(&mut reactions);
    reactions
}

#[derive(Clone, Debug)]
struct ReactionMarker {
    target_ref: String,
    key: String,
    actor: String,
    active: bool,
}

fn reaction_marker_from_event(event: &Value) -> Option<ReactionMarker> {
    let candidates = message_candidates(event);
    let kind = candidates
        .iter()
        .find_map(|candidate| value_string_at(candidate, &["kind", "event_kind", "type"]))?;
    let active = match kind {
        event_kind_str::REACTION_ADD => true,
        event_kind_str::REACTION_REMOVE => false,
        _ => return None,
    };
    let target_ref = first_string_in_candidates(
        &candidates,
        &[
            "target_ref",
            "target_event_id",
            "target",
            "target_message_id",
        ],
    )?
    .trim();
    if target_ref.is_empty() {
        return None;
    }
    let key = first_string_in_candidates(&candidates, &["key", "reaction", "reaction_key"])?.trim();
    if key.is_empty() {
        return None;
    }
    let actor = message_actor_from_candidates(&candidates)?;
    if actor.trim().is_empty() {
        return None;
    }
    Some(ReactionMarker {
        target_ref: target_ref.to_owned(),
        key: key.to_owned(),
        actor,
        active,
    })
}

fn apply_reaction_marker_to_messages(messages: &mut [ChatMessage], marker: &ReactionMarker) {
    let Some(message) = messages
        .iter_mut()
        .find(|message| message_matches_target_ref(message, &marker.target_ref))
    else {
        return;
    };
    if message.redacted {
        return;
    }
    if marker.active {
        push_reaction_member(&mut message.reactions, &marker.key, &marker.actor);
    } else {
        remove_reaction_member(&mut message.reactions, &marker.key, &marker.actor);
    }
    sort_reactions(&mut message.reactions);
}

fn apply_reaction_markers(messages: &mut [ChatMessage], events: &[Value]) {
    for marker in events.iter().filter_map(reaction_marker_from_event) {
        apply_reaction_marker_to_messages(messages, &marker);
    }
}

fn message_revision_target_ref_from_candidates(candidates: &[&Value]) -> Option<String> {
    candidates
        .iter()
        .find(|candidate| message_kind_is_revise(candidate))
        .and_then(|_| {
            candidates.iter().find_map(|candidate| {
                value_string_at(
                    candidate,
                    &["target_ref", "target_event_id", "message_id", "revision_of"],
                )
            })
        })
        .map(str::trim)
        .filter(|value| {
            !value.is_empty()
                && (value.starts_with("ak:event:") || value.starts_with("ak:message:"))
        })
        .map(ToOwned::to_owned)
}

fn message_ref_equivalents(value: &str) -> [String; 2] {
    let trimmed = value.trim();
    let alternate = if let Ok(event_id) = arkret_sdk::EventId::new(trimmed.to_owned()) {
        arkret_sdk::MessageId::from_event_id(&event_id).to_string()
    } else if let Ok(message_id) = arkret_sdk::MessageId::new(trimmed.to_owned()) {
        message_id.event_id().to_string()
    } else {
        trimmed.to_owned()
    };
    [trimmed.to_owned(), alternate]
}

fn message_matches_target_ref(message: &ChatMessage, target_ref: &str) -> bool {
    let refs = message_ref_equivalents(target_ref);
    refs.iter().any(|candidate| {
        candidate == &message.id
            || message
                .protocol_message_id
                .as_deref()
                .is_some_and(|message_id| candidate == message_id)
    })
}

fn append_revision_body(message: &mut ChatMessage, body: String) {
    if body.is_empty() || body == message.body {
        return;
    }
    if message.revisions.last().is_none_or(|last| last != &body)
        && !message.revisions.iter().any(|existing| existing == &body)
    {
        message.revisions.push(body);
    }
}

fn fold_revision_message_into(message: &mut ChatMessage, revision: ChatMessage) {
    let revision_created_at = revision.created_at;
    if revision.redacted {
        message.redacted = true;
        message.body.clear();
        message.content_format = None;
        message.reactions.clear();
        message.mentions.clear();
        message.crypto_state = MessageCryptoState::Plaintext;
    } else {
        let previous = std::mem::replace(&mut message.body, revision.body);
        message.content_format = revision.content_format;
        append_revision_body(message, previous);
    }
    message.edited = true;
    message.timestamp = revision.timestamp;
    message.pending = revision.pending;
    message.failed = revision.failed;
    message.error = revision.error;
    message.crypto_state = revision.crypto_state;
    if revision_created_at.is_some() {
        message.created_at = revision_created_at;
    }
}

fn message_created_at_from_candidates(
    candidates: &[&Value],
) -> Option<chrono::DateTime<chrono::Utc>> {
    first_string_in_candidates(candidates, &["created_at"])
        .and_then(|created_at| chrono::DateTime::parse_from_rfc3339(created_at).ok())
        .map(|timestamp| timestamp.with_timezone(&chrono::Utc))
}

fn message_protocol_message_id_from_candidates(candidates: &[&Value]) -> Option<String> {
    if let Some(message_id) = candidates
        .iter()
        .filter(|candidate| message_kind_is_create(candidate))
        .find_map(|candidate| value_string_at(candidate, &["event_id", "id"]))
        .and_then(|event_id| arkret_sdk::EventId::new(event_id.to_owned()).ok())
        .map(|event_id| arkret_sdk::MessageId::from_event_id(&event_id))
    {
        return Some(message_id.as_str().to_owned());
    }
    if let Some(message_id) = candidates
        .iter()
        .filter(|candidate| message_kind_is_revise(candidate))
        .find_map(|candidate| {
            candidate
                .get("payload")
                .filter(|payload| payload.is_object())
                .and_then(|payload| value_string_at(payload, &["message_id"]))
        })
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        return Some(message_id.to_owned());
    }
    candidates
        .iter()
        .rev()
        .find_map(|candidate| value_string_at(candidate, &["message_id"]))
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

fn message_protocol_ids_match(left: &ChatMessage, right: &ChatMessage) -> bool {
    let Some(left_id) = left
        .protocol_message_id
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        return false;
    };
    right
        .protocol_message_id
        .as_deref()
        .map(str::trim)
        .is_some_and(|right_id| right_id == left_id)
}

fn carry_create_metadata(target: &mut ChatMessage, source: &ChatMessage) {
    if target.reply_to.is_none() {
        target.reply_to = source.reply_to.clone();
    }
    if target.protocol_message_id.is_none() {
        target.protocol_message_id = source.protocol_message_id.clone();
    }
    if target.revision_source.is_none() {
        target.revision_source = source.revision_source.clone();
    }
}

fn merge_reactions_into(target: &mut ChatMessage, source: &ChatMessage) {
    if target.redacted {
        return;
    }
    for (key, senders) in &source.reactions {
        for sender in senders {
            push_reaction_member(&mut target.reactions, key, sender);
        }
    }
    sort_reactions(&mut target.reactions);
}

/// Canonical duplicate-`create` merge for a matched pair of chat messages.
///
/// Single source of truth for folding a re-projected or late-arriving
/// `create`/tombstone into the copy already rendered. Both projection paths
/// call it: `push_or_merge_create_message` (event-list projection, matched by
/// protocol message id) and `strands::merge_chat_messages` (list-vs-list
/// merge, matched by event id or protocol id). The former
/// `strands::replace_chat_message_preserving_local_metadata` twin was folded
/// in here; its extra `created_at` carry-forward is preserved below.
///
/// Newer-vs-same is decided by `is_newer_or_same_lifecycle_version_than`
/// (`>=` on the same-version id tie-break), so an incoming message at the same
/// lifecycle version replaces the row while carrying existing local metadata
/// forward.
pub(crate) fn merge_duplicate_create_message(
    existing: &mut ChatMessage,
    mut incoming: ChatMessage,
) {
    let incoming_is_settled = !incoming.pending && !incoming.failed;
    if existing.redacted && !incoming.redacted {
        carry_create_metadata(existing, &incoming);
        append_revision_body(existing, incoming.body);
        return;
    }
    let incoming_is_strictly_newer =
        match (incoming.created_at.as_ref(), existing.created_at.as_ref()) {
            (Some(incoming_at), Some(existing_at)) => incoming_at > existing_at,
            (Some(_), None) => true,
            _ => false,
        };
    let existing_has_newer_local_revisions = !incoming_is_strictly_newer
        && existing.edited
        && existing.revisions.len() > incoming.revisions.len();
    if incoming.redacted
        || (incoming.is_newer_or_same_lifecycle_version_than(existing)
            && !existing_has_newer_local_revisions)
    {
        carry_create_metadata(&mut incoming, existing);
        // An echo / re-projection that could not recover the plaintext
        // (author sidecar not yet visible, group key not yet available)
        // arrives with an empty body. Never blank out a body the local copy
        // already rendered; only a redaction tombstone (handled above) may
        // remove content. Restoring before `append_revision_body` keeps the
        // carried body out of the edit history.
        if incoming.body.is_empty() && !existing.body.is_empty() {
            incoming.body = existing.body.clone();
            incoming.content_format = existing.content_format;
        }
        // Carry forward locally-tracked edit metadata. The sync projection
        // rebuilds a message from its events but does not surface the
        // per-message revision count, so a re-projection would otherwise wipe
        // the write-status counter the moment a sync tick lands between two
        // edits. Preserve the existing `edited` flag and revision history (the
        // body still updates to the incoming/revised content) so the numeric
        // counter is stable across re-projections.
        if !incoming.edited && existing.edited {
            incoming.edited = true;
        }
        if incoming.revisions.is_empty() && !existing.revisions.is_empty() {
            incoming.revisions = std::mem::take(&mut existing.revisions);
        }
        append_revision_body(&mut incoming, existing.body.clone());
        if incoming.created_at.is_none() {
            incoming.created_at = existing.created_at;
        }
        merge_reactions_into(&mut incoming, existing);
        *existing = incoming;
    } else {
        carry_create_metadata(existing, &incoming);
        if incoming_is_settled {
            existing.pending = false;
            existing.failed = false;
            existing.error = None;
        }
        if incoming.edited {
            existing.edited = true;
        }
        if existing.created_at.is_none() {
            existing.created_at = incoming.created_at;
        }
        merge_reactions_into(existing, &incoming);
        for revision in incoming.revisions {
            append_revision_body(existing, revision);
        }
        append_revision_body(existing, incoming.body);
    }
}

fn push_or_merge_create_message(messages: &mut Vec<ChatMessage>, message: ChatMessage) {
    if let Some(index) = messages
        .iter()
        .position(|existing| message_protocol_ids_match(existing, &message))
    {
        merge_duplicate_create_message(&mut messages[index], message);
    } else {
        messages.push(message);
    }
}

fn chat_messages_from_event_list_with_sidecar(
    realm_id: &str,
    events: &[Value],
    state_store: Option<&LocalStateStore>,
    decrypt_identity: Option<(&arkret_sdk::AccountId, &str, &arkret_sdk::DeviceId)>,
) -> Vec<ChatMessage> {
    fold_event_list_into_chat_messages(Vec::new(), realm_id, events, state_store, decrypt_identity)
}

fn canonical_message_revision_target(target_ref: &str) -> String {
    let [direct, alternate] = message_ref_equivalents(target_ref);
    if direct.starts_with("ak:message:") {
        direct
    } else {
        alternate
    }
}

fn revision_event_id(revision: &ChatMessage) -> Option<arkret_sdk::EventId> {
    arkret_sdk::EventId::new(revision.id.clone()).ok()
}

/// Apply a message's accepted revisions to its row.
///
/// A message revision is one typed target updated in Commit order
/// (`authz/event-auth-state-resolution.md` section 6), so the last accepted
/// revision this client folded is the displayed value. Earlier revisions are
/// still applied first, so fields only the older revision wrote survive, and
/// they are never presented as a second current value.
fn fold_revision_group(
    messages: &mut [ChatMessage],
    target_ref: &str,
    revisions: Vec<ChatMessage>,
) -> bool {
    let Some(winner_id) = revisions.last().and_then(revision_event_id) else {
        return false;
    };
    let Some(index) = messages
        .iter()
        .position(|message| message_matches_target_ref(message, target_ref))
    else {
        return false;
    };
    for revision in revisions {
        fold_revision_message_into(&mut messages[index], revision);
    }
    messages[index].revision_source = Some(winner_id.event_digest());
    true
}

/// Ordinary chat projection only consumes a proof-verified Event whose signed
/// scope is this Realm or one of its Circles. A native Sidecar Event may name
/// the same source Strand in its payload, but that does not authorize an echo
/// into the shared timeline. Missing proof/scope stays out of this fold.
fn verified_ordinary_chat_event_scope(
    realm_id: &str,
    event: &Value,
    state_store: Option<&LocalStateStore>,
    decrypt_identity: Option<(&arkret_sdk::AccountId, &str, &arkret_sdk::DeviceId)>,
) -> bool {
    let Some(envelope) = message_candidates(event).into_iter().find(|candidate| {
        candidate
            .get("producer_proof")
            .and_then(Value::as_object)
            .is_some()
            && candidate
                .get("actor_id")
                .and_then(actor_principal_from_value)
                .is_some_and(|actor| !actor.trim().is_empty())
    }) else {
        return false;
    };
    let Some(signed_realm_id) = envelope.get("realm_id").and_then(Value::as_str) else {
        return false;
    };
    if !realm_id.is_empty() && realm_id != signed_realm_id {
        return false;
    }
    if verify_chat_envelope_proof_for_realm(signed_realm_id, event, state_store, decrypt_identity)
        != ChatProofVerdict::Verified
    {
        return false;
    }
    let Some(scope) = envelope
        .get("scope_ref")
        .and_then(|value| serde_json::from_value::<arkret_sdk::ScopeRef>(value.clone()).ok())
    else {
        return false;
    };
    match scope {
        arkret_sdk::ScopeRef::Realm {
            realm_id: scope_realm_id,
        }
        | arkret_sdk::ScopeRef::Circle {
            realm_id: scope_realm_id,
            ..
        } => scope_realm_id.as_str() == signed_realm_id,
        arkret_sdk::ScopeRef::Sidecar { .. } | arkret_sdk::ScopeRef::RealmGenesis => false,
        _ => false,
    }
}

/// An unverified tombstone cannot be rendered as an attributed row. Its only
/// safe local effect is to suppress an exact already-visible target, never to
/// replace content or assert a new revision.
fn unverified_tombstone_suppression_target(
    expected_realm_id: &str,
    event: &Value,
) -> Option<(String, String)> {
    let candidates = message_candidates(event);
    if !message_is_redaction_tombstone(&candidates) {
        return None;
    }
    let realm_id = event
        .get("realm_id")
        .and_then(Value::as_str)
        .or_else(|| first_string_in_candidates(&candidates, &["realm_id"]))?;
    arkret_sdk::RealmId::new(realm_id.to_owned()).ok()?;
    if !expected_realm_id.is_empty() && expected_realm_id != realm_id {
        return None;
    }
    // A local redaction replacement can retain the original event_id while
    // carrying a distinct protocol message_id. That explicit typed target
    // must win over the create-id derivation or the old body remains visible.
    let target = candidates
        .iter()
        .find_map(|candidate| candidate.get("message_id").and_then(Value::as_str))
        .or_else(|| {
            event
                .pointer("/unsigned/local_target_ref")
                .and_then(Value::as_str)
        })
        .map(ToOwned::to_owned)
        .or_else(|| message_protocol_message_id_from_candidates(&candidates))?;
    let target = arkret_sdk::MessageId::new(target).ok()?;
    Some((realm_id.to_owned(), target.to_string()))
}

fn fold_event_list_into_chat_messages(
    mut messages: Vec<ChatMessage>,
    realm_id: &str,
    events: &[Value],
    state_store: Option<&LocalStateStore>,
    decrypt_identity: Option<(&arkret_sdk::AccountId, &str, &arkret_sdk::DeviceId)>,
) -> Vec<ChatMessage> {
    let mut ordinary_events = Vec::new();
    let mut suppressed_targets = std::collections::BTreeSet::new();
    for event in events {
        if verified_ordinary_chat_event_scope(realm_id, event, state_store, decrypt_identity) {
            ordinary_events.push(event.clone());
        } else if let Some(target) = unverified_tombstone_suppression_target(realm_id, event) {
            suppressed_targets.insert(target);
        }
    }
    let mut durable_messages = Vec::new();
    let mut pending_revisions = BTreeMap::<String, Vec<ChatMessage>>::new();
    for event in &ordinary_events {
        let candidates = message_candidates(event);
        let revision_target_ref = message_revision_target_ref_from_candidates(&candidates);
        let Some(message) =
            chat_message_from_event_with_sidecar(realm_id, event, state_store, decrypt_identity)
        else {
            continue;
        };
        if let Some(target_ref) = revision_target_ref {
            pending_revisions
                .entry(canonical_message_revision_target(&target_ref))
                .or_default()
                .push(message);
            continue;
        }
        push_or_merge_create_message(&mut durable_messages, message);
    }
    pending_revisions.retain(|target_ref, revisions| {
        !fold_revision_group(&mut durable_messages, target_ref, std::mem::take(revisions))
    });
    merge_chat_messages(&mut messages, durable_messages);
    for (target_ref, revisions) in pending_revisions {
        if !fold_revision_group(&mut messages, &target_ref, revisions.clone())
            && let Some(revision) = revisions.into_iter().find(|revision| revision.redacted)
        {
            // Account sync projects one logical row per message_id. When the
            // latest row is a server-folded redacted revision, its original
            // create may therefore be absent from this batch. The tombstone is
            // still self-contained and must survive as the message's durable
            // row; a later create/backfill copy will dedupe by protocol id.
            push_or_merge_create_message(&mut messages, revision);
        }
    }
    apply_message_redactions(&mut messages, &ordinary_events);
    apply_reaction_markers(&mut messages, &ordinary_events);
    messages.retain(|message| {
        let target_ref = message
            .protocol_message_id
            .as_deref()
            .unwrap_or(&message.id);
        !suppressed_targets.contains(&(
            message.realm_id.clone(),
            canonical_message_revision_target(target_ref),
        ))
    });
    messages
}

pub(crate) fn text_from_parts(value: &Value) -> Option<&str> {
    value
        .get("parts")
        .and_then(Value::as_array)
        .and_then(|parts| parts.first())
        .and_then(text_body_from_value)
}

pub(crate) fn text_body_from_value(value: &Value) -> Option<&str> {
    value_string_at(value, &["body", "text", "message", "plain_text"])
        .or_else(|| text_from_parts(value))
        .or_else(|| {
            value
                .get("content")
                .filter(|content| content.is_object())
                .and_then(text_body_from_value)
        })
}

fn long_text_marker_from_value(value: &Value) -> Option<String> {
    if value.get("kind").and_then(Value::as_str) == Some(arkret_sdk::CONTENT_KIND_LONG_TEXT) {
        return crate::content::encode_long_text_marker(
            value.get("blob_ref")?.as_str()?,
            value.get("body")?.as_str()?,
            arkret_sdk::ContentBlock::from_value(value.clone())
                .ok()?
                .long_text_media_type()?
                .text_format()
                .as_str(),
        );
    }
    value
        .get("parts")
        .and_then(Value::as_array)
        .and_then(|parts| parts.iter().find_map(long_text_marker_from_value))
        .or_else(|| {
            value
                .get("content")
                .filter(|content| content.is_object())
                .and_then(long_text_marker_from_value)
        })
}

fn display_body_from_value(value: &Value) -> Option<String> {
    long_text_marker_from_value(value)
        .or_else(|| text_body_from_value(value).map(ToOwned::to_owned))
}

pub(crate) fn content_format_from_value(value: &Value) -> Option<arkret_sdk::TextFormat> {
    match value.get("kind").and_then(Value::as_str) {
        Some(arkret_sdk::CONTENT_KIND_TEXT) => value
            .get("format")
            .and_then(Value::as_str)
            .and_then(arkret_sdk::TextFormat::parse),
        Some(arkret_sdk::CONTENT_KIND_LONG_TEXT) => {
            arkret_sdk::ContentBlock::from_value(value.clone())
                .ok()?
                .long_text_media_type()
                .map(arkret_sdk::LongTextMediaType::text_format)
        }
        _ => value
            .get("parts")
            .and_then(Value::as_array)
            .and_then(|parts| parts.iter().find_map(content_format_from_value))
            .or_else(|| value.get("content").and_then(content_format_from_value)),
    }
}

pub(super) fn content_from_private_sidecar(
    value: String,
) -> (String, Option<arkret_sdk::TextFormat>) {
    serde_json::from_str::<Value>(&value)
        .ok()
        .filter(|content| {
            content
                .get("kind")
                .and_then(Value::as_str)
                .is_some_and(|kind| kind.starts_with("ak.content."))
        })
        .and_then(|content| {
            display_body_from_value(&content)
                .map(|body| (body, content_format_from_value(&content)))
        })
        .unwrap_or((value, None))
}

pub(crate) fn text_body_from_message(candidates: &[&Value]) -> Option<String> {
    candidates
        .iter()
        .find_map(|candidate| display_body_from_value(candidate))
}

pub(crate) fn short_message_time(value: Option<&str>) -> String {
    value
        .and_then(|raw| chrono::DateTime::parse_from_rfc3339(raw).ok())
        .map(|time| time.format("%H:%M").to_string())
        .or_else(|| value.map(ToOwned::to_owned))
        .unwrap_or_default()
}

pub(crate) fn mentions_from_value(value: &Value) -> Vec<MentionNode> {
    value
        .as_array()
        .map(|items| {
            items
                .iter()
                .filter_map(|item| serde_json::from_value::<MentionNode>(item.clone()).ok())
                .collect()
        })
        .unwrap_or_default()
}

pub(crate) fn mentions_from_candidates(candidates: &[&Value]) -> Vec<MentionNode> {
    for candidate in candidates {
        let mut mentions = Vec::new();
        for key in ["mentions", "audience_mentions"] {
            if let Some(value) = candidate.get(key).or_else(|| {
                candidate
                    .get("content")
                    .and_then(|content| content.get(key))
            }) {
                mentions.extend(mentions_from_value(value));
            }
        }
        if !mentions.is_empty() {
            return mentions;
        }
    }
    Vec::new()
}

pub(crate) fn chat_message_from_event(realm_id: &str, event: &Value) -> Option<ChatMessage> {
    chat_message_from_event_with_sidecar(realm_id, event, None, None)
}

fn decrypt_chat_encrypted_content_value(
    state_store: &LocalStateStore,
    realm_id: &str,
    authority: &arkret_sdk::AccountId,
    device_id: &arkret_sdk::DeviceId,
    effective_scope: Option<&arkret_sdk::ScopeRef>,
    encrypted_content: &Value,
    verified_sender_domain: Option<&[u8]>,
) -> Option<Value> {
    let envelope =
        serde_json::from_value::<arkret_sdk::EncryptedEnvelope>(encrypted_content.clone()).ok()?;
    let realm_scope;
    let effective_scope = match effective_scope {
        Some(scope) => scope,
        None => {
            realm_scope = arkret_sdk::ScopeRef::Realm {
                realm_id: arkret_sdk::RealmId::new(realm_id.to_owned()).ok()?,
            };
            &realm_scope
        }
    };
    let verified_sender_domain = verified_sender_domain.or_else(|| {
        crate::mls::runtime::warn_mls_decrypt_once(
            realm_id,
            &arkret_sdk::canonical::sha256_digest(envelope.ciphertext.as_bytes()),
            envelope.encryption_context.epoch(),
            None,
            "verified sender device domain is unavailable",
        );
        None
    })?;
    let payload = crate::mls::runtime::encrypted_payload_from_verified_event_context(
        state_store,
        &envelope,
        effective_scope,
        arkret_wire::event_kind_str::MESSAGE_CREATE,
        verified_sender_domain,
        None,
    )?;
    let secure_store = crate::secure_key_store::default_secure_key_store("inkson");
    let plaintext =
        crate::mls::runtime::decrypt_application_payload_for_scope_from_verified_sender(
            state_store,
            secure_store.as_ref(),
            realm_id,
            authority,
            device_id,
            &payload,
            effective_scope,
            verified_sender_domain,
        )?;
    serde_json::from_slice::<Value>(&plaintext).ok()
}

/// Find the proof-bearing Event layer of a committed chat row and check its
/// `producer_proof` without resolving any signing key.
///
/// The row is a committed Event read from this account's own Station, whose
/// stream verification already bound it to the governance `RealmCommit`. The
/// governance Station judged the producer device authorization when it
/// admitted the Event, so the client only checks that the proof is
/// self-consistent (`server-trusted-results.md` §2, `federation.md` §3): the
/// digest covers the exact canonical Event bytes, the verification method
/// projects to the actual signer and a human device fragment is a complete
/// device id. A human-device producer is then [`ChatProofVerdict::Verified`];
/// other producers keep their own evidence rule and stay
/// [`ChatProofVerdict::Unresolved`] here.
pub(crate) fn verify_committed_chat_producer_proof(event: &Value) -> ChatProofVerdict {
    let candidates = message_candidates(event);
    let proof_bearing = candidates.iter().copied().find(|candidate| {
        candidate
            .get("producer_proof")
            .and_then(Value::as_object)
            .is_some()
            && candidate
                .get("actor_id")
                .and_then(actor_principal_from_value)
                .is_some_and(|actor| !actor.trim().is_empty())
    });
    let Some(envelope) = proof_bearing else {
        // An attributed row that ships no proof asserts a sender it cannot
        // back, so it never renders as trusted plaintext. Only a wholly
        // unattributed (system) row is Unattributed.
        let attributed = candidates.iter().copied().any(|candidate| {
            candidate
                .get("actor_id")
                .and_then(actor_principal_from_value)
                .is_some_and(|actor| !actor.trim().is_empty())
        });
        return if attributed {
            ChatProofVerdict::Rejected
        } else {
            ChatProofVerdict::Unattributed
        };
    };
    match committed_human_device_producer(envelope) {
        Ok(Some(_)) => ChatProofVerdict::Verified,
        Ok(None) => ChatProofVerdict::Unresolved,
        Err(()) => ChatProofVerdict::Rejected,
    }
}

/// The human-device producer of one exact committed Event, after the key-free
/// self-consistency check under the Realm's digest suite.
fn committed_human_device_producer(
    envelope: &Value,
) -> Result<Option<arkret_wire::HumanDeviceProducer>, ()> {
    let event = serde_json::from_value::<arkret_sdk::Event>(envelope.clone()).map_err(|_| ())?;
    let digest_suite = event.realm_id.digest_suite_code().digest_suite();
    event
        .verify_producer_proof_self_consistency(digest_suite)
        .map_err(|_| ())
}

/// Realm-aware receiver proof gate. A cached retired minimal-metadata marker
/// is not a valid Realm profile and must not select its old pairwise trust
/// path or silently fall through to ordinary producer verification.
pub(crate) fn verify_chat_envelope_proof_for_realm(
    realm_id: &str,
    event: &Value,
    state_store: Option<&LocalStateStore>,
    decrypt_identity: Option<(&arkret_sdk::AccountId, &str, &arkret_sdk::DeviceId)>,
) -> ChatProofVerdict {
    if let Some(store) = state_store
        && store.realm_projection_has_retired_minimal_metadata_marker(realm_id)
    {
        return ChatProofVerdict::Rejected;
    }
    let candidates = message_candidates(event);
    if let Some(envelope) = candidates.iter().copied().find(|candidate| {
        candidate
            .pointer("/unsigned/agent_authorization_admission")
            .is_some()
    }) {
        let Some(store) = state_store else {
            return ChatProofVerdict::Unresolved;
        };
        let coordinates = encrypted_content_coordinates(realm_id, &candidates);
        let mls_view = if let Some((group_id, epoch, group_state_ref)) = &coordinates {
            let Some((authority, _, self_device)) = decrypt_identity else {
                return ChatProofVerdict::Unresolved;
            };
            let secure_store = crate::secure_key_store::default_secure_key_store("inkson");
            let Some(view) = crate::mls::runtime::ordinary_agent_mls_author_view(
                store,
                secure_store.as_ref(),
                realm_id,
                authority,
                self_device,
                group_id,
                *epoch,
                group_state_ref,
            ) else {
                return ChatProofVerdict::Unresolved;
            };
            Some(view)
        } else {
            None
        };
        let mls_binding = coordinates
            .as_ref()
            .and_then(|(group_id, epoch, group_state_ref)| {
                mls_view.as_ref().map(|view| {
                    crate::identity::agent_signer_evidence::OrdinaryAgentMlsBinding {
                        view,
                        group_id,
                        epoch: *epoch,
                        group_state_ref,
                    }
                })
            });
        return match crate::identity::agent_signer_evidence::verify_cached_event(
            envelope,
            store,
            mls_binding,
        ) {
            crate::identity::agent_signer_evidence::CachedAgentEventVerdict::Verified => {
                ChatProofVerdict::Verified
            }
            crate::identity::agent_signer_evidence::CachedAgentEventVerdict::Rejected => {
                ChatProofVerdict::Rejected
            }
            crate::identity::agent_signer_evidence::CachedAgentEventVerdict::Unresolved => {
                ChatProofVerdict::Unresolved
            }
            crate::identity::agent_signer_evidence::CachedAgentEventVerdict::NotAgent => {
                ChatProofVerdict::Rejected
            }
        };
    }
    verify_committed_chat_producer_proof(event)
}

pub(crate) fn verified_chat_sender_domain_for_realm(
    realm_id: &str,
    event: &Value,
    state_store: Option<&LocalStateStore>,
    decrypt_identity: Option<(&arkret_sdk::AccountId, &str, &arkret_sdk::DeviceId)>,
) -> Option<Vec<u8>> {
    if verify_chat_envelope_proof_for_realm(realm_id, event, state_store, decrypt_identity)
        != ChatProofVerdict::Verified
    {
        return None;
    }
    // Standard content AAD uses the sender leaf's canonical ActorId
    // credential, preserving its Station. The device remains a proof selector
    // and must not replace the credential identity.
    let envelope = message_candidates(event).into_iter().find(|candidate| {
        candidate
            .get("producer_proof")
            .and_then(Value::as_object)
            .is_some()
    })?;
    let producer = committed_human_device_producer(envelope).ok()??;
    arkret_sdk::mls_basic_credential_identity(&arkret_sdk::ActorId::account(producer.account_id))
        .ok()
}

/// Reconstruct the encrypted-content group coordinates used by ordinary
/// Agent proof admission.
fn encrypted_content_coordinates(
    realm_id: &str,
    candidates: &[&Value],
) -> Option<(String, u64, String)> {
    let content = candidates.iter().find_map(|candidate| {
        candidate.get("encrypted_content").or_else(|| {
            candidate
                .get("content")
                .and_then(|content| content.get("encrypted_content"))
        })
    })?;
    let envelope = serde_json::from_value::<arkret_sdk::EncryptedEnvelope>(content.clone()).ok()?;
    let effective_scope = arkret_sdk::ScopeRef::Realm {
        realm_id: arkret_sdk::RealmId::new(realm_id.to_owned()).ok()?,
    };
    Some((
        effective_scope
            .canonical_mls_group_id()
            .ok()?
            .as_str()
            .to_owned(),
        envelope.encryption_context.epoch(),
        envelope
            .encryption_context
            .group_state_ref()
            .as_str()
            .to_owned(),
    ))
}

/// X9 — build a `ChatMessage` from a synced/projected event, preferring the
/// author's own local plaintext sidecar (`mls_private_plaintext`, keyed by
/// `message:{message_id}`) over the encrypted payload. OpenMLS forbids an
/// author from decrypting their OWN application messages, so for the author's
/// encrypted messages the ciphertext is undecryptable and the projection carries
/// no plaintext body. Without the sidecar, keep the message as a visible
/// crypto-pending row instead of dropping it, so a fresh browser shows "locked"
/// rather than "No messages". The sidecar lookup mirrors kanban's
/// `private_strand_field_text`.
pub(crate) fn chat_message_from_event_with_sidecar(
    realm_id: &str,
    event: &Value,
    state_store: Option<&LocalStateStore>,
    decrypt_identity: Option<(&arkret_sdk::AccountId, &str, &arkret_sdk::DeviceId)>,
) -> Option<ChatMessage> {
    let candidates = message_candidates(event);
    let is_redaction_tombstone = message_is_redaction_tombstone(&candidates);
    // Receiver proof gate (server-trusted-results.md §2, fail-closed): a
    // producer proof that is not self-consistent MUST NOT enter the
    // conversation view.
    let mut proof_verdict =
        verify_chat_envelope_proof_for_realm(realm_id, event, state_store, decrypt_identity);
    let server_projection_tombstone = is_redaction_tombstone
        && event
            .pointer("/unsigned/projection_only")
            .and_then(Value::as_bool)
            == Some(true);
    if proof_verdict == ChatProofVerdict::Rejected && server_projection_tombstone {
        // Soland may replace an accepted create/revision with a proofless
        // projection-only tombstone. This form can only remove content and is
        // therefore safe to render as unattributed server state; it cannot
        // inject sender-authored plaintext or actions. All non-tombstone
        // attributed rows remain fail-closed above.
        proof_verdict = ChatProofVerdict::Unattributed;
    }
    if proof_verdict == ChatProofVerdict::Rejected {
        return None;
    }
    let verified_sender_domain = (proof_verdict == ChatProofVerdict::Verified)
        .then(|| {
            verified_chat_sender_domain_for_realm(realm_id, event, state_store, decrypt_identity)
        })
        .flatten();
    let effective_scope = candidates
        .iter()
        .find_map(|candidate| {
            candidate
                .get("scope_ref")
                .or_else(|| candidate.get("effective_scope"))
                .cloned()
        })
        .and_then(|scope| serde_json::from_value::<arkret_sdk::ScopeRef>(scope).ok());
    if poll_content_from_candidates(&candidates)
        .and_then(|content| content.get("kind").and_then(Value::as_str))
        .is_some_and(|kind| kind == "ak.content.poll.response")
    {
        return None;
    }
    let message_realm = first_string_in_candidates(&candidates, &["realm_id"]).unwrap_or(realm_id);
    // T7.4: locate the canonical `encrypted_content` envelope (if any) up front
    // so the read path can BOTH surface the decryption state AND attempt a real
    // decrypt-on-read for remote members below.
    let encrypted_content_value = candidates.iter().find_map(|candidate| {
        candidate.get("encrypted_content").cloned().or_else(|| {
            candidate
                .get("content")
                .and_then(|content| content.get("encrypted_content"))
                .cloned()
        })
    });
    let has_encrypted_payload = encrypted_content_value.is_some();
    // Receive-side redaction fold: a redacted message arrives as a tombstone
    // form (same event_id, body stripped). Render the tombstone marker rather
    // than the original body, even on a fresh reload where this is the only
    // copy of the message the receiver ever sees.
    // Author-owned plaintext sidecar: look up the body the author stored on
    // encrypted send, keyed by `message:{message_id}` under the discussion
    // strand. Falls back to the decoded payload body (another member's message
    // we CAN decrypt, or a plaintext message).
    let sidecar_body = if is_redaction_tombstone {
        None
    } else {
        state_store.and_then(|store| {
            let message_id = message_protocol_message_id_from_candidates(&candidates)?;
            let strand_id = first_string_in_candidates(&candidates, &["strand_id"])?;
            store.private_plaintext_for(message_realm, strand_id, &format!("message:{message_id}"))
        })
    };
    let sidecar_content = sidecar_body.map(content_from_private_sidecar);
    let body_from_sidecar = sidecar_content.is_some();
    // P0 decrypt-on-read: a remote member's message carries ciphertext but no
    // author sidecar. Parse the canonical envelope, decrypt with this device's
    // MLS snapshot secret, and extract the Content Block text. Soft-fails to
    // `None` (→ Decrypting/KeyMissing) when the snapshot/secret is unavailable.
    let decrypt_context = if !is_redaction_tombstone && !body_from_sidecar {
        match (
            decrypt_identity,
            state_store,
            encrypted_content_value.as_ref(),
        ) {
            (Some((authority, actor_id, device_id)), Some(store), Some(encrypted)) => {
                Some((store, authority, actor_id, device_id, encrypted))
            }
            _ => None,
        }
    } else {
        None
    };
    let decrypt_was_attempted = decrypt_context.is_some();
    let decrypted_content =
        decrypt_context.and_then(|(store, authority, _, device_id, encrypted)| {
            decrypt_chat_encrypted_content_value(
                store,
                message_realm,
                authority,
                device_id,
                effective_scope.as_ref(),
                encrypted,
                verified_sender_domain.as_deref(),
            )
            .and_then(|content_value| {
                display_body_from_value(&content_value)
                    .map(|body| (body, content_format_from_value(&content_value)))
            })
        });
    let body_was_decrypted = decrypted_content.is_some();
    let (body, content_format) = if is_redaction_tombstone {
        (String::new(), None)
    } else {
        match sidecar_content.or(decrypted_content) {
            Some(content) => content,
            None if has_encrypted_payload => (String::new(), None),
            None => (
                text_body_from_message(&candidates)?,
                candidates
                    .iter()
                    .find_map(|candidate| content_format_from_value(candidate)),
            ),
        }
    };
    let explicit_message_kind = candidates
        .iter()
        .any(|candidate| message_kind_is_create(candidate) || message_kind_is_revise(candidate));
    let message_payload_shape =
        first_string_in_candidates(&candidates, &["message_id", "strand_id"]).is_some();
    if !explicit_message_kind && !message_payload_shape {
        return None;
    }
    let event_id = value_string_at(event, &["event_id", "id"])
        .or_else(|| first_string_in_candidates(&candidates, &["event_id", "message_id", "id"]))
        .unwrap_or("event:unknown")
        .to_owned();
    let protocol_message_id = message_protocol_message_id_from_candidates(&candidates);
    let strand_id = first_string_in_candidates(&candidates, &["strand_id"])
        .or_else(|| {
            event
                .get("unsigned")
                .and_then(|unsigned| unsigned.get("local_target_ref"))
                .and_then(Value::as_str)
        })
        .filter(|value| value.starts_with("ak:strand:"))
        .unwrap_or("ak:strand:ALH536fxXVv9EDZIoWa7sN1gzbTVJQ02x6AugHURwkvE")
        .to_owned();
    // Message submit payloads normatively do not carry `scope_circle_id`.
    // The reducer stamps the immutable Event `effective_scope`; selecting the
    // matching Circle snapshot above binds decryption to that scope without
    // inventing a payload field that v1 forbids.
    let crypto_state = if proof_verdict == ChatProofVerdict::Unresolved {
        // A non-device producer whose signer evidence is not verified yet is
        // flagged rather than presented as trusted.
        MessageCryptoState::NeedsVerification
    } else if body_from_sidecar || body_was_decrypted {
        // X9: the author's own plaintext was recovered from the local sidecar,
        // OR (P0) a remote member's ciphertext was decrypted-on-read — the body
        // is authoritative and fully resolved, so do not leave it stuck in
        // `Decrypting`.
        MessageCryptoState::Plaintext
    } else if has_encrypted_payload {
        if decrypt_was_attempted {
            MessageCryptoState::KeyMissing
        } else {
            MessageCryptoState::Decrypting
        }
    } else {
        MessageCryptoState::Plaintext
    };
    let reactions = if is_redaction_tombstone {
        Vec::new()
    } else {
        reactions_from_candidates(&candidates)
    };
    let sender = message_actor_from_candidates(&candidates)?;
    Some(ChatMessage {
        realm_id: first_string_in_candidates(&candidates, &["realm_id"])
            .unwrap_or(realm_id)
            .to_owned(),
        id: event_id,
        protocol_message_id,
        actor_id: candidates.iter().find_map(|candidate| {
            candidate
                .get("actor_id")
                .and_then(|value| serde_json::from_value::<arkret_sdk::ActorId>(value.clone()).ok())
        }),
        sender,
        // §4.10 — act-on-behalf carries a signed envelope-level
        // `executed_by`. When present and distinct from the actor, the
        // renderer shows the "controller via agent" double signature.
        executed_by: candidates.iter().find_map(|candidate| {
            candidate
                .get("executed_by")
                .and_then(actor_principal_from_value)
                .filter(|value| !value.trim().is_empty())
        }),
        body,
        content_format,
        timestamp: short_message_time(first_string_in_candidates(&candidates, &["created_at"])),
        created_at: message_created_at_from_candidates(&candidates),
        strand_id,
        reply_to: first_string_in_candidates(&candidates, &["reply_to_id"]).map(ToOwned::to_owned),
        reactions,
        redacted: is_redaction_tombstone,
        edited: false,
        revisions: Vec::new(),
        revision_source: None,
        pending: false,
        failed: false,
        error: None,
        mentions: mentions_from_candidates(&candidates),
        crypto_state,
    })
}

pub(crate) fn chat_messages_from_events_with_sidecar(
    realm_id: &str,
    events: &[Value],
    state_store: Option<&LocalStateStore>,
    decrypt_identity: Option<(&arkret_sdk::AccountId, &str, &arkret_sdk::DeviceId)>,
) -> Vec<ChatMessage> {
    chat_messages_from_event_list_with_sidecar(realm_id, events, state_store, decrypt_identity)
}

/// Normalize a batch of realm timeline events (from `account.subscribe`
/// `timeline.events[]` / realm `backfill`) into [`RawOperationRecord`]s for the
/// discussion message lifecycle, so the chat feed projects **local-first** from
/// `raw_operations` — exactly like the kanban board does via
/// `kanban_operations_from_events` — instead of refetching + redecrypting the
/// whole realm on every Discussion-tab open.
///
/// Canonical `ak.message.create` events (including server-folded redaction
/// tombstones, which reuse the same kind + `event_id`) are kept.
/// Shared `ak.pin.*` control events are kept in the same discussion log so the
/// pinned-message bar and reaction summary project from the same local-first
/// source. Poll responses have their own projection and are deliberately
/// excluded. The FULL event is stored as the record
/// payload so the receiver-proof gate, the `encrypted_content` ciphertext, and
/// the tombstone markers all survive into the local-first render path — the
/// decrypted plaintext is NEVER stored here (it stays in the author sidecar /
/// decrypt-on-read path), preserving the encrypted-send at-rest invariant
/// (chat X10.6).
pub(crate) fn poll_content_from_candidates<'a>(candidates: &[&'a Value]) -> Option<&'a Value> {
    candidates
        .iter()
        .find(|candidate| {
            candidate
                .get("kind")
                .and_then(Value::as_str)
                .is_some_and(|kind| matches!(kind, "ak.content.poll" | "ak.content.poll.response"))
        })
        .copied()
}

fn poll_content_from_private_sidecar(
    realm_id: &str,
    candidates: &[&Value],
    state_store: Option<&LocalStateStore>,
) -> Option<Value> {
    let store = state_store?;
    let message_id = message_protocol_message_id_from_candidates(candidates)?;
    let strand_id = first_string_in_candidates(candidates, &["strand_id"])?;
    let message_realm = first_string_in_candidates(candidates, &["realm_id"]).unwrap_or(realm_id);
    let plaintext = store.private_plaintext_for(
        message_realm,
        strand_id,
        &format!("message-content:{message_id}"),
    )?;
    serde_json::from_str(&plaintext).ok()
}

pub(crate) fn poll_cards_from_events_with_sidecar(
    realm_id: &str,
    events: &[Value],
    state_store: Option<&LocalStateStore>,
    decrypt_identity: Option<(&arkret_sdk::AccountId, &str, &arkret_sdk::DeviceId)>,
) -> Vec<crate::messaging::polls::PollCard> {
    let mut cards = Vec::<crate::messaging::polls::PollCard>::new();
    use arkret_models_collaboration::poll::{PollPartition, PollResponseSet, VerifiedPollResponse};
    let verified_inputs = state_store
        .map(LocalStateStore::verified_poll_inputs)
        .unwrap_or_default();
    let visible_ids = events
        .iter()
        .flat_map(|event| message_candidates(event).into_iter())
        .filter_map(|candidate| {
            candidate
                .get("event_id")
                .and_then(Value::as_str)
                .map(str::to_owned)
        })
        .collect::<std::collections::BTreeSet<_>>();
    // Trusted original Events replace any enriched or altered timeline copy.
    // All retained responses participate, even when the visible timeline window
    // no longer contains the earlier vote.
    let mut source_events = events
        .iter()
        .filter(|event| {
            let candidates = message_candidates(event);
            let id = candidates
                .iter()
                .find_map(|candidate| candidate.get("event_id").and_then(Value::as_str));
            !verified_inputs
                .iter()
                .any(|input| Some(input.event.event_id.as_str()) == id)
        })
        .cloned()
        .collect::<Vec<_>>();
    source_events.extend(
        verified_inputs
            .iter()
            .filter(|input| realm_id.is_empty() || input.event.realm_id.as_str() == realm_id)
            .filter_map(|input| serde_json::to_value(&input.event).ok()),
    );
    let mut responses = Vec::<(
        PollPartition,
        arkret_sdk::CommittedEventRef,
        Vec<String>,
        Vec<arkret_sdk::PollResponseHead>,
    )>::new();
    let mut card_scopes = std::collections::BTreeMap::new();
    let mut unresolved_inputs = Vec::new();
    for event in &source_events {
        let candidates = message_candidates(event);
        // v1 poll state accepts only plaintext ContentBlocks visible to admission.
        if candidates
            .iter()
            .any(|candidate| candidate.get("encrypted_content").is_some())
        {
            continue;
        }
        let signed_scope = candidates
            .iter()
            .copied()
            .find(|candidate| {
                candidate.get("actor_id").is_some() && candidate.get("producer_proof").is_some()
            })
            .and_then(|envelope| envelope.get("scope_ref"))
            .and_then(|scope| serde_json::from_value::<arkret_sdk::ScopeRef>(scope.clone()).ok());
        let realm_id = match &signed_scope {
            Some(arkret_sdk::ScopeRef::Realm { realm_id })
            | Some(arkret_sdk::ScopeRef::Circle { realm_id, .. }) => realm_id.as_str(),
            _ => realm_id,
        };
        let proof_verdict =
            verify_chat_envelope_proof_for_realm(realm_id, event, state_store, decrypt_identity);
        if proof_verdict == ChatProofVerdict::Rejected {
            if let Ok(original) = serde_json::from_value::<arkret_sdk::Event>(event.clone())
                && let Some(input) = verified_inputs.iter().find(|input| input.event == original)
            {
                unresolved_inputs.push(input.accepted_ref.clone());
            }
            continue;
        }
        let verified_sender_domain = (proof_verdict == ChatProofVerdict::Verified)
            .then(|| {
                verified_chat_sender_domain_for_realm(
                    realm_id,
                    event,
                    state_store,
                    decrypt_identity,
                )
            })
            .flatten();
        let direct_content = poll_content_from_candidates(&candidates).cloned();
        let private_content = direct_content
            .is_none()
            .then(|| poll_content_from_private_sidecar(realm_id, &candidates, state_store))
            .flatten();
        let decrypted_content =
            (direct_content.is_none() && private_content.is_none()).then(|| {
                let message_realm =
                    first_string_in_candidates(&candidates, &["realm_id"]).unwrap_or(realm_id);
                let effective_scope = candidates
                    .iter()
                    .find_map(|candidate| {
                        candidate
                            .get("scope_ref")
                            .or_else(|| candidate.get("effective_scope"))
                            .cloned()
                    })
                    .and_then(|scope| serde_json::from_value::<arkret_sdk::ScopeRef>(scope).ok());
                let encrypted_content = candidates.iter().find_map(|candidate| {
                    candidate.get("encrypted_content").or_else(|| {
                        candidate
                            .get("content")
                            .and_then(|content| content.get("encrypted_content"))
                    })
                })?;
                let (store, (authority, _, device_id)) = (state_store?, decrypt_identity?);
                decrypt_chat_encrypted_content_value(
                    store,
                    message_realm,
                    authority,
                    device_id,
                    effective_scope.as_ref(),
                    encrypted_content,
                    verified_sender_domain.as_deref(),
                )
            });
        let content = direct_content
            .or(private_content)
            .or(decrypted_content.flatten());
        let envelope = candidates.iter().copied().find(|candidate| {
            candidate.get("actor_id").is_some() && candidate.get("producer_proof").is_some()
        });
        let verified_input = envelope
            .and_then(|envelope| envelope.get("event_id"))
            .and_then(Value::as_str)
            .and_then(|id| {
                verified_inputs
                    .iter()
                    .find(|input| input.event.event_id.as_str() == id)
            })
            .filter(|input| {
                envelope
                    .and_then(|envelope| {
                        serde_json::from_value::<arkret_sdk::Event>(envelope.clone()).ok()
                    })
                    .as_ref()
                    == Some(&input.event)
            });
        let identity = (proof_verdict == ChatProofVerdict::Verified)
            .then(|| {
                envelope.and_then(|envelope| {
                    let event_id: arkret_sdk::EventId =
                        serde_json::from_value(envelope.get("event_id")?.clone()).ok()?;
                    let actor_id: arkret_sdk::ActorId =
                        serde_json::from_value(envelope.get("actor_id")?.clone()).ok()?;
                    Some((event_id.event_digest(), actor_id, envelope))
                })
            })
            .flatten();
        let Some(content) = content else {
            if let Some(input) = verified_input {
                unresolved_inputs.push(input.accepted_ref.clone());
            }
            continue;
        };
        let scope = signed_scope.clone().and_then(|scope| match scope {
            arkret_sdk::ScopeRef::Realm { realm_id } => Some((realm_id, None)),
            arkret_sdk::ScopeRef::Circle {
                realm_id,
                circle_id,
            } => Some((realm_id, Some(circle_id))),
            _ => None,
        });
        let Ok(block) = serde_json::from_value::<
            arkret_models_collaboration::events_payloads::PollContentBlock,
        >(content) else {
            continue;
        };
        if block.validate().is_err() {
            continue;
        }
        let definition = match block {
            arkret_models_collaboration::events_payloads::PollContentBlock::Response(block) => {
                if let (Some((_, actor_id, _)), Some(input)) = (identity, verified_input) {
                    let original_poll = verified_inputs.iter().find(|poll| {
                        arkret_sdk::MessageId::from_event_id(&poll.event.event_id)
                            == block.poll_response.poll_ref
                            && poll.accepted_ref.stream_ref == input.accepted_ref.stream_ref
                            && poll.accepted_ref.stream_position
                                < input.accepted_ref.stream_position
                    });
                    let heads = input
                        .event
                        .payload
                        .get("poll_response_heads")
                        .map(|value| {
                            serde_json::from_value::<Vec<arkret_sdk::PollResponseHead>>(
                                value.clone(),
                            )
                        })
                        .transpose();
                    if let (Some(poll), Ok(heads)) = (original_poll, heads) {
                        responses.push((
                            PollPartition {
                                realm_id: input.event.realm_id.clone(),
                                stream_ref: input.accepted_ref.stream_ref.clone(),
                                poll_ref: block.poll_response.poll_ref,
                                poll_event_ref: poll.event.event_id.clone(),
                                actor_id,
                            },
                            input.accepted_ref.clone(),
                            block.poll_response.selections,
                            heads.unwrap_or_default(),
                        ));
                    }
                }
                continue;
            }
            arkret_models_collaboration::events_payloads::PollContentBlock::Definition(block) => {
                if verified_input
                    .is_some_and(|input| !visible_ids.contains(input.event.event_id.as_str()))
                {
                    continue;
                }
                block
            }
        };
        let Some(message) =
            chat_message_from_event_with_sidecar(realm_id, event, state_store, decrypt_identity)
        else {
            continue;
        };
        // The card's tally identity is the wire message id (`ak:message:…`,
        // what `poll_response.poll_ref` points at); the event id stays the
        // local render identity.
        let Some(poll_ref) = message
            .protocol_message_id
            .as_ref()
            .and_then(|id| arkret_sdk::MessageId::new(id.clone()).ok())
        else {
            continue;
        };
        let mut card = crate::messaging::polls::PollCard::from_definition(
            message.id.clone(),
            &poll_ref,
            &definition,
        );
        card.provisional = identity.is_none()
            || !verified_input.is_some_and(|input| {
                state_store.is_some_and(|store| {
                    store.verified_poll_partition_complete(
                        &input.accepted_ref.stream_ref,
                        input.accepted_ref.stream_position,
                    )
                })
            });
        if identity.is_some() {
            card.verified_scope = verified_input.map(|input| input.event.scope_ref.clone());
        }
        if identity.is_some()
            && let Some((realm_id, circle_id)) = scope
        {
            card_scopes.insert((realm_id, circle_id, poll_ref), cards.len());
        }
        cards.push(card);
    }
    // Ascending Commit position is only for resolving signed predecessor
    // declarations. The SDK reducer itself selects max position, not arrival order.
    responses.sort_by(|left, right| {
        (&left.0.stream_ref, left.1.stream_position)
            .cmp(&(&right.0.stream_ref, right.1.stream_position))
    });
    let mut accepted_responses = std::collections::BTreeMap::new();
    let mut reduced = PollResponseSet::default();
    for (partition, accepted_ref, selections, heads) in responses {
        let circle = match &partition.stream_ref {
            arkret_sdk::CommitStreamRef::Circle { circle_id, .. } => Some(circle_id.clone()),
            _ => None,
        };
        let key = (
            partition.realm_id.clone(),
            circle,
            partition.poll_ref.clone(),
        );
        let Some(index) = card_scopes.get(&key).copied() else {
            continue;
        };
        let answers = cards[index]
            .options
            .iter()
            .map(|option| option.id.clone())
            .collect::<std::collections::BTreeSet<_>>();
        let max_selections = usize::try_from(cards[index].max_selections).unwrap_or(usize::MAX);
        let Ok(response) = VerifiedPollResponse::new(
            partition.clone(),
            accepted_ref.clone(),
            &selections,
            &answers,
            max_selections,
            heads,
            |id| accepted_responses.get(id).cloned(),
        ) else {
            continue;
        };
        if reduced.insert(response).is_err() {
            cards[index].provisional = true;
            continue;
        }
        accepted_responses.insert(accepted_ref.event_id.clone(), (partition, accepted_ref));
    }
    for (partition, projection) in reduced.project(true) {
        let circle = match &partition.stream_ref {
            arkret_sdk::CommitStreamRef::Circle { circle_id, .. } => Some(circle_id.clone()),
            _ => None,
        };
        let Some(index) = card_scopes
            .get(&(
                partition.realm_id.clone(),
                circle,
                partition.poll_ref.clone(),
            ))
            .copied()
        else {
            continue;
        };
        let card = &mut cards[index];
        if let Some(winner) = projection.winner {
            card.response_heads.insert(
                partition.actor_id.clone(),
                arkret_sdk::PollResponseHead {
                    poll_event_ref: partition.poll_event_ref,
                    response_event_ref: winner.event_id,
                },
            );
        }
        for (option, voters) in card.options.iter().zip(card.votes.iter_mut()) {
            if projection.selections.contains(&option.id) {
                voters.push(partition.actor_id.clone());
            }
        }
    }
    for ((realm_id, circle_id, poll_ref), index) in card_scopes {
        let stream = match circle_id {
            Some(circle_id) => arkret_sdk::CommitStreamRef::Circle {
                realm_id,
                circle_id,
            },
            None => arkret_sdk::CommitStreamRef::Realm { realm_id },
        };
        if let Some(poll) = verified_inputs
            .iter()
            .find(|input| arkret_sdk::MessageId::from_event_id(&input.event.event_id) == poll_ref)
        {
            cards[index].provisional |= unresolved_inputs.iter().any(|input| {
                input.stream_ref == stream
                    && input.stream_position >= poll.accepted_ref.stream_position
            });
        }
    }
    cards
}

pub(crate) fn shared_message_pins_from_raw_operations(
    records: &[crate::state::RawOperationRecord],
    active_pin_scope: &SharedPinScope,
) -> Vec<SharedMessagePin> {
    let mut pins = Vec::<SharedMessagePin>::new();
    for record in records {
        apply_shared_pin_event(&mut pins, &record.payload, active_pin_scope);
    }
    pins.sort_by(|left, right| {
        left.rank
            .cmp(&right.rank)
            .then_with(|| left.target_ref.cmp(&right.target_ref))
    });
    pins
}

pub(crate) fn apply_shared_pin_event(
    pins: &mut Vec<SharedMessagePin>,
    event: &Value,
    active_pin_scope: &SharedPinScope,
) {
    let Some(kind) = event
        .get("kind")
        .or_else(|| event.get("event_kind"))
        .and_then(Value::as_str)
    else {
        return;
    };
    if !matches!(
        kind,
        event_kind_str::PIN_ADD | event_kind_str::PIN_REMOVE | event_kind_str::PIN_REORDER
    ) {
        return;
    }
    let payload = event
        .get("payload")
        .or_else(|| event.get("content"))
        .or_else(|| event.get("body"))
        .unwrap_or(event);
    let Some(pin_scope) = payload.get("pin_scope") else {
        return;
    };
    let Some(scope_kind) = pin_scope.get("kind").and_then(Value::as_str) else {
        return;
    };
    let Some(scope_id) = pin_scope.get("id").and_then(Value::as_str) else {
        return;
    };
    let Some(scope) = SharedPinScope::from_wire(scope_kind, scope_id) else {
        return;
    };
    if &scope != active_pin_scope {
        return;
    }
    let Some(target_ref) = payload.get("target_ref").and_then(Value::as_str) else {
        return;
    };
    match kind {
        event_kind_str::PIN_ADD => {
            let rank = payload
                .get("rank")
                .and_then(Value::as_str)
                .unwrap_or("U")
                .to_owned();
            if let Some(existing) = pins
                .iter_mut()
                .find(|pin| pin.matches_scope(&scope) && pin.target_ref == target_ref)
            {
                existing.rank = rank;
            } else {
                pins.push(SharedMessagePin::new(&scope, target_ref.to_owned(), rank));
            }
        }
        event_kind_str::PIN_REMOVE => {
            pins.retain(|pin| !(pin.matches_scope(&scope) && pin.target_ref == target_ref));
        }
        event_kind_str::PIN_REORDER => {
            if let Some(rank) = payload.get("rank").and_then(Value::as_str)
                && let Some(existing) = pins
                    .iter_mut()
                    .find(|pin| pin.matches_scope(&scope) && pin.target_ref == target_ref)
            {
                existing.rank = rank.to_owned();
            }
        }
        _ => {}
    }
}

pub(crate) fn chat_messages_from_sync_realms_with_sidecar(
    realms: &std::collections::BTreeMap<String, Value>,
    state_store: Option<&LocalStateStore>,
    decrypt_identity: Option<(&arkret_sdk::AccountId, &str, &arkret_sdk::DeviceId)>,
) -> Vec<ChatMessage> {
    let mut messages = Vec::new();
    for (realm_id, body) in realms {
        let Some(wire_events) = body
            .get("timeline")
            .and_then(|projection| projection.get("events"))
            .and_then(Value::as_array)
        else {
            continue;
        };
        messages.extend(chat_messages_from_events_with_sidecar(
            realm_id,
            wire_events,
            state_store,
            decrypt_identity,
        ));
    }
    messages
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct TypingActorSnapshot {
    pub(crate) actors: Vec<String>,
    pub(crate) next_expires_at_ms: Option<i64>,
}

/// Active typing actors from the decrypted `ak.typing` Signal projection.
///
/// v1 removed the plaintext `ephemeral.events[]` bucket from Realm sync, so
/// this no longer reads a Realm projection body: typing arrives as AEAD
/// plaintext inside a `SignalEnvelope`, and `strand_id` / `typing` live in that
/// plaintext. The envelope's own `expires_at` is the TTL, and it is copied onto
/// each stored body as `expires_at` when the Signal is decrypted.
pub(crate) fn typing_actor_snapshot_from_signals(
    bodies: &[Value],
    strand_id: &str,
    principal_id: &str,
) -> TypingActorSnapshot {
    let mut actors = std::collections::BTreeSet::<String>::new();
    let mut next_expires_at_ms: Option<i64> = None;
    let now = chrono::Utc::now();
    for body in bodies {
        if value_string_at(body, &["kind"]).unwrap_or_default() != "ak.typing" {
            continue;
        }
        if body.get("typing").and_then(Value::as_bool) == Some(false)
            || value_string_at(body, &["strand_id"]).unwrap_or_default() != strand_id
        {
            continue;
        }
        let Some(expires_at) = value_string_at(body, &["expires_at"])
            .and_then(|value| chrono::DateTime::parse_from_rfc3339(value).ok())
            .map(|value| value.with_timezone(&chrono::Utc))
        else {
            continue;
        };
        if expires_at <= now {
            continue;
        }
        let Some(actor) = body.get("actor_id").and_then(signal_actor_identity) else {
            continue;
        };
        if actor != principal_id {
            actors.insert(actor);
            let expires_at_ms = expires_at.timestamp_millis();
            next_expires_at_ms = Some(match next_expires_at_ms {
                Some(current) => current.min(expires_at_ms),
                None => expires_at_ms,
            });
        }
    }
    TypingActorSnapshot {
        actors: actors.into_iter().collect(),
        next_expires_at_ms,
    }
}

fn signal_actor_identity(value: &Value) -> Option<String> {
    serde_json::from_value::<arkret_sdk::ActorId>(value.clone())
        .ok()
        .map(|actor| actor.to_string())
}

pub(crate) fn sync_presence_actor(event: &Value) -> Option<String> {
    event.get("actor_id").and_then(signal_actor_identity)
}

/// Only the canonical, admitted Signal projection is consumed here.
pub(crate) fn sync_presence_state(event: &Value) -> Option<String> {
    event
        .get("state")
        .and_then(Value::as_str)
        .and_then(arkret_sdk::PresenceStatus::parse_wire)
        .map(|state| state.as_wire().to_owned())
}

/// Transient status message carried by a presence projection event
/// (profiles-presence.md §3.3). Fail-closed: values violating the wire
/// constraint are dropped rather than truncated.
pub(crate) fn sync_presence_status_message(event: &Value) -> Option<String> {
    event
        .get("status_message")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|message| !message.is_empty())
        .filter(|message| arkret_sdk::validate_status_message(message).is_ok())
        .map(ToOwned::to_owned)
}

fn sync_presence_timestamp(event: &Value, field: &str) -> Option<chrono::DateTime<chrono::Utc>> {
    event
        .get(field)
        .and_then(Value::as_str)
        .and_then(|value| chrono::DateTime::parse_from_rfc3339(value).ok())
        .map(|value| value.with_timezone(&chrono::Utc))
}

fn sync_presence_event_is_live(event: &Value, now: chrono::DateTime<chrono::Utc>) -> bool {
    event.get("kind").and_then(Value::as_str) == Some("ak.presence")
        && sync_presence_timestamp(event, "expires_at").is_some_and(|expiry| expiry > now)
}

pub(crate) type PresenceMaps = (
    std::collections::BTreeMap<String, String>,
    std::collections::BTreeMap<String, String>,
    std::collections::BTreeMap<String, String>,
);

pub(crate) fn presence_projection_refresh_key(scope: &str, events: &[Value]) -> String {
    use std::hash::{Hash, Hasher};

    let mut projection = std::collections::hash_map::DefaultHasher::new();
    serde_json::to_vec(events)
        .unwrap_or_default()
        .hash(&mut projection);
    format!("{scope}|{:016x}", projection.finish())
}

pub(crate) fn presence_maps_from_sync_events(
    events: &[Value],
    participants: &[String],
    principal_id: &str,
    account_label: &str,
) -> Option<PresenceMaps> {
    if events.is_empty() {
        return None;
    }
    let participant_by_identity = participants
        .iter()
        .filter_map(|participant| {
            serde_json::from_str::<arkret_sdk::ActorId>(participant)
                .ok()
                .map(|actor| (actor.to_string(), participant.clone()))
        })
        .collect::<std::collections::BTreeMap<_, _>>();
    let account_identity = serde_json::from_str::<arkret_sdk::ActorId>(principal_id)
        .ok()
        .map(|actor| actor.to_string());
    let mut states = std::collections::BTreeMap::<String, String>::new();
    let mut labels = std::collections::BTreeMap::<String, String>::new();
    let mut status_messages = std::collections::BTreeMap::<String, String>::new();
    for did in participants {
        states.insert(
            did.clone(),
            if Some(did) == account_identity.as_ref() {
                "online".to_owned()
            } else {
                "offline".to_owned()
            },
        );
        if Some(did) == account_identity.as_ref()
            && let Some(label) = clean_participant_display_name(account_label, Some(did))
        {
            labels.insert(did.clone(), label);
        }
    }
    let now = chrono::Utc::now();
    let mut presence_by_actor = std::collections::BTreeMap::<
        String,
        (
            Vec<arkret_sdk::PresenceStatus>,
            Option<(Option<chrono::DateTime<chrono::Utc>>, String, String)>,
        ),
    >::new();
    for event in events {
        let Some(actor_core) = sync_presence_actor(event) else {
            continue;
        };
        let Some(actor) = participant_by_identity.get(&actor_core).cloned() else {
            continue;
        };
        if !sync_presence_event_is_live(event, now) {
            continue;
        }
        let Some(state) = sync_presence_state(event)
            .as_deref()
            .and_then(arkret_sdk::PresenceStatus::parse_wire)
        else {
            continue;
        };
        let entry = presence_by_actor.entry(actor).or_default();
        entry.0.push(state);
        if let Some(message) = sync_presence_status_message(event) {
            // `expires_at` rather than `sent_at`: the Signal receive engine no
            // longer publishes a sender instant (see `live_body_value`), and
            // the effective expiry orders one actor's presence bodies the same
            // way for a fixed TTL profile.
            let candidate = (
                sync_presence_timestamp(event, "expires_at"),
                event
                    .get("device_id")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_owned(),
                message,
            );
            if entry.1.as_ref().is_none_or(|current| candidate > *current) {
                entry.1 = Some(candidate);
            }
        }
    }
    let matched_remote = presence_by_actor
        .keys()
        .any(|actor| Some(actor) != account_identity.as_ref());
    for (actor, (actor_states, status_message)) in presence_by_actor {
        states.insert(
            actor.clone(),
            arkret_sdk::aggregate_presence_states(actor_states)
                .as_wire()
                .to_owned(),
        );
        if let Some((_, _, message)) = status_message {
            status_messages.insert(actor, message);
        }
    }
    matched_remote.then_some((states, labels, status_messages))
}

pub(crate) fn chat_messages_from_local_state_with_sidecar(
    state: &ClientLocalState,
    state_store: Option<&LocalStateStore>,
    decrypt_identity: Option<(&arkret_sdk::AccountId, &str, &arkret_sdk::DeviceId)>,
) -> Vec<ChatMessage> {
    let events = state
        .raw_operations
        .iter()
        .map(|record| {
            let mut payload = record.payload.clone();
            if payload.get("realm_id").is_none()
                && let Some(realm_id) = record.realm_id.as_deref()
                && let Some(object) = payload.as_object_mut()
            {
                object.insert("realm_id".to_owned(), Value::String(realm_id.to_owned()));
            }
            payload
        })
        .collect::<Vec<_>>();
    chat_messages_from_event_list_with_sidecar("", &events, state_store, decrypt_identity)
}

/// Fold durable lifecycle events onto an existing optimistic projection.
///
/// A sender can have its local `ChatMessage` before the canonical create event
/// reaches `raw_operations`, while remote reaction/revision/redaction controls
/// are already durable. Seeding the fold lets those controls resolve their
/// protocol target immediately; later canonical creates still dedupe through
/// the normal create merge path.
pub(crate) fn fold_local_state_into_chat_messages_with_sidecar(
    seed: Vec<ChatMessage>,
    state: &ClientLocalState,
    state_store: Option<&LocalStateStore>,
    decrypt_identity: Option<(&arkret_sdk::AccountId, &str, &arkret_sdk::DeviceId)>,
) -> Vec<ChatMessage> {
    let events = state
        .raw_operations
        .iter()
        .map(|record| {
            let mut payload = record.payload.clone();
            if payload.get("realm_id").is_none()
                && let Some(realm_id) = record.realm_id.as_deref()
                && let Some(object) = payload.as_object_mut()
            {
                object.insert("realm_id".to_owned(), Value::String(realm_id.to_owned()));
            }
            payload
        })
        .collect::<Vec<_>>();
    fold_event_list_into_chat_messages(seed, "", &events, state_store, decrypt_identity)
}

pub(crate) fn poll_cards_from_local_state_with_sidecar(
    state: &ClientLocalState,
    state_store: Option<&LocalStateStore>,
    decrypt_identity: Option<(&arkret_sdk::AccountId, &str, &arkret_sdk::DeviceId)>,
) -> Vec<crate::messaging::polls::PollCard> {
    let events = state
        .raw_operations
        .iter()
        .map(|record| record.payload.clone())
        .collect::<Vec<_>>();
    poll_cards_from_events_with_sidecar("", &events, state_store, decrypt_identity)
}
