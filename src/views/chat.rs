use dioxus::prelude::*;
use dioxus_router::hooks::use_navigator;
use serde_json::{Value, json};

use crate::{
    api::{ContrixApi, is_auth_expired_error, is_plaintext_visibility_policy_error},
    audit::build_audit_ryw_receipt,
    components::{HelpTip, UiIcon},
    hlc::{Hlc, observe_seq},
    local_state::{ClientLocalState, LocalStateStore, MoveSubmissionState},
    models::SubmitEventResponse,
    move_builder::{build_mls_commit_move, did_key_verification_method, sign_unsigned_move},
    operation::{OperationBuilder, OperationEnvelope, cx_ops, uuid_v7},
    routes::Route,
    views::helpers::{
        StructuredMention, active_sync_token, authed_api_with_sync, parse_structured_mentions,
    },
};

const CHAT_EMOJI_GRID: &[&str] = &[
    "\u{1f44d}",
    "\u{2764}\u{fe0f}",
    "\u{1f389}",
    "\u{1f440}",
    "\u{1f680}",
];

#[derive(Clone, Debug, PartialEq)]
struct ChannelEntity {
    flow_id: String,
    name: String,
    kind: String,
    category: String,
    topic: Option<String>,
    unread: usize,
}

#[derive(Clone, Debug, PartialEq)]
struct ChatMessage {
    space_id: String,
    id: String,
    sender: String,
    body: String,
    timestamp: String,
    flow_id: String,
    reply_to: Option<String>,
    reactions: Vec<(String, Vec<String>)>,
    redacted: bool,
    edited: bool,
    revisions: Vec<String>,
    pending: bool,
    failed: bool,
    error: Option<String>,
    mentions: Vec<StructuredMention>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DiscussionSidePanel {
    Users,
    Settings,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum SpaceParticipantRole {
    Owner,
    Admin,
    Member,
}

impl SpaceParticipantRole {
    fn label(self) -> &'static str {
        match self {
            Self::Owner => "Owner",
            Self::Admin => "Admin",
            Self::Member => "Member",
        }
    }

    fn rank(self) -> u8 {
        match self {
            Self::Owner => 0,
            Self::Admin => 1,
            Self::Member => 2,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct SpaceParticipant {
    did: String,
    display_name: Option<String>,
    display_name_rank: u8,
    role: SpaceParticipantRole,
    is_self: bool,
}

fn chat_message_revise_operation(
    space_id: &str,
    actor: &str,
    event_id: &str,
    body: &str,
) -> crate::operation::OperationEnvelope {
    OperationBuilder::new(space_id, actor, "cx.message.revise")
        .target_ref(event_id)
        .body(json!({
            "body": body,
            "content": {
                "blocks": [{"kind": "text", "text": body}],
                "body": body,
            },
            "target_event_id": event_id,
        }))
        .build("yougen")
}

fn chat_message_redact_operation(
    space_id: &str,
    actor: &str,
    event_id: &str,
    reason: &str,
) -> crate::operation::OperationEnvelope {
    OperationBuilder::new(space_id, actor, "cx.message.redact")
        .target_ref(event_id)
        .body(json!({
            "reason": reason,
            "target_event_id": event_id,
        }))
        .build("yougen")
}

fn chat_reaction_add_operation(
    space_id: &str,
    actor: &str,
    event_id: &str,
    key: &str,
) -> crate::operation::OperationEnvelope {
    OperationBuilder::new(space_id, actor, "cx.reaction.add")
        .target_ref(event_id)
        .body(json!({
            "actor": actor,
            "event_id": event_id,
            "key": key,
        }))
        .build("yougen")
}

fn normalize_participant_id(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_owned())
    }
}

fn participant_id_from_state_key(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if let Some(index) = trimmed.find("did:") {
        normalize_participant_id(&trimmed[index..])
    } else {
        None
    }
}

fn participant_role_from_str(
    value: Option<&str>,
    fallback: SpaceParticipantRole,
) -> SpaceParticipantRole {
    match value
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase()
        .as_str()
    {
        "owner" => SpaceParticipantRole::Owner,
        "admin" | "administrator" => SpaceParticipantRole::Admin,
        _ => fallback,
    }
}

fn participant_id_from_value(value: &Value) -> Option<String> {
    if let Some(raw) = value.as_str() {
        return normalize_participant_id(raw);
    }

    let object = value.as_object()?;
    [
        "did",
        "account_did",
        "actor_did",
        "member",
        "user",
        "actor",
        "actor_id",
        "subject",
        "state_key",
        "id",
        "identifier",
    ]
    .iter()
    .find_map(|key| object.get(*key).and_then(participant_id_from_value))
}

fn participant_id_from_member_value(value: &Value) -> Option<String> {
    if let Some(raw) = value.as_str() {
        return normalize_participant_id(raw);
    }

    let object = value.as_object()?;
    [
        "did",
        "account_did",
        "actor_did",
        "member",
        "user",
        "actor",
        "actor_id",
        "subject",
    ]
    .iter()
    .find_map(|key| object.get(*key).and_then(participant_id_from_member_value))
}

fn clean_participant_display_name(value: &str, did: Option<&str>) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed.starts_with("did:") || did == Some(trimmed) {
        None
    } else {
        Some(trimmed.to_owned())
    }
}

fn participant_display_name_from_value(value: &Value, did: Option<&str>) -> Option<(String, u8)> {
    let object = value.as_object()?;
    for (rank, keys) in [
        (
            0,
            ["remark", "note", "local_name", "contact_name"].as_slice(),
        ),
        (
            1,
            [
                "display_name",
                "displayName",
                "nickname",
                "alias",
                "preferred_name",
            ]
            .as_slice(),
        ),
        (2, ["name", "handle", "username"].as_slice()),
    ] {
        if let Some(name) = keys
            .iter()
            .find_map(|key| object.get(*key).and_then(Value::as_str))
            .and_then(|raw| clean_participant_display_name(raw, did))
        {
            return Some((name, rank));
        }
    }

    [
        "profile", "account", "member", "user", "actor", "subject", "details",
    ]
    .iter()
    .find_map(|key| {
        object
            .get(*key)
            .filter(|child| child.is_object())
            .and_then(|child| participant_display_name_from_value(child, did))
    })
}

fn upsert_participant(
    participants: &mut Vec<SpaceParticipant>,
    did: &str,
    role: SpaceParticipantRole,
    account_did: &str,
    display_name: Option<(String, u8)>,
) {
    let Some(did) = normalize_participant_id(did) else {
        return;
    };
    let is_self = did == account_did;
    if let Some(existing) = participants
        .iter_mut()
        .find(|candidate| candidate.did == did)
    {
        if role.rank() < existing.role.rank() {
            existing.role = role;
        }
        existing.is_self |= is_self;
        if let Some((display_name, rank)) = display_name
            && (existing.display_name.is_none() || rank < existing.display_name_rank)
        {
            existing.display_name = Some(display_name);
            existing.display_name_rank = rank;
        }
    } else {
        let (display_name, display_name_rank) = display_name
            .map(|(name, rank)| (Some(name), rank))
            .unwrap_or((None, u8::MAX));
        participants.push(SpaceParticipant {
            did,
            display_name,
            display_name_rank,
            role,
            is_self,
        });
    }
}

fn collect_participant_field(
    value: &Value,
    key: &str,
    role: SpaceParticipantRole,
    account_did: &str,
    participants: &mut Vec<SpaceParticipant>,
) {
    let Some(field) = value.get(key) else {
        return;
    };

    if let Some(items) = field.as_array() {
        for item in items {
            let item_role = item
                .get("role")
                .and_then(Value::as_str)
                .map(|raw_role| participant_role_from_str(Some(raw_role), role))
                .unwrap_or(role);
            if let Some(did) = participant_id_from_value(item) {
                upsert_participant(
                    participants,
                    &did,
                    item_role,
                    account_did,
                    participant_display_name_from_value(item, Some(&did)),
                );
            }
        }
    } else if let Some(did) = participant_id_from_value(field) {
        upsert_participant(
            participants,
            &did,
            role,
            account_did,
            participant_display_name_from_value(field, Some(&did)),
        );
    }
}

fn collect_state_participants(
    projection: &Value,
    account_did: &str,
    participants: &mut Vec<SpaceParticipant>,
) {
    let Some(state) = projection.get("state").and_then(Value::as_array) else {
        return;
    };

    for item in state {
        let kind = item
            .get("kind")
            .or_else(|| item.get("type"))
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_ascii_lowercase();
        let state_key = item
            .get("state_key")
            .or_else(|| item.get("key"))
            .and_then(Value::as_str)
            .unwrap_or_default();
        let body = item
            .get("content")
            .or_else(|| item.get("value"))
            .or_else(|| item.get("body"))
            .unwrap_or(item);

        let did = participant_id_from_state_key(state_key)
            .or_else(|| participant_id_from_member_value(body))
            .or_else(|| participant_id_from_member_value(item));
        if !kind.contains("member") && did.is_none() {
            continue;
        }

        let role = participant_role_from_str(
            body.get("role")
                .or_else(|| item.get("role"))
                .and_then(Value::as_str),
            SpaceParticipantRole::Member,
        );
        if let Some(did) = did {
            let display_name = participant_display_name_from_value(body, Some(&did))
                .or_else(|| participant_display_name_from_value(item, Some(&did)));
            upsert_participant(participants, &did, role, account_did, display_name);
        }
    }
}

fn space_participants(projection: Option<&Value>, account_did: &str) -> Vec<SpaceParticipant> {
    let mut participants = Vec::new();

    if let Some(projection) = projection {
        for key in ["owner", "created_by", "creator"] {
            collect_participant_field(
                projection,
                key,
                SpaceParticipantRole::Owner,
                account_did,
                &mut participants,
            );
        }
        for key in ["owners", "admins", "admin_dids"] {
            collect_participant_field(
                projection,
                key,
                SpaceParticipantRole::Admin,
                account_did,
                &mut participants,
            );
        }
        for key in ["members", "participants"] {
            collect_participant_field(
                projection,
                key,
                SpaceParticipantRole::Member,
                account_did,
                &mut participants,
            );
        }

        if let Some(summary) = projection.get("summary") {
            for key in ["owner", "created_by", "creator"] {
                collect_participant_field(
                    summary,
                    key,
                    SpaceParticipantRole::Owner,
                    account_did,
                    &mut participants,
                );
            }
            for key in ["owners", "admins", "admin_dids"] {
                collect_participant_field(
                    summary,
                    key,
                    SpaceParticipantRole::Admin,
                    account_did,
                    &mut participants,
                );
            }
            for key in ["members", "participants"] {
                collect_participant_field(
                    summary,
                    key,
                    SpaceParticipantRole::Member,
                    account_did,
                    &mut participants,
                );
            }
        }

        collect_state_participants(projection, account_did, &mut participants);
    }

    if !account_did.trim().is_empty() {
        upsert_participant(
            &mut participants,
            account_did,
            SpaceParticipantRole::Member,
            account_did,
            None,
        );
    }

    participants.sort_by(|left, right| {
        right
            .is_self
            .cmp(&left.is_self)
            .then_with(|| left.role.rank().cmp(&right.role.rank()))
            .then_with(|| left.did.cmp(&right.did))
    });
    participants
}

fn is_own_message_sender(sender: &str, account_did: &str) -> bool {
    let sender = sender.trim();
    !sender.is_empty() && (sender == "yougen" || sender == account_did.trim())
}

fn short_principal_label(value: &str) -> String {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return "Unknown".to_owned();
    }
    let principal = trimmed.strip_prefix("did:web:").unwrap_or(trimmed);
    let tail = principal.rsplit(':').next().unwrap_or(principal);
    if tail.len() > 18 {
        format!("{}...{}", &tail[..8], &tail[tail.len() - 6..])
    } else {
        tail.to_owned()
    }
}

fn sender_display_label(
    sender: &str,
    account_did: &str,
    account_display_name: &str,
    participants: &[SpaceParticipant],
) -> String {
    if is_own_message_sender(sender, account_did) {
        return clean_participant_display_name(account_display_name, Some(account_did))
            .unwrap_or_else(|| "yougen".to_owned());
    }
    participants
        .iter()
        .find(|participant| participant.did == sender.trim())
        .and_then(|participant| participant.display_name.clone())
        .unwrap_or_else(|| short_principal_label(sender))
}

fn parse_discussion_principals(input: &str) -> Vec<String> {
    let mut principals = Vec::new();
    for candidate in input.split(|ch: char| matches!(ch, ',' | '\n' | '\r' | '\t' | ';')) {
        let trimmed = candidate.trim();
        if !trimmed.is_empty() && !principals.iter().any(|existing| existing == trimmed) {
            principals.push(trimmed.to_owned());
        }
    }
    principals
}

fn discussion_participants(actor: &str, input: &str) -> Vec<String> {
    let mut participants = Vec::new();
    if !actor.trim().is_empty() {
        participants.push(actor.trim().to_owned());
    }
    for principal in parse_discussion_principals(input) {
        if !participants.iter().any(|existing| existing == &principal) {
            participants.push(principal);
        }
    }
    participants
}

fn current_mention_query(text: &str) -> Option<(usize, String)> {
    for (idx, ch) in text.char_indices().rev() {
        if ch == '@' {
            let preceding_ok = text[..idx]
                .chars()
                .next_back()
                .is_none_or(|c| matches!(c, ' ' | '\t' | '\n' | '\r' | ',' | ';'));
            if preceding_ok {
                let query_start = idx + '@'.len_utf8();
                return Some((idx, text[query_start..].to_owned()));
            }
            return None;
        }
        if matches!(ch, ' ' | '\t' | '\n' | '\r' | ',' | ';') {
            return None;
        }
    }
    None
}

fn apply_mention_completion(current: &str, replacement: &str) -> String {
    if let Some((idx, _)) = current_mention_query(current) {
        let mut out = current[..idx].to_owned();
        out.push_str(replacement);
        out.push_str(", ");
        out
    } else {
        let trimmed = current.trim_end_matches(|c: char| c.is_whitespace() || c == ',');
        let mut out = trimmed.to_owned();
        if !out.is_empty() {
            out.push_str(", ");
        }
        out.push_str(replacement);
        out.push_str(", ");
        out
    }
}

fn chat_message_create_operation(
    space_id: &str,
    actor: &str,
    flow_id: &str,
    channel_kind: &str,
    message_id: &str,
    body: &str,
    mentions: &[StructuredMention],
    reply_to: Option<&str>,
) -> crate::operation::OperationEnvelope {
    let mention_values = mentions_to_json(mentions);
    let mention_relations = mention_relation_json(message_id, mentions);
    OperationBuilder::new(space_id, actor, "cx.message.create")
        .target_ref(flow_id)
        .body(json!({
            "body": body,
            "branch": "discussion",
            "content": {
                "blocks": [{"kind": "text", "text": body}],
                "body": body,
                "mentions": mention_values.clone(),
            },
            "encrypted": false,
            "flow_id": flow_id,
            "kind": channel_kind,
            "message_id": message_id,
            "mentions": mention_values,
            "mention_relations": mention_relations,
            "reply_to": reply_to,
            "thread_id": reply_to,
        }))
        .build("yougen")
}

fn chat_send_error_message(error: &anyhow::Error) -> String {
    if is_auth_expired_error(error) {
        "Session expired while sending. Refresh the session or sign in again, then retry."
            .to_owned()
    } else if is_plaintext_visibility_policy_error(error) {
        "Plaintext is not enabled for this Space on the current service. Send Secure or update Space plaintext visibility."
            .to_owned()
    } else {
        error.to_string()
    }
}

fn collect_plaintext_services(value: &Value, services: &mut Vec<String>) {
    if let Some(items) = value
        .get("plaintext_visible_services")
        .and_then(Value::as_array)
    {
        for item in items {
            if let Some(service) = item.as_str() {
                let service = service.trim();
                if !service.is_empty() && !services.iter().any(|existing| existing == service) {
                    services.push(service.to_owned());
                }
            }
        }
    }
}

fn plaintext_services_for_policy(projection: Option<&Value>, service_did: &str) -> Vec<String> {
    let mut services = Vec::new();
    if let Some(projection) = projection {
        collect_plaintext_services(projection, &mut services);
        if let Some(summary) = projection.get("summary") {
            collect_plaintext_services(summary, &mut services);
        }
    }
    let service_did = service_did.trim();
    if !service_did.is_empty() && !services.iter().any(|existing| existing == service_did) {
        services.push(service_did.to_owned());
    }
    services
}

fn value_string_at<'a>(value: &'a Value, keys: &[&str]) -> Option<&'a str> {
    keys.iter()
        .find_map(|key| value.get(*key).and_then(Value::as_str))
}

fn collect_message_candidates<'a>(value: &'a Value, out: &mut Vec<&'a Value>, depth: usize) {
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

fn message_candidates(event: &Value) -> Vec<&Value> {
    let mut candidates = Vec::new();
    collect_message_candidates(event, &mut candidates, 0);
    candidates
}

fn first_string_in_candidates<'a>(candidates: &[&'a Value], keys: &[&str]) -> Option<&'a str> {
    candidates
        .iter()
        .find_map(|candidate| value_string_at(candidate, keys))
}

fn message_kind_is_create(value: &Value) -> bool {
    value_string_at(value, &["kind", "type", "op_type", "event_type"]) == Some("cx.message.create")
}

fn text_from_blocks(value: &Value) -> Option<&str> {
    value
        .get("blocks")
        .and_then(Value::as_array)
        .and_then(|blocks| blocks.first())
        .and_then(|block| block.get("text"))
        .and_then(Value::as_str)
}

fn text_body_from_value(value: &Value) -> Option<&str> {
    value_string_at(value, &["body", "text", "message", "plain_text"])
        .or_else(|| text_from_blocks(value))
        .or_else(|| {
            value
                .get("content")
                .filter(|content| content.is_object())
                .and_then(text_body_from_value)
        })
}

fn text_body_from_message(candidates: &[&Value]) -> Option<String> {
    candidates
        .iter()
        .find_map(|candidate| text_body_from_value(candidate))
        .map(ToOwned::to_owned)
}

fn short_message_time(value: Option<&str>) -> String {
    value
        .and_then(|raw| chrono::DateTime::parse_from_rfc3339(raw).ok())
        .map(|time| time.format("%H:%M").to_string())
        .or_else(|| value.map(ToOwned::to_owned))
        .unwrap_or_default()
}

fn mentions_from_value(value: &Value) -> Vec<StructuredMention> {
    value
        .as_array()
        .map(|items| {
            items
                .iter()
                .filter_map(|item| {
                    let target = item.get("target").and_then(Value::as_str)?;
                    Some(StructuredMention {
                        kind: item
                            .get("kind")
                            .and_then(Value::as_str)
                            .unwrap_or("ref")
                            .to_owned(),
                        target: target.to_owned(),
                        token: item
                            .get("token")
                            .and_then(Value::as_str)
                            .unwrap_or(target)
                            .to_owned(),
                    })
                })
                .collect()
        })
        .unwrap_or_default()
}

fn mentions_from_candidates(candidates: &[&Value]) -> Vec<StructuredMention> {
    candidates
        .iter()
        .find_map(|candidate| {
            candidate
                .get("mentions")
                .or_else(|| {
                    candidate
                        .get("content")
                        .and_then(|content| content.get("mentions"))
                })
                .map(mentions_from_value)
                .filter(|mentions| !mentions.is_empty())
        })
        .unwrap_or_default()
}

fn seq_from_candidates(candidates: &[&Value]) -> Option<u64> {
    candidates.iter().find_map(|candidate| {
        candidate
            .get("actor_seq")
            .and_then(Value::as_u64)
            .or_else(|| {
                candidate
                    .get("causal")
                    .and_then(|causal| causal.get("actor_seq"))
                    .and_then(Value::as_u64)
            })
    })
}

fn chat_message_from_event(space_id: &str, event: &Value) -> Option<ChatMessage> {
    let candidates = message_candidates(event);
    let body = text_body_from_message(&candidates)?;
    let explicit_message_kind = candidates
        .iter()
        .any(|candidate| message_kind_is_create(candidate));
    let message_payload_shape =
        first_string_in_candidates(&candidates, &["message_id", "flow_id", "thread_id"]).is_some();
    if !explicit_message_kind && !message_payload_shape {
        return None;
    }
    if let Some(seq) = seq_from_candidates(&candidates) {
        observe_seq(seq);
    }
    let event_id = value_string_at(event, &["event_id", "id"])
        .or_else(|| first_string_in_candidates(&candidates, &["event_id", "message_id", "id"]))
        .unwrap_or("event:unknown")
        .to_owned();
    let flow_id = first_string_in_candidates(&candidates, &["flow_id", "thread_id"])
        .or_else(|| {
            event
                .get("unsigned")
                .and_then(|unsigned| unsigned.get("local_target_ref"))
                .and_then(Value::as_str)
        })
        .filter(|value| value.starts_with("cx:flow:"))
        .unwrap_or("cx:flow:general")
        .to_owned();
    Some(ChatMessage {
        space_id: first_string_in_candidates(&candidates, &["space_id"])
            .unwrap_or(space_id)
            .to_owned(),
        id: event_id,
        sender: first_string_in_candidates(
            &candidates,
            &["sender", "sender_id", "actor_id", "actor"],
        )
        .unwrap_or("did:web:unknown")
        .to_owned(),
        body,
        timestamp: short_message_time(first_string_in_candidates(
            &candidates,
            &["created_at", "timestamp", "origin_server_ts"],
        )),
        flow_id,
        reply_to: first_string_in_candidates(&candidates, &["reply_to", "thread_id"])
            .map(ToOwned::to_owned),
        reactions: Vec::new(),
        redacted: false,
        edited: false,
        revisions: Vec::new(),
        pending: false,
        failed: false,
        error: None,
        mentions: mentions_from_candidates(&candidates),
    })
}

fn chat_messages_from_events(space_id: &str, events: &[Value]) -> Vec<ChatMessage> {
    events
        .iter()
        .filter_map(|event| chat_message_from_event(space_id, event))
        .collect()
}

fn chat_messages_from_sync_spaces(
    spaces: &std::collections::BTreeMap<String, Value>,
) -> Vec<ChatMessage> {
    let mut messages = Vec::new();
    for (space_id, body) in spaces {
        let Some(timeline_events) = body
            .get("timeline")
            .and_then(|timeline| timeline.get("events"))
            .and_then(Value::as_array)
        else {
            continue;
        };
        messages.extend(chat_messages_from_events(space_id, timeline_events));
    }
    messages
}

fn chat_messages_from_local_state(state: &ClientLocalState) -> Vec<ChatMessage> {
    state
        .raw_operations
        .iter()
        .filter_map(|record| {
            chat_message_from_event(
                record.space_id.as_deref().unwrap_or_default(),
                &record.payload,
            )
        })
        .collect()
}

fn bool_at_path(value: &Value, path: &[&str]) -> Option<bool> {
    let mut current = value;
    for key in path {
        current = current.get(*key)?;
    }
    current.as_bool()
}

fn string_at_path<'a>(value: &'a Value, path: &[&str]) -> Option<&'a str> {
    let mut current = value;
    for key in path {
        current = current.get(*key)?;
    }
    current.as_str()
}

fn first_string_in_candidate_paths<'a>(
    candidates: &[&'a Value],
    paths: &[&[&str]],
) -> Option<&'a str> {
    candidates.iter().find_map(|candidate| {
        paths
            .iter()
            .find_map(|path| string_at_path(candidate, path))
    })
}

fn candidate_has_track(candidate: &Value, track: &str) -> bool {
    candidate
        .get("tracks")
        .and_then(|tracks| tracks.get(track))
        .is_some()
        || candidate
            .get("flow")
            .and_then(|flow| flow.get("tracks"))
            .and_then(|tracks| tracks.get(track))
            .is_some()
}

fn flow_create_has_discussion_track(candidates: &[&Value]) -> bool {
    candidates
        .iter()
        .any(|candidate| candidate_has_track(candidate, "discussion"))
}

fn flow_create_has_synthesis_track(candidates: &[&Value]) -> bool {
    candidates
        .iter()
        .any(|candidate| candidate_has_track(candidate, "synthesis"))
        || candidates.iter().any(|candidate| {
            bool_at_path(candidate, &["create_card"]).unwrap_or(false)
                || bool_at_path(candidate, &["fields", "has_synthesis"]).unwrap_or(false)
                || bool_at_path(candidate, &["flow", "fields", "has_synthesis"]).unwrap_or(false)
        })
}

fn channel_from_flow_event(_space_id: &str, event: &Value) -> Option<ChannelEntity> {
    let candidates = message_candidates(event);
    if !candidates
        .iter()
        .any(|candidate| value_string_at(candidate, &["kind", "type"]) == Some("cx.flow.create"))
    {
        return None;
    }
    if !flow_create_has_discussion_track(&candidates)
        && !candidates.iter().any(|candidate| {
            value_string_at(candidate, &["branch"]) == Some("discussion")
                || value_string_at(candidate, &["category"]) == Some("discussion")
        })
    {
        return None;
    }

    let flow_id = first_string_in_candidate_paths(
        &candidates,
        &[
            &["flow_id"],
            &["target_ref"],
            &["flow", "id"],
            &["flow", "flow_id"],
        ],
    )?
    .trim();
    if !flow_id.starts_with("cx:flow:") {
        return None;
    }

    let name = first_string_in_candidate_paths(
        &candidates,
        &[&["title"], &["name"], &["flow", "title"], &["flow", "name"]],
    )
    .unwrap_or(flow_id)
    .to_owned();
    let category = first_string_in_candidate_paths(
        &candidates,
        &[
            &["category"],
            &["fields", "category"],
            &["flow", "fields", "category"],
        ],
    )
    .unwrap_or("general")
    .to_owned();
    let topic = first_string_in_candidate_paths(
        &candidates,
        &[
            &["summary"],
            &["topic"],
            &["description"],
            &["flow", "summary"],
            &["flow", "topic"],
            &["flow", "description"],
        ],
    )
    .map(ToOwned::to_owned);
    let has_synthesis = flow_create_has_synthesis_track(&candidates);

    Some(ChannelEntity {
        flow_id: flow_id.to_owned(),
        name,
        kind: if has_synthesis {
            "flow".to_owned()
        } else {
            "discussion".to_owned()
        },
        category,
        topic,
        unread: 0,
    })
}

fn channels_from_events(space_id: &str, events: &[Value]) -> Vec<ChannelEntity> {
    events
        .iter()
        .filter_map(|event| channel_from_flow_event(space_id, event))
        .collect()
}

fn channels_from_sync_spaces(
    spaces: &std::collections::BTreeMap<String, Value>,
) -> Vec<ChannelEntity> {
    let mut channels = Vec::new();
    for (space_id, body) in spaces {
        let Some(timeline_events) = body
            .get("timeline")
            .and_then(|timeline| timeline.get("events"))
            .and_then(Value::as_array)
        else {
            continue;
        };
        channels.extend(channels_from_events(space_id, timeline_events));
    }
    channels
}

fn channels_from_local_state(state: &ClientLocalState) -> Vec<ChannelEntity> {
    state
        .raw_operations
        .iter()
        .filter_map(|record| {
            channel_from_flow_event(
                record.space_id.as_deref().unwrap_or_default(),
                &record.payload,
            )
        })
        .collect()
}

fn merge_channels(target: &mut Vec<ChannelEntity>, incoming: Vec<ChannelEntity>) {
    for channel in incoming {
        if let Some(existing) = target
            .iter_mut()
            .find(|candidate| candidate.flow_id == channel.flow_id)
        {
            *existing = channel;
        } else {
            target.push(channel);
        }
    }
}

fn merge_chat_messages(target: &mut Vec<ChatMessage>, incoming: Vec<ChatMessage>) {
    for message in incoming {
        if !target.iter().any(|existing| existing.id == message.id) {
            target.push(message);
        }
    }
}

async fn submit_chat_operation_with_plaintext_retry(
    api: &ContrixApi,
    space_id: &str,
    plaintext_visible_services: &[String],
    operation: &OperationEnvelope,
) -> anyhow::Result<SubmitEventResponse> {
    match api.submit_operation_event(operation).await {
        Ok(response) => Ok(response),
        Err(error) if is_plaintext_visibility_policy_error(&error) => {
            let mut services = plaintext_visible_services.to_vec();
            if services.is_empty()
                && let Ok(description) = api.describe().await
                && !description.service_did.trim().is_empty()
            {
                services.push(description.service_did);
            }
            if services.is_empty() {
                return Err(error);
            }
            api.update_space(
                space_id,
                json!({"plaintext_visible_services": services}),
            )
            .await
            .map_err(|update_error| {
                anyhow::anyhow!(
                    "plaintext policy update failed: {update_error}; original send failed: {error}"
                )
            })?;
            api.submit_operation_event(operation).await
        }
        Err(error) => Err(error),
    }
}

#[component]
pub fn ChatPanel(
    base_url: String,
    plaintext_service_did: String,
    account_did: String,
    token: Signal<String>,
    selected_space: String,
    selected_space_scope: Vec<String>,
    sync_cursor: Signal<String>,
    frontier_state: Signal<String>,
    state_store: Signal<LocalStateStore>,
) -> Element {
    let navigator = use_navigator();
    let mut channels = use_signal(Vec::<ChannelEntity>::new);
    let mut selected_channel = use_signal(String::new);
    let mut messages = use_signal(Vec::<ChatMessage>::new);
    let mut chat_draft = use_signal(String::new);
    let mut new_channel_name = use_signal(String::new);
    let mut new_channel_topic = use_signal(String::new);
    let mut new_channel_members = use_signal(String::new);
    let mut new_channel_create_card = use_signal(|| false);
    let mut create_dialog_open = use_signal(|| false);
    let mut status_msg = use_signal(String::new);
    let mut reply_to_message = use_signal(|| Option::<String>::None);
    let mut editing_message = use_signal(|| Option::<String>::None);
    let mut edit_draft = use_signal(String::new);
    let mut redact_confirm = use_signal(|| Option::<String>::None);
    let mut reaction_picker = use_signal(|| Option::<String>::None);
    let mut initial_sync_requested = use_signal(|| false);
    let account_display_name = use_signal(String::new);
    let mut track_filter = use_signal(|| "discussion_only".to_owned());
    let mut left_panel_open = use_signal(|| true);
    let mut right_panel = use_signal(|| Option::<DiscussionSidePanel>::None);
    let selected_channel_value = selected_channel();
    let all_channels = channels();
    let filter_value = track_filter();
    let visible_channels: Vec<ChannelEntity> = all_channels
        .iter()
        .filter(|channel| filter_value == "with_discussion_track" || channel.kind == "discussion")
        .cloned()
        .collect();
    let visible_channels_empty = visible_channels.is_empty();
    let selected_channel_info = visible_channels
        .iter()
        .find(|channel| channel.flow_id == selected_channel_value)
        .cloned()
        .or_else(|| visible_channels.first().cloned());
    let selected_channel_name = selected_channel_info
        .as_ref()
        .map(|channel| channel.name.clone())
        .unwrap_or_else(|| "Select a discussion".to_owned());
    let selected_channel_category = selected_channel_info
        .as_ref()
        .map(|channel| channel.category.clone())
        .unwrap_or_else(|| "discussion".to_owned());
    let selected_channel_unread = selected_channel_info
        .as_ref()
        .map(|channel| channel.unread)
        .unwrap_or(0);
    let visible_messages = messages()
        .iter()
        .filter(|msg| {
            msg.flow_id == selected_channel_value
                && (selected_space_scope.is_empty()
                    || selected_space_scope
                        .iter()
                        .any(|space| space == &msg.space_id))
        })
        .cloned()
        .collect::<Vec<_>>();
    let visible_message_count = visible_messages.len();
    let left_open = left_panel_open();
    let active_right_panel = right_panel();
    let right_open = active_right_panel.is_some();
    let shell_class = format!(
        "discussion-shell{}{}",
        if left_open { "" } else { " left-collapsed" },
        if right_open { "" } else { " right-collapsed" }
    );
    let participant_projection = state_store
        .read()
        .load()
        .space_projections
        .get(&selected_space)
        .cloned();
    let participants = space_participants(participant_projection.as_ref(), &account_did);
    let participants_for_messages = participants.clone();
    let account_display_label = account_display_name();

    if !initial_sync_requested() && !token().trim().is_empty() {
        initial_sync_requested.set(true);
        let base = base_url.clone();
        let api_token = token();
        let wait_for = active_sync_token(&sync_cursor());
        let selected_space_for_load = selected_space.clone();
        let selected_scope_for_load = selected_space_scope.clone();
        let account_did_for_load = account_did.clone();
        let mut account_display_name_for_load = account_display_name;
        spawn(async move {
            let Ok(api) = authed_api_with_sync(&base, api_token, wait_for) else {
                return;
            };
            let mut loaded_messages = chat_messages_from_local_state(&state_store.read().load());
            if let Ok(account) = api.account_me().await
                && account.did == account_did_for_load
                && let Some(display_name) = clean_participant_display_name(
                    account.display_name.as_deref().unwrap_or(""),
                    Some(&account_did_for_load),
                )
            {
                account_display_name_for_load.set(display_name);
            }
            if let Ok(sync) = api.sync(None).await {
                {
                    let mut store = state_store.write();
                    store.save_sync_cursor(sync.next_batch.clone());
                    for (space_id, projection) in &sync.spaces {
                        store.save_space_projection(space_id.clone(), projection.clone());
                    }
                }
                loaded_messages.extend(chat_messages_from_sync_spaces(&sync.spaces));
                merge_channels(
                    &mut channels.write(),
                    channels_from_sync_spaces(&sync.spaces),
                );
                sync_cursor.set(sync.next_batch);
            }

            let spaces_to_backfill = if selected_scope_for_load.is_empty() {
                vec![selected_space_for_load]
            } else {
                selected_scope_for_load
            };
            for space_id in spaces_to_backfill {
                if space_id.trim().is_empty() {
                    continue;
                }
                if let Ok(backfill) = api.backfill(&space_id).await {
                    merge_channels(
                        &mut channels.write(),
                        channels_from_events(&space_id, &backfill.events),
                    );
                    loaded_messages.extend(chat_messages_from_events(&space_id, &backfill.events));
                }
            }

            merge_channels(
                &mut channels.write(),
                channels_from_local_state(&state_store.read().load()),
            );
            if selected_channel().trim().is_empty() {
                if let Some(first_channel) = channels.read().first() {
                    selected_channel.set(first_channel.flow_id.clone());
                }
            }
            if !loaded_messages.is_empty() {
                merge_chat_messages(&mut messages.write(), loaded_messages);
            }
        });
    }

    rsx! {
        div { class: "{shell_class}", "data-testid": "chat-panel",
            if left_open {
                aside { class: "discussion-panel discussion-sidebar-panel", "data-testid": "discussion-list-panel",
                    div { class: "discussion-panel-head",
                        div { class: "discussion-title-row",
                            h2 { "Discussions" }
                            HelpTip { text: "Only discussion tracks under this Space are listed. Use the alternate filter to include other flows that expose a discussion track." }
                        }
                        div { class: "discussion-panel-head-actions",
                            button {
                                class: "primary icon-button",
                                "aria-label": "New discussion",
                                title: "New discussion",
                                "data-testid": "open-channel-dialog",
                                onclick: move |_| create_dialog_open.set(true),
                                UiIcon { name: "plus" }
                            }
                            button {
                                class: "secondary icon-button",
                                "aria-label": "Hide discussion list",
                                "data-testid": "collapse-discussion-list",
                                onclick: move |_| left_panel_open.set(false),
                                UiIcon { name: "panel-left-close" }
                            }
                        }
                    }
                    div { class: "discussion-filter segmented-control",
                        button {
                            class: if track_filter() == "discussion_only" { "segment active" } else { "segment" },
                            "data-testid": "discussion-filter-only",
                            onclick: move |_| track_filter.set("discussion_only".to_owned()),
                            "Discussion only"
                        }
                        button {
                            class: if track_filter() == "with_discussion_track" { "segment active" } else { "segment" },
                            "data-testid": "discussion-filter-track",
                            onclick: move |_| track_filter.set("with_discussion_track".to_owned()),
                            "Has discussion"
                        }
                    }
                    div { class: "discussion-list", "data-testid": "channel-list",
                        for channel in visible_channels {
                            button {
                                class: if channel.flow_id == selected_channel() { "discussion-track-row active" } else { "discussion-track-row" },
                                "data-testid": "channel-item",
                                onclick: {
                                    let id = channel.flow_id.clone();
                                    move |_| selected_channel.set(id.clone())
                                },
                                div { class: "discussion-track-main",
                                    span { class: "discussion-track-name", "{channel.name}" }
                                    span { class: "discussion-track-topic",
                                        if let Some(topic) = &channel.topic {
                                            "{topic}"
                                        } else {
                                            "No topic"
                                        }
                                    }
                                }
                                div { class: "discussion-track-meta",
                                    span { class: "badge", "{channel.category}" }
                                    if channel.unread > 0 {
                                        span { class: "badge accent", "{channel.unread}" }
                                    }
                                }
                            }
                        }
                        if visible_channels_empty {
                            div { class: "discussion-empty", "data-testid": "empty-discussion-list", "No discussions yet." }
                        }
                    }
                }
            } else {
                div { class: "discussion-rail discussion-left-rail", "data-testid": "discussion-list-rail",
                    button {
                        class: "secondary icon-button",
                        "aria-label": "Show discussion list",
                        "data-testid": "expand-discussion-list",
                        onclick: move |_| left_panel_open.set(true),
                        UiIcon { name: "panel-left-open" }
                    }
                }
            }

            if create_dialog_open() {
                div { class: "discussion-modal-backdrop", "data-testid": "channel-create-modal",
                    div { class: "discussion-modal", role: "dialog", "aria-modal": "true", "aria-label": "New discussion",
                        div { class: "discussion-modal-head",
                            div { class: "discussion-title-row",
                                h2 { "New Discussion" }
                                HelpTip { text: "Creates a Flow with a primary discussion track. Enable the card option when the same Flow should also carry a synthesis track." }
                            }
                            button {
                                class: "secondary icon-button",
                                "aria-label": "Close",
                                "data-testid": "close-channel-dialog",
                                onclick: move |_| create_dialog_open.set(false),
                                UiIcon { name: "x" }
                            }
                        }
                        div { class: "discussion-modal-body workflow-form",
                            label { "Title" }
                            input {
                                "data-testid": "new-channel-name",
                                value: "{new_channel_name}",
                                placeholder: "Discussion title",
                                oninput: move |evt| new_channel_name.set(evt.value()),
                            }
                            label { "Summary" }
                            input {
                                "data-testid": "new-channel-topic",
                                value: "{new_channel_topic}",
                                placeholder: "Short purpose or context",
                                oninput: move |evt| new_channel_topic.set(evt.value()),
                            }
                            label { "Users" }
                            textarea {
                                "data-testid": "new-channel-members",
                                value: "{new_channel_members}",
                                rows: "3",
                                placeholder: "did:web:bob.example  (type @ to search)",
                                oninput: move |evt| new_channel_members.set(evt.value()),
                            }
                            {
                                let members_text = new_channel_members();
                                let mention = current_mention_query(&members_text);
                                let suggestions: Vec<SpaceParticipant> = if let Some((_, ref query)) = mention {
                                    let query_lower = query.to_ascii_lowercase();
                                    let already: Vec<String> = parse_discussion_principals(&members_text);
                                    participants
                                        .iter()
                                        .filter(|p| !p.is_self)
                                        .filter(|p| !already.iter().any(|d| d == &p.did))
                                        .filter(|p| {
                                            if query_lower.is_empty() {
                                                return true;
                                            }
                                            if p.did.to_ascii_lowercase().contains(&query_lower) {
                                                return true;
                                            }
                                            p.display_name
                                                .as_deref()
                                                .map(|n| n.to_ascii_lowercase().contains(&query_lower))
                                                .unwrap_or(false)
                                        })
                                        .take(6)
                                        .cloned()
                                        .collect()
                                } else {
                                    Vec::new()
                                };
                                rsx! {
                                    if mention.is_some() && !suggestions.is_empty() {
                                        div {
                                            class: "mention-suggestions",
                                            "data-testid": "new-channel-members-suggestions",
                                            for participant in suggestions {
                                                {
                                                    let did_for_click = participant.did.clone();
                                                    let did_for_label = participant.did.clone();
                                                    let display = participant
                                                        .display_name
                                                        .clone()
                                                        .unwrap_or_else(|| short_principal_label(&participant.did));
                                                    rsx! {
                                                        button {
                                                            r#type: "button",
                                                            class: "mention-suggestion-item",
                                                            "data-testid": "new-channel-members-suggestion",
                                                            onclick: move |_| {
                                                                let next = apply_mention_completion(
                                                                    &new_channel_members(),
                                                                    &did_for_click,
                                                                );
                                                                new_channel_members.set(next);
                                                            },
                                                            span { class: "mention-suggestion-name", "{display}" }
                                                            span { class: "mention-suggestion-did muted", "{did_for_label}" }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                            label { class: "discussion-checkbox-row",
                                input {
                                    r#type: "checkbox",
                                    "data-testid": "new-channel-create-card",
                                    checked: new_channel_create_card(),
                                    onchange: move |evt| new_channel_create_card.set(evt.value() == "true"),
                                }
                                span { "Create matching Card" }
                            }
                        }
                        div { class: "discussion-modal-actions",
                            button {
                                class: "secondary",
                                "data-testid": "cancel-channel-create",
                                onclick: move |_| create_dialog_open.set(false),
                                "Cancel"
                            }
                            button {
                                class: "primary",
                                "data-testid": "create-channel-button",
                                onclick: {
                                    let base = base_url.clone();
                                    let actor = account_did.clone();
                                    let space = selected_space.clone();
                                    move |_| {
                                        let title = new_channel_name().trim().to_owned();
                                        if title.is_empty() {
                                            status_msg.set("Discussion title is required".to_owned());
                                            return;
                                        }
                                        let category = "general".to_owned();
                                        let summary = new_channel_topic().trim().to_owned();
                                        let member_text = new_channel_members();
                                        let create_card = new_channel_create_card();
                                        let participants = discussion_participants(&actor, &member_text);
                                        let flow_id = format!("cx:flow:{}", uuid_v7());
                                        let rank = format!("r{}", chrono::Utc::now().timestamp_millis());
                                        let op = match cx_ops::discussion_flow_create(
                                            &space,
                                            &actor,
                                            &flow_id,
                                            &title,
                                        ) {
                                            Ok(builder) => {
                                                let mut op = builder.build("yougen");
                                                op.body["category"] = json!(category.clone());
                                                op.body["participants"] = json!(participants.clone());
                                                op.body["create_card"] = json!(create_card);
                                                if !op.body.get("fields").is_some_and(|fields| fields.is_object()) {
                                                    op.body["fields"] = json!({});
                                                }
                                                op.body["fields"]["category"] = json!(category.clone());
                                                op.body["fields"]["participants"] = json!(participants.clone());
                                                op.body["fields"]["has_synthesis"] = json!(create_card);
                                                if !op.body["flow"]
                                                    .get("fields")
                                                    .is_some_and(|fields| fields.is_object())
                                                {
                                                    op.body["flow"]["fields"] = json!({});
                                                }
                                                op.body["flow"]["fields"]["category"] =
                                                    json!(category.clone());
                                                op.body["flow"]["fields"]["participants"] =
                                                    json!(participants.clone());
                                                op.body["flow"]["fields"]["has_synthesis"] =
                                                    json!(create_card);
                                                op.body["rank"] = json!(rank.clone());
                                                if !summary.is_empty() {
                                                    op.body["summary"] = json!(summary.clone());
                                                    op.body["flow"]["summary"] = json!(summary.clone());
                                                }
                                                if !create_card {
                                                    if let Some(tracks) = op.body["flow"]["tracks"].as_object_mut() {
                                                        tracks.remove("synthesis");
                                                    }
                                                }
                                                op
                                            }
                                            Err(error) => {
                                                status_msg.set(format!(
                                                    "Could not create discussion: {error}"
                                                ));
                                                return;
                                            }
                                        };
                                        let api_token = token();
                                        let wait_for = active_sync_token(&sync_cursor());
                                        let channel_topic = if summary.is_empty() { None } else { Some(summary) };
                                        let base = base.clone();
                                        let space = space.clone();
                                        status_msg.set("Creating discussion".to_owned());
                                        spawn(async move {
                                            match authed_api_with_sync(&base, api_token, wait_for) {
                                                Ok(api) => match api
                                                        .submit_operation_event(&op)
                                                        .await
                                                    {
                                                        Ok(submitted) => {
                                                            channels.write().push(ChannelEntity {
                                                                flow_id: flow_id.clone(),
                                                                name: title.clone(),
                                                                kind: "discussion".to_owned(),
                                                                category: category.clone(),
                                                                topic: channel_topic.clone(),
                                                                unread: 0,
                                                            });
                                                            selected_channel.set(flow_id.clone());
                                                            frontier_state.set(submitted.event_id.clone());
                                                            sync_cursor.set(submitted.sync_token.clone());
                                                            {
                                                                let mut store = state_store.write();
                                                                store.save_sync_cursor(submitted.sync_token.clone());
                                                                store.append_raw_operation(
                                                                    op.operation_id.clone(),
                                                                    Some(space.clone()),
                                                                    json!({
                                                                        "flow_id": flow_id,
                                                                        "kind": "cx.flow.create",
                                                                        "title": title,
                                                                        "category": category,
                                                                        "summary": channel_topic,
                                                                        "create_card": create_card,
                                                                        "flow": op.body["flow"].clone(),
                                                                        "event_id": submitted.event_id,
                                                                    }),
                                                                );
                                                            }
                                                            status_msg.set("Discussion created".to_owned());
                                                            new_channel_name.set(String::new());
                                                            new_channel_topic.set(String::new());
                                                            new_channel_members.set(String::new());
                                                            new_channel_create_card.set(false);
                                                            create_dialog_open.set(false);
                                                        }
                                                        Err(error) => status_msg.set(format!("Discussion create failed: {error}")),
                                                    },
                                                    Err(error) => status_msg.set(format!("Invalid server URL: {error}")),
                                                }
                                            });
                                        }
                                    },
                                "Create"
                            }
                        }
                    }
                }
            }

            section { class: "discussion-panel discussion-main-panel", "data-testid": "discussion-main-panel",
                header { class: "discussion-chat-head",
                    div { class: "discussion-title-stack",
                        div { class: "discussion-title-row",
                            h1 { "{selected_channel_name}" }
                        }
                    }
                    div { class: "discussion-head-actions",
                        button {
                            class: if active_right_panel == Some(DiscussionSidePanel::Settings) { "secondary icon-button active" } else { "secondary icon-button" },
                            "aria-label": "Settings",
                            title: "Settings",
                            "data-testid": "discussion-settings-toggle",
                            onclick: move |_| {
                                let next_panel = if right_panel() == Some(DiscussionSidePanel::Settings) {
                                    None
                                } else {
                                    Some(DiscussionSidePanel::Settings)
                                };
                                right_panel.set(next_panel);
                            },
                            UiIcon { name: "settings" }
                        }
                        button {
                            class: if active_right_panel == Some(DiscussionSidePanel::Users) { "secondary icon-button active" } else { "secondary icon-button" },
                            "aria-label": "Users",
                            title: "Users",
                            "data-testid": "discussion-users-toggle",
                            onclick: move |_| {
                                let next_panel = if right_panel() == Some(DiscussionSidePanel::Users) {
                                    None
                                } else {
                                    Some(DiscussionSidePanel::Users)
                                };
                                right_panel.set(next_panel);
                            },
                            UiIcon { name: "users" }
                        }
                    }
                }

                div { class: "discussion-chat-feed", "data-testid": "message-list",
                    for msg in visible_messages {
                        div {
                            class: if is_own_message_sender(&msg.sender, &account_did) {
                                if msg.failed { "discussion-message is-own is-failed" } else { "discussion-message is-own" }
                            } else if msg.failed {
                                "discussion-message is-failed"
                            } else {
                                "discussion-message"
                            },
                            "data-testid": "chat-message",
                            div { class: "msg-body",
                                div { class: "msg-head",
                                    span { class: "name", "{sender_display_label(&msg.sender, &account_did, &account_display_label, &participants_for_messages)}" }
                                    time { "{msg.timestamp}" }
                                    if msg.failed {
                                        span { class: "message-failure-icon", title: "Message send failed",
                                            UiIcon { name: "alert" }
                                        }
                                        span { class: "badge badge-error", "failed" }
                                    } else if msg.pending {
                                        span { class: "badge", "pending" }
                                    }
                                    if msg.edited { span { class: "badge", "edited" } }
                                }
                                if msg.reply_to.is_some() {
                                    div { class: "muted", "data-testid": "chat-reply-indicator", "Replying to a message" }
                                }
                                if msg.redacted {
                                    div { class: "msg-content redacted", "data-testid": "chat-redacted-tombstone", "[Message redacted]" }
                                } else {
                                    div { class: "msg-content", "{msg.body}" }
                                }
                                if !msg.mentions.is_empty() {
                                    div { class: "actions chat-chip-row", "data-testid": "chat-mentions",
                                        for mention in &msg.mentions {
                                            span { class: "badge", "{mention.target}" }
                                        }
                                    }
                                }
                                if !msg.reactions.is_empty() {
                                    div { class: "actions chat-chip-row", "data-testid": "chat-reactions",
                                        for (emoji, senders) in &msg.reactions {
                                            span { class: "badge", "{emoji} {senders.len()}" }
                                        }
                                    }
                                }
                                if !msg.revisions.is_empty() {
                                    div { class: "section chat-revision-stack", "data-testid": "chat-revision-chain",
                                        div { class: "muted", "Edited versions ({msg.revisions.len()})" }
                                        for revision in &msg.revisions {
                                            div { class: "muted", "{revision}" }
                                        }
                                    }
                                }
                                if msg.failed {
                                    div { class: "message-error-row", "data-testid": "chat-message-error",
                                        span { class: "message-error-mark", "!" }
                                        span {
                                            if let Some(error) = &msg.error {
                                                "{error}"
                                            } else {
                                                "Message send failed"
                                            }
                                        }
                                        button {
                                            class: "message-retry-button",
                                            "data-testid": "chat-retry-button",
                                            onclick: {
                                                let base = base_url.clone();
                                                let service_did = plaintext_service_did.clone();
                                                let space = msg.space_id.clone();
                                                let actor = account_did.clone();
                                                let local_id = msg.id.clone();
                                                let body = msg.body.clone();
                                                let flow_id = msg.flow_id.clone();
                                                let mentions = msg.mentions.clone();
                                                let reply_to = msg.reply_to.clone();
                                                move |_| {
                                                    if let Some(found) = messages
                                                        .write()
                                                        .iter_mut()
                                                        .find(|candidate| candidate.id == local_id)
                                                    {
                                                        found.pending = true;
                                                        found.failed = false;
                                                        found.error = None;
                                                    }
                                                    status_msg.set("Retrying message".to_owned());
                                                    let base = base.clone();
                                                    let service_did = service_did.clone();
                                                    let space = space.clone();
                                                    let actor = actor.clone();
                                                    let api_token = token();
                                                    let wait_for = active_sync_token(&sync_cursor());
                                                    let message_id = local_id.clone();
                                                    let message_id_for_lookup = local_id.clone();
                                                    let message_id_for_store = message_id.clone();
                                                    let body_for_store = body.clone();
                                                    let actor_for_store = actor.clone();
                                                    let flow_id_for_store = flow_id.clone();
                                                    let reply_to_for_store = reply_to.clone();
                                                    let projection = state_store
                                                        .read()
                                                        .load()
                                                        .space_projections
                                                        .get(&space)
                                                        .cloned();
                                                    let plaintext_services = plaintext_services_for_policy(
                                                        projection.as_ref(),
                                                        &service_did,
                                                    );
                                                    let op = chat_message_create_operation(
                                                        &space,
                                                        &actor,
                                                        &flow_id,
                                                        "discussion",
                                                        &message_id,
                                                        &body,
                                                        &mentions,
                                                        reply_to.as_deref(),
                                                    );
                                                    let mention_values_for_store = mentions_to_json(&mentions);
                                                    let space_for_record = space.clone();
                                                    spawn(async move {
                                                        match authed_api_with_sync(&base, api_token, wait_for) {
                                                            Ok(api) => match submit_chat_operation_with_plaintext_retry(
                                                                &api,
                                                                &space,
                                                                &plaintext_services,
                                                                &op,
                                                            ).await {
                                                                Ok(resp) => {
                                                                    {
                                                                        let mut store = state_store.write();
                                                                        store.save_sync_cursor(resp.sync_token.clone());
                                                                        store.append_raw_operation(
                                                                            op.operation_id.clone(),
                                                                            Some(space_for_record),
                                                                            json!({
                                                                                "event_id": resp.event_id.clone(),
                                                                                "kind": "cx.message.create",
                                                                                "actor": actor_for_store,
                                                                                "body": body_for_store,
                                                                                "flow_id": flow_id_for_store,
                                                                                "message_id": message_id_for_store,
                                                                                "mentions": mention_values_for_store,
                                                                                "reply_to": reply_to_for_store,
                                                                                "status": resp.status.clone(),
                                                                            }),
                                                                        );
                                                                    }
                                                                    if let Some(found) = messages
                                                                        .write()
                                                                        .iter_mut()
                                                                        .find(|candidate| candidate.id == message_id_for_lookup)
                                                                    {
                                                                        found.id = resp.event_id.clone();
                                                                        found.pending = false;
                                                                        found.failed = false;
                                                                        found.error = None;
                                                                    }
                                                                    sync_cursor.set(resp.sync_token.clone());
                                                                    frontier_state.set(resp.event_id.clone());
                                                                    status_msg.set("Message sent".to_owned());
                                                                }
                                                                Err(error) => {
                                                                    let auth_expired = is_auth_expired_error(&error);
                                                                    let message = chat_send_error_message(&error);
                                                                    if let Some(found) = messages
                                                                        .write()
                                                                        .iter_mut()
                                                                        .find(|candidate| candidate.id == message_id_for_lookup)
                                                                    {
                                                                        found.pending = false;
                                                                        found.failed = true;
                                                                        found.error = Some(message.clone());
                                                                    }
                                                                    status_msg.set(format!("Message send failed: {message}"));
                                                                    if auth_expired {
                                                                        let _ = navigator.push(Route::Login);
                                                                    }
                                                                }
                                                            },
                                                            Err(error) => {
                                                                let message = format!("Invalid server URL: {error}");
                                                                if let Some(found) = messages
                                                                    .write()
                                                                    .iter_mut()
                                                                    .find(|candidate| candidate.id == message_id_for_lookup)
                                                                {
                                                                    found.pending = false;
                                                                    found.failed = true;
                                                                    found.error = Some(message.clone());
                                                                }
                                                                status_msg.set(message);
                                                            }
                                                        }
                                                    });
                                                }
                                            },
                                            "Retry"
                                        }
                                    }
                                }
                                if !msg.redacted {
                                    div { class: "actions chat-message-actions",
                                        button {
                                            class: "chat-message-action",
                                            "data-testid": "chat-reply-button",
                                            onclick: {
                                                let msg_id = msg.id.clone();
                                                move |_| reply_to_message.set(Some(msg_id.clone()))
                                            },
                                            "Reply"
                                        }
                                        button {
                                            class: "chat-message-action",
                                            "data-testid": "chat-react-button",
                                            onclick: {
                                                let msg_id = msg.id.clone();
                                                move |_| {
                                                    let current = reaction_picker();
                                                    reaction_picker.set(if current == Some(msg_id.clone()) { None } else { Some(msg_id.clone()) });
                                                }
                                            },
                                            "React"
                                        }
                                        button {
                                            class: "chat-message-action",
                                            "data-testid": "chat-edit-button",
                                            onclick: {
                                                let msg_id = msg.id.clone();
                                                let body = msg.body.clone();
                                                move |_| {
                                                    editing_message.set(Some(msg_id.clone()));
                                                    edit_draft.set(body.clone());
                                                }
                                            },
                                            "Edit"
                                        }
                                        button {
                                            class: "chat-message-action",
                                            "data-testid": "chat-redact-button",
                                            onclick: {
                                                let msg_id = msg.id.clone();
                                                move |_| redact_confirm.set(Some(msg_id.clone()))
                                            },
                                            "Redact"
                                        }
                                    }
                                }
                                if reaction_picker() == Some(msg.id.clone()) {
                                    div { class: "actions chat-chip-row", "data-testid": "chat-reaction-picker",
                                        for emoji in CHAT_EMOJI_GRID {
                                            button {
                                                class: "secondary emoji-button",
                                                onclick: {
                                                    let base = base_url.clone();
                                                    let space = selected_space.clone();
                                                    let actor = account_did.clone();
                                                    let msg_id = msg.id.clone();
                                                    let emoji = emoji.to_string();
                                                    move |_| {
                                                        if let Some(found) = messages.write().iter_mut().find(|candidate| candidate.id == msg_id) {
                                                            if let Some((_, senders)) = found.reactions.iter_mut().find(|(key, _)| key == &emoji) {
                                                                if !senders.iter().any(|sender| sender == &actor) {
                                                                    senders.push(actor.clone());
                                                                }
                                                            } else {
                                                                found.reactions.push((emoji.clone(), vec![actor.clone()]));
                                                            }
                                                        }
                                                        let base = base.clone();
                                                        let space = space.clone();
                                                        let actor = actor.clone();
                                                        let msg_id = msg_id.clone();
                                                        let emoji = emoji.clone();
                                                        let api_token = token();
                                                        let wait_for = active_sync_token(&sync_cursor());
                                                        spawn(async move {
                                                            if let Ok(api) = authed_api_with_sync(&base, api_token, wait_for) {
                                                                let op = chat_reaction_add_operation(&space, &actor, &msg_id, &emoji);
                                                                let _ = api.submit_operation_event(&op).await;
                                                            }
                                                        });
                                                        reaction_picker.set(None);
                                                    }
                                                },
                                                "{emoji}"
                                            }
                                        }
                                    }
                                }
                                if editing_message() == Some(msg.id.clone()) {
                                    div { class: "composer compact-composer", "data-testid": "chat-edit-composer",
                                        textarea {
                                            value: "{edit_draft}",
                                            oninput: move |evt| edit_draft.set(evt.value()),
                                        }
                                        div { class: "actions",
                                            button {
                                                class: "primary",
                                                "data-testid": "chat-save-edit-button",
                                                onclick: {
                                                    let base = base_url.clone();
                                                    let space = selected_space.clone();
                                                    let actor = account_did.clone();
                                                    let msg_id = msg.id.clone();
                                                    move |_| {
                                                        let content = edit_draft().trim().to_owned();
                                                        if content.is_empty() {
                                                            status_msg.set("Edit skipped: body is empty".to_owned());
                                                            editing_message.set(None);
                                                            return;
                                                        }
                                                        if let Some(found) = messages.write().iter_mut().find(|candidate| candidate.id == msg_id) {
                                                            found.revisions.push(found.body.clone());
                                                            found.body = content.clone();
                                                            found.edited = true;
                                                            found.pending = true;
                                                        }
                                                        editing_message.set(None);
                                                        let base = base.clone();
                                                        let space = space.clone();
                                                        let actor = actor.clone();
                                                        let msg_id = msg_id.clone();
                                                        let api_token = token();
                                                        let wait_for = active_sync_token(&sync_cursor());
                                                        spawn(async move {
                                                            match authed_api_with_sync(&base, api_token, wait_for) {
                                                                Ok(api) => {
                                                                    let op = chat_message_revise_operation(&space, &actor, &msg_id, &content);
                                                                    match api.submit_operation_event(&op).await {
                                                                        Ok(_resp) => {
                                                                            if let Some(found) = messages.write().iter_mut().find(|candidate| candidate.id == msg_id) {
                                                                                found.pending = false;
                                                                            }
                                                                            status_msg.set("Message updated".to_owned());
                                                                        }
                                                                        Err(error) => status_msg.set(format!("Message update failed: {error}")),
                                                                    }
                                                                }
                                                                Err(error) => status_msg.set(format!("Invalid server URL: {error}")),
                                                            }
                                                        });
                                                    }
                                                },
                                                "Save"
                                            }
                                            button {
                                                class: "secondary",
                                                onclick: move |_| editing_message.set(None),
                                                "Cancel"
                                            }
                                        }
                                    }
                                }
                                if redact_confirm() == Some(msg.id.clone()) {
                                    div { class: "chat-redact-confirm", "data-testid": "chat-redact-confirm",
                                        div { class: "discussion-subhead", span { "Remove message" } }
                                        div { class: "actions",
                                            button {
                                                class: "primary",
                                                "data-testid": "chat-confirm-redact-button",
                                                onclick: {
                                                    let base = base_url.clone();
                                                    let space = selected_space.clone();
                                                    let actor = account_did.clone();
                                                    let msg_id = msg.id.clone();
                                                    move |_| {
                                                        if let Some(found) = messages.write().iter_mut().find(|candidate| candidate.id == msg_id) {
                                                            found.redacted = true;
                                                            found.body.clear();
                                                            found.pending = true;
                                                        }
                                                        redact_confirm.set(None);
                                                        let base = base.clone();
                                                        let space = space.clone();
                                                        let actor = actor.clone();
                                                        let msg_id = msg_id.clone();
                                                        let api_token = token();
                                                        let wait_for = active_sync_token(&sync_cursor());
                                                        spawn(async move {
                                                            match authed_api_with_sync(&base, api_token, wait_for) {
                                                                Ok(api) => {
                                                                    let op = chat_message_redact_operation(&space, &actor, &msg_id, "user requested tombstone");
                                                                    match api.submit_operation_event(&op).await {
                                                                        Ok(_resp) => {
                                                                            if let Some(found) = messages.write().iter_mut().find(|candidate| candidate.id == msg_id) {
                                                                                found.pending = false;
                                                                            }
                                                                            status_msg.set("Message removed".to_owned());
                                                                        }
                                                                        Err(error) => status_msg.set(format!("Message removal failed: {error}")),
                                                                    }
                                                                }
                                                                Err(error) => status_msg.set(format!("Invalid server URL: {error}")),
                                                            }
                                                        });
                                                    }
                                                },
                                                "Confirm"
                                            }
                                            button {
                                                class: "secondary",
                                                onclick: move |_| redact_confirm.set(None),
                                                "Cancel"
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                    if visible_message_count == 0 {
                        div { class: "discussion-empty", "No messages yet." }
                    }
                }
            }

            if active_right_panel == Some(DiscussionSidePanel::Users) {
                aside { class: "discussion-panel discussion-details-panel", "data-testid": "discussion-users-panel",
                    div { class: "discussion-panel-head",
                        div { class: "discussion-title-row",
                            h2 { "Users" }
                        }
                    }
                    div { class: "discussion-detail-section",
                        div { class: "discussion-subhead", span { "Space users" } }
                        for participant in participants {
                            div {
                                class: if participant.is_self { "contact-row participant-row self" } else { "contact-row participant-row" },
                                "data-testid": "discussion-user-row",
                                span { class: "participant-avatar", UiIcon { name: "user" } }
                                div { class: "participant-main",
                                    strong { class: "mono participant-did", "{participant.did}" }
                                    div { class: "participant-badges",
                                        if participant.is_self {
                                            span { class: "badge participant-badge self", "You" }
                                        }
                                        span {
                                            class: match participant.role {
                                                SpaceParticipantRole::Owner => "badge participant-badge admin",
                                                SpaceParticipantRole::Admin => "badge participant-badge admin",
                                                SpaceParticipantRole::Member => "badge participant-badge member",
                                            },
                                            "{participant.role.label()}"
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            if active_right_panel == Some(DiscussionSidePanel::Settings) {
                aside { class: "discussion-panel discussion-details-panel", "data-testid": "discussion-settings-panel",
                    div { class: "discussion-panel-head",
                        div { class: "discussion-title-row",
                            h2 { "Settings" }
                        }
                    }
                    div { class: "discussion-detail-section",
                        div { class: "discussion-subhead", span { "Settings" } }
                        label { class: "settings-row",
                            span { "Mute notifications" }
                            input { r#type: "checkbox" }
                        }
                        label { class: "settings-row",
                            span { "Read receipts" }
                            input { r#type: "checkbox", checked: true }
                        }
                        label { class: "settings-row",
                            span { "Shared history" }
                            input { r#type: "checkbox", checked: true }
                        }
                    }
                    div { class: "discussion-detail-section",
                        div { class: "discussion-subhead", span { "Selected" } }
                        div { class: "detail-row", span { "Category" } strong { "{selected_channel_category}" } }
                        div { class: "detail-row", span { "Unread" } strong { "{selected_channel_unread}" } }
                        div { class: "detail-row", span { "Messages" } strong { "{visible_message_count}" } }
                    }
                }
            }

            div { class: "discussion-composer", "data-testid": "chat-composer",
                if reply_to_message().is_some() {
                    div { class: "muted", "data-testid": "chat-reply-banner",
                        "Replying to a message"
                        button {
                            class: "secondary",
                            onclick: move |_| reply_to_message.set(None),
                            "Cancel"
                        }
                    }
                }
                textarea {
                    "data-testid": "chat-input",
                    value: "{chat_draft}",
                    placeholder: "Message this discussion. Use @did:web:alice.example or #cx:task:123.",
                    oninput: move |evt| chat_draft.set(evt.value()),
                }
                div { class: "actions",
                    button {
                        class: "primary",
                        "data-testid": "send-chat-button",
                        onclick: {
                            let base = base_url.clone();
                            let service_did = plaintext_service_did.clone();
                            let space = selected_space.clone();
                            let actor = account_did.clone();
                            move |_| {
                                let body = chat_draft().trim().to_owned();
                                if body.is_empty() {
                                    return;
                                }
                                let mentions = parse_structured_mentions(&body);
                                let local_id = format!("chat-msg-{}", uuid_v7());
                                let channel = channels()
                                    .iter()
                                    .find(|candidate| candidate.flow_id == selected_channel())
                                    .cloned();
                                let Some(channel) = channel else {
                                    status_msg.set("select a discussion first".to_owned());
                                    return;
                                };
                                messages.write().push(ChatMessage {
                                    space_id: space.clone(),
                                    id: local_id.clone(),
                                    sender: "yougen".to_owned(),
                                    body: body.clone(),
                                    timestamp: chrono::Utc::now().format("%H:%M").to_string(),
                                    flow_id: channel.flow_id.clone(),
                                    reply_to: reply_to_message(),
                                    reactions: Vec::new(),
                                    redacted: false,
                                    edited: false,
                                    revisions: Vec::new(),
                                    pending: true,
                                    failed: false,
                                    error: None,
                                    mentions: mentions.clone(),
                                });

                                let base = base.clone();
                                let service_did = service_did.clone();
                                let space = space.clone();
                                let api_token = token();
                                let actor = actor.clone();
                                let flow_id = channel.flow_id.clone();
                                let channel_kind = channel.kind.clone();
                                let message_id = local_id.clone();
                                let reply_to = reply_to_message();
                                let op = chat_message_create_operation(
                                    &space,
                                    &actor,
                                    &flow_id,
                                    &channel_kind,
                                    &message_id,
                                    &body,
                                    &mentions,
                                    reply_to.as_deref(),
                                );
                                let mention_values_for_store = mentions_to_json(&mentions);
                                let space_for_record = space.clone();
                                let actor_for_store = actor.clone();
                                let body_for_store = body.clone();
                                let flow_id_for_store = flow_id.clone();
                                let message_id_for_store = message_id.clone();
                                let reply_to_for_store = reply_to.clone();
                                let projection = state_store
                                    .read()
                                    .load()
                                    .space_projections
                                    .get(&space)
                                    .cloned();
                                let plaintext_services =
                                    plaintext_services_for_policy(projection.as_ref(), &service_did);
                                let wait_for = active_sync_token(&sync_cursor());
                                spawn(async move {
                                    match authed_api_with_sync(&base, api_token, wait_for) {
                                        Ok(api) => match submit_chat_operation_with_plaintext_retry(
                                            &api,
                                            &space,
                                            &plaintext_services,
                                            &op,
                                        ).await {
                                            Ok(resp) => {
                                                {
                                                    let mut store = state_store.write();
                                                    store.save_sync_cursor(resp.sync_token.clone());
                                                    store.append_raw_operation(
                                                        op.operation_id.clone(),
                                                        Some(space_for_record),
                                                        json!({
                                                            "event_id": resp.event_id.clone(),
                                                            "kind": "cx.message.create",
                                                            "actor": actor_for_store,
                                                            "body": body_for_store,
                                                            "flow_id": flow_id_for_store,
                                                            "message_id": message_id_for_store,
                                                            "mentions": mention_values_for_store,
                                                            "reply_to": reply_to_for_store,
                                                            "status": resp.status.clone(),
                                                        }),
                                                    );
                                                }
                                                if let Some(found) = messages
                                                    .write()
                                                    .iter_mut()
                                                    .find(|candidate| candidate.id == local_id)
                                                {
                                                    found.id = resp.event_id.clone();
                                                    found.pending = false;
                                                    found.failed = false;
                                                    found.error = None;
                                                }
                                                sync_cursor.set(resp.sync_token.clone());
                                                frontier_state.set(resp.event_id.clone());
                                                status_msg.set("Message sent".to_owned());
                                            }
                                            Err(error) => {
                                                let auth_expired = is_auth_expired_error(&error);
                                                let message = chat_send_error_message(&error);
                                                if let Some(found) = messages
                                                    .write()
                                                    .iter_mut()
                                                    .find(|candidate| candidate.id == local_id)
                                                {
                                                    found.pending = false;
                                                    found.failed = true;
                                                    found.error = Some(message.clone());
                                                }
                                                status_msg.set(format!("Message send failed: {message}"));
                                                if auth_expired {
                                                    let _ = navigator.push(Route::Login);
                                                }
                                            }
                                        },
                                        Err(error) => {
                                            let message = format!("Invalid server URL: {error}");
                                            if let Some(found) = messages
                                                .write()
                                                .iter_mut()
                                                .find(|candidate| candidate.id == local_id)
                                            {
                                                found.pending = false;
                                                found.failed = true;
                                                found.error = Some(message.clone());
                                            }
                                            status_msg.set(message);
                                        }
                                    }
                                });
                                chat_draft.set(String::new());
                                reply_to_message.set(None);
                            }
                        },
                        "Send"
                    }
                    button {
                        class: "secondary",
                        "data-testid": "send-e2ee-move-button",
                        onclick: {
                            let base = base_url.clone();
                            let space = selected_space.clone();
                            let actor = account_did.clone();
                            move |_| {
                                let body = chat_draft().trim().to_owned();
                                if body.is_empty() {
                                    status_msg.set("Type a message before secure send".to_owned());
                                    return;
                                }
                                let space = space.clone();
                                let actor = actor.clone();
                                let api_token = token();
                                let wait_for = active_sync_token(&sync_cursor());
                                let hlc = Hlc::now("yougen").to_string();
                                let anchor_view = state_store.read().anchor_view_for(&space);
                                let anchor_ref = anchor_view.move_anchor_ref();
                                let covered_frontier = anchor_view
                                    .covered_frontier
                                    .clone()
                                    .unwrap_or_else(|| {
                                        // Fallback: bind to the
                                        // sha256(empty) sentinel — soland
                                        // surfaces a `covered_frontier`
                                        // mismatch which the Move tracker
                                        // maps to pending_mls_binding.
                                        "cx:state:sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_owned()
                                    });
                                let new_epoch = anchor_view
                                    .mls_epoch
                                    .map(|e| e + 1)
                                    .unwrap_or(1);
                                let identity =
                                    match state_store.write().ensure_local_identity() {
                                        Ok(id) => id,
                                        Err(err) => {
                                            status_msg.set(format!(
                                                "identity unavailable: {err}"
                                            ));
                                            return;
                                        }
                                    };
                                let did = identity.device_did.clone();
                                let vm =
                                    did_key_verification_method(&identity.signing_key.verifying_key());
                                // 1) MLS commit Move bumps the epoch +
                                //    records covered_frontier.
                                //
                                // TODO (B3b follow-up): when this chat
                                // path is migrated onto a real MLS group
                                // (with persisted ContrixMlsGroup state +
                                // a real key-schedule hash + prev_epoch
                                // tracked alongside the new_epoch), swap
                                // this call for
                                // `build_mls_commit_move_with_governance_binding`
                                // and feed it a
                                // `GovernanceBindingPayload::from_anchor(...)`
                                // so the server can enforce
                                // `mls_governance_binding.full.v1`. The
                                // current path writes only the local
                                // epoch cas-register because we don't
                                // have a real key schedule to attest.
                                let commit_unsigned = match build_mls_commit_move(
                                    &did,
                                    &space,
                                    &space,
                                    new_epoch,
                                    &covered_frontier,
                                    &anchor_ref,
                                    &hlc,
                                ) {
                                    Ok(u) => u,
                                    Err(err) => {
                                        status_msg.set(format!(
                                            "mls commit move build failed: {err}"
                                        ));
                                        return;
                                    }
                                };
                                let commit_signed =
                                    sign_unsigned_move(commit_unsigned, &identity.signing_key, &vm);
                                let msg_op = OperationBuilder::new(
                                    &space,
                                    &actor,
                                    "cx.message.create",
                                )
                                .body(json!({
                                    "body": format!("[encrypted epoch {new_epoch}]"),
                                    "content": {
                                        "blocks": [{
                                            "kind": "text",
                                            "text": format!("[encrypted epoch {new_epoch}]"),
                                        }],
                                        "body": format!("[encrypted epoch {new_epoch}]"),
                                    },
                                    "covered_frontier": covered_frontier.clone(),
                                    "encrypted_payload": {
                                        "ciphertext": body,
                                        "epoch": new_epoch,
                                    },
                                }))
                                .build("yougen");
                                let base = base.clone();
                                let space_for_record = space.clone();
                                let anchor_for_record = anchor_ref.clone();
                                let actor_for_audit = actor.clone();
                                spawn(async move {
                                    if let Ok(api) = authed_api_with_sync(&base, api_token, wait_for) {
                                        // Submit MLS commit first; if
                                        // it fails, abort message send
                                        // (covered_frontier won't bind).
                                        match api.submit_move(&commit_signed).await {
                                            Ok(resp) => {
                                                let state = MoveSubmissionState::from_submit_state(
                                                    resp.state.as_str(),
                                                    resp.reason.as_deref(),
                                                );
                                                state_store.write().record_move_submission(
                                                    resp.move_id.clone(),
                                                    space_for_record.clone(),
                                                    "mls_commit".to_owned(),
                                                    state,
                                                    resp.reason.clone(),
                                                    Some(anchor_for_record.clone()),
                                                );
                                                if state.is_failed() {
                                                    status_msg.set(format!(
                                                        "MLS commit Move failed: {} reason={:?}",
                                                        resp.move_id, resp.reason
                                                    ));
                                                    return;
                                                }
                                            }
                                            Err(err) => {
                                                status_msg.set(format!(
                                                    "MLS commit Move submit failed: {err}"
                                                ));
                                                return;
                                            }
                                        }
                                        match api.submit_operation_event(&msg_op).await {
                                            Ok(resp) => {
                                                {
                                                    let mut store = state_store.write();
                                                    store.save_sync_cursor(resp.sync_token.clone());
                                                    store.append_raw_operation(
                                                        msg_op.operation_id.clone(),
                                                        Some(space_for_record.clone()),
                                                        json!({
                                                            "event_id": resp.event_id.clone(),
                                                            "kind": "cx.message.create",
                                                            "status": resp.status.clone(),
                                                        }),
                                                    );
                                                }
                                                sync_cursor.set(resp.sync_token.clone());
                                                frontier_state.set(resp.event_id.clone());
                                            status_msg.set(format!(
                                                "Encrypted message sent"
                                            ));

                                            // Disclosed-audit hardening profile
                                            // (`cx.profile.disclosed_audit.e2ee.v1`):
                                            // emit a per-actor read-your-write
                                            // receipt right after a successful
                                            // E2EE commit. The receipt is
                                            // actor-private (only the sender
                                            // can audit their own writes), so
                                            // this is fire-and-forget — if the
                                            // server isn't running the
                                            // disclosed-audit profile, it will
                                            // store the event as a regular
                                            // operation and the audit timeline
                                            // can still surface it.
                                            //
                                            // `delivered_to_devices` is empty
                                            // for now: a real MLS path would
                                            // pass the post-commit member
                                            // device list so an auditor can
                                            // verify message-to-device fan-out.
                                            let audit_op = build_audit_ryw_receipt(
                                                &space_for_record,
                                                &actor_for_audit,
                                                &resp.event_id,
                                                Vec::new(),
                                            )
                                            .build("yougen");
                                            let _ = api.submit_operation_event(&audit_op).await;
                                        }
                                        Err(err) => status_msg.set(format!(
                                            "Message send failed: {err}"
                                        )),
                                    }
                                }
                                });
                                chat_draft.set(String::new());
                            }
                        },
                        "Send Secure"
                    }
                }
                if !status_msg().is_empty() {
                    div { class: "muted discussion-status", "data-testid": "chat-status", "{status_msg}" }
                }
            }
        }
    }
}

fn mentions_to_json(mentions: &[StructuredMention]) -> Vec<serde_json::Value> {
    mentions
        .iter()
        .map(|mention| {
            json!({
                "kind": mention.kind,
                "target": mention.target,
                "token": mention.token,
            })
        })
        .collect()
}

fn mention_relation_json(source: &str, mentions: &[StructuredMention]) -> Vec<serde_json::Value> {
    mentions
        .iter()
        .map(|mention| {
            json!({
                "relation_type": "mentions",
                "source": source,
                "target": mention.target,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_message_event_with_operation_body_shape() {
        let event = json!({
            "id": "cx:event:body-shape",
            "type": "cx.message.create",
            "actor": "did:web:alice.example",
            "space_id": "cx:space:demo",
            "created_at": "2026-05-14T01:23:45Z",
            "causal": {"actor_seq": 42},
            "body": {
                "body": "restored from durable history",
                "flow_id": "cx:flow:announce",
                "message_id": "chat-msg-local",
                "mentions": [{"kind": "actor", "target": "did:web:bob.example", "token": "@bob"}]
            }
        });

        let message = chat_message_from_event("cx:space:fallback", &event).unwrap();

        assert_eq!(message.id, "cx:event:body-shape");
        assert_eq!(message.space_id, "cx:space:demo");
        assert_eq!(message.flow_id, "cx:flow:announce");
        assert_eq!(message.body, "restored from durable history");
        assert_eq!(message.sender, "did:web:alice.example");
        assert_eq!(message.mentions[0].target, "did:web:bob.example");
    }

    #[test]
    fn parses_message_event_with_nested_envelope_payload_shape() {
        let event = json!({
            "event": {
                "event_id": "cx:event:nested",
                "kind": "cx.message.create",
                "actor_id": "did:web:alice.example",
                "actor_seq": 43,
                "payload": {
                    "content": {
                        "blocks": [{"kind": "text", "text": "nested payload message"}]
                    },
                    "flow_id": "cx:flow:support",
                    "message_id": "chat-msg-nested"
                }
            }
        });

        let message = chat_message_from_event("cx:space:demo", &event).unwrap();

        assert_eq!(message.id, "cx:event:nested");
        assert_eq!(message.flow_id, "cx:flow:support");
        assert_eq!(message.body, "nested payload message");
    }

    #[test]
    fn restores_messages_from_local_raw_operations() {
        let state = ClientLocalState {
            raw_operations: vec![crate::local_state::RawOperationRecord {
                operation_id: "cx:operation:local".to_owned(),
                space_id: Some("cx:space:local".to_owned()),
                received_at: chrono::Utc::now(),
                payload: json!({
                    "event_id": "cx:event:local",
                    "kind": "cx.message.create",
                    "actor": "did:web:alice.example",
                    "body": "local fallback message",
                    "flow_id": "cx:flow:announce",
                    "message_id": "chat-msg-local"
                }),
            }],
            ..ClientLocalState::default()
        };

        let messages = chat_messages_from_local_state(&state);

        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].space_id, "cx:space:local");
        assert_eq!(messages[0].flow_id, "cx:flow:announce");
        assert_eq!(messages[0].body, "local fallback message");
    }

    #[test]
    fn treats_canonical_account_did_as_own_sender() {
        let participants = Vec::new();

        assert!(is_own_message_sender(
            "did:web:alice.example",
            "did:web:alice.example"
        ));
        assert_eq!(
            sender_display_label(
                "did:web:alice.example",
                "did:web:alice.example",
                "",
                &participants
            ),
            "yougen"
        );
        assert_eq!(
            sender_display_label(
                "did:web:alice.example",
                "did:web:alice.example",
                "Alice Local",
                &participants,
            ),
            "Alice Local"
        );
    }

    #[test]
    fn participant_display_name_prefers_local_remark() {
        let participants = vec![SpaceParticipant {
            did: "did:web:bob.example".to_owned(),
            display_name: Some("Bobby".to_owned()),
            display_name_rank: 0,
            role: SpaceParticipantRole::Member,
            is_self: false,
        }];

        assert_eq!(
            sender_display_label(
                "did:web:bob.example",
                "did:web:alice.example",
                "Alice",
                &participants,
            ),
            "Bobby"
        );
        assert_eq!(
            sender_display_label(
                "did:web:carol.example",
                "did:web:alice.example",
                "Alice",
                &participants
            ),
            "carol.example"
        );
    }

    #[test]
    fn extracts_participant_display_name_from_projection() {
        let projection = json!({
            "members": [
                {
                    "did": "did:web:bob.example",
                    "display_name": "Bob Example",
                    "remark": "Bob from ops"
                }
            ]
        });

        let participants = space_participants(Some(&projection), "did:web:alice.example");
        let bob = participants
            .iter()
            .find(|participant| participant.did == "did:web:bob.example")
            .unwrap();

        assert_eq!(bob.display_name.as_deref(), Some("Bob from ops"));
    }

    #[test]
    fn channel_from_flow_event_requires_real_discussion_track() {
        let event = json!({
            "event_id": "cx:event:flow",
            "kind": "cx.flow.create",
            "space_id": "cx:space:demo",
            "flow_id": "cx:flow:ops",
            "title": "Ops discussion",
            "category": "support",
            "summary": "Operations support",
            "flow": {
                "id": "cx:flow:ops",
                "title": "Ops discussion",
                "tracks": {
                    "discussion": {"profile": "discussion"}
                }
            }
        });

        let channel = channel_from_flow_event("cx:space:demo", &event).unwrap();

        assert_eq!(channel.flow_id, "cx:flow:ops");
        assert_eq!(channel.name, "Ops discussion");
        assert_eq!(channel.category, "support");
        assert_eq!(channel.kind, "discussion");
        assert_eq!(channel.topic.as_deref(), Some("Operations support"));
    }

    #[test]
    fn channel_from_flow_event_ignores_non_discussion_flows() {
        let event = json!({
            "event_id": "cx:event:flow",
            "kind": "cx.flow.create",
            "space_id": "cx:space:demo",
            "flow_id": "cx:flow:doc",
            "title": "Doc flow",
            "flow": {
                "id": "cx:flow:doc",
                "title": "Doc flow",
                "tracks": {
                    "document": {"profile": "document"}
                }
            }
        });

        assert!(channel_from_flow_event("cx:space:demo", &event).is_none());
    }
}
