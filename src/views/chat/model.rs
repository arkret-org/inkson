use super::*;

pub(super) const CHAT_EMOJI_GRID: &[&str] = &[
    "\u{1f44d}",
    "\u{2764}\u{fe0f}",
    "\u{1f389}",
    "\u{1f440}",
    "\u{1f680}",
];

#[derive(Clone, Debug, PartialEq)]
pub(super) struct ChannelEntity {
    pub(super) strand_id: String,
    pub(super) name: String,
    pub(super) kind: String,
    pub(super) category: String,
    pub(super) topic: Option<String>,
    pub(super) unread: usize,
    pub(super) is_default: bool,
    /// Explicit Strand security state from Strand metadata. `None` inherits
    /// the current Realm / Space security posture.
    pub(super) security_encrypted: Option<bool>,
    /// CKP-0007 P3B.2.3 / P3B.2.4 — Circle scope this Strand was
    /// created under, when the Strand projection carries a
    /// `scope_circle_id`. The composer banner and the per-message
    /// accent rail read from this field; `None` means the Strand
    /// inherits the parent Realm scope and no banner / rail is
    /// rendered.
    pub(super) scope_circle: Option<StrandScopeCircle>,
}

/// Minimal Circle-scope projection embedded on each [`ChannelEntity`].
/// Mirrors the subset of [`crate::circle::CircleSummary`] needed by
/// the chat composer banner and timeline accent rail.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct StrandScopeCircle {
    /// `ck:circle:…`
    pub(super) circle_id: String,
    /// Circle title used in the banner heading + accent-rail tooltip.
    pub(super) title: String,
    /// Cached member count for the banner subline. `0` means the
    /// projection has not been hydrated yet — render "members" with
    /// no count rather than `0 members`.
    pub(super) member_count: u32,
}

/// T7.4: end-to-end encryption decryption state for a message.
///
/// Derived from the presence of `content.encrypted_content` on the
/// envelope plus what the local MLS group can currently do with it.
/// `Plaintext` is the default; encrypted messages cycle
/// `Decrypting → (Plaintext | KeyMissing | NeedsVerification)`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum MessageCryptoState {
    /// Body is already plaintext (no `encrypted_content`).
    Plaintext,
    /// We see an `encrypted_content` envelope and the MLS group exists, but a
    /// decrypt round-trip hasn't completed for this event yet.
    Decrypting,
    /// `encrypted_content` present but no local MLS group / no key
    /// package received yet — Welcome is pending.
    KeyMissing,
    /// Sender device hasn't been verified (cross-signing missing or
    /// fingerprint mismatch). The body still decrypted, but we flag it.
    NeedsVerification,
}

impl MessageCryptoState {
    pub(super) fn is_pending(&self) -> bool {
        matches!(self, Self::Decrypting | Self::KeyMissing)
    }
}

#[derive(Clone, Debug, PartialEq)]
pub(super) struct ChatMessage {
    pub(super) realm_id: String,
    pub(super) id: String,
    pub(super) sender: String,
    pub(super) body: String,
    pub(super) timestamp: String,
    pub(super) strand_id: String,
    pub(super) reply_to: Option<String>,
    pub(super) reactions: Vec<(String, Vec<String>)>,
    pub(super) redacted: bool,
    pub(super) edited: bool,
    pub(super) revisions: Vec<String>,
    pub(super) pending: bool,
    pub(super) failed: bool,
    pub(super) error: Option<String>,
    pub(super) mentions: Vec<MentionNode>,
    /// T7.4: E2EE decrypt status for this message. Defaults to
    /// `Plaintext`; messages with `content.encrypted_content` start at
    /// `Decrypting` until the audit-emitter future resolves them.
    pub(super) crypto_state: MessageCryptoState,
}

pub(super) fn fail_optimistic_chat_send(
    mut messages: Signal<Vec<ChatMessage>>,
    mut chat_draft: Signal<String>,
    mut status_msg: Signal<String>,
    message_id: &str,
    body_for_restore: &str,
    message: String,
) {
    if let Some(found) = messages
        .write()
        .iter_mut()
        .find(|candidate| candidate.id == message_id)
    {
        found.pending = false;
        found.failed = true;
        found.error = Some(message.clone());
    }
    if chat_draft().trim().is_empty() {
        chat_draft.set(body_for_restore.to_owned());
    }
    status_msg.set(message);
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum DiscussionSidePanel {
    Users,
    Settings,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum SpaceParticipantRole {
    Owner,
    Admin,
    Member,
}

impl SpaceParticipantRole {
    pub(super) fn label(self) -> &'static str {
        match self {
            Self::Owner => "Owner",
            Self::Admin => "Admin",
            Self::Member => "Member",
        }
    }

    pub(super) fn rank(self) -> u8 {
        match self {
            Self::Owner => 0,
            Self::Admin => 1,
            Self::Member => 2,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct AgentParticipantMetadata {
    pub(super) controller_did: String,
    pub(super) controller_handle: String,
    pub(super) agent_slug: String,
    pub(super) display_name: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct SpaceParticipant {
    pub(super) did: String,
    pub(super) display_name: Option<String>,
    pub(super) handle_label: Option<String>,
    pub(super) display_name_rank: u8,
    pub(super) role: SpaceParticipantRole,
    pub(super) is_self: bool,
    /// `true` when this DID was registered as an agent endpoint
    /// (`ck.agent.endpoint`). Surfaces a 🤖 badge in member lists,
    /// @mention picker rows, and chat sender attribution so operators
    /// can immediately distinguish bot/agent principals from real
    /// human members.
    pub(super) is_agent: bool,
    pub(super) agent_metadata: Option<AgentParticipantMetadata>,
}

// The MLS encrypt + commit/envelope/payload build + commit→message submission
// orchestration for the encrypted "Send Secure" path now lives in the shared
// `crate::views::secure_send` module so the Chat and Timeline views drive ONE
// MLS core + persist-on-accept pipeline. The Chat composer calls
// `secure_send::build_secure_send` / `secure_send::submit_secure_send`
// directly; the former local `run_local_mls_encrypt` / `chat_mls_*` helpers
// moved there verbatim.

pub(super) fn chat_message_revise_operation(
    realm_id: &str,
    actor: &str,
    event_id: &str,
    body: &str,
) -> crate::operation::EventEnvelope {
    OperationBuilder::new(realm_id, actor, "ck.message.revise")
        .target_ref(event_id)
        .body(json!({
            "content": {
                "kind": "ck.content.text",
                "body": body,
            },
            "target_ref": event_id,
        }))
        .build("yougen")
}

pub(super) fn chat_message_redact_operation(
    realm_id: &str,
    actor: &str,
    event_id: &str,
    reason: &str,
) -> crate::operation::EventEnvelope {
    OperationBuilder::new(realm_id, actor, "ck.message.redact")
        .target_ref(event_id)
        .body(json!({
            "reason": reason,
            "target_event_id": event_id,
        }))
        .build("yougen")
}

pub(super) fn chat_reaction_add_operation(
    realm_id: &str,
    actor: &str,
    event_id: &str,
    key: &str,
) -> crate::operation::EventEnvelope {
    OperationBuilder::new(realm_id, actor, "ck.reaction.add")
        .target_ref(event_id)
        .body(json!({
            "target_ref": event_id,
            "key": key,
        }))
        .build("yougen")
}

/// E2EE reaction (encryption-and-audit.md §2.9): the plaintext `key` carries
/// the v1 keyed-HMAC routing tag (`sha256:<hex>`) so the server can still
/// OR-Set dedup / rate-limit without learning the emoji; the real emoji
/// travels inside `encrypted_payload`.
pub(super) fn chat_reaction_add_operation_encrypted(
    realm_id: &str,
    actor: &str,
    event_id: &str,
    routing_tag: &str,
    encrypted_payload: &cokret_sdk::EncryptedPayload,
) -> crate::operation::EventEnvelope {
    let encrypted_payload_json =
        serde_json::to_value(encrypted_payload).unwrap_or(serde_json::Value::Null);
    OperationBuilder::new(realm_id, actor, "ck.reaction.add")
        .target_ref(event_id)
        .body(json!({
            "target_ref": event_id,
            "key": routing_tag,
            "encrypted_payload": encrypted_payload_json,
        }))
        .build("yougen")
}

/// Build the `ck.reaction.add` operation for a tapped emoji, choosing the
/// plaintext or E2EE (§2.9 routing-tag) shape based on whether the channel
/// is encrypted. On any MLS failure in an encrypted channel the reaction is
/// dropped (returns `None`) rather than leaking the emoji in plaintext.
#[allow(clippy::too_many_arguments)]
pub(super) fn build_chat_reaction_add_operation(
    mut state_store: Signal<LocalStateStore>,
    realm_id: &str,
    actor: &str,
    device_id: &str,
    event_id: &str,
    emoji: &str,
    channel_encrypted: bool,
) -> Option<crate::operation::EventEnvelope> {
    if !channel_encrypted {
        return Some(chat_reaction_add_operation(
            realm_id, actor, event_id, emoji,
        ));
    }
    let realm_id = trim_realm_id(realm_id);
    let secure_store = crate::secure_key_store::default_secure_key_store("yougen");
    match crate::mls::runtime::encrypt_reaction_with_device_snapshot(
        &mut state_store.write(),
        secure_store.as_ref(),
        &realm_id,
        actor,
        device_id,
        emoji,
    ) {
        Ok(sealed) => Some(chat_reaction_add_operation_encrypted(
            &realm_id,
            actor,
            event_id,
            &sealed.routing_tag,
            &sealed.encrypted_payload,
        )),
        Err(_) => None,
    }
}

pub(super) fn normalize_participant_id(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_owned())
    }
}

pub(super) fn participant_id_from_state_key(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if let Some(index) = trimmed.find("did:") {
        normalize_participant_id(&trimmed[index..])
    } else {
        None
    }
}

pub(super) fn participant_role_from_str(
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

pub(super) fn participant_id_from_value(value: &Value) -> Option<String> {
    if let Some(raw) = value.as_str() {
        return normalize_participant_id(raw);
    }

    let object = value.as_object()?;
    [
        "did",
        "account_did",
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

pub(super) fn participant_id_from_member_value(value: &Value) -> Option<String> {
    if let Some(raw) = value.as_str() {
        return normalize_participant_id(raw);
    }

    let object = value.as_object()?;
    [
        "did",
        "account_did",
        "member",
        "user",
        "actor",
        "actor_id",
        "subject",
    ]
    .iter()
    .find_map(|key| object.get(*key).and_then(participant_id_from_member_value))
}

pub(super) fn clean_participant_display_name(value: &str, did: Option<&str>) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed.starts_with("did:") || did == Some(trimmed) {
        None
    } else {
        Some(trimmed.to_owned())
    }
}

pub(super) fn participant_display_name_from_value(
    value: &Value,
    did: Option<&str>,
) -> Option<(String, u8)> {
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

pub(super) fn mention_handle_label_from_value(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed.starts_with("did:") {
        return None;
    }
    crate::identity_handle::parse_user_handle(trimmed).map(|handle| handle.display)
}

pub(super) fn participant_handle_label_from_value(
    value: &Value,
    did: Option<&str>,
) -> Option<String> {
    let object = value.as_object()?;
    // R3.1 wire rename: spec field is `handle`. Older payloads may
    // still ship `handle_uri` (cokret:// URI form retired @ 7157ee8);
    // accept both for migration compatibility.
    [
        "handle",
        "handle_uri",
        "handleUri",
        "user_handle",
        "userHandle",
        "acct_alias",
        "acctAlias",
        "acct",
        "mxid",
    ]
    .iter()
    .find_map(|key| {
        object
            .get(*key)
            .and_then(Value::as_str)
            .filter(|raw| did != Some(raw.trim()))
            .and_then(mention_handle_label_from_value)
    })
    .or_else(|| {
        [
            "profile", "account", "member", "user", "actor", "subject", "details",
        ]
        .iter()
        .find_map(|key| {
            object
                .get(*key)
                .filter(|child| child.is_object())
                .and_then(|child| participant_handle_label_from_value(child, did))
        })
    })
}

pub(super) fn mention_label_for_participant(participant: &SpaceParticipant) -> Option<String> {
    participant
        .handle_label
        .clone()
        .or_else(|| {
            participant
                .display_name
                .as_deref()
                .and_then(mention_handle_label_from_value)
        })
        .or_else(|| crate::views::helpers::handle_display_from_did(&participant.did))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct MentionInlinePart {
    pub(super) text: String,
    pub(super) mention_label: Option<String>,
    pub(super) is_local: bool,
}

/// R3.2 §3.8.2 (YG-MENT-2) — resolve the *current* display label for a
/// structured actor mention via the shared SDK `render_mention()` helper.
///
/// The authoritative `target` (principal `subject_id`) drives §3.2.1
/// primary-handle selection. `handle_at_time` / `display_name_at_time`
/// are audit metadata and feed ONLY the degraded fallback ladder — they
/// are NEVER used as the current display value directly.
///
/// `TODO(R3.2.1)`: feed the Realm-scoped roster handle-claim snapshot +
/// accepted_issuers + a locally cached verified handle in here. Until the
/// live claim cache + `list_handles_for_subject` plumbing lands we pass an
/// empty snapshot, so the renderer steps down to the cached/name/DID
/// fallback ladder (each visually degraded) instead of inventing a
/// handle.
pub(super) fn mention_label_from_node(mention: &MentionNode) -> Option<String> {
    if let Some(audience_mention) = mention.as_audience_mention() {
        return audience_mention
            .mention_text_original
            .as_deref()
            .and_then(|token| token.strip_prefix('@'))
            .filter(|label| !label.is_empty())
            .map(ToOwned::to_owned)
            .or_else(|| Some(audience_mention.audience.as_wire().to_owned()));
    }
    let mention = mention.as_mention()?;
    let display_name = mention.display_name_at_time.as_deref();
    let rendered = crate::views::helpers::render_actor_mention(
        mention.subject_id.as_str(),
        &[],  // claim_set_snapshot — TODO(R3.2.1) roster handle-claim evidence
        &[],  // accepted_issuers — TODO(R3.2.1) Realm policy
        None, // context (target Realm id)
        None, // cached verified handle — TODO(R3.2.1) local cache
        display_name,
    );
    // The verified / cached tiers render `@{localpart}:{domain}`; strip
    // the leading `@` to match the inline label shape used by the chat
    // renderer (which adds its own `@` styling). Name-only / unresolved
    // tiers return the bare name / truncated DID.
    Some(
        rendered
            .label
            .strip_prefix('@')
            .unwrap_or(&rendered.label)
            .to_owned(),
    )
}

pub(super) fn local_server_domain(base_url: &str) -> Option<String> {
    url::Url::parse(base_url)
        .ok()
        .and_then(|url| url.host_str().map(|host| host.to_ascii_lowercase()))
}

pub(super) fn handle_domain(label: &str) -> Option<String> {
    crate::identity_handle::parse_user_handle(label).map(|handle| handle.domain)
}

pub(super) fn is_local_handle_label(label: &str, base_url: &str) -> bool {
    let Some(handle_domain) = handle_domain(label) else {
        return false;
    };
    let Some(server_domain) = local_server_domain(base_url) else {
        return false;
    };
    handle_domain == server_domain
        || server_domain.ends_with(&format!(".{handle_domain}"))
        || handle_domain.ends_with(&format!(".{server_domain}"))
}

pub(super) fn account_handle_display_from_server(
    account_handle: &str,
    server_url: &str,
) -> Option<String> {
    let trimmed = account_handle.trim().trim_start_matches('@').trim();
    if trimmed.is_empty() {
        return None;
    }
    if let Some(handle) = mention_handle_label_from_value(trimmed) {
        return Some(handle);
    }
    let server_domain = local_server_domain(server_url)?;
    mention_handle_label_from_value(&format!("{trimmed}:{server_domain}"))
}

pub(super) fn is_leading_mention_punct(ch: char) -> bool {
    matches!(ch, '(' | '[' | '{' | '"' | '\'')
}

pub(super) fn is_trailing_mention_punct(ch: char) -> bool {
    matches!(
        ch,
        ',' | '.' | '!' | '?' | ';' | ')' | ']' | '}' | '"' | '\''
    )
}

pub(super) fn token_core_bounds(token: &str) -> (usize, usize) {
    let start = token
        .char_indices()
        .find(|(_, ch)| !is_leading_mention_punct(*ch))
        .map(|(idx, _)| idx)
        .unwrap_or(token.len());
    let end = token
        .char_indices()
        .rev()
        .find(|(idx, ch)| *idx >= start && !is_trailing_mention_punct(*ch))
        .map(|(idx, ch)| idx + ch.len_utf8())
        .unwrap_or(start);
    (start, end)
}

pub(super) fn split_preserving_whitespace(text: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut current = String::new();
    let mut current_is_whitespace: Option<bool> = None;

    for ch in text.chars() {
        let is_whitespace = ch.is_whitespace();
        if let Some(previous) = current_is_whitespace
            && previous != is_whitespace
        {
            parts.push(std::mem::take(&mut current));
        }
        current_is_whitespace = Some(is_whitespace);
        current.push(ch);
    }

    if !current.is_empty() {
        parts.push(current);
    }

    parts
}

pub(super) fn mention_inline_parts(
    text: &str,
    mentions: &[MentionNode],
    base_url: &str,
) -> Vec<MentionInlinePart> {
    let labels: std::collections::BTreeSet<String> = mentions
        .iter()
        .filter_map(mention_label_from_node)
        .collect();
    if labels.is_empty() {
        return vec![MentionInlinePart {
            text: text.to_owned(),
            mention_label: None,
            is_local: false,
        }];
    }

    let mut parts = Vec::new();
    for segment in split_preserving_whitespace(text) {
        if segment.chars().all(char::is_whitespace) {
            parts.push(MentionInlinePart {
                text: segment,
                mention_label: None,
                is_local: false,
            });
            continue;
        }

        let (core_start, core_end) = token_core_bounds(&segment);
        let core = &segment[core_start..core_end];
        let parsed_label = core
            .strip_prefix('@')
            .and_then(mention_handle_label_from_value);
        let Some(label) = parsed_label.filter(|label| labels.contains(label)) else {
            parts.push(MentionInlinePart {
                text: segment,
                mention_label: None,
                is_local: false,
            });
            continue;
        };

        let prefix = &segment[..core_start];
        if !prefix.is_empty() {
            parts.push(MentionInlinePart {
                text: prefix.to_owned(),
                mention_label: None,
                is_local: false,
            });
        }
        let mention_text = format!("@{label}");
        parts.push(MentionInlinePart {
            text: mention_text,
            is_local: is_local_handle_label(&label, base_url),
            mention_label: Some(label),
        });
        let suffix = &segment[core_end..];
        if !suffix.is_empty() {
            parts.push(MentionInlinePart {
                text: suffix.to_owned(),
                mention_label: None,
                is_local: false,
            });
        }
    }
    parts
}

pub(super) fn upsert_participant(
    participants: &mut Vec<SpaceParticipant>,
    did: &str,
    role: SpaceParticipantRole,
    account_did: &str,
    display_name: Option<(String, u8)>,
    handle_label: Option<String>,
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
        if existing.handle_label.is_none() {
            existing.handle_label = handle_label;
        }
    } else {
        let (display_name, display_name_rank) = display_name
            .map(|(name, rank)| (Some(name), rank))
            .unwrap_or((None, u8::MAX));
        participants.push(SpaceParticipant {
            did,
            display_name,
            handle_label,
            display_name_rank,
            role,
            is_self,
            // Default; the caller annotates agent DIDs via
            // `annotate_agent_participants` after the projection-based
            // upsert pass completes.
            is_agent: false,
            agent_metadata: None,
        });
    }
}

fn raw_operation_kind(payload: &Value) -> Option<&str> {
    payload
        .get("kind")
        .and_then(Value::as_str)
        .or_else(|| payload.get("type").and_then(Value::as_str))
}

fn raw_operation_realm_matches(
    record: &crate::local_state::RawOperationRecord,
    realm_id: &str,
) -> bool {
    let expected = realm_id.trim();
    if expected.is_empty() {
        return true;
    }
    record
        .realm_id
        .as_deref()
        .or_else(|| record.payload.get("realm_id").and_then(Value::as_str))
        .map(|record_realm| record_realm == expected)
        .unwrap_or(true)
}

fn value_at_path<'a>(value: &'a Value, path: &[&str]) -> Option<&'a Value> {
    path.iter()
        .try_fold(value, |current, key| current.get(*key))
}

fn string_at_any_path(value: &Value, paths: &[&[&str]]) -> Option<String> {
    paths
        .iter()
        .find_map(|path| value_at_path(value, path).and_then(Value::as_str))
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

fn agent_endpoint_agent_id(payload: &Value) -> Option<String> {
    string_at_any_path(
        payload,
        &[
            &["body", "agent_id"],
            &["payload", "agent_id"],
            &["payload", "body", "agent_id"],
            &["agent_id"],
            &["target_ref"],
            &["unsigned", "local_target_ref"],
        ],
    )
}

fn agent_endpoint_controller_did(payload: &Value) -> Option<String> {
    string_at_any_path(
        payload,
        &[
            &["body", "controller_subject_id"],
            &["body", "controller_did"],
            &["payload", "controller_subject_id"],
            &["payload", "controller_did"],
            &["payload", "body", "controller_subject_id"],
            &["payload", "body", "controller_did"],
            &["controller_subject_id"],
            &["controller_did"],
            &["actor_id"],
            &["actor"],
        ],
    )
}

fn agent_endpoint_controller_handle(payload: &Value) -> Option<String> {
    string_at_any_path(
        payload,
        &[
            &["body", "controller_handle_at_time"],
            &["body", "controller_handle"],
            &["payload", "controller_handle_at_time"],
            &["payload", "controller_handle"],
            &["payload", "body", "controller_handle_at_time"],
            &["payload", "body", "controller_handle"],
            &["controller_handle_at_time"],
            &["controller_handle"],
        ],
    )
    .and_then(|handle| {
        crate::identity_handle::parse_user_handle(&handle).map(|parsed| parsed.handle)
    })
}

fn agent_endpoint_slug(payload: &Value) -> Option<String> {
    string_at_any_path(
        payload,
        &[
            &["body", "agent_slug"],
            &["payload", "agent_slug"],
            &["payload", "body", "agent_slug"],
            &["agent_slug"],
        ],
    )
    .filter(|slug| cokret_sdk::models::validate_agent_slug(slug).is_ok())
}

fn agent_endpoint_display_name(payload: &Value, agent_id: &str) -> Option<String> {
    string_at_any_path(
        payload,
        &[
            &["body", "display_name"],
            &["body", "agent_display_name"],
            &["payload", "display_name"],
            &["payload", "agent_display_name"],
            &["payload", "body", "display_name"],
            &["payload", "body", "agent_display_name"],
            &["display_name"],
            &["agent_display_name"],
        ],
    )
    .and_then(|value| clean_participant_display_name(&value, Some(agent_id)))
}

fn merge_agent_metadata(existing: &mut AgentParticipantMetadata, next: AgentParticipantMetadata) {
    if existing.controller_did.is_empty() {
        existing.controller_did = next.controller_did;
    }
    if existing.controller_handle.is_empty() {
        existing.controller_handle = next.controller_handle;
    }
    if existing.agent_slug.is_empty() {
        existing.agent_slug = next.agent_slug;
    }
    if existing.display_name.is_empty() {
        existing.display_name = next.display_name;
    }
}

/// Scan local raw operations for `ck.agent.endpoint` rows and return
/// display metadata keyed by agent DID. The endpoint event only requires
/// `agent_id`; controller / slug / display fields are optional and are
/// consumed only when present. Missing controller falls back to the
/// endpoint event actor.
pub(super) fn agent_metadata_from_raw_operations(
    raw_operations: &[crate::local_state::RawOperationRecord],
    realm_id: &str,
) -> std::collections::BTreeMap<String, AgentParticipantMetadata> {
    let mut out = std::collections::BTreeMap::new();
    for record in raw_operations {
        if raw_operation_kind(&record.payload) != Some("ck.agent.endpoint") {
            continue;
        }
        if !raw_operation_realm_matches(record, realm_id) {
            continue;
        }
        let Some(agent_id) = agent_endpoint_agent_id(&record.payload) else {
            continue;
        };
        let next = AgentParticipantMetadata {
            controller_did: agent_endpoint_controller_did(&record.payload).unwrap_or_default(),
            controller_handle: agent_endpoint_controller_handle(&record.payload)
                .or_else(|| {
                    agent_endpoint_controller_did(&record.payload)
                        .and_then(|did| crate::views::helpers::handle_display_from_did(&did))
                })
                .unwrap_or_default(),
            agent_slug: agent_endpoint_slug(&record.payload).unwrap_or_default(),
            display_name: agent_endpoint_display_name(&record.payload, &agent_id)
                .unwrap_or_default(),
        };
        out.entry(agent_id)
            .and_modify(|existing| merge_agent_metadata(existing, next.clone()))
            .or_insert(next);
    }
    out
}

/// Compatibility helper for older call sites and tests that only need
/// the endpoint DID set.
#[cfg(test)]
pub(super) fn agent_ids_from_raw_operations(
    raw_operations: &[crate::local_state::RawOperationRecord],
    realm_id: &str,
) -> Vec<String> {
    agent_metadata_from_raw_operations(raw_operations, realm_id)
        .into_keys()
        .collect()
}

pub(super) fn agent_metadata_from_mentions(
    messages: &[ChatMessage],
) -> std::collections::BTreeMap<String, AgentParticipantMetadata> {
    let mut out = std::collections::BTreeMap::new();
    for mention in messages
        .iter()
        .flat_map(|message| message.mentions.iter())
        .filter_map(MentionNode::as_mention)
    {
        let agent_slug = mention.agent_slug_at_time.as_deref().unwrap_or_default();
        let Some(controller_subject_id) = mention.controller_subject_id.as_ref() else {
            continue;
        };
        if agent_slug.is_empty()
            || controller_subject_id.as_str().trim().is_empty()
            || cokret_sdk::models::validate_agent_slug(agent_slug).is_err()
        {
            continue;
        }
        let next = AgentParticipantMetadata {
            controller_did: controller_subject_id.as_str().trim().to_owned(),
            controller_handle: mention
                .controller_handle_at_time
                .as_ref()
                .and_then(|handle| crate::identity_handle::parse_user_handle(handle.canonical()))
                .map(|parsed| parsed.handle)
                .unwrap_or_default(),
            agent_slug: agent_slug.trim().to_owned(),
            display_name: clean_participant_display_name(
                mention.display_name_at_time.as_deref().unwrap_or_default(),
                Some(mention.subject_id.as_str()),
            )
            .unwrap_or_default(),
        };
        out.entry(mention.subject_id.as_str().trim().to_owned())
            .and_modify(|existing| merge_agent_metadata(existing, next.clone()))
            .or_insert(next);
    }
    out
}

pub(super) fn merge_agent_metadata_maps(
    base: &mut std::collections::BTreeMap<String, AgentParticipantMetadata>,
    overlay: std::collections::BTreeMap<String, AgentParticipantMetadata>,
) {
    for (agent_id, metadata) in overlay {
        base.entry(agent_id)
            .and_modify(|existing| merge_agent_metadata(existing, metadata.clone()))
            .or_insert(metadata);
    }
}

/// Mark every participant whose DID appears in `agent_ids` as
/// `is_agent = true`. No-op for unknown DIDs.
#[cfg(test)]
pub(super) fn annotate_agent_participants(
    participants: &mut [SpaceParticipant],
    agent_ids: &[String],
) {
    if agent_ids.is_empty() {
        return;
    }
    for participant in participants.iter_mut() {
        if agent_ids.iter().any(|did| did == &participant.did) {
            participant.is_agent = true;
        }
    }
}

pub(super) fn upsert_agent_participants(
    participants: &mut Vec<SpaceParticipant>,
    agent_metadata: &std::collections::BTreeMap<String, AgentParticipantMetadata>,
    account_did: &str,
) {
    for (agent_id, metadata) in agent_metadata {
        if participants
            .iter()
            .any(|participant| participant.did == *agent_id)
        {
            continue;
        }
        participants.push(SpaceParticipant {
            did: agent_id.clone(),
            display_name: (!metadata.display_name.is_empty())
                .then_some(metadata.display_name.clone()),
            handle_label: None,
            display_name_rank: if metadata.display_name.is_empty() {
                u8::MAX
            } else {
                1
            },
            role: SpaceParticipantRole::Member,
            is_self: agent_id == account_did,
            is_agent: true,
            agent_metadata: Some(metadata.clone()),
        });
    }
}

pub(super) fn annotate_agent_participants_with_metadata(
    participants: &mut [SpaceParticipant],
    agent_metadata: &std::collections::BTreeMap<String, AgentParticipantMetadata>,
) {
    for participant in participants.iter_mut() {
        if let Some(metadata) = agent_metadata.get(&participant.did) {
            participant.is_agent = true;
            participant.agent_metadata = Some(metadata.clone());
            if participant.display_name.is_none() && !metadata.display_name.is_empty() {
                participant.display_name = Some(metadata.display_name.clone());
                participant.display_name_rank = 1;
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum ParticipantRosterRow {
    Participant(SpaceParticipant),
    ControllerWithAgents {
        controller: SpaceParticipant,
        agents: Vec<SpaceParticipant>,
    },
}

pub(super) fn participant_roster_rows(
    participants: &[SpaceParticipant],
) -> Vec<ParticipantRosterRow> {
    let visible_dids = participants
        .iter()
        .map(|participant| participant.did.as_str())
        .collect::<std::collections::BTreeSet<_>>();
    let mut agents_by_controller =
        std::collections::BTreeMap::<String, Vec<SpaceParticipant>>::new();
    for participant in participants
        .iter()
        .filter(|participant| participant.is_agent)
    {
        let Some(metadata) = participant.agent_metadata.as_ref() else {
            continue;
        };
        if metadata.controller_did.is_empty()
            || !visible_dids.contains(metadata.controller_did.as_str())
        {
            continue;
        }
        agents_by_controller
            .entry(metadata.controller_did.clone())
            .or_default()
            .push(participant.clone());
    }

    for agents in agents_by_controller.values_mut() {
        agents.sort_by(|left, right| {
            agent_display_label(left)
                .cmp(&agent_display_label(right))
                .then(left.did.cmp(&right.did))
        });
    }

    let grouped_agent_dids = agents_by_controller
        .values()
        .flatten()
        .map(|agent| agent.did.as_str())
        .collect::<std::collections::BTreeSet<_>>();

    let mut rows = Vec::new();
    for participant in participants {
        if grouped_agent_dids.contains(participant.did.as_str()) {
            continue;
        }
        if let Some(agents) = agents_by_controller.get(&participant.did)
            && !agents.is_empty()
        {
            rows.push(ParticipantRosterRow::ControllerWithAgents {
                controller: participant.clone(),
                agents: agents.clone(),
            });
            continue;
        }
        rows.push(ParticipantRosterRow::Participant(participant.clone()));
    }
    rows
}

pub(super) fn collect_participant_field(
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
                    participant_handle_label_from_value(item, Some(&did)),
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
            participant_handle_label_from_value(field, Some(&did)),
        );
    }
}

pub(super) fn collect_state_participants(
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
            let handle_label = participant_handle_label_from_value(body, Some(&did))
                .or_else(|| participant_handle_label_from_value(item, Some(&did)));
            upsert_participant(
                participants,
                &did,
                role,
                account_did,
                display_name,
                handle_label,
            );
        }
    }
}

pub(super) fn space_participants(
    projection: Option<&Value>,
    account_did: &str,
) -> Vec<SpaceParticipant> {
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

pub(super) fn display_label_for_actor(
    state_store: &LocalStateStore,
    participants: &[SpaceParticipant],
    live_labels: &std::collections::BTreeMap<String, String>,
    did: &str,
) -> String {
    if let Some(label) = live_labels
        .get(did)
        .and_then(|label| clean_participant_display_name(label, Some(did)))
    {
        return label;
    }
    participants
        .iter()
        .find(|participant| participant.did == did)
        .and_then(participant_sender_label)
        .unwrap_or_else(|| crate::views::helpers::display_name_for_did(state_store, did))
}

pub(super) fn is_own_message_sender(sender: &str, account_did: &str) -> bool {
    let sender = sender.trim();
    !sender.is_empty() && (sender == "yougen" || sender == account_did.trim())
}

pub(super) fn short_principal_label(value: &str) -> String {
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

pub(super) fn agent_display_label(participant: &SpaceParticipant) -> String {
    participant
        .agent_metadata
        .as_ref()
        .and_then(|metadata| {
            (!metadata.display_name.trim().is_empty()).then_some(metadata.display_name.clone())
        })
        .or_else(|| participant.display_name.clone())
        .or_else(|| participant_handle_label(participant))
        .unwrap_or_else(|| short_principal_label(&participant.did))
}

pub(super) fn participant_sender_label(participant: &SpaceParticipant) -> Option<String> {
    if participant.is_agent {
        return Some(agent_display_label(participant));
    }
    participant_handle_label(participant).or_else(|| participant.display_name.clone())
}

pub(super) fn participant_handle_label(participant: &SpaceParticipant) -> Option<String> {
    participant
        .handle_label
        .clone()
        .or_else(|| crate::views::helpers::handle_display_from_did(&participant.did))
}

pub(super) fn participant_roster_display_label(
    state_store: &LocalStateStore,
    participant: &SpaceParticipant,
) -> String {
    if participant.is_agent {
        return agent_display_label(participant);
    }
    participant_sender_label(participant).unwrap_or_else(|| {
        crate::views::helpers::display_name_for_did(state_store, &participant.did)
    })
}

pub(super) fn agent_controller_label(
    participant: &SpaceParticipant,
    participants: &[SpaceParticipant],
) -> Option<String> {
    let metadata = participant.agent_metadata.as_ref()?;
    if !metadata.controller_handle.trim().is_empty() {
        return Some(metadata.controller_handle.clone());
    }
    participants
        .iter()
        .find(|candidate| candidate.did == metadata.controller_did)
        .and_then(participant_sender_label)
        .or_else(|| crate::views::helpers::handle_display_from_did(&metadata.controller_did))
        .or_else(|| {
            (!metadata.controller_did.trim().is_empty())
                .then(|| short_principal_label(&metadata.controller_did))
        })
}

pub(super) fn agent_selector_label(participant: &SpaceParticipant) -> Option<String> {
    let metadata = participant.agent_metadata.as_ref()?;
    if metadata.controller_handle.trim().is_empty() || metadata.agent_slug.trim().is_empty() {
        return None;
    }
    Some(format!(
        "{}/{}",
        metadata.controller_handle.trim(),
        metadata.agent_slug.trim()
    ))
}

pub(super) fn mention_candidate_for_participant(
    participant: &SpaceParticipant,
    participants: &[SpaceParticipant],
) -> Option<crate::messaging::mentions::MentionCandidate> {
    if participant.is_agent {
        let display_name = agent_display_label(participant);
        let selector = agent_selector_label(participant);
        let metadata = participant.agent_metadata.as_ref();
        let controller_label = agent_controller_label(participant, participants);
        return Some(crate::messaging::mentions::MentionCandidate {
            did: participant.did.clone(),
            display_name,
            insert_label: selector.unwrap_or_else(|| {
                mention_label_for_participant(participant)
                    .unwrap_or_else(|| short_principal_label(&participant.did))
            }),
            subtitle: controller_label
                .map(|label| format!("agent of {label}"))
                .unwrap_or_else(|| "agent".to_owned()),
            is_agent: true,
            controller_subject_id: metadata
                .map(|metadata| metadata.controller_did.clone())
                .unwrap_or_default(),
            controller_handle_at_time: metadata
                .map(|metadata| metadata.controller_handle.clone())
                .unwrap_or_default(),
            agent_slug_at_time: metadata
                .map(|metadata| metadata.agent_slug.clone())
                .unwrap_or_default(),
        });
    }

    mention_label_for_participant(participant).map(|display_name| {
        crate::messaging::mentions::MentionCandidate {
            did: participant.did.clone(),
            display_name,
            insert_label: String::new(),
            subtitle: String::new(),
            is_agent: false,
            controller_subject_id: String::new(),
            controller_handle_at_time: String::new(),
            agent_slug_at_time: String::new(),
        }
    })
}

pub(super) fn sender_display_label(
    sender: &str,
    account_did: &str,
    account_display_name: &str,
    participants: &[SpaceParticipant],
) -> String {
    if is_own_message_sender(sender, account_did) {
        let account_did = account_did.trim();
        let own_participant = participants
            .iter()
            .find(|participant| participant.did == account_did);
        return own_participant
            .and_then(|participant| participant.handle_label.clone())
            .or_else(|| clean_participant_display_name(account_display_name, Some(account_did)))
            .or_else(|| own_participant.and_then(|participant| participant.display_name.clone()))
            .or_else(|| crate::views::helpers::handle_display_from_did(account_did))
            .unwrap_or_else(|| {
                if account_did.is_empty() {
                    "yougen".to_owned()
                } else {
                    short_principal_label(account_did)
                }
            });
    }
    participants
        .iter()
        .find(|participant| participant.did == sender.trim())
        .and_then(participant_sender_label)
        .or_else(|| crate::views::helpers::handle_display_from_did(sender))
        .unwrap_or_else(|| short_principal_label(sender))
}

pub(super) fn chat_reply_quote_preview(
    messages: &[ChatMessage],
    reply_id: &str,
    account_did: &str,
    account_display_name: &str,
    participants: &[SpaceParticipant],
) -> Option<(String, String)> {
    let quoted = messages.iter().find(|m| m.id == reply_id)?;
    let name = sender_display_label(
        &quoted.sender,
        account_did,
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

pub(super) fn watch_level_label_key(level: WatchLevel) -> &'static str {
    match level {
        WatchLevel::MentionsOnly => "chat.watch_level.mentions_only",
        WatchLevel::Participating => "chat.watch_level.participating",
        WatchLevel::All => "chat.watch_level.all",
        WatchLevel::Muted => "chat.watch_level.muted",
    }
}

pub(super) fn watch_level_wire_value(level: WatchLevel) -> &'static str {
    level.as_wire()
}

#[cfg(test)]
pub(super) fn watch_level_from_wire(value: &str) -> WatchLevel {
    if value == "none" {
        WatchLevel::Muted
    } else {
        WatchLevel::from_wire(value).unwrap_or(WatchLevel::All)
    }
}

pub(super) fn is_schema_message_id(value: &str) -> bool {
    let Some(suffix) = value.trim().strip_prefix("ck:message:") else {
        return false;
    };
    !suffix.is_empty()
        && suffix
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.' | ':'))
}

pub(super) fn new_chat_message_id() -> String {
    format!("ck:message:{}", uuid_v7())
}

pub(super) fn schema_message_id_or_new(value: &str) -> String {
    if is_schema_message_id(value) {
        value.trim().to_owned()
    } else {
        new_chat_message_id()
    }
}

// YOU-02-001: these helpers return `Result` instead of panicking — the
// realm/strand ids they parse come from server-synced UI state, and a
// non-canonical id must not abort the client (wasm panic = blank page).
pub(super) fn sdk_payload_value(
    result: cokret_sdk::Result<Value>,
    context: &str,
) -> anyhow::Result<Value> {
    result.map_err(|err| anyhow::anyhow!("{context}: {err}"))
}

pub(super) fn strand_id_value(value: &str) -> anyhow::Result<cokret_sdk::StrandId> {
    cokret_sdk::StrandId::new(value.to_owned())
        .map_err(|err| anyhow::anyhow!("invalid strand id {value:?}: {err:?}"))
}

pub(super) fn chat_message_create_operation(
    realm_id: &str,
    actor: &str,
    strand_id: &str,
    _channel_kind: &str,
    message_id: &str,
    body: &str,
    mentions: &[MentionNode],
    reply_to: Option<&str>,
) -> anyhow::Result<crate::operation::EventEnvelope> {
    let actor_mentions = mentions
        .iter()
        .filter_map(|mention| mention.as_mention().cloned())
        .collect::<Vec<_>>();
    let audience_mentions = mentions
        .iter()
        .filter_map(|mention| mention.as_audience_mention().cloned())
        .collect::<Vec<_>>();
    let mut content = cokret_sdk::ContentBlock::text(body);
    if !actor_mentions.is_empty() {
        content = content
            .with_mentions(actor_mentions)
            .map_err(|err| anyhow::anyhow!("chat message mentions serialize: {err}"))?;
    }
    if !audience_mentions.is_empty() {
        content = content
            .with_audience_mentions(audience_mentions)
            .map_err(|err| anyhow::anyhow!("chat message audience_mentions serialize: {err}"))?;
    }
    // T2.3: v1 wire uses `track_name` — a display-only timeline segment
    // identifier — instead of the removed `branch` top-level field.
    let mut payload = cokret_sdk::MessageCreatePayload::with_content(
        strand_id_value(strand_id)?,
        "discussion",
        sdk_payload_value(content.to_value(), "chat message content serialize")?,
    )
    .with_message_id(message_id);
    if let Some(reply_to) = reply_to.filter(|value| !value.trim().is_empty()) {
        payload = payload.with_reply_to(reply_to);
    }
    Ok(OperationBuilder::new(realm_id, actor, "ck.message.create")
        .target_ref(strand_id)
        .body(sdk_payload_value(
            payload.to_value(),
            "chat ck.message.create payload serialize",
        )?)
        .build("yougen"))
}

pub(super) fn chat_send_error_message(error: &anyhow::Error) -> String {
    if is_auth_expired_error(error) {
        "Session expired while sending. Refresh the session or sign in again, then retry."
            .to_owned()
    } else if is_plaintext_visibility_policy_error(error) {
        "Plaintext is not enabled for this Realm on the current service. Send Secure or update Realm plaintext visibility."
            .to_owned()
    } else if is_space_membership_denied_error(error) {
        "This account is not a member of this Realm. Join the Realm or switch to an account that is a member before sending."
            .to_owned()
    } else {
        error.to_string()
    }
}

pub(super) fn collect_plaintext_services(value: &Value, services: &mut Vec<String>) {
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

pub(super) fn plaintext_services_for_policy(
    projection: Option<&Value>,
    service_did: &str,
) -> Vec<String> {
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

pub(super) fn value_string_at<'a>(value: &'a Value, keys: &[&str]) -> Option<&'a str> {
    keys.iter()
        .find_map(|key| value.get(*key).and_then(Value::as_str))
}

pub(super) fn collect_message_candidates<'a>(
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

pub(super) fn message_candidates(event: &Value) -> Vec<&Value> {
    let mut candidates = Vec::new();
    collect_message_candidates(event, &mut candidates, 0);
    candidates
}

pub(super) fn first_string_in_candidates<'a>(
    candidates: &[&'a Value],
    keys: &[&str],
) -> Option<&'a str> {
    candidates
        .iter()
        .find_map(|candidate| value_string_at(candidate, keys))
}

pub(super) fn message_actor_from_candidates<'a>(candidates: &[&'a Value]) -> Option<&'a str> {
    first_string_in_candidates(candidates, &["actor_id", "sender_actor_id"])
}

pub(super) fn message_kind_is_create(value: &Value) -> bool {
    value_string_at(value, &["kind", "type", "op_type", "event_type"]) == Some("ck.message.create")
}

pub(super) fn text_from_blocks(value: &Value) -> Option<&str> {
    value
        .get("blocks")
        .and_then(Value::as_array)
        .and_then(|blocks| blocks.first())
        .and_then(|block| block.get("text"))
        .and_then(Value::as_str)
}

pub(super) fn text_body_from_value(value: &Value) -> Option<&str> {
    value_string_at(value, &["body", "text", "message", "plain_text"])
        .or_else(|| text_from_blocks(value))
        .or_else(|| {
            value
                .get("content")
                .filter(|content| content.is_object())
                .and_then(text_body_from_value)
        })
}

pub(super) fn text_body_from_message(candidates: &[&Value]) -> Option<String> {
    candidates
        .iter()
        .find_map(|candidate| text_body_from_value(candidate))
        .map(ToOwned::to_owned)
}

pub(super) fn short_message_time(value: Option<&str>) -> String {
    value
        .and_then(|raw| chrono::DateTime::parse_from_rfc3339(raw).ok())
        .map(|time| time.format("%H:%M").to_string())
        .or_else(|| value.map(ToOwned::to_owned))
        .unwrap_or_default()
}

pub(super) fn mentions_from_value(value: &Value) -> Vec<MentionNode> {
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

pub(super) fn mentions_from_candidates(candidates: &[&Value]) -> Vec<MentionNode> {
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

pub(super) fn seq_from_candidates(candidates: &[&Value]) -> Option<u64> {
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

pub(super) fn chat_message_from_event(realm_id: &str, event: &Value) -> Option<ChatMessage> {
    chat_message_from_event_with_sidecar(realm_id, event, None, None)
}

/// P0 decrypt-on-read: turn a remote member's canonical `encrypted_content`
/// envelope into a plaintext chat body.
///
/// Parses the canonical `ck.schema.encrypted_envelope.v1` shape, unwraps it
/// to the typed [`cokret_sdk::EncryptedPayload`], and hands it to the shared
/// MLS decrypt core. The decrypted bytes are the canonical Content Block JSON
/// (see the secure send path), so we parse them and extract the display text.
/// Returns `None` on any soft failure (no local MLS snapshot, wrong/absent
/// device secret, payload that doesn't decrypt) so the caller leaves the
/// message in the `Decrypting`/`KeyMissing` state instead of presenting an
/// undecrypted body.
pub(super) fn decrypt_chat_encrypted_content(
    state_store: &LocalStateStore,
    realm_id: &str,
    actor_id: &str,
    device_id: &str,
    encrypted_content: &Value,
) -> Option<String> {
    let envelope =
        serde_json::from_value::<cokret_sdk::EncryptedEnvelopeV1>(encrypted_content.clone())
            .ok()?;
    let payload_value = serde_json::to_value(envelope.to_payload().ok()?).ok()?;
    let plaintext = crate::views::timeline::try_local_mls_decrypt_core(
        state_store,
        realm_id,
        actor_id,
        device_id,
        &payload_value,
    )?;
    let content_value = serde_json::from_slice::<Value>(&plaintext).ok()?;
    text_body_from_value(&content_value).map(ToOwned::to_owned)
}

/// X9 — build a `ChatMessage` from a synced/projected event, preferring the
/// author's own local plaintext sidecar (`mls_private_plaintext`, keyed by
/// `message:{message_id}`) over the encrypted payload. OpenMLS forbids an
/// author from decrypting their OWN application messages, so for the author's
/// encrypted messages the ciphertext is undecryptable and the timeline carries
/// no plaintext body. Without the sidecar, keep the message as a visible
/// crypto-pending row instead of dropping it, so a fresh browser shows "locked"
/// rather than "No messages". The sidecar lookup mirrors kanban's
/// `private_strand_field_text`.
pub(super) fn chat_message_from_event_with_sidecar(
    realm_id: &str,
    event: &Value,
    state_store: Option<&LocalStateStore>,
    decrypt_identity: Option<(&str, &str)>,
) -> Option<ChatMessage> {
    let candidates = message_candidates(event);
    if poll_content_from_candidates(&candidates)
        .and_then(|content| content.get("kind").and_then(Value::as_str))
        .is_some_and(|kind| matches!(kind, "ck.content.poll.response" | "ck.content.poll.close"))
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
    // Author-owned plaintext sidecar: look up the body the author stored on
    // encrypted send, keyed by `message:{message_id}` under the discussion
    // strand. Falls back to the decoded payload body (another member's message
    // we CAN decrypt, or a plaintext message).
    let sidecar_body = state_store.and_then(|store| {
        let message_id = first_string_in_candidates(&candidates, &["message_id"])?;
        let strand_id = first_string_in_candidates(&candidates, &["strand_id", "thread_id"])?;
        store.private_plaintext_for(message_realm, strand_id, &format!("message:{message_id}"))
    });
    let body_from_sidecar = sidecar_body.is_some();
    // P0 decrypt-on-read: a remote member's message carries ciphertext but no
    // author sidecar. Parse the canonical envelope, decrypt with this device's
    // MLS snapshot secret, and extract the Content Block text. Soft-fails to
    // `None` (→ Decrypting/KeyMissing) when the snapshot/secret is unavailable.
    let decrypted_body = if !body_from_sidecar
        && let (Some((actor_id, device_id)), Some(store), Some(encrypted)) = (
            decrypt_identity,
            state_store,
            encrypted_content_value.as_ref(),
        ) {
        decrypt_chat_encrypted_content(store, message_realm, actor_id, device_id, encrypted)
    } else {
        None
    };
    let body_was_decrypted = decrypted_body.is_some();
    let body = match sidecar_body.or(decrypted_body) {
        Some(plaintext) => plaintext,
        None if has_encrypted_payload => String::new(),
        None => text_body_from_message(&candidates)?,
    };
    let explicit_message_kind = candidates
        .iter()
        .any(|candidate| message_kind_is_create(candidate));
    let message_payload_shape =
        first_string_in_candidates(&candidates, &["message_id", "strand_id", "thread_id"])
            .is_some();
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
    let strand_id = first_string_in_candidates(&candidates, &["strand_id", "thread_id"])
        .or_else(|| {
            event
                .get("unsigned")
                .and_then(|unsigned| unsigned.get("local_target_ref"))
                .and_then(Value::as_str)
        })
        .filter(|value| value.starts_with("ck:strand:"))
        .unwrap_or("ck:strand:general")
        .to_owned();
    // CKP-0007 P3B.2.7 — compare the envelope's `effective_scope`
    // against the payload `scope_circle_id`. When they disagree we
    // route the message into `NeedsVerification` so the UI badge
    // surfaces the mismatch rather than presenting a body decrypted
    // under the wrong MLS group as trustworthy.
    let effective_scope_circle = candidates
        .iter()
        .find_map(|candidate| {
            candidate
                .get("effective_scope")
                .and_then(|scope| scope.get("circle_id"))
                .and_then(|value| value.as_str())
                .map(str::trim)
                .filter(|value| !value.is_empty())
        })
        .map(ToOwned::to_owned);
    let payload_scope_circle = candidates
        .iter()
        .find_map(|candidate| {
            candidate
                .get("scope_circle_id")
                .or_else(|| {
                    candidate
                        .get("content")
                        .and_then(|content| content.get("scope_circle_id"))
                })
                .and_then(|value| value.as_str())
                .map(str::trim)
                .filter(|value| !value.is_empty())
        })
        .map(ToOwned::to_owned);
    let scope_mismatch = match (
        effective_scope_circle.as_deref(),
        payload_scope_circle.as_deref(),
    ) {
        (None, None) => false,
        (Some(env), Some(payload)) => env != payload,
        // One side mentions a Circle but the other doesn't — flag it
        // so the user is prompted to verify before trusting the body.
        _ => true,
    };
    let crypto_state = if scope_mismatch {
        MessageCryptoState::NeedsVerification
    } else if body_from_sidecar || body_was_decrypted {
        // X9: the author's own plaintext was recovered from the local sidecar,
        // OR (P0) a remote member's ciphertext was decrypted-on-read — the body
        // is authoritative and fully resolved, so do not leave it stuck in
        // `Decrypting`.
        MessageCryptoState::Plaintext
    } else if has_encrypted_payload {
        MessageCryptoState::Decrypting
    } else {
        MessageCryptoState::Plaintext
    };
    Some(ChatMessage {
        realm_id: first_string_in_candidates(&candidates, &["realm_id"])
            .unwrap_or(realm_id)
            .to_owned(),
        id: event_id,
        sender: message_actor_from_candidates(&candidates)
            .unwrap_or("did:web:unknown")
            .to_owned(),
        body,
        timestamp: short_message_time(first_string_in_candidates(&candidates, &["created_at"])),
        strand_id,
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
        crypto_state,
    })
}

pub(super) fn chat_messages_from_events_with_sidecar(
    realm_id: &str,
    events: &[Value],
    state_store: Option<&LocalStateStore>,
    decrypt_identity: Option<(&str, &str)>,
) -> Vec<ChatMessage> {
    events
        .iter()
        .filter_map(|event| {
            chat_message_from_event_with_sidecar(realm_id, event, state_store, decrypt_identity)
        })
        .collect()
}

pub(super) fn poll_content_from_candidates<'a>(candidates: &[&'a Value]) -> Option<&'a Value> {
    candidates
        .iter()
        .find(|candidate| {
            candidate
                .get("kind")
                .and_then(Value::as_str)
                .is_some_and(|kind| {
                    matches!(
                        kind,
                        "ck.content.poll" | "ck.content.poll.response" | "ck.content.poll.close"
                    )
                })
        })
        .copied()
}

pub(super) fn poll_cards_from_events(events: &[Value]) -> Vec<crate::messaging::polls::PollCard> {
    let mut cards = Vec::<crate::messaging::polls::PollCard>::new();
    let mut by_poll_id = std::collections::BTreeMap::<String, usize>::new();
    for event in events {
        let candidates = message_candidates(event);
        let Some(content) = poll_content_from_candidates(&candidates) else {
            continue;
        };
        if let Some((poll_id, choices)) =
            crate::messaging::polls::poll_response_from_content(content)
        {
            let actor = message_actor_from_candidates(&candidates).unwrap_or("did:web:unknown");
            if let Some(index) = by_poll_id.get(&poll_id).copied() {
                cards[index].vote_choices(actor, &choices);
            }
            continue;
        }
        if let Some(poll_id) = crate::messaging::polls::poll_close_id_from_content(content) {
            if let Some(index) = by_poll_id.get(&poll_id).copied() {
                cards[index].close();
            }
            continue;
        }
        let Some(message) = chat_message_from_event("", event) else {
            continue;
        };
        if let Some(card) =
            crate::messaging::polls::PollCard::from_content(message.id.clone(), content)
        {
            by_poll_id.insert(card.poll_id.clone(), cards.len());
            cards.push(card);
        }
    }
    cards
}

pub(super) fn chat_messages_from_sync_realms_with_sidecar(
    realms: &std::collections::BTreeMap<String, Value>,
    state_store: Option<&LocalStateStore>,
    decrypt_identity: Option<(&str, &str)>,
) -> Vec<ChatMessage> {
    let mut messages = Vec::new();
    for (realm_id, body) in realms {
        let Some(timeline_events) = body
            .get("timeline")
            .and_then(|timeline| timeline.get("events"))
            .and_then(Value::as_array)
        else {
            continue;
        };
        messages.extend(chat_messages_from_events_with_sidecar(
            realm_id,
            timeline_events,
            state_store,
            decrypt_identity,
        ));
    }
    messages
}

pub(super) fn poll_cards_from_sync_realms(
    realms: &std::collections::BTreeMap<String, Value>,
) -> Vec<crate::messaging::polls::PollCard> {
    let mut cards = Vec::new();
    for body in realms.values() {
        let Some(timeline_events) = body
            .get("timeline")
            .and_then(|timeline| timeline.get("events"))
            .and_then(Value::as_array)
        else {
            continue;
        };
        cards.extend(poll_cards_from_events(timeline_events));
    }
    cards
}

pub(super) fn normalize_sync_realm_id(realm_id: &str) -> String {
    realm_id.trim().to_owned()
}

pub(super) fn sync_realm_ids_match(left: &str, right: &str) -> bool {
    normalize_sync_realm_id(left) == normalize_sync_realm_id(right)
}

pub(super) fn typing_actors_from_sync_realms(
    realms: &std::collections::BTreeMap<String, Value>,
    realm_id: &str,
    account_did: &str,
) -> Vec<String> {
    let mut actors = std::collections::BTreeSet::<String>::new();
    for (candidate_realm_id, body) in realms {
        if !sync_realm_ids_match(candidate_realm_id, realm_id) {
            continue;
        }
        let Some(ephemeral) = body.get("ephemeral").and_then(Value::as_array) else {
            continue;
        };
        for item in ephemeral {
            let kind = value_string_at(item, &["type", "kind"]).unwrap_or_default();
            if kind != "ck.typing" {
                continue;
            }
            let Some(entries) = item.get("actors").and_then(Value::as_array) else {
                continue;
            };
            for entry in entries {
                let actor = value_string_at(entry, &["actor", "actor_id"])
                    .unwrap_or_default()
                    .trim();
                if !actor.is_empty() && actor != account_did {
                    actors.insert(actor.to_owned());
                }
            }
        }
    }
    actors.into_iter().collect()
}

pub(super) fn sync_presence_actor(event: &Value) -> Option<String> {
    value_string_at(event, &["user_id", "actor_id", "actor"])
        .map(str::trim)
        .filter(|actor| !actor.is_empty())
        .map(ToOwned::to_owned)
}

pub(super) fn sync_presence_status(event: &Value) -> Option<String> {
    event
        .get("presence")
        .and_then(|presence| {
            presence
                .as_str()
                .or_else(|| presence.get("status").and_then(Value::as_str))
        })
        .or_else(|| event.get("status").and_then(Value::as_str))
        .map(str::trim)
        .filter(|status| !status.is_empty())
        .map(ToOwned::to_owned)
}

pub(super) fn presence_maps_from_sync_events(
    events: &[Value],
    participants: &[String],
    account_did: &str,
    account_label: &str,
) -> Option<(
    std::collections::BTreeMap<String, String>,
    std::collections::BTreeMap<String, String>,
)> {
    if events.is_empty() {
        return None;
    }
    let participant_set = participants
        .iter()
        .cloned()
        .collect::<std::collections::BTreeSet<_>>();
    let mut states = std::collections::BTreeMap::<String, String>::new();
    let mut labels = std::collections::BTreeMap::<String, String>::new();
    for did in participants {
        states.insert(
            did.clone(),
            if did == account_did {
                "online".to_owned()
            } else {
                "offline".to_owned()
            },
        );
        if did == account_did
            && let Some(label) = clean_participant_display_name(account_label, Some(did))
        {
            labels.insert(did.clone(), label);
        }
    }
    let mut matched_remote = false;
    for event in events {
        let Some(actor) = sync_presence_actor(event) else {
            continue;
        };
        if !participant_set.contains(&actor) {
            continue;
        }
        if actor != account_did {
            matched_remote = true;
        }
        states.insert(
            actor,
            sync_presence_status(event).unwrap_or_else(|| "offline".to_owned()),
        );
    }
    matched_remote.then_some((states, labels))
}

pub(super) fn chat_messages_from_local_state_with_sidecar(
    state: &ClientLocalState,
    state_store: Option<&LocalStateStore>,
    decrypt_identity: Option<(&str, &str)>,
) -> Vec<ChatMessage> {
    state
        .raw_operations
        .iter()
        .filter_map(|record| {
            chat_message_from_event_with_sidecar(
                record.realm_id.as_deref().unwrap_or_default(),
                &record.payload,
                state_store,
                decrypt_identity,
            )
        })
        .collect()
}

pub(super) fn poll_cards_from_local_state(
    state: &ClientLocalState,
) -> Vec<crate::messaging::polls::PollCard> {
    let events = state
        .raw_operations
        .iter()
        .map(|record| record.payload.clone())
        .collect::<Vec<_>>();
    poll_cards_from_events(&events)
}

pub(super) fn bool_at_path(value: &Value, path: &[&str]) -> Option<bool> {
    let mut current = value;
    for key in path {
        current = current.get(*key)?;
    }
    current.as_bool()
}

pub(super) fn string_at_path<'a>(value: &'a Value, path: &[&str]) -> Option<&'a str> {
    let mut current = value;
    for key in path {
        current = current.get(*key)?;
    }
    current.as_str()
}

pub(super) fn first_string_in_candidate_paths<'a>(
    candidates: &[&'a Value],
    paths: &[&[&str]],
) -> Option<&'a str> {
    candidates.iter().find_map(|candidate| {
        paths
            .iter()
            .find_map(|path| string_at_path(candidate, path))
    })
}

pub(super) fn default_discussion_strand_id(realm_id: &str) -> String {
    let trimmed = realm_id.trim();
    if trimmed.starts_with("ck:strand:") {
        trimmed.to_owned()
    } else if let Some(suffix) = trimmed.strip_prefix("ck:realm:") {
        format!("ck:strand:{suffix}")
    } else {
        format!("ck:strand:{}", trimmed.trim_start_matches("ck:"))
    }
}

pub(super) fn candidate_has_track(candidate: &Value, track: &str) -> bool {
    candidate
        .get("tracks")
        .and_then(|tracks| tracks.get(track))
        .is_some()
        || ["object", "strand"].iter().any(|wrapper| {
            candidate
                .get(*wrapper)
                .and_then(|inner| inner.get("tracks"))
                .and_then(|tracks| tracks.get(track))
                .is_some()
        })
}

pub(super) fn strand_create_has_discussion_track(candidates: &[&Value]) -> bool {
    candidates
        .iter()
        .any(|candidate| candidate_has_track(candidate, "discussion"))
}

pub(super) fn strand_create_has_synthesis_track(candidates: &[&Value]) -> bool {
    candidates
        .iter()
        .any(|candidate| candidate_has_track(candidate, "synthesis"))
        || candidates.iter().any(|candidate| {
            bool_at_path(candidate, &["create_card"]).unwrap_or(false)
                || bool_at_path(candidate, &["fields", "has_synthesis"]).unwrap_or(false)
                || bool_at_path(candidate, &["object", "fields", "has_synthesis"]).unwrap_or(false)
                || bool_at_path(candidate, &["strand", "fields", "has_synthesis"]).unwrap_or(false)
        })
}

pub(super) fn strand_security_state_from_candidates(candidates: &[&Value]) -> Option<bool> {
    candidates
        .iter()
        .find_map(|candidate| crate::security_state::strand_projection_security_state(candidate))
}

pub(super) fn channel_from_strand_projection(
    realm_id: &str,
    strand: &Value,
    is_default: bool,
) -> Option<ChannelEntity> {
    if !candidate_has_track(strand, "discussion") {
        return None;
    }

    let strand_id = first_string_in_candidate_paths(&[strand], &[&["strand_id"], &["id"]])
        .map(str::trim)
        .filter(|id| id.starts_with("ck:strand:"))
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| default_discussion_strand_id(realm_id));
    let name = first_string_in_candidate_paths(&[strand], &[&["title"], &["name"]])
        .filter(|title| !title.trim().is_empty())
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| {
            if is_default {
                "Discussion".to_owned()
            } else {
                strand_id.clone()
            }
        });
    let category = first_string_in_candidate_paths(
        &[strand],
        &[
            &["category"],
            &["fields", "category"],
            &["summary", "category"],
        ],
    )
    .filter(|category| !category.trim().is_empty())
    .map(ToOwned::to_owned)
    .unwrap_or_else(|| {
        if is_default {
            "default strand".to_owned()
        } else {
            "general".to_owned()
        }
    });
    let topic = first_string_in_candidate_paths(
        &[strand],
        &[
            &["summary"],
            &["topic"],
            &["description"],
            &["fields", "summary"],
            &["fields", "topic"],
        ],
    )
    .filter(|topic| !topic.trim().is_empty())
    .map(ToOwned::to_owned)
    .or_else(|| {
        if is_default {
            Some("Default Strand discussion track".to_owned())
        } else {
            None
        }
    });
    let has_synthesis = strand_create_has_synthesis_track(&[strand]);
    let security_encrypted = crate::security_state::strand_projection_security_state(strand);
    let scope_circle = strand_scope_circle_from_projection(strand);

    Some(ChannelEntity {
        strand_id,
        name,
        kind: if !is_default && has_synthesis {
            "strand".to_owned()
        } else {
            "discussion".to_owned()
        },
        category,
        topic,
        unread: 0,
        is_default,
        security_encrypted,
        scope_circle,
    })
}

/// Extract the optional Circle-scope projection from a Strand
/// projection JSON. Looks under both the top-level
/// `scope_circle_id` and the canonical `scope.circle_id` shape so
/// the helper tolerates both projection layouts.
pub(super) fn strand_scope_circle_from_projection(strand: &Value) -> Option<StrandScopeCircle> {
    let circle_id = first_string_in_candidate_paths(
        &[strand],
        &[
            &["scope_circle_id"],
            &["scope", "circle_id"],
            &["scope", "scope_circle_id"],
            &["fields", "scope_circle_id"],
        ],
    )
    .map(str::trim)
    .filter(|value| value.starts_with("ck:circle:"))
    .map(ToOwned::to_owned)?;

    let title = first_string_in_candidate_paths(
        &[strand],
        &[
            &["scope_circle_title"],
            &["scope", "circle_title"],
            &["scope", "title"],
        ],
    )
    .filter(|value| !value.trim().is_empty())
    .map(ToOwned::to_owned)
    .unwrap_or_else(|| circle_id.clone());

    let member_count = u32_at_path(strand, &["scope_circle_member_count"])
        .or_else(|| u32_at_path(strand, &["scope", "member_count"]))
        .unwrap_or(0);

    Some(StrandScopeCircle {
        circle_id,
        title,
        member_count,
    })
}

pub(super) fn u32_at_path(value: &Value, path: &[&str]) -> Option<u32> {
    let mut current = value;
    for segment in path {
        current = current.get(segment)?;
    }
    current
        .as_u64()
        .and_then(|raw| u32::try_from(raw).ok())
        .or_else(|| {
            current
                .as_str()
                .and_then(|raw| raw.trim().parse::<u32>().ok())
        })
}

pub(super) fn default_discussion_channel(
    realm_id: &str,
    realm_body: Option<&Value>,
) -> ChannelEntity {
    if let Some(strand) = realm_body
        .and_then(|body| body.get("summary"))
        .and_then(|summary| summary.get("strand"))
        && let Some(channel) = channel_from_strand_projection(realm_id, strand, true)
    {
        return channel;
    }

    ChannelEntity {
        strand_id: default_discussion_strand_id(realm_id),
        name: "Discussion".to_owned(),
        kind: "discussion".to_owned(),
        category: "default strand".to_owned(),
        topic: Some("Default Strand discussion track".to_owned()),
        unread: 0,
        is_default: true,
        security_encrypted: realm_body.map(crate::security_state::realm_projection_is_encrypted),
        scope_circle: None,
    }
}

pub(super) fn discussion_channel_for_strand(realm_id: &str, strand_id: &str) -> ChannelEntity {
    let trimmed_strand_id = strand_id.trim();
    if trimmed_strand_id.is_empty() {
        return default_discussion_channel(realm_id, None);
    }

    ChannelEntity {
        strand_id: trimmed_strand_id.to_owned(),
        name: "Discussion".to_owned(),
        kind: "discussion".to_owned(),
        category: "discussion".to_owned(),
        topic: None,
        unread: 0,
        is_default: trimmed_strand_id == default_discussion_strand_id(realm_id),
        security_encrypted: None,
        scope_circle: None,
    }
}

pub(super) fn channel_from_strand_event(realm_id: &str, event: &Value) -> Option<ChannelEntity> {
    let candidates = message_candidates(event);
    if !candidates
        .iter()
        .any(|candidate| value_string_at(candidate, &["kind", "type"]) == Some("ck.strand.create"))
    {
        return None;
    }
    if !strand_create_has_discussion_track(&candidates)
        && !candidates.iter().any(|candidate| {
            // T2.3: the v1 wire uses `track_name`; writers MUST NOT emit the
            // removed `branch` field.
            value_string_at(candidate, &["track_name"]) == Some("discussion")
        })
    {
        return None;
    }

    let strand_id = first_string_in_candidate_paths(
        &candidates,
        &[
            &["strand_id"],
            &["target_ref"],
            &["object", "id"],
            &["object", "strand_id"],
            &["strand", "id"],
            &["strand", "strand_id"],
        ],
    )?
    .trim();
    if !strand_id.starts_with("ck:strand:") {
        return None;
    }

    let name = first_string_in_candidate_paths(
        &candidates,
        &[
            &["title"],
            &["name"],
            &["object", "title"],
            &["object", "name"],
            &["strand", "title"],
            &["strand", "name"],
        ],
    )
    .unwrap_or(strand_id)
    .to_owned();
    let category = first_string_in_candidate_paths(
        &candidates,
        &[
            &["category"],
            &["fields", "category"],
            &["object", "fields", "category"],
            &["strand", "fields", "category"],
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
            &["object", "summary"],
            &["object", "topic"],
            &["object", "description"],
            &["strand", "summary"],
            &["strand", "topic"],
            &["strand", "description"],
        ],
    )
    .map(ToOwned::to_owned);
    let has_synthesis = strand_create_has_synthesis_track(&candidates);
    let security_encrypted = strand_security_state_from_candidates(&candidates);
    let scope_circle = candidates
        .iter()
        .find_map(|candidate| strand_scope_circle_from_projection(candidate));

    Some(ChannelEntity {
        strand_id: strand_id.to_owned(),
        name,
        kind: if has_synthesis {
            "strand".to_owned()
        } else {
            "discussion".to_owned()
        },
        category,
        topic,
        unread: 0,
        is_default: strand_id == default_discussion_strand_id(realm_id),
        security_encrypted,
        scope_circle,
    })
}

pub(super) fn channels_from_events(realm_id: &str, events: &[Value]) -> Vec<ChannelEntity> {
    events
        .iter()
        .filter_map(|event| channel_from_strand_event(realm_id, event))
        .collect()
}

pub(super) fn channels_from_sync_realms(
    realms: &std::collections::BTreeMap<String, Value>,
    default_realm_ids: &[String],
) -> Vec<ChannelEntity> {
    let mut channels = Vec::new();
    for (realm_id, body) in realms {
        if default_realm_ids.iter().any(|id| id == realm_id) {
            channels.push(default_discussion_channel(realm_id, Some(body)));
        }
        let Some(timeline_events) = body
            .get("timeline")
            .and_then(|timeline| timeline.get("events"))
            .and_then(Value::as_array)
        else {
            continue;
        };
        channels.extend(channels_from_events(realm_id, timeline_events));
    }
    channels
}

pub(super) fn channels_from_local_state(state: &ClientLocalState) -> Vec<ChannelEntity> {
    state
        .raw_operations
        .iter()
        .filter_map(|record| {
            channel_from_strand_event(
                record.realm_id.as_deref().unwrap_or_default(),
                &record.payload,
            )
        })
        .collect()
}

pub(super) fn merge_channels(target: &mut Vec<ChannelEntity>, incoming: Vec<ChannelEntity>) {
    for channel in incoming {
        if let Some(existing) = target
            .iter_mut()
            .find(|candidate| candidate.strand_id == channel.strand_id)
        {
            *existing = channel;
        } else {
            target.push(channel);
        }
    }
}

pub(super) fn merge_chat_messages(target: &mut Vec<ChatMessage>, incoming: Vec<ChatMessage>) {
    for message in incoming {
        if !target.iter().any(|existing| existing.id == message.id) {
            target.push(message);
        }
    }
}

pub(super) fn merge_poll_cards(
    target: &mut Vec<crate::messaging::polls::PollCard>,
    incoming: Vec<crate::messaging::polls::PollCard>,
) {
    for card in incoming {
        if let Some(existing) = target
            .iter_mut()
            .find(|candidate| candidate.poll_id == card.poll_id)
        {
            *existing = card;
        } else {
            target.push(card);
        }
    }
}

pub(super) async fn submit_chat_operation_with_plaintext_retry(
    api: &CokretApi,
    realm_id: &str,
    actor_id: &str,
    plaintext_visible_services: &[String],
    operation: &EventEnvelope,
) -> anyhow::Result<SubmitEventResult> {
    match api.submit_event_envelope(operation).await {
        Ok(response) => Ok(response),
        Err(error) if is_plaintext_visibility_policy_error(&error) => {
            let mut services = plaintext_visible_services.to_vec();
            if let Ok(description) = api.describe().await {
                let service_did = description.service_did.as_str().trim();
                if !service_did.is_empty()
                    && !services.iter().any(|existing| existing == service_did)
                {
                    services.push(service_did.to_owned());
                }
            }
            if services.is_empty() {
                return Err(error);
            }
            api.update_realm_metadata(
                realm_id,
                actor_id,
                json!({"plaintext_visible_services": services}),
            )
            .await
            .map_err(|update_error| {
                anyhow::anyhow!(
                    "plaintext policy update failed: {update_error}; original send failed: {error}"
                )
            })?;
            api.submit_event_envelope(operation).await
        }
        Err(error) => Err(error),
    }
}

/// Submit a chat operation and, if the first attempt fails with a
/// definitive `auth_expired` (the short-lived principal bearer died
/// between background refresh ticks), silently re-mint the bearer through
/// the shared refresher and retry once before surfacing the error.
///
/// The send paths used to bounce straight to `/login` on the first
/// `auth_expired` — the "it randomly asks me to sign in mid-conversation"
/// report. Routing through [`crate::session::refresh_current_bearer`]
/// keeps the user signed in across a routine token rollover; only a
/// genuinely dead session (refresh material exhausted) still returns an
/// `auth_expired` for the caller to route to login.
pub(super) async fn submit_chat_operation_with_auth_refresh(
    base_url: &str,
    actor_id: &str,
    realm_id: &str,
    access_token: String,
    wait_for_sync_token: Option<String>,
    plaintext_visible_services: &[String],
    operation: &EventEnvelope,
) -> anyhow::Result<SubmitEventResult> {
    let api = authed_api_with_sync(base_url, access_token, wait_for_sync_token.clone())?;
    let first = submit_chat_operation_with_plaintext_retry(
        &api,
        realm_id,
        actor_id,
        plaintext_visible_services,
        operation,
    )
    .await;
    match first {
        Ok(response) => Ok(response),
        Err(error) if is_auth_expired_error(&error) => {
            match crate::session::refresh_current_bearer().await {
                Some(fresh_token) => {
                    let retry_api =
                        authed_api_with_sync(base_url, fresh_token, wait_for_sync_token)?;
                    submit_chat_operation_with_plaintext_retry(
                        &retry_api,
                        realm_id,
                        actor_id,
                        plaintext_visible_services,
                        operation,
                    )
                    .await
                }
                // Refresh material is exhausted — the session is really
                // dead. Hand the original auth_expired back so the caller
                // routes to login.
                None => Err(error),
            }
        }
        Err(error) => Err(error),
    }
}
