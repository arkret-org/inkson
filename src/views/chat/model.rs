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
    pub(super) flow_id: String,
    pub(super) name: String,
    pub(super) kind: String,
    pub(super) category: String,
    pub(super) topic: Option<String>,
    pub(super) unread: usize,
    pub(super) is_default: bool,
    /// Explicit Flow security state from Flow metadata. `None` inherits
    /// the current Realm / Space security posture.
    pub(super) security_encrypted: Option<bool>,
    /// CKP-0007 P3B.2.3 / P3B.2.4 — Circle scope this Flow was
    /// created under, when the Flow projection carries a
    /// `scope_circle_id`. The composer banner and the per-message
    /// accent rail read from this field; `None` means the Flow
    /// inherits the parent Realm scope and no banner / rail is
    /// rendered.
    pub(super) scope_circle: Option<FlowScopeCircle>,
}

/// Minimal Circle-scope projection embedded on each [`ChannelEntity`].
/// Mirrors the subset of [`crate::circle::CircleSummary`] needed by
/// the chat composer banner and timeline accent rail.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct FlowScopeCircle {
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
    pub(super) flow_id: String,
    pub(super) reply_to: Option<String>,
    pub(super) reactions: Vec<(String, Vec<String>)>,
    pub(super) redacted: bool,
    pub(super) edited: bool,
    pub(super) revisions: Vec<String>,
    pub(super) pending: bool,
    pub(super) failed: bool,
    pub(super) error: Option<String>,
    pub(super) mentions: Vec<StructuredMention>,
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
}

/// Hydrate the local MLS group for a Space (or
/// restore a device-key-protected snapshot), encrypt `plaintext_bytes`
/// against it, persist the post-encrypt group state back under the same
/// device snapshot secret, and return:
///
/// * `Some(schedule_hash)` — the post-encrypt group's `epoch_authenticator`- derived `Hash`, fed
///   into the SDK MLS governance binding payload.
/// * `member_dids` — every principal DID in the group (single-element for solo bootstrap; the full
///   member set for a hydrated multi-device group). Replaces the prior single-`device_did`
///   audit-receipt fallback.
/// * encrypted content — the typed SDK `EncryptedPayload` serialised as `serde_json::Value` ready
///   to drop into the message's `encrypted_content`.
///
/// On any failure (missing Welcome/snapshot, restore fails, encrypt fails) the
/// helper returns `(None, vec![], None, None)` and the caller aborts the
/// Send Secure flow.
/// Encrypt a discussion message under the Space MLS group and return the
/// structured MLS payload + the canonical AAD it was bound to. The caller
/// wraps these into a spec-conforming `ck.schema.encrypted_envelope.v1` via
/// [`cokret_sdk::EncryptedEnvelopeV1::from_payload`] once it has the
/// `ck.mls.commit` event id for `key_ref.group_state_ref`.
///
/// Runs on wasm: the underlying `mls::runtime::encrypt_message_with_device_snapshot`
/// uses the same wasm-enabled OpenMLS path as kanban flow-content encryption.
pub(super) type LocalEncryptedMessage = (
    cokret_sdk::EncryptedPayload,
    cokret_sdk::EncryptedEnvelopeAadV1,
);

pub(super) type LocalMlsEncryptResult = (
    Option<cokret_sdk::Hash>,
    Vec<cokret_sdk::Did>,
    Option<LocalEncryptedMessage>,
    Option<cokret_sdk::MlsCommitEnvelope>,
    // X14 — post-commit snapshot, persisted by the caller ONLY after the
    // server accepts the `ck.mls.commit` (persist-on-accept).
    Option<crate::mls::persistence::MlsSnapshotEnvelope>,
);

pub(super) fn run_local_mls_encrypt(
    mut state_store: Signal<LocalStateStore>,
    space_id: &str,
    realm_id: &str,
    principal_id: &str,
    device_id: &str,
    plaintext_bytes: &[u8],
) -> LocalMlsEncryptResult {
    let empty = (None, Vec::new(), None, None, None);
    let secure_store = crate::secure_key_store::default_secure_key_store("yougen");
    let aad = cokret_sdk::EncryptedEnvelopeAadV1::hidden(realm_id, "ck.message.create");
    let Ok(aad_value) = serde_json::to_value(&aad) else {
        return empty;
    };
    let Ok((schedule_hash, member_dids, payload, commit_envelope, new_snapshot)) =
        crate::mls::runtime::encrypt_message_with_device_snapshot(
            &mut state_store.write(),
            secure_store.as_ref(),
            space_id,
            principal_id,
            device_id,
            "application/vnd.cokret.message+json",
            aad_value,
            plaintext_bytes,
        )
    else {
        return empty;
    };
    (
        Some(schedule_hash),
        member_dids,
        Some((payload, aad)),
        Some(commit_envelope),
        Some(new_snapshot),
    )
}

pub(super) fn chat_sha256_hash_from_ref(value: &str) -> Option<String> {
    if let Some(hex) = value.strip_prefix("sha256:")
        && hex.len() == 64
        && hex
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
    {
        return Some(value.to_owned());
    }
    for prefix in ["ck:anchor:", "ck:state:"] {
        if let Some(rest) = value.strip_prefix(prefix) {
            return chat_sha256_hash_from_ref(rest);
        }
    }
    None
}

pub(super) fn chat_mls_base_epoch_ref(anchor_view: &LocalAnchorView, space_id: &str) -> String {
    anchor_view
        .frontier
        .iter()
        .chain(anchor_view.leaves.iter())
        .chain(anchor_view.state_root.iter())
        .find_map(|value| {
            if value.starts_with("ck:event:") && cokret_sdk::EventId::new(value.clone()).is_ok() {
                Some(value.clone())
            } else {
                chat_sha256_hash_from_ref(value)
            }
        })
        .unwrap_or_else(|| {
            crate::canonical::canonical_sha256(&json!({
                "kind": "chat_mls_base_epoch",
                "space_id": space_id,
                "epoch": anchor_view.mls_epoch.unwrap_or(0),
            }))
            .unwrap_or_else(|_| {
                "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_owned()
            })
        })
}

pub(super) fn chat_mls_membership_frontier(
    anchor_view: &LocalAnchorView,
    fallback_event_id: &cokret_sdk::EventId,
) -> Vec<cokret_sdk::EventId> {
    let mut frontier = anchor_view
        .frontier
        .iter()
        .chain(anchor_view.leaves.iter())
        .filter_map(|value| cokret_sdk::EventId::new(value.clone()).ok())
        .collect::<Vec<_>>();
    if frontier.is_empty() {
        frontier.push(fallback_event_id.clone());
    }
    frontier.sort();
    frontier.dedup();
    frontier
}

pub(super) fn chat_mls_policy_root(
    anchor_view: &LocalAnchorView,
    space_id: &str,
    schedule_hash: &cokret_sdk::Hash,
) -> Result<cokret_sdk::Hash, String> {
    let hash = anchor_view
        .state_root
        .as_deref()
        .and_then(chat_sha256_hash_from_ref)
        .unwrap_or_else(|| {
            crate::canonical::canonical_sha256(&json!({
                "kind": "chat_mls_policy_root",
                "space_id": space_id,
                "frontier": anchor_view.frontier,
                "state_root": anchor_view.state_root,
                "schedule_hash": schedule_hash.as_str(),
            }))
            .unwrap_or_else(|_| {
                "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_owned()
            })
        });
    cokret_sdk::Hash::new(hash).map_err(|err| format!("invalid MLS policy root hash: {err:?}"))
}

pub(super) fn chat_message_revise_operation(
    space_id: &str,
    actor: &str,
    event_id: &str,
    body: &str,
) -> crate::operation::EventEnvelope {
    OperationBuilder::new(space_id, actor, "ck.message.revise")
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
    space_id: &str,
    actor: &str,
    event_id: &str,
    reason: &str,
) -> crate::operation::EventEnvelope {
    OperationBuilder::new(space_id, actor, "ck.message.redact")
        .target_ref(event_id)
        .body(json!({
            "reason": reason,
            "target_event_id": event_id,
        }))
        .build("yougen")
}

pub(super) fn chat_reaction_add_operation(
    space_id: &str,
    actor: &str,
    event_id: &str,
    key: &str,
) -> crate::operation::EventEnvelope {
    OperationBuilder::new(space_id, actor, "ck.reaction.add")
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
    space_id: &str,
    actor: &str,
    event_id: &str,
    routing_tag: &str,
    encrypted_payload: &cokret_sdk::EncryptedPayload,
) -> crate::operation::EventEnvelope {
    let encrypted_payload_json =
        serde_json::to_value(encrypted_payload).unwrap_or(serde_json::Value::Null);
    OperationBuilder::new(space_id, actor, "ck.reaction.add")
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
    space_id: &str,
    actor: &str,
    device_id: &str,
    event_id: &str,
    emoji: &str,
    channel_encrypted: bool,
) -> Option<crate::operation::EventEnvelope> {
    if !channel_encrypted {
        return Some(chat_reaction_add_operation(
            space_id, actor, event_id, emoji,
        ));
    }
    let realm_id = scope_id_as_realm_id(space_id);
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
            space_id,
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
pub(super) fn mention_label_from_structured(mention: &StructuredMention) -> Option<String> {
    if mention.kind == "audience_mention" {
        return mention
            .token
            .strip_prefix('@')
            .filter(|label| !label.is_empty())
            .map(ToOwned::to_owned);
    }
    if mention.kind != "actor" {
        return mention
            .token
            .strip_prefix('@')
            .and_then(mention_handle_label_from_value);
    }
    let display_name =
        (!mention.display_name_at_time.is_empty()).then_some(mention.display_name_at_time.as_str());
    let rendered = crate::views::helpers::render_actor_mention(
        &mention.target,
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
    mentions: &[StructuredMention],
    base_url: &str,
) -> Vec<MentionInlinePart> {
    let labels: std::collections::BTreeSet<String> = mentions
        .iter()
        .filter_map(mention_label_from_structured)
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
        });
    }
}

/// Scan the local store's raw_operations for `ck.agent.endpoint`
/// rows and return the set of agent DIDs that were registered in
/// `realm_id`. Used to mark `SpaceParticipant::is_agent` so member /
/// mention / sender rows can render an agent badge.
///
/// Reads the agent DID from `payload.body.agent_id` (per
/// `crate::operation::cx_ops::agent_endpoint`). Returns an empty Vec
/// when no agent endpoints are registered.
pub(super) fn agent_ids_from_raw_operations(
    raw_operations: &[crate::local_state::RawOperationRecord],
    realm_id: &str,
) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for record in raw_operations {
        let kind = record
            .payload
            .get("kind")
            .and_then(Value::as_str)
            .unwrap_or("");
        if kind != "ck.agent.endpoint" {
            continue;
        }
        if let Some(record_realm) = record.realm_id.as_deref()
            && record_realm != realm_id
        {
            continue;
        }
        let did = record
            .payload
            .get("body")
            .and_then(|b| b.get("agent_id"))
            .and_then(Value::as_str)
            .map(str::to_owned);
        if let Some(did) = did
            && !out.iter().any(|existing| existing == &did)
        {
            out.push(did);
        }
    }
    out
}

/// Mark every participant whose DID appears in `agent_ids` as
/// `is_agent = true`. No-op for unknown DIDs.
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
        .and_then(|participant| {
            participant
                .handle_label
                .clone()
                .or_else(|| crate::views::helpers::handle_display_from_did(&participant.did))
                .or_else(|| participant.display_name.clone())
        })
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

pub(super) fn sender_display_label(
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

pub(super) fn sdk_payload_value(result: cokret_sdk::Result<Value>, context: &str) -> Value {
    result.unwrap_or_else(|err| panic!("{context}: {err}"))
}

pub(super) fn flow_id_value(value: &str) -> cokret_sdk::FlowId {
    cokret_sdk::FlowId::new(value.to_owned())
        .unwrap_or_else(|err| panic!("invalid flow id {value:?}: {err:?}"))
}

pub(super) fn chat_message_create_operation(
    space_id: &str,
    actor: &str,
    flow_id: &str,
    _channel_kind: &str,
    message_id: &str,
    body: &str,
    mentions: &[StructuredMention],
    reply_to: Option<&str>,
) -> crate::operation::EventEnvelope {
    let audience_mention_values = audience_mentions_to_json(mentions);
    let mut content = cokret_sdk::ContentBlock::text(body);
    if !audience_mention_values.is_empty() {
        content = content.with_field("audience_mentions", Value::Array(audience_mention_values));
    }
    // T2.3: the legacy `branch` top-level field is forbidden on the wire
    // (artifacts/registry/forbidden-wire-fields.json, hard_reject). v1 uses
    // `track_name` — a display-only timeline segment identifier — instead.
    let mut payload = cokret_sdk::MessageCreatePayload::with_content(
        flow_id_value(flow_id),
        "discussion",
        sdk_payload_value(content.to_value(), "chat message content serialize"),
    )
    .with_message_id(message_id);
    if let Some(reply_to) = reply_to.filter(|value| !value.trim().is_empty()) {
        payload = payload.with_reply_to(reply_to);
    }
    OperationBuilder::new(space_id, actor, "ck.message.create")
        .target_ref(flow_id)
        .body(sdk_payload_value(
            payload.to_value(),
            "chat ck.message.create payload serialize",
        ))
        .build("yougen")
}

pub(super) fn chat_send_error_message(error: &anyhow::Error) -> String {
    if is_auth_expired_error(error) {
        "Session expired while sending. Refresh the session or sign in again, then retry."
            .to_owned()
    } else if is_plaintext_visibility_policy_error(error) {
        "Plaintext is not enabled for this Space on the current service. Send Secure or update Space plaintext visibility."
            .to_owned()
    } else if is_space_membership_denied_error(error) {
        "This account is not a member of this Space. Join the Space or switch to an account that is a member before sending."
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

pub(super) fn mentions_from_value(value: &Value) -> Vec<StructuredMention> {
    value
        .as_array()
        .map(|items| {
            items
                .iter()
                .filter_map(|item| {
                    // R3.2 §3.8: the authoritative reference is
                    // `subject_id` (principal DID). Accept the pre-R3.2
                    // `subject` and yougen-legacy `target` as fallbacks
                    // for not-yet-migrated payloads.
                    let kind = item.get("kind").and_then(Value::as_str).unwrap_or("ref");
                    let target = if kind == "audience_mention" {
                        item.get("audience")
                            .and_then(Value::as_str)
                            .or_else(|| item.get("target").and_then(Value::as_str))?
                    } else {
                        item.get("subject_id")
                            .and_then(Value::as_str)
                            .or_else(|| item.get("subject").and_then(Value::as_str))
                            .or_else(|| item.get("target").and_then(Value::as_str))?
                    };
                    Some(StructuredMention {
                        kind: kind.to_owned(),
                        target: target.to_owned(),
                        token: item
                            .get("token")
                            .and_then(Value::as_str)
                            .or_else(|| item.get("mention_text_original").and_then(Value::as_str))
                            .unwrap_or(target)
                            .to_owned(),
                        // R3.2 audit metadata: R3.2 field names only (no
                        // pre-R3.2 compat). These NEVER drive the current
                        // display value — the renderer runs §3.2.1 off
                        // `target` instead.
                        display_name_at_time: item
                            .get("display_name_at_time")
                            .and_then(Value::as_str)
                            .unwrap_or_default()
                            .to_owned(),
                        handle_at_time: item
                            .get("handle_at_time")
                            .and_then(Value::as_str)
                            .unwrap_or_default()
                            .to_owned(),
                        mention_text_original: item
                            .get("mention_text_original")
                            .and_then(Value::as_str)
                            .unwrap_or_default()
                            .to_owned(),
                        resolved_at: item
                            .get("resolved_at")
                            .and_then(Value::as_str)
                            .unwrap_or_default()
                            .to_owned(),
                    })
                })
                .collect()
        })
        .unwrap_or_default()
}

pub(super) fn mentions_from_candidates(candidates: &[&Value]) -> Vec<StructuredMention> {
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

pub(super) fn chat_message_from_event(space_id: &str, event: &Value) -> Option<ChatMessage> {
    chat_message_from_event_with_sidecar(space_id, event, None, None)
}

/// P0 decrypt-on-read: turn a remote member's canonical `encrypted_content`
/// envelope into a plaintext chat body.
///
/// Prefers the canonical `ck.schema.encrypted_envelope.v1` shape — parse the
/// envelope and unwrap it to the typed [`cokret_sdk::EncryptedPayload`] before
/// handing it to the shared MLS decrypt core — and falls back to a raw
/// `EncryptedPayload` for legacy messages written before the envelope wrap. The
/// decrypted bytes are the canonical Content Block JSON (see the secure send
/// path), so we parse them and extract the display text, falling back to raw
/// UTF-8 for any legacy raw-body ciphertext. Returns `None` on any soft failure
/// (no local MLS snapshot, wrong/absent device secret, payload that doesn't
/// decrypt) so the caller leaves the message in the `Decrypting`/`KeyMissing`
/// state instead of presenting an undecrypted body.
pub(super) fn decrypt_chat_encrypted_content(
    state_store: &LocalStateStore,
    space_id: &str,
    actor_did: &str,
    device_id: &str,
    encrypted_content: &Value,
) -> Option<String> {
    let payload_value = match serde_json::from_value::<cokret_sdk::EncryptedEnvelopeV1>(
        encrypted_content.clone(),
    ) {
        Ok(envelope) => serde_json::to_value(envelope.to_payload().ok()?).ok()?,
        Err(_) => encrypted_content.clone(),
    };
    let plaintext = crate::views::timeline::try_local_mls_decrypt_core(
        state_store,
        space_id,
        actor_did,
        device_id,
        &payload_value,
    )?;
    let as_utf8 = String::from_utf8(plaintext.clone()).ok();
    match serde_json::from_slice::<Value>(&plaintext) {
        Ok(content_value) => text_body_from_value(&content_value)
            .map(ToOwned::to_owned)
            .or(as_utf8),
        Err(_) => as_utf8,
    }
}

/// X9 — build a `ChatMessage` from a synced/projected event, preferring the
/// author's own local plaintext sidecar (`mls_private_plaintext`, keyed by
/// `message:{message_id}`) over the encrypted payload. OpenMLS forbids an
/// author from decrypting their OWN application messages, so for the author's
/// encrypted messages the ciphertext is undecryptable and the timeline carries
/// no plaintext body. Without the sidecar, keep the message as a visible
/// crypto-pending row instead of dropping it, so a fresh browser shows "locked"
/// rather than "No messages". The sidecar lookup mirrors kanban's
/// `private_flow_field_text`.
pub(super) fn chat_message_from_event_with_sidecar(
    space_id: &str,
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
    let message_space = first_string_in_candidates(&candidates, &["space_id"]).unwrap_or(space_id);
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
    // flow. Falls back to the decoded payload body (another member's message
    // we CAN decrypt, or a plaintext message).
    let sidecar_body = state_store.and_then(|store| {
        let message_id = first_string_in_candidates(&candidates, &["message_id"])?;
        let flow_id = first_string_in_candidates(&candidates, &["flow_id", "thread_id"])?;
        store.private_plaintext_for(message_space, flow_id, &format!("message:{message_id}"))
    });
    let body_from_sidecar = sidecar_body.is_some();
    // P0 decrypt-on-read: a remote member's message carries ciphertext but no
    // author sidecar. Parse the canonical envelope, decrypt with this device's
    // MLS snapshot secret, and extract the Content Block text. Soft-fails to
    // `None` (→ Decrypting/KeyMissing) when the snapshot/secret is unavailable.
    let decrypted_body = if !body_from_sidecar
        && let (Some((actor_did, device_id)), Some(store), Some(encrypted)) = (
            decrypt_identity,
            state_store,
            encrypted_content_value.as_ref(),
        ) {
        decrypt_chat_encrypted_content(store, message_space, actor_did, device_id, encrypted)
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
        .filter(|value| value.starts_with("ck:flow:"))
        .unwrap_or("ck:flow:general")
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
        realm_id: first_string_in_candidates(&candidates, &["space_id"])
            .unwrap_or(space_id)
            .to_owned(),
        id: event_id,
        sender: first_string_in_candidates(
            &candidates,
            // canonical envelope 主体是 `actor_id`(spec forbidden-wire-fields.json:
            // sender → sender_actor_id)。优先读 actor_id / sender_actor_id;
            // `sender` / `sender_id` / `actor` 已废弃,仅作向后兼容容忍服务端旧值。
            &[
                "actor_id",
                "sender_actor_id",
                "sender",
                "sender_id",
                "actor",
            ],
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
        crypto_state,
    })
}

pub(super) fn chat_messages_from_events_with_sidecar(
    space_id: &str,
    events: &[Value],
    state_store: Option<&LocalStateStore>,
    decrypt_identity: Option<(&str, &str)>,
) -> Vec<ChatMessage> {
    events
        .iter()
        .filter_map(|event| {
            chat_message_from_event_with_sidecar(space_id, event, state_store, decrypt_identity)
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
            let actor = first_string_in_candidates(
                &candidates,
                // actor_id 优先(canonical),sender* / actor 仅作向后兼容(已废弃)。
                &[
                    "actor_id",
                    "sender_actor_id",
                    "sender",
                    "sender_id",
                    "actor",
                ],
            )
            .unwrap_or("did:web:unknown");
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

pub(super) fn profile_presence_status(profile: &Value) -> String {
    profile
        .get("presence")
        .and_then(|presence| presence.get("status"))
        .and_then(Value::as_str)
        .filter(|status| !status.trim().is_empty())
        .unwrap_or("offline")
        .to_owned()
}

// Perf (P0): the chat presence/typing poll used to do a *full*
// `account_subscribe_snapshot(None)` every 400ms (~2.5 full syncs/sec) which
// duplicates the global `SyncEngine` and floods the network panel. Typing
// indicators only need ~2s freshness (the sender throttles `typing=true` to one
// emit / 3s), so a 2s cadence keeps the indicator responsive at 1/5th the load.
pub(super) const CHAT_SYNC_POLL_INTERVAL_MS: u64 = 2_000;
// At the 2s cadence above, `profile_presence` fallback every 4 ticks (~8s) and a
// 2-tick warmup (~4s) keep presence fresh without a per-member request storm.
pub(super) const CHAT_PROFILE_PRESENCE_FALLBACK_EVERY_TICKS: usize = 4;
pub(super) const CHAT_PROFILE_PRESENCE_FALLBACK_WARMUP_TICKS: usize = 2;

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

pub(super) fn profile_display_label(profile: &Value, did: &str) -> String {
    profile
        .get("display_name")
        .and_then(Value::as_str)
        .and_then(|label| clean_participant_display_name(label, Some(did)))
        .unwrap_or_else(|| did.to_owned())
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

pub(super) fn default_discussion_flow_id(realm_id: &str) -> String {
    let trimmed = realm_id.trim();
    if trimmed.starts_with("ck:flow:") {
        trimmed.to_owned()
    } else if let Some(suffix) = trimmed.strip_prefix("ck:realm:") {
        format!("ck:flow:{suffix}")
    } else {
        format!("ck:flow:{}", trimmed.trim_start_matches("ck:"))
    }
}

pub(super) fn candidate_has_track(candidate: &Value, track: &str) -> bool {
    candidate
        .get("tracks")
        .and_then(|tracks| tracks.get(track))
        .is_some()
        || ["object", "flow"].iter().any(|wrapper| {
            candidate
                .get(*wrapper)
                .and_then(|inner| inner.get("tracks"))
                .and_then(|tracks| tracks.get(track))
                .is_some()
        })
}

pub(super) fn flow_create_has_discussion_track(candidates: &[&Value]) -> bool {
    candidates
        .iter()
        .any(|candidate| candidate_has_track(candidate, "discussion"))
}

pub(super) fn flow_create_has_synthesis_track(candidates: &[&Value]) -> bool {
    candidates
        .iter()
        .any(|candidate| candidate_has_track(candidate, "synthesis"))
        || candidates.iter().any(|candidate| {
            bool_at_path(candidate, &["create_card"]).unwrap_or(false)
                || bool_at_path(candidate, &["fields", "has_synthesis"]).unwrap_or(false)
                || bool_at_path(candidate, &["object", "fields", "has_synthesis"]).unwrap_or(false)
                || bool_at_path(candidate, &["flow", "fields", "has_synthesis"]).unwrap_or(false)
        })
}

pub(super) fn flow_security_state_from_candidates(candidates: &[&Value]) -> Option<bool> {
    candidates
        .iter()
        .find_map(|candidate| crate::security_state::flow_projection_security_state(candidate))
}

pub(super) fn channel_from_flow_projection(
    realm_id: &str,
    flow: &Value,
    is_default: bool,
) -> Option<ChannelEntity> {
    if !candidate_has_track(flow, "discussion") {
        return None;
    }

    let flow_id = first_string_in_candidate_paths(&[flow], &[&["flow_id"], &["id"]])
        .map(str::trim)
        .filter(|id| id.starts_with("ck:flow:"))
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| default_discussion_flow_id(realm_id));
    let name = first_string_in_candidate_paths(&[flow], &[&["title"], &["name"]])
        .filter(|title| !title.trim().is_empty())
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| {
            if is_default {
                "Discussion".to_owned()
            } else {
                flow_id.clone()
            }
        });
    let category = first_string_in_candidate_paths(
        &[flow],
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
            "default flow".to_owned()
        } else {
            "general".to_owned()
        }
    });
    let topic = first_string_in_candidate_paths(
        &[flow],
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
            Some("Default Flow discussion track".to_owned())
        } else {
            None
        }
    });
    let has_synthesis = flow_create_has_synthesis_track(&[flow]);
    let security_encrypted = crate::security_state::flow_projection_security_state(flow);
    let scope_circle = flow_scope_circle_from_projection(flow);

    Some(ChannelEntity {
        flow_id,
        name,
        kind: if !is_default && has_synthesis {
            "flow".to_owned()
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

/// Extract the optional Circle-scope projection from a Flow
/// projection JSON. Looks under both the top-level
/// `scope_circle_id` and the canonical `scope.circle_id` shape so
/// the helper tolerates both projection layouts.
pub(super) fn flow_scope_circle_from_projection(flow: &Value) -> Option<FlowScopeCircle> {
    let circle_id = first_string_in_candidate_paths(
        &[flow],
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
        &[flow],
        &[
            &["scope_circle_title"],
            &["scope", "circle_title"],
            &["scope", "title"],
        ],
    )
    .filter(|value| !value.trim().is_empty())
    .map(ToOwned::to_owned)
    .unwrap_or_else(|| circle_id.clone());

    let member_count = u32_at_path(flow, &["scope_circle_member_count"])
        .or_else(|| u32_at_path(flow, &["scope", "member_count"]))
        .unwrap_or(0);

    Some(FlowScopeCircle {
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
    if let Some(flow) = realm_body
        .and_then(|body| body.get("summary"))
        .and_then(|summary| summary.get("flow"))
        && let Some(channel) = channel_from_flow_projection(realm_id, flow, true)
    {
        return channel;
    }

    ChannelEntity {
        flow_id: default_discussion_flow_id(realm_id),
        name: "Discussion".to_owned(),
        kind: "discussion".to_owned(),
        category: "default flow".to_owned(),
        topic: Some("Default Flow discussion track".to_owned()),
        unread: 0,
        is_default: true,
        security_encrypted: realm_body.map(crate::security_state::realm_projection_is_encrypted),
        scope_circle: None,
    }
}

pub(super) fn discussion_channel_for_flow(realm_id: &str, flow_id: &str) -> ChannelEntity {
    let trimmed_flow_id = flow_id.trim();
    if trimmed_flow_id.is_empty() {
        return default_discussion_channel(realm_id, None);
    }

    ChannelEntity {
        flow_id: trimmed_flow_id.to_owned(),
        name: "Discussion".to_owned(),
        kind: "discussion".to_owned(),
        category: "discussion".to_owned(),
        topic: None,
        unread: 0,
        is_default: trimmed_flow_id == default_discussion_flow_id(realm_id),
        security_encrypted: None,
        scope_circle: None,
    }
}

pub(super) fn channel_from_flow_event(realm_id: &str, event: &Value) -> Option<ChannelEntity> {
    let candidates = message_candidates(event);
    if !candidates
        .iter()
        .any(|candidate| value_string_at(candidate, &["kind", "type"]) == Some("ck.flow.create"))
    {
        return None;
    }
    if !flow_create_has_discussion_track(&candidates)
        && !candidates.iter().any(|candidate| {
            // T2.3: the v1 wire uses `track_name`; legacy `branch` is a
            // hard_reject field per forbidden-wire-fields.json, so writers
            // MUST NOT emit it. Readers fall back to `category` only for
            // payloads that pre-date the track concept entirely.
            value_string_at(candidate, &["track_name"]) == Some("discussion")
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
            &["object", "id"],
            &["object", "flow_id"],
            &["flow", "id"],
            &["flow", "flow_id"],
        ],
    )?
    .trim();
    if !flow_id.starts_with("ck:flow:") {
        return None;
    }

    let name = first_string_in_candidate_paths(
        &candidates,
        &[
            &["title"],
            &["name"],
            &["object", "title"],
            &["object", "name"],
            &["flow", "title"],
            &["flow", "name"],
        ],
    )
    .unwrap_or(flow_id)
    .to_owned();
    let category = first_string_in_candidate_paths(
        &candidates,
        &[
            &["category"],
            &["fields", "category"],
            &["object", "fields", "category"],
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
            &["object", "summary"],
            &["object", "topic"],
            &["object", "description"],
            &["flow", "summary"],
            &["flow", "topic"],
            &["flow", "description"],
        ],
    )
    .map(ToOwned::to_owned);
    let has_synthesis = flow_create_has_synthesis_track(&candidates);
    let security_encrypted = flow_security_state_from_candidates(&candidates);
    let scope_circle = candidates
        .iter()
        .find_map(|candidate| flow_scope_circle_from_projection(candidate));

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
        is_default: flow_id == default_discussion_flow_id(realm_id),
        security_encrypted,
        scope_circle,
    })
}

pub(super) fn channels_from_events(realm_id: &str, events: &[Value]) -> Vec<ChannelEntity> {
    events
        .iter()
        .filter_map(|event| channel_from_flow_event(realm_id, event))
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
            channel_from_flow_event(
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
            .find(|candidate| candidate.flow_id == channel.flow_id)
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
    space_id: &str,
    actor_did: &str,
    plaintext_visible_services: &[String],
    operation: &EventEnvelope,
) -> anyhow::Result<SubmitEventResponse> {
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
                space_id,
                actor_did,
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
    actor_did: &str,
    space_id: &str,
    access_token: String,
    wait_for_sync_token: Option<String>,
    plaintext_visible_services: &[String],
    operation: &EventEnvelope,
) -> anyhow::Result<SubmitEventResponse> {
    let api = authed_api_with_sync(base_url, access_token, wait_for_sync_token.clone())?;
    let first = submit_chat_operation_with_plaintext_retry(
        &api,
        space_id,
        actor_did,
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
                        space_id,
                        actor_did,
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
