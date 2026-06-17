use super::*;

pub(crate) fn chat_reply_quote_preview(
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

pub(crate) fn collect_plaintext_services(value: &Value, services: &mut Vec<String>) {
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

pub(crate) fn plaintext_services_for_policy(
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
    first_string_in_candidates(candidates, &["actor_id", "sender_actor_id"])
}

pub(crate) fn message_kind_is_create(value: &Value) -> bool {
    value_string_at(value, &["kind", "type", "op_type", "event_type"]) == Some("ck.message.create")
}

pub(crate) fn text_from_blocks(value: &Value) -> Option<&str> {
    value
        .get("blocks")
        .and_then(Value::as_array)
        .and_then(|blocks| blocks.first())
        .and_then(|block| block.get("text"))
        .and_then(Value::as_str)
}

pub(crate) fn text_body_from_value(value: &Value) -> Option<&str> {
    value_string_at(value, &["body", "text", "message", "plain_text"])
        .or_else(|| text_from_blocks(value))
        .or_else(|| {
            value
                .get("content")
                .filter(|content| content.is_object())
                .and_then(text_body_from_value)
        })
}

pub(crate) fn text_body_from_message(candidates: &[&Value]) -> Option<String> {
    candidates
        .iter()
        .find_map(|candidate| text_body_from_value(candidate))
        .map(ToOwned::to_owned)
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

pub(crate) fn seq_from_candidates(candidates: &[&Value]) -> Option<u64> {
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

pub(crate) fn chat_message_from_event(realm_id: &str, event: &Value) -> Option<ChatMessage> {
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
pub(crate) fn decrypt_chat_encrypted_content(
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

/// Find the proof-bearing envelope layer for a chat event and verify its
/// `proofs` against the sender's authoritative directory verify key.
///
/// Uses the shared receiver primitive (`device_directory`) — the SAME resolver
/// and detached-JWS verifier the call-signal path uses. Lookups are cache-only
/// (the chat render path is synchronous); a cache miss yields
/// [`ChatProofVerdict::Unresolved`] so the message is flagged, not silently
/// trusted.
pub(crate) fn verify_chat_envelope_proof(event: &Value) -> ChatProofVerdict {
    // Locate the envelope layer that actually carries `actor_id` + `proofs`.
    // Projected chat events nest the signed envelope under `event` / `envelope`
    // / `raw`; scan the same candidate layers used elsewhere.
    let candidates = message_candidates(event);
    let envelope = candidates.iter().copied().find(|candidate| {
        candidate.get("proofs").and_then(Value::as_array).is_some()
            && candidate.get("actor_id").and_then(Value::as_str).is_some()
    });
    let Some(envelope) = envelope else {
        return ChatProofVerdict::NotApplicable;
    };
    let actor = envelope
        .get("actor_id")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let device = envelope
        .get("device_id")
        .or_else(|| envelope.get("sender_device_id"))
        .and_then(Value::as_str)
        .unwrap_or_default();
    if actor.is_empty() || device.is_empty() {
        // A proof-bearing envelope with no resolvable (actor, device) cannot be
        // verified → fail-closed reject.
        return ChatProofVerdict::Rejected;
    }
    match crate::device_directory::cached_device_signing_key(actor, device) {
        crate::device_directory::CacheLookup::Hit(key) => {
            if crate::device_directory::verify_persistent_envelope_proofs(envelope, &key) {
                ChatProofVerdict::Verified
            } else {
                ChatProofVerdict::Rejected
            }
        }
        crate::device_directory::CacheLookup::NegativeHit => ChatProofVerdict::Rejected,
        crate::device_directory::CacheLookup::Miss => ChatProofVerdict::Unresolved,
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
/// `private_strand_field_text`.
pub(crate) fn chat_message_from_event_with_sidecar(
    realm_id: &str,
    event: &Value,
    state_store: Option<&LocalStateStore>,
    decrypt_identity: Option<(&str, &str)>,
) -> Option<ChatMessage> {
    // Receiver proof gate (device-lifecycle.md §8.2, fail-closed): a present
    // sender proof that fails verification (bad sig / revoked / absent device)
    // MUST NOT enter the conversation view.
    let proof_verdict = verify_chat_envelope_proof(event);
    if proof_verdict == ChatProofVerdict::Rejected {
        return None;
    }
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
    let crypto_state = if scope_mismatch || proof_verdict == ChatProofVerdict::Unresolved {
        // Either a Circle-scope mismatch, OR a present sender proof whose verify
        // key is not yet resolvable from the directory cache — flag for
        // verification rather than presenting the body as trusted.
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
        // CKP-0008 §4.10 — act-on-behalf carries a signed envelope-level
        // `executed_by`. When present and distinct from the actor, the
        // renderer shows the "controller via agent" double signature.
        executed_by: first_string_in_candidates(&candidates, &["executed_by"])
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned),
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

pub(crate) fn chat_messages_from_events_with_sidecar(
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

pub(crate) fn poll_content_from_candidates<'a>(candidates: &[&'a Value]) -> Option<&'a Value> {
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

pub(crate) fn poll_cards_from_events(events: &[Value]) -> Vec<crate::messaging::polls::PollCard> {
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

pub(crate) fn chat_messages_from_sync_realms_with_sidecar(
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

pub(crate) fn poll_cards_from_sync_realms(
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

pub(crate) fn normalize_sync_realm_id(realm_id: &str) -> String {
    realm_id.trim().to_owned()
}

pub(crate) fn sync_realm_ids_match(left: &str, right: &str) -> bool {
    normalize_sync_realm_id(left) == normalize_sync_realm_id(right)
}

pub(crate) fn typing_actors_from_sync_realms(
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

pub(crate) fn sync_presence_actor(event: &Value) -> Option<String> {
    value_string_at(event, &["user_id", "actor_id", "actor"])
        .map(str::trim)
        .filter(|actor| !actor.is_empty())
        .map(ToOwned::to_owned)
}

pub(crate) fn sync_presence_status(event: &Value) -> Option<String> {
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

pub(crate) fn presence_maps_from_sync_events(
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

pub(crate) fn chat_messages_from_local_state_with_sidecar(
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

pub(crate) fn poll_cards_from_local_state(
    state: &ClientLocalState,
) -> Vec<crate::messaging::polls::PollCard> {
    let events = state
        .raw_operations
        .iter()
        .map(|record| record.payload.clone())
        .collect::<Vec<_>>();
    poll_cards_from_events(&events)
}

pub(crate) fn bool_at_path(value: &Value, path: &[&str]) -> Option<bool> {
    let mut current = value;
    for key in path {
        current = current.get(*key)?;
    }
    current.as_bool()
}

pub(crate) fn string_at_path<'a>(value: &'a Value, path: &[&str]) -> Option<&'a str> {
    let mut current = value;
    for key in path {
        current = current.get(*key)?;
    }
    current.as_str()
}

pub(crate) fn first_string_in_candidate_paths<'a>(
    candidates: &[&'a Value],
    paths: &[&[&str]],
) -> Option<&'a str> {
    candidates.iter().find_map(|candidate| {
        paths
            .iter()
            .find_map(|path| string_at_path(candidate, path))
    })
}
