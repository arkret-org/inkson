use super::*;

pub(crate) fn default_discussion_strand_id(realm_id: &str) -> String {
    let trimmed = realm_id.trim();
    if trimmed.starts_with("ck:strand:") {
        trimmed.to_owned()
    } else if let Some(suffix) = trimmed.strip_prefix("ck:realm:") {
        format!("ck:strand:{suffix}")
    } else {
        format!("ck:strand:{}", trimmed.trim_start_matches("ck:"))
    }
}

pub(crate) fn candidate_has_track(candidate: &Value, track: &str) -> bool {
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

pub(crate) fn strand_create_has_discussion_track(candidates: &[&Value]) -> bool {
    candidates
        .iter()
        .any(|candidate| candidate_has_track(candidate, "discussion"))
}

pub(crate) fn strand_create_has_synthesis_track(candidates: &[&Value]) -> bool {
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

pub(crate) fn strand_security_state_from_candidates(candidates: &[&Value]) -> Option<bool> {
    candidates
        .iter()
        .find_map(|candidate| crate::security_state::strand_projection_security_state(candidate))
}

pub(crate) fn channel_from_strand_projection(
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
pub(crate) fn strand_scope_circle_from_projection(strand: &Value) -> Option<StrandScopeCircle> {
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

pub(crate) fn u32_at_path(value: &Value, path: &[&str]) -> Option<u32> {
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

pub(crate) fn default_discussion_channel(
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

pub(crate) fn discussion_channel_for_strand(realm_id: &str, strand_id: &str) -> ChannelEntity {
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

pub(crate) fn channel_from_strand_event(realm_id: &str, event: &Value) -> Option<ChannelEntity> {
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

pub(crate) fn channels_from_events(realm_id: &str, events: &[Value]) -> Vec<ChannelEntity> {
    events
        .iter()
        .filter_map(|event| channel_from_strand_event(realm_id, event))
        .collect()
}

pub(crate) fn channels_from_sync_realms(
    realms: &std::collections::BTreeMap<String, Value>,
    default_realm_ids: &[String],
) -> Vec<ChannelEntity> {
    let mut channels = Vec::new();
    for (realm_id, body) in realms {
        if default_realm_ids.iter().any(|id| id == realm_id) {
            channels.push(default_discussion_channel(realm_id, Some(body)));
        }
        let Some(wire_events) = body
            .get("timeline")
            .and_then(|projection| projection.get("events"))
            .and_then(Value::as_array)
        else {
            continue;
        };
        channels.extend(channels_from_events(realm_id, wire_events));
    }
    channels
}

pub(crate) fn channels_from_local_state(state: &ClientLocalState) -> Vec<ChannelEntity> {
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

pub(crate) fn merge_channels(target: &mut Vec<ChannelEntity>, incoming: Vec<ChannelEntity>) {
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

fn chat_message_protocol_id(message: &ChatMessage) -> Option<&str> {
    message
        .protocol_message_id
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

fn chat_message_has_protocol_id(message: &ChatMessage, protocol_id: &str) -> bool {
    chat_message_protocol_id(message).is_some_and(|candidate| candidate == protocol_id)
}

fn append_chat_message_revision_body(message: &mut ChatMessage, body: String) {
    if body.is_empty() || body == message.body {
        return;
    }
    if message.revisions.last().is_none_or(|last| last != &body)
        && !message.revisions.iter().any(|existing| existing == &body)
    {
        message.revisions.push(body);
    }
}

fn carry_chat_message_identity_metadata(target: &mut ChatMessage, source: &ChatMessage) {
    if target.protocol_message_id.is_none() {
        target.protocol_message_id = source.protocol_message_id.clone();
    }
    if target.reply_to.is_none() {
        target.reply_to = source.reply_to.clone();
    }
}

fn push_chat_message_reaction_member(
    reactions: &mut Vec<(String, Vec<String>)>,
    key: &str,
    actor: &str,
) {
    if key.trim().is_empty() || actor.trim().is_empty() {
        return;
    }
    if let Some((_, senders)) = reactions.iter_mut().find(|(existing, _)| existing == key) {
        if !senders.iter().any(|sender| sender == actor) {
            senders.push(actor.to_owned());
        }
    } else {
        reactions.push((key.to_owned(), vec![actor.to_owned()]));
    }
}

fn sort_chat_message_reactions(reactions: &mut Vec<(String, Vec<String>)>) {
    for (_, senders) in reactions.iter_mut() {
        senders.sort();
        senders.dedup();
    }
    reactions.retain(|(_, senders)| !senders.is_empty());
    reactions.sort_by(|left, right| left.0.cmp(&right.0));
}

fn merge_chat_message_reactions_into(target: &mut ChatMessage, source: &ChatMessage) {
    if target.redacted {
        return;
    }
    for (key, senders) in &source.reactions {
        for sender in senders {
            push_chat_message_reaction_member(&mut target.reactions, key, sender);
        }
    }
    sort_chat_message_reactions(&mut target.reactions);
}

fn replace_chat_message_preserving_local_metadata(
    existing: &mut ChatMessage,
    mut message: ChatMessage,
) {
    if existing.redacted && !message.redacted {
        carry_chat_message_identity_metadata(existing, &message);
        append_chat_message_revision_body(existing, message.body);
        return;
    }
    if message.redacted || message.is_newer_or_same_lifecycle_version_than(existing) {
        carry_chat_message_identity_metadata(&mut message, existing);
        // Carry forward locally-tracked edit metadata. The sync projection
        // rebuilds a message from its events but does not surface the
        // per-message revision count, so a re-projection would otherwise wipe
        // the write-status counter the moment a sync tick lands between two
        // edits. Preserve the existing `edited` flag and revision history (the
        // body still updates to the incoming/revised content) so the numeric
        // counter is stable across re-projections.
        if !message.edited && existing.edited {
            message.edited = true;
        }
        if message.revisions.is_empty() && !existing.revisions.is_empty() {
            message.revisions = std::mem::take(&mut existing.revisions);
        }
        append_chat_message_revision_body(&mut message, existing.body.clone());
        if message.created_at.is_none() {
            message.created_at = existing.created_at.clone();
        }
        merge_chat_message_reactions_into(&mut message, existing);
        *existing = message;
    } else {
        carry_chat_message_identity_metadata(existing, &message);
        if message.edited {
            existing.edited = true;
        }
        if existing.created_at.is_none() {
            existing.created_at = message.created_at;
        }
        merge_chat_message_reactions_into(existing, &message);
        for revision in message.revisions {
            append_chat_message_revision_body(existing, revision);
        }
        append_chat_message_revision_body(existing, message.body);
    }
}

fn prune_duplicate_chat_message_entries(
    target: &mut Vec<ChatMessage>,
    keep_id: &str,
    protocol_id: Option<&str>,
) {
    let mut kept_primary = false;
    target.retain(|message| {
        if message.id == keep_id {
            if kept_primary {
                return false;
            }
            kept_primary = true;
            return true;
        }
        !protocol_id.is_some_and(|protocol_id| chat_message_has_protocol_id(message, protocol_id))
    });
}

pub(crate) fn merge_chat_messages(target: &mut Vec<ChatMessage>, incoming: Vec<ChatMessage>) {
    for message in incoming {
        let protocol_id = chat_message_protocol_id(&message).map(ToOwned::to_owned);
        if let Some(existing_index) = target.iter().position(|existing| {
            existing.id == message.id
                || protocol_id
                    .as_deref()
                    .is_some_and(|protocol_id| chat_message_has_protocol_id(existing, protocol_id))
        }) {
            replace_chat_message_preserving_local_metadata(&mut target[existing_index], message);
            let keep_id = target[existing_index].id.clone();
            let protocol_id =
                chat_message_protocol_id(&target[existing_index]).map(ToOwned::to_owned);
            prune_duplicate_chat_message_entries(target, &keep_id, protocol_id.as_deref());
        } else {
            target.push(message);
        }
    }
}

fn pending_message_private_plaintext_sidecar_body(
    message: &ChatMessage,
    store: &LocalStateStore,
    default_realm_id: &str,
) -> Option<String> {
    if !message.crypto_state.is_pending() || message.redacted {
        return None;
    }
    let message_id = message
        .protocol_message_id
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .or_else(|| {
            let id = message.id.trim();
            (!id.is_empty()).then_some(id)
        })?;
    let strand_id = message.strand_id.trim();
    if strand_id.is_empty() {
        return None;
    }
    let default_realm_id = default_realm_id.trim();
    let message_realm_id = message.realm_id.trim();
    if !default_realm_id.is_empty()
        && !message_realm_id.is_empty()
        && message_realm_id != default_realm_id
    {
        return None;
    }
    let lookup_realm_id = if message_realm_id.is_empty() {
        default_realm_id
    } else {
        message_realm_id
    };
    if lookup_realm_id.is_empty() {
        return None;
    }
    store.private_plaintext_for(lookup_realm_id, strand_id, &format!("message:{message_id}"))
}

pub(crate) fn pending_messages_have_private_plaintext_sidecar(
    messages: &[ChatMessage],
    store: &LocalStateStore,
    default_realm_id: &str,
) -> bool {
    messages.iter().any(|message| {
        pending_message_private_plaintext_sidecar_body(message, store, default_realm_id).is_some()
    })
}

pub(crate) fn restore_pending_messages_from_private_plaintext_sidecar(
    messages: &mut [ChatMessage],
    store: &LocalStateStore,
    default_realm_id: &str,
) -> bool {
    let mut changed = false;
    for message in messages.iter_mut() {
        let Some(body) =
            pending_message_private_plaintext_sidecar_body(message, store, default_realm_id)
        else {
            continue;
        };
        if message.body != body || message.crypto_state != MessageCryptoState::Plaintext {
            message.body = body;
            message.crypto_state = MessageCryptoState::Plaintext;
            changed = true;
        }
    }
    changed
}

pub(crate) fn merge_moderation_appeal_prompts(
    target: &mut Vec<ModerationAppealPrompt>,
    incoming: Vec<ModerationAppealPrompt>,
) {
    for prompt in incoming {
        if let Some(existing) = target.iter_mut().find(|candidate| {
            candidate.realm_id == prompt.realm_id && candidate.decision_ref == prompt.decision_ref
        }) {
            *existing = prompt;
        } else {
            target.push(prompt);
        }
    }
}

pub(crate) fn merge_poll_cards(
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
