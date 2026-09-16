use super::*;

pub(crate) fn default_discussion_strand_id(realm_body: &Value) -> Option<String> {
    let strand_id = realm_body.get("default_strand_id")?.as_str()?;
    arkret_sdk::StrandId::new(strand_id.to_owned())
        .ok()
        .map(|id| id.to_string())
}

pub(crate) fn discussion_channel_for_strand(strand_id: &str) -> Option<ChannelEntity> {
    let trimmed_strand_id = strand_id.trim();
    if trimmed_strand_id.is_empty() {
        return None;
    }
    let strand_id = arkret_sdk::StrandId::new(trimmed_strand_id.to_owned()).ok()?;

    Some(ChannelEntity {
        strand_id: strand_id.to_string(),
        name: "Discussion".to_owned(),
        kind: "discussion".to_owned(),
        category: "discussion".to_owned(),
        topic: None,
        unread: 0,
        is_default: false,
        is_private_sidecar: false,
        security_encrypted: None,
        scope_circle: None,
    })
}

pub(crate) fn channel_from_current_strand(
    realm_id: &str,
    entry: &arkret_sdk::CurrentResultEntry,
) -> Option<ChannelEntity> {
    entry
        .selector()
        .validate_for_realm(&arkret_sdk::RealmId::new(realm_id.to_owned()).ok()?)
        .ok()?;
    let strand = crate::current_projection::unique_strand_head(entry)?;
    if strand.realm_id.as_str() != realm_id || !strand.tracks.contains_key("discussion") {
        return None;
    }
    strand.validate_content_surfaces().ok()?;
    let strand_id = strand.id.as_ref()?.to_string();
    let metadata = strand.metadata.as_ref();
    let name = metadata
        .and_then(|metadata| metadata.title.as_ref())
        .filter(|title| !title.trim().is_empty())
        .cloned()
        .unwrap_or_else(|| strand_id.clone());
    let category = metadata
        .and_then(|metadata| metadata.fields.get("category"))
        .and_then(Value::as_str)
        .unwrap_or("general")
        .to_owned();
    let topic = metadata.and_then(|metadata| metadata.summary.clone());
    let security_encrypted =
        (strand.encrypted_metadata.is_some() || strand.encrypted_content.is_some()).then_some(true);
    let scope_circle = strand.scope_circle_id.map(|circle_id| StrandScopeCircle {
        circle_id: circle_id.to_string(),
        title: circle_id.to_string(),
        member_count: 0,
    });
    Some(ChannelEntity {
        strand_id,
        name,
        kind: if strand.tracks.contains_key("synthesis") {
            "strand"
        } else {
            "discussion"
        }
        .to_owned(),
        category,
        topic,
        unread: 0,
        is_default: false,
        is_private_sidecar: false,
        security_encrypted,
        scope_circle,
    })
}

pub(crate) fn channels_from_local_state(
    state: &ClientLocalState,
    selected_realm_id: &str,
) -> Vec<ChannelEntity> {
    state
        .realm_tree_projections
        .get(selected_realm_id)
        .and_then(|projection| projection.get("current"))
        .and_then(|value| serde_json::from_value::<arkret_sdk::CurrentEntries>(value.clone()).ok())
        .into_iter()
        .flat_map(|current| current.entries.into_iter())
        .filter_map(|entry| channel_from_current_strand(selected_realm_id, &entry))
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
            merge_duplicate_create_message(&mut target[existing_index], message);
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
) -> Option<(String, Option<arkret_sdk::TextFormat>)> {
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
    store
        .private_plaintext_for(lookup_realm_id, strand_id, &format!("message:{message_id}"))
        .map(super::events::content_from_private_sidecar)
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
        let Some((body, content_format)) =
            pending_message_private_plaintext_sidecar_body(message, store, default_realm_id)
        else {
            continue;
        };
        if message.body != body
            || message.content_format != content_format
            || message.crypto_state != MessageCryptoState::Plaintext
        {
            message.body = body;
            message.content_format = content_format;
            message.crypto_state = MessageCryptoState::Plaintext;
            changed = true;
        }
    }
    changed
}

pub(crate) fn replace_poll_projection(
    target: &mut Vec<crate::messaging::polls::PollCard>,
    incoming: Vec<crate::messaging::polls::PollCard>,
) {
    target.retain(|card| {
        card.poll_ref.is_none() || incoming.iter().any(|next| next.poll_ref == card.poll_ref)
    });
    for card in incoming {
        if let Some(existing) = target
            .iter_mut()
            .find(|candidate| candidate.poll_ref.is_some() && candidate.poll_ref == card.poll_ref)
        {
            // The optimistic message keeps its local render id when the
            // accepted create is merged by wire message id. Keep the poll
            // card attached to that same message while replacing its durable
            // tally/state projection.
            let render_message_id = existing.message_id.clone();
            *existing = card;
            existing.message_id = render_message_id;
        } else {
            target.push(card);
        }
    }
}
