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

/// One Discussion channel from the Station's current result for a Strand.
///
/// The snapshot carries the whole Strand object under `CurrentSelector::Strand`
/// at an exact signed revision, so nothing here re-derives the value from
/// Event order.
pub(crate) fn channel_from_current_strand(
    realm_id: &str,
    strand: arkret_sdk::Strand,
) -> Option<ChannelEntity> {
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

pub(crate) fn channels_from_current_view(
    current: Option<&crate::current_projection::RealmCurrentView>,
    selected_realm_id: &str,
) -> Vec<ChannelEntity> {
    let Some(entries) = current.and_then(|view| view.entries_for(selected_realm_id)) else {
        return Vec::new();
    };
    entries
        .iter()
        .cloned()
        .filter_map(|entry| match entry {
            arkret_wire::TypedCurrentResult::Value {
                selector: arkret_wire::CurrentSelector::Strand { .. },
                value,
                ..
            } => serde_json::from_value::<arkret_sdk::Strand>(value).ok(),
            _ => None,
        })
        .filter_map(|strand| channel_from_current_strand(selected_realm_id, strand))
        .collect()
}

pub(crate) fn channels_from_current_view_with_store(
    current: Option<&crate::current_projection::RealmCurrentView>,
    realm: &str,
    store: &LocalStateStore,
) -> Vec<ChannelEntity> {
    let mut channels = channels_from_current_view(current, realm);
    let Some(identity) = crate::secure_key_store::active_device_seed_scope() else {
        return channels;
    };
    if store.active_authority().as_ref() != Some(&identity.authority) {
        return channels;
    }
    for channel in &mut channels {
        let envelope = current
            .and_then(|view| view.entries_for(realm))
            .into_iter()
            .flatten()
            .find_map(|entry| {
                let arkret_wire::TypedCurrentResult::Value {
                    selector, value, ..
                } = entry;
                match selector {
                    arkret_wire::CurrentSelector::Strand { strand_id }
                        if strand_id.as_str() == channel.strand_id =>
                    {
                        value.get("encrypted_metadata").and_then(|value| {
                            serde_json::from_value::<arkret_sdk::EncryptedEnvelope>(value.clone())
                                .ok()
                        })
                    }
                    _ => None,
                }
            });
        if envelope.is_some() {
            channel.name = crate::views::chat::direct_structure::metadata_title(
                store,
                realm,
                &channel.strand_id,
                envelope.as_ref(),
                &identity.authority,
                &identity.device_id,
            );
        }
    }
    channels
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

/// Navigation filters choose which rows to show, never the addressed Strand.
/// An embedded discussion can target a synthesis card hidden by that filter.
pub(crate) fn discussion_channels_for_surface(
    channels: &[ChannelEntity],
    selected_strand: &str,
    track_filter: &str,
) -> (Vec<ChannelEntity>, Option<ChannelEntity>) {
    let selected = channels
        .iter()
        .find(|channel| channel.strand_id == selected_strand)
        .cloned();
    let visible = channels
        .iter()
        .filter(|channel| {
            track_filter == "with_discussion_track"
                || channel.is_default
                || channel.kind == "discussion"
        })
        .cloned()
        .collect();
    (visible, selected)
}

fn chat_message_protocol_id(message: &ChatMessage) -> Option<&str> {
    message
        .protocol_message_id
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

type MessageSlots = std::collections::BTreeMap<String, std::collections::BTreeSet<usize>>;

#[derive(Default)]
struct MessageMergeIndex {
    ids: MessageSlots,
    protocols: MessageSlots,
}

#[cfg(test)]
thread_local! {
    static MERGE_INDEX_STEPS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

impl MessageMergeIndex {
    fn insert(&mut self, slot: usize, message: &ChatMessage) {
        #[cfg(test)]
        MERGE_INDEX_STEPS.with(|steps| steps.set(steps.get() + 1));
        self.ids.entry(message.id.clone()).or_default().insert(slot);
        if let Some(protocol) = chat_message_protocol_id(message) {
            self.protocols
                .entry(protocol.to_owned())
                .or_default()
                .insert(slot);
        }
    }

    fn remove(&mut self, slot: usize, message: &ChatMessage) {
        #[cfg(test)]
        MERGE_INDEX_STEPS.with(|steps| steps.set(steps.get() + 1));
        Self::remove_alias(&mut self.ids, &message.id, slot);
        if let Some(protocol) = chat_message_protocol_id(message) {
            Self::remove_alias(&mut self.protocols, protocol, slot);
        }
    }

    fn remove_alias(index: &mut MessageSlots, alias: &str, slot: usize) {
        if let Some(slots) = index.get_mut(alias) {
            slots.remove(&slot);
            if slots.is_empty() {
                index.remove(alias);
            }
        }
    }

    fn first_match(&self, message: &ChatMessage) -> Option<usize> {
        #[cfg(test)]
        MERGE_INDEX_STEPS.with(|steps| steps.set(steps.get() + 1));
        let by_id = self
            .ids
            .get(&message.id)
            .and_then(|slots| slots.first())
            .copied();
        let by_protocol = chat_message_protocol_id(message)
            .and_then(|protocol| self.protocols.get(protocol))
            .and_then(|slots| slots.first())
            .copied();
        match (by_id, by_protocol) {
            (Some(left), Some(right)) => Some(left.min(right)),
            (left, right) => left.or(right),
        }
    }

    fn duplicate_slots(&self, message: &ChatMessage) -> std::collections::BTreeSet<usize> {
        let same_id = self.ids.get(&message.id).expect("merged row is indexed");
        let primary = *same_id.first().expect("merged row has a primary slot");
        let same_protocol =
            chat_message_protocol_id(message).and_then(|protocol| self.protocols.get(protocol));
        same_id
            .iter()
            .chain(same_protocol.into_iter().flatten())
            .filter_map(|slot| {
                #[cfg(test)]
                MERGE_INDEX_STEPS.with(|steps| steps.set(steps.get() + 1));
                (*slot != primary).then_some(*slot)
            })
            .collect()
    }
}

pub(crate) fn merge_chat_messages(target: &mut Vec<ChatMessage>, incoming: Vec<ChatMessage>) {
    if incoming.is_empty() {
        return;
    }
    // Slots retain the original presentation order throughout this merge.
    // Index every alias, including untouched initial duplicates: a bridge
    // must still select the first row matching either alias, not a preferred ID.
    let mut slots = std::mem::take(target)
        .into_iter()
        .map(Some)
        .collect::<Vec<_>>();
    let mut index = MessageMergeIndex::default();
    for (slot, message) in slots.iter().enumerate() {
        index.insert(slot, message.as_ref().expect("initial slot is occupied"));
    }
    for message in incoming {
        if let Some(slot) = index.first_match(&message) {
            let existing = slots[slot].as_mut().expect("matched slot is occupied");
            index.remove(slot, existing);
            merge_duplicate_create_message(existing, message);
            index.insert(slot, existing);
            // Merging can rewrite both aliases. The earliest row with the new
            // keep ID survives even if it precedes the row we just updated.
            for duplicate in index.duplicate_slots(existing) {
                let removed = slots[duplicate].take().expect("duplicate slot is occupied");
                index.remove(duplicate, &removed);
            }
        } else {
            index.insert(slots.len(), &message);
            slots.push(Some(message));
        }
    }
    // Compact once, without sorting or rebuilding identities across streams.
    target.extend(slots.into_iter().filter_map(|message| {
        #[cfg(test)]
        MERGE_INDEX_STEPS.with(|steps| steps.set(steps.get() + 1));
        message
    }));
}

#[cfg(test)]
#[path = "strands_merge_tests.rs"]
mod merge_tests;

fn pending_message_private_plaintext_sidecar_body(
    message: &ChatMessage,
    store: &LocalStateStore,
    selected_realm_id: &str,
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
    let selected_realm_id = selected_realm_id.trim();
    let message_realm_id = message.realm_id.trim();
    if !selected_realm_id.is_empty()
        && !message_realm_id.is_empty()
        && message_realm_id != selected_realm_id
    {
        return None;
    }
    let lookup_realm_id = arkret_sdk::RealmId::new(message_realm_id.to_owned()).ok()?;
    store
        .private_plaintext_for(
            lookup_realm_id.as_str(),
            strand_id,
            &format!("message:{message_id}"),
        )
        .map(super::events::content_from_private_sidecar)
}

pub(crate) fn pending_messages_have_private_plaintext_sidecar(
    messages: &[ChatMessage],
    store: &LocalStateStore,
    selected_realm_id: &str,
) -> bool {
    messages.iter().any(|message| {
        pending_message_private_plaintext_sidecar_body(message, store, selected_realm_id).is_some()
    })
}

pub(crate) fn restore_pending_messages_from_private_plaintext_sidecar(
    messages: &mut [ChatMessage],
    store: &LocalStateStore,
    selected_realm_id: &str,
) -> bool {
    let mut changed = false;
    for message in messages.iter_mut() {
        let Some((body, content_format)) =
            pending_message_private_plaintext_sidecar_body(message, store, selected_realm_id)
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

pub(crate) fn poll_card_matches_render_ids(
    card: &crate::messaging::polls::PollCard,
    message_id: &str,
    protocol_message_id: Option<&str>,
) -> bool {
    card.message_id == message_id
        || card.poll_ref.as_ref().is_some_and(|poll_ref| {
            protocol_message_id.is_some_and(|message_ref| poll_ref.as_str() == message_ref)
        })
}
