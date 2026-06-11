use cokret_sdk::push_rule_core::WatchLevel;
use dioxus::html::HasFileData;
use dioxus::prelude::*;
use dioxus_primitives::checkbox::CheckboxState;
use dioxus_router::hooks::use_navigator;
use serde_json::{Value, json};

use crate::api::{
    CokretApi, is_auth_expired_error, is_plaintext_visibility_policy_error,
    is_space_membership_denied_error,
};
use crate::audit::build_audit_ryw_receipt;
use crate::components::{HelpTip, SecurityStateBadge, UiIcon};
use crate::hlc::{Hlc, observe_seq};
use crate::local_state::{ClientLocalState, LocalAnchorView, LocalStateStore, MoveSubmissionState};
use crate::models::SubmitEventOutcome;
use crate::operation::{EventEnvelope, OperationBuilder, ck_ops, trim_realm_id, uuid_v7};
use crate::routes::Route;
use crate::ui::button::{Button, ButtonVariant};
use crate::ui::checkbox::Checkbox;
use crate::ui::dialog::Dialog;
use crate::ui::input::Input;
use crate::ui::label::Label;
use crate::ui::textarea::Textarea;
use crate::views::helpers::{
    StructuredMention, active_sync_token, authed_api_with_sync, parse_structured_mentions,
    short_protocol_id, with_authed_api_with_sync,
};

mod model;

use model::*;

fn render_message_text_block(
    key: String,
    text: String,
    mentions: Vec<StructuredMention>,
    base_url: String,
) -> Element {
    let parts = mention_inline_parts(&text, &mentions, &base_url);
    rsx! {
        p {
            key: "{key}",
            class: "content-block-text",
            "data-testid": "content-block-text",
            for (idx, part) in parts.into_iter().enumerate() {
                {
                    let part_key = format!("{key}-part-{idx}");
                    if let Some(label) = part.mention_label {
                        let class = if part.is_local {
                            "mention-token is-local"
                        } else {
                            "mention-token is-remote"
                        };
                        rsx! {
                            span {
                                key: "{part_key}",
                                class: "{class}",
                                "data-testid": "timeline-event-mention",
                                title: "{label}",
                                "{part.text}"
                            }
                        }
                    } else {
                        rsx! {
                            span { key: "{part_key}", "{part.text}" }
                        }
                    }
                }
            }
        }
    }
}

fn render_message_body(body: &str, mentions: &[StructuredMention], base_url: &str) -> Element {
    let blocks = crate::content::parse_message_body(body);
    if mentions.is_empty() {
        return crate::content::render_blocks(&blocks);
    }

    let owned_mentions = mentions.to_vec();
    let base_url = base_url.to_owned();
    rsx! {
        div { class: "content-blocks", "data-testid": "content-blocks",
            for (idx, block) in blocks.into_iter().enumerate() {
                {
                    let key = format!("content-block-{idx}");
                    match block {
                        crate::content::ContentBlock::Text(text) => {
                            render_message_text_block(
                                key,
                                text,
                                owned_mentions.clone(),
                                base_url.clone(),
                            )
                        }
                        other => {
                            let single = vec![other];
                            rsx! {
                                div { key: "{key}",
                                    {crate::content::render_blocks(&single)}
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
#[component]
pub fn ChatPanel(
    base_url: String,
    plaintext_service_did: String,
    account_did: String,
    device_id: String,
    token: Signal<String>,
    selected_realm_id: String,
    sync_cursor: Signal<String>,
    frontier_state: Signal<String>,
    state_store: Signal<LocalStateStore>,
    initial_flow_id: String,
    embedded: bool,
    direct_mode: bool,
) -> Element {
    let navigator = use_navigator();
    let initial_default_channel = (!selected_realm_id.trim().is_empty())
        .then(|| discussion_channel_for_flow(&selected_realm_id, &initial_flow_id));
    let initial_selected_channel = initial_default_channel
        .as_ref()
        .map(|channel| channel.flow_id.clone())
        .unwrap_or_default();
    let mut channels = use_signal(move || {
        initial_default_channel
            .clone()
            .into_iter()
            .collect::<Vec<_>>()
    });
    let mut selected_channel = use_signal(move || initial_selected_channel.clone());
    {
        let selected_realm_for_initial_flow = selected_realm_id.clone();
        let initial_flow_id_for_effect = initial_flow_id.clone();
        use_effect(move || {
            if selected_realm_for_initial_flow.trim().is_empty() {
                return;
            }
            let desired_channel = discussion_channel_for_flow(
                &selected_realm_for_initial_flow,
                &initial_flow_id_for_effect,
            );
            if selected_channel() != desired_channel.flow_id {
                selected_channel.set(desired_channel.flow_id.clone());
            }
            let has_channel = channels
                .read()
                .iter()
                .any(|channel| channel.flow_id == desired_channel.flow_id);
            if !has_channel {
                channels.write().push(desired_channel);
            }
        });
    }
    let mut messages = use_signal(Vec::<ChatMessage>::new);
    let mut chat_draft = use_signal(String::new);
    // Perf (P0): replace the per-keystroke `ck.typing` POST with a leading-edge
    // throttle (≤ once / 3s) plus a trailing `typing=false` once the user stops.
    let typing_throttle = crate::perf::use_typing_throttle(3_000, 4_000);
    // A6.2 composer drag-drop attachment state. `compose_dragover` toggles
    // the `is-dragover` outline as the user holds a file over the
    // textarea; `compose_upload_status` shows an inline progress / error
    // string for the most recent drop or hidden-input upload.
    let mut compose_dragover = use_signal(|| false);
    let mut compose_upload_status = use_signal(String::new);
    // A6.3 message pinning. Local-only scaffolding: the spec does not
    // yet define a `ck.message.pin` event_kind, so we keep pin state in
    // a per-realm Signal and surface it at the top of the discussion.
    // When soland exposes the pin endpoint (see TODO below) we'll
    // replace this with a real API call + projection sync.
    //
    // TODO(soland): replace `pinned_messages` with the canonical
    // `ck.message.pin` event family per spec
    // `flow-and-message.md §8.6` once soland ships it.
    let mut pinned_messages = use_signal(Vec::<String>::new);
    // Currently-open context menu (right-click on a message). Stores
    // the message id whose menu is open; None means no menu visible.
    let mut message_context_menu = use_signal(|| Option::<String>::None);
    let mut new_channel_name = use_signal(String::new);
    let mut new_channel_topic = use_signal(String::new);
    let mut new_channel_create_card = use_signal(|| false);
    let mut create_dialog_open = use_signal(|| false);
    // T7.2: per-Flow watch level signal for the topbar fast switcher.
    // Optimistically updates on user click; a failed submit rolls back to
    // the prior value.
    let mut flow_watch_level = use_signal(|| WatchLevel::All);
    let mut watch_level_menu_open = use_signal(|| false);
    let mut status_msg = use_signal(String::new);
    let mut reply_to_message = use_signal(|| Option::<String>::None);
    let mut editing_message = use_signal(|| Option::<String>::None);
    let mut edit_draft = use_signal(String::new);
    let mut redact_confirm = use_signal(|| Option::<String>::None);
    let mut reaction_picker = use_signal(|| Option::<String>::None);
    let mut initial_sync_requested = use_signal(|| false);
    let mut initial_sync_finished = use_signal(|| false);
    // G3.Y2 — mention picker. `mention_picker_state` tracks open/closed
    // + the current `@`-query + the list of inserted chips so the
    // composer can render `mention-picker` / `mention-suggestion` /
    // `mention-chip` testids off a single signal.
    let mut mention_picker_state = use_signal(crate::messaging::mentions::MentionPickerState::new);
    // G3.Y2 — poll composer. `poll_draft` is `Some(_)` while the
    // attachment menu's poll form is open; on send it becomes
    // `PollCard` in `poll_cards`. The attachment menu open/closed
    // state is held in `attachment_menu_open`.
    let mut attachment_menu_open = use_signal(|| false);
    let mut poll_draft = use_signal(|| Option::<crate::messaging::polls::PollDraft>::None);
    let mut poll_cards = use_signal(Vec::<crate::messaging::polls::PollCard>::new);
    // G3.Y2 — typing indicator. `typing_actors` lists the DIDs of
    // other actors who have sent a `ck.typing` ephemeral within the
    // TTL window returned by the live sync projection.
    let typing_actors = use_signal(Vec::<String>::new);
    // G3.Y2 — presence. Maps `actor_id -> "online"|"away"|"offline"`.
    // Refreshed from the global SyncEngine's account-subscribe projection
    // when `sync_cursor` advances.
    let presence_states = use_signal(std::collections::BTreeMap::<String, String>::new);
    let presence_labels = use_signal(std::collections::BTreeMap::<String, String>::new);
    let mut presence_sync_key_seen = use_signal(String::new);
    // G3.Y2 — discussion promote modal. Holds the source message id
    // (or Flow id) + the desired private discussion title.
    let mut promote_discussion_draft =
        use_signal(crate::messaging::discussion_promote::PromoteDiscussionDraft::default);
    // Map of `source_message_id -> private_discussion_flow_id` for the
    // `discussion-promoted-indicator` row. Populated optimistically
    // on submit and updated from the server response.
    let mut promoted_targets = use_signal(std::collections::BTreeMap::<String, String>::new);
    // G3.Y2 — `ck.read_cursor.advance` book-keeping. `latest_read_cursor`
    // stores the highest event_id we've posted a read marker for so
    // we don't spam soland on every render tick.
    let mut latest_read_cursor = use_signal(String::new);
    // A5 — personal blocklist. `blocked_did_set` snapshots the local
    // store at render time; `blocked_show_anyway` tracks per-message
    // reveal opt-ins so the user can peek at an otherwise-hidden body
    // without clearing the block.
    let mut blocked_show_anyway = use_signal(std::collections::BTreeSet::<String>::new);
    let blocked_did_set: std::collections::BTreeSet<String> = state_store
        .read()
        .client_blocklist()
        .into_iter()
        .map(|entry| entry.did)
        .collect();
    let account_display_name = use_signal(String::new);
    let mut track_filter = use_signal(|| "discussion_only".to_owned());
    let mut left_panel_open = use_signal(|| true);
    let mut right_panel =
        use_signal(|| Option::<DiscussionSidePanel>::Some(DiscussionSidePanel::Users));
    let selected_channel_value = selected_channel();
    let all_channels = channels();
    let filter_value = track_filter();
    let visible_channels: Vec<ChannelEntity> = all_channels
        .iter()
        .filter(|channel| {
            filter_value == "with_discussion_track"
                || channel.is_default
                || channel.kind == "discussion"
        })
        .cloned()
        .collect();
    let visible_channels_empty = visible_channels.is_empty();
    let selected_channel_info = visible_channels
        .iter()
        .find(|channel| channel.flow_id == selected_channel_value)
        .cloned()
        .or_else(|| visible_channels.first().cloned());
    let selected_channel_name = if embedded {
        "Discussion".to_owned()
    } else {
        selected_channel_info
            .as_ref()
            .map(|channel| channel.name.clone())
            .unwrap_or_else(|| crate::i18n::tr("chat.empty.title"))
    };
    let selected_channel_category = selected_channel_info
        .as_ref()
        .map(|channel| channel.category.clone())
        .unwrap_or_else(|| "discussion".to_owned());
    let selected_channel_unread = selected_channel_info
        .as_ref()
        .map(|channel| channel.unread)
        .unwrap_or(0);
    let selected_realm_security_encrypted = {
        let state = state_store.read().load();
        crate::security_state::security_projection_for_scope_id(
            &state.realm_tree_projections,
            &selected_realm_id,
        )
        .map(crate::security_state::realm_projection_is_encrypted)
        .unwrap_or(false)
    };
    let selected_channel_security_encrypted = selected_channel_info
        .as_ref()
        .and_then(|channel| channel.security_encrypted)
        .unwrap_or(selected_realm_security_encrypted);
    // In an encrypted channel the default Send must MLS-encrypt, never ship
    // plaintext. We hide the plaintext send button and promote the MLS send
    // button to the primary action carrying the `send-chat-button` testid;
    // in plaintext channels it stays the secondary `send-e2ee-move-button`.
    let send_secure_variant = if selected_channel_security_encrypted {
        ButtonVariant::Primary
    } else {
        ButtonVariant::Secondary
    };
    let send_secure_testid = if selected_channel_security_encrypted {
        "send-chat-button"
    } else {
        "send-e2ee-move-button"
    };
    let send_secure_label = if selected_channel_security_encrypted {
        crate::i18n::tr("chat.send")
    } else {
        crate::i18n::tr("chat.send_secure")
    };
    let all_messages_snapshot = messages();
    let visible_messages = all_messages_snapshot
        .iter()
        .filter(|msg| {
            msg.flow_id == selected_channel_value
                && (selected_realm_id.trim().is_empty() || msg.realm_id == selected_realm_id)
        })
        .cloned()
        .collect::<Vec<_>>();
    // CKP-0007 P3B.2.4 — per-flow Circle-scope lookup used by the
    // timeline accent rail. We index by `flow_id` once instead of
    // searching the `channels` Vec for every rendered message.
    let flow_scope_lookup: std::collections::BTreeMap<String, FlowScopeCircle> = all_channels
        .iter()
        .filter_map(|channel| {
            channel
                .scope_circle
                .clone()
                .map(|circle| (channel.flow_id.clone(), circle))
        })
        .collect();
    let visible_message_count = visible_messages.len();
    // G3.Y2 — derive the highest visible event id so we can post a
    // `ck.read_cursor.advance` covering everything we've rendered. The marker
    // itself is actor-private (`discovery/read-receipts.md §3.1`).
    let highest_visible_event_id: Option<String> = visible_messages
        .iter()
        .rev()
        .find(|msg| !msg.id.is_empty() && !msg.pending)
        .map(|msg| msg.id.clone());
    if let Some(top_event) = highest_visible_event_id.as_ref()
        && latest_read_cursor().as_str() != top_event
    {
        latest_read_cursor.set(top_event.clone());
        // Post the visible read receipt through the canonical
        // ephemeral channel; local marker state keeps the rendered
        // testid surface stable while server projection catches up.
        let base = base_url.clone();
        let realm = selected_realm_id.clone();
        let event_id = top_event.clone();
        let actor = account_did.clone();
        let api_token = token();
        spawn(async move {
            let _ = crate::views::helpers::with_authed_api(&base, api_token, |api| async move {
                api.send_receipt(&realm, &actor, &event_id, "ck.receipt.read")
                    .await
            })
            .await;
        });
    }
    // Both lookups are read-only `.iter().find()` scans, so they borrow the
    // single `all_messages_snapshot` clone instead of cloning the whole Vec
    // twice more per render.
    let messages_for_reply_lookup = &all_messages_snapshot;
    let messages_for_composer_lookup = &all_messages_snapshot;
    let left_open = !embedded && !direct_mode && left_panel_open();
    let active_right_panel = if embedded { None } else { right_panel() };
    let right_open = active_right_panel.is_some();
    let shell_class = format!(
        "discussion-shell{}{}{}{}",
        if embedded { " embedded" } else { "" },
        if direct_mode { " direct-mode" } else { "" },
        if left_open { "" } else { " left-collapsed" },
        if right_open { "" } else { " right-collapsed" }
    );
    let participant_projection = state_store
        .read()
        .load()
        .realm_tree_projections
        .get(&selected_realm_id)
        .cloned();
    let mut participants = space_participants(participant_projection.as_ref(), &account_did);
    // Mark agent endpoints registered in this Realm so the @mention
    // picker, member list, and sender row can render a 🤖 badge.
    // Source of truth is the local store's `ck.agent.endpoint` raw
    // operations (same projection the Agents panel reads from).
    {
        let agent_ids = agent_ids_from_raw_operations(
            &state_store.read().load().raw_operations,
            &selected_realm_id,
        );
        annotate_agent_participants(&mut participants, &agent_ids);
    }
    let participants_for_messages = participants.clone();
    let account_display_label = account_display_name();

    let mut participant_dids_for_presence = participants_for_messages
        .iter()
        .map(|participant| participant.did.clone())
        .filter(|did| !did.trim().is_empty())
        .collect::<Vec<_>>();
    participant_dids_for_presence.sort();
    participant_dids_for_presence.dedup();
    let has_remote_presence = participant_dids_for_presence
        .iter()
        .any(|did| did != &account_did);
    let presence_sync_key = format!(
        "{}|{}",
        selected_realm_id,
        participant_dids_for_presence.join(",")
    );
    {
        let realm = selected_realm_id.clone();
        let actor = account_did.clone();
        let participants_for_sync = participant_dids_for_presence.clone();
        let mut typing_actors_for_sync = typing_actors;
        let mut presence_states_for_sync = presence_states;
        let mut presence_labels_for_sync = presence_labels;
        let self_label_for_sync = account_display_label.clone();
        use_effect(move || {
            if token().trim().is_empty() || realm.trim().is_empty() || !has_remote_presence {
                return;
            }
            let cursor = sync_cursor();
            if cursor.trim().is_empty() || cursor == "-" {
                return;
            }
            let next_sync_key = format!("{presence_sync_key}|{cursor}");
            if presence_sync_key_seen.peek().as_str() == next_sync_key {
                return;
            }
            presence_sync_key_seen.set(next_sync_key);

            let snapshot = state_store.read().load();
            let active_typers =
                typing_actors_from_sync_realms(&snapshot.realm_tree_projections, &realm, &actor);
            if *typing_actors_for_sync.peek() != active_typers {
                typing_actors_for_sync.set(active_typers);
            }

            let (next_presence, next_labels) = presence_maps_from_sync_events(
                &snapshot.presence_projection,
                &participants_for_sync,
                &actor,
                &self_label_for_sync,
            )
            .unwrap_or_else(|| {
                let mut next_presence = std::collections::BTreeMap::<String, String>::new();
                let mut next_labels = std::collections::BTreeMap::<String, String>::new();
                for did in &participants_for_sync {
                    if did == &actor {
                        next_presence.insert(did.clone(), "online".to_owned());
                        if let Some(label) =
                            clean_participant_display_name(&self_label_for_sync, Some(did))
                        {
                            next_labels.insert(did.clone(), label);
                        }
                    } else {
                        next_presence.insert(did.clone(), "offline".to_owned());
                    }
                }
                (next_presence, next_labels)
            });
            if *presence_states_for_sync.peek() != next_presence {
                presence_states_for_sync.set(next_presence);
            }
            if *presence_labels_for_sync.peek() != next_labels {
                presence_labels_for_sync.set(next_labels);
            }
        });
    }

    if !initial_sync_requested() && !token().trim().is_empty() {
        initial_sync_requested.set(true);
        initial_sync_finished.set(false);
        let base = base_url.clone();
        let api_token = token();
        let wait_for = active_sync_token(sync_cursor());
        let selected_realm_for_load = selected_realm_id.clone();
        let account_did_for_load = account_did.clone();
        // P0 decrypt-on-read identity: this device's actor + device id let the
        // message projection decrypt remote members' canonical encrypted_content
        // envelopes from the local MLS snapshot.
        let local_decrypt_identity = Some((account_did.as_str(), device_id.as_str()));
        let (local_messages, local_poll_cards, local_channels) = {
            let store = state_store.read();
            let snapshot = store.load();
            (
                chat_messages_from_local_state_with_sidecar(
                    &snapshot,
                    Some(&store),
                    local_decrypt_identity,
                ),
                poll_cards_from_local_state(&snapshot),
                channels_from_local_state(&snapshot),
            )
        };
        if !local_channels.is_empty() {
            merge_channels(&mut channels.write(), local_channels);
        }
        if selected_channel().trim().is_empty()
            && let Some(first_channel) = channels.read().first()
        {
            selected_channel.set(first_channel.flow_id.clone());
        }
        if !local_messages.is_empty() {
            merge_chat_messages(&mut messages.write(), local_messages);
        }
        if !local_poll_cards.is_empty() {
            merge_poll_cards(&mut poll_cards.write(), local_poll_cards);
        }
        let account_did_for_decrypt = account_did.clone();
        let device_id_for_decrypt = device_id.clone();
        let mut account_display_name_for_load = account_display_name;
        let mut initial_sync_finished_for_load = initial_sync_finished;
        spawn(async move {
            let decrypt_identity = Some((
                account_did_for_decrypt.as_str(),
                device_id_for_decrypt.as_str(),
            ));
            let Ok(api) = authed_api_with_sync(&base, api_token, wait_for) else {
                initial_sync_finished_for_load.set(true);
                return;
            };
            let mut loaded_messages = Vec::new();
            let mut loaded_poll_cards = Vec::new();
            if let Ok(account) = api.account_me().await
                && account.did == account_did_for_load
            {
                if let Some(display_name) =
                    account_handle_display_from_server(&account.handle, &base).or_else(|| {
                        clean_participant_display_name(
                            account.display_name.as_deref().unwrap_or(""),
                            Some(&account_did_for_load),
                        )
                    })
                {
                    account_display_name_for_load.set(display_name);
                }
            }
            if let Ok(sync) = api.account_subscribe_snapshot(None).await {
                {
                    let mut store = state_store.write();
                    store.save_sync_cursor(sync.cursor.clone());
                    store.save_presence_projection(sync.presence.clone());
                    for (realm_id, projection) in &sync.realms {
                        store.save_realm_tree_projection(realm_id.clone(), projection.clone());
                    }
                }
                loaded_messages.extend(chat_messages_from_sync_realms_with_sidecar(
                    &sync.realms,
                    Some(&state_store.read()),
                    decrypt_identity,
                ));
                loaded_poll_cards.extend(poll_cards_from_sync_realms(&sync.realms));
                merge_channels(
                    &mut channels.write(),
                    channels_from_sync_realms(&sync.realms, &[selected_realm_for_load.clone()]),
                );
                sync_cursor.set(sync.cursor);
            }

            if !selected_realm_for_load.trim().is_empty() {
                if let Ok(backfill) = api.backfill(&selected_realm_for_load).await {
                    merge_channels(
                        &mut channels.write(),
                        channels_from_events(&selected_realm_for_load, &backfill.events),
                    );
                    loaded_messages.extend(chat_messages_from_events_with_sidecar(
                        &selected_realm_for_load,
                        &backfill.events,
                        Some(&state_store.read()),
                        decrypt_identity,
                    ));
                    loaded_poll_cards.extend(poll_cards_from_events(&backfill.events));
                }
            }

            merge_channels(
                &mut channels.write(),
                channels_from_local_state(&state_store.read().load()),
            );
            if selected_channel().trim().is_empty()
                && let Some(first_channel) = channels.read().first()
            {
                selected_channel.set(first_channel.flow_id.clone());
            }
            if !loaded_messages.is_empty() {
                merge_chat_messages(&mut messages.write(), loaded_messages);
            }
            if !loaded_poll_cards.is_empty() {
                merge_poll_cards(&mut poll_cards.write(), loaded_poll_cards);
            }
            initial_sync_finished_for_load.set(true);
        });
    }

    // T7.4: refresh per-message crypto state when local group state is
    // missing. Messages flagged `Decrypting` transition to `KeyMissing`
    // when no MLS snapshot is saved for the Space so the user sees a clear
    // "waiting for Welcome" indicator instead of a spinner forever.
    {
        let realm_for_crypto = selected_realm_id.clone();
        let mut messages_sig = messages;
        use_effect(move || {
            let snapshot_missing = state_store
                .read()
                .mls_snapshot_for(&realm_for_crypto)
                .is_none();
            // Only mutate when we'd actually move someone from Decrypting
            // into KeyMissing — Decrypting → Plaintext requires a real
            // decrypt attempt that this view doesn't yet run.
            // Peek first so we only take a (re-render-triggering) write lock
            // when at least one row would actually transition. Without this
            // guard every `state_store` change re-marked `messages` dirty even
            // when nothing changed, forcing a redundant repaint.
            let has_decrypting = snapshot_missing
                && messages_sig
                    .peek()
                    .iter()
                    .any(|msg| matches!(msg.crypto_state, MessageCryptoState::Decrypting));
            if has_decrypting {
                let mut current = messages_sig.write();
                for msg in current.iter_mut() {
                    if matches!(msg.crypto_state, MessageCryptoState::Decrypting) {
                        msg.crypto_state = MessageCryptoState::KeyMissing;
                    }
                }
            }
        });
    }

    {
        let messages_for_scroll = messages;
        let selected_channel_for_scroll = selected_channel;
        // Only scroll to the latest message when the visible count or the
        // active channel actually changes. Tracking the last-scrolled
        // (count, channel) pair keeps unrelated message mutations (e.g. a
        // crypto_state flip on an existing row) from yanking the feed.
        let mut last_scroll_key = use_signal(|| (0_usize, String::new()));
        use_effect(move || {
            let message_count = messages_for_scroll.read().len();
            let channel = selected_channel_for_scroll.read().clone();
            let key = (message_count, channel);
            if last_scroll_key.peek().clone() != key {
                last_scroll_key.set(key);
                scroll_chat_feed_to_latest();
            }
        });
    }

    let composer_class = "discussion-composer";
    let discussion_feed_loading = !visible_channels_empty
        && visible_message_count == 0
        && !token().trim().is_empty()
        && !initial_sync_finished();

    rsx! {
        div { class: "{shell_class}", "data-testid": "chat-panel", "data-chat-mode": if direct_mode { "direct" } else { "collaboration" },
            if left_open {
                aside { class: "discussion-panel discussion-sidebar-panel", "data-testid": "discussion-list-panel",
                    div { class: "discussion-panel-head",
                        div { class: "discussion-title-row",
                            h2 { {crate::i18n::tr("chat.discussions_header")} }
                            HelpTip { text: "Discussion is the selected Flow's track. The default Flow is always available for this Realm; the alternate filter includes every Flow with a discussion track." }
                        }
                        div { class: "discussion-panel-head-actions",
                            Button {
                                variant: ButtonVariant::Primary,
                                class: "icon-button",
                                "aria-label": crate::i18n::tr("chat.new_flow"),
                                title: crate::i18n::tr("chat.new_flow"),
                                "data-testid": "open-channel-dialog",
                                onclick: move |_| create_dialog_open.set(true),
                                UiIcon { name: "plus" }
                            }
                            Button {
                                variant: ButtonVariant::Secondary,
                                class: "icon-button",
                                "aria-label": crate::i18n::tr("chat.hide_list"),
                                "data-testid": "collapse-discussion-list",
                                onclick: move |_| left_panel_open.set(false),
                                UiIcon { name: "panel-left-close" }
                            }
                        }
                    }
                    div { class: "discussion-filter segmented-control",
                        Button {
                            variant: ButtonVariant::Secondary,
                            class: if track_filter() == "discussion_only" { "segment active" } else { "segment" },
                            "data-testid": "discussion-filter-only",
                            onclick: move |_| track_filter.set("discussion_only".to_owned()),
                            "Default + discussion"
                        }
                        Button {
                            variant: ButtonVariant::Secondary,
                            class: if track_filter() == "with_discussion_track" { "segment active" } else { "segment" },
                            "data-testid": "discussion-filter-track",
                            onclick: move |_| track_filter.set("with_discussion_track".to_owned()),
                            "All Flow tracks"
                        }
                    }
                    div { class: "discussion-list", "data-testid": "channel-list",
                        for channel in visible_channels {
                            Button {
                                variant: ButtonVariant::Secondary,
                                class: if channel.flow_id == selected_channel() { "discussion-track-row active" } else { "discussion-track-row" },
                                "data-testid": "channel-item",
                                onclick: {
                                    let id = channel.flow_id.clone();
                                    move |_| selected_channel.set(id.clone())
                                },
                                div { class: "discussion-track-main",
                                    span { class: "discussion-track-name-row",
                                        SecurityStateBadge {
                                            encrypted: channel.security_encrypted.unwrap_or(selected_realm_security_encrypted),
                                            compact: true,
                                            test_id: Some("flow-track-security-state".to_owned()),
                                        }
                                        span { class: "discussion-track-name", "{channel.name}" }
                                    }
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
                            div { class: "discussion-empty", "data-testid": "empty-discussion-list", {crate::i18n::tr("chat.empty_discussions")} }
                        }
                    }
                }
            } else if !embedded && !direct_mode {
                div { class: "discussion-rail discussion-left-rail", "data-testid": "discussion-list-rail",
                    Button {
                        variant: ButtonVariant::Secondary,
                        class: "icon-button",
                        "aria-label": "Show discussion list",
                        "data-testid": "expand-discussion-list",
                        onclick: move |_| left_panel_open.set(true),
                        UiIcon { name: "panel-left-open" }
                    }
                }
            }

            if !embedded && !direct_mode && create_dialog_open() {
                Dialog {
                    open: true,
                    on_open_change: move |open: bool| {
                        if !open {
                            create_dialog_open.set(false);
                        }
                    },
                    "data-testid": "channel-create-modal",
                    "aria-label": "New Flow",
                    div { class: "discussion-modal",
                        div { class: "discussion-modal-head",
                            div { class: "discussion-title-row",
                                h2 { "New Flow" }
                                HelpTip { text: "Creates an additional Flow. Its discussion track is available from this view; enable the card option when the same Flow should also carry a synthesis track." }
                            }
                            Button {
                                variant: ButtonVariant::Secondary,
                                class: "icon-button",
                                "aria-label": "Close",
                                "data-testid": "close-channel-dialog",
                                onclick: move |_| create_dialog_open.set(false),
                                UiIcon { name: "x" }
                            }
                        }
                        div { class: "discussion-modal-body workflow-form",
                            Label { html_for: "new-channel-name-input", {crate::i18n::tr("chat.label.title")} }
                            Input {
                                id: "new-channel-name-input",
                                "data-testid": "new-channel-name",
                                value: "{new_channel_name}",
                                placeholder: "Flow title",
                                oninput: move |event: FormEvent| new_channel_name.set(event.value()),
                            }
                            Label { html_for: "new-channel-topic-input", {crate::i18n::tr("chat.label.summary")} }
                            Input {
                                id: "new-channel-topic-input",
                                "data-testid": "new-channel-topic",
                                value: "{new_channel_topic}",
                                placeholder: "Short purpose or context",
                                oninput: move |event: FormEvent| new_channel_topic.set(event.value()),
                            }
                            label { class: "discussion-checkbox-row",
                                Checkbox {
                                    "data-testid": "new-channel-create-card",
                                    checked: if new_channel_create_card() { CheckboxState::Checked } else { CheckboxState::Unchecked },
                                    on_checked_change: move |state: CheckboxState| new_channel_create_card.set(bool::from(state)),
                                }
                                span { "Create matching Card" }
                            }
                        }
                        div { class: "discussion-modal-actions",
                            Button {
                                variant: ButtonVariant::Secondary,
                                "data-testid": "cancel-channel-create",
                                onclick: move |_| create_dialog_open.set(false),
                                {crate::i18n::tr("common.cancel")}
                            }
                            Button {
                                variant: ButtonVariant::Primary,
                                "data-testid": "create-channel-button",
                                onclick: {
                                    let base = base_url.clone();
                                    let actor = account_did.clone();
                                    let realm = selected_realm_id.clone();
                                    move |_| {
                                        let title = new_channel_name().trim().to_owned();
                                        if title.is_empty() {
                                            status_msg.set("Flow title is required".to_owned());
                                            return;
                                        }
                                        let category = "general".to_owned();
                                        let summary = new_channel_topic().trim().to_owned();
                                        let create_card = new_channel_create_card();
                                        let flow_id = format!("ck:flow:{}", uuid_v7());
                                        let rank = format!("r{}", chrono::Utc::now().timestamp_millis());
                                        let op = match ck_ops::discussion_flow_create(
                                            &realm,
                                            &actor,
                                            &flow_id,
                                            &title,
                                        ) {
                                            Ok(builder) => {
                                                let mut op = builder.build("yougen");
                                                if !op.payload["object"]
                                                    .get("fields")
                                                    .is_some_and(|fields| fields.is_object())
                                                {
                                                    op.payload["object"]["fields"] = json!({});
                                                }
                                                op.payload["object"]["fields"]["category"] =
                                                    json!(category.clone());
                                                op.payload["object"]["fields"]["has_synthesis"] =
                                                    json!(create_card);
                                                op.payload["object"]["rank"] = json!(rank.clone());
                                                if !summary.is_empty() {
                                                    op.payload["object"]["summary"] = json!(summary.clone());
                                                }
                                                if !create_card
                                                    && let Some(tracks) = op.payload["object"]["tracks"].as_object_mut()
                                                {
                                                    tracks.remove("synthesis");
                                                }
                                                if let Err(error) = op.refresh_proof_hashes() {
                                                    status_msg.set(format!(
                                                        "Could not create Flow proof: {error}"
                                                    ));
                                                    return;
                                                }
                                                op
                                            }
                                            Err(error) => {
                                                status_msg.set(format!(
                                                    "Could not create Flow: {error}"
                                                ));
                                                return;
                                            }
                                        };
                                        let api_token = token();
                                        let wait_for = active_sync_token(sync_cursor());
                                        let channel_topic = if summary.is_empty() { None } else { Some(summary) };
                                        let base = base.clone();
                                        let realm = realm.clone();
                                        status_msg.set("Creating Flow".to_owned());
                                        spawn(async move {
                                            match authed_api_with_sync(&base, api_token.clone(), wait_for) {
                                                Ok(api) => match api
                                                        .submit_event_envelope(&op)
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
                                                                is_default: false,
                                                                security_encrypted: None,
                                                                // P3B.2.3 — the new-Flow form
                                                                // currently creates Realm-scoped
                                                                // Flows only; Circle scope
                                                                // selection arrives once the
                                                                // CircleScopePicker is mounted
                                                                // on this form.
                                                                scope_circle: None,
                                                            });
                                                            selected_channel.set(flow_id.clone());
                                                            frontier_state.set(submitted.event_id.clone());
                                                            {
                                                                let mut store = state_store.write();
                                                                // Keep POST /events sync_token out of the persisted
                                                                // account-subscribe cursor; the background sync loop
                                                                // must resume only from /account/subscribe cursors.
                                                                store.append_raw_operation(
                                                                    op.local_operation_id().to_owned(),
                                                                    Some(realm.clone()),
                                                                    json!({
                                                                        "flow_id": flow_id,
                                                                        "kind": "ck.flow.create",
                                                                        "title": title,
                                                                        "category": category,
                                                                        "summary": channel_topic,
                                                                        "create_card": create_card,
                                                                        "object": op.payload["object"].clone(),
                                                                        "event_id": submitted.event_id,
                                                                    }),
                                                                );
                                                            }
                                                            status_msg.set("Flow created".to_owned());
                                                            new_channel_name.set(String::new());
                                                            new_channel_topic.set(String::new());
                                                            new_channel_create_card.set(false);
                                                            create_dialog_open.set(false);
                                                        }
                                                        Err(error) => status_msg.set(format!("Flow create failed: {error}")),
                                                    },
                                                    Err(error) => status_msg.set(format!("Invalid server URL: {error}")),
                                                }
                                            });
                                        }
                                    },
                                {crate::i18n::tr("chat.button.create")}
                            }
                        }
                    }
                }
            }

            section { class: "discussion-panel discussion-main-panel", "data-testid": "discussion-main-panel",
                header { class: "discussion-chat-head",
                    div { class: "discussion-title-stack",
                        div { class: "discussion-title-row",
                            SecurityStateBadge {
                                encrypted: selected_channel_security_encrypted,
                                compact: true,
                                test_id: Some("selected-flow-security-state".to_owned()),
                            }
                            h1 { "{selected_channel_name}" }
                        }
                    }
                    if !embedded {
                    div { class: "discussion-head-actions",
                        // T7.2: watch-level fast switcher. Issues a
                        // `ck.flow.watch.set` event on selection. We
                        // optimistically update the local signal first;
                        // a network failure rolls back via status_msg.
                        {
                            let level_now = flow_watch_level();
                            let menu_open = watch_level_menu_open();
                            let level_label = crate::i18n::tr(watch_level_label_key(level_now));
                            let flow_id_for_watch = selected_channel_value.clone();
                            let realm_for_watch = selected_realm_id.clone();
                            let actor_for_watch = account_did.clone();
                            let watch_disabled = flow_id_for_watch.trim().is_empty();
                            rsx! {
                                div { class: "watch-level-picker", "data-testid": "watch-level-picker",
                                    Button {
                                        variant: ButtonVariant::Secondary,
                                        r#type: "button",
                                        class: "watch-level-toggle",
                                        "data-testid": "watch-level-toggle",
                                        disabled: watch_disabled,
                                        title: crate::i18n::tr("chat.watch_level.tooltip"),
                                        onclick: move |_| {
                                            watch_level_menu_open.set(!watch_level_menu_open());
                                        },
                                        span { class: "watch-level-toggle-label",
                                            "{crate::i18n::tr(\"chat.watch_level.prefix\")}: {level_label}"
                                        }
                                        span { class: "watch-level-toggle-caret", "\u{25be}" }
                                    }
                                    if menu_open && !watch_disabled {
                                        div { class: "watch-level-menu", "data-testid": "watch-level-menu",
                                            {
                                                let options = [
                                                    WatchLevel::MentionsOnly,
                                                    WatchLevel::Participating,
                                                    WatchLevel::All,
                                                    WatchLevel::Muted,
                                                ];
                                                rsx! {
                                                    for option in options.iter().copied() {
                                                        {
                                                            let option_label = crate::i18n::tr(watch_level_label_key(option));
                                                            let flow_id_for_click = flow_id_for_watch.clone();
                                                            let realm_for_click = realm_for_watch.clone();
                                                            let actor_for_click = actor_for_watch.clone();
                                                            let base_for_click = base_url.clone();
                                                            let is_active = level_now == option;
                                                            rsx! {
                                                                Button {
                                                                    variant: ButtonVariant::Secondary,
                                                                    r#type: "button",
                                                                    class: if is_active { "watch-level-option active" } else { "watch-level-option" },
                                                                    "data-testid": "watch-level-option",
                                                                    onclick: move |_| {
                                                                        let prev = flow_watch_level();
                                                                        flow_watch_level.set(option);
                                                                        watch_level_menu_open.set(false);
                                                                        status_msg.set(crate::i18n::tr("chat.watch_level.pending"));
                                                                        let api_token = token();
                                                                        let wait_for = active_sync_token(sync_cursor());
                                                                        let watch_op = match ck_ops::flow_watch_set(
                                                                            &realm_for_click,
                                                                            &actor_for_click,
                                                                            &actor_for_click,
                                                                            &flow_id_for_click,
                                                                            Some(watch_level_wire_value(option)),
                                                                            None,
                                                                        ) {
                                                                            Ok(builder) => builder.build("yougen"),
                                                                            Err(err) => {
                                                                                tracing::warn!("flow_watch_set build failed: {err:#}");
                                                                                flow_watch_level.set(prev);
                                                                                status_msg.set(crate::i18n::tr("chat.watch_level.failed"));
                                                                                return;
                                                                            }
                                                                        };
                                                                        let base = base_for_click.clone();
                                                                        spawn(async move {
                                                                            match authed_api_with_sync(&base, api_token, wait_for) {
                                                                                Ok(api) => match api.submit_event_envelope(&watch_op).await {
                                                                                    Ok(_) => {
                                                                                        status_msg.set(crate::i18n::tr("chat.watch_level.saved"));
                                                                                    }
                                                                                    Err(_) => {
                                                                                        // Rollback on failure.
                                                                                        flow_watch_level.set(prev);
                                                                                        status_msg.set(crate::i18n::tr("chat.watch_level.failed"));
                                                                                    }
                                                                                },
                                                                                Err(_) => {
                                                                                    flow_watch_level.set(prev);
                                                                                    status_msg.set(crate::i18n::tr("chat.watch_level.failed"));
                                                                                }
                                                                            }
                                                                        });
                                                                    },
                                                                    "{option_label}"
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        Button {
                            variant: ButtonVariant::Secondary,
                            class: if active_right_panel == Some(DiscussionSidePanel::Settings) { "icon-button active" } else { "icon-button" },
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
                        Button {
                            variant: ButtonVariant::Secondary,
                            class: if active_right_panel == Some(DiscussionSidePanel::Users) { "icon-button active" } else { "icon-button" },
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
                }

                // A6.3 pinned bar (above the chat feed). Lists every
                // pinned message id with a short body preview. Clicking
                // an item scrolls (well, focuses) the corresponding
                // message via its `data-testid` anchor.
                //
                // Local-only scaffolding — see TODO at `pinned_messages`
                // signal declaration. Replace with the soland pinning
                // projection when the spec lands.
                {
                    let pinned_now = pinned_messages();
                    let pinned_view: Vec<(String, String)> = pinned_now
                        .iter()
                        .filter_map(|id| {
                            messages_for_reply_lookup
                                .iter()
                                .find(|m| m.id == *id)
                                .map(|m| (m.id.clone(), m.body.clone()))
                        })
                        .collect();
                    rsx! {
                        if !embedded || !pinned_view.is_empty() {
                            div {
                                class: "pinned-bar",
                                "data-testid": "pinned-bar",
                                if pinned_view.is_empty() {
                                    span {
                                        class: "pinned-bar-empty",
                                        "data-testid": "pinned-bar-empty",
                                        {crate::i18n::tr("pinned_bar.empty")}
                                    }
                                } else {
                                    div { class: "pinned-bar-head",
                                        UiIcon { name: "pin" }
                                        span { {crate::i18n::tr("pinned_bar.title")} }
                                    }
                                    div { class: "pinned-bar-list",
                                        for (id, body) in pinned_view {
                                            {
                                                let id_for_click = id.clone();
                                                let preview = if body.chars().count() > 40 {
                                                    format!(
                                                        "{}...",
                                                        body.chars().take(40).collect::<String>()
                                                    )
                                                } else {
                                                    body
                                                };
                                                rsx! {
                                                    Button {
                                                        variant: ButtonVariant::Secondary,
                                                        r#type: "button",
                                                        class: "pinned-bar-item",
                                                        "data-testid": "pinned-bar-item",
                                                        title: crate::i18n::tr("pinned_bar.scroll_to"),
                                                        onclick: move |_| {
                                                            // Best-effort scroll: emit
                                                            // a console hint via
                                                            // status_msg so QA can see
                                                            // the click registered.
                                                            // Real scroll-into-view
                                                            // wires into Dioxus's
                                                            // mounted ref API; deferred
                                                            // until A6.3 lands the
                                                            // soland projection.
                                                            status_msg.set(format!(
                                                                "jump to pinned message {}",
                                                                id_for_click
                                                            ));
                                                        },
                                                        UiIcon { name: "pin" }
                                                        span { class: "pinned-bar-preview", "{preview}" }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                // G3.Y2 — typing indicator. Shown when one or more
                // other actors in the active flow have sent a
                // `ck.typing` ephemeral within `TYPING_TTL_SECONDS`.
                // The DIDs live on `data-typing-actors` so cotest can
                // assert on them without scraping localised text.
                {
                    let active_typers: Vec<String> = typing_actors()
                        .into_iter()
                        .filter(|did| did != &account_did)
                        .collect();
                    if !active_typers.is_empty() {
                        let attr_value = active_typers.join(",");
                        let live_labels = presence_labels();
                        let label = active_typers
                            .iter()
                            .map(|did| {
                                display_label_for_actor(
                                    &state_store.read(),
                                    &participants_for_messages,
                                    &live_labels,
                                    did,
                                )
                            })
                            .collect::<Vec<_>>()
                            .join(", ");
                        rsx! {
                            div {
                                class: "typing-indicator",
                                "data-testid": "typing-indicator",
                                "data-typing-actors": "{attr_value}",
                                span { class: "typing-dots", "\u{2022}\u{2022}\u{2022}" }
                                span { class: "typing-actors", "{label}" }
                                span { class: "muted", " is typing\u{2026}" }
                            }
                        }
                    } else {
                        rsx! {}
                    }
                }

                div { class: "discussion-chat-feed", "data-testid": "message-list",
                    for msg in visible_messages {
                        {
                            let scope_circle = flow_scope_lookup.get(&msg.flow_id).cloned();
                            let scope_class = if scope_circle.is_some() {
                                " has-circle-accent-rail"
                            } else {
                                ""
                            };
                            let scope_attr = scope_circle
                                .as_ref()
                                .map(|c| c.circle_id.clone())
                                .unwrap_or_default();
                            let message_is_pinned = pinned_messages()
                                .iter()
                                .any(|id| id == &msg.id);
                            rsx! {
                        div {
                            key: "{msg.id}",
                            class: {
                                let mut base = if is_own_message_sender(&msg.sender, &account_did) {
                                    if msg.failed { "discussion-message is-own is-failed".to_owned() } else { "discussion-message is-own".to_owned() }
                                } else if msg.failed {
                                    "discussion-message is-failed".to_owned()
                                } else {
                                    "discussion-message".to_owned()
                                };
                                // T7.4: grey out and italicise messages
                                // that are still waiting on key material.
                                if msg.crypto_state.is_pending() {
                                    base.push_str(" is-crypto-pending");
                                }
                                if message_is_pinned {
                                    base.push_str(" is-pinned");
                                }
                                base.push_str(scope_class);
                                base
                            },
                            "data-testid": "chat-message",
                            "data-circle-scope-id": "{scope_attr}",
                            "data-crypto-state": match msg.crypto_state {
                                MessageCryptoState::Plaintext => "plaintext",
                                MessageCryptoState::Decrypting => "decrypting",
                                MessageCryptoState::KeyMissing => "key_missing",
                                MessageCryptoState::NeedsVerification => "needs_verification",
                            },
                            // A6.3: right-click toggles a tiny context
                            // menu offering Pin/Unpin for this message.
                            // prevent_default suppresses the browser's
                            // native context menu so ours surfaces alone.
                            oncontextmenu: {
                                let msg_id = msg.id.clone();
                                move |evt| {
                                    evt.prevent_default();
                                    let next = if message_context_menu()
                                        .as_deref()
                                        == Some(msg_id.as_str())
                                    {
                                        None
                                    } else {
                                        Some(msg_id.clone())
                                    };
                                    message_context_menu.set(next);
                                }
                            },
                            // CKP-0007 P3B.2.4 — Circle scope accent
                            // rail. Renders a left-edge coloured ribbon
                            // with the Circle title as a tooltip when
                            // the message's enclosing Flow has a
                            // `scope_circle_id`. The CSS class
                            // `has-circle-accent-rail` on the outer
                            // message div positions the ribbon at the
                            // left margin.
                            if let Some(circle) = scope_circle.as_ref() {
                                div {
                                    class: "circle-accent-rail",
                                    "data-testid": "circle-accent-rail",
                                    "data-circle-id": "{circle.circle_id}",
                                    title: "Circle scope · {circle.title}",
                                    "aria-label": "This message is part of the Circle named {circle.title}",
                                }
                            }
                            // Tiny pop-out menu — Pin / Unpin / Cancel.
                            // The render condition checks per-message
                            // so only one menu is visible at a time.
                            if message_context_menu().as_deref() == Some(msg.id.as_str()) {
                                div {
                                    class: "message-context-menu",
                                    "data-testid": "message-context-menu",
                                    {
                                        let is_pinned = pinned_messages()
                                            .iter()
                                            .any(|id| id == &msg.id);
                                        let msg_id = msg.id.clone();
                                        let msg_id_for_label = msg.id.clone();
                                        rsx! {
                                            Button {
                                                variant: ButtonVariant::Secondary,
                                                r#type: "button",
                                                "data-testid": "message-pin-button",
                                                onclick: move |_| {
                                                    let mut current = pinned_messages();
                                                    if let Some(idx) = current
                                                        .iter()
                                                        .position(|id| id == &msg_id)
                                                    {
                                                        current.remove(idx);
                                                    } else {
                                                        current.push(msg_id.clone());
                                                    }
                                                    pinned_messages.set(current);
                                                    message_context_menu.set(None);
                                                    // TODO(soland): replace
                                                    // the local-only Signal
                                                    // with the canonical
                                                    // pinning event projection
                                                    // once the reducer lands.
                                                },
                                                if is_pinned {
                                                    {crate::i18n::tr("message.unpin")}
                                                } else {
                                                    {crate::i18n::tr("message.pin")}
                                                }
                                            }
                                            Button {
                                                variant: ButtonVariant::Secondary,
                                                r#type: "button",
                                                onclick: move |_| {
                                                    let _ = msg_id_for_label.clone();
                                                    message_context_menu.set(None);
                                                },
                                                "Cancel"
                                            }
                                        }
                                    }
                                }
                            }
                            div { class: "msg-body",
                                if message_is_pinned {
                                    Button {
                                        variant: ButtonVariant::Secondary,
                                        r#type: "button",
                                        class: "message-pin-indicator",
                                        "data-testid": "message-pinned-button",
                                        "aria-label": crate::i18n::tr("message.unpin"),
                                        title: crate::i18n::tr("message.unpin"),
                                        onclick: {
                                            let msg_id = msg.id.clone();
                                            move |_| {
                                                let mut current = pinned_messages();
                                                current.retain(|id| id != &msg_id);
                                                pinned_messages.set(current);
                                            }
                                        },
                                        UiIcon { name: "pin" }
                                    }
                                }
                                div { class: "msg-head",
                                    span { class: "name", "{sender_display_label(&msg.sender, &account_did, &account_display_label, &participants_for_messages)}" }
                                    {
                                        let sender_is_agent = participants_for_messages
                                            .iter()
                                            .any(|p| p.did == msg.sender && p.is_agent);
                                        rsx! {
                                            if sender_is_agent {
                                                span {
                                                    class: "badge member-badge member-badge-agent",
                                                    "data-testid": "member-badge-agent",
                                                    title: "Automated member (bot)",
                                                    "\u{1f916} "
                                                    {crate::i18n::tr("member.badge.agent")}
                                                }
                                            }
                                        }
                                    }
                                    time { "{msg.timestamp}" }
                                    if msg.failed {
                                        span {
                                            class: "message-status-icon is-failed",
                                            "data-testid": "message-send-status",
                                            title: "Message send failed",
                                            "!"
                                        }
                                    } else if msg.pending {
                                        span {
                                            class: "message-status-icon is-pending",
                                            "data-testid": "message-send-status",
                                            title: "Sending"
                                        }
                                    }
                                    if msg.edited { span { class: "badge", "edited" } }
                                }
                                // T7.4: per-message crypto status row.
                                // Sits directly under the head so the
                                // icon + label appear before the body
                                // when it's awaiting decrypt.
                                {
                                    match msg.crypto_state {
                                        MessageCryptoState::Plaintext => rsx! { },
                                        MessageCryptoState::Decrypting => rsx! {
                                            div {
                                                class: "crypto-status-row crypto-status-decrypting",
                                                "data-testid": "crypto-status-decrypting",
                                                span { class: "crypto-status-icon", "\u{23f3}" }
                                                span { {crate::i18n::tr("chat.crypto.decrypting")} }
                                            }
                                        },
                                        MessageCryptoState::KeyMissing => rsx! {
                                            div {
                                                class: "crypto-status-row crypto-status-key-missing",
                                                "data-testid": "crypto-status-key-missing",
                                                span { class: "crypto-status-icon", "\u{1f511}" }
                                                span { {crate::i18n::tr("chat.crypto.key_missing")} }
                                                span { class: "muted", {crate::i18n::tr("chat.crypto.key_missing_hint")} }
                                            }
                                        },
                                        MessageCryptoState::NeedsVerification => rsx! {
                                            div {
                                                class: "crypto-status-row crypto-status-needs-verification",
                                                "data-testid": "crypto-status-needs-verification",
                                                span { class: "crypto-status-icon", "\u{26a0}" }
                                                span { {crate::i18n::tr("chat.crypto.needs_verification")} }
                                            }
                                        },
                                    }
                                }
                                if let Some(reply_id) = msg.reply_to.as_ref() {
                                    if let Some((quoted_name, quoted_body)) = chat_reply_quote_preview(
                                        messages_for_reply_lookup,
                                        reply_id,
                                        &account_did,
                                        &account_display_label,
                                        &participants_for_messages,
                                    ) {
                                        div { class: "chat-reply-quote", "data-testid": "chat-reply-indicator",
                                            span { class: "chat-reply-quote-name", "{quoted_name}" }
                                            div { class: "chat-reply-quote-body", "{quoted_body}" }
                                        }
                                    } else {
                                        div { class: "chat-reply-quote chat-reply-quote-missing", "data-testid": "chat-reply-indicator",
                                            "Replying to a message"
                                        }
                                    }
                                }
                                if msg.redacted {
                                    div { class: "msg-content redacted", "data-testid": "chat-redacted-tombstone", "[Message redacted]" }
                                } else if blocked_did_set.contains(&msg.sender)
                                    && !blocked_show_anyway.read().contains(&msg.id)
                                {
                                    // A5 — sender is on the personal
                                    // blocklist; show a placeholder
                                    // body + a "Show anyway" reveal.
                                    div {
                                        class: "msg-content muted",
                                        "data-testid": "timeline-blocked-row",
                                        {crate::i18n::tr("timeline.blocked_user")}
                                    }
                                    Button {
                                        variant: ButtonVariant::Secondary,
                                        "data-testid": "timeline-blocked-show-anyway",
                                        onclick: {
                                            let eid = msg.id.clone();
                                            move |_| {
                                                blocked_show_anyway.write().insert(eid.clone());
                                            }
                                        },
                                        {crate::i18n::tr("timeline.show_anyway")}
                                    }
                                } else {
                                    div { class: "msg-content",
                                        {render_message_body(&msg.body, &msg.mentions, &base_url)}
                                    }
                                }
                                if !msg.reactions.is_empty() {
                                    div { class: "actions chat-chip-row", "data-testid": "chat-reactions",
                                        for (emoji, senders) in &msg.reactions {
                                            span { class: "badge", "{emoji} {senders.len()}" }
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
                                        Button {
                                            variant: ButtonVariant::Secondary,
                                            class: "message-retry-button",
                                            "data-testid": "chat-retry-button",
                                            onclick: {
                                                let base = base_url.clone();
                                                let service_did = plaintext_service_did.clone();
                                                let realm = msg.realm_id.clone();
                                                let actor = account_did.clone();
                                                let local_id = msg.id.clone();
                                                let body = msg.body.clone();
                                                let flow_id = msg.flow_id.clone();
                                                let mentions = msg.mentions.clone();
                                                let reply_to = msg.reply_to.clone();
                                                move |_| {
                                                    let retry_message_id =
                                                        schema_message_id_or_new(&local_id);
                                                    if let Some(found) = messages
                                                        .write()
                                                        .iter_mut()
                                                        .find(|candidate| candidate.id == local_id)
                                                    {
                                                        found.id = retry_message_id.clone();
                                                        found.pending = true;
                                                        found.failed = false;
                                                        found.error = None;
                                                    }
                                                    status_msg.set("Retrying message".to_owned());
                                                    let base = base.clone();
                                                    let service_did = service_did.clone();
                                                    let realm = realm.clone();
                                                    let actor = actor.clone();
                                                    let api_token = token();
                                                    let wait_for = active_sync_token(sync_cursor());
                                                    let message_id = retry_message_id.clone();
                                                    let message_id_for_lookup = retry_message_id.clone();
                                                    let message_id_for_store = message_id.clone();
                                                    let body_for_store = body.clone();
                                                    let actor_for_store = actor.clone();
                                                    let flow_id_for_store = flow_id.clone();
                                                    let reply_to_for_store = reply_to.clone();
                                                    let projection = state_store
                                                        .read()
                                                        .load()
                                                        .realm_tree_projections
                                                        .get(&realm)
                                                        .cloned();
                                                    let plaintext_services = plaintext_services_for_policy(
                                                        projection.as_ref(),
                                                        &service_did,
                                                    );
                                                    let op = match chat_message_create_operation(
                                                        &realm,
                                                        &actor,
                                                        &flow_id,
                                                        "discussion",
                                                        &message_id,
                                                        &body,
                                                        &mentions,
                                                        reply_to.as_deref(),
                                                    ) {
                                                        Ok(op) => op,
                                                        Err(error) => {
                                                            if let Some(found) = messages
                                                                .write()
                                                                .iter_mut()
                                                                .find(|candidate| candidate.id == message_id_for_lookup)
                                                            {
                                                                found.pending = false;
                                                                found.failed = true;
                                                                found.error = Some(format!("send failed: {error:#}"));
                                                            }
                                                            status_msg.set(format!("send failed: {error:#}"));
                                                            return;
                                                        }
                                                    };
                                                    let mention_values_for_store = mentions_to_json(&mentions);
                                                    let realm_for_record = realm.clone();
                                                    let actor_for_retry = actor.clone();
                                                    spawn(async move {
                                                        match submit_chat_operation_with_auth_refresh(
                                                            &base,
                                                            &actor_for_retry,
                                                            &realm,
                                                            api_token,
                                                            wait_for,
                                                            &plaintext_services,
                                                            &op,
                                                        ).await {
                                                            Ok(resp) => {
                                                                {
                                                                    let mut store = state_store.write();
                                                                    store.append_raw_operation(
                                                                        op.local_operation_id().to_owned(),
                                                                        Some(realm_for_record),
                                                                        json!({
                                                                            "event_id": resp.event_id.clone(),
                                                                            "kind": "ck.message.create",
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
                                                        }
                                                    });
                                                }
                                            },
                                            {crate::i18n::tr("common.retry")}
                                        }
                                    }
                                }
                                if !msg.redacted {
                                    div { class: "actions chat-message-actions",
                                        Button {
                                            variant: ButtonVariant::Secondary,
                                            class: "chat-message-action",
                                            "data-testid": "chat-reply-button",
                                            onclick: {
                                                let msg_id = msg.id.clone();
                                                move |_| reply_to_message.set(Some(msg_id.clone()))
                                            },
                                            {crate::i18n::tr("chat.button.reply")}
                                        }
                                        Button {
                                            variant: ButtonVariant::Secondary,
                                            class: "chat-message-action",
                                            "data-testid": "chat-react-button",
                                            onclick: {
                                                let msg_id = msg.id.clone();
                                                move |_| {
                                                    let current = reaction_picker();
                                                    reaction_picker.set(if current == Some(msg_id.clone()) { None } else { Some(msg_id.clone()) });
                                                }
                                            },
                                            {crate::i18n::tr("chat.button.react")}
                                        }
                                        Button {
                                            variant: ButtonVariant::Secondary,
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
                                            {crate::i18n::tr("common.edit")}
                                        }
                                        Button {
                                            variant: ButtonVariant::Secondary,
                                            class: "chat-message-action",
                                            "data-testid": "chat-redact-button",
                                            onclick: {
                                                let msg_id = msg.id.clone();
                                                move |_| redact_confirm.set(Some(msg_id.clone()))
                                            },
                                            {crate::i18n::tr("chat.button.redact")}
                                        }
                                    }
                                }
                                // G3.Y2 — per-message read-receipt
                                // indicator. Surfaces the set of actors
                                // who have published a `ck.read_cursor.advance`
                                // covering this message via
                                // `presence_aggregate`. Empty (`hidden`)
                                // until the receive path is wired.
                                //
                                // TODO(G3.Y2-followup): subscribe to
                                // `ck.read_cursor.advance` ephemeral channel +
                                // populate from
                                // `presence_rx::PresenceAggregate`.
                                {
                                    // TODO(G3.Y2-followup): wire to
                                    // `presence_rx::PresenceAggregate`
                                    // once the chat view subscribes to
                                    // soland's ephemeral channel for
                                    // `ck.read_cursor.advance`. For now the
                                    // list is empty — the testid still
                                    // mounts when there is data so
                                    // cotest can assert against it.
                                    let readers: Vec<String> = Vec::new();
                                    if !readers.is_empty() {
                                        let attr = readers.join(",");
                                        rsx! {
                                            div {
                                                class: "read-receipt-indicator",
                                                "data-testid": "read-receipt-indicator",
                                                "data-readers": "{attr}",
                                                for did in &readers {
                                                    span {
                                                        class: "read-receipt-avatar",
                                                        title: "{did}",
                                                        "\u{2713}"
                                                    }
                                                }
                                            }
                                        }
                                    } else {
                                        rsx! {}
                                    }
                                }
                                // G3.Y2 — poll card. If this message
                                // carries a poll payload (currently
                                // matched by a poll_card entry whose
                                // message_id == msg.id), render the
                                // poll surface inline. The poll
                                // composer in the attachment menu
                                // pushes a new PollCard here on send.
                                {
                                    let card_lookup = poll_cards()
                                        .iter()
                                        .find(|card| card.message_id == msg.id)
                                        .cloned();
                                    match card_lookup {
                                        Some(card) => {
                                            let poll_id = card.poll_id.clone();
                                            let total = card.total_votes();
                                            let voted = card.actor_has_voted(&account_did);
                                            rsx! {
                                                div {
                                                    class: "poll-card timeline-event-poll",
                                                    "data-testid": "poll-card",
                                                    "data-poll-id": "{poll_id}",
                                                    div {
                                                        class: "poll-question",
                                                        "data-testid": "poll-question-text",
                                                        "{card.question}"
                                                    }
                                                    div {
                                                        class: "poll-state",
                                                        "data-testid": "poll-state",
                                                        if card.closed { "closed" } else { "open" }
                                                    }
                                                    for (idx, option) in card.options.iter().enumerate() {
                                                        {
                                                            let votes_for = card.votes_for(idx);
                                                            let option_index_attr = idx as i64;
                                                            let option_label = option.label.clone();
                                                            let option_id = option.id.clone();
                                                            let card_poll_id = poll_id.clone();
                                                            let card_message_id = card.message_id.clone();
                                                            let realm = msg.realm_id.clone();
                                                            let actor = account_did.clone();
                                                            let card_closed = card.closed;
                                                            let base_for_vote = base_url.clone();
                                                            rsx! {
                                                                div {
                                                                    class: "poll-result-row",
                                                                    "data-testid": "poll-result-row",
                                                                    "data-option-index": "{option_index_attr}",
                                                                    "data-option-text": "{option_label}",
                                                                    if !card_closed {
                                                                        Button {
                                                                            variant: ButtonVariant::Secondary,
                                                                            class: "poll-option poll-vote-button",
                                                                            "data-testid": "poll-option",
                                                                            disabled: card_closed,
                                                                            onclick: {
                                                                                let card_message_id = card_message_id.clone();
                                                                                let actor = actor.clone();
                                                                                let realm = realm.clone();
                                                                                let card_poll_id = card_poll_id.clone();
                                                                                let option_id = option_id.clone();
                                                                                let api_token = token();
                                                                                let base_for_vote = base_for_vote.clone();
                                                                                move |_| {
                                                                                    if let Some(found) = poll_cards
                                                                                        .write()
                                                                                        .iter_mut()
                                                                                        .find(|c| c.message_id == card_message_id)
                                                                                    {
                                                                                        found.vote(&actor, idx);
                                                                                    }
                                                                                    if let Some(found) = messages.write().iter_mut().find(|candidate| candidate.id == card_message_id) {
                                                                                        found.pending = true;
                                                                                        found.failed = false;
                                                                                        found.error = None;
                                                                                    }
                                                                                    let base = base_for_vote.clone();
                                                                                    let realm = realm.clone();
                                                                                    let actor = actor.clone();
                                                                                    let poll_id = card_poll_id.clone();
                                                                                    let option_id = option_id.clone();
                                                                                    let message_id_for_status = card_message_id.clone();
                                                                                    let api_token = api_token.clone();
                                                                                    spawn(async move {
                                                                                        match crate::views::helpers::with_authed_api(
                                                                                            &base,
                                                                                            api_token,
                                                                                            |api| async move {
                                                                                                let op = crate::messaging::polls::build_poll_vote_op(
                                                                                                    &realm,
                                                                                                    &actor,
                                                                                                    &poll_id,
                                                                                                    &option_id,
                                                                                                )?;
                                                                                                api.submit_event_envelope(&op).await
                                                                                            },
                                                                                        )
                                                                                        .await
                                                                                        {
                                                                                            Ok(_) => {
                                                                                                if let Some(found) = messages.write().iter_mut().find(|candidate| candidate.id == message_id_for_status.as_str()) {
                                                                                                    found.pending = false;
                                                                                                    found.failed = false;
                                                                                                    found.error = None;
                                                                                                }
                                                                                                status_msg.set("Poll vote sent".to_owned());
                                                                                            }
                                                                                            Err(error) => {
                                                                                                let error_text = error.display();
                                                                                                if let Some(found) = messages.write().iter_mut().find(|candidate| candidate.id == message_id_for_status.as_str()) {
                                                                                                    found.pending = false;
                                                                                                    found.failed = true;
                                                                                                    found.error = Some(format!("Poll vote failed: {error_text}"));
                                                                                                }
                                                                                                status_msg.set(format!("Poll vote failed: {error_text}"));
                                                                                            }
                                                                                        }
                                                                                    });
                                                                                }
                                                                            },
                                                                            "{option_label}"
                                                                        }
                                                                    } else {
                                                                        span {
                                                                            class: "poll-option-label",
                                                                            "{option_label}"
                                                                        }
                                                                    }
                                                                    span {
                                                                        class: "poll-vote-count",
                                                                        "data-testid": "poll-vote-count",
                                                                        "{votes_for}"
                                                                    }
                                                                }
                                                            }
                                                        }
                                                    }
                                                    if !card.closed {
                                                        Button {
                                                            variant: ButtonVariant::Secondary,
                                                            r#type: "button",
                                                            class: "poll-close-button",
                                                            "data-testid": "poll-close-button",
                                                            onclick: {
                                                                let card_message_id = card.message_id.clone();
                                                                let card_poll_id = poll_id.clone();
                                                                let realm = msg.realm_id.clone();
                                                                let actor = account_did.clone();
                                                                let base_for_close = base_url.clone();
                                                                let api_token = token();
                                                                move |_| {
                                                                    if let Some(found) = poll_cards
                                                                        .write()
                                                                        .iter_mut()
                                                                        .find(|c| c.message_id == card_message_id)
                                                                    {
                                                                        found.close();
                                                                    }
                                                                    if let Some(found) = messages.write().iter_mut().find(|candidate| candidate.id == card_message_id) {
                                                                        found.pending = true;
                                                                        found.failed = false;
                                                                        found.error = None;
                                                                    }
                                                                    let base = base_for_close.clone();
                                                                    let realm = realm.clone();
                                                                    let actor = actor.clone();
                                                                    let poll_id = card_poll_id.clone();
                                                                    let message_id_for_status = card_message_id.clone();
                                                                    let api_token = api_token.clone();
                                                                    spawn(async move {
                                                                        match crate::views::helpers::with_authed_api(
                                                                            &base,
                                                                            api_token,
                                                                            |api| async move {
                                                                                let op = crate::messaging::polls::build_poll_close_op(
                                                                                    &realm,
                                                                                    &actor,
                                                                                    &poll_id,
                                                                                )?;
                                                                                api.submit_event_envelope(&op).await
                                                                            },
                                                                        )
                                                                        .await
                                                                        {
                                                                            Ok(_) => {
                                                                                if let Some(found) = messages.write().iter_mut().find(|candidate| candidate.id == message_id_for_status.as_str()) {
                                                                                    found.pending = false;
                                                                                    found.failed = false;
                                                                                    found.error = None;
                                                                                }
                                                                                status_msg.set("Poll closed".to_owned());
                                                                            }
                                                                            Err(error) => {
                                                                                let error_text = error.display();
                                                                                if let Some(found) = messages.write().iter_mut().find(|candidate| candidate.id == message_id_for_status.as_str()) {
                                                                                    found.pending = false;
                                                                                    found.failed = true;
                                                                                    found.error = Some(format!("Poll close failed: {error_text}"));
                                                                                }
                                                                                status_msg.set(format!("Poll close failed: {error_text}"));
                                                                            }
                                                                        }
                                                                    });
                                                                }
                                                            },
                                                            "Close poll"
                                                        }
                                                    }
                                                    div {
                                                        class: "poll-total",
                                                        "data-testid": "poll-total-votes",
                                                        "{total} votes"
                                                    }
                                                    if voted {
                                                        div {
                                                            class: "poll-results-summary",
                                                            "data-testid": "poll-results-summary",
                                                            "Thanks for voting."
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                        None => rsx! {},
                                    }
                                }
                                // G3.Y2 — discussion-promoted indicator.
                                // Lights up after a successful promote
                                // round-trip; the target is the private
                                // Circle-scoped discussion Flow.
                                {
                                    // After a successful promote, the
                                    // resulting private discussion Flow id lives in
                                    // `promoted_targets` keyed by the
                                    // source message id; we render an
                                    // anchor row so the parent timeline
                                    // shows the divergence point.
                                    let promoted_to = promoted_targets()
                                        .get(&msg.id)
                                        .cloned();
                                    match promoted_to {
                                        Some(discussion_flow_id) => {
                                            let discussion_flow_id_label = short_protocol_id(&discussion_flow_id);
                                            let discussion_flow_href = format!(
                                                "/chat/{}",
                                                selected_realm_id
                                            );
                                            rsx! {
                                                div {
                                                    class: "discussion-promoted-indicator",
                                                    "data-testid": "discussion-promoted-indicator",
                                                    "data-discussion-flow-id": "{discussion_flow_id}",
                                                    span { "Discussion moved to private Flow " }
                                                    a {
                                                        href: "{discussion_flow_href}",
                                                        title: "{discussion_flow_id}",
                                                        "{discussion_flow_id_label}"
                                                    }
                                                }
                                            }
                                        },
                                        None => rsx! {},
                                    }
                                }
                                if reaction_picker() == Some(msg.id.clone()) {
                                    div { class: "actions chat-chip-row", "data-testid": "chat-reaction-picker",
                                        for emoji in CHAT_EMOJI_GRID {
                                            Button {
                                                variant: ButtonVariant::Secondary,
                                                class: "emoji-button",
                                                onclick: {
                                                    let base = base_url.clone();
                                                    let realm = selected_realm_id.clone();
                                                    let actor = account_did.clone();
                                                    let device = device_id.clone();
                                                    let msg_id = msg.id.clone();
                                                    let emoji = emoji.to_string();
                                                    let channel_encrypted = selected_channel_security_encrypted;
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
                                                        // Build the op synchronously: in an encrypted channel this
                                                        // seals the emoji + derives the §2.9 routing tag (and persists
                                                        // the advanced MLS ratchet) before the network spawn.
                                                        let Some(op) = build_chat_reaction_add_operation(
                                                            state_store,
                                                            &realm,
                                                            &actor,
                                                            &device,
                                                            &msg_id,
                                                            &emoji,
                                                            channel_encrypted,
                                                        ) else {
                                                            status_msg.set(
                                                                "Reaction skipped: MLS state not ready for this encrypted channel".to_owned(),
                                                            );
                                                            reaction_picker.set(None);
                                                            return;
                                                        };
                                                        let base = base.clone();
                                                        let api_token = token();
                                                        let wait_for = active_sync_token(sync_cursor());
                                                        spawn(async move {
                                                            let _ = with_authed_api_with_sync(
                                                                &base,
                                                                api_token,
                                                                wait_for,
                                                                |api| async move {
                                                                    api.submit_event_envelope(&op).await
                                                                },
                                                            )
                                                            .await;
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
                                        Textarea {
                                            value: "{edit_draft}",
                                            oninput: move |event: FormEvent| edit_draft.set(event.value()),
                                        }
                                        div { class: "actions",
                                            Button {
                                                variant: ButtonVariant::Primary,
                                                "data-testid": "chat-save-edit-button",
                                                onclick: {
                                                    let base = base_url.clone();
                                                    let realm = selected_realm_id.clone();
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
                                                            found.failed = false;
                                                            found.error = None;
                                                        }
                                                        editing_message.set(None);
                                                        let base = base.clone();
                                                        let realm = realm.clone();
                                                        let actor = actor.clone();
                                                        let msg_id = msg_id.clone();
                                                        let api_token = token();
                                                        let wait_for = active_sync_token(sync_cursor());
                                                        spawn(async move {
                                                            match authed_api_with_sync(&base, api_token, wait_for) {
                                                                Ok(api) => {
                                                                    let op = chat_message_revise_operation(&realm, &actor, &msg_id, &content);
                                                                    match api.submit_event_envelope(&op).await {
                                                                        Ok(_resp) => {
                                                                            if let Some(found) = messages.write().iter_mut().find(|candidate| candidate.id == msg_id) {
                                                                                found.pending = false;
                                                                                found.failed = false;
                                                                                found.error = None;
                                                                            }
                                                                            status_msg.set("Message updated".to_owned());
                                                                        }
                                                                        Err(error) => {
                                                                            if let Some(found) = messages.write().iter_mut().find(|candidate| candidate.id == msg_id) {
                                                                                found.pending = false;
                                                                                found.failed = true;
                                                                                found.error = Some(format!("Message update failed: {error}"));
                                                                            }
                                                                            status_msg.set(format!("Message update failed: {error}"));
                                                                        }
                                                                    }
                                                                }
                                                                Err(error) => status_msg.set(format!("Invalid server URL: {error}")),
                                                            }
                                                        });
                                                    }
                                                },
                                                "Save"
                                            }
                                            Button {
                                                variant: ButtonVariant::Secondary,
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
                                            Button {
                                                variant: ButtonVariant::Primary,
                                                "data-testid": "chat-confirm-redact-button",
                                                onclick: {
                                                    let base = base_url.clone();
                                                    let realm = selected_realm_id.clone();
                                                    let actor = account_did.clone();
                                                    let msg_id = msg.id.clone();
                                                    move |_| {
                                                        if let Some(found) = messages.write().iter_mut().find(|candidate| candidate.id == msg_id) {
                                                            found.redacted = true;
                                                            found.body.clear();
                                                            found.pending = true;
                                                            found.failed = false;
                                                            found.error = None;
                                                        }
                                                        redact_confirm.set(None);
                                                        let base = base.clone();
                                                        let realm = realm.clone();
                                                        let actor = actor.clone();
                                                        let msg_id = msg_id.clone();
                                                        let api_token = token();
                                                        let wait_for = active_sync_token(sync_cursor());
                                                        spawn(async move {
                                                            match authed_api_with_sync(&base, api_token, wait_for) {
                                                                Ok(api) => {
                                                                    let op = chat_message_redact_operation(&realm, &actor, &msg_id, "user requested tombstone");
                                                                    match api.submit_event_envelope(&op).await {
                                                                        Ok(_resp) => {
                                                                            if let Some(found) = messages.write().iter_mut().find(|candidate| candidate.id == msg_id) {
                                                                                found.pending = false;
                                                                                found.failed = false;
                                                                                found.error = None;
                                                                            }
                                                                            status_msg.set("Message removed".to_owned());
                                                                        }
                                                                        Err(error) => {
                                                                            if let Some(found) = messages.write().iter_mut().find(|candidate| candidate.id == msg_id) {
                                                                                found.pending = false;
                                                                                found.failed = true;
                                                                                found.error = Some(format!("Message removal failed: {error}"));
                                                                            }
                                                                            status_msg.set(format!("Message removal failed: {error}"));
                                                                        }
                                                                    }
                                                                }
                                                                Err(error) => status_msg.set(format!("Invalid server URL: {error}")),
                                                            }
                                                        });
                                                    }
                                                },
                                                "Confirm"
                                            }
                                            Button {
                                                variant: ButtonVariant::Secondary,
                                                onclick: move |_| redact_confirm.set(None),
                                                "Cancel"
                                            }
                                        }
                                    }
                                }
                            }
                        }
                            }
                        }
                    }
                    if visible_channels_empty {
                        div { class: "empty-state discussion-empty-main", "data-testid": "discussion-main-empty",
                            div { class: "ico", UiIcon { name: "plus" } }
                            div { class: "t", {crate::i18n::tr("chat.empty.title")} }
                            div { class: "s", {crate::i18n::tr("chat.empty.description")} }
                            if !embedded {
                                div { class: "actions",
                                    Button {
                                        variant: ButtonVariant::Primary,
                                        "data-testid": "discussion-empty-create-button",
                                        onclick: move |_| create_dialog_open.set(true),
                                        {crate::i18n::tr("chat.empty.create_button")}
                                    }
                                }
                            }
                        }
                    } else if visible_message_count == 0 {
                        if discussion_feed_loading {
                            div {
                                class: "discussion-empty discussion-loading",
                                "data-testid": "discussion-loading",
                                span { class: "discussion-loading-spinner", "aria-hidden": "true" }
                                span { {crate::i18n::tr("chat.loading_messages")} }
                            }
                        } else {
                            div { class: "discussion-empty", {crate::i18n::tr("chat.empty_messages")} }
                        }
                    }
                }
            }

            if active_right_panel == Some(DiscussionSidePanel::Users) {
                aside { class: "discussion-panel discussion-details-panel", "data-testid": "discussion-users-panel",
                    div { class: "discussion-panel-head",
                        div { class: "discussion-title-row",
                            h2 { {crate::i18n::tr("chat.users_header")} }
                        }
                    }
                    // T7.5: lightweight tab bar so members and settings
                    // share a single right panel rather than competing
                    // for the same slot. Each tab maps to one
                    // `DiscussionSidePanel` value the existing buttons
                    // already toggle.
                    div { class: "discussion-right-tabs",
                        Button {
                            variant: ButtonVariant::Secondary,
                            r#type: "button",
                            class: "discussion-right-tab active",
                            "data-testid": "discussion-right-tab-members",
                            onclick: move |_| right_panel.set(Some(DiscussionSidePanel::Users)),
                            {crate::i18n::tr("chat.tabs.members")}
                        }
                        Button {
                            variant: ButtonVariant::Secondary,
                            r#type: "button",
                            class: "discussion-right-tab",
                            "data-testid": "discussion-right-tab-settings",
                            onclick: move |_| right_panel.set(Some(DiscussionSidePanel::Settings)),
                            {crate::i18n::tr("chat.tabs.settings")}
                        }
                    }
                    // G3.Y2 — presence list. One row per participant
                    // with `data-presence-state` derived from soland's
                    // live profile presence surface.
                    div { class: "discussion-detail-section",
                        div { class: "discussion-subhead", span { "Presence" } }
                        div {
                            class: "presence-list",
                            "data-testid": "presence-list",
                            for participant in &participants {
                                {
                                    let did_attr = participant.did.clone();
                                    let live_labels = presence_labels();
                                    let display = display_label_for_actor(
                                        &state_store.read(),
                                        &participants,
                                        &live_labels,
                                        &participant.did,
                                    );
                                    let state = presence_states
                                        .read()
                                        .get(&participant.did)
                                        .cloned()
                                        .unwrap_or_else(|| {
                                            if participant.is_self {
                                                "online".to_owned()
                                            } else {
                                                "offline".to_owned()
                                            }
                                        });
                                    let state_for_class = state.clone();
                                    rsx! {
                                        div {
                                            class: "presence-row presence-row-{state_for_class}",
                                            "data-testid": "presence-row",
                                            "data-actor-did": "{did_attr}",
                                            "data-presence-state": "{state}",
                                            span { class: "presence-dot presence-dot-{state}" }
                                            span { class: "presence-name", "{display}" }
                                            span { class: "muted mono", title: "{did_attr}", " {did_attr}" }
                                            span { class: "muted", " ({state})" }
                                        }
                                    }
                                }
                            }
                        }
                    }
                    div { class: "discussion-detail-section",
                        div { class: "discussion-subhead", span { "Space users" } }
                        for participant in participants {
                            // F-REMARK-FANOUT-1: prefer the actor-private
                            // ContactRemark.local_name (sync'd via
                            // ck.contacts.actor.<did> account_data) over
                            // the raw DID. The DID stays in the `title`
                            // attribute so it's still copy-pasteable for
                            // verification / debugging.
                            {
                                let participant_display = crate::views::helpers::display_name_for_did(
                                    &state_store.read(),
                                    &participant.did,
                                );
                                let participant_did_attr = participant.did.clone();
                                let participant_did_label = short_protocol_id(&participant_did_attr);
                                // T7.3: derive binding context host
                                // (e.g. `acme.example`) from the DID
                                // method/host so the row reads as
                                // `Alice @ acme.example` rather than
                                // dropping the raw service DID into the
                                // visible list. The full DID is still
                                // available in the title attribute and
                                // an expandable details row.
                                let binding_host = participant
                                    .did
                                    .strip_prefix("did:web:")
                                    .map(|rest| rest.split(':').next().unwrap_or(rest).to_owned());
                                rsx! {
                            div {
                                class: if participant.is_self { "contact-row participant-row self" } else { "contact-row participant-row" },
                                "data-testid": "discussion-user-row",
                                span { class: "participant-avatar", UiIcon { name: "user" } }
                                div { class: "participant-main",
                                    strong {
                                        class: "mono participant-did",
                                        title: "{participant_did_attr}",
                                        "{participant_display}"
                                        if let Some(host) = binding_host.as_ref() {
                                            span { class: "binding-context",
                                                "data-testid": "binding-context",
                                                {crate::i18n::tr("chat.binding_context.separator")}
                                                span { class: "binding-context-host", "{host}" }
                                            }
                                        }
                                    }
                                    div { class: "participant-badges",
                                        if participant.is_self {
                                            span { class: "badge participant-badge self", {crate::i18n::tr("chat.you_badge")} }
                                        }
                                        if participant.is_agent {
                                            span {
                                                class: "badge member-badge member-badge-agent",
                                                "data-testid": "member-badge-agent",
                                                title: "Automated member (bot)",
                                                "\u{1f916} "
                                                {crate::i18n::tr("member.badge.agent")}
                                            }
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
                                    details { class: "binding-context-details",
                                        summary { class: "muted", {crate::i18n::tr("chat.binding_context.details")} }
                                        div { class: "mono muted", title: "{participant_did_attr}",
                                            "{participant_did_label}"
                                        }
                                    }
                                }
                            }
                                }
                            }
                        }
                    }
                }
            }

            if active_right_panel == Some(DiscussionSidePanel::Settings) {
                {
                // F-CHAT-DEAD-UI-1: three toggles in the discussion-settings
                // panel used to be pure decoration (no onchange, hard-coded
                // `checked: true`). The first two are now wired to the
                // same actor-private account_data that /settings already
                // edits, so a change here mirrors immediately into the
                // global view. "Shared history" is a Realm-scoped policy
                // event (`ck.realm.history_visibility`) — it's not a
                // client-side per-discussion toggle, so the third row
                // shows an explanatory hint instead of pretending to be
                // a checkbox.
                let realm_id_for_mute = selected_realm_id.clone();
                let flow_id_for_rr = selected_channel_value.clone();
                let muted_realms_now = state_store.read().muted_realms();
                let realm_is_muted = muted_realms_now.contains(&realm_id_for_mute);
                let rr_default_send = state_store.read().read_receipt_default_send();
                let rr_flow_override =
                    state_store.read().read_receipt_flow_override(&flow_id_for_rr);
                let rr_active = rr_flow_override.unwrap_or(rr_default_send);
                rsx! {
                aside { class: "discussion-panel discussion-details-panel", "data-testid": "discussion-settings-panel",
                    div { class: "discussion-panel-head",
                        div { class: "discussion-title-row",
                            h2 { {crate::i18n::tr("chat.settings_header")} }
                        }
                    }
                    // T7.5: same tab bar as the users panel so the user
                    // can switch tabs in-place without re-clicking the
                    // topbar icons.
                    div { class: "discussion-right-tabs",
                        Button {
                            variant: ButtonVariant::Secondary,
                            r#type: "button",
                            class: "discussion-right-tab",
                            "data-testid": "discussion-right-tab-members",
                            onclick: move |_| right_panel.set(Some(DiscussionSidePanel::Users)),
                            {crate::i18n::tr("chat.tabs.members")}
                        }
                        Button {
                            variant: ButtonVariant::Secondary,
                            r#type: "button",
                            class: "discussion-right-tab active",
                            "data-testid": "discussion-right-tab-settings",
                            onclick: move |_| right_panel.set(Some(DiscussionSidePanel::Settings)),
                            {crate::i18n::tr("chat.tabs.settings")}
                        }
                    }
                    div { class: "discussion-detail-section",
                        div { class: "discussion-subhead", span { "Settings" } }
                        label { class: "settings-row",
                            span { {crate::i18n::tr("chat.settings.mute_notifications")} }
                            Checkbox {
                                "data-testid": "discussion-settings-mute",
                                checked: if realm_is_muted { CheckboxState::Checked } else { CheckboxState::Unchecked },
                                on_checked_change: {
                                    let realm_id = realm_id_for_mute.clone();
                                    move |state: CheckboxState| {
                                        let new_muted = bool::from(state);
                                        state_store
                                            .write()
                                            .set_realm_muted(realm_id.clone(), new_muted);
                                    }
                                },
                            }
                        }
                        label { class: "settings-row",
                            span { {crate::i18n::tr("chat.settings.read_receipts")} }
                            Checkbox {
                                "data-testid": "discussion-settings-read-receipts",
                                checked: if rr_active { CheckboxState::Checked } else { CheckboxState::Unchecked },
                                on_checked_change: {
                                    let flow_id = flow_id_for_rr.clone();
                                    move |state: CheckboxState| {
                                        let new_value = bool::from(state);
                                        state_store
                                            .write()
                                            .set_read_receipt_flow_override(
                                                flow_id.clone(),
                                                Some(new_value),
                                            );
                                    }
                                },
                            }
                        }
                        div { class: "settings-row settings-row-readonly",
                            "data-testid": "discussion-settings-shared-history-note",
                            span { {crate::i18n::tr("chat.settings.shared_history")} }
                            span { class: "muted",
                                {crate::i18n::tr("chat.settings.shared_history_hint")}
                            }
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
                }
            }

            // G3.Y2 — discussion promote confirmation modal. Renders
            // a single input for the child Board Space title + a confirm
            // button that fires a Realm-scoped ck.space.create.
            if crate::messaging::discussion_promote::discussion_promote_enabled()
                && promote_discussion_draft.read().is_open()
            {
                div { class: "discussion-modal-backdrop",
                    "data-testid": "discussion-promote-modal",
                    div { class: "discussion-modal",
                        div { class: "discussion-modal-head",
                            h2 { "Promote discussion to its own Space" }
                            Button {
                                variant: ButtonVariant::Secondary,
                                r#type: "button",
                                onclick: move |_| promote_discussion_draft.write().close(),
                                "Cancel"
                            }
                        }
                        label { class: "form-row",
                            span { "Child Space title" }
                            input {
                                r#type: "text",
                                "data-testid": "discussion-promote-confirm-input",
                                value: "{promote_discussion_draft.read().title}",
                                oninput: move |evt| {
                                    promote_discussion_draft.write().title = evt.value();
                                },
                            }
                        }
                        div { class: "actions",
                            Button {
                                variant: ButtonVariant::Primary,
                                "data-testid": "discussion-promote-confirm-button",
                                disabled: !promote_discussion_draft.read().is_submittable(),
                                onclick: {
                                    let base = base_url.clone();
                                    let realm = selected_realm_id.clone();
                                    let actor = account_did.clone();
                                    move |_| {
                                        let draft_snapshot = promote_discussion_draft.read().clone();
                                        let Some(source_id) = draft_snapshot.source_id.clone() else {
                                            return;
                                        };
                                        let title = draft_snapshot.title.trim().to_owned();
                                        let ids = crate::messaging::discussion_promote::PromoteIds::fresh();
                                        // Optimistic UI: anchor the
                                        // promoted indicator before the
                                        // server round-trip completes.
                                        promoted_targets
                                            .write()
                                            .insert(source_id.clone(), ids.discussion_flow_id.clone());
                                        promote_discussion_draft.write().close();

                                        let base = base.clone();
                                        let realm = realm.clone();
                                        let actor = actor.clone();
                                        let api_token = token();
                                        let ids_clone = ids.clone();
                                        let source_id_for_rollback = source_id.clone();
                                        spawn(async move {
                                            // Experimental discussion promote is
                                            // hidden from the default local UI
                                            // until soland's reducer is enabled.
                                            // YOU-02-007: stop at the first
                                            // failed op and roll back the
                                            // optimistic promoted indicator so
                                            // a half-applied promote is not
                                            // presented as success.
                                            let outcome = crate::views::helpers::with_authed_api(
                                                &base,
                                                api_token,
                                                |api| async move {
                                                    let ops = crate::messaging::discussion_promote::build_promote_ops(
                                                        &realm,
                                                        &actor,
                                                        &source_id,
                                                        &ids_clone,
                                                        &title,
                                                    )?;
                                                    for op in ops {
                                                        api.submit_event_envelope(&op).await?;
                                                    }
                                                    Ok(())
                                                },
                                            ).await;
                                            if let Err(err) = outcome {
                                                tracing::warn!(
                                                    "discussion promote failed: {}",
                                                    err.display()
                                                );
                                                promoted_targets
                                                    .write()
                                                    .remove(&source_id_for_rollback);
                                                status_msg.set(format!(
                                                    "Discussion promote failed: {}",
                                                    err.display()
                                                ));
                                            }
                                        });
                                    }
                                },
                                "Create private discussion"
                            }
                        }
                    }
                }
            }

            // G3.Y2 — read-receipt marker bar. A horizontal divider
            // anchored at the highest event id we've sent a
            // `ck.read_cursor.advance` for; renders only when we have one. The
            // bar appears below the message list so users can see the
            // "everyone read up to here" anchor without scrolling
            // around. The marker itself is actor-private — see
            // discovery/read-receipts.md §3.1.
            if !embedded && !latest_read_cursor().is_empty() {
                {
                    let latest_read_cursor_value = latest_read_cursor();
                    let latest_read_cursor_label = short_protocol_id(&latest_read_cursor_value);
                    rsx! {
                        div {
                            class: "read-receipt-marker-bar",
                            "data-testid": "read-receipt-marker-bar",
                            "data-up-to-event-id": "{latest_read_cursor_value}",
                            span { "Read up to " }
                            span { class: "mono", title: "{latest_read_cursor_value}", "{latest_read_cursor_label}" }
                        }
                    }
                }
            }

            if !visible_channels_empty {
            div { class: "{composer_class}", "data-testid": "chat-composer",
                // CKP-0007 P3B.2.3 — Circle composer banner. Rendered
                // at the top of the composer surface when the active
                // Flow carries a `scope_circle_id`. The component is
                // pure: `CircleScope::Realm` renders nothing, so the
                // surface stays quiet during normal Realm-scoped
                // writes.
                {
                    let scope = selected_channel_info
                        .as_ref()
                        .and_then(|channel| channel.scope_circle.clone())
                        .map(|circle| crate::circle::CircleScope::Circle {
                            circle_id: circle.circle_id,
                            title: circle.title,
                            member_count: circle.member_count,
                        })
                        .unwrap_or(crate::circle::CircleScope::Realm);
                    rsx! {
                        crate::components::CircleComposerBanner { scope }
                    }
                }
                if let Some(reply_id) = reply_to_message() {
                    div { class: "chat-reply-quote-banner", "data-testid": "chat-reply-banner",
                        if let Some((quoted_name, quoted_body)) = chat_reply_quote_preview(
                            messages_for_composer_lookup,
                            &reply_id,
                            &account_did,
                            &account_display_label,
                            &participants_for_messages,
                        ) {
                            div { class: "chat-reply-quote",
                                span { class: "chat-reply-quote-name", "{quoted_name}" }
                                div { class: "chat-reply-quote-body", "{quoted_body}" }
                            }
                        } else {
                            div { class: "chat-reply-quote chat-reply-quote-missing",
                                "Replying to a message"
                            }
                        }
                        Button {
                            variant: ButtonVariant::Secondary,
                            onclick: move |_| reply_to_message.set(None),
                            "Cancel"
                        }
                    }
                }
                // A6.2: drag-drop attachment zone wrapping the textarea.
                // Dropping a file uploads the bytes via
                // `upload_blob_bytes`, then appends `[Attachment: {ref}]`
                // to the draft so the existing send pipeline picks it
                // up as message body. `ondragover` is required to
                // prevent the browser's default open-the-file behaviour.
                div {
                    class: if compose_dragover() {
                        "compose-drop-zone is-dragover"
                    } else {
                        "compose-drop-zone"
                    },
                    "data-testid": "compose-drop-zone",
                    ondragover: move |evt| {
                        evt.prevent_default();
                        if !compose_dragover() { compose_dragover.set(true); }
                    },
                    ondragleave: move |_| compose_dragover.set(false),
                    ondrop: {
                        let base = base_url.clone();
                        let realm = selected_realm_id.clone();
                        move |evt| {
                            evt.prevent_default();
                            compose_dragover.set(false);
                            let files = evt.files();
                            if files.is_empty() {
                                // Some platforms (notably the desktop
                                // web embedder) deliver drops without
                                // file payloads — surface that rather
                                // than silently no-op.
                                compose_upload_status.set(
                                    crate::i18n::tr("compose.upload_error"),
                                );
                                return;
                            }
                            let api_token = token();
                            let base = base.clone();
                            let realm = realm.clone();
                            compose_upload_status.set(
                                crate::i18n::tr("compose.upload_progress"),
                            );
                            spawn(async move {
                                let api = match crate::views::helpers::authed_api_with_sync(
                                    &base,
                                    api_token,
                                    None,
                                ) {
                                    Ok(api) => api,
                                    Err(err) => {
                                        compose_upload_status.set(format!(
                                            "{}: {err}",
                                            crate::i18n::tr("compose.upload_error"),
                                        ));
                                        return;
                                    }
                                };
                                let mut ok_count = 0usize;
                                let mut last_error: Option<String> = None;
                                for file in files {
                                    let filename = file.name();
                                    let content_type = file
                                        .content_type()
                                        .unwrap_or_else(|| "application/octet-stream".to_owned());
                                    let bytes = match file.read_bytes().await {
                                        Ok(b) => b.to_vec(),
                                        Err(err) => {
                                            last_error = Some(format!("{err}"));
                                            continue;
                                        }
                                    };
                                    match api
                                        .upload_blob_bytes_scoped(
                                            bytes,
                                            &content_type,
                                            Some(&realm),
                                            Some(&filename),
                                        )
                                        .await
                                    {
                                        Ok(resp) => {
                                            let current = chat_draft();
                                            let needs_space = !current.is_empty()
                                                && !current.ends_with(' ')
                                                && !current.ends_with('\n');
                                            let attachment = format!(
                                                "{}[Attachment: {}]",
                                                if needs_space { " " } else { "" },
                                                resp.blob_ref
                                            );
                                            chat_draft.set(format!("{current}{attachment}"));
                                            ok_count += 1;
                                        }
                                        Err(err) => {
                                            last_error = Some(err.to_string());
                                        }
                                    }
                                }
                                if let Some(err) = last_error {
                                    compose_upload_status.set(format!(
                                        "{}: {err}",
                                        crate::i18n::tr("compose.upload_error"),
                                    ));
                                } else if ok_count > 0 {
                                    compose_upload_status.set(format!(
                                        "{ok_count} attachment(s) uploaded"
                                    ));
                                } else {
                                    compose_upload_status.set(
                                        crate::i18n::tr("compose.upload_error"),
                                    );
                                }
                            });
                        }
                    },
                    Textarea {
                        "data-testid": "chat-input",
                        value: "{chat_draft}",
                        placeholder: "Message this discussion. Use @alice:example.com to mention a member or #task-123 to link a card.",
                        oninput: {
                            let base = base_url.clone();
                            let realm = selected_realm_id.clone();
                            let actor = account_did.clone();
                            move |event: FormEvent| {
                                let value = event.value();
                                chat_draft.set(value.clone());
                                // G3.Y2 — auto-open the mention picker
                                // when the user types an `@`. The
                                // composer reads `mention_picker_state.open`
                                // to know whether to render the
                                // `mention-picker` element.
                                if value.ends_with('@') {
                                    mention_picker_state.write().open();
                                }
                                // G3.Y2 — typing signal, fire-and-forget so the
                                // composer never blocks; failures fall back
                                // silently per the spec. Perf (P0): the throttle
                                // emits `typing=true` on the leading edge (≤ once
                                // / 3s) and `typing=false` after the user stops,
                                // instead of one POST per keystroke. The
                                // receiving side TTL-expires stale entries.
                                let base = base.clone();
                                let realm = realm.clone();
                                let actor = actor.clone();
                                typing_throttle.on_keystroke(move |is_typing| {
                                    let base = base.clone();
                                    let realm = realm.clone();
                                    let actor = actor.clone();
                                    let api_token = token();
                                    spawn(async move {
                                        let _ = crate::views::helpers::with_authed_api(
                                            &base,
                                            api_token,
                                            |api| async move {
                                                api.send_typing(&realm, &actor, None, is_typing).await
                                            },
                                        ).await;
                                    });
                                });
                            }
                        },
                    }
                    // G3.Y2 — mention chip row + picker. Sits below
                    // the textarea so picker rows can overlay the
                    // message list without changing the textarea's
                    // size. The trigger button is a dev-mode handle
                    // for cotest — production users open the picker
                    // by typing `@`, but having the explicit button
                    // gives the tests a stable click target.
                    div { class: "mention-chip-row",
                        Button {
                            variant: ButtonVariant::Secondary,
                            r#type: "button",
                            class: "composer-tool-button",
                            "data-testid": "mention-trigger-button",
                            title: "Mention member",
                            "aria-label": "Mention member",
                            onclick: move |_| {
                                let mut state = mention_picker_state.write();
                                if state.open {
                                    state.close();
                                } else {
                                    state.open();
                                }
                            },
                            UiIcon { name: "at-sign" }
                        }
                        Button {
                            variant: ButtonVariant::Secondary,
                            r#type: "button",
                            class: "composer-tool-button",
                            "data-testid": "attachment-menu-button",
                            title: "Add attachment",
                            "aria-label": "Add attachment",
                            onclick: move |_| {
                                let current = attachment_menu_open();
                                attachment_menu_open.set(!current);
                            },
                            UiIcon { name: "plus" }
                        }
                        if crate::messaging::polls::polls_enabled() {
                            Button {
                                variant: ButtonVariant::Secondary,
                                r#type: "button",
                                class: "composer-tool-button",
                                "data-testid": "open-poll-composer-button",
                                title: "Create poll",
                                "aria-label": "Create poll",
                                onclick: move |_| {
                                    attachment_menu_open.set(false);
                                    poll_draft.set(Some(
                                        crate::messaging::polls::PollDraft::new(),
                                    ));
                                },
                                "Poll"
                            }
                        }
                        if attachment_menu_open() {
                            div { class: "attachment-menu",
                                if crate::messaging::polls::polls_enabled() {
                                    Button {
                                        variant: ButtonVariant::Secondary,
                                        r#type: "button",
                                        class: "attachment-menu-item",
                                        "data-testid": "attachment-menu-poll",
                                        onclick: move |_| {
                                            attachment_menu_open.set(false);
                                            poll_draft.set(Some(
                                                crate::messaging::polls::PollDraft::new(),
                                            ));
                                        },
                                        "Create poll"
                                    }
                                }
                            }
                        }
                        for chip in mention_picker_state.read().inserted.clone() {
                            div {
                                class: "mention-chip",
                                "data-testid": "mention-chip",
                                "data-mention-did": "{chip.did}",
                                span { "@{chip.display_name}" }
                                Button {
                                    variant: ButtonVariant::Secondary,
                                    r#type: "button",
                                    onclick: {
                                        let did = chip.did.clone();
                                        move |_| mention_picker_state.write().remove(&did)
                                    },
                                    "\u{00d7}"
                                }
                            }
                        }
                    }
                    if mention_picker_state.read().open {
                        div { class: "mention-picker",
                            "data-testid": "mention-picker",
                            div { class: "mention-picker-head",
                                Input {
                                    r#type: "text",
                                    class: "mention-picker-query",
                                    placeholder: "Search members",
                                    value: "{mention_picker_state.read().query}",
                                    oninput: move |event: FormEvent| {
                                        mention_picker_state.write().set_query(event.value());
                                    },
                                }
                                Button {
                                    variant: ButtonVariant::Secondary,
                                    r#type: "button",
                                    "data-testid": "mention-picker-close-button",
                                    onclick: move |_| mention_picker_state.write().close(),
                                    "Close"
                                }
                            }
                            {
                                let candidates: Vec<crate::messaging::mentions::MentionCandidate> =
                                    participants_for_messages
                                        .iter()
                                        .filter_map(|p| {
                                            mention_label_for_participant(p).map(|display_name| {
                                                crate::messaging::mentions::MentionCandidate {
                                                    did: p.did.clone(),
                                                    display_name,
                                                }
                                            })
                                        })
                                        .collect();
                                // `filter` borrows from `candidates`, not from the
                                // picker state, so we run it under the read guard and
                                // only clone the matched candidates we actually render
                                // instead of cloning the whole picker state first.
                                let matches: Vec<crate::messaging::mentions::MentionCandidate> =
                                    mention_picker_state
                                        .read()
                                        .filter(&candidates)
                                        .into_iter()
                                        .cloned()
                                        .collect();
                                rsx! {
                                    div { class: "mention-suggestions",
                                        if matches.is_empty() {
                                            div { class: "muted", "No matches" }
                                        } else {
                                            for candidate in matches {
                                                {
                                                    rsx! {
                                                        Button {
                                                            variant: ButtonVariant::Secondary,
                                                            key: "{candidate.did}",
                                                            r#type: "button",
                                                            class: "mention-suggestion",
                                                            "data-testid": "mention-suggestion",
                                                            "data-mention-did": "{candidate.did}",
                                                            title: "@{candidate.display_name}",
                                                            onclick: {
                                                                let candidate = candidate.clone();
                                                                move |_| {
                                                                    let inserted = mention_picker_state
                                                                        .write()
                                                                        .insert(candidate.clone());
                                                                    if inserted {
                                                                        // Replace the trailing `@`
                                                                        // (if any) with the chip
                                                                        // mention so the draft text
                                                                        // and the chip list stay in
                                                                        // sync.
                                                                        let current = chat_draft();
                                                                        let trimmed = current
                                                                            .strip_suffix('@')
                                                                            .unwrap_or(&current)
                                                                            .to_owned();
                                                                        let needs_space = !trimmed.is_empty()
                                                                            && !trimmed.ends_with(' ');
                                                                        chat_draft.set(format!(
                                                                            "{trimmed}{}@{} ",
                                                                            if needs_space { " " } else { "" },
                                                                            candidate.display_name,
                                                                        ));
                                                                    }
                                                                    mention_picker_state.write().close();
                                                                }
                                                            },
                                                            span { class: "mention-suggestion-name",
                                                                "@{candidate.display_name}"
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                    if compose_dragover() {
                        div {
                            class: "compose-drop-zone-hint",
                            "data-testid": "compose-drop-hint",
                            {crate::i18n::tr("compose.drop_zone.hint")}
                        }
                    }
                }
                if !compose_upload_status().is_empty() {
                    div {
                        class: "compose-upload-progress",
                        "data-testid": "compose-upload-progress",
                        "{compose_upload_status}"
                    }
                }
                if crate::messaging::polls::polls_enabled() {
                if let Some(draft) = poll_draft.read().clone() {
                    div { class: "poll-composer",
                        "data-testid": "poll-composer",
                        Input {
                            r#type: "text",
                            "data-testid": "poll-question-input",
                            placeholder: "Question",
                            value: "{draft.question}",
                            oninput: move |event: FormEvent| {
                                if let Some(current) = poll_draft.write().as_mut() {
                                    current.set_question(event.value());
                                }
                            },
                        }
                        for (idx, option) in draft.options.iter().enumerate() {
                            Input {
                                r#type: "text",
                                "data-testid": "poll-option-input",
                                "data-option-index": "{idx as i64}",
                                placeholder: "Option {idx + 1}",
                                value: "{option}",
                                oninput: move |event: FormEvent| {
                                    if let Some(current) = poll_draft.write().as_mut() {
                                        current.set_option(idx, event.value());
                                    }
                                },
                            }
                        }
                        div { class: "actions",
                            Button {
                                variant: ButtonVariant::Secondary,
                                r#type: "button",
                                "data-testid": "poll-add-option-button",
                                onclick: move |_| {
                                    if let Some(current) = poll_draft.write().as_mut() {
                                        current.add_option();
                                    }
                                },
                                "Add option"
                            }
                            Button {
                                variant: ButtonVariant::Primary,
                                r#type: "button",
                                "data-testid": "poll-create-button",
                                disabled: !draft.is_sendable(),
                                onclick: {
                                    let base = base_url.clone();
                                    let realm = selected_realm_id.clone();
                                    let actor = account_did.clone();
                                    let selected_flow = selected_channel_value.clone();
                                    move |_| {
                                        let Some(draft_snapshot) = poll_draft.read().clone() else {
                                            return;
                                        };
                                        if !draft_snapshot.is_sendable() {
                                            return;
                                        }
                                        let poll_id = crate::messaging::polls::new_poll_id();
                                        let card = crate::messaging::polls::PollCard::from_draft(
                                            poll_id.clone(),
                                            &draft_snapshot,
                                        );
                                        // Optimistic UI: surface the
                                        // poll card immediately, push
                                        // a synthetic ChatMessage so
                                        // the timeline anchors it.
                                        poll_cards.write().push(card.clone());
                                        messages.write().push(ChatMessage {
                                            realm_id: realm.clone(),
                                            id: poll_id.clone(),
                                            sender: actor.clone(),
                                            body: format!("[poll] {}", draft_snapshot.question),
                                            timestamp: chrono::Utc::now().format("%H:%M").to_string(),
                                            flow_id: selected_flow.clone(),
                                            reply_to: None,
                                            reactions: Vec::new(),
                                            redacted: false,
                                            edited: false,
                                            revisions: Vec::new(),
                                            pending: true,
                                            failed: false,
                                            error: None,
                                            mentions: Vec::new(),
                                            crypto_state: MessageCryptoState::Plaintext,
                                        });
                                        poll_draft.set(None);

                                        let base = base.clone();
                                        let realm = realm.clone();
                                        let actor = actor.clone();
                                        let flow_id = selected_flow.clone();
                                        let api_token = token();
                                        let draft_for_op = draft_snapshot.clone();
                                        let poll_id_for_op = poll_id.clone();
                                        let poll_id_for_status = poll_id.clone();
                                        spawn(async move {
                                            match crate::views::helpers::with_authed_api(
                                                &base,
                                                api_token,
                                                |api| async move {
                                                    let op = crate::messaging::polls::build_poll_create_op(
                                                        &realm,
                                                        &actor,
                                                        &flow_id,
                                                        &poll_id_for_op,
                                                        &draft_for_op,
                                                    )?;
                                                    api.submit_event_envelope(&op).await
                                                },
                                            )
                                            .await
                                            {
                                                Ok(_) => {
                                                    if let Some(found) = messages.write().iter_mut().find(|candidate| candidate.id == poll_id_for_status) {
                                                        found.pending = false;
                                                        found.failed = false;
                                                        found.error = None;
                                                    }
                                                    status_msg.set("Poll sent".to_owned());
                                                }
                                                Err(error) => {
                                                    let error_text = error.display();
                                                    if let Some(found) = messages.write().iter_mut().find(|candidate| candidate.id == poll_id_for_status) {
                                                        found.pending = false;
                                                        found.failed = true;
                                                        found.error = Some(format!("Poll send failed: {error_text}"));
                                                    }
                                                    status_msg.set(format!("Poll send failed: {error_text}"));
                                                }
                                            }
                                        });
                                    }
                                },
                                "Send poll"
                            }
                            // Cotest also references `send-poll-button`
                            // — wire it to the same handler so both
                            // testids resolve.
                            Button {
                                variant: ButtonVariant::Secondary,
                                r#type: "button",
                                "data-testid": "send-poll-button",
                                onclick: {
                                    let base = base_url.clone();
                                    let realm = selected_realm_id.clone();
                                    let actor = account_did.clone();
                                    let selected_flow = selected_channel_value.clone();
                                    move |_| {
                                        let Some(draft_snapshot) = poll_draft.read().clone() else {
                                            return;
                                        };
                                        if !draft_snapshot.is_sendable() {
                                            return;
                                        }
                                        let poll_id = crate::messaging::polls::new_poll_id();
                                        let card = crate::messaging::polls::PollCard::from_draft(
                                            poll_id.clone(),
                                            &draft_snapshot,
                                        );
                                        poll_cards.write().push(card.clone());
                                        messages.write().push(ChatMessage {
                                            realm_id: realm.clone(),
                                            id: poll_id.clone(),
                                            sender: actor.clone(),
                                            body: format!("[poll] {}", draft_snapshot.question),
                                            timestamp: chrono::Utc::now().format("%H:%M").to_string(),
                                            flow_id: selected_flow.clone(),
                                            reply_to: None,
                                            reactions: Vec::new(),
                                            redacted: false,
                                            edited: false,
                                            revisions: Vec::new(),
                                            pending: true,
                                            failed: false,
                                            error: None,
                                            mentions: Vec::new(),
                                            crypto_state: MessageCryptoState::Plaintext,
                                        });
                                        poll_draft.set(None);

                                        let base = base.clone();
                                        let realm = realm.clone();
                                        let actor = actor.clone();
                                        let flow_id = selected_flow.clone();
                                        let api_token = token();
                                        let draft_for_op = draft_snapshot.clone();
                                        let poll_id_for_op = poll_id.clone();
                                        let poll_id_for_status = poll_id.clone();
                                        spawn(async move {
                                            match crate::views::helpers::with_authed_api(
                                                &base,
                                                api_token,
                                                |api| async move {
                                                    let op = crate::messaging::polls::build_poll_create_op(
                                                        &realm,
                                                        &actor,
                                                        &flow_id,
                                                        &poll_id_for_op,
                                                        &draft_for_op,
                                                    )?;
                                                    api.submit_event_envelope(&op).await
                                                },
                                            )
                                            .await
                                            {
                                                Ok(_) => {
                                                    if let Some(found) = messages.write().iter_mut().find(|candidate| candidate.id == poll_id_for_status) {
                                                        found.pending = false;
                                                        found.failed = false;
                                                        found.error = None;
                                                    }
                                                    status_msg.set("Poll sent".to_owned());
                                                }
                                                Err(error) => {
                                                    let error_text = error.display();
                                                    if let Some(found) = messages.write().iter_mut().find(|candidate| candidate.id == poll_id_for_status) {
                                                        found.pending = false;
                                                        found.failed = true;
                                                        found.error = Some(format!("Poll send failed: {error_text}"));
                                                    }
                                                    status_msg.set(format!("Poll send failed: {error_text}"));
                                                }
                                            }
                                        });
                                    }
                                },
                                "Send"
                            }
                            Button {
                                variant: ButtonVariant::Secondary,
                                r#type: "button",
                                onclick: move |_| poll_draft.set(None),
                                "Cancel"
                            }
                        }
                    }
                }
                }
                div { class: "actions",
                    if !selected_channel_security_encrypted {
                    Button {
                        variant: ButtonVariant::Primary,
                        "data-testid": "send-chat-button",
                        onclick: {
                            let base = base_url.clone();
                            let service_did = plaintext_service_did.clone();
                            let realm = selected_realm_id.clone();
                            let actor = account_did.clone();
                            move |_| {
                                let body = chat_draft().trim().to_owned();
                                if body.is_empty() {
                                    return;
                                }
                                let mut mentions = parse_structured_mentions(&body);
                                // G3.Y2 — merge mention picker chips
                                // into the structured mentions list so
                                // the @mention picker counts as a
                                // first-class source (not just typed
                                // `@name` text).
                                {
                                    let picker = mention_picker_state.read().inserted.clone();
                                    for chip in picker {
                                        if !mentions.iter().any(|m| m.target == chip.did) {
                                            let parsed_handle = crate::identity_handle::parse_user_handle(
                                                &chip.display_name,
                                            );
                                            // R3.2: `target` is the authoritative
                                            // subject_id (principal DID). The handle /
                                            // display strings are compose-time audit
                                            // metadata only.
                                            mentions.push(crate::views::helpers::StructuredMention {
                                                kind: "actor".to_owned(),
                                                target: chip.did.clone(),
                                                token: format!("@{}", chip.display_name),
                                                display_name_at_time: chip.display_name.clone(),
                                                handle_at_time: parsed_handle
                                                    .map(|h| h.handle)
                                                    .unwrap_or_default(),
                                                mention_text_original: format!(
                                                    "@{}",
                                                    chip.display_name
                                                ),
                                                resolved_at: String::new(),
                                            });
                                        }
                                    }
                                }
                                let local_id = new_chat_message_id();
                                let channel = channels()
                                    .iter()
                                    .find(|candidate| candidate.flow_id == selected_channel())
                                    .cloned();
                                let Some(channel) = channel else {
                                    status_msg.set("select a discussion first".to_owned());
                                    return;
                                };
                                messages.write().push(ChatMessage {
                                    realm_id: realm.clone(),
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
                                    // Local-only sends start plaintext;
                                    // the Send Secure flow may upgrade
                                    // them via a separate `messages.write()`
                                    // patch after `encrypt_payload`.
                                    crypto_state: MessageCryptoState::Plaintext,
                                });

                                let base = base.clone();
                                let service_did = service_did.clone();
                                let realm = realm.clone();
                                let api_token = token();
                                let actor = actor.clone();
                                let flow_id = channel.flow_id.clone();
                                let channel_kind = channel.kind.clone();
                                let message_id = local_id.clone();
                                let reply_to = reply_to_message();
                                let mut op = match chat_message_create_operation(
                                    &realm,
                                    &actor,
                                    &flow_id,
                                    &channel_kind,
                                    &message_id,
                                    &body,
                                    &mentions,
                                    reply_to.as_deref(),
                                ) {
                                    Ok(op) => op,
                                    Err(error) => {
                                        if let Some(found) = messages
                                            .write()
                                            .iter_mut()
                                            .find(|candidate| candidate.id == local_id)
                                        {
                                            found.pending = false;
                                            found.failed = true;
                                            found.error = Some(format!("send failed: {error:#}"));
                                        }
                                        status_msg.set(format!("send failed: {error:#}"));
                                        return;
                                    }
                                };
                                // G3.Y2 — mention sidecar hashes.
                                // Decorates the outgoing payload with
                                // `mention_sidecar_hash: [hex, ...]`
                                // so the server can route mention
                                // notifications without seeing the
                                // mentioned actor's DID in plaintext.
                                // See `discovery/push-notifications.md
                                // §4.5`. We use the Space id as the
                                // mention salt until soland exposes a
                                // dedicated salt projection.
                                if !mentions.is_empty() {
                                    let mention_dids: Vec<String> = mentions
                                        .iter()
                                        .filter(|m| m.kind == "actor")
                                        .map(|m| m.target.clone())
                                        .collect();
                                    let hashes =
                                        crate::messaging::mentions::mention_sidecar_hashes(
                                            &realm,
                                            &mention_dids,
                                        );
                                    if let Some(content) = op
                                        .payload
                                        .get_mut("content")
                                        .and_then(Value::as_object_mut)
                                    {
                                        content.insert(
                                            "mention_sidecar_hash".to_owned(),
                                            serde_json::Value::Array(
                                                hashes
                                                    .into_iter()
                                                    .map(serde_json::Value::String)
                                                    .collect(),
                                            ),
                                        );
                                    }
                                }
                                // Clear the picker chip list now that
                                // we've folded the mentions into the
                                // outgoing op.
                                mention_picker_state.write().clear();
                                let mention_values_for_store = mentions_to_json(&mentions);
                                let realm_for_record = realm.clone();
                                let actor_for_store = actor.clone();
                                let body_for_store = body.clone();
                                let body_for_restore = body.clone();
                                let flow_id_for_store = flow_id.clone();
                                let message_id_for_store = message_id.clone();
                                let reply_to_for_store = reply_to.clone();
                                let projection = state_store
                                    .read()
                                    .load()
                                    .realm_tree_projections
                                    .get(&realm)
                                    .cloned();
                                let plaintext_services =
                                    plaintext_services_for_policy(projection.as_ref(), &service_did);
                                let wait_for = active_sync_token(sync_cursor());
                                let actor_for_retry = actor.clone();
                                spawn(async move {
                                    match submit_chat_operation_with_auth_refresh(
                                        &base,
                                        &actor_for_retry,
                                        &realm,
                                        api_token,
                                        wait_for,
                                        &plaintext_services,
                                        &op,
                                    ).await {
                                        Ok(resp) => {
                                            {
                                                let mut store = state_store.write();
                                                store.append_raw_operation(
                                                    op.local_operation_id().to_owned(),
                                                    Some(realm_for_record),
                                                    json!({
                                                        "event_id": resp.event_id.clone(),
                                                        "kind": "ck.message.create",
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
                                            frontier_state.set(resp.event_id.clone());
                                            status_msg.set("Message sent".to_owned());
                                        }
                                        Err(error) => {
                                            let auth_expired = is_auth_expired_error(&error);
                                            let membership_denied =
                                                is_space_membership_denied_error(&error);
                                            let message = chat_send_error_message(&error);
                                            if membership_denied {
                                                messages
                                                    .write()
                                                    .retain(|candidate| candidate.id != local_id);
                                                if chat_draft().trim().is_empty() {
                                                    chat_draft.set(body_for_restore.clone());
                                                }
                                            } else if let Some(found) = messages
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
                                    }
                                });
                                chat_draft.set(String::new());
                                reply_to_message.set(None);
                            }
                        },
                        {crate::i18n::tr("chat.send")}
                    }
                    }
                    Button {
                        variant: send_secure_variant,
                        "data-testid": send_secure_testid,
                        onclick: {
                            let base = base_url.clone();
                            let realm = selected_realm_id.clone();
                            let actor = account_did.clone();
                            let selected_flow = selected_channel_value.clone();
                            move |_| {
                                let body = chat_draft().trim().to_owned();
                                if body.is_empty() {
                                    status_msg.set("Type a message before secure send".to_owned());
                                    return;
                                }
                                let realm = realm.clone();
                                let actor = actor.clone();
                                let flow_id = if selected_flow.trim().is_empty() {
                                    default_discussion_flow_id(&realm)
                                } else {
                                    selected_flow.clone()
                                };
                                // P2: preserve the composer's reply target on the
                                // encrypted path (it was silently dropped before).
                                let reply_to = reply_to_message()
                                    .filter(|value| !value.trim().is_empty());
                                let message_id = new_chat_message_id();
                                messages.write().push(ChatMessage {
                                    realm_id: realm.clone(),
                                    id: message_id.clone(),
                                    sender: "yougen".to_owned(),
                                    body: body.clone(),
                                    timestamp: chrono::Utc::now().format("%H:%M").to_string(),
                                    flow_id: flow_id.clone(),
                                    reply_to: reply_to.clone(),
                                    reactions: Vec::new(),
                                    redacted: false,
                                    edited: false,
                                    revisions: Vec::new(),
                                    pending: true,
                                    failed: false,
                                    error: None,
                                    mentions: Vec::new(),
                                    crypto_state: MessageCryptoState::Plaintext,
                                });
                                chat_draft.set(String::new());
                                reply_to_message.set(None);
                                let base = base.clone();
                                let realm = realm.clone();
                                let actor = actor.clone();
                                let did = device_id.clone();
                                let api_token = token();
                                let wait_for = active_sync_token(sync_cursor());
                                let backup_trigger_signal =
                                    crate::components::try_needs_mls_backup_signal();
                                let base_for_backup_trigger = base.clone();
                                let token_for_backup_trigger = api_token.clone();
                                let actor_for_backup_trigger = actor.clone();
                                spawn(async move {
                                // P1: encrypt the canonical Content Block JSON
                                // (`ck.content.text`), NOT the bare body bytes, so
                                // strict receivers can parse the decrypted payload
                                // as `application/vnd.cokret.message+json` and the
                                // decrypt-on-read path round-trips it back to text.
                                let secure_content_value = match sdk_payload_value(
                                    cokret_sdk::ContentBlock::text(&body).to_value(),
                                    "chat encrypted content block serialize",
                                ) {
                                    Ok(value) => value,
                                    Err(err) => {
                                        fail_optimistic_chat_send(
                                            messages,
                                            chat_draft,
                                            status_msg,
                                            &message_id,
                                            &body,
                                            format!(
                                                "Send Secure could not encode message content: {err:#}"
                                            ),
                                        );
                                        return;
                                    }
                                };
                                let secure_content_bytes = match serde_json::to_vec(
                                    &secure_content_value,
                                ) {
                                    Ok(bytes) => bytes,
                                    Err(err) => {
                                        fail_optimistic_chat_send(
                                            messages,
                                            chat_draft,
                                            status_msg,
                                            &message_id,
                                            &body,
                                            format!(
                                                "Send Secure could not encode message content: {err}"
                                            ),
                                        );
                                        return;
                                    }
                                };
                                let _hlc = Hlc::now("yougen").to_string();
                                let anchor_view = state_store.read().anchor_view_for_realm(&realm);
                                let anchor_ref = anchor_view.move_anchor_ref();
                                // 1) MLS commit event bumps the epoch +
                                //    records covered_frontier.
                                // Real MLS encrypt path. The shared runtime
                                // restores the local group from this device's
                                // secure-store-backed snapshot secret, then
                                // persists the post-encrypt state. B3d
                                // (schedule_hash) and B6c (member DIDs) now
                                // read from the same group instance.
                                let (
                                    local_schedule_hash,
                                    local_member_dids,
                                    encrypted_message,
                                    real_commit_envelope,
                                    new_mls_snapshot,
                                ): LocalMlsEncryptResult = run_local_mls_encrypt(
                                    state_store,
                                    &realm,
                                    &actor,
                                    &did,
                                    &secure_content_bytes,
                                );

                                let Some((encrypted_payload, envelope_aad)) = encrypted_message else {
                                    fail_optimistic_chat_send(
                                        messages,
                                        chat_draft,
                                        status_msg,
                                        &message_id,
                                        &body,
                                        "Send Secure could not produce an MLS encrypted payload".to_owned(),
                                    );
                                    return;
                                };
                                let Some(local_schedule_hash) = local_schedule_hash.clone() else {
                                    fail_optimistic_chat_send(
                                        messages,
                                        chat_draft,
                                        status_msg,
                                        &message_id,
                                        &body,
                                        "Send Secure could not derive the MLS key schedule hash".to_owned(),
                                    );
                                    return;
                                };
                                if local_member_dids.is_empty() {
                                    fail_optimistic_chat_send(
                                        messages,
                                        chat_draft,
                                        status_msg,
                                        &message_id,
                                        &body,
                                        "Send Secure could not resolve MLS group members".to_owned(),
                                    );
                                    return;
                                }
                                let base_group_state_ref =
                                    chat_mls_base_epoch_ref(&anchor_view, &realm);
                                let (group_state_ref, commit_envelope) =
                                    if let Some(real_commit_envelope) =
                                        real_commit_envelope.as_ref()
                                    {
                                        let mls_commit_epoch = real_commit_envelope.epoch;
                                        // base_epoch MUST be the SDK group's PRE-commit
                                        // epoch so next_epoch == base_epoch + 1 holds by
                                        // construction. `real_commit_envelope.epoch` is the
                                        // POST-commit epoch (self_update_commit merges the
                                        // pending commit).
                                        let prev_epoch = mls_commit_epoch.saturating_sub(1);
                                        let commit_event_id =
                                            format!("ck:event:{}", uuid_v7());
                                        let commit_event_id_typed =
                                            match cokret_sdk::EventId::new(
                                                commit_event_id.clone(),
                                            ) {
                                                Ok(value) => value,
                                                Err(err) => {
                                                    fail_optimistic_chat_send(
                                                        messages,
                                                        chat_draft,
                                                        status_msg,
                                                        &message_id,
                                                        &body,
                                                        format!(
                                                            "MLS commit event id invalid: {err:?}"
                                                        ),
                                                    );
                                                    return;
                                                }
                                            };
                                        let realm_id =
                                            match cokret_sdk::RealmId::new(trim_realm_id(&realm)) {
                                                Ok(value) => value,
                                                Err(err) => {
                                                    fail_optimistic_chat_send(
                                                        messages,
                                                        chat_draft,
                                                        status_msg,
                                                        &message_id,
                                                        &body,
                                                        format!(
                                                            "MLS commit Realm id invalid: {err:?}"
                                                        ),
                                                    );
                                                    return;
                                                }
                                            };
                                        let policy_root = match chat_mls_policy_root(
                                            &anchor_view,
                                            &realm,
                                            &local_schedule_hash,
                                        ) {
                                            Ok(value) => value,
                                            Err(err) => {
                                                fail_optimistic_chat_send(
                                                    messages,
                                                    chat_draft,
                                                    status_msg,
                                                    &message_id,
                                                    &body,
                                                    err,
                                                );
                                                return;
                                            }
                                        };
                                        let governance_binding =
                                            match cokret_sdk::MlsGovernanceBindingPayload::realm(
                                                realm_id,
                                                real_commit_envelope.group_id.clone(),
                                                prev_epoch,
                                                mls_commit_epoch,
                                                chat_mls_membership_frontier(
                                                    &anchor_view,
                                                    &commit_event_id_typed,
                                                ),
                                                policy_root,
                                            ) {
                                                Ok(value) => value,
                                                Err(err) => {
                                                    fail_optimistic_chat_send(
                                                        messages,
                                                        chat_draft,
                                                        status_msg,
                                                        &message_id,
                                                        &body,
                                                        format!(
                                                            "MLS governance binding failed: {err}"
                                                        ),
                                                    );
                                                    return;
                                                }
                                            };
                                        let mls_commit_payload =
                                            match cokret_sdk::MlsCommitPayload::new(
                                                real_commit_envelope.group_id.clone(),
                                                prev_epoch,
                                                base_group_state_ref.clone(),
                                                Vec::new(),
                                                mls_commit_epoch,
                                                real_commit_envelope.commit_digest.clone(),
                                                governance_binding,
                                            ) {
                                                Ok(value) => value,
                                                Err(err) => {
                                                    fail_optimistic_chat_send(
                                                        messages,
                                                        chat_draft,
                                                        status_msg,
                                                        &message_id,
                                                        &body,
                                                        format!("MLS commit payload failed: {err}"),
                                                    );
                                                    return;
                                                }
                                            };
                                        // Spec-canonical write path: ck.mls.commit event via ck.events.submit.
                                        let commit_builder =
                                            match crate::operation::ck_ops::mls_commit_with_governance(
                                                &realm,
                                                &actor,
                                                &mls_commit_payload,
                                            ) {
                                                Ok(builder) => builder,
                                                Err(err) => {
                                                    fail_optimistic_chat_send(
                                                        messages,
                                                        chat_draft,
                                                        status_msg,
                                                        &message_id,
                                                        &body,
                                                        format!("MLS commit payload failed: {err}"),
                                                    );
                                                    return;
                                                }
                                            };
                                        let mut commit_envelope =
                                            commit_builder.build("yougen");
                                        commit_envelope.event_id = commit_event_id.clone();
                                        (commit_event_id, Some(commit_envelope))
                                    } else {
                                        (base_group_state_ref, None)
                                    };
                                // Wrap the MLS payload in the spec-canonical
                                // `ck.schema.encrypted_envelope.v1` wire shape,
                                // binding key_ref.group_state_ref to the current
                                // MLS group state. Ordinary application messages
                                // ride the current epoch; only forced epoch
                                // advances produce a fresh ck.mls.commit event.
                                let encrypted_envelope =
                                    match cokret_sdk::EncryptedEnvelopeV1::from_payload(
                                        &encrypted_payload,
                                        envelope_aad,
                                        cokret_sdk::AadVisibility::Hidden,
                                        &group_state_ref,
                                    ) {
                                        Ok(value) => value,
                                        Err(err) => {
                                            fail_optimistic_chat_send(
                                                messages,
                                                chat_draft,
                                                status_msg,
                                                &message_id,
                                                &body,
                                                format!(
                                                    "MLS encrypted envelope build failed: {err}"
                                                ),
                                            );
                                            return;
                                        }
                                    };
                                let encrypted_payload_json =
                                    match serde_json::to_value(&encrypted_envelope) {
                                        Ok(value) => value,
                                        Err(err) => {
                                            fail_optimistic_chat_send(
                                                messages,
                                                chat_draft,
                                                status_msg,
                                                &message_id,
                                                &body,
                                                format!(
                                                    "MLS encrypted envelope encode failed: {err}"
                                                ),
                                            );
                                            return;
                                        }
                                    };
                                let typed_flow_id = match flow_id_value(&flow_id) {
                                    Ok(value) => value,
                                    Err(err) => {
                                        fail_optimistic_chat_send(
                                            messages,
                                            chat_draft,
                                            status_msg,
                                            &message_id,
                                            &body,
                                            format!("Send Secure flow id invalid: {err:#}"),
                                        );
                                        return;
                                    }
                                };
                                let mut message_payload =
                                    cokret_sdk::MessageCreatePayload::with_encrypted_content(
                                        typed_flow_id,
                                        "discussion",
                                        encrypted_payload_json,
                                    )
                                    .with_message_id(message_id.clone());
                                // P2: carry the reply target as wire metadata so
                                // reply threading / routing matches the plaintext
                                // path (the readable body stays inside the
                                // encrypted Content Block).
                                if let Some(reply_to) = reply_to.as_deref() {
                                    message_payload = message_payload.with_reply_to(reply_to);
                                }
                                let msg_payload_value = match sdk_payload_value(
                                    message_payload.to_value(),
                                    "chat encrypted ck.message.create payload serialize",
                                ) {
                                    Ok(value) => value,
                                    Err(err) => {
                                        fail_optimistic_chat_send(
                                            messages,
                                            chat_draft,
                                            status_msg,
                                            &message_id,
                                            &body,
                                            format!(
                                                "Send Secure payload encode failed: {err:#}"
                                            ),
                                        );
                                        return;
                                    }
                                };
                                let msg_op = OperationBuilder::new(
                                    &realm,
                                    &actor,
                                    "ck.message.create",
                                )
                                .body(msg_payload_value)
                                .build("yougen");
                                let base = base.clone();
                                let realm_for_record = realm.clone();
                                let anchor_for_record = anchor_ref.clone();
                                let actor_for_audit = actor.clone();
                                let audit_delivered: Vec<String> = local_member_dids
                                    .iter()
                                    .map(|did| did.as_str().to_owned())
                                    .collect();
                                let commit_op_id = commit_envelope
                                    .as_ref()
                                    .map(|commit| commit.local_operation_id().to_owned());
                                let device_for_sidecar_backup = did.clone();
                                // X9: capture identifiers needed by the
                                // encrypted Ok(resp) arm to (A) clear the
                                // optimistic bubble's `pending` flag and (B)
                                // persist the message plaintext into the
                                // author-owned sidecar so reload / a new
                                // device can render the author's own
                                // (otherwise undecryptable) messages.
                                let message_id_for_lookup = message_id.clone();
                                let message_id_for_sidecar = message_id.clone();
                                // X10.6: also persisted into the raw_operation
                                // record below so the tab-switch / reload
                                // rebuild can reconstruct the sidecar key.
                                let message_id_for_record = message_id.clone();
                                let actor_for_record = actor.clone();
                                // The synced event carries this exact flow_id
                                // string (the payload was built with
                                // `flow_id_value(&flow_id)`, which wraps it
                                // verbatim), so the read-side sidecar lookup
                                // keyed on the event's `flow_id` matches.
                                let flow_id_for_sidecar = flow_id.clone();
                                let flow_id_for_record = flow_id.clone();
                                let body_for_sidecar = body.clone();
                                // P2: recoverable draft — if the encrypted send
                                // fails we restore the composer text instead of
                                // losing it.
                                let body_for_restore = body.clone();
                                let message_id_for_failure = message_id.clone();
                                spawn(async move {
                                    if let Ok(api) = authed_api_with_sync(&base, api_token, wait_for) {
                                        if let Some(commit_envelope) = commit_envelope {
                                            // Submit a forced MLS commit first; if it fails,
                                            // abort message send (covered_frontier won't bind).
                                            match api.submit_event_envelope(&commit_envelope).await {
                                                Ok(resp) => {
                                                    // X14 — persist-on-accept: the
                                                    // server accepted the commit, so
                                                    // NOW advance the local snapshot
                                                    // to the post-commit epoch. On a
                                                    // commit reject we skip this and
                                                    // the snapshot stays at the
                                                    // pre-commit epoch, so the next
                                                    // Send Secure retries at the
                                                    // correct `expected_prev_epoch`
                                                    // instead of skewing forever.
                                                    if let Some(snapshot) = new_mls_snapshot {
                                                        state_store
                                                            .write()
                                                            .save_mls_snapshot(
                                                                realm_for_record.clone(),
                                                                snapshot,
                                                            );
                                                        // §7.10 continuous backup: the
                                                        // commit advanced the epoch, so
                                                        // re-upload this Realm's
                                                        // mls_history series tail
                                                        // (debounced; no-op until the
                                                        // 24-word Recovery Key exists).
                                                        crate::components::schedule_mls_history_backup_after_commit(
                                                            base.clone(),
                                                            token_for_backup_trigger.clone(),
                                                            actor_for_backup_trigger.clone(),
                                                            device_for_sidecar_backup.clone(),
                                                            realm_for_record.clone(),
                                                            state_store,
                                                        );
                                                    }
                                                    if let Some(commit_op_id) = commit_op_id {
                                                        state_store.write().record_move_submission_with_event_id(
                                                            commit_op_id,
                                                            Some(resp.event_id.clone()),
                                                            realm_for_record.clone(),
                                                            "mls_commit".to_owned(),
                                                            MoveSubmissionState::from_submit_state(
                                                                "accepted", None,
                                                            ),
                                                            None,
                                                            Some(anchor_for_record.clone()),
                                                        );
                                                    }
                                                }
                                                Err(err) => {
                                                    let message = format!(
                                                        "MLS commit event submit failed: {err}"
                                                    );
                                                    // P2: reconcile the optimistic
                                                    // bubble so it doesn't spin
                                                    // forever, and keep the draft.
                                                    if let Some(found) = messages
                                                        .write()
                                                        .iter_mut()
                                                        .find(|candidate| {
                                                            candidate.id == message_id_for_failure
                                                        })
                                                    {
                                                        found.pending = false;
                                                        found.failed = true;
                                                        found.error = Some(message.clone());
                                                    }
                                                    if chat_draft().trim().is_empty() {
                                                        chat_draft.set(body_for_restore.clone());
                                                    }
                                                    status_msg.set(message);
                                                    return;
                                                }
                                            }
                                        }
                                        match api.submit_event_envelope(&msg_op).await {
                                            Ok(resp) => {
                                                {
                                                    let mut store = state_store.write();
                                                    // X10.6: persist the message
                                                    // identity (message_id + flow_id +
                                                    // actor), NOT the plaintext body,
                                                    // into the raw_operation record.
                                                    // The encrypted send originally
                                                    // stored only {event_id, kind,
                                                    // status}, so the tab-switch / reload
                                                    // rebuild — which re-derives the
                                                    // discussion from raw_operations via
                                                    // `chat_messages_from_local_state_with_sidecar`
                                                    // — could NOT reconstruct the sidecar
                                                    // key `message:{message_id}` under
                                                    // `flow_id`. The sidecar lookup in
                                                    // `chat_message_from_event_with_sidecar`
                                                    // bails (`message_id`/`flow_id`
                                                    // missing → `None`), then there is no
                                                    // plaintext body → the author's own
                                                    // (undecryptable) message is dropped
                                                    // → the Discussion goes blank on the
                                                    // next render. We deliberately keep
                                                    // the body OUT of raw_operations (it
                                                    // belongs only in the account-private
                                                    // `mls_private_plaintext` sidecar
                                                    // saved just below); persisting the
                                                    // identity is enough for the rebuild
                                                    // to re-key the sidecar and restore
                                                    // the body. `encrypted_content` is a
                                                    // marker so the reader still treats
                                                    // it as E2EE when no sidecar exists
                                                    // (e.g. another device/member).
                                                    store.append_raw_operation(
                                                        msg_op.local_operation_id().to_owned(),
                                                        Some(realm_for_record.clone()),
                                                        json!({
                                                            "event_id": resp.event_id.clone(),
                                                            "kind": "ck.message.create",
                                                            "actor": actor_for_record.clone(),
                                                            "flow_id": flow_id_for_record.clone(),
                                                            "message_id": message_id_for_record.clone(),
                                                            "encrypted_content": true,
                                                            "status": resp.status.clone(),
                                                        }),
                                                    );
                                                    // BUG B (X9): persist the message
                                                    // plaintext into the author-owned
                                                    // sidecar so reload / a new device can
                                                    // render the author's own encrypted
                                                    // messages (OpenMLS forbids an author
                                                    // from decrypting their own ciphertext).
                                                    // Keyed by `message:{message_id}` under
                                                    // the discussion flow, sharing the
                                                    // `mls_private_plaintext` map that the
                                                    // X5.3 cross-device backup already
                                                    // snapshots — no extra backup wiring.
                                                    store.save_private_plaintext(
                                                        &realm_for_record,
                                                        &flow_id_for_sidecar,
                                                        &format!("message:{message_id_for_sidecar}"),
                                                        &body_for_sidecar,
                                                    );
                                                }
                                                // BUG A (X9): clear the optimistic bubble's
                                                // `pending` spinner now that the server
                                                // accepted the encrypted message (mirrors
                                                // the plaintext path). Reconcile the local
                                                // id to the server event_id so the synced
                                                // copy dedups against this echo.
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
                                                frontier_state.set(resp.event_id.clone());
                                                status_msg.set("Encrypted message sent".to_owned());
                                                crate::components::schedule_mls_private_plaintext_backup_after_encrypted_write(
                                                    base_for_backup_trigger.clone(),
                                                    token_for_backup_trigger.clone(),
                                                    actor_for_backup_trigger.clone(),
                                                    device_for_sidecar_backup.clone(),
                                                    state_store,
                                                );

                                            // X11.2 — first-write trigger.
                                            // After this encrypted send landed,
                                            // if the server holds no
                                            // `mls_account_secret` backup yet,
                                            // flip `needs_mls_backup` on
                                            // directly so the prompt surfaces
                                            // promptly (not gated on the boot
                                            // detection effect). Best-effort +
                                            // non-blocking.
                                            if let Some(signal) = backup_trigger_signal {
                                                crate::components::maybe_flag_mls_backup_after_encrypted_write(
                                                    base_for_backup_trigger.clone(),
                                                    token_for_backup_trigger.clone(),
                                                    actor_for_backup_trigger.clone(),
                                                    signal,
                                                )
                                                .await;
                                            }

                                            // Disclosed-audit hardening profile
                                            // (`ck.profile.disclosed_audit.e2ee.v1`):
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
                                            // B6b: at minimum surface the
                                            // local device DID — that's the
                                            // device we provably reached
                                            // (it sent the commit). A real
                                            // MLS commit yields the full
                                            // post-commit member device set
                                            // through `MlsAddMemberResult`
                                            // / `MlsRemoveMemberResult`; the
                                            // executor will replace this
                                            // single-element fallback when
                                            // the group state path lands.
                                            let audit_op = build_audit_ryw_receipt(
                                                &realm_for_record,
                                                &actor_for_audit,
                                                &resp.event_id,
                                                audit_delivered.clone(),
                                            )
                                            .build("yougen");
                                            // YOU-02-007: the receipt is
                                            // best-effort for delivery, but a
                                            // silent failure left a gap in the
                                            // disclosed-audit chain with no
                                            // trace. Log + surface it so the
                                            // sender knows the audit row is
                                            // missing (message itself sent).
                                            if let Err(err) =
                                                api.submit_event_envelope(&audit_op).await
                                            {
                                                tracing::warn!(
                                                    "audit RYW receipt for {} failed: {err:#}",
                                                    resp.event_id
                                                );
                                                status_msg.set(format!(
                                                    "Message sent; audit receipt failed: {err}"
                                                ));
                                            }
                                        }
                                        Err(err) => {
                                            let message =
                                                format!("Message send failed: {err}");
                                            // P2: mark the optimistic bubble
                                            // failed (was left spinning) and
                                            // keep the draft recoverable.
                                            if let Some(found) = messages
                                                .write()
                                                .iter_mut()
                                                .find(|candidate| {
                                                    candidate.id == message_id_for_failure
                                                })
                                            {
                                                found.pending = false;
                                                found.failed = true;
                                                found.error = Some(message.clone());
                                            }
                                            if chat_draft().trim().is_empty() {
                                                chat_draft.set(body_for_restore.clone());
                                            }
                                            status_msg.set(message);
                                        }
                                    }
                                    } else {
                                        // P2: auth/API init failed — without this
                                        // arm the optimistic bubble spun forever
                                        // and no status was shown.
                                        let message = "Send Secure failed: could not start an authenticated session".to_owned();
                                        if let Some(found) = messages
                                            .write()
                                            .iter_mut()
                                            .find(|candidate| {
                                                candidate.id == message_id_for_failure
                                            })
                                        {
                                            found.pending = false;
                                            found.failed = true;
                                            found.error = Some(message.clone());
                                        }
                                        if chat_draft().trim().is_empty() {
                                            chat_draft.set(body_for_restore.clone());
                                        }
                                        status_msg.set(message);
                                    }
                                });
                                });
                            }
                        },
                        "{send_secure_label}"
                    }
                }
                if !embedded && !status_msg().is_empty() {
                    div { class: "muted discussion-status", "data-testid": "chat-status", "{status_msg}" }
                }
            }
            }
        }
    }
}

fn mentions_to_json(mentions: &[StructuredMention]) -> Vec<serde_json::Value> {
    mentions
        .iter()
        .filter(|mention| mention.kind != "audience_mention")
        .map(|mention| {
            // R3.2 §3.8: emit `subject_id` (the authoritative principal
            // DID) as the actor reference. `handle_at_time` /
            // `display_name_at_time` / `mention_text_original` are
            // compose-time audit metadata ONLY — verifier / reducer /
            // policy MUST ignore them. We still carry yougen-legacy
            // `target` for our own local-op round-trip.
            let mut obj = serde_json::Map::new();
            obj.insert("kind".to_owned(), json!(mention.kind));
            obj.insert("subject_id".to_owned(), json!(mention.target));
            obj.insert("target".to_owned(), json!(mention.target));
            obj.insert("token".to_owned(), json!(mention.token));
            if !mention.display_name_at_time.is_empty() {
                obj.insert(
                    "display_name_at_time".to_owned(),
                    json!(mention.display_name_at_time),
                );
            }
            if !mention.handle_at_time.is_empty() {
                obj.insert("handle_at_time".to_owned(), json!(mention.handle_at_time));
            }
            if !mention.mention_text_original.is_empty() {
                obj.insert(
                    "mention_text_original".to_owned(),
                    json!(mention.mention_text_original),
                );
            }
            if !mention.resolved_at.is_empty() {
                obj.insert("resolved_at".to_owned(), json!(mention.resolved_at));
            }
            Value::Object(obj)
        })
        .collect()
}

fn audience_mentions_to_json(mentions: &[StructuredMention]) -> Vec<serde_json::Value> {
    mentions
        .iter()
        .filter(|mention| mention.kind == "audience_mention")
        .map(|mention| {
            let mut obj = serde_json::Map::new();
            obj.insert("kind".to_owned(), json!("audience_mention"));
            obj.insert("audience".to_owned(), json!(mention.target));
            if !mention.mention_text_original.is_empty() {
                obj.insert(
                    "mention_text_original".to_owned(),
                    json!(mention.mention_text_original),
                );
            }
            if !mention.resolved_at.is_empty() {
                obj.insert("resolved_at".to_owned(), json!(mention.resolved_at));
            }
            Value::Object(obj)
        })
        .collect()
}

fn scroll_chat_feed_to_latest() {
    let script = r#"
setTimeout(() => {
  const panels = document.querySelectorAll('[data-testid="chat-panel"]');
  const panel = panels[panels.length - 1];
  const feed = panel && panel.querySelector('[data-testid="message-list"]');
  if (feed) {
    feed.scrollTop = feed.scrollHeight;
  }
}, 0);
"#;
    let _ = document::eval(script);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The Welcome-receive shuttle iterates `events[]` from
    /// `DeviceMessagesGetOutcome` and surfaces only
    /// `ck.mls.welcome` payloads.
    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn collect_welcome_entries_filters_cx_mls_welcome_and_drops_other_kinds() {
        let value = json!({
            "events": [
                {"type": "ck.mls.welcome", "content": {"welcome_envelope_id": "w-1"}},
                {"type": "ck.key.verify.request", "content": {"ignore_me": true}},
                {"type": "ck.mls.welcome", "content": {"welcome_envelope_id": "w-2"}},
                {"type": "ck.mls.welcome", "content": {"welcome_envelope_id": "w-3"}},
                {"type": "ck.device.message", "content": {"ignore_me": true}},
            ]
        });
        let welcomes = crate::mls::runtime::collect_welcome_entries(&value);
        let ids: Vec<&str> = welcomes
            .iter()
            .filter_map(|w| w.get("welcome_envelope_id").and_then(|v| v.as_str()))
            .collect();
        assert_eq!(ids.len(), 3);
        assert!(ids.contains(&"w-1"));
        assert!(ids.contains(&"w-2"));
        assert!(ids.contains(&"w-3"));
    }

    /// Empty / missing `events` envelope returns no welcomes — the
    /// shuttle silently returns instead of panicking.
    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn collect_welcome_entries_tolerates_missing_events_envelope() {
        assert!(crate::mls::runtime::collect_welcome_entries(&json!({})).is_empty());
        assert!(crate::mls::runtime::collect_welcome_entries(&json!({"events": null})).is_empty());
        assert!(crate::mls::runtime::collect_welcome_entries(&json!({"events": []})).is_empty());
    }

    #[test]
    fn parses_message_event_with_operation_body_shape() {
        let event = json!({
            "id": "ck:event:body-shape",
            "type": "ck.message.create",
            "actor": "did:web:alice.example",
            "realm_id": "ck:realm:demo",
            "created_at": "2026-05-14T01:23:45Z",
            "causal": {"actor_seq": 42},
            "body": {
                "body": "restored from durable history",
                "flow_id": "ck:flow:announce",
                "message_id": "chat-msg-local",
                "mentions": [{"kind": "actor", "target": "did:web:bob.example", "token": "@bob"}]
            }
        });

        let message = chat_message_from_event("ck:realm:fallback", &event).unwrap();

        assert_eq!(message.id, "ck:event:body-shape");
        assert_eq!(message.realm_id, "ck:realm:demo");
        assert_eq!(message.flow_id, "ck:flow:announce");
        assert_eq!(message.body, "restored from durable history");
        assert_eq!(message.sender, "did:web:alice.example");
        assert_eq!(message.mentions[0].target, "did:web:bob.example");
    }

    #[test]
    fn parses_message_event_with_nested_envelope_payload_shape() {
        let event = json!({
            "event": {
                "event_id": "ck:event:nested",
                "kind": "ck.message.create",
                "actor_id": "did:web:alice.example",
                "actor_seq": 43,
                "payload": {
                    "content": {
                        "kind": "ck.content.text",
                        "body": "nested payload message"
                    },
                    "flow_id": "ck:flow:support",
                    "message_id": "chat-msg-nested"
                }
            }
        });

        let message = chat_message_from_event("ck:realm:demo", &event).unwrap();

        assert_eq!(message.id, "ck:event:nested");
        assert_eq!(message.flow_id, "ck:flow:support");
        assert_eq!(message.body, "nested payload message");
    }

    #[test]
    fn chat_message_create_operation_emits_schema_canonical_content() {
        let op = chat_message_create_operation(
            "ck:realm:01904100-0000-7000-8000-000000000010",
            "did:web:alice.example",
            "ck:flow:01904100-0000-7000-8000-000000000001",
            "discussion",
            "ck:message:01904100-0000-7000-8000-000000000001",
            "hello from chat",
            &[],
            None,
        ).expect("builds");

        assert_eq!(op.kind, "ck.message.create");
        assert_eq!(
            op.payload["message_id"].as_str(),
            Some("ck:message:01904100-0000-7000-8000-000000000001")
        );
        assert_eq!(
            op.payload["flow_id"].as_str(),
            Some("ck:flow:01904100-0000-7000-8000-000000000001")
        );
        assert_eq!(op.payload["track_name"].as_str(), Some("discussion"));
        assert_eq!(
            op.payload["content"]["kind"].as_str(),
            Some("ck.content.text")
        );
        assert_eq!(
            op.payload["content"]["body"].as_str(),
            Some("hello from chat")
        );
        assert!(op.payload["content"].get("blocks").is_none());
        assert!(op.payload.get("body").is_none());
        assert!(op.payload.get("encrypted").is_none());
        assert!(op.payload.get("kind").is_none());
        assert!(op.payload.get("mentions").is_none());
        assert!(op.payload.get("audience_mentions").is_none());
        assert!(op.payload.get("mention_relations").is_none());
        assert!(op.payload.get("reply_to").is_none());
        assert!(op.payload.get("thread_id").is_none());
        cokret_sdk::schema::event_payload_validator_catalog()
            .validate_payload(&op.kind, &op.payload)
            .unwrap();
    }

    #[test]
    fn chat_message_create_operation_embeds_audience_mentions_in_content_only() {
        let mentions = parse_structured_mentions("ping @here and @carol:example.com");
        let op = chat_message_create_operation(
            "ck:realm:01904100-0000-7000-8000-000000000010",
            "did:web:alice.example",
            "ck:flow:01904100-0000-7000-8000-000000000001",
            "discussion",
            "ck:message:01904100-0000-7000-8000-000000000002",
            "ping @here and @carol:example.com",
            &mentions,
            None,
        ).expect("builds");

        assert_eq!(
            op.payload["content"]["audience_mentions"][0]["audience"].as_str(),
            Some("flow_engaged")
        );
        assert!(op.payload.get("audience_mentions").is_none());
        assert!(op.payload.get("mentions").is_none());
        assert!(op.payload.get("mention_relations").is_none());
        cokret_sdk::schema::event_payload_validator_catalog()
            .validate_payload(&op.kind, &op.payload)
            .unwrap();
    }

    #[test]
    fn chat_message_create_operation_includes_reply_fields_only_when_present() {
        let op = chat_message_create_operation(
            "ck:realm:01904100-0000-7000-8000-000000000010",
            "did:web:alice.example",
            "ck:flow:01904100-0000-7000-8000-000000000001",
            "discussion",
            "ck:message:01904100-0000-7000-8000-000000000003",
            "reply body",
            &[],
            Some("ck:message:01904100-0000-7000-8000-000000000004"),
        ).expect("builds");

        assert_eq!(
            op.payload["reply_to"].as_str(),
            Some("ck:message:01904100-0000-7000-8000-000000000004")
        );
        assert!(op.payload.get("thread_id").is_none());
        cokret_sdk::schema::event_payload_validator_catalog()
            .validate_payload(&op.kind, &op.payload)
            .unwrap();
    }

    #[test]
    fn chat_message_ids_use_schema_prefix() {
        let id = new_chat_message_id();

        assert!(id.starts_with("ck:message:"));
        assert!(is_schema_message_id(&id));
        assert!(is_schema_message_id("ck:message:local-1"));
        assert!(!is_schema_message_id("chat-msg-local"));
        assert!(schema_message_id_or_new("chat-msg-local").starts_with("ck:message:"));
    }

    #[test]
    fn restores_messages_from_local_raw_operations() {
        let state = ClientLocalState {
            raw_operations: vec![crate::local_state::RawOperationRecord {
                operation_id: "ck:operation:local".to_owned(),
                realm_id: Some("ck:realm:local".to_owned()),
                received_at: chrono::Utc::now(),
                payload: json!({
                    "event_id": "ck:event:local",
                    "kind": "ck.message.create",
                    "actor": "did:web:alice.example",
                    "body": "local fallback message",
                    "flow_id": "ck:flow:announce",
                    "message_id": "chat-msg-local"
                }),
            }],
            ..ClientLocalState::default()
        };

        let messages = chat_messages_from_local_state_with_sidecar(&state, None, None);

        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].realm_id, "ck:realm:local");
        assert_eq!(messages[0].flow_id, "ck:flow:announce");
        assert_eq!(messages[0].body, "local fallback message");
    }

    #[test]
    fn rebuild_restores_authors_own_encrypted_message_from_sidecar() {
        // X10.6 regression: an encrypted send persists a body-less
        // raw_operation stub (it MUST NOT store the plaintext in
        // raw_operations) plus the plaintext into the account-private
        // sidecar keyed by `message:{message_id}` under the flow. On a
        // card-detail Discussion tab switch / reload the ChatPanel remounts
        // and re-derives the feed from raw_operations via
        // `chat_messages_from_local_state_with_sidecar`. The stub now carries
        // `message_id` + `flow_id`, so the rebuild can re-key the sidecar and
        // restore the author's own (otherwise undecryptable) message body.
        let temp = std::env::temp_dir().join(format!("yougen-x10_6-rebuild-sidecar-{}", uuid_v7()));
        let mut store = LocalStateStore::with_path(temp);
        store.save_private_plaintext(
            "ck:realm:local",
            "ck:flow:announce",
            "message:chat-msg-enc",
            "secret discussion body",
        );

        let state = ClientLocalState {
            raw_operations: vec![crate::local_state::RawOperationRecord {
                operation_id: "ck:operation:enc".to_owned(),
                realm_id: Some("ck:realm:local".to_owned()),
                received_at: chrono::Utc::now(),
                // Encrypted stub: identity only, NO plaintext body.
                payload: json!({
                    "event_id": "ck:event:enc",
                    "kind": "ck.message.create",
                    "actor": "did:web:alice.example",
                    "flow_id": "ck:flow:announce",
                    "message_id": "chat-msg-enc",
                    "encrypted_content": true,
                    "status": "accepted"
                }),
            }],
            ..ClientLocalState::default()
        };

        // Without the sidecar (e.g. another device) the stub has no readable
        // body, but it must still surface as an encrypted/locked row so the
        // discussion does not look empty.
        let without_sidecar = chat_messages_from_local_state_with_sidecar(&state, None, None);
        assert_eq!(without_sidecar.len(), 1);
        assert_eq!(without_sidecar[0].flow_id, "ck:flow:announce");
        assert_eq!(without_sidecar[0].body, "");
        assert!(matches!(
            without_sidecar[0].crypto_state,
            MessageCryptoState::Decrypting
        ));

        // With the sidecar (same device, tab switch / reload) the body is
        // restored and the message is fully resolved (not stuck decrypting).
        let restored = chat_messages_from_local_state_with_sidecar(&state, Some(&store), None);
        assert_eq!(restored.len(), 1);
        assert_eq!(restored[0].flow_id, "ck:flow:announce");
        assert_eq!(restored[0].body, "secret discussion body");
        assert!(matches!(
            restored[0].crypto_state,
            MessageCryptoState::Plaintext
        ));
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
            handle_label: None,
            display_name_rank: 0,
            role: SpaceParticipantRole::Member,
            is_self: false,
            is_agent: false,
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
    fn sender_display_label_prefers_full_handle_over_handle_localpart() {
        let participants = vec![SpaceParticipant {
            did: "did:web:local.host:users:alice".to_owned(),
            display_name: Some("alice".to_owned()),
            handle_label: None,
            display_name_rank: 2,
            role: SpaceParticipantRole::Member,
            is_self: true,
            is_agent: false,
        }];

        assert_eq!(
            sender_display_label(
                "did:web:local.host:users:alice",
                "did:web:local.host:users:alice",
                "alice",
                &participants,
            ),
            "alice:local.host"
        );
    }

    #[test]
    fn sender_display_label_prefers_projection_handle_label() {
        let participants = vec![SpaceParticipant {
            did: "did:web:example.com:users:bob".to_owned(),
            display_name: Some("bob".to_owned()),
            handle_label: Some("bob:example.com".to_owned()),
            display_name_rank: 2,
            role: SpaceParticipantRole::Member,
            is_self: false,
            is_agent: false,
        }];

        assert_eq!(
            sender_display_label(
                "did:web:example.com:users:bob",
                "did:web:local.host:users:alice",
                "alice:local.host",
                &participants,
            ),
            "bob:example.com"
        );
    }

    #[test]
    fn account_handle_display_from_server_expands_account_localpart() {
        assert_eq!(
            account_handle_display_from_server("alice", "https://local.host").as_deref(),
            Some("alice:local.host")
        );
        assert_eq!(
            account_handle_display_from_server("alice:example.com", "https://local.host")
                .as_deref(),
            Some("alice:example.com")
        );
        assert_eq!(
            account_handle_display_from_server("  ", "https://local.host"),
            None
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
    fn extracts_participant_handle_label_from_projection() {
        // R3.1: canonical wire field is `handle` (`<localpart>:<domain>`).
        let projection = json!({
            "members": [
                {
                    "actor_id": "did:web:example.com:users:bob",
                    "handle": "bob:example.com"
                }
            ]
        });

        let participants = space_participants(Some(&projection), "did:web:alice.example");
        let bob = participants
            .iter()
            .find(|participant| participant.did == "did:web:example.com:users:bob")
            .unwrap();

        assert_eq!(
            mention_label_for_participant(bob).as_deref(),
            Some("bob:example.com")
        );
    }

    #[test]
    fn mention_label_for_participant_falls_back_to_materialized_handle_did() {
        let participant = SpaceParticipant {
            did: "did:web:example.com:users:bob".to_owned(),
            display_name: None,
            handle_label: None,
            display_name_rank: u8::MAX,
            role: SpaceParticipantRole::Member,
            is_self: false,
            is_agent: false,
        };

        assert_eq!(
            mention_label_for_participant(&participant).as_deref(),
            Some("bob:example.com")
        );
    }

    #[test]
    fn mention_label_for_participant_requires_handle() {
        let participant = SpaceParticipant {
            did: "did:webvh:zQmed2r1bBnz5cpB6SoL1UxvqNQPQpimEnHy7Rc9VLLrifC:local.host:webvh:01ks6dnzv".to_owned(),
            display_name: None,
            handle_label: None,
            display_name_rank: u8::MAX,
            role: SpaceParticipantRole::Member,
            is_self: false,
            is_agent: false,
        };

        assert!(mention_label_for_participant(&participant).is_none());
    }

    #[test]
    fn mention_inline_parts_styles_only_full_handles() {
        let mention = StructuredMention {
            kind: "actor".to_owned(),
            target: "did:web:local.host:users:alice".to_owned(),
            token: "@alice:local.host".to_owned(),
            display_name_at_time: "alice:local.host".to_owned(),
            handle_at_time: "alice:local.host".to_owned(),
            mention_text_original: "@alice:local.host".to_owned(),
            resolved_at: String::new(),
        };

        let parts = mention_inline_parts(
            "@alice Hello @alice:local.host.",
            &[mention],
            "https://auth.local.host",
        );
        assert!(parts.iter().any(
            |part| part.mention_label.as_deref() == Some("alice:local.host") && part.is_local
        ));
        assert!(
            parts
                .iter()
                .any(|part| part.text == "@alice" && part.mention_label.is_none())
        );
    }

    #[test]
    fn mention_inline_parts_marks_external_handles_remote() {
        let mention = StructuredMention {
            kind: "actor".to_owned(),
            target: "did:web:example.com:users:bob".to_owned(),
            token: "@bob:example.com".to_owned(),
            display_name_at_time: "bob:example.com".to_owned(),
            handle_at_time: "bob:example.com".to_owned(),
            mention_text_original: "@bob:example.com".to_owned(),
            resolved_at: String::new(),
        };

        let parts = mention_inline_parts("@bob:example.com", &[mention], "https://local.host");
        let mention_part = parts
            .iter()
            .find(|part| part.mention_label.as_deref() == Some("bob:example.com"))
            .unwrap();
        assert!(!mention_part.is_local);
    }

    #[test]
    fn participant_with_agent_id_renders_with_agent_badge() {
        // Three participants in the realm: Alice (the local account),
        // Bob (a real human member), and a Researcher Agent registered
        // via `ck.agent.endpoint`. After `annotate_agent_participants`
        // the agent DID must carry `is_agent = true` while the human
        // members stay `false`.
        let mut participants = vec![
            SpaceParticipant {
                did: "did:web:alice.example".to_owned(),
                display_name: Some("Alice".to_owned()),
                handle_label: None,
                display_name_rank: 0,
                role: SpaceParticipantRole::Owner,
                is_self: true,
                is_agent: false,
            },
            SpaceParticipant {
                did: "did:web:bob.example".to_owned(),
                display_name: Some("Bob".to_owned()),
                handle_label: None,
                display_name_rank: 1,
                role: SpaceParticipantRole::Member,
                is_self: false,
                is_agent: false,
            },
            SpaceParticipant {
                did: "did:web:researcher-agent.example".to_owned(),
                display_name: None,
                handle_label: None,
                display_name_rank: u8::MAX,
                role: SpaceParticipantRole::Member,
                is_self: false,
                is_agent: false,
            },
        ];

        annotate_agent_participants(
            &mut participants,
            &["did:web:researcher-agent.example".to_owned()],
        );

        let alice = &participants[0];
        let bob = &participants[1];
        let agent = &participants[2];
        assert!(!alice.is_agent, "human owner must not be flagged as agent");
        assert!(!bob.is_agent, "human member must not be flagged as agent");
        assert!(
            agent.is_agent,
            "DID registered via ck.agent.endpoint must be flagged as agent"
        );
    }

    #[test]
    fn agent_ids_from_raw_operations_filters_by_realm_and_kind() {
        use chrono::Utc;

        use crate::local_state::RawOperationRecord;

        // Mixed bag of raw ops: an agent endpoint for the right realm,
        // an agent endpoint for a different realm (should be filtered
        // out by space_id), and a non-agent kind (should be filtered
        // out by kind).
        let records = vec![
            RawOperationRecord {
                operation_id: "op-1".to_owned(),
                realm_id: Some("ck:realm:demo".to_owned()),
                received_at: Utc::now(),
                payload: json!({
                    "kind": "ck.agent.endpoint",
                    "body": { "agent_id": "did:web:researcher-agent.example" }
                }),
            },
            RawOperationRecord {
                operation_id: "op-2".to_owned(),
                realm_id: Some("ck:realm:other".to_owned()),
                received_at: Utc::now(),
                payload: json!({
                    "kind": "ck.agent.endpoint",
                    "body": { "agent_id": "did:web:other-agent.example" }
                }),
            },
            RawOperationRecord {
                operation_id: "op-3".to_owned(),
                realm_id: Some("ck:realm:demo".to_owned()),
                received_at: Utc::now(),
                payload: json!({
                    "kind": "ck.message.create",
                    "body": { "body": "hello" }
                }),
            },
        ];

        let agent_ids = agent_ids_from_raw_operations(&records, "ck:realm:demo");
        assert_eq!(
            agent_ids,
            vec!["did:web:researcher-agent.example".to_owned()]
        );
    }

    #[test]
    fn channel_from_flow_event_requires_real_discussion_track() {
        let event = json!({
            "event_id": "ck:event:flow",
            "kind": "ck.flow.create",
            "realm_id": "ck:realm:demo",
            "flow_id": "ck:flow:ops",
            "title": "Ops discussion",
            "category": "support",
            "summary": "Operations support",
            "flow": {
                "id": "ck:flow:ops",
                "title": "Ops discussion",
                "tracks": {
                    "discussion": {"profile": "discussion"}
                }
            }
        });

        let channel = channel_from_flow_event("ck:realm:demo", &event).unwrap();

        assert_eq!(channel.flow_id, "ck:flow:ops");
        assert_eq!(channel.name, "Ops discussion");
        assert_eq!(channel.category, "support");
        assert_eq!(channel.kind, "discussion");
        assert_eq!(channel.topic.as_deref(), Some("Operations support"));
        assert!(!channel.is_default);
    }

    #[test]
    fn channel_from_flow_event_ignores_non_discussion_flows() {
        let event = json!({
            "event_id": "ck:event:flow",
            "kind": "ck.flow.create",
            "realm_id": "ck:realm:demo",
            "flow_id": "ck:flow:doc",
            "title": "Doc flow",
            "flow": {
                "id": "ck:flow:doc",
                "title": "Doc flow",
                "tracks": {
                    "document": {"profile": "document"}
                }
            }
        });

        assert!(channel_from_flow_event("ck:realm:demo", &event).is_none());
    }

    #[test]
    fn default_discussion_channel_uses_realm_default_flow_projection() {
        let body = json!({
            "summary": {
                "title": "Demo Realm",
                "flow": {
                    "flow_id": "ck:flow:demo",
                    "title": "General",
                    "summary": "Realm-wide conversation",
                    "tracks": {
                        "discussion": {"enabled": true},
                        "synthesis": {"enabled": true}
                    }
                }
            }
        });

        let channel = default_discussion_channel("ck:realm:demo", Some(&body));

        assert_eq!(channel.flow_id, "ck:flow:demo");
        assert_eq!(channel.name, "General");
        assert_eq!(channel.kind, "discussion");
        assert_eq!(channel.topic.as_deref(), Some("Realm-wide conversation"));
        assert!(channel.is_default);
    }

    #[test]
    fn default_discussion_channel_synthesizes_default_flow_when_projection_is_absent() {
        let channel = default_discussion_channel("ck:realm:demo", None);

        assert_eq!(channel.flow_id, "ck:flow:demo");
        assert_eq!(channel.name, "Discussion");
        assert_eq!(channel.category, "default flow");
        assert!(channel.is_default);
    }

    #[test]
    fn presence_maps_from_sync_events_prefers_account_subscribe_presence() {
        let participants = vec![
            "did:web:alice.example".to_owned(),
            "did:web:bob.example".to_owned(),
            "did:web:carol.example".to_owned(),
        ];
        let events = vec![
            json!({
                "user_id": "did:web:bob.example",
                "presence": "online",
                "updated_at": "2026-05-29T04:12:43Z"
            }),
            json!({
                "actor_id": "did:web:mallory.example",
                "presence": "online"
            }),
        ];

        let (states, labels) = presence_maps_from_sync_events(
            &events,
            &participants,
            "did:web:alice.example",
            "Alice",
        )
        .expect("presence events should match participants");

        assert_eq!(
            states.get("did:web:alice.example"),
            Some(&"online".to_owned())
        );
        assert_eq!(
            states.get("did:web:bob.example"),
            Some(&"online".to_owned())
        );
        assert_eq!(
            states.get("did:web:carol.example"),
            Some(&"offline".to_owned())
        );
        assert_eq!(
            labels.get("did:web:alice.example"),
            Some(&"Alice".to_owned())
        );
        assert!(!states.contains_key("did:web:mallory.example"));
    }

    #[test]
    fn watch_level_wire_round_trip() {
        for level in [
            WatchLevel::MentionsOnly,
            WatchLevel::Participating,
            WatchLevel::All,
            WatchLevel::Muted,
        ] {
            assert_eq!(watch_level_from_wire(watch_level_wire_value(level)), level);
        }
        assert_eq!(watch_level_from_wire("none"), WatchLevel::Muted);
    }

    // ── T7.4 crypto state helpers ────────────────────────────────

    #[test]
    fn message_crypto_state_pending_detects_grey_states() {
        assert!(!MessageCryptoState::Plaintext.is_pending());
        assert!(MessageCryptoState::Decrypting.is_pending());
        assert!(MessageCryptoState::KeyMissing.is_pending());
        assert!(!MessageCryptoState::NeedsVerification.is_pending());
    }

    #[test]
    fn secure_content_block_round_trips_back_to_text() {
        // P1: the secure send path encrypts the canonical Content Block JSON
        // (not raw body bytes), and the decrypt-on-read path extracts the text
        // back out via `text_body_from_value`. This locks that symmetry without
        // standing up a full MLS group.
        let body = "secret hello with spaces";
        let content_value = cokret_sdk::ContentBlock::text(body)
            .to_value()
            .expect("content block serializes");
        let bytes = serde_json::to_vec(&content_value).expect("content block bytes");
        let parsed: Value = serde_json::from_slice(&bytes).expect("content block parses");
        assert_eq!(text_body_from_value(&parsed).as_deref(), Some(body));
    }

    #[test]
    fn decrypt_chat_encrypted_content_soft_fails_without_snapshot() {
        // No local MLS snapshot for this realm -> decrypt-on-read returns None
        // so the caller leaves the message in Decrypting/KeyMissing rather than
        // surfacing garbage.
        let temp = std::env::temp_dir().join(format!(
            "yougen-chat-decrypt-{}.json",
            crate::operation::uuid_v7()
        ));
        let store = LocalStateStore::with_path(temp);
        let envelope = json!({
            "scheme": "mls-rfc9420",
            "group_id": "group-x",
            "epoch": 1,
            "content_type": "application/vnd.cokret.message+json",
            "ciphertext": "AAAA",
            "payload_digest": "sha256:0",
        });
        assert!(
            decrypt_chat_encrypted_content(
                &store,
                "ck:realm:none",
                "did:web:alice.example",
                "ck:device:01964137-0000-7000-8000-000000000001",
                &envelope,
            )
            .is_none()
        );
    }

    #[test]
    fn chat_message_from_event_flags_encrypted_payload_as_decrypting() {
        let event = json!({
            "event_id": "evt:1",
            "content": {
                "type": "ck.message.create",
                "body": "[encrypted]",
                "flow_id": "ck:flow:1",
                "encrypted_content": {"ciphertext": "blob"},
            }
        });
        let msg = chat_message_from_event("ck:realm:demo", &event).expect("message");
        assert_eq!(msg.crypto_state, MessageCryptoState::Decrypting);
    }

    #[test]
    fn chat_message_from_event_keeps_bodyless_encrypted_payload_visible() {
        let event = json!({
            "event_id": "evt:bodyless",
            "content": {
                "type": "ck.message.create",
                "flow_id": "ck:flow:1",
                "message_id": "ck:message:1",
                "encrypted_content": {
                    "scheme": "mls-rfc9420",
                    "version": "1.0",
                    "group_id": "ck:mls:test",
                    "epoch": 1,
                    "content_type": "application/vnd.cokret.message+json",
                    "ciphertext": "AAAA",
                    "payload_digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000"
                },
            }
        });

        let msg = chat_message_from_event("ck:realm:demo", &event).expect("message");

        assert_eq!(msg.body, "");
        assert_eq!(msg.flow_id, "ck:flow:1");
        assert_eq!(msg.crypto_state, MessageCryptoState::Decrypting);
    }

    #[test]
    fn chat_message_revise_operation_uses_schema_target_ref() {
        let op = chat_message_revise_operation(
            "ck:realm:019e4fd4-4e26-7cc9-af7e-d7102d6f4a22",
            "did:web:bob.example",
            "ck:event:019e4fd4-4e26-7cc9-af7e-d7102d6f4a23",
            "edited",
        );

        assert_eq!(
            op.payload["target_ref"],
            "ck:event:019e4fd4-4e26-7cc9-af7e-d7102d6f4a23"
        );
        assert_eq!(op.payload["content"]["kind"], "ck.content.text");
        assert_eq!(op.payload["content"]["body"], "edited");
        assert!(op.payload.get("body").is_none());
        assert!(op.payload.get("target_event_id").is_none());
        cokret_sdk::schema::event_payload_validator_catalog()
            .validate_payload(&op.kind, &op.payload)
            .unwrap();
    }

    #[test]
    fn chat_reaction_add_operation_uses_schema_target_ref() {
        let op = chat_reaction_add_operation(
            "ck:realm:019e4fd4-4e26-7cc9-af7e-d7102d6f4a22",
            "did:web:bob.example",
            "ck:event:019e4fd4-4e26-7cc9-af7e-d7102d6f4a23",
            "+1",
        );

        assert_eq!(
            op.payload["target_ref"],
            "ck:event:019e4fd4-4e26-7cc9-af7e-d7102d6f4a23"
        );
        assert_eq!(op.payload["key"], "+1");
        assert!(op.payload.get("event_id").is_none());
        assert!(op.payload.get("actor").is_none());
        cokret_sdk::schema::event_payload_validator_catalog()
            .validate_payload(&op.kind, &op.payload)
            .unwrap();
    }
}
