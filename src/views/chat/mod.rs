use cokret_sdk::push_rule_core::WatchLevel;
use dioxus::html::HasFileData;
use dioxus::prelude::*;
use dioxus_primitives::checkbox::CheckboxState;
use dioxus_router::hooks::use_navigator;
use serde_json::{Value, json};

use crate::api::{
    CokretApi, is_plaintext_visibility_policy_error, is_space_membership_denied_error,
};
use crate::audit::build_audit_ryw_receipt;
use crate::components::{HelpTip, SecurityStateBadge, SelfAttributionBadge, UiIcon};
use crate::hlc::{Hlc, observe_seq};
use crate::local_state::{ClientLocalState, LocalStateStore};
use crate::models::SubmitEventResult;
use crate::operation::{
    OperationBuilder, ck_ops, sdk_event_local_operation_id, trim_realm_id, uuid_v7,
};
use crate::routes::Route;
use crate::ui::button::{Button, ButtonVariant};
use crate::ui::checkbox::Checkbox;
use crate::ui::dialog::Dialog;
use crate::ui::input::Input;
use crate::ui::label::Label;
use crate::ui::textarea::Textarea;
use crate::views::helpers::{
    MentionNode, active_sync_token, authed_api_with_sync, parse_agent_selector_mention_tokens,
    parse_mention_nodes, short_protocol_id, with_authed_api_with_sync,
};
use crate::views::moderation_appeal::{AppealEntrypoint, AppealState};

mod model;
mod render;

const PRESENCE_HEARTBEAT_SECS: u64 = 25;

// Re-exported for the sync engine so the account-aggregate stream folds
// discussion message events into the shared `raw_operations` log (local-first
// feed), mirroring `kanban::kanban_operations_from_events`.
#[cfg(test)]
pub(crate) use model::message_operations_from_events;
use model::*;
use render::*;

fn moderation_prompt_state(prompt: &ModerationAppealPrompt) -> AppealState {
    match prompt.state.as_str() {
        "submitted" => AppealState::Submitted,
        "under_review" => AppealState::UnderReview,
        "decided" => AppealState::Decided {
            verdict: prompt
                .verdict
                .clone()
                .unwrap_or_else(|| "unknown".to_owned()),
        },
        "closed" => AppealState::Closed,
        _ => AppealState::None,
    }
}

async fn resolve_agent_selector_mentions(
    base_url: &str,
    api_token: String,
    wait_for_sync_token: Option<String>,
    body: &str,
    realm_id: &str,
    requester: &str,
) -> Vec<MentionNode> {
    let tokens = parse_agent_selector_mention_tokens(body);
    if tokens.is_empty() {
        return Vec::new();
    }
    let Ok(api) = authed_api_with_sync(base_url, api_token, wait_for_sync_token) else {
        return Vec::new();
    };
    let mut mentions = Vec::new();
    for token in tokens {
        let Ok(outcome) = api
            .resolve_agent_selector_mention(
                &token.controller_handle,
                &token.agent_slug,
                realm_id,
                requester,
            )
            .await
        else {
            continue;
        };
        let Ok(controller_handle) = cokret_sdk::Handle::parse(&token.controller_handle) else {
            continue;
        };
        let mention = cokret_sdk::Mention::new(outcome.subject)
            .with_agent_selector_metadata(
                outcome.controller_subject,
                controller_handle,
                outcome.agent_slug,
            )
            .with_mention_text_original(token.mention_text_original)
            .with_resolved_at(chrono::Utc::now());
        mentions.push(MentionNode::mention(mention));
    }
    mentions
}

fn chat_visible_read_receipt_should_send(
    store: &LocalStateStore,
    strand_id: &str,
    realm_id: &str,
) -> bool {
    let strand_id = strand_id.trim();
    let realm_id = realm_id.trim();
    store.read_receipt_should_send(
        (!strand_id.is_empty()).then_some(strand_id),
        (!realm_id.is_empty()).then_some(realm_id),
    )
}

fn chat_visible_read_receipt_should_display(
    store: &LocalStateStore,
    strand_id: &str,
    realm_id: &str,
) -> bool {
    let strand_id = strand_id.trim();
    let realm_id = realm_id.trim();
    store.read_receipt_should_display(
        (!strand_id.is_empty()).then_some(strand_id),
        (!realm_id.is_empty()).then_some(realm_id),
    )
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
    initial_strand_id: String,
    embedded: bool,
    direct_mode: bool,
) -> Element {
    let navigator = use_navigator();
    let did_cache = use_context::<Signal<crate::did_resolver::DidResolutionCache>>();
    let initial_default_channel = (!selected_realm_id.trim().is_empty())
        .then(|| discussion_channel_for_strand(&selected_realm_id, &initial_strand_id));
    let initial_selected_channel = initial_default_channel
        .as_ref()
        .map(|channel| channel.strand_id.clone())
        .unwrap_or_default();
    let mut channels = use_signal(move || {
        initial_default_channel
            .clone()
            .into_iter()
            .collect::<Vec<_>>()
    });
    let mut selected_channel = use_signal(move || initial_selected_channel.clone());
    {
        let selected_realm_for_initial_strand = selected_realm_id.clone();
        let initial_strand_id_for_effect = initial_strand_id.clone();
        use_effect(move || {
            if selected_realm_for_initial_strand.trim().is_empty() {
                return;
            }
            let desired_channel = discussion_channel_for_strand(
                &selected_realm_for_initial_strand,
                &initial_strand_id_for_effect,
            );
            if selected_channel() != desired_channel.strand_id {
                selected_channel.set(desired_channel.strand_id.clone());
            }
            let has_channel = channels
                .read()
                .iter()
                .any(|channel| channel.strand_id == desired_channel.strand_id);
            if !has_channel {
                channels.write().push(desired_channel);
            }
        });
    }
    let mut messages = use_signal(Vec::<ChatMessage>::new);
    let mut moderation_appeal_prompts = use_signal(Vec::<ModerationAppealPrompt>::new);
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
    let mut shared_pins = use_signal(Vec::<SharedMessagePin>::new);
    let private_saved_targets = use_signal(std::collections::BTreeSet::<String>::new);
    let private_saved_account_data =
        use_signal(std::collections::BTreeMap::<String, Value>::new);
    // Currently-open context menu (right-click on a message). Stores
    // the message id whose menu is open; None means no menu visible.
    let mut message_context_menu = use_signal(|| Option::<String>::None);
    let mut new_channel_name = use_signal(String::new);
    let mut new_channel_topic = use_signal(String::new);
    let mut new_channel_create_card = use_signal(|| false);
    let mut create_dialog_open = use_signal(|| false);
    // T7.2: per-Strand watch level signal for the topbar fast switcher.
    // Optimistically updates on user click; a failed submit rolls back to
    // the prior value.
    let mut strand_watch_level = use_signal(|| WatchLevel::All);
    let mut watch_level_menu_open = use_signal(|| false);
    let mut status_msg = use_signal(String::new);
    // Offline send outbox (sync/offline-conflict). `chat_outbox` holds the
    // messages parked while `navigator.onLine` is false; it rehydrates from
    // localStorage so a reload mid-outage keeps the unsent rows. `is_online`
    // is polled from `navigator.onLine`; a transition false->true drains the
    // outbox through the normal send path.
    let mut chat_outbox = use_signal({
        let account_did = account_did.clone();
        move || load_outbox(&account_did)
    });
    let mut is_online = use_signal(navigator_online);
    // Guards the reconnect drain so a re-render mid-flush doesn't double-submit
    // the same queued message.
    let mut outbox_flushing = use_signal(|| false);
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
    let typing_next_expires_at_ms = use_signal(|| Option::<i64>::None);
    // G3.Y2 — presence. Maps `actor_id -> "online"|"idle"|"dnd"|"offline"`.
    // Refreshed from the global SyncEngine's account-subscribe projection
    // when `sync_cursor` advances.
    let presence_states = use_signal(std::collections::BTreeMap::<String, String>::new);
    let presence_labels = use_signal(std::collections::BTreeMap::<String, String>::new);
    // Transient status messages (`actor_id -> status_message`) carried by
    // the presence projection (profiles-presence.md §3.3).
    let presence_status_messages = use_signal(std::collections::BTreeMap::<String, String>::new);
    let mut presence_sync_key_seen = use_signal(String::new);
    let mut presence_announce_key_seen = use_signal(String::new);
    let mut presence_heartbeat_tick = use_signal(|| 0u64);
    // G3.Y2 — discussion promote modal. Holds the source message id
    // (or Strand id) + the desired private discussion title.
    let mut promote_discussion_draft =
        use_signal(crate::messaging::discussion_promote::PromoteDiscussionDraft::default);
    // Map of `source_message_id -> private_discussion_strand_id` for the
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

    {
        let base = base_url.clone();
        let realm = selected_realm_id.clone();
        let actor = account_did.clone();
        let device = device_id.clone();
        let mut state_store_for_presence = state_store;
        use_effect(move || {
            let realm = trim_realm_id(&realm);
            let actor = actor.trim().to_owned();
            let device = device.clone();
            let heartbeat_tick = presence_heartbeat_tick();
            let visibility = state_store_for_presence.read().presence_visibility();
            // Manual presence preference (profiles-presence.md §3.6):
            // while active it pins the broadcast state on every device
            // and supplies the transient status message.
            let now = chrono::Utc::now();
            let mut preference = state_store_for_presence.read().presence_preference();
            if !preference.is_empty() && !preference.is_active(now) {
                state_store_for_presence
                    .write()
                    .set_presence_preference(crate::local_state::PresencePreferenceState::default());
                preference = crate::local_state::PresencePreferenceState::default();
            }
            let state = preference
                .effective_manual_state(now)
                .unwrap_or("online")
                .to_owned();
            let status_message = preference.effective_status_message(now).map(str::to_owned);
            let api_token = token();
            if realm.is_empty()
                || actor.is_empty()
                || api_token.trim().is_empty()
                || !visibility.allows_presence_send()
            {
                return;
            }
            let announce_key = format!(
                "{realm}|{actor}|{}|{state}|{}|{heartbeat_tick}",
                visibility.as_wire(),
                status_message.as_deref().unwrap_or("")
            );
            if presence_announce_key_seen.peek().as_str() == announce_key {
                return;
            }
            presence_announce_key_seen.set(announce_key);
            let base = base.clone();
            spawn(async move {
                let _ =
                    crate::views::helpers::with_authed_api(&base, api_token, |api| async move {
                        api.send_presence(
                            &realm,
                            &actor,
                            &device,
                            &state,
                            status_message.as_deref(),
                            None,
                        )
                        .await
                    })
                    .await;
                crate::api::sleep_for(std::time::Duration::from_secs(PRESENCE_HEARTBEAT_SECS))
                    .await;
                let next_tick = (*presence_heartbeat_tick.peek()).wrapping_add(1);
                presence_heartbeat_tick.set(next_tick);
            });
        });
    }

    {
        let mut shared_pins_for_sync = shared_pins;
        let mut private_saved_targets_for_sync = private_saved_targets;
        let mut private_saved_account_data_for_sync = private_saved_account_data;
        use_effect(move || {
            let active_strand = selected_channel();
            let snapshot = state_store.read().load();
            let next_shared =
                shared_message_pins_from_raw_operations(&snapshot.raw_operations, &active_strand);
            if *shared_pins_for_sync.peek() != next_shared {
                shared_pins_for_sync.set(next_shared);
            }
            let saved_entries = snapshot.saved_account_data;
            let next_saved_targets = private_saved_targets_from_account_data(
                &saved_entries,
                CHAT_PRIVATE_SAVED_COLLECTION_TITLE,
            );
            if *private_saved_targets_for_sync.peek() != next_saved_targets {
                private_saved_targets_for_sync.set(next_saved_targets);
            }
            if *private_saved_account_data_for_sync.peek() != saved_entries {
                private_saved_account_data_for_sync.set(saved_entries);
            }
        });
    }

    // Connectivity poll: mirror `navigator.onLine` into `is_online` on a
    // short cadence. We poll rather than bind window online/offline events so
    // the signal is owned by the Dioxus runtime; Playwright's
    // `context.setOffline()` flips `navigator.onLine`, which this picks up.
    {
        use_future(move || async move {
            loop {
                let online = navigator_online();
                if *is_online.peek() != online {
                    is_online.set(online);
                }
                // Perf: connectivity is a low-frequency state; 750ms polling was
                // too tight. Relaxed to 2500ms, still reflecting navigator.onLine
                // flips promptly (including Playwright setOffline).
                crate::api::sleep_for(std::time::Duration::from_millis(2_500)).await;
            }
        });
    }

    // Reconnect drain: when connectivity returns and the outbox is non-empty,
    // resubmit each parked message through the normal `ck.message.create`
    // path, then clear it from the queue. Entries reuse their stable local
    // id so the reducer collapses the replay with the optimistic row.
    {
        let base_for_flush = base_url.clone();
        let service_for_flush = plaintext_service_did.clone();
        let account_for_flush = account_did.clone();
        use_effect(move || {
            let online = is_online();
            let pending = chat_outbox.read().clone();
            if !online || pending.is_empty() || *outbox_flushing.peek() {
                return;
            }
            outbox_flushing.set(true);
            let base = base_for_flush.clone();
            let service_did = service_for_flush.clone();
            let account_did = account_for_flush.clone();
            let api_token = token();
            let wait_for = active_sync_token(sync_cursor());
            spawn(async move {
                for entry in pending {
                    let projection = state_store
                        .read()
                        .load()
                        .realm_tree_projections
                        .get(&entry.realm_id)
                        .cloned();
                    let plaintext_services =
                        plaintext_services_for_policy(projection.as_ref(), &service_did);
                    let op = match chat_message_create_operation(
                        &entry.realm_id,
                        &account_did,
                        &entry.strand_id,
                        &entry.channel_kind,
                        &entry.message_id,
                        &entry.body,
                        &[],
                        entry.reply_to.as_deref(),
                    ) {
                        Ok(op) => op,
                        Err(error) => {
                            status_msg.set(format!("outbox flush failed: {error:#}"));
                            continue;
                        }
                    };
                    match submit_chat_operation_with_auth_refresh(
                        &base,
                        &account_did,
                        &entry.realm_id,
                        api_token.clone(),
                        wait_for.clone(),
                        &plaintext_services,
                        &op,
                    )
                    .await
                    {
                        Ok(resp) => {
                            if let Some(found) = messages
                                .write()
                                .iter_mut()
                                .find(|candidate| candidate.id == entry.message_id)
                            {
                                found.id = resp.event_id.clone();
                                found.pending = false;
                                found.failed = false;
                                found.error = None;
                            }
                            frontier_state.set(resp.event_id.clone());
                            chat_outbox
                                .write()
                                .retain(|queued| queued.message_id != entry.message_id);
                            let remaining = chat_outbox.read().clone();
                            save_outbox(&account_did, &remaining);
                            status_msg.set(crate::i18n::tr("chat.outbox.flushed"));
                        }
                        Err(error) => {
                            // Leave the entry queued for the next reconnect
                            // tick; surface the failure but don't drop the
                            // message.
                            status_msg.set(format!("outbox flush retry pending: {error:#}"));
                        }
                    }
                }
                outbox_flushing.set(false);
            });
        });
    }
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
        .find(|channel| channel.strand_id == selected_channel_value)
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
    let selected_realm_pending_mls_binding = state_store
        .read()
        .realm_has_pending_mls_binding(&selected_realm_id);
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
            msg.strand_id == selected_channel_value
                && (selected_realm_id.trim().is_empty() || msg.realm_id == selected_realm_id)
        })
        .cloned()
        .collect::<Vec<_>>();
    let visible_moderation_appeal_prompts = moderation_appeal_prompts()
        .into_iter()
        .filter(|prompt| {
            selected_realm_id.trim().is_empty() || prompt.realm_id == selected_realm_id
        })
        .collect::<Vec<_>>();
    // CKP-0007 P3B.2.4 — per-strand Circle-scope lookup used by the
    // message accent rail. We index by `strand_id` once instead of
    // searching the `channels` Vec for every rendered message.
    let strand_scope_lookup: std::collections::BTreeMap<String, StrandScopeCircle> = all_channels
        .iter()
        .filter_map(|channel| {
            channel
                .scope_circle
                .clone()
                .map(|circle| (channel.strand_id.clone(), circle))
        })
        .collect();
    let visible_message_count = visible_messages.len();
    // Perf: prebuild lookup sets for the message-render hot path. Previously each
    // message ran a full `.iter().any()` over `shared_pins`/`chat_outbox`
    // (O(messages x N)) and repeatedly cloned `private_saved_targets`. Materialize
    // them once as HashSets here so the loop body does O(1) lookups.
    let pinned_target_set: std::collections::HashSet<String> = shared_pins()
        .iter()
        .map(|pin| pin.target_ref.clone())
        .collect();
    let outbox_message_id_set: std::collections::HashSet<String> = chat_outbox()
        .iter()
        .map(|queued| queued.message_id.clone())
        .collect();
    // `private_saved_targets` is itself a BTreeSet; clone it once for reuse in the
    // loop instead of triggering a full-set clone per message.
    let private_saved_target_set = private_saved_targets();
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
        let should_send_receipt = {
            let store = state_store.read();
            chat_visible_read_receipt_should_send(
                &store,
                &selected_channel_value,
                &selected_realm_id,
            )
        };
        // Post the visible read receipt through the canonical
        // ephemeral channel; local marker state keeps the rendered
        // testid surface stable while server projection catches up.
        if should_send_receipt {
            let base = base_url.clone();
            let realm = selected_realm_id.clone();
            let event_id = top_event.clone();
            let actor = account_did.clone();
            let device = device_id.clone();
            let strand_id = if selected_channel_value.trim().is_empty() {
                default_discussion_strand_id(&realm)
            } else {
                selected_channel_value.clone()
            };
            let api_token = token();
            spawn(async move {
                let _ =
                    crate::views::helpers::with_authed_api(&base, api_token, |api| async move {
                        api.send_receipt(
                            &realm,
                            &actor,
                            &device,
                            &strand_id,
                            &event_id,
                            "ck.receipt.read",
                        )
                        .await
                    })
                    .await;
            });
        }
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
        let mut agent_metadata = agent_metadata_from_raw_operations(
            &state_store.read().load().raw_operations,
            &selected_realm_id,
        );
        merge_agent_metadata_maps(
            &mut agent_metadata,
            agent_metadata_from_mentions(&all_messages_snapshot),
        );
        upsert_agent_participants(&mut participants, &agent_metadata, &account_did);
        annotate_agent_participants_with_metadata(&mut participants, &agent_metadata);
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
        let strand = if selected_channel_value.trim().is_empty() {
            default_discussion_strand_id(&realm)
        } else {
            selected_channel_value.clone()
        };
        let participants_for_sync = participant_dids_for_presence.clone();
        let mut typing_actors_for_sync = typing_actors;
        let mut typing_next_expires_at_ms_for_sync = typing_next_expires_at_ms;
        let mut presence_states_for_sync = presence_states;
        let mut presence_labels_for_sync = presence_labels;
        let mut presence_status_messages_for_sync = presence_status_messages;
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
            let active_typing = typing_actor_snapshot_from_sync_realms(
                &snapshot.realm_tree_projections,
                &realm,
                &strand,
                &actor,
            );
            if typing_actors_for_sync.peek().as_slice() != active_typing.actors.as_slice() {
                typing_actors_for_sync.set(active_typing.actors.clone());
            }
            if *typing_next_expires_at_ms_for_sync.peek() != active_typing.next_expires_at_ms {
                typing_next_expires_at_ms_for_sync.set(active_typing.next_expires_at_ms);
            }

            let (next_presence, next_labels, next_status_messages) =
                presence_maps_from_sync_events(
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
                    (
                        next_presence,
                        next_labels,
                        std::collections::BTreeMap::new(),
                    )
                });
            if *presence_states_for_sync.peek() != next_presence {
                presence_states_for_sync.set(next_presence);
            }
            if *presence_labels_for_sync.peek() != next_labels {
                presence_labels_for_sync.set(next_labels);
            }
            if *presence_status_messages_for_sync.peek() != next_status_messages {
                presence_status_messages_for_sync.set(next_status_messages);
            }
        });
    }
    {
        let mut typing_actors_for_expiry = typing_actors;
        let mut typing_next_expires_at_ms_for_expiry = typing_next_expires_at_ms;
        use_effect(move || {
            let Some(expires_at_ms) = typing_next_expires_at_ms_for_expiry() else {
                return;
            };
            let delay_ms =
                (expires_at_ms - chrono::Utc::now().timestamp_millis()).max(0) as u64 + 50;
            spawn(async move {
                crate::api::sleep_for(std::time::Duration::from_millis(delay_ms)).await;
                if *typing_next_expires_at_ms_for_expiry.peek() == Some(expires_at_ms) {
                    typing_actors_for_expiry.set(Vec::new());
                    typing_next_expires_at_ms_for_expiry.set(None);
                }
            });
        });
    }

    if !initial_sync_requested() && !token().trim().is_empty() {
        initial_sync_requested.set(true);
        initial_sync_finished.set(false);
        let base = base_url.clone();
        let api_token = token();
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
            selected_channel.set(first_channel.strand_id.clone());
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
            // The bootstrap snapshot must NOT carry a `wait_for` frontier. On
            // wasm the subscribe response is read as a single buffered body
            // (account.rs cannot frame-read NDJSON in the browser), so a
            // `wait_for` header makes the server hold the stream open until the
            // cursor advances — on a quiet realm that never returns and the
            // discussion feed is stuck on "Loading…". The ongoing delta sync
            // (sync_engine::run_iteration) omits `wait_for` for the same reason;
            // read-your-writes only applies after a local write (outbox flush).
            let Ok(api) = authed_api_with_sync(&base, api_token, None) else {
                initial_sync_finished_for_load.set(true);
                return;
            };
            let mut loaded_messages = Vec::new();
            let mut loaded_poll_cards = Vec::new();
            let mut loaded_moderation_appeal_prompts = Vec::new();
            if let Ok(account) = api.account_me().await
                && account.did == account_did_for_load
                && let Some(display_name) =
                    account_handle_display_from_server(&account.handle, &base).or_else(|| {
                        clean_participant_display_name(
                            account.display_name.as_deref().unwrap_or(""),
                            Some(&account_did_for_load),
                        )
                    })
            {
                account_display_name_for_load.set(display_name);
            }
            if let Ok(sync) = api.account_subscribe_snapshot(None).await {
                {
                    let mut store = state_store.write();
                    store.save_sync_cursor(sync.cursor.clone());
                    store.save_presence_projection(sync.presence.clone());
                    for (realm_id, projection) in &sync.realms {
                        store.save_realm_tree_projection(realm_id.clone(), projection.clone());
                    }
                    crate::disappearing::shred_expired_message_plaintext_from_sync_realms(
                        &mut store,
                        &sync.realms,
                    );
                }
                crate::sync_engine::prefetch_persistent_event_sender_keys(&api, &sync, did_cache)
                    .await;
                loaded_messages.extend(chat_messages_from_sync_realms_with_sidecar(
                    &sync.realms,
                    Some(&state_store.read()),
                    decrypt_identity,
                ));
                loaded_poll_cards.extend(poll_cards_from_sync_realms(&sync.realms));
                loaded_moderation_appeal_prompts.extend(
                    moderation_appeal_prompts_from_sync_realms(&sync.realms, &account_did_for_load),
                );
                merge_channels(
                    &mut channels.write(),
                    channels_from_sync_realms(
                        &sync.realms,
                        std::slice::from_ref(&selected_realm_for_load),
                    ),
                );
                sync_cursor.set(sync.cursor);
            }

            if !selected_realm_for_load.trim().is_empty()
                && let Ok(backfill) = api.backfill(&selected_realm_for_load).await
            {
                crate::sync_engine::prefetch_persistent_event_sender_keys_from_values(
                    &api,
                    &backfill.events,
                    did_cache,
                )
                .await;
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
                loaded_moderation_appeal_prompts.extend(moderation_appeal_prompts_from_events(
                    &selected_realm_for_load,
                    &backfill.events,
                    &account_did_for_load,
                ));
            }

            merge_channels(
                &mut channels.write(),
                channels_from_local_state(&state_store.read().load()),
            );
            if selected_channel().trim().is_empty()
                && let Some(first_channel) = channels.read().first()
            {
                selected_channel.set(first_channel.strand_id.clone());
            }
            if !loaded_messages.is_empty() {
                merge_chat_messages(&mut messages.write(), loaded_messages);
            }
            if !loaded_poll_cards.is_empty() {
                merge_poll_cards(&mut poll_cards.write(), loaded_poll_cards);
            }
            if !loaded_moderation_appeal_prompts.is_empty() {
                merge_moderation_appeal_prompts(
                    &mut moderation_appeal_prompts.write(),
                    loaded_moderation_appeal_prompts,
                );
            }
            initial_sync_finished_for_load.set(true);
        });
    }

    // T7.4: safety-net crypto state refresh for rows built without the
    // decrypt-on-read context. The model layer marks attempted decrypt
    // failures as `KeyMissing`; this covers legacy/no-snapshot rows so the
    // user sees a clear missing-key state instead of a spinner forever.
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
        let realm_for_sidecar = selected_realm_id.clone();
        let mut messages_sig = messages;
        use_effect(move || {
            let store = state_store.read();
            if !pending_messages_have_private_plaintext_sidecar(
                messages_sig.peek().as_slice(),
                &store,
                &realm_for_sidecar,
            ) {
                return;
            }
            let mut current = messages_sig.write();
            restore_pending_messages_from_private_plaintext_sidecar(
                current.as_mut_slice(),
                &store,
                &realm_for_sidecar,
            );
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
                            HelpTip { text: "Discussion is the selected Strand's track. The default Strand is always available for this Realm; the alternate filter includes every Strand with a discussion track." }
                        }
                        div { class: "discussion-panel-head-actions",
                            Button {
                                variant: ButtonVariant::Primary,
                                class: "icon-button",
                                "aria-label": crate::i18n::tr("chat.new_strand"),
                                title: crate::i18n::tr("chat.new_strand"),
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
                            "All Strand tracks"
                        }
                    }
                    div { class: "discussion-list", "data-testid": "channel-list",
                        for channel in visible_channels {
                            Button {
                                variant: ButtonVariant::Secondary,
                                class: if channel.strand_id == selected_channel() { "discussion-track-row active" } else { "discussion-track-row" },
                                "data-testid": "channel-item",
                                onclick: {
                                    let id = channel.strand_id.clone();
                                    move |_| selected_channel.set(id.clone())
                                },
                                div { class: "discussion-track-main",
                                    span { class: "discussion-track-name-row",
                                        SecurityStateBadge {
                                            encrypted: channel.security_encrypted.unwrap_or(selected_realm_security_encrypted),
                                            compact: true,
                                            test_id: Some("strand-track-security-state".to_owned()),
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
                    "aria-label": "New Strand",
                    div { class: "discussion-modal",
                        div { class: "discussion-modal-head",
                            div { class: "discussion-title-row",
                                h2 { "New Strand" }
                                HelpTip { text: "Creates an additional Strand. Its discussion track is available from this view; enable the card option when the same Strand should also carry a synthesis track." }
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
                                placeholder: "Strand title",
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
                                            status_msg.set("Strand title is required".to_owned());
                                            return;
                                        }
                                        let category = "general".to_owned();
                                        let summary = new_channel_topic().trim().to_owned();
                                        let create_card = new_channel_create_card();
                                        let strand_id = format!("ck:strand:{}", uuid_v7());
                                        let rank = format!("r{}", chrono::Utc::now().timestamp_millis());
                                        let op = match ck_ops::discussion_strand_create(
                                            &realm,
                                            &actor,
                                            &strand_id,
                                            &title,
                                        ) {
                                            Ok(builder) => {
                                                let mut op = match builder.build_sdk_event("yougen") {
                                                    Ok(event) => event,
                                                    Err(error) => {
                                                        status_msg.set(format!(
                                                            "Could not create Strand proof: {error}"
                                                        ));
                                                        return;
                                                    }
                                                };
                                                if !op.content["object"]
                                                    .get("fields")
                                                    .is_some_and(|fields| fields.is_object())
                                                {
                                                    op.content["object"]["fields"] = json!({});
                                                }
                                                op.content["object"]["fields"]["category"] =
                                                    json!(category.clone());
                                                op.content["object"]["fields"]["has_synthesis"] =
                                                    json!(create_card);
                                                op.content["object"]["rank"] = json!(rank.clone());
                                                if !summary.is_empty() {
                                                    op.content["object"]["summary"] = json!(summary.clone());
                                                }
                                                if !create_card
                                                    && let Some(tracks) = op.content["object"]["tracks"].as_object_mut()
                                                {
                                                    tracks.remove("synthesis");
                                                }
                                                op
                                            }
                                            Err(error) => {
                                                status_msg.set(format!(
                                                    "Could not create Strand: {error}"
                                                ));
                                                return;
                                            }
                                        };
                                        let api_token = token();
                                        let wait_for = active_sync_token(sync_cursor());
                                        let channel_topic = if summary.is_empty() { None } else { Some(summary) };
                                        let base = base.clone();
                                        let realm = realm.clone();
                                        status_msg.set("Creating Strand".to_owned());
                                        let sdk_op = op;
                                        spawn(async move {
                                            match authed_api_with_sync(&base, api_token.clone(), wait_for) {
                                                Ok(api) => match api.submit_sdk_event(&sdk_op).await
                                                    {
                                                        Ok(submitted) => {
                                                            channels.write().push(ChannelEntity {
                                                                strand_id: strand_id.clone(),
                                                                name: title.clone(),
                                                                kind: "discussion".to_owned(),
                                                                category: category.clone(),
                                                                topic: channel_topic.clone(),
                                                                unread: 0,
                                                                is_default: false,
                                                                security_encrypted: None,
                                                                // P3B.2.3 — the new-Strand form
                                                                // currently creates Realm-scoped
                                                                // Strands only; Circle scope
                                                                // selection arrives once the
                                                                // CircleScopePicker is mounted
                                                                // on this form.
                                                                scope_circle: None,
                                                            });
                                                            selected_channel.set(strand_id.clone());
                                                            frontier_state.set(submitted.event_id.clone());
                                                            {
                                                                let mut store = state_store.write();
                                                                // Keep POST /events sync_token out of the persisted
                                                                // account-subscribe cursor; the background sync loop
                                                                // must resume only from /account/subscribe cursors.
                                                                store.append_raw_operation(
                                                                    sdk_event_local_operation_id(&sdk_op).to_owned(),
                                                                    Some(realm.clone()),
                                                                    json!({
                                                                        "strand_id": strand_id,
                                                                        "kind": "ck.strand.create",
                                                                        "title": title,
                                                                        "category": category,
                                                                        "summary": channel_topic,
                                                                        "create_card": create_card,
                                                                        "object": sdk_op.content["object"].clone(),
                                                                        "event_id": submitted.event_id,
                                                                    }),
                                                                );
                                                            }
                                                            status_msg.set("Strand created".to_owned());
                                                            new_channel_name.set(String::new());
                                                            new_channel_topic.set(String::new());
                                                            new_channel_create_card.set(false);
                                                            create_dialog_open.set(false);
                                                        }
                                                        Err(error) => status_msg.set(format!("Strand create failed: {error}")),
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
                                test_id: Some("selected-strand-security-state".to_owned()),
                            }
                            h1 { "{selected_channel_name}" }
                        }
                    }
                    if !embedded {
                    div { class: "discussion-head-actions",
                        // Start a realm-scoped call. `direct_mode` strands map
                        // to a 1:1 call; group strands open an SFU conference.
                        {
                            let realm_for_call = selected_realm_id.clone();
                            let realm_for_video = selected_realm_id.clone();
                            let call_disabled = realm_for_call.trim().is_empty();
                            rsx! {
                                Button {
                                    variant: ButtonVariant::Secondary,
                                    r#type: "button",
                                    "data-testid": "chat-call-voice-button",
                                    disabled: call_disabled,
                                    title: crate::i18n::tr("chat.call.voice"),
                                    onclick: move |_| {
                                        navigator.push(Route::Call {
                                            call_id: String::new(),
                                            peer: String::new(),
                                            realm_id: realm_for_call.clone(),
                                            video: "0".to_owned(),
                                            incoming: "0".to_owned(),
                                        });
                                    },
                                    "\u{1f4de}"
                                }
                                Button {
                                    variant: ButtonVariant::Secondary,
                                    r#type: "button",
                                    "data-testid": "chat-call-video-button",
                                    disabled: call_disabled,
                                    title: crate::i18n::tr("chat.call.video"),
                                    onclick: move |_| {
                                        navigator.push(Route::Call {
                                            call_id: String::new(),
                                            peer: String::new(),
                                            realm_id: realm_for_video.clone(),
                                            video: "1".to_owned(),
                                            incoming: "0".to_owned(),
                                        });
                                    },
                                    "\u{1f4f9}"
                                }
                            }
                        }
                        // T7.2: watch-level fast switcher. Issues a
                        // `ck.strand.watch.set` event on selection. We
                        // optimistically update the local signal first;
                        // a network failure rolls back via status_msg.
                        {
                            let level_now = strand_watch_level();
                            let menu_open = watch_level_menu_open();
                            let level_label = crate::i18n::tr(watch_level_label_key(level_now));
                            let strand_id_for_watch = selected_channel_value.clone();
                            let realm_for_watch = selected_realm_id.clone();
                            let actor_for_watch = account_did.clone();
                            let watch_disabled = strand_id_for_watch.trim().is_empty();
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
                                                            let strand_id_for_click = strand_id_for_watch.clone();
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
                                                                        let prev = strand_watch_level();
                                                                        strand_watch_level.set(option);
                                                                        watch_level_menu_open.set(false);
                                                                        status_msg.set(crate::i18n::tr("chat.watch_level.pending"));
                                                                        let api_token = token();
                                                                        let wait_for = active_sync_token(sync_cursor());
                                                                        let watch_op = match ck_ops::strand_watch_set(
                                                                            &realm_for_click,
                                                                            &actor_for_click,
                                                                            &actor_for_click,
                                                                            &strand_id_for_click,
                                                                            Some(watch_level_wire_value(option)),
                                                                            None,
                                                                        ) {
                                                                            Ok(builder) => builder.build_sdk_event("yougen"),
                                                                            Err(err) => {
                                                                                tracing::warn!("strand_watch_set build failed: {err:#}");
                                                                                strand_watch_level.set(prev);
                                                                                status_msg.set(crate::i18n::tr("chat.watch_level.failed"));
                                                                                return;
                                                                            }
                                                                        };
                                                                        let watch_op = match watch_op {
                                                                            Ok(watch_op) => watch_op,
                                                                            Err(err) => {
                                                                                tracing::warn!("strand_watch_set SDK conversion failed: {err:#}");
                                                                                strand_watch_level.set(prev);
                                                                                status_msg.set(crate::i18n::tr("chat.watch_level.failed"));
                                                                                return;
                                                                            }
                                                                        };
                                                                        let base = base_for_click.clone();
                                                                        spawn(async move {
                                                                            match authed_api_with_sync(&base, api_token, wait_for) {
                                                                                Ok(api) => match api.submit_sdk_event(&watch_op).await {
                                                                                    Ok(_) => {
                                                                                        status_msg.set(crate::i18n::tr("chat.watch_level.saved"));
                                                                                    }
                                                                                    Err(_) => {
                                                                                        // Rollback on failure.
                                                                                        strand_watch_level.set(prev);
                                                                                        status_msg.set(crate::i18n::tr("chat.watch_level.failed"));
                                                                                    }
                                                                                },
                                                                                Err(_) => {
                                                                                    strand_watch_level.set(prev);
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

                // Offline outbox banner. Visible while the browser is offline
                // or the queue is non-empty so the user knows sends are parked
                // and will flush on reconnect (sync/offline-conflict).
                {
                    let queued_count = chat_outbox().len();
                    let online = is_online();
                    rsx! {
                        if !online || queued_count > 0 {
                            div {
                                class: "chat-outbox-banner",
                                "data-testid": "chat-outbox-banner",
                                "data-online": if online { "true" } else { "false" },
                                "data-queued-count": "{queued_count}",
                                role: "status",
                                span { class: "chat-outbox-icon", "\u{23f8}" }
                                span {
                                    if online {
                                        {crate::i18n::tr("chat.outbox.flushing")}
                                    } else {
                                        {crate::i18n::tr("chat.outbox.offline_banner")}
                                    }
                                }
                                span {
                                    class: "chat-outbox-count",
                                    "data-testid": "chat-outbox-count",
                                    "{queued_count}"
                                }
                            }
                        }
                    }
                }

                // Shared pin bar. Source is the `ck.pin.*` shared event
                // projection only; holder-private `ck.saved.v1:*`
                // account-data is rendered on message rows instead.
                {
                    let shared_pins_now = shared_pins();
                    let pinned_view: Vec<(String, String, String)> = shared_pins_now
                        .iter()
                        .filter_map(|pin| {
                            messages_for_reply_lookup
                                .iter()
                                .find(|m| {
                                    m.pin_saved_target_ref() == pin.target_ref
                                        || m.id == pin.target_ref
                                })
                                .map(|m| (m.id.clone(), pin.target_ref.clone(), m.body.clone()))
                        })
                        .collect();
                    rsx! {
                        if !embedded || !pinned_view.is_empty() {
                            div {
                                class: "pinned-bar",
                                "data-testid": "pinned-bar",
                                "data-source": "shared-event",
                                "data-permission": "ck.pin.add ck.pin.remove",
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
                                        for (id, target_ref, body) in pinned_view {
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
                                                        "data-source": "shared-event",
                                                        "data-target-ref": "{target_ref}",
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

                if selected_realm_pending_mls_binding && selected_channel_security_encrypted {
                    div {
                        class: "event warning-banner",
                        "data-testid": "epoch-update-required-banner",
                        role: "alert",
                        "epoch_update_required: membership frontier changed; MLS Remove commit required"
                    }
                }

                // G3.Y2 — typing indicator. Shown when one or more
                // other actors in the active strand have sent a
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
                    for prompt in visible_moderation_appeal_prompts {
                        {
                            let current_state = moderation_prompt_state(&prompt);
                            let api_token = token();
                            rsx! {
                                AppealEntrypoint {
                                    key: "{prompt.decision_ref}",
                                    realm_id: prompt.realm_id.clone(),
                                    appellant: account_did.clone(),
                                    decision_event_id: prompt.decision_ref.clone(),
                                    target_ref: prompt.target_ref.clone(),
                                    base_url: base_url.clone(),
                                    api_token,
                                    current_state,
                                }
                            }
                        }
                    }
                    for msg in visible_messages {
                        {
                            let scope_circle = strand_scope_lookup.get(&msg.strand_id).cloned();
                            let scope_class = if scope_circle.is_some() {
                                " has-circle-accent-rail"
                            } else {
                                ""
                            };
                            let scope_attr = scope_circle
                                .as_ref()
                                .map(|c| c.circle_id.clone())
                                .unwrap_or_default();
                            let message_target_ref = msg.pin_saved_target_ref().to_owned();
                            // O(1) lookup into the prebuilt set, semantically
                            // equivalent to the original `.iter().any(...)`: a pin
                            // matches when target_ref equals the message target_ref or message id.
                            let message_is_pinned = pinned_target_set.contains(&message_target_ref)
                                || pinned_target_set.contains(&msg.id);
                            let message_is_saved_private =
                                private_saved_target_set.contains(&message_target_ref);
                            let message_is_queued_offline =
                                outbox_message_id_set.contains(&msg.id);
                            let sender_is_own =
                                is_own_message_sender(&msg.sender, &account_did);
                            // T7: shared per-message action dispatchers. The hover
                            // action row and the right-click context menu both call
                            // these closures so the two surfaces expose an identical
                            // action set without duplicating the underlying logic.
                            // Signals are `Copy`, so each closure re-shadows the ones
                            // it mutates as a local `mut` copy to stay a plain `Fn`.
                            let reply_action: std::rc::Rc<dyn Fn()> = std::rc::Rc::new({
                                let reply_target =
                                    msg.reply_target_ref().map(ToOwned::to_owned);
                                move || {
                                    let mut reply_to_message = reply_to_message;
                                    if let Some(target) = reply_target.clone() {
                                        reply_to_message.set(Some(target));
                                    }
                                }
                            });
                            let react_action: std::rc::Rc<dyn Fn()> = std::rc::Rc::new({
                                let msg_id = msg.id.clone();
                                move || {
                                    let mut reaction_picker = reaction_picker;
                                    let current = reaction_picker();
                                    reaction_picker.set(if current == Some(msg_id.clone()) {
                                        None
                                    } else {
                                        Some(msg_id.clone())
                                    });
                                }
                            });
                            let edit_action: std::rc::Rc<dyn Fn()> = std::rc::Rc::new({
                                let msg_id = msg.id.clone();
                                let body = msg.body.clone();
                                move || {
                                    let mut editing_message = editing_message;
                                    let mut edit_draft = edit_draft;
                                    editing_message.set(Some(msg_id.clone()));
                                    edit_draft.set(body.clone());
                                }
                            });
                            let redact_action: std::rc::Rc<dyn Fn()> = std::rc::Rc::new({
                                let msg_id = msg.id.clone();
                                move || {
                                    let mut redact_confirm = redact_confirm;
                                    redact_confirm.set(Some(msg_id.clone()));
                                }
                            });
                            // T7: holder-private save, shared between the context
                            // menu and the hover `chat-save-button`. Writes the
                            // `ck.saved.v1:*` account-data entry exactly like the
                            // former inline context-menu handler.
                            let private_save_action: std::rc::Rc<dyn Fn()> = std::rc::Rc::new({
                                let actor_for_saved = account_did.clone();
                                let device_for_saved = device_id.clone();
                                let base_for_saved = base_url.clone();
                                let target_for_saved = message_target_ref.clone();
                                move || {
                                    let mut status_msg = status_msg;
                                    let mut message_context_menu = message_context_menu;
                                    let mut state_store = state_store;
                                    let mut private_saved_targets = private_saved_targets;
                                    let mut private_saved_account_data = private_saved_account_data;
                                    if private_saved_targets().contains(&target_for_saved) {
                                        message_context_menu.set(None);
                                        return;
                                    }
                                    let namespace_key = match load_chat_productivity_namespace_key(
                                        &actor_for_saved,
                                        &device_for_saved,
                                    ) {
                                        Ok(key) => key,
                                        Err(error) => {
                                            status_msg.set(format!("Private save failed: {error:#}"));
                                            message_context_menu.set(None);
                                            return;
                                        }
                                    };
                                    let updated_hlc = Hlc::now("yougen").encode();
                                    let item = match chat_saved_account_data_item(
                                        &namespace_key,
                                        &target_for_saved,
                                        &updated_hlc,
                                    ) {
                                        Ok(item) => item,
                                        Err(error) => {
                                            status_msg.set(format!("Private save failed: {error:#}"));
                                            message_context_menu.set(None);
                                            return;
                                        }
                                    };
                                    let account_data_value =
                                        match crate::account_data::saved_item_account_data_value(&item.value) {
                                            Ok(value) => value,
                                            Err(error) => {
                                                status_msg.set(format!("Private save failed: {error:#}"));
                                                message_context_menu.set(None);
                                                return;
                                            }
                                        };
                                    {
                                        let mut store = state_store.write();
                                        if let Err(error) = store.stage_saved_account_data_item(&item) {
                                            status_msg.set(format!("Private save failed: {error:#}"));
                                            message_context_menu.set(None);
                                            return;
                                        }
                                    }
                                    private_saved_targets.write().insert(target_for_saved.clone());
                                    private_saved_account_data.write().insert(
                                        item.account_data_key.clone(),
                                        account_data_value.clone(),
                                    );
                                    message_context_menu.set(None);
                                    status_msg.set(crate::i18n::tr("message.private_saved"));
                                    let base = base_for_saved.clone();
                                    let api_token = token();
                                    let wait_for = active_sync_token(sync_cursor());
                                    let key_for_submit = item.account_data_key.clone();
                                    spawn(async move {
                                        match authed_api_with_sync(&base, api_token, wait_for) {
                                            Ok(api) => {
                                                if let Err(error) = api
                                                    .set_private_account_data_with_cas(
                                                        &key_for_submit,
                                                        account_data_value,
                                                        None,
                                                    )
                                                    .await
                                                {
                                                    status_msg.set(format!("Private save stayed local: {error}"));
                                                }
                                            }
                                            Err(error) => {
                                                status_msg.set(format!("Private save stayed local: {error}"));
                                            }
                                        }
                                    });
                                }
                            });
                            rsx! {
                        div {
                            key: "{msg.id}",
                            class: {
                                let mut base = if sender_is_own {
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
                                MessageCryptoState::LateRecoveryRejected => "late_recovery_rejected",
                            },
                            // Right-click toggles a context menu with separate
                            // shared pin and holder-private saved actions.
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
                            // the message's enclosing Strand has a
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
                            // Tiny pop-out menu. Shared pin writes durable
                            // `ck.pin.*`; private save writes `ck.saved.v1:*`
                            // through holder-private account-data.
                            // The render condition checks per-message
                            // so only one menu is visible at a time.
                            if message_context_menu().as_deref() == Some(msg.id.as_str()) {
                                div {
                                    class: "message-context-menu",
                                    "data-testid": "message-context-menu",
                                    {
                                        let target_ref = msg.pin_saved_target_ref().to_owned();
                                        let is_pinned = shared_pins()
                                            .iter()
                                            .any(|pin| pin.target_ref == target_ref || pin.target_ref == msg.id);
                                        let is_saved_private =
                                            private_saved_targets().contains(&target_ref);
                                        let realm_for_pin = msg.realm_id.clone();
                                        let strand_for_pin = msg.strand_id.clone();
                                        let actor_for_pin = account_did.clone();
                                        let base_for_pin = base_url.clone();
                                        let target_for_pin = target_ref.clone();
                                        let existing_pin = shared_pins()
                                            .into_iter()
                                            .find(|pin| pin.target_ref == target_for_pin || pin.target_ref == msg.id);
                                        rsx! {
                                            // T7: mirror the hover action row so both
                                            // surfaces expose the same action set. The
                                            // entries reuse the shared per-message
                                            // dispatchers and only add the menu-close
                                            // glue. Hidden for redacted messages, same
                                            // as the hover row.
                                            if !msg.redacted {
                                                Button {
                                                    variant: ButtonVariant::Secondary,
                                                    r#type: "button",
                                                    "data-testid": "message-context-reply-button",
                                                    disabled: msg.reply_target_ref().is_none(),
                                                    onclick: {
                                                        let reply_action = reply_action.clone();
                                                        move |_| {
                                                            (*reply_action)();
                                                            message_context_menu.set(None);
                                                        }
                                                    },
                                                    {crate::i18n::tr("chat.button.reply")}
                                                }
                                                Button {
                                                    variant: ButtonVariant::Secondary,
                                                    r#type: "button",
                                                    "data-testid": "message-context-react-button",
                                                    onclick: {
                                                        let react_action = react_action.clone();
                                                        move |_| {
                                                            (*react_action)();
                                                            message_context_menu.set(None);
                                                        }
                                                    },
                                                    {crate::i18n::tr("chat.button.react")}
                                                }
                                                Button {
                                                    variant: ButtonVariant::Secondary,
                                                    r#type: "button",
                                                    "data-testid": "message-context-edit-button",
                                                    onclick: {
                                                        let edit_action = edit_action.clone();
                                                        move |_| {
                                                            (*edit_action)();
                                                            message_context_menu.set(None);
                                                        }
                                                    },
                                                    {crate::i18n::tr("common.edit")}
                                                }
                                                Button {
                                                    variant: ButtonVariant::Secondary,
                                                    r#type: "button",
                                                    "data-testid": "message-context-redact-button",
                                                    onclick: {
                                                        let redact_action = redact_action.clone();
                                                        move |_| {
                                                            (*redact_action)();
                                                            message_context_menu.set(None);
                                                        }
                                                    },
                                                    {crate::i18n::tr("chat.button.redact")}
                                                }
                                            }
                                            Button {
                                                variant: ButtonVariant::Secondary,
                                                r#type: "button",
                                                "data-testid": "message-shared-pin-button",
                                                "data-source": "shared-event",
                                                "data-permission": if is_pinned { "ck.pin.remove" } else { "ck.pin.add" },
                                                onclick: move |_| {
                                                    let rank = existing_pin
                                                        .as_ref()
                                                        .map(|pin| pin.rank.clone())
                                                        .unwrap_or_else(next_shared_pin_rank);
                                                    let op = if is_pinned {
                                                        shared_message_pin_remove_operation(
                                                            &realm_for_pin,
                                                            &actor_for_pin,
                                                            &strand_for_pin,
                                                            &target_for_pin,
                                                        )
                                                    } else {
                                                        shared_message_pin_add_operation(
                                                            &realm_for_pin,
                                                            &actor_for_pin,
                                                            &strand_for_pin,
                                                            &target_for_pin,
                                                            &rank,
                                                        )
                                                    };
                                                    let op = match op {
                                                        Ok(op) => op,
                                                        Err(error) => {
                                                            status_msg.set(format!("Shared pin failed: {error:#}"));
                                                            message_context_menu.set(None);
                                                            return;
                                                        }
                                                    };
                                                    if is_pinned {
                                                        shared_pins.write().retain(|pin| {
                                                            !(pin.pin_scope_id == strand_for_pin
                                                                && pin.target_ref == target_for_pin)
                                                        });
                                                    } else if !shared_pins().iter().any(|pin| {
                                                        pin.pin_scope_id == strand_for_pin
                                                            && pin.target_ref == target_for_pin
                                                    }) {
                                                        shared_pins.write().push(SharedMessagePin {
                                                            pin_scope_id: strand_for_pin.clone(),
                                                            target_ref: target_for_pin.clone(),
                                                            rank: rank.clone(),
                                                        });
                                                    }
                                                    message_context_menu.set(None);
                                                    status_msg.set(if is_pinned {
                                                        crate::i18n::tr("message.shared_unpin_pending")
                                                    } else {
                                                        crate::i18n::tr("message.shared_pin_pending")
                                                    });
                                                    let base = base_for_pin.clone();
                                                    let api_token = token();
                                                    let wait_for = active_sync_token(sync_cursor());
                                                    let realm_for_store = realm_for_pin.clone();
                                                    let strand_for_store = strand_for_pin.clone();
                                                    let target_for_store = target_for_pin.clone();
                                                    let existing_for_rollback = existing_pin.clone();
                                                    spawn(async move {
                                                        match authed_api_with_sync(&base, api_token, wait_for) {
                                                            Ok(api) => match api.submit_sdk_event(&op).await {
                                                                Ok(submitted) => {
                                                                    {
                                                                        let mut store = state_store.write();
                                                                        store.append_raw_operation(
                                                                            sdk_event_local_operation_id(&op).to_owned(),
                                                                            Some(realm_for_store),
                                                                            json!({
                                                                                "event_id": submitted.event_id.clone(),
                                                                                "kind": op.kind.as_str(),
                                                                                "payload": op.content.clone(),
                                                                            }),
                                                                        );
                                                                    }
                                                                    frontier_state.set(submitted.event_id);
                                                                    status_msg.set(if is_pinned {
                                                                        crate::i18n::tr("message.shared_unpinned")
                                                                    } else {
                                                                        crate::i18n::tr("message.shared_pinned")
                                                                    });
                                                                }
                                                                Err(error) => {
                                                                    if is_pinned {
                                                                        if let Some(pin) = existing_for_rollback {
                                                                            shared_pins.write().push(pin);
                                                                        }
                                                                    } else {
                                                                        shared_pins.write().retain(|pin| {
                                                                            !(pin.pin_scope_id == strand_for_store
                                                                                && pin.target_ref == target_for_store)
                                                                        });
                                                                    }
                                                                    status_msg.set(format!("Shared pin failed: {error}"));
                                                                }
                                                            },
                                                            Err(error) => {
                                                                if is_pinned {
                                                                    if let Some(pin) = existing_for_rollback {
                                                                        shared_pins.write().push(pin);
                                                                    }
                                                                } else {
                                                                    shared_pins.write().retain(|pin| {
                                                                        !(pin.pin_scope_id == strand_for_store
                                                                            && pin.target_ref == target_for_store)
                                                                    });
                                                                }
                                                                status_msg.set(format!("Shared pin failed: {error}"));
                                                            }
                                                        }
                                                    });
                                                },
                                                if is_pinned {
                                                    {crate::i18n::tr("message.shared_unpin")}
                                                } else {
                                                    {crate::i18n::tr("message.shared_pin")}
                                                }
                                            }
                                            Button {
                                                variant: ButtonVariant::Secondary,
                                                r#type: "button",
                                                disabled: is_saved_private,
                                                "data-testid": "message-private-save-button",
                                                "data-source": "private-account-data",
                                                "data-account-data-prefix": "ck.saved.v1",
                                                // T7: delegates to the shared dispatcher
                                                // (also used by the hover
                                                // `chat-save-button`); it handles the
                                                // already-saved early-return and closes
                                                // the menu itself.
                                                onclick: {
                                                    let private_save_action = private_save_action.clone();
                                                    move |_| (*private_save_action)()
                                                },
                                                if is_saved_private {
                                                    {crate::i18n::tr("message.private_saved")}
                                                } else {
                                                    {crate::i18n::tr("message.private_save")}
                                                }
                                            }
                                            Button {
                                                variant: ButtonVariant::Secondary,
                                                r#type: "button",
                                                onclick: move |_| {
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
                                        "data-source": "shared-event",
                                        "data-target-ref": "{message_target_ref}",
                                        "aria-label": crate::i18n::tr("message.shared_pin"),
                                        title: crate::i18n::tr("message.shared_pin"),
                                        onclick: {
                                            let msg_id = msg.id.clone();
                                            move |_| {
                                                message_context_menu.set(Some(msg_id.clone()));
                                            }
                                        },
                                        UiIcon { name: "pin" }
                                    }
                                }
                                if message_is_saved_private {
                                    span {
                                        class: "message-private-saved-indicator",
                                        "data-testid": "message-private-saved-indicator",
                                        "data-source": "private-account-data",
                                        "data-account-data-prefix": "ck.saved.v1",
                                        "data-target-ref": "{message_target_ref}",
                                        title: crate::i18n::tr("message.private_saved"),
                                        UiIcon { name: "check" }
                                    }
                                }
                                div { class: "msg-head",
                                    span { class: "name", "{sender_display_label(&msg.sender, &account_did, &account_display_label, &participants_for_messages)}" }
                                    if sender_is_own {
                                        SelfAttributionBadge {
                                            class: Some("message-self-badge".to_owned()),
                                            test_id: Some("message-self-badge".to_owned()),
                                        }
                                    }
                                    {
                                        let sender_participant = participants_for_messages
                                            .iter()
                                            .find(|p| p.did == msg.sender);
                                        let sender_is_agent = sender_participant
                                            .map(|participant| participant.is_agent)
                                            .unwrap_or(false);
                                        let sender_agent_owner = sender_participant
                                            .and_then(|participant| {
                                                agent_controller_label(
                                                    participant,
                                                    &participants_for_messages,
                                                )
                                            });
                                        // CKP-0008 §4.10 — act-on-behalf: the
                                        // controller (actor_id = msg.sender) is
                                        // the primary name, the agent executor
                                        // (executed_by) renders as "via {agent}".
                                        let act_on_behalf_agent = act_on_behalf_agent_label(
                                            &msg.sender,
                                            msg.executed_by.as_deref(),
                                            &participants_for_messages,
                                        );
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
                                            if let Some(owner_label) = sender_agent_owner {
                                                span {
                                                    class: "agent-owner-label",
                                                    "data-testid": "message-agent-owner",
                                                    "agent of {owner_label}"
                                                }
                                            }
                                            if let Some(agent_label) = act_on_behalf_agent {
                                                span {
                                                    class: "agent-via-label",
                                                    "data-testid": "message-act-on-behalf-via",
                                                    "data-executed-by": msg.executed_by.clone().unwrap_or_default(),
                                                    "via {agent_label}"
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
                                    } else if msg.pending && message_is_queued_offline {
                                        // Parked in the offline outbox: distinct
                                        // from the in-flight "Sending" spinner so
                                        // the user (and E2E) can tell a message is
                                        // waiting for connectivity, not the server.
                                        span {
                                            class: "message-status-icon is-queued-offline",
                                            "data-testid": "message-send-status",
                                            "data-send-state": "queued_offline",
                                            title: crate::i18n::tr("chat.outbox.queued_offline"),
                                            "\u{23f8}"
                                        }
                                    } else if msg.pending {
                                        span {
                                            class: "message-status-icon is-pending",
                                            "data-testid": "message-send-status",
                                            "data-send-state": "sending",
                                            title: "Sending"
                                        }
                                    }
                                    if msg.edited {
                                        span {
                                            class: "badge",
                                            "data-testid": "message-write-status",
                                            "data-revision-count": "{msg.revisions.len()}",
                                            title: crate::i18n::tr("chat.message.write_status"),
                                            {
                                                format!(
                                                    "{} ({})",
                                                    crate::i18n::tr("chat.message.revised"),
                                                    msg.revisions.len(),
                                                )
                                            }
                                        }
                                    }
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
                                        MessageCryptoState::LateRecoveryRejected => {
                                            // T6: map the raw protocol reason code to a
                                            // human-readable explanation. All known
                                            // `late_recovery_*` reason codes share the
                                            // late-recovery copy; anything else falls back
                                            // to a generic undecryptable message. The raw
                                            // code stays available in the tooltip for
                                            // debugging/support.
                                            let raw_code = msg
                                                .error
                                                .as_deref()
                                                .unwrap_or("late_recovery_rejected")
                                                .to_owned();
                                            let friendly = if raw_code.starts_with("late_recovery") {
                                                crate::i18n::tr("chat.crypto.late_recovery_rejected")
                                            } else {
                                                crate::i18n::tr("chat.crypto.undecryptable_generic")
                                            };
                                            rsx! {
                                                div {
                                                    class: "crypto-status-row crypto-status-late-recovery-rejected",
                                                    "data-testid": "crypto-status-late-recovery-rejected",
                                                    title: "{raw_code}",
                                                    span { class: "crypto-status-icon", "\u{26a0}" }
                                                    span { {friendly} }
                                                }
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
                                        "data-testid": "message-blocked-row",
                                        {crate::i18n::tr("message.blocked_user")}
                                    }
                                    Button {
                                        variant: ButtonVariant::Secondary,
                                        "data-testid": "message-blocked-show-anyway",
                                        onclick: {
                                            let eid = msg.id.clone();
                                            move |_| {
                                                blocked_show_anyway.write().insert(eid.clone());
                                            }
                                        },
                                        {crate::i18n::tr("message.show_anyway")}
                                    }
                                } else {
                                    div { class: "msg-content", "data-testid": "event-body",
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
                                                let strand_id = msg.strand_id.clone();
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
                                                        found.protocol_message_id =
                                                            Some(retry_message_id.clone());
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
                                                    let strand_id_for_store = strand_id.clone();
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
                                                        &strand_id,
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
                                                    let mention_values_for_store = mention_nodes_to_values(&mentions);
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
                                                                        sdk_event_local_operation_id(&op).to_owned(),
                                                                        Some(realm_for_record),
                                                                        json!({
                                                                            "event_id": resp.event_id.clone(),
                                                                            "kind": "ck.message.create",
                                                                            "actor_id": actor_for_store,
                                                                            "body": body_for_store,
                                                                            "strand_id": strand_id_for_store,
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
                                            disabled: msg.reply_target_ref().is_none(),
                                            onclick: {
                                                let reply_action = reply_action.clone();
                                                move |_| (*reply_action)()
                                            },
                                            {crate::i18n::tr("chat.button.reply")}
                                        }
                                        Button {
                                            variant: ButtonVariant::Secondary,
                                            class: "chat-message-action",
                                            "data-testid": "chat-react-button",
                                            onclick: {
                                                let react_action = react_action.clone();
                                                move |_| (*react_action)()
                                            },
                                            {crate::i18n::tr("chat.button.react")}
                                        }
                                        Button {
                                            variant: ButtonVariant::Secondary,
                                            class: "chat-message-action",
                                            "data-testid": "chat-edit-button",
                                            onclick: {
                                                let edit_action = edit_action.clone();
                                                move |_| (*edit_action)()
                                            },
                                            {crate::i18n::tr("common.edit")}
                                        }
                                        Button {
                                            variant: ButtonVariant::Secondary,
                                            class: "chat-message-action",
                                            "data-testid": "chat-redact-button",
                                            onclick: {
                                                let redact_action = redact_action.clone();
                                                move |_| (*redact_action)()
                                            },
                                            {crate::i18n::tr("chat.button.redact")}
                                        }
                                        // Shared-pin toggle exposed directly on the
                                        // hover action row (mirrors the right-click
                                        // context-menu pin), so E2E and keyboard
                                        // users can pin without the native menu.
                                        // Writes the same durable `ck.pin.*` events.
                                        {
                                            let realm_for_pin = msg.realm_id.clone();
                                            let strand_for_pin = msg.strand_id.clone();
                                            let actor_for_pin = account_did.clone();
                                            let base_for_pin = base_url.clone();
                                            let target_for_pin = message_target_ref.clone();
                                            let msg_id_for_pin = msg.id.clone();
                                            let is_pinned = message_is_pinned;
                                            let existing_pin = shared_pins()
                                                .into_iter()
                                                .find(|pin| {
                                                    pin.target_ref == target_for_pin
                                                        || pin.target_ref == msg_id_for_pin
                                                });
                                            rsx! {
                                                Button {
                                                    variant: ButtonVariant::Secondary,
                                                    class: "chat-message-action",
                                                    "data-testid": "chat-pin-button",
                                                    "data-source": "shared-event",
                                                    "data-pinned": if is_pinned { "true" } else { "false" },
                                                    "data-permission": if is_pinned { "ck.pin.remove" } else { "ck.pin.add" },
                                                    onclick: move |_| {
                                                        let rank = existing_pin
                                                            .as_ref()
                                                            .map(|pin| pin.rank.clone())
                                                            .unwrap_or_else(next_shared_pin_rank);
                                                        let op = if is_pinned {
                                                            shared_message_pin_remove_operation(
                                                                &realm_for_pin,
                                                                &actor_for_pin,
                                                                &strand_for_pin,
                                                                &target_for_pin,
                                                            )
                                                        } else {
                                                            shared_message_pin_add_operation(
                                                                &realm_for_pin,
                                                                &actor_for_pin,
                                                                &strand_for_pin,
                                                                &target_for_pin,
                                                                &rank,
                                                            )
                                                        };
                                                        let op = match op {
                                                            Ok(op) => op,
                                                            Err(error) => {
                                                                status_msg.set(format!("Shared pin failed: {error:#}"));
                                                                return;
                                                            }
                                                        };
                                                        if is_pinned {
                                                            shared_pins.write().retain(|pin| {
                                                                !(pin.pin_scope_id == strand_for_pin
                                                                    && pin.target_ref == target_for_pin)
                                                            });
                                                        } else if !shared_pins().iter().any(|pin| {
                                                            pin.pin_scope_id == strand_for_pin
                                                                && pin.target_ref == target_for_pin
                                                        }) {
                                                            shared_pins.write().push(SharedMessagePin {
                                                                pin_scope_id: strand_for_pin.clone(),
                                                                target_ref: target_for_pin.clone(),
                                                                rank: rank.clone(),
                                                            });
                                                        }
                                                        status_msg.set(if is_pinned {
                                                            crate::i18n::tr("message.shared_unpin_pending")
                                                        } else {
                                                            crate::i18n::tr("message.shared_pin_pending")
                                                        });
                                                        let base = base_for_pin.clone();
                                                        let api_token = token();
                                                        let wait_for = active_sync_token(sync_cursor());
                                                        let realm_for_store = realm_for_pin.clone();
                                                        let strand_for_store = strand_for_pin.clone();
                                                        let target_for_store = target_for_pin.clone();
                                                        let existing_for_rollback = existing_pin.clone();
                                                        spawn(async move {
                                                            match authed_api_with_sync(&base, api_token, wait_for) {
                                                                Ok(api) => match api.submit_sdk_event(&op).await {
                                                                    Ok(submitted) => {
                                                                        {
                                                                            let mut store = state_store.write();
                                                                            store.append_raw_operation(
                                                                                sdk_event_local_operation_id(&op).to_owned(),
                                                                                Some(realm_for_store),
                                                                                json!({
                                                                                    "event_id": submitted.event_id.clone(),
                                                                                    "kind": op.kind.as_str(),
                                                                                    "payload": op.content.clone(),
                                                                                }),
                                                                            );
                                                                        }
                                                                        frontier_state.set(submitted.event_id);
                                                                        status_msg.set(if is_pinned {
                                                                            crate::i18n::tr("message.shared_unpinned")
                                                                        } else {
                                                                            crate::i18n::tr("message.shared_pinned")
                                                                        });
                                                                    }
                                                                    Err(error) => {
                                                                        if is_pinned {
                                                                            if let Some(pin) = existing_for_rollback {
                                                                                shared_pins.write().push(pin);
                                                                            }
                                                                        } else {
                                                                            shared_pins.write().retain(|pin| {
                                                                                !(pin.pin_scope_id == strand_for_store
                                                                                    && pin.target_ref == target_for_store)
                                                                            });
                                                                        }
                                                                        status_msg.set(format!("Shared pin failed: {error}"));
                                                                    }
                                                                },
                                                                Err(error) => {
                                                                    if is_pinned {
                                                                        if let Some(pin) = existing_for_rollback {
                                                                            shared_pins.write().push(pin);
                                                                        }
                                                                    } else {
                                                                        shared_pins.write().retain(|pin| {
                                                                            !(pin.pin_scope_id == strand_for_store
                                                                                && pin.target_ref == target_for_store)
                                                                        });
                                                                    }
                                                                    status_msg.set(format!("Shared pin failed: {error}"));
                                                                }
                                                            }
                                                        });
                                                    },
                                                    if is_pinned {
                                                        {crate::i18n::tr("message.shared_unpin")}
                                                    } else {
                                                        {crate::i18n::tr("message.shared_pin")}
                                                    }
                                                }
                                            }
                                        }
                                        // T7: holder-private save exposed on the hover
                                        // action row, mirroring the context-menu entry.
                                        // Both delegate to the shared dispatcher.
                                        Button {
                                            variant: ButtonVariant::Secondary,
                                            class: "chat-message-action",
                                            disabled: message_is_saved_private,
                                            "data-testid": "chat-save-button",
                                            "data-source": "private-account-data",
                                            "data-account-data-prefix": "ck.saved.v1",
                                            onclick: {
                                                let private_save_action = private_save_action.clone();
                                                move |_| (*private_save_action)()
                                            },
                                            if message_is_saved_private {
                                                {crate::i18n::tr("message.private_saved")}
                                            } else {
                                                {crate::i18n::tr("message.private_save")}
                                            }
                                        }
                                    }
                                }
                                // G3.Y2 — per-message read-receipt
                                // indicator. Surfaces the set of actors
                                // who have published a `ck.read_cursor.advance`
                                // covering this message. Empty (`hidden`)
                                // until the receive path is wired.
                                //
                                // TODO(G3.Y2-followup): populate from the
                                // soland sync projection once it carries
                                // per-message `ck.read_cursor.advance`
                                // coverage.
                                {
                                    // TODO(G3.Y2-followup): fill from the
                                    // sync projection read-cursor coverage
                                    // when available. For now the
                                    // list is empty — the testid still
                                    // mounts when there is data so
                                    // cotest can assert against it.
                                    let readers: Vec<String> = Vec::new();
                                    let should_display = {
                                        let store = state_store.read();
                                        chat_visible_read_receipt_should_display(
                                            &store,
                                            &selected_channel_value,
                                            &selected_realm_id,
                                        )
                                    };
                                    if should_display && !readers.is_empty() {
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
                                                    class: "poll-card message-event-poll",
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
                                                            let strand = msg.strand_id.clone();
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
                                                                                let strand = strand.clone();
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
                                                                                    let strand = strand.clone();
                                                                                    let actor = actor.clone();
                                                                                    let poll_ref = card_poll_id.clone();
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
                                                                                                    &strand,
                                                                                                    &poll_ref,
                                                                                                    &[option_id],
                                                                                                )?;
                                                                                                api.submit_sdk_event(&op).await
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
                                                                move |_| {
                                                                    // Spec v1 registers no poll-close carrier
                                                                    // (content-block-poll.schema.json oneOf has only
                                                                    // poll_block / poll_response_block, and no poll
                                                                    // Morph type or close event kind exists) —
                                                                    // closing is a LOCAL view state only and is
                                                                    // never written to the wire.
                                                                    if let Some(found) = poll_cards
                                                                        .write()
                                                                        .iter_mut()
                                                                        .find(|c| c.message_id == card_message_id)
                                                                    {
                                                                        found.close();
                                                                    }
                                                                    status_msg.set("Poll closed in this view".to_owned());
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
                                // Circle-scoped discussion Strand.
                                {
                                    // After a successful promote, the
                                    // resulting private discussion Strand id lives in
                                    // `promoted_targets` keyed by the
                                    // source message id; we render an
                                    // seal row so the parent discussion
                                    // shows the divergence point.
                                    let promoted_to = promoted_targets()
                                        .get(&msg.id)
                                        .cloned();
                                    match promoted_to {
                                        Some(discussion_strand_id) => {
                                            let discussion_strand_id_label = short_protocol_id(&discussion_strand_id);
                                            let discussion_strand_href = format!(
                                                "/chat/{}",
                                                selected_realm_id
                                            );
                                            rsx! {
                                                div {
                                                    class: "discussion-promoted-indicator",
                                                    "data-testid": "discussion-promoted-indicator",
                                                    "data-discussion-strand-id": "{discussion_strand_id}",
                                                    span { "Discussion moved to private Strand " }
                                                    a {
                                                        href: "{discussion_strand_href}",
                                                        title: "{discussion_strand_id}",
                                                        "{discussion_strand_id_label}"
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
                                                        let op = match build_chat_reaction_add_operation(
                                                            state_store,
                                                            &realm,
                                                            &actor,
                                                            &device,
                                                            &msg_id,
                                                            &emoji,
                                                            channel_encrypted,
                                                        ) {
                                                            Ok(Some(op)) => op,
                                                            Ok(None) => {
                                                                status_msg.set(
                                                                    "Reaction skipped: MLS state not ready for this encrypted channel".to_owned(),
                                                                );
                                                                reaction_picker.set(None);
                                                                return;
                                                            }
                                                            Err(error) => {
                                                                status_msg.set(format!("Reaction skipped: {error:#}"));
                                                                reaction_picker.set(None);
                                                                return;
                                                            }
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
                                                                    api.submit_sdk_event(&op).await
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
                                                                    let op = match chat_message_revise_operation(&realm, &actor, &msg_id, &content) {
                                                                        Ok(op) => op,
                                                                        Err(error) => {
                                                                            if let Some(found) = messages.write().iter_mut().find(|candidate| candidate.id == msg_id) {
                                                                                found.pending = false;
                                                                                found.failed = true;
                                                                                found.error = Some(format!("Message update failed: {error:#}"));
                                                                            }
                                                                            status_msg.set(format!("Message update failed: {error:#}"));
                                                                            return;
                                                                        }
                                                                    };
                                                                    match api.submit_sdk_event(&op).await {
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
                                                                    let op = match chat_message_redact_operation(&realm, &actor, &msg_id, "user requested tombstone") {
                                                                        Ok(op) => op,
                                                                        Err(error) => {
                                                                            if let Some(found) = messages.write().iter_mut().find(|candidate| candidate.id == msg_id) {
                                                                                found.pending = false;
                                                                                found.failed = true;
                                                                                found.error = Some(format!("Message removal failed: {error:#}"));
                                                                            }
                                                                            status_msg.set(format!("Message removal failed: {error:#}"));
                                                                            return;
                                                                        }
                                                                    };
                                                                    match api.submit_sdk_event(&op).await {
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
                                    let status_message = presence_status_messages
                                        .read()
                                        .get(&participant.did)
                                        .cloned();
                                    rsx! {
                                        div {
                                            class: "presence-row presence-row-{state_for_class}",
                                            "data-testid": "presence-row",
                                            "data-actor-did": "{did_attr}",
                                            "data-presence-state": "{state}",
                                            span { class: "presence-dot presence-dot-{state}" }
                                            span { class: "presence-name", title: "{did_attr}", "{display}" }
                                            span { class: "muted", " ({state})" }
                                            if let Some(status_message) = status_message {
                                                span {
                                                    class: "muted presence-status-message",
                                                    "data-testid": "presence-status-message",
                                                    " — {status_message}"
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                    div { class: "discussion-detail-section",
                        div { class: "discussion-subhead", span { "Space users" } }
                        for row in participant_roster_rows(&participants) {
                            {
                                match row {
                                    ParticipantRosterRow::Participant(participant) => {
                                        let display_label = participant_roster_display_label(
                                            &state_store.read(),
                                            &participant,
                                        );
                                        rsx! {
                                            DiscussionParticipantRow {
                                                participant,
                                                participants: participants_for_messages.clone(),
                                                display_label,
                                                nested_agent: false,
                                            }
                                        }
                                    }
                                    ParticipantRosterRow::ControllerWithAgents { controller, agents } => {
                                        let display_label = participant_roster_display_label(
                                            &state_store.read(),
                                            &controller,
                                        );
                                        rsx! {
                                            div {
                                                class: "participant-agent-group",
                                                "data-testid": "participant-agent-group",
                                                DiscussionParticipantRow {
                                                    participant: controller,
                                                    participants: participants_for_messages.clone(),
                                                    display_label,
                                                    nested_agent: false,
                                                }
                                                div { class: "participant-agent-children",
                                                    for agent in agents {
                                                        {
                                                            let display_label = participant_roster_display_label(
                                                                &state_store.read(),
                                                                &agent,
                                                            );
                                                            rsx! {
                                                                DiscussionParticipantRow {
                                                                    participant: agent,
                                                                    participants: participants_for_messages.clone(),
                                                                    display_label,
                                                                    nested_agent: true,
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
                let strand_id_for_rr = selected_channel_value.clone();
                let muted_realms_now = state_store.read().muted_realms();
                let realm_is_muted = muted_realms_now.contains(&realm_id_for_mute);
                let rr_default_send = state_store.read().read_receipt_default_send();
                let rr_strand_override =
                    state_store.read().read_receipt_strand_override(&strand_id_for_rr);
                let rr_active = rr_strand_override.unwrap_or(rr_default_send);
                let rr_default_display = state_store.read().read_receipt_default_display();
                let rr_strand_display_override = state_store
                    .read()
                    .read_receipt_strand_display_override(&strand_id_for_rr);
                let rr_display_active = rr_strand_display_override.unwrap_or(rr_default_display);
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
                                    let strand_id = strand_id_for_rr.clone();
                                    move |state: CheckboxState| {
                                        let new_value = bool::from(state);
                                        state_store
                                            .write()
                                            .set_read_receipt_strand_override(
                                                strand_id.clone(),
                                                Some(new_value),
                                            );
                                    }
                                },
                            }
                        }
                        label { class: "settings-row",
                            span { "Show others' read receipts" }
                            Checkbox {
                                "data-testid": "discussion-settings-read-receipts-display",
                                checked: if rr_display_active { CheckboxState::Checked } else { CheckboxState::Unchecked },
                                on_checked_change: {
                                    let strand_id = strand_id_for_rr.clone();
                                    move |state: CheckboxState| {
                                        let new_value = bool::from(state);
                                        state_store
                                            .write()
                                            .set_read_receipt_strand_display_override(
                                                strand_id.clone(),
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
                                        // Optimistic UI: seal the
                                        // promoted indicator before the
                                        // server round-trip completes.
                                        promoted_targets
                                            .write()
                                            .insert(source_id.clone(), ids.discussion_strand_id.clone());
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
                                                        api.submit_sdk_event(&op).await?;
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
            // sealed at the highest event id we've sent a
            // `ck.read_cursor.advance` for; renders only when we have one. The
            // bar appears below the message list so users can see the
            // "everyone read up to here" seal without scrolling
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
                // Strand carries a `scope_circle_id`. The component is
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
                        onkeydown: move |event: KeyboardEvent| {
                            let key = event.key().to_string();
                            let modifiers = event.modifiers();
                            if (modifiers.ctrl() || modifiers.meta()) && key == "Enter" {
                                event.prevent_default();
                                event.stop_propagation();
                                let _ = dioxus::document::eval(
                                    r#"
                                    (() => {
                                      const target = document.activeElement;
                                      const composer =
                                        target instanceof HTMLElement ? target.closest('[data-testid="chat-composer"]') : null;
                                      const button = composer && composer.querySelector('[data-testid="send-chat-button"]');
                                      if (button instanceof HTMLElement) button.click();
                                    })();
                                    "#,
                                );
                            }
                        },
                        oninput: {
                            let base = base_url.clone();
                            let realm = selected_realm_id.clone();
                            let actor = account_did.clone();
                            let typing_device_id = device_id.clone();
                            let selected_strand = selected_channel_value.clone();
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
                                // Typing follows a visibility policy at
                                // least as strict as presence
                                // (profiles-presence.md §3.5): with
                                // `presence_visibility="nobody"` the
                                // client MUST NOT send `ck.typing`,
                                // symmetric with the presence send gate.
                                if !state_store
                                    .read()
                                    .presence_visibility()
                                    .allows_presence_send()
                                {
                                    return;
                                }
                                let base = base.clone();
                                let realm = realm.clone();
                                let actor = actor.clone();
                                let device = typing_device_id.clone();
                                let strand_id = if selected_strand.trim().is_empty() {
                                    default_discussion_strand_id(&realm)
                                } else {
                                    selected_strand.clone()
                                };
                                typing_throttle.on_keystroke(move |is_typing| {
                                    let base = base.clone();
                                    let realm = realm.clone();
                                    let actor = actor.clone();
                                    let device = device.clone();
                                    let strand_id = strand_id.clone();
                                    let api_token = token();
                                    spawn(async move {
                                        let _ = crate::views::helpers::with_authed_api(
                                            &base,
                                            api_token,
                                            |api| async move {
                                                api.send_typing(
                                                    &realm,
                                                    &actor,
                                                    &device,
                                                    &strand_id,
                                                    is_typing,
                                                )
                                                .await
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
                                span { "@{chip.insert_label()}" }
                                if !chip.subtitle.is_empty() {
                                    span { class: "mention-chip-subtitle", "{chip.subtitle}" }
                                }
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
                                        .filter_map(|p| mention_candidate_for_participant(p, &participants_for_messages))
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
                                                            title: "@{candidate.insert_label()}",
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
                                                                        let insert_label = candidate.insert_label();
                                                                        chat_draft.set(format!(
                                                                            "{trimmed}{}@{} ",
                                                                            if needs_space { " " } else { "" },
                                                                            insert_label,
                                                                        ));
                                                                    }
                                                                    mention_picker_state.write().close();
                                                                }
                                                            },
                                                            span { class: "mention-suggestion-name",
                                                                "@{candidate.insert_label()}"
                                                            }
                                                            if !candidate.subtitle.is_empty() {
                                                                span { class: "mention-suggestion-subtitle",
                                                                    "{candidate.subtitle}"
                                                                }
                                                            }
                                                            if candidate.is_agent {
                                                                span {
                                                                    class: "badge member-badge member-badge-agent",
                                                                    "data-testid": "mention-suggestion-agent-badge",
                                                                    {crate::i18n::tr("member.badge.agent")}
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
                                    let selected_strand = selected_channel_value.clone();
                                    move |_| {
                                        let Some(draft_snapshot) = poll_draft.read().clone() else {
                                            return;
                                        };
                                        if !draft_snapshot.is_sendable() {
                                            return;
                                        }
                                        let poll_id = crate::messaging::polls::new_poll_id();
                                        // Build the canonical poll_block op up front (synchronous)
                                        // so the optimistic card can adopt the stamped wire
                                        // message id — the identity later
                                        // `poll_response.poll_ref` votes point at.
                                        let op = match crate::messaging::polls::build_poll_create_op(
                                            &realm,
                                            &actor,
                                            &selected_strand,
                                            &draft_snapshot,
                                        ) {
                                            Ok(op) => op,
                                            Err(error) => {
                                                status_msg.set(format!("Poll send failed: {error}"));
                                                return;
                                            }
                                        };
                                        let message_ref = crate::messaging::polls::poll_message_ref(&op);
                                        let mut card = crate::messaging::polls::PollCard::from_draft(
                                            poll_id.clone(),
                                            &draft_snapshot,
                                        );
                                        if let Some(message_ref) = message_ref.clone() {
                                            card.poll_id = message_ref;
                                        }
                                        // Optimistic UI: surface the
                                        // poll card immediately, then push
                                        // a synthetic ChatMessage so chat
                                        // renders it in place.
                                        poll_cards.write().push(card);
                                        messages.write().push(ChatMessage {
                                            realm_id: realm.clone(),
                                            id: poll_id.clone(),
                                            protocol_message_id: message_ref,
                                            sender: actor.clone(),
                                            executed_by: None,
                                            body: format!("[poll] {}", draft_snapshot.question),
                                            timestamp: chrono::Utc::now().format("%H:%M").to_string(),
                                            strand_id: selected_strand.clone(),
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
                                        let api_token = token();
                                        let poll_id_for_status = poll_id.clone();
                                        spawn(async move {
                                            match crate::views::helpers::with_authed_api(
                                                &base,
                                                api_token,
                                                |api| async move { api.submit_sdk_event(&op).await },
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
                                    let selected_strand = selected_channel_value.clone();
                                    move |_| {
                                        let Some(draft_snapshot) = poll_draft.read().clone() else {
                                            return;
                                        };
                                        if !draft_snapshot.is_sendable() {
                                            return;
                                        }
                                        let poll_id = crate::messaging::polls::new_poll_id();
                                        // Same canonical poll_block flow as the primary
                                        // `poll-create-button` handler above.
                                        let op = match crate::messaging::polls::build_poll_create_op(
                                            &realm,
                                            &actor,
                                            &selected_strand,
                                            &draft_snapshot,
                                        ) {
                                            Ok(op) => op,
                                            Err(error) => {
                                                status_msg.set(format!("Poll send failed: {error}"));
                                                return;
                                            }
                                        };
                                        let message_ref = crate::messaging::polls::poll_message_ref(&op);
                                        let mut card = crate::messaging::polls::PollCard::from_draft(
                                            poll_id.clone(),
                                            &draft_snapshot,
                                        );
                                        if let Some(message_ref) = message_ref.clone() {
                                            card.poll_id = message_ref;
                                        }
                                        poll_cards.write().push(card);
                                        messages.write().push(ChatMessage {
                                            realm_id: realm.clone(),
                                            id: poll_id.clone(),
                                            protocol_message_id: message_ref,
                                            sender: actor.clone(),
                                            executed_by: None,
                                            body: format!("[poll] {}", draft_snapshot.question),
                                            timestamp: chrono::Utc::now().format("%H:%M").to_string(),
                                            strand_id: selected_strand.clone(),
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
                                        let api_token = token();
                                        let poll_id_for_status = poll_id.clone();
                                        spawn(async move {
                                            match crate::views::helpers::with_authed_api(
                                                &base,
                                                api_token,
                                                |api| async move { api.submit_sdk_event(&op).await },
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
                            // Captured for the offline-outbox park branch (keyed
                            // by account so the persisted queue is per-identity).
                            let account_did = account_did.clone();
                            move |_| {
                                let body = chat_draft().trim().to_owned();
                                if body.is_empty() {
                                    return;
                                }
                                if let Err(error) = chat_content_block_for_body(&body) {
                                    status_msg.set(format!("Message send failed: {error:#}"));
                                    return;
                                }
                                let mut mentions = parse_mention_nodes(&body);
                                // G3.Y2 — merge mention picker chips
                                // into the structured mentions list so
                                // the @mention picker counts as a
                                // first-class source (not just typed
                                // `@name` text).
                                {
                                    let picker = mention_picker_state.read().inserted.clone();
                                    for chip in picker {
                                        if !mentions.iter().any(|m| {
                                            m.as_mention().is_some_and(|mention| {
                                                mention.subject_id.as_str() == chip.did
                                            })
                                        }) {
                                            let Ok(subject_id) = cokret_sdk::Did::new(chip.did.clone()) else {
                                                continue;
                                            };
                                            let insert_label = chip.insert_label().to_owned();
                                            let parsed_handle =
                                                (!chip.is_agent).then(|| {
                                                    crate::identity_handle::parse_user_handle(
                                                        &insert_label,
                                                    )
                                                }).flatten();
                                            let mut mention = cokret_sdk::Mention::new(subject_id)
                                                .with_mention_text_original(format!("@{insert_label}"));
                                            if !chip.display_name.trim().is_empty() {
                                                mention = mention
                                                    .with_display_name_at_time(chip.display_name.clone());
                                            }
                                            if let Some(handle) = parsed_handle
                                                .and_then(|parsed| cokret_sdk::Handle::parse(&parsed.handle).ok())
                                            {
                                                mention = mention.with_handle_at_time(handle);
                                            }
                                            if let (Ok(controller_subject_id), Ok(controller_handle)) = (
                                                cokret_sdk::Did::new(chip.controller_subject_id.clone()),
                                                cokret_sdk::Handle::parse(&chip.controller_handle_at_time),
                                            ) && !chip.agent_slug_at_time.trim().is_empty() {
                                                mention = mention.with_agent_selector_metadata(
                                                    controller_subject_id,
                                                    controller_handle,
                                                    chip.agent_slug_at_time.clone(),
                                                );
                                            }
                                            mentions.push(MentionNode::mention(mention));
                                        }
                                    }
                                }
                                let local_id = new_chat_message_id();
                                let channel = channels()
                                    .iter()
                                    .find(|candidate| candidate.strand_id == selected_channel())
                                    .cloned();
                                let Some(channel) = channel else {
                                    status_msg.set("select a discussion first".to_owned());
                                    return;
                                };
                                messages.write().push(ChatMessage {
                                    realm_id: realm.clone(),
                                    id: local_id.clone(),
                                    protocol_message_id: Some(local_id.clone()),
                                    sender: actor.clone(),
                                    executed_by: None,
                                    body: body.clone(),
                                    timestamp: chrono::Utc::now().format("%H:%M").to_string(),
                                    strand_id: channel.strand_id.clone(),
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
                                    // the Send Secure strand may upgrade
                                    // them via a separate `messages.write()`
                                    // patch after `encrypt_payload`.
                                    crypto_state: MessageCryptoState::Plaintext,
                                });

                                // Offline park: when `navigator.onLine` is false
                                // we keep the optimistic row (still `pending`) and
                                // persist the send intent to the outbox instead of
                                // firing the network call. The reconnect effect
                                // drains it. The row renders a "queued" badge
                                // because its id is in `chat_outbox`. Read the
                                // navigator live (not just the polled signal) so a
                                // send right after going offline never races the
                                // poll tick into a failed network attempt.
                                let offline_now = !is_online() || !navigator_online();
                                if offline_now {
                                    if *is_online.peek() {
                                        is_online.set(false);
                                    }
                                    let entry = OutboxMessage {
                                        realm_id: realm.clone(),
                                        strand_id: channel.strand_id.clone(),
                                        channel_kind: channel.kind.clone(),
                                        message_id: local_id.clone(),
                                        body: body.clone(),
                                        reply_to: reply_to_message(),
                                    };
                                    chat_outbox.write().push(entry);
                                    let parked = chat_outbox.read().clone();
                                    save_outbox(&account_did, &parked);
                                    mention_picker_state.write().clear();
                                    chat_draft.set(String::new());
                                    reply_to_message.set(None);
                                    status_msg.set(crate::i18n::tr("chat.outbox.queued_offline"));
                                    return;
                                }

                                let base = base.clone();
                                let service_did = service_did.clone();
                                let realm = realm.clone();
                                let api_token = token();
                                let actor = actor.clone();
                                let strand_id = channel.strand_id.clone();
                                let channel_kind = channel.kind.clone();
                                let message_id = local_id.clone();
                                let reply_to = reply_to_message();
                                // Clear the picker chip list now that
                                // we've folded the mentions into the
                                // pending send state.
                                mention_picker_state.write().clear();
                                let realm_for_record = realm.clone();
                                let actor_for_store = actor.clone();
                                let body_for_store = body.clone();
                                let body_for_restore = body.clone();
                                let body_for_resolve = body.clone();
                                let strand_id_for_store = strand_id.clone();
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
                                    let mut mentions = mentions;
                                    for mention in resolve_agent_selector_mentions(
                                        &base,
                                        api_token.clone(),
                                        wait_for.clone(),
                                        &body_for_resolve,
                                        &realm,
                                        &actor,
                                    )
                                    .await
                                    {
                                        push_unique_mention_node(&mut mentions, mention);
                                    }
                                    if let Some(found) = messages
                                        .write()
                                        .iter_mut()
                                        .find(|candidate| candidate.id == local_id)
                                    {
                                        found.mentions = mentions.clone();
                                    }
                                    let mut op = match chat_message_create_operation(
                                        &realm,
                                        &actor,
                                        &strand_id,
                                        &channel_kind,
                                        &message_id,
                                        &body_for_resolve,
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
                                                found.error =
                                                    Some(format!("send failed: {error:#}"));
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
                                            .filter_map(|m| {
                                                m.as_mention()
                                                    .map(|mention| mention.subject_id.as_str().to_owned())
                                            })
                                            .collect();
                                        let hashes =
                                            crate::messaging::mentions::mention_sidecar_hashes(
                                                &realm,
                                                &mention_dids,
                                            );
                                        if let Some(content) = op
                                            .content
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
                                    let mention_values_for_store = mention_nodes_to_values(&mentions);
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
                                                    sdk_event_local_operation_id(&op).to_owned(),
                                                    Some(realm_for_record),
                                                    json!({
                                                        "event_id": resp.event_id.clone(),
                                                        "kind": "ck.message.create",
                                                        "actor_id": actor_for_store,
                                                        "body": body_for_store,
                                                        "strand_id": strand_id_for_store,
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
                        disabled: selected_realm_pending_mls_binding,
                        onclick: {
                            let base = base_url.clone();
                            let realm = selected_realm_id.clone();
                            let actor = account_did.clone();
                            let selected_strand = selected_channel_value.clone();
                            let pending_mls_binding = selected_realm_pending_mls_binding;
                            move |_| {
                                if pending_mls_binding {
                                    status_msg.set(
                                        "epoch_update_required: membership frontier changed; MLS Remove commit required"
                                            .to_owned(),
                                    );
                                    return;
                                }
                                let body = chat_draft().trim().to_owned();
                                if body.is_empty() {
                                    status_msg.set("Type a message before secure send".to_owned());
                                    return;
                                }
                                // P1: encrypt the canonical Content Block JSON
                                // (`ck.content.text`), NOT the bare body bytes, so
                                // strict receivers can parse the decrypted payload
                                // as `application/vnd.cokret.message+json` and the
                                // decrypt-on-read path round-trips it back to text.
                                let secure_content_block = match chat_content_block_for_body(&body)
                                {
                                    Ok(content) => content,
                                    Err(err) => {
                                        status_msg.set(format!(
                                            "Send Secure rejected message content: {err:#}"
                                        ));
                                        return;
                                    }
                                };
                                let secure_content_value = match sdk_payload_value(
                                    secure_content_block.to_value(),
                                    "chat encrypted content block serialize",
                                ) {
                                    Ok(value) => value,
                                    Err(err) => {
                                        status_msg.set(format!(
                                            "Send Secure could not encode message content: {err:#}"
                                        ));
                                        return;
                                    }
                                };
                                let secure_content_bytes =
                                    match serde_json::to_vec(&secure_content_value) {
                                        Ok(bytes) => bytes,
                                        Err(err) => {
                                            status_msg.set(format!(
                                                "Send Secure could not encode message content: {err}"
                                            ));
                                            return;
                                        }
                                    };
                                let realm = realm.clone();
                                let actor = actor.clone();
                                let strand_id = if selected_strand.trim().is_empty() {
                                    default_discussion_strand_id(&realm)
                                } else {
                                    selected_strand.clone()
                                };
                                // P2: preserve the composer's reply target on the
                                // encrypted path (it was silently dropped before).
                                let reply_to = reply_to_message()
                                    .filter(|value| !value.trim().is_empty());
                                let message_id = new_chat_message_id();
                                messages.write().push(ChatMessage {
                                    realm_id: realm.clone(),
                                    id: message_id.clone(),
                                    protocol_message_id: Some(message_id.clone()),
                                    sender: actor.clone(),
                                    executed_by: None,
                                    body: body.clone(),
                                    timestamp: chrono::Utc::now().format("%H:%M").to_string(),
                                    strand_id: strand_id.clone(),
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
                                let _hlc = Hlc::now("yougen").to_string();
                                let seal_view = state_store.read().seal_view_for_realm(&realm);
                                // Shared MLS core: encrypt → forced ck.mls.commit
                                // envelope (governance / prev→post epoch /
                                // policy_root / membership_frontier) → spec
                                // `ck.schema.encrypted_envelope.v1` wrap →
                                // ck.message.create payload. This mirrors the
                                // shared secure send builder.
                                let secure_build = match crate::views::secure_send::build_secure_send(
                                    state_store,
                                    &seal_view,
                                    &realm,
                                    &actor,
                                    &did,
                                    &strand_id,
                                    &message_id,
                                    reply_to.as_deref(),
                                    &secure_content_bytes,
                                    None,
                                ) {
                                    Ok(build) => build,
                                    Err(message) => {
                                        fail_optimistic_chat_send(
                                            messages,
                                            chat_draft,
                                            status_msg,
                                            &message_id,
                                            &body,
                                            message,
                                        );
                                        return;
                                    }
                                };
                                let base = base.clone();
                                let realm_for_record = realm.clone();
                                let actor_for_audit = actor.clone();
                                let audit_delivered: Vec<String> = secure_build
                                    .member_dids
                                    .iter()
                                    .map(|did| did.as_str().to_owned())
                                    .collect();
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
                                // The synced event carries this exact strand_id
                                // string (the payload was built with
                                // `strand_id_value(&strand_id)`, which wraps it
                                // verbatim), so the read-side sidecar lookup
                                // keyed on the event's `strand_id` matches.
                                let strand_id_for_sidecar = strand_id.clone();
                                let strand_id_for_record = strand_id.clone();
                                let body_for_sidecar = body.clone();
                                // P2: recoverable draft — if the encrypted send
                                // fails we restore the composer text instead of
                                // losing it.
                                let body_for_restore = body.clone();
                                let message_id_for_failure = message_id.clone();
                                // Capture the message op id BEFORE the build is
                                // moved into the shared submitter — the encrypted
                                // raw_operation record (X10.6 sidecar re-key) is
                                // keyed on it.
                                let msg_local_op_id =
                                    crate::operation::sdk_event_local_operation_id(
                                        &secure_build.message_event,
                                    )
                                    .to_owned();
                                spawn(async move {
                                    let Ok(api) = authed_api_with_sync(&base, api_token.clone(), wait_for) else {
                                        // P2: auth/API init failed — without this
                                        // arm the optimistic bubble spun forever
                                        // and no status was shown.
                                        fail_optimistic_chat_send(
                                            messages,
                                            chat_draft,
                                            status_msg,
                                            &message_id_for_failure,
                                            &body_for_restore,
                                            "Send Secure failed: could not start an authenticated session".to_owned(),
                                        );
                                        return;
                                    };
                                    // Shared submit: forced ck.mls.commit first
                                    // (persist-on-accept snapshot + §7.10 backup
                                    // schedule + move record), then the encrypted
                                    // ck.message.create.
                                    let outcome = crate::views::secure_send::submit_secure_send(
                                        &api,
                                        state_store,
                                        secure_build,
                                        &realm_for_record,
                                        &device_for_sidecar_backup,
                                        base.clone(),
                                        token_for_backup_trigger.clone(),
                                        actor_for_backup_trigger.clone(),
                                    )
                                    .await;
                                    let resp = match outcome {
                                        crate::views::secure_send::SecureSendOutcome::Sent {
                                            event_id,
                                            status,
                                        } => (event_id, status),
                                        crate::views::secure_send::SecureSendOutcome::CommitFailed {
                                            message,
                                        }
                                        | crate::views::secure_send::SecureSendOutcome::MessageFailed {
                                            message,
                                        } => {
                                            // P2: reconcile the optimistic bubble so
                                            // it doesn't spin forever, and keep the
                                            // draft recoverable.
                                            fail_optimistic_chat_send(
                                                messages,
                                                chat_draft,
                                                status_msg,
                                                &message_id_for_failure,
                                                &body_for_restore,
                                                message,
                                            );
                                            return;
                                        }
                                    };
                                    let (resp_event_id, resp_status) = resp;
                                    {
                                        let mut store = state_store.write();
                                        // X10.6: persist the message identity
                                        // (message_id + strand_id + actor), NOT the
                                        // plaintext body, into the raw_operation
                                        // record so the tab-switch / reload rebuild
                                        // can reconstruct the sidecar key
                                        // `message:{message_id}` under `strand_id`.
                                        // The body lives only in the account-private
                                        // `mls_private_plaintext` sidecar saved just
                                        // below. `encrypted_content` marks the row as
                                        // E2EE for readers with no sidecar (another
                                        // device / member).
                                        store.append_raw_operation(
                                            msg_local_op_id.clone(),
                                            Some(realm_for_record.clone()),
                                            json!({
                                                "event_id": resp_event_id.clone(),
                                                "kind": "ck.message.create",
                                                "actor_id": actor_for_record.clone(),
                                                "strand_id": strand_id_for_record.clone(),
                                                "message_id": message_id_for_record.clone(),
                                                "encrypted_content": true,
                                                "status": resp_status.clone(),
                                            }),
                                        );
                                        // BUG B (X9): persist the message plaintext
                                        // into the author-owned sidecar so reload / a
                                        // new device can render the author's own
                                        // encrypted messages (OpenMLS forbids an
                                        // author from decrypting their own
                                        // ciphertext). Keyed by `message:{message_id}`
                                        // under the discussion strand, sharing the
                                        // `mls_private_plaintext` map that the X5.3
                                        // cross-device backup already snapshots.
                                        store.save_private_plaintext(
                                            &realm_for_record,
                                            &strand_id_for_sidecar,
                                            &format!("message:{message_id_for_sidecar}"),
                                            &body_for_sidecar,
                                        );
                                    }
                                    // BUG A (X9): clear the optimistic bubble's
                                    // `pending` spinner now that the server accepted
                                    // the encrypted message (mirrors the plaintext
                                    // path). Reconcile the local id to the server
                                    // event_id so the synced copy dedups against this
                                    // echo.
                                    if let Some(found) = messages
                                        .write()
                                        .iter_mut()
                                        .find(|candidate| candidate.id == message_id_for_lookup)
                                    {
                                        found.id = resp_event_id.clone();
                                        found.pending = false;
                                        found.failed = false;
                                        found.error = None;
                                    }
                                    frontier_state.set(resp_event_id.clone());
                                    status_msg.set("Encrypted message sent".to_owned());
                                    crate::components::schedule_mls_private_plaintext_backup_after_encrypted_write(
                                        base_for_backup_trigger.clone(),
                                        token_for_backup_trigger.clone(),
                                        actor_for_backup_trigger.clone(),
                                        device_for_sidecar_backup.clone(),
                                        state_store,
                                    );

                                    // X11.2 — first-write trigger. After this
                                    // encrypted send landed, auto-back up the
                                    // account secret when possible; otherwise
                                    // fall back to the prompt. Best-effort.
                                    if let Some(signal) = backup_trigger_signal {
                                        crate::components::maybe_auto_backup_mls_after_encrypted_write(
                                            base_for_backup_trigger.clone(),
                                            token_for_backup_trigger.clone(),
                                            actor_for_backup_trigger.clone(),
                                            device_for_sidecar_backup.clone(),
                                            state_store,
                                            signal,
                                        )
                                        .await;
                                    }

                                    // Disclosed-audit hardening profile
                                    // (`ck.profile.disclosed_audit.e2ee.v1`): emit a
                                    // per-actor read-your-write receipt right after a
                                    // successful E2EE commit. Actor-private +
                                    // fire-and-forget; non-profile servers store it
                                    // as a regular operation.
                                    let audit_op = build_audit_ryw_receipt(
                                        &realm_for_record,
                                        &actor_for_audit,
                                        &resp_event_id,
                                        audit_delivered.clone(),
                                    )
                                    .build_sdk_event("yougen");
                                    // YOU-02-007: surface a silent receipt failure so
                                    // the sender knows the audit row is missing (the
                                    // message itself sent).
                                    match audit_op {
                                        Ok(audit_op) => {
                                            if let Err(err) = api.submit_sdk_event(&audit_op).await
                                            {
                                                tracing::warn!(
                                                    "audit RYW receipt for {} failed: {err:#}",
                                                    resp_event_id
                                                );
                                                status_msg.set(format!(
                                                    "Message sent; audit receipt failed: {err}"
                                                ));
                                            }
                                        }
                                        Err(err) => {
                                            tracing::warn!(
                                                "audit RYW receipt for {} failed to build: {err:#}",
                                                resp_event_id
                                            );
                                            status_msg.set(format!(
                                                "Message sent; audit receipt failed: {err}"
                                            ));
                                        }
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

#[cfg(test)]
mod tests;
