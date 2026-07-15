use super::*;

#[component]
pub(super) fn ChatEffects(
    controller: ChatController,
    account_did: String,
    device_id: String,
    selected_realm_id: String,
    initial_strand_id: String,
    plaintext_service_id: String,
    sync_cursor: Signal<String>,
    realm_live_epoch: Signal<u64>,
    frontier_state: Signal<String>,
    agent_participation_sync_key: String,
    selected_scope_circle: Option<String>,
    readable_participation_agent_ids: Vec<String>,
    participant_dids_for_presence: Vec<String>,
    account_display_label: String,
    has_remote_presence: bool,
    presence_sync_key: String,
    token: Signal<String>,
) -> Element {
    let base_url = crate::app::SessionContext::base_url_string();
    let mut state_store = crate::app::SessionContext::get().state_store;
    let did_cache = use_context::<Signal<crate::identity::did_resolver::DidResolutionCache>>();
    let selected_channel_value = (controller.selected_channel)();
    let event_sink = ChatProjectionSink::new(controller);

    let channels = controller.channels;
    let mut selected_channel = controller.selected_channel;
    let shared_pins = controller.shared_pins;
    let private_saved_targets = controller.private_saved_targets;
    let private_saved_account_data = controller.private_saved_account_data;
    let is_online = controller.is_online;
    let latest_read_cursor = controller.latest_read_cursor;
    let typing_actors = controller.typing_actors;
    let typing_next_expires_at_ms = controller.typing_next_expires_at_ms;
    let mut presence_announce_key_seen = controller.presence_announce_key_seen;
    let mut presence_heartbeat_tick = controller.presence_heartbeat_tick;
    let mut queued_outbound_message_ids = controller.queued_outbound_message_ids;
    let messages = controller.messages;
    let mut owned_agent_sync_key_seen = controller.owned_agent_sync_key_seen;
    let mut agent_participation_sync_key_seen = controller.agent_participation_sync_key_seen;
    let presence_states = controller.presence_states;
    let presence_labels = controller.presence_labels;
    let presence_status_messages = controller.presence_status_messages;
    let mut presence_sync_key_seen = controller.presence_sync_key_seen;
    let initial_sync_requested = controller.initial_sync_requested;

    {
        let base = base_url.clone();
        let account = account_did.clone();
        use_effect(move || {
            let api_token = token();
            let request_key = account.trim().to_owned();
            if account.trim().is_empty()
                || api_token.trim().is_empty()
                || owned_agent_sync_key_seen.peek().as_str() == request_key
            {
                return;
            }
            owned_agent_sync_key_seen.set(request_key.clone());
            event_sink.emit(ChatProjectionEvent::OwnedAgents(
                std::collections::BTreeMap::new(),
            ));
            let base = base.clone();
            spawn(async move {
                let result = crate::transport::auth::with_authed_sdk_client(
                    &base,
                    api_token,
                    |http| async move {
                        let list = http.agent_list().await?;
                        Ok::<_, anyhow::Error>(crate::views::agents::mentionable_owned_agent_slugs(
                            list.agents,
                        ))
                    },
                )
                .await;
                if owned_agent_sync_key_seen.peek().as_str() == request_key
                    && let Ok(agents) = result
                {
                    event_sink.emit(ChatProjectionEvent::OwnedAgents(agents));
                }
            });
        });
    }

    {
        let realm = selected_realm_id.clone();
        let initial_strand = initial_strand_id.clone();
        use_effect(move || {
            if realm.trim().is_empty() {
                return;
            }
            let desired = discussion_channel_for_strand(&realm, &initial_strand);
            event_sink.emit(ChatProjectionEvent::EnsureChannel(desired));
        });
    }

    {
        let realm = selected_realm_id.clone();
        use_effect(move || {
            let strand = selected_channel();
            let snapshot = state_store.read().load();
            let scope = shared_pin_scope_for_message(&realm, &strand);
            let next_shared =
                shared_message_pins_from_raw_operations(&snapshot.raw_operations, &scope);
            if *shared_pins.peek() != next_shared {
                event_sink.emit(ChatProjectionEvent::SharedPins(next_shared));
            }
            let saved_entries = snapshot.saved_account_data;
            let next_saved = private_saved_targets_from_account_data(
                &saved_entries,
                CHAT_PRIVATE_SAVED_COLLECTION_TITLE,
            );
            if *private_saved_targets.peek() != next_saved
                || *private_saved_account_data.peek() != saved_entries
            {
                event_sink.emit(ChatProjectionEvent::PrivateSaved {
                    targets: next_saved,
                    entries: saved_entries,
                });
            }
        });
    }

    let account_for_connectivity = account_did.clone();
    use_future(move || {
        let account_for_connectivity = account_for_connectivity.clone();
        async move {
            loop {
                let online = navigator_online();
                if *is_online.peek() != online {
                    event_sink.emit(ChatProjectionEvent::Connectivity(online));
                }
                if let Ok(next) = crate::event_submit::pending_chat_outbound_message_ids(
                    &account_for_connectivity,
                )
                .await
                    && *queued_outbound_message_ids.peek() != next
                {
                    queued_outbound_message_ids.set(next);
                }
                crate::runtime_helpers::sleep_for(std::time::Duration::from_millis(2_500)).await;
            }
        }
    });

    let selected_realm_after_initial_sync = selected_realm_id.clone();
    let account_after_initial_sync = account_did.clone();
    let device_after_initial_sync = device_id.clone();
    use_effect(move || {
        let Some(expires_at_ms) = typing_next_expires_at_ms() else {
            return;
        };
        let delay_ms = (expires_at_ms - chrono::Utc::now().timestamp_millis()).max(0) as u64 + 50;
        spawn(async move {
            crate::runtime_helpers::sleep_for(std::time::Duration::from_millis(delay_ms)).await;
            if *typing_next_expires_at_ms.peek() == Some(expires_at_ms) {
                event_sink.emit(ChatProjectionEvent::Typing {
                    actors: Vec::new(),
                    expires_at_ms: None,
                });
            }
        });
    });

    {
        let realm = selected_realm_id.clone();
        let actor = account_did.clone();
        let device = device_id.clone();
        let base = base_url.clone();
        use_effect(move || {
            let strand = selected_channel();
            let top_event = controller
                .messages
                .read()
                .iter()
                .rev()
                .find(|message| {
                    message.strand_id == strand
                        && (realm.trim().is_empty() || message.realm_id == realm)
                        && !message.id.is_empty()
                        && !message.pending
                })
                .map(|message| message.id.clone());
            let Some(top_event) = top_event else {
                return;
            };
            if latest_read_cursor().as_str() == top_event {
                return;
            }
            event_sink.emit(ChatProjectionEvent::ReadCursor(top_event.clone()));
            if !chat_visible_read_receipt_should_send(&state_store.read(), &strand, &realm) {
                return;
            }
            let strand_id = if strand.trim().is_empty() {
                default_discussion_strand_id(&realm)
            } else {
                strand
            };
            let api_token = token();
            let base = base.clone();
            let realm = realm.clone();
            let actor = actor.clone();
            let device = device.clone();
            spawn(async move {
                let _ = crate::transport::auth::with_event_submitter(
                    &base,
                    api_token,
                    |submitter| async move {
                        submitter
                            .send_receipt(
                                &realm,
                                &actor,
                                &device,
                                &strand_id,
                                &top_event,
                                "ak.receipt.read",
                            )
                            .await
                    },
                )
                .await;
            });
        });
    }

    {
        let messages = controller.messages;
        let mut last_scroll_key = use_signal(|| (0_usize, String::new()));
        use_effect(move || {
            let key = (messages.read().len(), selected_channel());
            if last_scroll_key.peek().clone() != key {
                last_scroll_key.set(key);
                scroll_chat_feed_to_latest();
            }
        });
    }

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
                    .set_presence_preference(crate::state::PresencePreferenceState::default());
                preference = crate::state::PresencePreferenceState::default();
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
                let _ = crate::transport::auth::with_event_submitter(
                    &base,
                    api_token,
                    |sub| async move {
                        sub.send_presence(
                            &realm,
                            &actor,
                            &device,
                            &state,
                            status_message.as_deref(),
                            None,
                        )
                        .await
                    },
                )
                .await;
                crate::runtime_helpers::sleep_for(std::time::Duration::from_secs(
                    PRESENCE_HEARTBEAT_SECS,
                ))
                .await;
                let next_tick = (*presence_heartbeat_tick.peek()).wrapping_add(1);
                presence_heartbeat_tick.set(next_tick);
            });
        });
    }

    {
        let base = base_url.clone();
        let realm = selected_realm_id.clone();
        let strand = if selected_channel_value.trim().is_empty() {
            default_discussion_strand_id(&realm)
        } else {
            selected_channel_value.clone()
        };
        let circle = selected_scope_circle.clone();
        let agent_ids = readable_participation_agent_ids.clone();
        use_effect(move || {
            if token().trim().is_empty()
                || realm.trim().is_empty()
                || agent_participation_sync_key_seen.peek().as_str() == agent_participation_sync_key
            {
                return;
            }
            agent_participation_sync_key_seen.set(agent_participation_sync_key.clone());
            // A scope change must fail closed while the new participation
            // snapshot is loading; never reuse the previous strand/circle's
            // visibility decision for this agent list.
            event_sink.emit(ChatProjectionEvent::AgentParticipation(
                std::collections::BTreeMap::new(),
            ));
            if agent_ids.is_empty() {
                return;
            }
            let base = base.clone();
            let realm = realm.clone();
            let strand = strand.clone();
            let circle = circle.clone();
            let agent_ids = agent_ids.clone();
            let api_token = token();
            let request_key = agent_participation_sync_key.clone();
            spawn(async move {
                let result = crate::transport::auth::with_authed_sdk_client(
                    &base,
                    api_token,
                    move |http| async move {
                        let mut visible = std::collections::BTreeMap::new();
                        for agent_id in agent_ids {
                            if let Ok(outcome) = http.agent_participation_get(&agent_id).await {
                                visible.insert(
                                    agent_id,
                                    participation_allows_public_reply(
                                        &outcome.entries,
                                        &realm,
                                        circle.as_deref(),
                                        &strand,
                                    ),
                                );
                            }
                        }
                        Ok::<_, anyhow::Error>(visible)
                    },
                )
                .await;
                if agent_participation_sync_key_seen.peek().as_str() == request_key
                    && let Ok(visible) = result
                {
                    event_sink.emit(ChatProjectionEvent::AgentParticipation(visible));
                }
            });
        });
    }

    {
        let realm = selected_realm_id.clone();
        let actor = account_did.clone();
        let strand = if selected_channel_value.trim().is_empty() {
            default_discussion_strand_id(&realm)
        } else {
            selected_channel_value.clone()
        };
        let participants_for_sync = participant_dids_for_presence.clone();
        let typing_actors_for_sync = typing_actors;
        let typing_next_expires_at_ms_for_sync = typing_next_expires_at_ms;
        let presence_states_for_sync = presence_states;
        let presence_labels_for_sync = presence_labels;
        let presence_status_messages_for_sync = presence_status_messages;
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
            if typing_actors_for_sync.peek().as_slice() != active_typing.actors.as_slice()
                || *typing_next_expires_at_ms_for_sync.peek() != active_typing.next_expires_at_ms
            {
                event_sink.emit(ChatProjectionEvent::Typing {
                    actors: active_typing.actors.clone(),
                    expires_at_ms: active_typing.next_expires_at_ms,
                });
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
            if *presence_states_for_sync.peek() != next_presence
                || *presence_labels_for_sync.peek() != next_labels
                || *presence_status_messages_for_sync.peek() != next_status_messages
            {
                event_sink.emit(ChatProjectionEvent::Presence {
                    states: next_presence,
                    labels: next_labels,
                    status_messages: next_status_messages,
                });
            }
        });
    }
    use_effect(move || {
        if !initial_sync_requested() && !token().trim().is_empty() {
            event_sink.emit(ChatProjectionEvent::InitialSync {
                requested: true,
                finished: false,
            });
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
                event_sink.emit(ChatProjectionEvent::MergeChannels(local_channels));
            }
            if selected_channel().trim().is_empty()
                && let Some(first_channel) = channels.read().first()
            {
                selected_channel.set(first_channel.strand_id.clone());
            }
            if !local_messages.is_empty() {
                event_sink.emit(ChatProjectionEvent::MergeMessages(local_messages));
            }
            if !local_poll_cards.is_empty() {
                event_sink.emit(ChatProjectionEvent::MergePollCards(local_poll_cards));
            }
            let account_did_for_decrypt = account_did.clone();
            let device_id_for_decrypt = device_id.clone();
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
                    event_sink.emit(ChatProjectionEvent::InitialSync {
                        requested: true,
                        finished: true,
                    });
                    return;
                };
                let mut loaded_messages = Vec::new();
                let mut loaded_poll_cards = Vec::new();
                let mut loaded_moderation_appeal_prompts = Vec::new();
                if let Ok(account) =
                    async { crate::transport::account::account_me(&api.sdk_http_client()?).await }
                        .await
                    && account.did == account_did_for_load
                    && let Some(display_name) =
                        account_handle_display_from_server(&account.handle, &base).or_else(|| {
                            clean_participant_display_name(
                                account.display_name.as_deref().unwrap_or(""),
                                Some(&account_did_for_load),
                            )
                        })
                {
                    event_sink.emit(ChatProjectionEvent::AccountDisplayName(display_name));
                }
                if let Ok(http) = api.sdk_http_client()
                    && let Ok(sync) =
                        crate::client_core::account_subscribe_snapshot(&http, None).await
                {
                    {
                        let mut store = state_store.write();
                        store.save_sync_cursor(sync.cursor.clone());
                        store.save_presence_projection(&sync.updates.presence);
                        for (realm_id, projection) in &sync.realm_projections {
                            store.save_realm_tree_projection(realm_id.clone(), projection.clone());
                        }
                        crate::disappearing::shred_expired_message_plaintext_from_sync_realms(
                            &mut store,
                            &sync.realm_projections,
                        );
                    }
                    crate::sync_engine::prefetch_persistent_event_sender_keys(
                        &api,
                        &sync,
                        crate::app::runtime_adapter::value_cell(did_cache),
                        |realm_id| {
                            state_store
                                .read()
                                .realm_projection_is_minimal_metadata(realm_id)
                        },
                    )
                    .await;
                    loaded_messages.extend(chat_messages_from_sync_realms_with_sidecar(
                        &sync.realm_projections,
                        Some(&state_store.read()),
                        decrypt_identity,
                    ));
                    loaded_poll_cards.extend(poll_cards_from_sync_realms(&sync.realm_projections));
                    loaded_moderation_appeal_prompts.extend(
                        moderation_appeal_prompts_from_sync_realms(
                            &sync.realm_projections,
                            &account_did_for_load,
                        ),
                    );
                    event_sink.emit(ChatProjectionEvent::MergeChannels(
                        channels_from_sync_realms(
                            &sync.realm_projections,
                            std::slice::from_ref(&selected_realm_for_load),
                        ),
                    ));
                    sync_cursor.set(sync.cursor);
                }

                if !selected_realm_for_load.trim().is_empty()
                    && let Ok(sub) = api.event_submitter()
                    && let Ok(backfill) = sub.backfill(&selected_realm_for_load).await
                {
                    let backfill_events = backfill.event_values();
                    // §2.10.3 — a minimal-metadata Realm's backfill never primes
                    // the device directory: authors verify against the MLS leaf.
                    let backfill_realm_is_minimal_metadata = state_store
                        .read()
                        .realm_projection_is_minimal_metadata(&selected_realm_for_load);
                    if !backfill_realm_is_minimal_metadata {
                        crate::sync_engine::prefetch_persistent_event_sender_keys_from_values(
                            &api,
                            &backfill_events,
                            crate::app::runtime_adapter::value_cell(did_cache),
                        )
                        .await;
                    }
                    event_sink.emit(ChatProjectionEvent::MergeChannels(channels_from_events(
                        &selected_realm_for_load,
                        &backfill_events,
                    )));
                    loaded_messages.extend(chat_messages_from_events_with_sidecar(
                        &selected_realm_for_load,
                        &backfill_events,
                        Some(&state_store.read()),
                        decrypt_identity,
                    ));
                    loaded_poll_cards.extend(poll_cards_from_events(&backfill_events));
                    loaded_moderation_appeal_prompts.extend(moderation_appeal_prompts_from_events(
                        &selected_realm_for_load,
                        &backfill_events,
                        &account_did_for_load,
                    ));
                }

                event_sink.emit(ChatProjectionEvent::MergeChannels(
                    channels_from_local_state(&state_store.read().load()),
                ));
                if selected_channel().trim().is_empty()
                    && let Some(first_channel) = channels.read().first()
                {
                    selected_channel.set(first_channel.strand_id.clone());
                }
                if !loaded_messages.is_empty() {
                    event_sink.emit(ChatProjectionEvent::MergeMessages(loaded_messages));
                }
                if !loaded_poll_cards.is_empty() {
                    event_sink.emit(ChatProjectionEvent::MergePollCards(loaded_poll_cards));
                }
                if !loaded_moderation_appeal_prompts.is_empty() {
                    event_sink.emit(ChatProjectionEvent::MergeModerationPrompts(
                        loaded_moderation_appeal_prompts,
                    ));
                }
                event_sink.emit(ChatProjectionEvent::InitialSync {
                    requested: true,
                    finished: true,
                });
            });
        }
    });
    let mut local_timeline_sync_key_seen = use_signal(String::new);
    {
        let selected_realm_for_local_timeline = selected_realm_after_initial_sync.clone();
        let account_did_for_local_timeline = account_after_initial_sync.clone();
        let device_id_for_local_timeline = device_after_initial_sync.clone();
        use_effect(move || {
            let cursor = sync_cursor();
            let cursor = cursor.trim();
            let live_epoch = realm_live_epoch();
            if (cursor.is_empty() || cursor == "-") && live_epoch == 0 {
                return;
            }
            let realm = selected_realm_for_local_timeline.trim().to_owned();
            if realm.is_empty() {
                return;
            }
            let sync_key = format!("{realm}|{cursor}|{live_epoch}");
            if local_timeline_sync_key_seen.peek().as_str() == sync_key {
                return;
            }
            local_timeline_sync_key_seen.set(sync_key);
            let next_messages = {
                let store = state_store.read();
                let snapshot = store.load();
                chat_messages_from_local_state_with_sidecar(
                    &snapshot,
                    Some(&store),
                    Some((
                        account_did_for_local_timeline.as_str(),
                        device_id_for_local_timeline.as_str(),
                    )),
                )
                .into_iter()
                .filter(|message| message.realm_id == realm)
                .collect::<Vec<_>>()
            };
            if !next_messages.is_empty() {
                event_sink.emit(ChatProjectionEvent::MergeMessages(next_messages));
            }
        });
    }

    // T7.4: safety-net crypto state refresh for rows built without the
    // decrypt-on-read context. The model layer marks attempted decrypt
    // failures as `KeyMissing`; this covers legacy/no-snapshot rows so the
    // user sees a clear missing-key state instead of a spinner forever.
    {
        let realm_for_crypto = selected_realm_after_initial_sync.clone();
        let messages_sig = messages;
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
                let mut current = messages_sig.peek().clone();
                for msg in current.iter_mut() {
                    if matches!(msg.crypto_state, MessageCryptoState::Decrypting) {
                        msg.crypto_state = MessageCryptoState::KeyMissing;
                    }
                }
                event_sink.emit(ChatProjectionEvent::ReplaceMessages(current));
            }
        });
    }

    {
        let realm_for_sidecar = selected_realm_after_initial_sync.clone();
        let messages_sig = messages;
        use_effect(move || {
            let store = state_store.read();
            if !pending_messages_have_private_plaintext_sidecar(
                messages_sig.peek().as_slice(),
                &store,
                &realm_for_sidecar,
            ) {
                return;
            }
            let mut current = messages_sig.peek().clone();
            restore_pending_messages_from_private_plaintext_sidecar(
                current.as_mut_slice(),
                &store,
                &realm_for_sidecar,
            );
            event_sink.emit(ChatProjectionEvent::ReplaceMessages(current));
        });
    }

    rsx! {}
}
