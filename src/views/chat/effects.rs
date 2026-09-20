use super::*;

const CHAT_INITIAL_BACKFILL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(12);

#[component]
pub(super) fn ChatEffects(
    controller: ChatController,
    authority: arkret_sdk::AccountId,
    principal_id: String,
    device_id: arkret_sdk::DeviceId,
    selected_realm_id: String,
    initial_strand_id: String,
    plaintext_service_id: String,
    sync_cursor: Signal<String>,
    mut realm_live_epoch: Signal<u64>,
    frontier_state: Signal<String>,
    agent_participation_sync_key: String,
    selected_scope_circle: Option<String>,
    readable_participation_agent_ids: Vec<String>,
    participant_ids_for_presence: Vec<String>,
    account_display_label: String,
    has_remote_presence: bool,
    presence_sync_key: String,
    token: Signal<String>,
) -> Element {
    let base_url = crate::app::SessionContext::base_url_string();
    let mut state_store = crate::app::SessionContext::get().state_store;
    super::direct_authority::use_direct_authority(
        base_url.clone(),
        selected_realm_id.clone(),
        authority.clone(),
        token,
        frontier_state,
        state_store,
    );
    super::circle_welcome::use_circle_welcome(
        base_url.clone(),
        selected_realm_id.clone(),
        selected_scope_circle.clone(),
        authority.clone(),
        device_id.clone(),
        token,
        sync_cursor,
        state_store,
    );
    use_eligible_circle_scopes(
        controller,
        base_url.clone(),
        selected_realm_id.clone(),
        principal_id.clone(),
        token,
    );
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
    let mut queued_outbound_local_operation_ids = controller.queued_outbound_local_operation_ids;
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
        let account = principal_id.clone();
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
                            list.agent_projections,
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
        // These route-derived values are plain component props, not Signals.
        // The default Strand is often hydrated asynchronously after Chat first
        // mounts, so make prop changes explicit dependencies; otherwise the
        // one-shot empty value leaves the composer permanently unavailable.
        use_effect(use_reactive(
            (&realm, &initial_strand),
            move |(realm, initial_strand)| {
                if realm.trim().is_empty() {
                    return;
                }
                if let Some(desired) = discussion_channel_for_strand(&initial_strand) {
                    event_sink.emit(ChatProjectionEvent::EnsureChannel(desired));
                }
            },
        ));
    }

    {
        let realm = selected_realm_id.clone();
        use_effect(move || {
            let _live_epoch = realm_live_epoch();
            let _sync_cursor = sync_cursor();
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

    let authority_for_connectivity = authority.clone();
    let realm_for_connectivity = selected_realm_id.clone();
    use_future(move || {
        let authority_for_connectivity = authority_for_connectivity.clone();
        let realm_for_connectivity = realm_for_connectivity.clone();
        async move {
            loop {
                let online = navigator_online();
                if *is_online.peek() != online {
                    event_sink.emit(ChatProjectionEvent::Connectivity(online));
                }
                let strand_for_connectivity = selected_channel();
                if let Ok(next) = crate::event_submit::pending_chat_outbound_local_operation_ids(
                    &authority_for_connectivity,
                    &realm_for_connectivity,
                    &strand_for_connectivity,
                )
                .await
                    && *queued_outbound_local_operation_ids.peek() != next
                {
                    queued_outbound_local_operation_ids.set(next);
                }
                crate::runtime_helpers::sleep_for(std::time::Duration::from_millis(2_500)).await;
            }
        }
    });

    let selected_realm_after_initial_sync = selected_realm_id.clone();
    let account_after_initial_sync = principal_id.clone();
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
        let authority_for_receipt = authority.clone();
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
            if strand.trim().is_empty() {
                return;
            }
            let strand_id = strand;
            let api_token = token();
            let base = base.clone();
            let realm = realm.clone();
            let authority = authority_for_receipt.clone();
            let device = device.clone();
            // No accepted MLS state for the scope means the Signal capability
            // is withdrawn there. v1 has no plaintext read-receipt branch.
            let Ok(material) =
                crate::signal::key_material_for_scope(&state_store.read(), &realm, None)
            else {
                return;
            };
            // The seal burns the SDK-owned nonce counter into the persisted
            // MLS snapshot before submit, so the send path needs the store
            // itself, not just the material descriptor.
            let receipt_store = crate::app::runtime_adapter::state_store_handle(state_store);
            spawn(async move {
                let _ = crate::transport::auth::with_event_submitter(
                    &base,
                    api_token,
                    |submitter| async move {
                        submitter
                            .send_scope_signal(
                                arkret_sdk::ScopeRef::Realm {
                                    realm_id: arkret_sdk::RealmId::new(realm.clone())?,
                                },
                                &authority,
                                &device,
                                &material,
                                &crate::signal::SignalPayload::ReadReceipt {
                                    strand_id: arkret_sdk::StrandId::new(strand_id.clone())?,
                                    event_id: arkret_sdk::EventId::new(top_event.clone())?,
                                },
                                &receipt_store,
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
        let scroll_realm_id = selected_realm_id.clone();
        use_effect(move || {
            let selected_channel_value = selected_channel();
            let key = (messages.read().len(), selected_channel_value.clone());
            if last_scroll_key.peek().clone() != key {
                last_scroll_key.set(key);
                let offset_key = format!("{scroll_realm_id}\u{1f}{selected_channel_value}");
                let scroll_top = super::timeline_surface::chat_feed_scroll_offset(&offset_key);
                if scroll_top > 0.0 {
                    scroll_chat_feed_to_offset(scroll_top);
                } else {
                    scroll_chat_feed_to_latest();
                }
            }
        });
    }

    {
        let base = base_url.clone();
        let realm = selected_realm_id.clone();
        let actor = principal_id.clone();
        let authority_for_presence = authority.clone();
        let device = device_id.clone();
        let mut state_store_for_presence = state_store;
        use_effect(move || {
            let realm = trim_realm_id(&realm);
            let actor = actor.trim().to_owned();
            let authority = authority_for_presence.clone();
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
                    .set_presence_preference(crate::state::PresencePreference::default());
                preference = crate::state::PresencePreference::default();
            }
            let state = preference
                .effective_manual_state(now)
                .unwrap_or(arkret_sdk::PresenceStatus::Online)
                .as_wire()
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
            let base = base.clone();
            // Presence is an ordinary `session` Signal. Without accepted MLS
            // state for the scope the capability is withdrawn; there is no
            // plaintext presence broadcast in v1.
            let Ok(material) = crate::signal::key_material_for_scope(
                &state_store_for_presence.read(),
                &realm,
                None,
            ) else {
                return;
            };
            // Only claim this heartbeat after MLS material is available. A
            // page can mount before Welcome/checkpoint restoration; recording
            // it earlier prevents both the state-change retry and the timer
            // from ever starting, leaving this participant offline forever.
            presence_announce_key_seen.set(announce_key);
            let presence_store =
                crate::app::runtime_adapter::state_store_handle(state_store_for_presence);
            spawn(async move {
                let _ = crate::transport::auth::with_event_submitter(
                    &base,
                    api_token,
                    |sub| async move {
                        sub.send_scope_signal(
                            arkret_sdk::ScopeRef::Realm {
                                realm_id: arkret_sdk::RealmId::new(realm.clone())?,
                            },
                            &authority,
                            &device,
                            &material,
                            &crate::signal::SignalPayload::Presence {
                                state: state.clone(),
                                status_message: status_message.clone(),
                                last_active_at: None,
                            },
                            &presence_store,
                        )
                        .await
                    },
                )
                .await;
                // The Signal rail is intentionally cursorless and has no
                // catch-up. Repeat the first presence announcement quickly so
                // a subscriber reconnect racing this page mount does not stay
                // offline until the normal 25-second refresh; subsequent
                // announcements keep the normative 20-25 second cadence.
                crate::runtime_helpers::sleep_for(std::time::Duration::from_secs(
                    presence_heartbeat_delay_secs(heartbeat_tick),
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
        let strand = selected_channel_value.clone();
        let circle = selected_scope_circle.clone();
        let agent_ids = readable_participation_agent_ids.clone();
        use_effect(move || {
            if token().trim().is_empty()
                || realm.trim().is_empty()
                || strand.trim().is_empty()
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
                                        &outcome.agent_participation_entries,
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
        let actor = crate::app::SessionContext::get()
            .active_account()
            .map(|account| arkret_sdk::ActorId::account(account.authority).to_string())
            .unwrap_or_default();
        let strand = selected_channel_value.clone();
        let participants_for_sync = participant_ids_for_presence.clone();
        let typing_actors_for_sync = typing_actors;
        let typing_next_expires_at_ms_for_sync = typing_next_expires_at_ms;
        let presence_states_for_sync = presence_states;
        let presence_labels_for_sync = presence_labels;
        let presence_status_messages_for_sync = presence_status_messages;
        let self_label_for_sync = account_display_label.clone();
        use_effect(use_reactive!(
            |realm,
             actor,
             strand,
             participants_for_sync,
             self_label_for_sync,
             has_remote_presence,
             presence_sync_key| {
                if token().trim().is_empty()
                    || realm.trim().is_empty()
                    || strand.trim().is_empty()
                    || !has_remote_presence
                {
                    return;
                }
                // Signal is a cursorless rail. Its admitted live projection and
                // the visible roster drive this effect independently of account
                // sync progress, including a roster that arrives after mount.
                let snapshot = state_store.read().load();
                let next_sync_key = presence_projection_refresh_key(
                    &presence_sync_key,
                    &snapshot.presence_projection,
                );
                if presence_sync_key_seen.peek().as_str() == next_sync_key {
                    return;
                }
                presence_sync_key_seen.set(next_sync_key);

                let active_typing = typing_actor_snapshot_from_signals(
                    &snapshot.presence_projection,
                    &strand,
                    &actor,
                );
                if typing_actors_for_sync.peek().as_slice() != active_typing.actors.as_slice()
                    || *typing_next_expires_at_ms_for_sync.peek()
                        != active_typing.next_expires_at_ms
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
            }
        ));
    }
    let authority_for_initial_sync = authority.clone();
    use_effect(move || {
        if !initial_sync_requested() && !token().trim().is_empty() {
            event_sink.emit(ChatProjectionEvent::InitialSync {
                requested: true,
                finished: false,
            });
            let base = base_url.clone();
            let api_token = token();
            let selected_realm_for_load = selected_realm_id.clone();
            let principal_id_for_load = principal_id.clone();
            // P0 decrypt-on-read identity: this device's actor + device id let the
            // message projection decrypt remote members' canonical encrypted_content
            // envelopes from the local MLS snapshot.
            let local_decrypt_identity = Some((
                &authority_for_initial_sync,
                principal_id.as_str(),
                &device_id,
            ));
            let (local_messages, local_poll_cards, local_channels) = {
                let store = state_store.read();
                let snapshot = store.load();
                (
                    chat_messages_from_local_state_with_sidecar(
                        &snapshot,
                        Some(&store),
                        local_decrypt_identity,
                    ),
                    poll_cards_from_local_state_with_sidecar(
                        &snapshot,
                        Some(&store),
                        local_decrypt_identity,
                    ),
                    channels_from_local_state(&snapshot, &selected_realm_for_load),
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
            event_sink.emit(ChatProjectionEvent::ReplacePollProjection(local_poll_cards));
            let principal_id_for_decrypt = principal_id.clone();
            let authority_for_decrypt = authority_for_initial_sync.clone();
            let device_id_for_decrypt = device_id.clone();
            spawn(async move {
                let decrypt_identity = Some((
                    &authority_for_decrypt,
                    principal_id_for_decrypt.as_str(),
                    &device_id_for_decrypt,
                ));
                // These explicit Realm reads have no pending local write to
                // observe. The main account stream owns progressive baselines
                // and their durable cursor independently of this view.
                let Ok(api) = authed_api_with_sync(&base, api_token, None) else {
                    event_sink.emit(ChatProjectionEvent::InitialSync {
                        requested: true,
                        finished: true,
                    });
                    return;
                };
                if !selected_realm_for_load.trim().is_empty() {
                    tracing::debug!(
                        realm_id = %selected_realm_for_load,
                        phase = "realm_current_result",
                        "chat initial sync phase started"
                    );
                    if let Err(error) =
                        crate::mls::creator_bootstrap::refresh_realm_governance_frontier(
                            &api,
                            crate::app::runtime_adapter::state_store_handle(state_store),
                            &selected_realm_for_load,
                        )
                        .await
                    {
                        // A removed member may still enter this shell. Failure to
                        // obtain the Station's current result leaves authoring
                        // readiness unresolved; finishing this view load does not
                        // make the selected Realm's detail complete.
                        tracing::warn!(
                            realm_id = %selected_realm_for_load,
                            phase = "realm_current_result",
                            %error,
                            "chat initial sync could not refresh the Realm current result"
                        );
                    } else {
                        tracing::debug!(
                            realm_id = %selected_realm_for_load,
                            phase = "realm_current_result",
                            "chat initial sync phase completed"
                        );
                    }
                }
                let mut loaded_messages = Vec::new();
                if let Ok(account) =
                    async { crate::transport::account::account_me(&api.sdk_http_client()?).await }
                        .await
                    && crate::mls_api_helpers::principal_core_id(&principal_id_for_load)
                        .is_ok_and(|principal_id| principal_id == account.principal_id)
                    && let Some(display_name) =
                        normalize_account_handle(&account.handle).or_else(|| {
                            clean_participant_display_name(
                                account.display_name.as_deref().unwrap_or(""),
                                Some(&principal_id_for_load),
                            )
                        })
                {
                    event_sink.emit(ChatProjectionEvent::AccountDisplayName(display_name));
                }
                // The main account stream owns account cursors and selected-Realm detail.
                // Existing local messages and the explicit Realm read below populate this view.

                if !selected_realm_for_load.trim().is_empty()
                    && let Ok(sub) = api.event_submitter()
                {
                    // Backfill supplements the local projection and ongoing
                    // delta sync. It must not hold the discussion readiness
                    // gate forever when a quiet or partially projected Realm
                    // leaves the request open.
                    let backfill = tokio::select! {
                        result = sub.backfill(&selected_realm_for_load) => match result {
                            Ok(backfill) => {
                                tracing::debug!(
                                    realm_id = %selected_realm_for_load,
                                    phase = "realm_backfill",
                                    "chat initial sync phase completed"
                                );
                                Some(backfill)
                            }
                            Err(error) => {
                                tracing::warn!(
                                    realm_id = %selected_realm_for_load,
                                    phase = "realm_backfill",
                                    %error,
                                    "chat initial backfill failed; continuing from local projection and account stream"
                                );
                                None
                            }
                        },
                        _ = crate::runtime_helpers::sleep_for(CHAT_INITIAL_BACKFILL_TIMEOUT) => {
                            tracing::warn!(
                                realm_id = %selected_realm_for_load,
                                phase = "realm_backfill",
                                timeout_seconds = CHAT_INITIAL_BACKFILL_TIMEOUT.as_secs(),
                                "chat initial backfill timed out; continuing from local projection and account stream"
                            );
                            None
                        }
                    };
                    if let Some(backfill) = backfill {
                        // Chat is a display projection, not an authority or
                        // cryptographic replay path. Keep every complete Event
                        // in the page while omitting opaque stubs that cannot
                        // identify a timeline object. Rejecting the whole page
                        // here used to drop the complete, server-folded Message
                        // tombstone whenever its separate redact Event was
                        // returned as a withheld CommittedEventView, which has
                        // no reducer input.
                        let backfill_events = match backfill.display_event_values() {
                            Ok(events) => Some(events),
                            Err(error) => {
                                tracing::warn!(
                                    error = %error,
                                    "chat projection could not serialize accepted Events"
                                );
                                None
                            }
                        };
                        if let Some(backfill_events) = backfill_events {
                            // Persist the complete encrypted discussion history,
                            // including Sidecar exchange control Events, before any
                            // projection work. New controller devices and devices
                            // with an incomparable local cache frontier refold from
                            // this accepted union history instead of choosing an
                            // HLC/LWW winner.
                            let sidecar_history_changed =
                                crate::sync_engine::ingest_message_projection_events(
                                    &mut state_store.write(),
                                    &selected_realm_for_load,
                                    &backfill_events,
                                );
                            if sidecar_history_changed > 0 {
                                let next = realm_live_epoch.peek().wrapping_add(1);
                                realm_live_epoch.set(next);
                            }
                            // §2.10.3 — a minimal-metadata Realm's backfill never primes
                            // the device directory: authors verify against the MLS leaf.
                            let backfill_realm_is_minimal_metadata = state_store
                                .read()
                                .realm_projection_is_minimal_metadata(&selected_realm_for_load);
                            if !backfill_realm_is_minimal_metadata {
                                crate::sync_engine::prefetch_persistent_event_sender_keys_from_values(
                                &api,
                                &backfill_events,
                                crate::app::runtime_adapter::state_store_handle(state_store),
                            )
                            .await;
                            }
                            loaded_messages.extend(chat_messages_from_events_with_sidecar(
                                &selected_realm_for_load,
                                &backfill_events,
                                Some(&state_store.read()),
                                decrypt_identity,
                            ));
                        }
                    }
                }

                event_sink.emit(ChatProjectionEvent::MergeChannels(
                    channels_from_local_state(&state_store.read().load(), &selected_realm_for_load),
                ));
                if selected_channel().trim().is_empty()
                    && let Some(first_channel) = channels.read().first()
                {
                    selected_channel.set(first_channel.strand_id.clone());
                }
                if !loaded_messages.is_empty() {
                    event_sink.emit(ChatProjectionEvent::MergeMessages(loaded_messages));
                }
                // Tally only the durable accepted union, never one backfill page.
                let loaded_poll_cards = {
                    let store = state_store.read();
                    poll_cards_from_local_state_with_sidecar(
                        &store.load(),
                        Some(&store),
                        decrypt_identity,
                    )
                };
                event_sink.emit(ChatProjectionEvent::ReplacePollProjection(
                    loaded_poll_cards,
                ));
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
        let authority_for_local_timeline = authority.clone();
        let principal_id_for_local_timeline = account_after_initial_sync.clone();
        let device_id_for_local_timeline = device_after_initial_sync.clone();
        use_effect(move || {
            let cursor = sync_cursor();
            let account_sync_ready = crate::app::account_sync_ready(&cursor);
            let live_epoch = realm_live_epoch();
            if !account_sync_ready && live_epoch == 0 {
                return;
            }
            let realm = selected_realm_for_local_timeline.trim().to_owned();
            if realm.is_empty() {
                return;
            }
            // Timeline projection follows durable Realm revisions. Cursor
            // token re-mints for typing/receipts/calls must not rescan every
            // locally persisted message.
            let sync_key = format!("{realm}|{}|{live_epoch}", account_sync_ready as u8);
            if local_timeline_sync_key_seen.peek().as_str() == sync_key {
                return;
            }
            local_timeline_sync_key_seen.set(sync_key);
            let (next_messages, next_poll_cards) = {
                let store = state_store.read();
                let snapshot = store.load();
                let decrypt_identity = Some((
                    &authority_for_local_timeline,
                    principal_id_for_local_timeline.as_str(),
                    &device_id_for_local_timeline,
                ));
                let messages = chat_messages_from_local_state_with_sidecar(
                    &snapshot,
                    Some(&store),
                    decrypt_identity,
                )
                .into_iter()
                .filter(|message| message.realm_id == realm)
                .collect::<Vec<_>>();
                let poll_cards = poll_cards_from_local_state_with_sidecar(
                    &snapshot,
                    Some(&store),
                    decrypt_identity,
                );
                (messages, poll_cards)
            };
            if !next_messages.is_empty() {
                event_sink.emit(ChatProjectionEvent::MergeMessages(next_messages));
            }
            event_sink.emit(ChatProjectionEvent::ReplacePollProjection(next_poll_cards));
        });
    }

    // T7.4: safety-net crypto state refresh for rows built without the
    // decrypt-on-read context. The model layer marks attempted decrypt
    // failures as `KeyMissing`; this covers no-snapshot rows so the user
    // sees a clear missing-key state instead of a spinner forever.
    {
        let realm_for_crypto = selected_realm_after_initial_sync.clone();
        let messages_sig = messages;
        use_effect(move || {
            let snapshot_missing = state_store
                .read()
                .mls_checkpoint_for(&realm_for_crypto)
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

/// Load the Circles a new Strand may be scoped to.
///
/// Keyed on (server, actor, Realm) so a credential or context change retries
/// and nothing else does. The two guard Signals are read with `peek` because
/// this effect writes both of them: subscribing to them would make the load
/// re-trigger itself.
fn use_eligible_circle_scopes(
    controller: ChatController,
    base_url: String,
    realm_id: String,
    actor: String,
    token: Signal<String>,
) {
    let mut eligible_circle_scopes = controller.eligible_circle_scopes;
    let mut key_seen = controller.eligible_circle_scope_request_key_seen;
    let mut in_flight = controller.eligible_circle_scope_request_in_flight;
    use_effect(move || {
        let credential = token();
        let base = base_url.clone();
        let realm = realm_id.clone();
        let request_key = format!("{base}\u{1f}{actor}\u{1f}{realm}");
        if !should_start_circle_scope_request(
            &credential,
            key_seen.peek().as_str(),
            *in_flight.peek(),
            &request_key,
        ) {
            return;
        }
        key_seen.set(request_key.clone());
        in_flight.set(true);
        spawn(async move {
            let outcome =
                crate::transport::auth::with_authed_api(&base, credential, |api| async move {
                    api.http()
                        .circle_list(&realm)
                        .await
                        .map_err(anyhow::Error::from)
                })
                .await;
            match outcome {
                Ok(list) => {
                    let summaries = crate::circle::ordinary_circle_views(list)
                        .into_iter()
                        .filter(|circle| {
                            circle.state == arkret_sdk::CircleState::Active
                                && circle.viewer_membership
                                    == Some(arkret_sdk::CircleMembership::Join)
                        })
                        .map(|circle| CircleSummary {
                            id: circle.circle_id.to_string(),
                            realm_id: circle.realm_id.to_string(),
                            title: circle.title,
                            short_name: circle.display.short_name,
                            color_token: format!("{:?}", circle.display.color_token),
                            symbol: format!("{:?}", circle.display.symbol),
                            member_count: u32::try_from(circle.member_ids.len())
                                .unwrap_or(u32::MAX),
                            state: circle.state,
                            viewer_is_member: true,
                        })
                        .collect();
                    eligible_circle_scopes.set(summaries);
                }
                Err(error) => {
                    if key_seen.peek().as_str() == request_key {
                        // Permit a later credential/context change to retry,
                        // but do not immediately self-trigger this effect.
                        key_seen.set(String::new());
                    }
                    tracing::warn!(
                        error = %error.display(),
                        "Circle scope picker load failed"
                    );
                }
            }
            in_flight.set(false);
        });
    });
}
