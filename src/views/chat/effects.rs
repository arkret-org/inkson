use super::*;

const CHAT_INITIAL_BACKFILL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(12);

async fn read_owned_agents_with_retry<T, Read, ReadFuture, Wait, WaitFuture>(
    current: impl Fn() -> anyhow::Result<()>,
    mut read: Read,
    mut wait: Wait,
) -> anyhow::Result<T>
where
    Read: FnMut() -> ReadFuture,
    ReadFuture: std::future::Future<Output = anyhow::Result<T>>,
    Wait: FnMut(u64) -> WaitFuture,
    WaitFuture: std::future::Future<Output = ()>,
{
    for attempt in 0..8 {
        current()?;
        let result = read().await;
        current()?;
        match result {
            Ok(agents) => return Ok(agents),
            Err(error) if attempt == 7 => return Err(error),
            Err(error) => {
                tracing::warn!(attempt, reason = %error, "owned Agent inventory read will resume");
                wait((500_u64 << attempt.min(2)).min(2_000)).await;
            }
        }
    }
    unreachable!("bounded inventory read returns on the final attempt")
}

#[cfg(test)]
mod tests {
    use std::cell::{Cell, RefCell};
    use std::rc::Rc;

    use super::*;

    #[tokio::test(flavor = "current_thread")]
    async fn owned_agent_inventory_read_recovers_without_inventing_entries() {
        let reads = Cell::new(0);
        let waits = RefCell::new(Vec::new());
        let result = read_owned_agents_with_retry(
            || Ok(()),
            || {
                reads.set(reads.get() + 1);
                std::future::ready(if reads.get() == 1 {
                    Err(anyhow::anyhow!("temporary read failure"))
                } else {
                    Ok(std::collections::BTreeMap::<String, String>::new())
                })
            },
            |ms| {
                waits.borrow_mut().push(ms);
                std::future::ready(())
            },
        )
        .await
        .unwrap();
        assert!(result.is_empty(), "verified empty inventory remains empty");
        assert_eq!(reads.get(), 2);
        assert_eq!(*waits.borrow(), vec![500]);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn owned_agent_inventory_read_failure_is_bounded_and_not_an_empty_success() {
        let reads = Cell::new(0);
        let waits = RefCell::new(Vec::new());
        let error = read_owned_agents_with_retry(
            || Ok(()),
            || {
                reads.set(reads.get() + 1);
                std::future::ready(Err::<(), _>(anyhow::anyhow!("unavailable")))
            },
            |ms| {
                waits.borrow_mut().push(ms);
                std::future::ready(())
            },
        )
        .await
        .unwrap_err();
        assert_eq!(error.to_string(), "unavailable");
        assert_eq!(reads.get(), 8);
        assert_eq!(
            *waits.borrow(),
            vec![500, 1000, 2000, 2000, 2000, 2000, 2000]
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn owned_agent_inventory_read_cannot_publish_or_retry_after_fence_change() {
        for change_during_read in [true, false] {
            let valid = Cell::new(true);
            let reads = Cell::new(0);
            let result = read_owned_agents_with_retry(
                || {
                    anyhow::ensure!(valid.get(), "account, Station or session changed");
                    Ok(())
                },
                || {
                    reads.set(reads.get() + 1);
                    if change_during_read {
                        valid.set(false);
                        std::future::ready(Ok(1))
                    } else {
                        std::future::ready(Err(anyhow::anyhow!("temporary failure")))
                    }
                },
                |_| {
                    valid.set(false);
                    std::future::ready(())
                },
            )
            .await;
            assert!(result.unwrap_err().to_string().contains("session changed"));
            assert_eq!(reads.get(), 1, "stale read must never publish or retry");
        }
    }

    #[derive(Clone)]
    struct TimelineControl {
        signals: Rc<RefCell<Option<TimelineSignals>>>,
        builds: Rc<Cell<usize>>,
    }

    #[derive(Clone, Copy)]
    struct TimelineSignals {
        incoming: Cage<Vec<ChatMessage>>,
        messages: Cage<Vec<ChatMessage>>,
        realm: Cage<String>,
        cursor: Cage<String>,
        epoch: Cage<u64>,
    }

    fn row(id: &str, realm: &str) -> ChatMessage {
        ChatMessage {
            protocol_content: None,
            local_scope: None,
            realm_id: realm.to_owned(),
            id: id.to_owned(),
            protocol_message_id: Some(id.to_owned()),
            actor_id: None,
            sender: "fixture".to_owned(),
            executed_by: None,
            body: "fixture".to_owned(),
            content_format: None,
            timestamp: "00:00".to_owned(),
            created_at: None,
            strand_id: "fixture-strand".to_owned(),
            reply_to: None,
            reactions: Vec::new(),
            redacted: false,
            edited: false,
            revisions: Vec::new(),
            revision_source: None,
            pending: false,
            failed: false,
            error: None,
            mentions: Vec::new(),
            crypto_state: MessageCryptoState::Plaintext,
        }
    }

    fn timeline_harness(scope: &Scope, control: TimelineControl) -> View {
        let incoming = scope.cage((Vec::new)());
        let messages = scope.cage((Vec::new)());
        let realm = scope.cage("selected".to_owned());
        let cursor = scope.cage(String::new());
        let epoch = scope.cage(0_u64);
        let ordinary = scope.bond(move || {
            control.builds.set(control.builds.get() + 1);
            let mut rows = messages.get().clone();
            merge_chat_messages(&mut rows, incoming.get());
            rows
        });
        local_ordinary_timeline(scope, realm.into(), ordinary, messages, cursor, epoch);
        *control.signals.borrow_mut() = Some(TimelineSignals {
            incoming,
            messages,
            realm,
            cursor,
            epoch,
        });
        let count = messages.get().len();
        Box::new(text().content(count.to_string()))
    }

    fn settle(dom: &glory::App) {
        for _ in 0..6 {
            dom.flush().unwrap();
        }
    }

    #[test]
    fn ordinary_memo_updates_without_cursor_change_and_settles_feedback() {
        let control = TimelineControl {
            signals: Rc::new(RefCell::new(None)),
            builds: Rc::new(Cell::new(0)),
        };
        let dom = glory::App::memory();
        let capture = control.clone();
        dom.mount(widget(move |scope| {
            timeline_harness(scope, capture.clone()).build(scope)
        }))
        .unwrap();
        dom.flush().unwrap();
        settle(&dom);
        let signals = control.signals.borrow().unwrap();
        let mut queued = row("message", "selected");
        queued.pending = true;
        let other = row("other", "other-realm");
        {
            {
                let next_value = "opaque-ready".to_owned();
                signals.cursor.revise(|value| *value = next_value);
            };
            {
                let next_value = vec![queued, other];
                signals.incoming.revise(|value| *value = next_value);
            };
        };
        settle(&dom);
        {
            assert_eq!(signals.messages.get().len(), 1);
            assert!(signals.messages.get()[0].pending);
        };
        let mut accepted = row("message", "selected");
        accepted.edited = true;
        accepted.body = "verified revision".to_owned();
        accepted.revisions = vec!["fixture".to_owned()];
        accepted.reactions = vec![("+1".to_owned(), vec!["fixture".to_owned()])];
        {
            let next_value = vec![accepted.clone()];
            signals.incoming.revise(|value| *value = next_value);
        };
        settle(&dom);
        {
            let rows = signals.messages.get();
            assert_eq!(rows.len(), 1);
            assert!(!rows[0].pending);
            assert!(rows[0].edited);
            assert_eq!(rows[0].body, "verified revision");
            assert_eq!(rows[0].reactions, accepted.reactions);
            assert_eq!(signals.cursor.get(), "opaque-ready");
            assert_eq!(signals.epoch.get(), 0);
        };
        let builds = control.builds.get();
        settle(&dom);
        {
            let next_value = "reminted-ready".to_owned();
            signals.cursor.revise(|value| *value = next_value);
        };
        settle(&dom);
        assert_eq!(control.builds.get(), builds);
        accepted.redacted = true;
        accepted.body.clear();
        {
            let next_value = vec![accepted];
            signals.incoming.revise(|value| *value = next_value);
        };
        settle(&dom);
        assert!(signals.messages.get()[0].redacted);
        let builds = control.builds.get();
        settle(&dom);
        assert_eq!(control.builds.get(), builds);
    }

    #[test]
    fn ordinary_memo_preserves_readiness_and_realm_switch() {
        let control = TimelineControl {
            signals: Rc::new(RefCell::new(None)),
            builds: Rc::new(Cell::new(0)),
        };
        let dom = glory::App::memory();
        let capture = control.clone();
        dom.mount(widget(move |scope| {
            timeline_harness(scope, capture.clone()).build(scope)
        }))
        .unwrap();
        dom.flush().unwrap();
        settle(&dom);
        let signals = control.signals.borrow().unwrap();
        {
            {
                let next_value = vec![row("first", "selected"), row("second", "next")];
                signals.incoming.revise(|value| *value = next_value);
            };
        };
        settle(&dom);
        assert!(signals.messages.get().is_empty());
        {
            let next_value = 1;
            signals.epoch.revise(|value| *value = next_value);
        };
        settle(&dom);
        {
            assert_eq!(signals.messages.get().len(), 1);
            {
                let next_value = "next".to_owned();
                signals.realm.revise(|value| *value = next_value);
            };
        };
        settle(&dom);
        {
            let rows = signals.messages.get();
            assert_eq!(rows.len(), 2);
            assert!(rows.iter().any(|row| row.id == "second"));
        };
    }
}

fn local_ordinary_timeline(
    scope: &Scope,

    selected_realm_id: Lotus<String>,
    ordinary_timeline: Bond<Vec<ChatMessage>>,
    messages: Cage<Vec<ChatMessage>>,
    sync_cursor: Cage<String>,
    realm_live_epoch: Cage<u64>,
) {
    let account_sync_ready = scope.bond(move || crate::app::account_sync_ready(&sync_cursor.get()));
    scope.effect(move || {
        let realm = selected_realm_id.get();
        let ready = account_sync_ready.get();
        let live_epoch = realm_live_epoch.get();
        let projected = ordinary_timeline.get();
        if (!ready && live_epoch == 0) || realm.trim().is_empty() {
            return;
        }
        // This Memo has already verified and folded the complete history,
        // including revisions and control Events. Never fold/decrypt it again.
        let incoming = projected
            .iter()
            .filter(|message| message.realm_id == realm.trim())
            .cloned()
            .collect();
        let current = messages.get_untracked();
        let mut next = current.clone();
        merge_chat_messages(&mut next, incoming);
        if current != next {
            {
                let next_value = next;
                messages.revise(|value| *value = next_value);
            };
        }
    });
}

pub(super) fn chat_effects(
    scope: &Scope,
    context: Rc<crate::presentation::InksonContext>,

    controller: ChatController,
    authority: arkret_sdk::AccountId,
    principal_id: String,
    device_id: arkret_sdk::DeviceId,
    selected_realm_id: String,
    initial_strand_id: String,
    _plaintext_service_id: String,
    ordinary_timeline: Bond<Vec<ChatMessage>>,
    timeline_basis: Bond<super::timeline_projection::TimelineProjectionBasis>,
    sync_cursor: Cage<String>,
    realm_live_epoch: Cage<u64>,
    frontier_state: Cage<String>,
    _agent_participation_sync_key: String,
    _selected_scope_circle: Option<String>,
    _readable_participation_agent_ids: Vec<String>,
    _participant_ids_for_presence: Vec<String>,
    _account_display_label: String,
    _has_remote_presence: bool,
    _presence_sync_key: String,
    token: Cage<String>,
    live_snapshot: Bond<super::snapshot::ChatSnapshot>,
) {
    let base_url = context.base_url.get_untracked();
    let session_context = context.clone();
    let state_store = session_context.state_store.clone();
    super::sidecar_restore::sidecar_restore(
        scope,
        context.clone(),
        base_url.clone(),
        selected_realm_id.clone(),
        controller.selected_channel.into(),
        authority.clone(),
        device_id.clone(),
        token,
        timeline_basis,
        state_store.clone(),
    );
    super::sidecar_restore::sidecar_reconciliation(
        scope,
        context.clone(),
        base_url.clone(),
        selected_realm_id.clone(),
        controller.selected_channel.into(),
        authority.clone(),
        device_id.clone(),
        token,
        state_store.clone(),
        controller.status_msg,
    );
    super::direct_authority::direct_authority(
        scope,
        context.clone(),
        base_url.clone(),
        selected_realm_id.clone(),
        authority.clone(),
        token,
        frontier_state,
        realm_live_epoch,
        state_store.clone(),
    );
    super::circle_welcome::circle_welcome(
        scope,
        context.clone(),
        base_url.clone(),
        selected_realm_id.clone(),
        scope
            .bond(move || live_snapshot.get().selected_scope_circle)
            .into(),
        authority.clone(),
        device_id.clone(),
        token,
        sync_cursor,
        state_store.clone(),
    );
    eligible_circle_scopes(
        scope,
        context.clone(),
        controller,
        base_url.clone(),
        selected_realm_id.clone(),
        principal_id.clone(),
        token,
    );
    let event_sink = ChatProjectionSink::new(controller);

    let channels = controller.channels;
    let selected_channel = controller.selected_channel;
    let shared_pins = controller.shared_pins;
    let private_saved_targets = controller.private_saved_targets;
    let private_saved_account_data = controller.private_saved_account_data;
    let is_online = controller.is_online;
    let latest_read_cursor = controller.latest_read_cursor;
    let typing_actors = controller.typing_actors;
    let typing_next_expires_at_ms = controller.typing_next_expires_at_ms;
    let presence_announce_key_seen = controller.presence_announce_key_seen;
    let presence_heartbeat_tick = controller.presence_heartbeat_tick;
    let queued_outbound_local_operation_ids = controller.queued_outbound_local_operation_ids;
    let messages = controller.messages;
    let owned_agent_sync_key_seen = controller.owned_agent_sync_key_seen;
    let agent_participation_sync_key_seen = controller.agent_participation_sync_key_seen;
    let presence_states = controller.presence_states;
    let presence_labels = controller.presence_labels;
    let presence_status_messages = controller.presence_status_messages;
    let presence_sync_key_seen = controller.presence_sync_key_seen;
    let initial_sync_requested = controller.initial_sync_requested;

    {
        let watch_base_url = base_url.clone();
        let watch_realm_id = selected_realm_id.clone();
        let watch_authority = authority.clone();
        {
            let context = context.clone();

            scope.effect({
                let watch_base_url = watch_base_url.clone();
                let watch_realm_id = watch_realm_id.clone();
                let watch_authority = watch_authority.clone();
                move || {
                    let session_context = context.clone();

                    let strand = selected_channel.get();
                    let credential = token.get();
                    let _session_generation = session_context.session_generation.get();
                    let _account = session_context.active_account.get();
                    let _epoch = realm_live_epoch.get();
                    let readable_realm_strand = channels.get().iter().any(|channel| {
                        channel.strand_id == strand
                            && channel.scope_circle.is_none()
                            && !channel.is_private_sidecar
                    });
                    let request = readable_realm_strand
                        .then(|| {
                            Some(arkret_sdk::StrandWatchCurrentRequestBody {
                                realm_id: arkret_sdk::RealmId::new(watch_realm_id.clone()).ok()?,
                                strand_id: arkret_sdk::StrandId::new(strand).ok()?,
                                watcher_actor_id: arkret_sdk::ActorId::account(
                                    watch_authority.clone(),
                                ),
                            })
                        })
                        .flatten();
                    controller.refresh_strand_watch(watch_base_url.clone(), credential, request);
                }
            })
        };
    }

    {
        let base = base_url.clone();
        let account = authority.clone();
        let device = device_id.clone();
        let session_epoch = crate::identity::device_directory::session_cache_epoch();
        let read_generation = scope.cage(0_u64);
        {
            let context = context.clone();
            let effect_owner = scope.downgrade();
            scope.effect({let base=base.clone();let account=account.clone();let device=device.clone();move || {

 let session_context = context.clone();

                let api_token = token.get();
                let session_generation = session_context.session_generation.get();
                let inventory_revision = session_context.owned_agents_rev.get();
                let selected_account = session_context.active_account.get();
                let request_key = format!(
                    "{base}|{account}|{device}|{session_epoch}|{session_generation}|{inventory_revision}|{api_token}"
                );
                let eligible = !api_token.trim().is_empty()
                    && selected_account.as_ref().is_some_and(|selected| {
                        selected.authority == account && selected.device_id == device
                    });
                #[cfg(all(target_arch = "wasm32", feature = "wasm-localstorage-secrets-test"))]
                tracing::warn!(eligible, "chat owned Agent inventory eligibility");
                if eligible && owned_agent_sync_key_seen.get_untracked().as_str() == request_key {
                    return;
                }
                { let next_value = if eligible {
                    request_key.clone()
                } else {
                    String::new()
                }; owned_agent_sync_key_seen.revise(|value| *value = next_value); };
                let generation = read_generation.get_untracked().wrapping_add(1);
                { let next_value = generation; read_generation.revise(|value| *value = next_value); };
                event_sink.emit(ChatProjectionEvent::OwnedAgents(
                    std::collections::BTreeMap::new(),
                ));
                if !eligible {
                    return;
                }
                spawn_effect(&effect_owner, {
 let account=account.clone();
 let device=device.clone();
 let base=base.clone();
let session_context=session_context.clone();
let mut claim = PendingStringClaim::new(owned_agent_sync_key_seen);
async move {
                    let current = || -> anyhow::Result<()> {
                        // This read waits for authentication restoration in the
                        // session provider; it does not require a write signer.
                        anyhow::ensure!(
                            crate::identity::device_directory::session_cache_epoch()
                                == session_epoch
                                && session_context.session_generation.get_untracked() == session_generation
                                && session_context.owned_agents_rev.get_untracked() == inventory_revision
                                && session_context.active_account.get_untracked().as_ref().is_some_and(
                                    |selected| {
                                        selected.authority == account
                                            && selected.device_id == device
                                    }
                                )
                                && session_context.base_url.get_untracked() == base
                                && token.get_untracked() == api_token
                                && owned_agent_sync_key_seen.get_untracked().as_str() == request_key
                                && read_generation.get_untracked() == generation,
                            "owned Agent inventory account or session changed"
                        );
                        Ok(())
                    };
                    let result = read_owned_agents_with_retry(
                        &current,
                        || async {
                            crate::transport::auth::with_authed_sdk_client(
                                &base,
                                api_token.clone(),
                                |http| async move {
                                    let list = http.agent_page().await?;
                                    Ok::<_, anyhow::Error>(
                                        crate::views::agents::mentionable_owned_agent_slugs(
                                            list.agents,
                                        ),
                                    )
                                },
                            )
                            .await
                            .map_err(|error| anyhow::anyhow!(error.display()))
                        },
                        |ms| {
                            crate::runtime_helpers::sleep_for(std::time::Duration::from_millis(ms))
                        },
                    )
                    .await;
                    let still_current = current().is_ok();
                    #[cfg(all(target_arch = "wasm32", feature = "wasm-localstorage-secrets-test"))]
                    tracing::warn!(
                        success = result.is_ok(),
                        still_current,
                        verified_count = result.as_ref().map_or(0, |agents| agents.len()),
                        "chat owned Agent inventory completion"
                    );
                    if still_current && let Ok(agents) = result {
                        claim.complete();
                        event_sink.emit(ChatProjectionEvent::OwnedAgents(agents));
                    }
                }
});
            }})
        };
    }

    {
        let realm = selected_realm_id.clone();
        let initial_strand = initial_strand_id.clone();
        // These route-derived values are plain component props, not Signals.
        // The default Strand is often hydrated asynchronously after Chat first
        // mounts, so make prop changes explicit dependencies; otherwise the
        // one-shot empty value leaves the composer permanently unavailable.
        scope.effect({
            let realm = realm.clone();
            let initial_strand = initial_strand.clone();
            move || {
                if realm.trim().is_empty() {
                    return;
                }
                if let Some(desired) = discussion_channel_for_strand(&initial_strand) {
                    event_sink.emit(ChatProjectionEvent::EnsureChannel(desired));
                }
            }
        });
    }

    {
        let realm = selected_realm_id.clone();
        {
            let context = context.clone();

            scope.effect({
                let realm = realm.clone();
                move || {
                    let state_store = context.state_store.clone();

                    let _ = context.state_revision.get();

                    let _live_epoch = realm_live_epoch.get();
                    let _sync_cursor = sync_cursor.get();
                    let strand = selected_channel.get();
                    let snapshot = state_store.read(|value| value.load());
                    let scope = shared_pin_scope_for_message(&realm, &strand);
                    let next_shared =
                        shared_message_pins_from_raw_operations(&snapshot.raw_operations, &scope);
                    if shared_pins.get_untracked() != next_shared {
                        event_sink.emit(ChatProjectionEvent::SharedPins(next_shared));
                    }
                    let saved_entries: std::collections::BTreeMap<_, _> =
                        snapshot.saved_account_data.into_iter().collect();
                    let next_saved = private_saved_targets_from_account_data(
                        &saved_entries,
                        CHAT_PRIVATE_SAVED_COLLECTION_TITLE,
                    );
                    if private_saved_targets.get_untracked() != next_saved
                        || private_saved_account_data.get_untracked() != saved_entries
                    {
                        event_sink.emit(ChatProjectionEvent::PrivateSaved {
                            targets: next_saved,
                            entries: saved_entries,
                        });
                    }
                }
            })
        };
    }

    let authority_for_connectivity = authority.clone();
    let realm_for_connectivity = selected_realm_id.clone();
    // Chat survives route prop changes. Cancel the old scope's queue poll and
    // restart it for the active Account/Realm instead of retaining mount props.
    {
        let state_store = state_store.clone();
        let _ = scope.spawn(async move {
            let queue_state = state_store.handle();
            loop {
                let online = navigator_online();
                if is_online.get_untracked() != online {
                    event_sink.emit(ChatProjectionEvent::Connectivity(online));
                }
                let strand_for_connectivity = selected_channel.get();
                if let Ok(next) = crate::event_submit::pending_chat_outbound_local_operation_ids(
                    &authority_for_connectivity,
                    &realm_for_connectivity,
                    &strand_for_connectivity,
                    &queue_state,
                )
                .await
                    && queued_outbound_local_operation_ids.get_untracked() != next
                {
                    {
                        let next_value = next;
                        queued_outbound_local_operation_ids.revise(|value| *value = next_value);
                    };
                }
                crate::runtime_helpers::sleep_for(std::time::Duration::from_millis(2_500)).await;
            }
        });
    }

    let selected_realm_after_initial_sync = selected_realm_id.clone();
    let account_after_initial_sync = principal_id.clone();
    let device_after_initial_sync = device_id.clone();
    {
        let effect_owner = scope.downgrade();
        scope.effect(move || {
            let Some(expires_at_ms) = typing_next_expires_at_ms.get() else {
                return;
            };
            let delay_ms =
                (expires_at_ms - chrono::Utc::now().timestamp_millis()).max(0) as u64 + 50;
            spawn_effect(&effect_owner, {
                async move {
                    crate::runtime_helpers::sleep_for(std::time::Duration::from_millis(delay_ms))
                        .await;
                    if typing_next_expires_at_ms.get_untracked() == Some(expires_at_ms) {
                        event_sink.emit(ChatProjectionEvent::Typing {
                            actors: Vec::new(),
                            expires_at_ms: None,
                        });
                    }
                }
            });
        })
    };

    {
        let realm = selected_realm_id.clone();
        let authority_for_receipt = authority.clone();
        let device = device_id.clone();
        let base = base_url.clone();
        {
            let context = context.clone();
            let effect_owner = scope.downgrade();
            scope.effect(move || {
 let state_store = context.state_store.clone();

 let _ = context.state_revision.get();

            let strand = selected_channel.get();
            let plan = state_store.read(|store| super::model::automatic_read_receipt_plan(
                store,
                &controller.messages.get(),
                &realm,
                &strand,
                latest_read_cursor.get().as_str(),
            ));
            let Some(plan) = plan else {
                return;
            };
            let top_event = plan.event_id;
            event_sink.emit(ChatProjectionEvent::ReadCursor(top_event.clone()));
            let ordinary_direct_chat = state_store.read(|value| value.direct_conversation_peer(&realm))
                .is_some()
                && controller.channels.get().iter().any(|channel| {
                    channel.strand_id == strand
                        && channel.scope_circle.is_none()
                        && !channel.is_private_sidecar
                });
            if ordinary_direct_chat {
                let marker = state_store.read(|value| value.build_read_cursor_candidate(
                    authority_for_receipt.principal_id.to_string(),
                    device.to_string(),
                    realm.clone(),
                    Some(strand.clone()),
                    top_event.clone(),
                ));
                if let Ok(marker) = marker {
                    let base = base.clone();
                    let credential = token.get();
                    let fence = crate::transport::auth::AuthoringSessionFence::capture();
                    spawn_effect(&effect_owner, {
let state_store=state_store.clone();
async move {
                        let Ok(fence) = fence else {
                            return;
                        };
                        let result = crate::transport::auth::with_event_submitter(
                            &base,
                            credential,
                            |submitter| async move {
                                fence.check()?;
                                let outcome =
                                    crate::transport::account::submit_read_cursor_advance(
                                        &submitter, &marker,
                                    )
                                    .await?;
                                fence.check()?;
                                Ok(outcome)
                            },
                        )
                        .await;
                        match result {
                            Ok(outcome) => {
                                if let Err(error) =
                                    state_store.write(|value| value.apply_read_cursor_outcome(outcome))
                                {
                                    tracing::warn!(%error, "visible Chat read cursor installation failed");
                                }
                            }
                            Err(error) => {
                                tracing::debug!(error = %error.display_diagnostic(), "visible Chat read cursor remains pending")
                            }
                        }
                    }
});
                }
            }
            let Some(material) = plan.material else {
                return;
            };
            let Some(receipt_scope) = plan.scope else {
                return;
            };
            let strand_id = strand;
            let api_token = token.get();
            let base = base.clone();
            let authority = authority_for_receipt.clone();
            let device = device.clone();
            // The seal burns the SDK-owned nonce counter into the persisted
            // MLS snapshot before submit, so the send path needs the store
            // itself, not just the material descriptor.
            let receipt_store = state_store.handle();
            spawn_effect(&effect_owner, {
async move {
                let _ = crate::transport::auth::with_event_submitter(
                    &base,
                    api_token,
                    |submitter| async move {
                        submitter
                            .send_scope_signal(
                                receipt_scope,
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
            }
});
        })
        };
    }

    {
        let base = base_url.clone();
        let realm = selected_realm_id.clone();
        let actor = principal_id.clone();
        let authority_for_presence = authority.clone();
        let device = device_id.clone();
        let state_store_for_presence = context.state_store.clone();
        {
            let context = context.clone();
            let effect_owner = scope.downgrade();
            scope.effect(move || {
                let _ = context.state_revision.get();

                let realm = trim_realm_id(&realm);
                let actor = actor.trim().to_owned();
                let authority = authority_for_presence.clone();
                let device = device.clone();
                let heartbeat_tick = presence_heartbeat_tick.get();
                let visibility = state_store_for_presence.read(|store| store.presence_visibility());
                // Manual presence preference (profiles-presence.md §3.6):
                // while active it pins the broadcast state on every device
                // and supplies the transient status message.
                let now = chrono::Utc::now();
                let mut preference =
                    state_store_for_presence.read(|store| store.presence_preference());
                if !preference.is_empty() && !preference.is_active(now) {
                    state_store_for_presence.write(|store| {
                        store.set_presence_preference(crate::state::PresencePreference::default())
                    });
                    preference = crate::state::PresencePreference::default();
                }
                let state = preference
                    .effective_manual_state(now)
                    .unwrap_or(arkret_sdk::PresenceStatus::Online)
                    .as_wire()
                    .to_owned();
                let status_message = preference.effective_status_message(now).map(str::to_owned);
                let api_token = token.get();
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
                if presence_announce_key_seen.get_untracked().as_str() == announce_key {
                    return;
                }
                let base = base.clone();
                // Presence is an ordinary `session` Signal. Without accepted MLS
                // state for the scope the capability is withdrawn; there is no
                // plaintext presence broadcast in v1.
                let Ok(material) = state_store_for_presence
                    .read(|store| crate::signal::key_material_for_scope(store, &realm, None))
                else {
                    return;
                };
                // Only claim this heartbeat after MLS material is available. A
                // page can mount before Welcome/checkpoint restoration; recording
                // it earlier prevents both the state-change retry and the timer
                // from ever starting, leaving this participant offline forever.
                {
                    let next_value = announce_key;
                    presence_announce_key_seen.revise(|value| *value = next_value);
                };
                let presence_store = state_store_for_presence.handle();
                spawn_effect(&effect_owner, {
                    let mut claim = PendingStringClaim::new(presence_announce_key_seen);
                    async move {
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
                        let next_tick = (presence_heartbeat_tick.get_untracked()).wrapping_add(1);
                        {
                            let next_value = next_tick;
                            presence_heartbeat_tick.revise(|value| *value = next_value);
                        };
                        claim.complete();
                    }
                });
            })
        };
    }

    {
        let base = base_url.clone();
        let realm = selected_realm_id.clone();
        {
            let effect_owner = scope.downgrade();
            scope.effect(move || {
                let live = live_snapshot.get();
                let strand = selected_channel.get();
                let circle = live.selected_scope_circle;
                let agent_ids = live.readable_participation_agent_ids;
                let agent_participation_sync_key = live.agent_participation_sync_key;
                if token.get().trim().is_empty()
                    || realm.trim().is_empty()
                    || strand.trim().is_empty()
                    || agent_participation_sync_key_seen.get_untracked().as_str()
                        == agent_participation_sync_key
                {
                    return;
                }
                {
                    let next_value = agent_participation_sync_key.clone();
                    agent_participation_sync_key_seen.revise(|value| *value = next_value);
                };
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
                let api_token = token.get();
                let request_key = agent_participation_sync_key.clone();
                spawn_effect(&effect_owner, {
                    let mut claim = PendingStringClaim::new(agent_participation_sync_key_seen);
                    async move {
                        let result = crate::transport::auth::with_authed_sdk_client(
                            &base,
                            api_token,
                            move |http| async move {
                                let mut visible = std::collections::BTreeMap::new();
                                for agent_id in agent_ids {
                                    if let Ok(outcome) =
                                        http.agent_participation_get(&agent_id).await
                                    {
                                        visible.insert(
                                            agent_id,
                                            participation_allows_public_reply(
                                                &outcome.participation_entries,
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
                        if agent_participation_sync_key_seen.get_untracked().as_str() == request_key
                            && let Ok(visible) = result
                        {
                            claim.complete();
                            event_sink.emit(ChatProjectionEvent::AgentParticipation(visible));
                        }
                    }
                });
            })
        };
    }

    {
        let realm = selected_realm_id.clone();
        let actor = context
            .active_account
            .get()
            .map(|account| arkret_sdk::ActorId::account(account.authority).to_string())
            .unwrap_or_default();
        let typing_actors_for_sync = typing_actors;
        let typing_next_expires_at_ms_for_sync = typing_next_expires_at_ms;
        let presence_states_for_sync = presence_states;
        let presence_labels_for_sync = presence_labels;
        let presence_status_messages_for_sync = presence_status_messages;
        {
            let context = context.clone();

            scope.effect({
                let realm = realm.clone();
                let actor = actor.clone();
                move || {
                    let state_store = context.state_store.clone();

                    let _ = context.state_revision.get();

                    let live = live_snapshot.get();
                    let strand = selected_channel.get();
                    let participants_for_sync = live.participant_ids_for_presence;
                    let self_label_for_sync = live.account_display_label;
                    let has_remote_presence = live.has_remote_presence;
                    let presence_sync_key = live.presence_sync_key;
                    if token.get().trim().is_empty()
                        || realm.trim().is_empty()
                        || strand.trim().is_empty()
                        || !has_remote_presence
                    {
                        return;
                    }
                    // Signal is a cursorless rail. Its admitted live projection and
                    // the visible roster drive this effect independently of account
                    // sync progress, including a roster that arrives after mount.
                    let snapshot = state_store.read(|value| value.load());
                    let next_sync_key = presence_projection_refresh_key(
                        &presence_sync_key,
                        &snapshot.presence_projection,
                    );
                    if presence_sync_key_seen.get_untracked().as_str() == next_sync_key {
                        return;
                    }
                    {
                        let next_value = next_sync_key;
                        presence_sync_key_seen.revise(|value| *value = next_value);
                    };

                    let active_typing = typing_actor_snapshot_from_signals(
                        &snapshot.presence_projection,
                        &strand,
                        &actor,
                    );
                    if typing_actors_for_sync.get_untracked().as_slice()
                        != active_typing.actors.as_slice()
                        || typing_next_expires_at_ms_for_sync.get_untracked()
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
                            let mut next_presence =
                                std::collections::BTreeMap::<String, String>::new();
                            let mut next_labels =
                                std::collections::BTreeMap::<String, String>::new();
                            for did in &participants_for_sync {
                                if did == &actor {
                                    next_presence.insert(did.clone(), "online".to_owned());
                                    if let Some(label) = clean_participant_display_name(
                                        &self_label_for_sync,
                                        Some(did),
                                    ) {
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
                    if presence_states_for_sync.get_untracked() != next_presence
                        || presence_labels_for_sync.get_untracked() != next_labels
                        || presence_status_messages_for_sync.get_untracked() != next_status_messages
                    {
                        event_sink.emit(ChatProjectionEvent::Presence {
                            states: next_presence,
                            labels: next_labels,
                            status_messages: next_status_messages,
                        });
                    }
                }
            })
        };
    }
    let authority_for_initial_sync = authority.clone();
    {
        let context = context.clone();
        let effect_owner = scope.downgrade();
        scope.effect(move || {
 let state_store = context.state_store.clone();

 let _ = context.state_revision.get();

        if !initial_sync_requested.get() && !token.get().trim().is_empty() {
            event_sink.emit(ChatProjectionEvent::InitialSync {
                requested: true,
                finished: false,
            });
            let base = base_url.clone();
            let api_token = token.get();
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
            let (local_messages, local_poll_cards, local_channels) = state_store.read(|store| {
                let snapshot = store.load();
                (
                    ordinary_timeline.get(),
                    poll_cards_from_local_state_with_sidecar(
                        &snapshot,
                        Some(store),
                        local_decrypt_identity,
                    ),
                    channels_from_current_view_with_store(
                        store.current_product_view().as_ref(),
                        &selected_realm_for_load,
                        store,
                    ),
                )
            });
            if !local_channels.is_empty() {
                event_sink.emit(ChatProjectionEvent::MergeChannels(local_channels));
            }
            if selected_channel.get().trim().is_empty()
                && let Some(first_channel) = channels.get().first()
            {
                { let next_value = first_channel.strand_id.clone(); selected_channel.revise(|value| *value = next_value); };
            }
            if !local_messages.is_empty() {
                event_sink.emit(ChatProjectionEvent::MergeMessages(local_messages));
            }
            event_sink.emit(ChatProjectionEvent::ReplacePollProjection(local_poll_cards));
            let principal_id_for_decrypt = principal_id.clone();
            let authority_for_decrypt = authority_for_initial_sync.clone();
            let device_id_for_decrypt = device_id.clone();
            spawn_effect(&effect_owner, {
let state_store=state_store.clone();
let claim = PendingInitialSyncClaim::new(initial_sync_requested,controller.initial_sync_finished);
async move {
let _claim = claim;
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
                                state_store.write(|store| crate::sync_engine::ingest_message_projection_events(store,&selected_realm_for_load,&backfill_events));
                            if sidecar_history_changed > 0 {
                                let next = realm_live_epoch.get_untracked().wrapping_add(1);
                                { let next_value = next; realm_live_epoch.revise(|value| *value = next_value); };
                            }
                            loaded_messages.extend(state_store.read(|store| chat_messages_from_events_with_sidecar(&selected_realm_for_load,&backfill_events,Some(store),decrypt_identity)));
                        }
                    }
                }

                event_sink.emit(ChatProjectionEvent::MergeChannels(
                    state_store.read(|store| channels_from_current_view_with_store(store.current_product_view().as_ref(), &selected_realm_for_load, store)),
                ));
                if selected_channel.get().trim().is_empty()
                    && let Some(first_channel) = channels.get().first()
                {
                    { let next_value = first_channel.strand_id.clone(); selected_channel.revise(|value| *value = next_value); };
                }
                if !loaded_messages.is_empty() {
                    event_sink.emit(ChatProjectionEvent::MergeMessages(loaded_messages));
                }
                // Tally only the durable accepted union, never one backfill page.
                let loaded_poll_cards = state_store.read(|store| {
                    poll_cards_from_local_state_with_sidecar(
                        &store.load(),
                        Some(store),
                        decrypt_identity,
                    )
                });
                event_sink.emit(ChatProjectionEvent::ReplacePollProjection(
                    loaded_poll_cards,
                ));
                event_sink.emit(ChatProjectionEvent::InitialSync {
                    requested: true,
                    finished: true,
                });
            }
});
        }
    })
    };
    local_ordinary_timeline(
        scope,
        selected_realm_after_initial_sync.clone().into(),
        ordinary_timeline,
        messages,
        sync_cursor,
        realm_live_epoch,
    );
    let control_revision = std::rc::Rc::new(std::cell::Cell::new(0_u64));
    let local_control_revision = scope.bond(move || {
        let _ = timeline_basis.get();
        let next = control_revision.get().wrapping_add(1);
        control_revision.set(next);
        next
    });
    let account_sync_ready_for_controls =
        scope.bond(move || crate::app::account_sync_ready(&sync_cursor.get()));
    let local_timeline_sync_key_seen = scope.cage(String::new());
    {
        let selected_realm_for_local_timeline = selected_realm_after_initial_sync.clone();
        let authority_for_local_timeline = authority.clone();
        let principal_id_for_local_timeline = account_after_initial_sync.clone();
        let device_id_for_local_timeline = device_after_initial_sync.clone();
        {
            let context = context.clone();

            scope.effect({
                let realm = selected_realm_for_local_timeline.clone();
                move || {
                    let state_store = context.state_store.clone();

                    let _ = context.state_revision.get();

                    let account_sync_ready = account_sync_ready_for_controls.get();
                    let live_epoch = realm_live_epoch.get();
                    let revision = local_control_revision.get();
                    if !account_sync_ready && live_epoch == 0 {
                        return;
                    }
                    let realm = realm.trim().to_owned();
                    if realm.is_empty() {
                        return;
                    }
                    // Timeline projection follows durable Realm revisions. Cursor
                    // token re-mints for typing/receipts/calls must not rescan every
                    // locally persisted message.
                    let sync_key = format!(
                        "{realm}|{}|{live_epoch}|{revision}",
                        account_sync_ready as u8
                    );
                    if local_timeline_sync_key_seen.get_untracked().as_str() == sync_key {
                        return;
                    }
                    {
                        let next_value = sync_key;
                        local_timeline_sync_key_seen.revise(|value| *value = next_value);
                    };
                    let (next_channels, next_poll_cards) = state_store.read(|store| {
                        let snapshot = store.load();
                        let decrypt_identity = Some((
                            &authority_for_local_timeline,
                            principal_id_for_local_timeline.as_str(),
                            &device_id_for_local_timeline,
                        ));
                        let poll_cards = poll_cards_from_local_state_with_sidecar(
                            &snapshot,
                            Some(store),
                            decrypt_identity,
                        );
                        let channels = channels_from_current_view_with_store(
                            store.current_product_view().as_ref(),
                            &realm,
                            store,
                        );
                        (channels, poll_cards)
                    });
                    if !next_channels.is_empty() {
                        event_sink.emit(ChatProjectionEvent::MergeChannels(next_channels));
                    }
                    event_sink.emit(ChatProjectionEvent::ReplacePollProjection(next_poll_cards));
                }
            })
        };
    }

    // T7.4: safety-net crypto state refresh for rows built without the
    // decrypt-on-read context. The model layer marks attempted decrypt
    // failures as `KeyMissing`; this covers no-snapshot rows so the user
    // sees a clear missing-key state instead of a spinner forever.
    {
        let realm_for_crypto = selected_realm_after_initial_sync.clone();
        let messages_sig = messages;
        {
            let context = context.clone();

            scope.effect(move || {
                let state_store = context.state_store.clone();

                let _ = context.state_revision.get();

                let snapshot_missing =
                    state_store.read(|value| value.mls_checkpoint_for(&realm_for_crypto).is_none());
                // Only mutate when we'd actually move someone from Decrypting
                // into KeyMissing — Decrypting → Plaintext requires a real
                // decrypt attempt that this view doesn't yet run.
                // Peek first so we only take a (re-render-triggering) write lock
                // when at least one row would actually transition. Without this
                // guard every `state_store` change re-marked `messages` dirty even
                // when nothing changed, forcing a redundant repaint.
                let has_decrypting = snapshot_missing
                    && messages_sig
                        .get_untracked()
                        .iter()
                        .any(|msg| matches!(msg.crypto_state, MessageCryptoState::Decrypting));
                if has_decrypting {
                    let mut current = messages_sig.get_untracked().clone();
                    for msg in current.iter_mut() {
                        if matches!(msg.crypto_state, MessageCryptoState::Decrypting) {
                            msg.crypto_state = MessageCryptoState::KeyMissing;
                        }
                    }
                    event_sink.emit(ChatProjectionEvent::ReplaceMessages(current));
                }
            })
        };
    }

    {
        let realm_for_sidecar = selected_realm_after_initial_sync.clone();
        let messages_sig = messages;
        {
            let context = context.clone();

            scope.effect(move || {
                let state_store = context.state_store.clone();

                let _ = context.state_revision.get();

                let restored = state_store.read(|store| {
                    if !pending_messages_have_private_plaintext_sidecar(
                        messages_sig.get_untracked().as_slice(),
                        store,
                        &realm_for_sidecar,
                    ) {
                        return None;
                    }
                    let mut current = messages_sig.get_untracked().clone();
                    restore_pending_messages_from_private_plaintext_sidecar(
                        current.as_mut_slice(),
                        store,
                        &realm_for_sidecar,
                    );
                    Some(current)
                });
                if let Some(current) = restored {
                    event_sink.emit(ChatProjectionEvent::ReplaceMessages(current));
                }
            })
        };
    }
}

/// Load the Circles a new Strand may be scoped to.
///
/// Keyed on (server, actor, Realm) so a credential or context change retries
/// and nothing else does. The two guard Signals are read with `peek` because
/// this effect writes both of them: subscribing to them would make the load
/// re-trigger itself.
fn eligible_circle_scopes(
    scope: &Scope,
    context: Rc<crate::presentation::InksonContext>,

    controller: ChatController,
    base_url: String,
    realm_id: String,
    actor: String,
    token: Cage<String>,
) {
    let eligible_circle_scopes = controller.eligible_circle_scopes;
    let key_seen = controller.eligible_circle_scope_request_key_seen;
    let in_flight = controller.eligible_circle_scope_request_in_flight;
    let retry_revision = scope.cage(0_u64);
    key_seen.revise(String::clear);
    in_flight.revise(|value| *value = false);
    if let Err(error) = scope.on_cleanup(move || {
        let _ = key_seen.try_revise(String::clear);
        let _ = in_flight.try_revise(|value| *value = false);
    }) {
        scope.report_error(error);
    }
    {
        let context = context.clone();
        let effect_owner = scope.downgrade();
        scope.effect(move || {
            let _ = retry_revision.get();
            let credential = token.get();
            let session_context = context.clone();
            let generation = context.session_generation.get();
            let account = context.active_account.get();
            let base = base_url.clone();
            let realm = realm_id.clone();
            let request_key = format!("{base}\u{1f}{actor}\u{1f}{realm}");
            if !should_start_circle_scope_request(
                &credential,
                key_seen.get_untracked().as_str(),
                in_flight.get_untracked(),
                &request_key,
            ) {
                return;
            }
            {
                let next_value = request_key.clone();
                key_seen.revise(|value| *value = next_value);
            };
            {
                let next_value = true;
                in_flight.revise(|value| *value = next_value);
            };
            spawn_effect(&effect_owner, {
                async move {
                    let outcome = crate::transport::auth::with_authed_api(
                        &base,
                        credential,
                        |api| async move {
                            api.http()
                                .circle_list(&realm)
                                .await
                                .map_err(anyhow::Error::from)
                        },
                    )
                    .await;
                    if !session_context.session_matches(generation, &account)
                        || key_seen.get_untracked() != request_key
                    {
                        if key_seen.get_untracked() == request_key {
                            key_seen.revise(String::clear);
                            in_flight.revise(|value| *value = false);
                            retry_revision.revise(|value| *value = value.wrapping_add(1));
                        }
                        return;
                    }
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
                                    display: circle.display,
                                    member_count: u32::try_from(circle.member_ids.len())
                                        .unwrap_or(u32::MAX),
                                    state: circle.state,
                                    viewer_is_member: true,
                                })
                                .collect();
                            {
                                let next_value = summaries;
                                eligible_circle_scopes.revise(|value| *value = next_value);
                            };
                        }
                        Err(error) => {
                            if key_seen.get_untracked().as_str() == request_key {
                                // Permit a later credential/context change to retry,
                                // but do not immediately self-trigger this effect.
                                {
                                    let next_value = String::new();
                                    key_seen.revise(|value| *value = next_value);
                                };
                            }
                            tracing::warn!(
                                error = %error.display(),
                                "Circle scope picker load failed"
                            );
                        }
                    }
                    {
                        let next_value = false;
                        in_flight.revise(|value| *value = next_value);
                    };
                }
            });
        })
    };
}

fn spawn_effect(
    owner: &glory::ui::WeakScope,
    future: impl std::future::Future<Output = ()> + 'static,
) {
    if let Some(scope) = owner.upgrade()
        && let Err(error) = scope.spawn(future)
    {
        scope.report_error(error);
    }
}

/// A cancelled/failed read releases only its own uncompleted dedupe claim.
/// Source versions reject leaving and returning to an identical key (ABA).
struct PendingStringClaim {
    seen: Cage<String>,
    version: Option<u64>,
    completed: bool,
}
impl PendingStringClaim {
    fn new(seen: Cage<String>) -> Self {
        Self {
            seen,
            version: seen.try_version().ok(),
            completed: false,
        }
    }
    fn complete(&mut self) {
        self.completed = true;
    }
}
impl Drop for PendingStringClaim {
    fn drop(&mut self) {
        if !self.completed && self.version.is_some() && self.seen.try_version().ok() == self.version
        {
            let _ = self.seen.try_revise(String::clear);
        }
    }
}
struct PendingInitialSyncClaim {
    requested: Cage<bool>,
    finished: Cage<bool>,
    version: Option<u64>,
}
impl PendingInitialSyncClaim {
    fn new(requested: Cage<bool>, finished: Cage<bool>) -> Self {
        Self {
            requested,
            finished,
            version: requested.try_version().ok(),
        }
    }
}
impl Drop for PendingInitialSyncClaim {
    fn drop(&mut self) {
        if self.version.is_some()
            && self.requested.try_version().ok() == self.version
            && self
                .finished
                .try_with_untracked(|value| !*value)
                .unwrap_or(false)
        {
            let _ = self.requested.try_revise(|value| *value = false);
        }
    }
}
#[cfg(test)]
mod pending_claim_tests {
    use super::*;
    #[test]
    fn cancelled_owner_releases_its_unfinished_read_before_or_after_first_poll() {
        for poll_first in [false, true] {
            let executor = Rc::new(glory::core::executor::Executor::new(256));
            let app = glory::App::with_host(executor.clone(), glory::render::memory::Memory::new);
            let key = app.scope().cage("pending-key".to_owned());
            let owner = app.scope().child().unwrap();
            let claim = PendingStringClaim::new(key);
            owner
                .spawn(async move {
                    let _claim = claim;
                    std::future::pending::<()>().await;
                })
                .unwrap();
            if poll_first {
                let _ = executor.poll_one();
            }
            assert_eq!(key.get_untracked(), "pending-key");
            owner.dispose();
            assert!(key.get_untracked().is_empty());
            assert!(app.scope().is_alive());
        }
    }
    #[test]
    fn completed_or_superseded_read_never_releases_the_current_key() {
        let app = glory::App::memory();
        let key = app.scope().cage("same-key".to_owned());
        let mut completed = PendingStringClaim::new(key);
        completed.complete();
        drop(completed);
        assert_eq!(key.get_untracked(), "same-key");
        let stale = PendingStringClaim::new(key);
        key.revise(|value| *value = "different-key".into());
        key.revise(|value| *value = "same-key".into());
        drop(stale);
        assert_eq!(
            key.get_untracked(),
            "same-key",
            "an old same-key claim must not erase its replacement"
        );
    }
    #[test]
    fn initial_sync_releases_only_an_unfinished_matching_attempt() {
        let app = glory::App::memory();
        let requested = app.scope().cage(true);
        let finished = app.scope().cage(false);
        drop(PendingInitialSyncClaim::new(requested, finished));
        assert!(!requested.get_untracked());
        requested.revise(|value| *value = true);
        let completed = PendingInitialSyncClaim::new(requested, finished);
        finished.revise(|value| *value = true);
        drop(completed);
        assert!(requested.get_untracked());
        finished.revise(|value| *value = false);
        let replaced = PendingInitialSyncClaim::new(requested, finished);
        requested.revise(|value| *value = false);
        requested.revise(|value| *value = true);
        drop(replaced);
        assert!(requested.get_untracked());
    }
}
