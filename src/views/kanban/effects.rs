use super::*;

#[component]
pub(super) fn KanbanEffects(
    controller: KanbanController,
    columns: Memo<Vec<KanbanColumn>>,
    route: Route,
    local_realm_id: String,
    base_url: String,
    token: Signal<String>,
    seed_fallback_allowed: bool,
    selected_realm_id: String,
    projection_realm_id: String,
    account_did: String,
    device_id: String,
    sync_cursor: Signal<String>,
    realm_live_epoch: Signal<u64>,
) -> Element {
    let mut state_store = crate::app::SessionContext::get().state_store;
    let KanbanController {
        mut board_space_options,
        mut selected_board_space_id,
        mut collection_view_columns,
        board_view_id,
        mut projection_source,
        mut lifecycle_container_projection,
        mut lifecycle_strand_projection,
        mut selected_card,
        mut mls_sidecar_restore_key_seen,
        mut card_edit_title,
        mut card_edit_description,
        mut card_edit_body,
        mut card_edit_synthesis,
        mut card_edit_synthesis_target_id,
        mut card_edit_labels,
        mut card_edit_assignee,
        mut card_edit_due,
        mut card_edit_calendar,
        mut calendar_rsvp_occurrence,
        mut editing_card_detail,
        mut card_detail_edit_status,
        mut assignee_picker_open,
        mut assignee_filter,
        mut assignee_selected_actor_ids,
        mut assignee_edit_status,
        mut due_picker_open,
        mut due_edit_value,
        mut due_calendar_month,
        mut due_edit_status,
        mut card_detail_actions_open,
        mut card_detail_discussion_mounted_for,
        mut card_detail_tab,
        card_detail_sidebar_tab,
        mut card_synthesis_history_open_id,
        mut card_synthesis_selected_revision_id,
        mut member_handle_fetching,
        mut command_queue,
        mut board_status,
        ..
    } = controller;

    {
        let realm = local_realm_id.clone();
        use_effect(move || {
            let raw_operations = state_store.read().load().raw_operations;
            let containers = space_container_views_from_ops(&raw_operations, &realm);
            let strands = strand_views_from_ops(&raw_operations);
            let options = board_space_options_from_projection(&containers);
            if *lifecycle_container_projection.peek() != containers {
                lifecycle_container_projection.set(containers);
            }
            if *lifecycle_strand_projection.peek() != strands {
                lifecycle_strand_projection.set(strands);
            }
            if !options.is_empty() && *board_space_options.peek() != options {
                board_space_options.set(options.clone());
            }
            if selected_board_space_id.peek().trim().is_empty()
                && let Some(first) = options.first()
            {
                selected_board_space_id.set(first.id.clone());
            }
        });
    }

    let refresh_base_url = base_url.clone();
    let refresh_lifecycle_realm_id = local_realm_id.clone();
    let refresh_decrypt_realm_id = selected_realm_id.clone();
    let refresh_decrypt_actor = account_did.clone();
    let refresh_decrypt_device = device_id.clone();
    use_effect(move || {
        let commands = command_queue();
        if commands.is_empty() {
            return;
        }
        command_queue.set(std::collections::VecDeque::new());
        for command in commands {
            match command {
                KanbanCommand::RefreshProjection => refresh_projection(
                    refresh_base_url.clone(),
                    token(),
                    board_view_id(),
                    refresh_lifecycle_realm_id.clone(),
                    refresh_decrypt_realm_id.clone(),
                    refresh_decrypt_actor.clone(),
                    refresh_decrypt_device.clone(),
                    seed_fallback_allowed,
                    state_store,
                    selected_board_space_id,
                    collection_view_columns,
                    projection_source,
                    board_status,
                ),
                KanbanCommand::SubmitOperation {
                    base_url,
                    token,
                    realm_id,
                    operation,
                    scope_security_encrypted,
                } => submit_kanban_operation_event(
                    base_url,
                    token,
                    realm_id,
                    *operation,
                    scope_security_encrypted,
                    state_store,
                    board_status,
                ),
            }
        }
    });

    use_effect(move || {
        if !state_store.read().has_pending_local_projection_commands() {
            return;
        }
        state_store.write().project_pending_local_commands();
    });

    use_effect(move || {
        sync_selected_card_from_columns(selected_card, &columns());
    });

    {
        let routed_strand_id = route_card_strand_id(&route);
        use_effect(move || {
            let Some(strand_id) = routed_strand_id.clone() else {
                return;
            };
            if selected_card()
                .as_ref()
                .is_some_and(|card| card_matches_strand_id(card, &strand_id))
            {
                return;
            }
            if let Some(card) = find_card_by_strand_id(&columns.read(), &strand_id) {
                let draft = card_detail_draft_from_card(&card);
                card_edit_title.set(draft.title);
                card_edit_description.set(draft.description);
                card_edit_body.set(draft.body);
                card_edit_synthesis.set(draft.synthesis);
                card_edit_synthesis_target_id.set(None);
                card_edit_labels.set(draft.labels.join(", "));
                card_edit_assignee.set(draft.assignee);
                card_edit_due.set(draft.due);
                let calendar = draft.calendar.clone();
                card_edit_calendar.set(calendar.clone());
                calendar_rsvp_occurrence.set(calendar_occurrence_hint(&calendar));
                editing_card_detail.set(false);
                card_detail_edit_status.set(String::new());
                assignee_picker_open.set(false);
                assignee_filter.set(String::new());
                assignee_selected_actor_ids
                    .set(card_assigned_actor_ids(&card).into_iter().collect());
                assignee_edit_status.set(String::new());
                due_picker_open.set(false);
                due_edit_value.set(editor_value_for_optional_card_field(&card.due));
                due_calendar_month.set(due_calendar_month_for_value(&card.due));
                due_edit_status.set(String::new());
                card_detail_actions_open.set(false);
                let routed_tab = card_detail_tab_from_current_url();
                if routed_tab == CardDetailContentTab::Discussion {
                    card_detail_discussion_mounted_for.set(Some(card.primary_strand_id.clone()));
                }
                card_detail_tab.set(routed_tab);
                card_synthesis_history_open_id.set(None);
                card_synthesis_selected_revision_id.set(None);
                selected_card.set(Some(card));
            }
        });
    }

    {
        let routed_board_id = route_board_id(&route);
        use_effect(move || {
            let Some(board_id) = routed_board_id.clone() else {
                return;
            };
            if selected_board_space_id() != board_id {
                selected_board_space_id.set(board_id);
            }
        });
    }

    {
        let routed_strand_id = route_card_strand_id(&route);
        use_effect(move || {
            let Some(strand_id) = routed_strand_id.clone() else {
                return;
            };
            let raw_operations = state_store.read().load().raw_operations;
            let Some(strand_board) = strand_views_from_ops(&raw_operations)
                .into_iter()
                .find(|view| view.strand_id == strand_id)
                .and_then(|view| view.board_space_id)
            else {
                return;
            };
            if selected_board_space_id() != strand_board {
                selected_board_space_id.set(strand_board);
            }
        });
    }

    // T20 — auto-refresh-on-mount. The component renders empty or explicit
    // SeedFallback synchronously, then fires an async fetch against soland's
    // `/_arkret/self/views/:id/projection` when a View id is provided. Success
    // promotes the board to ApiDerived; failure leaves the current server
    // projection / empty state in place with a status note.
    // The `bootstrapped` guard ensures we run this only once per mount —
    // matching the login view's `auto_capture_bootstrapped` pattern so a
    // second render (e.g. from a parent signal) doesn't re-trigger the
    // fetch.
    let mut bootstrapped = use_signal(|| false);
    let auto_base = base_url.clone();
    let auto_token = token;
    let auto_seed_fallback_allowed = seed_fallback_allowed;
    let auto_board_view_id = board_view_id;
    let auto_lifecycle_realm_id = local_realm_id.clone();
    let auto_decrypt_realm_id = selected_realm_id.clone();
    let auto_decrypt_actor = account_did.clone();
    let auto_decrypt_device = device_id.clone();
    use_future(move || {
        let base = auto_base.clone();
        let lifecycle_realm_id = auto_lifecycle_realm_id.clone();
        let decrypt_realm_id = auto_decrypt_realm_id.clone();
        let decrypt_actor = auto_decrypt_actor.clone();
        let decrypt_device = auto_decrypt_device.clone();
        async move {
            if bootstrapped() {
                return;
            }
            bootstrapped.set(true);
            let api_token = auto_token();
            if api_token.trim().is_empty() {
                return;
            }
            // Backfill the realm's durable events into the op log FIRST, before the
            // materialized-board-View gate below. This is how the event-sourced
            // Space-container / Strand projections (and therefore the board
            // switcher) discover content created by OTHER members — including a
            // board an invited member deep-links into before its create arrives on
            // the live subscribe. It depends only on the realm, not on a View.
            let events_res = if lifecycle_realm_id.trim().is_empty() {
                None
            } else {
                let realm_id = lifecycle_realm_id.clone();
                match with_authed_api(&base, api_token.clone(), |api| async move {
                    api.event_submitter()?.backfill(&realm_id).await
                })
                .await
                {
                    Ok(response) => Some(response),
                    Err(err) if err.is_auth_expired() => return,
                    Err(_) => None,
                }
            };
            // Ingest the backfilled events into `raw_operations` so the event-
            // sourced board/list/card projection sees cross-member content.
            // Previously the bootstrap used these events ONLY for the strand
            // overlay (`strand_update_operations_from_events`) and never folded
            // them into `raw_operations`; combined with the empty-View early-return
            // below skipping the backfill entirely, a joined member who deep-linked
            // to another member's board ingested nothing and saw an empty board
            // switcher. `ingest_kanban_events` handles the backfill event shape
            // (`event_kind`/`kind`, `operation_id`/`event_id`) and dedups by id.
            if let Some(resp) = events_res.as_ref() {
                let event_values = resp.event_values();
                let mut guard = state_store.write();
                crate::sync_engine::ingest_kanban_projection_events(
                    &mut guard,
                    &lifecycle_realm_id,
                    &event_values,
                );
            }

            let view = auto_board_view_id();
            if view.trim().is_empty() {
                board_status.set(
                    "No board View selected; using Space-container/Strand projections and local queue only"
                        .to_owned(),
                );
                return;
            }
            let remote_update_operations = events_res
                .as_ref()
                .map(|resp| strand_update_operations_from_events(&resp.event_values()))
                .unwrap_or_default();
            match with_authed_sdk_client(&base, api_token, |http| async move {
                crate::transport::realm_read::collection_projection(&http, &view).await
            })
            .await
            {
                Ok(projection) => {
                    let cols = {
                        let decrypt_store = state_store.read();
                        let decrypt_ctx = MlsDecryptCtx {
                            state_store: &decrypt_store,
                            realm_id: &decrypt_realm_id,
                            actor_id: &decrypt_actor,
                            device_id: &decrypt_device,
                            circle_id: None,
                        };
                        overlay_collection_projection_with_operations(
                            &projection,
                            &decrypt_store,
                            &selected_board_space_id(),
                            &remote_update_operations,
                            Some(&decrypt_ctx),
                        )
                    };
                    if !cols.is_empty() {
                        // Opt-in trusted server materialization: hand the
                        // overlaid View columns to the `columns` memo, which
                        // prefers them over the event-sourced projection.
                        collection_view_columns.set(Some(cols));
                    }
                    projection_source.set(BoardProjectionSource::ApiDerived);
                    board_status.set(format!(
                        "Board view loaded: {} group(s) · view={}",
                        projection.groups.len(),
                        projection.view_id.as_str()
                    ));
                }
                Err(err) => {
                    if auto_seed_fallback_allowed {
                        projection_source.set(BoardProjectionSource::SeedFallback);
                        board_status.set(format!(
                            "Board data unavailable on mount: {}; showing sample fallback",
                            err.display()
                        ));
                    } else {
                        projection_source.set(BoardProjectionSource::Unavailable);
                        board_status.set(format!(
                            "Board view unavailable on mount: {}; keeping lifecycle projection",
                            err.display()
                        ));
                    }
                }
            }
        }
    });

    // F-KANBAN-LIVE-1: refresh the board projection only when account
    // subscribe advances. The global SyncEngine owns the liveness channel;
    // this panel must not poll `spaces` / `strands` / `events` on a timer while
    // no durable event has arrived.
    let mut live_refresh_key_seen = use_signal({
        let initial_realm_id = local_realm_id.clone();
        move || {
            let initial_view = board_view_id.peek().clone();
            let initial_cursor = sync_cursor.peek().clone();
            let initial_sync_ready = {
                let cursor = initial_cursor.trim();
                !(cursor.is_empty() || cursor == "-")
            };
            let initial_epoch = *realm_live_epoch.peek();
            let initial_mls_unlock = {
                let store = state_store.peek();
                kanban_mls_unlock_signature(
                    !store.mls_snapshots().is_empty(),
                    crate::app::local_mls_epoch_floor_all(&store),
                )
            };
            kanban_projection_refresh_key(
                &initial_realm_id,
                &initial_view,
                initial_sync_ready,
                initial_epoch,
                &initial_mls_unlock,
            )
        }
    });
    let live_base = base_url.clone();
    let live_token = token;
    let live_board_view_id = board_view_id;
    let live_lifecycle_realm_id = local_realm_id.clone();
    let live_lifecycle_local_realm_id = local_realm_id.clone();
    let live_decrypt_realm_id = selected_realm_id.clone();
    let live_decrypt_actor = account_did.clone();
    let live_decrypt_device = device_id.clone();
    use_effect(move || {
        let base = live_base.clone();
        let lifecycle_realm_id = live_lifecycle_realm_id.clone();
        let lifecycle_local_realm_id = live_lifecycle_local_realm_id.clone();
        let decrypt_realm_id = live_decrypt_realm_id.clone();
        let decrypt_actor = live_decrypt_actor.clone();
        let decrypt_device = live_decrypt_device.clone();
        let api_token = live_token();
        let view = live_board_view_id();
        if api_token.trim().is_empty() {
            return;
        }
        // Observe the cursor so the first successful account sync wakes this
        // effect, but reduce it to a readiness transition before constructing
        // the refresh key. Cursor tokens are checkpoints, not render
        // revisions; re-minting the same frontier must not backfill events.
        let account_sync_ready = {
            let cursor = sync_cursor();
            let cursor = cursor.trim();
            !(cursor.is_empty() || cursor == "-")
        };
        // Reading `realm_live_epoch` here subscribes this effect to the per-realm
        // events engine, so fresh cross-member events trigger a reproject even
        // when the account `sync_cursor` never advanced for them.
        let live_epoch = realm_live_epoch();
        // Third freshness axis: read the MLS-unlock state through `.read()` so
        // this effect subscribes to `state_store` and re-runs when a snapshot is
        // installed. An invitee's Welcome/snapshot can land AFTER the one-shot
        // bootstrap backfill, while the account cursor and events engine are both
        // stale — folding snapshot-presence + epoch floor into the refresh key
        // makes that arrival re-trigger the backfill so the pre-join history can
        // finally decrypt, instead of staying blank until a manual page refresh.
        // (invitee-history-late-decrypt)
        let mls_unlock = {
            let store = state_store.read();
            kanban_mls_unlock_signature(
                !store.mls_snapshots().is_empty(),
                crate::app::local_mls_epoch_floor_all(&store),
            )
        };
        let Some(refresh_key) = next_kanban_projection_refresh_key(
            live_refresh_key_seen.peek().as_str(),
            &lifecycle_realm_id,
            &view,
            account_sync_ready,
            live_epoch,
            &mls_unlock,
        ) else {
            return;
        };
        live_refresh_key_seen.set(refresh_key);
        spawn(async move {
            if !view.trim().is_empty() {
                let view_for_call = view.clone();
                if let Ok(projection) =
                    with_authed_sdk_client(&base, api_token, |http| async move {
                        crate::transport::realm_read::collection_projection(&http, &view_for_call)
                            .await
                    })
                    .await
                {
                    let cols = {
                        let decrypt_store = state_store.read();
                        let decrypt_ctx = MlsDecryptCtx {
                            state_store: &decrypt_store,
                            realm_id: &decrypt_realm_id,
                            actor_id: &decrypt_actor,
                            device_id: &decrypt_device,
                            circle_id: None,
                        };
                        overlay_collection_projection_with_operations(
                            &projection,
                            &decrypt_store,
                            &selected_board_space_id(),
                            &[],
                            Some(&decrypt_ctx),
                        )
                    };
                    // Opt-in trusted server materialization. Only overwrite when
                    // the server returned a non-empty projection — an empty
                    // response shouldn't wipe the event-sourced board.
                    if !cols.is_empty() {
                        collection_view_columns.set(Some(cols));
                        projection_source.set(BoardProjectionSource::ApiDerived);
                    }
                }
            } else {
                // Event-sourced live reconcile (spec
                // `arkret-work/specs/active/2026-06-29-kanban-event-sourced-projection.md`).
                // The per-session server strand/space projections are
                // visibility-filtered and, for an encrypted realm, never carry
                // another member's card content (title in `encrypted_metadata`,
                // unreadable to the server). Pull the durable event log — the
                // only source carrying every member's space/strand creates —
                // and fold it into `raw_operations`. The `columns` memo + the
                // container/selection sync effect re-project the board purely
                // from events; this branch ONLY ingests. This is what makes
                // cross-member cards appear.
                collection_view_columns.set(None);
                let events_res = {
                    let realm_id = lifecycle_realm_id.clone();
                    with_authed_api(&base, api_token, |api| async move {
                        api.event_submitter()?.backfill(&realm_id).await
                    })
                    .await
                };
                if events_res
                    .as_ref()
                    .err()
                    .is_some_and(|err| err.is_auth_expired())
                {
                    return;
                }
                if let Ok(backfill) = events_res {
                    let event_values = backfill.event_values();
                    let mut store = state_store.write();
                    crate::sync_engine::ingest_kanban_projection_events(
                        &mut store,
                        &lifecycle_local_realm_id,
                        &event_values,
                    );
                }
            }
        });
    });

    // Locked author-private fields can become readable after another device
    // uploads the account-private plaintext sidecar. A device that already has
    // the account MLS secret should restore that sidecar silently with active
    // device proof, then re-project the current board using a fresh backfill.
    {
        let restore_base = base_url.clone();
        let restore_token = token;
        let restore_realm_id = selected_realm_id.clone();
        let restore_local_realm_id = local_realm_id.clone();
        let restore_actor = account_did.clone();
        let restore_device = device_id.clone();
        let restore_sync_cursor = sync_cursor;
        let restore_realm_live_epoch = realm_live_epoch;
        use_effect(move || {
            let Some(card) = selected_card() else {
                return;
            };
            if !card.body_locked && !card.synthesis_locked {
                return;
            }
            let api_token = restore_token();
            if restore_base.trim().is_empty()
                || api_token.trim().is_empty()
                || restore_realm_id.trim().is_empty()
                || restore_actor.trim().is_empty()
                || restore_device.trim().is_empty()
            {
                return;
            }
            let secure_store = crate::secure_key_store::default_secure_key_store("inkson");
            if !matches!(
                crate::mls::runtime::load_account_mls_secret(secure_store.as_ref(), &restore_actor),
                Ok(Some(_))
            ) {
                return;
            }
            let projection_shape = {
                let containers_len = lifecycle_container_projection.read().len();
                let strands_len = lifecycle_strand_projection.read().len();
                format!("{containers_len}:{strands_len}")
            };
            let restore_key = format!(
                "{}|{}|{}|{}|{}|{}|body={}|synthesis={}",
                restore_base.trim().trim_end_matches('/'),
                restore_actor.trim(),
                restore_device.trim(),
                restore_realm_id.trim(),
                card.primary_strand_id,
                projection_shape,
                card.body_locked,
                card.synthesis_locked
            );
            // Wake when account bootstrap first becomes ready, but never use
            // the opaque cursor token as a data revision. Durable Realm
            // changes are represented by the explicit live epoch.
            let account_sync_ready = {
                let cursor = restore_sync_cursor();
                let cursor = cursor.trim();
                !(cursor.is_empty() || cursor == "-")
            };
            let live_epoch = restore_realm_live_epoch();
            let restore_key = format!(
                "{restore_key}|sync_ready={}|epoch={live_epoch}",
                account_sync_ready as u8
            );
            if mls_sidecar_restore_key_seen() == restore_key {
                return;
            }
            mls_sidecar_restore_key_seen.set(restore_key);

            let base = restore_base.clone();
            let realm_id = restore_realm_id.clone();
            let local_realm_id = restore_local_realm_id.clone();
            let actor = restore_actor.clone();
            let device = restore_device.clone();
            spawn(async move {
                for attempt in 0..5u32 {
                    if attempt > 0 {
                        crate::runtime_helpers::sleep_for(std::time::Duration::from_millis(
                            500 * (1 << (attempt - 1)),
                        ))
                        .await;
                    }
                    let actor_for_fetch = actor.clone();
                    let device_for_fetch = device.clone();
                    let realm_for_fetch = realm_id.clone();
                    let result =
                        with_authed_api(&base, api_token.clone(), move |api| async move {
                            let payload = crate::mls::account_recovery::fetch_mls_restore_payload_with_unlock_proof(
                                &api,
                                &actor_for_fetch,
                                &device_for_fetch,
                            )
                            .await?;
                            let events = api
                                .event_submitter()?
                                .backfill(&realm_for_fetch)
                                .await
                                .map(|response| response.event_values())
                                .unwrap_or_default();
                            Ok((payload, events))
                        })
                        .await;
                    let (payload, events) = match result {
                        Ok(value) => value,
                        Err(error) => {
                            if let Some(retry_after_ms) =
                                crate::api_error::rate_limited_retry_after(error.inner())
                            {
                                tracing::warn!(
                                    target: "mls_sidecar_restore",
                                    retry_after_ms,
                                    "key-backup unlock rate limited; stopping sidecar restore retries"
                                );
                                break;
                            }
                            if let Some(backoff) = error
                                .inner()
                                .downcast_ref::<crate::key_backup::KeyBackupUnlockBackoff>(
                            ) {
                                tracing::debug!(
                                    target: "mls_sidecar_restore",
                                    retry_after_ms = backoff.retry_after_ms(),
                                    "key-backup unlock is in local backoff; stopping sidecar restore retries"
                                );
                                break;
                            }
                            continue;
                        }
                    };

                    let secure_store = crate::secure_key_store::default_secure_key_store("inkson");
                    let restored_private_plaintext = {
                        let mut store = state_store.write();
                        let report = crate::mls::account_recovery::restore_mls_history_with_local_secret_from_payload(
                            &payload,
                            &mut store,
                            secure_store.as_ref(),
                            &actor,
                            &device,
                        );
                        report.private_plaintext_restored || report.restored > 0
                    };

                    // Fold the freshly backfilled events into the op log. The
                    // restore also wrote the account-private plaintext sidecar
                    // into `state_store`, so the `columns` memo re-projects with
                    // the now-unlockable decrypt context automatically — no
                    // explicit reproject here.
                    {
                        let mut store = state_store.write();
                        crate::sync_engine::ingest_kanban_projection_events(
                            &mut store,
                            &local_realm_id,
                            &events,
                        );
                    }
                    let card_unlocked = selected_card()
                        .is_some_and(|card| !card.body_locked && !card.synthesis_locked);
                    if restored_private_plaintext || card_unlocked {
                        break;
                    }
                }
            });
        });
    }

    // Hydrate Space-container / Strand lifecycle state from the soland
    // `/_arkret/self/realms/{realm_id}/{spaces|strands}` endpoints so
    // an Archive accepted on the server stays archived after a page
    // refresh. The probe is fire-and-forget; a 404 / 401 just leaves
    // columns/cards in their `Active` default and the user is no worse
    // off than before this wiring.
    let mut lifecycle_bootstrapped_for = use_signal(String::new);
    let lifecycle_realm_id = local_realm_id.clone();
    // When the kanban panel mounts on a card-detail URL
    // (`/kanban/<realm>/task/<strand>`), the card's home board is resolved
    // by the route → board reconciler effect above (from the event-folded
    // strands); this cold-start spawn only needs to ingest the durable log.
    if !lifecycle_realm_id.is_empty() && lifecycle_bootstrapped_for() != lifecycle_realm_id {
        lifecycle_bootstrapped_for.set(lifecycle_realm_id.clone());
        let base = base_url.clone();
        let lifecycle_token = token;
        let lifecycle_local_realm_id = local_realm_id.clone();
        spawn(async move {
            let realm_id = lifecycle_realm_id.clone();
            let api_token = lifecycle_token();
            if api_token.trim().is_empty() {
                return;
            }
            let events_res = {
                let realm_id = realm_id.clone();
                with_authed_api(&base, api_token, |api| async move {
                    api.event_submitter()?.backfill(&realm_id).await
                })
                .await
            };
            if events_res
                .as_ref()
                .err()
                .is_some_and(|err| err.is_auth_expired())
            {
                return;
            }
            if let Ok(backfill) = events_res {
                let event_values = backfill.event_values();
                // Event-sourced cold start (spec
                // `arkret-work/specs/active/2026-06-29-kanban-event-sourced-projection.md`):
                // fold the durable event log into `raw_operations`. The `columns`
                // memo + the container/selection sync effect re-project the board
                // purely from events; this spawn ONLY ingests. The per-session
                // server strand/space projection endpoints are dropped as content
                // sources — they cannot carry another member's encrypted content.
                let mut store = state_store.write();
                crate::sync_engine::ingest_kanban_projection_events(
                    &mut store,
                    &lifecycle_local_realm_id,
                    &event_values,
                );
            }
        });
    }

    // R3.2 handle rendering: roster rows may omit inline handle claims for
    // privacy, size, or freshness. When the Members tab is actually open,
    // backfill missing current primary handles through the subject/context
    // reverse lookup and cache the result locally with a short TTL.
    {
        let handle_base_url = base_url.clone();
        let handle_realm_id = selected_realm_id.clone();
        let handle_projection_realm_id = projection_realm_id.clone();
        let handle_token = token;
        use_effect(move || {
            let should_fetch_member_handles = card_detail_sidebar_tab()
                == CardDetailSidebarTab::Members
                || card_detail_tab() == CardDetailContentTab::Synthesis;
            if !should_fetch_member_handles {
                return;
            }
            let Some(card) = selected_card() else {
                return;
            };
            if card_detail_discussion_mounted_for().as_deref()
                == Some(card.primary_strand_id.as_str())
            {
                // The mounted ChatPanel owns the same shared resolver. Avoid
                // issuing a duplicate request from the parent card surface.
                return;
            }
            let store_snapshot = state_store.read().load();
            let projection = store_snapshot.realm_tree_projections.get(&handle_realm_id);
            let rows = realm_member_roster(projection);
            if rows.is_empty() {
                return;
            }
            let realm_context = member_roster_realm_context(
                &handle_realm_id,
                &handle_projection_realm_id,
                projection,
            );
            let fetches = {
                let store = state_store.read();
                let in_flight = member_handle_fetching.read();
                crate::views::member_display::missing_member_handle_lookups(
                    &store,
                    &realm_context,
                    &rows,
                    &in_flight,
                )
            };
            for request in fetches {
                let request_key = request.request_key.clone();
                member_handle_fetching.write().insert(request_key.clone());
                let base = handle_base_url.clone();
                let api_token = handle_token();
                let mut fetching = member_handle_fetching;
                let store = state_store;
                spawn(async move {
                    crate::views::member_display::fetch_and_cache_member_handle(
                        base, api_token, store, request,
                    )
                    .await;
                    fetching.write().remove(&request_key);
                });
            }
        });
    }

    rsx! {}
}

#[allow(clippy::too_many_arguments)]
fn refresh_projection(
    base_url: String,
    api_token: String,
    view: String,
    lifecycle_realm_id: String,
    decrypt_realm_id: String,
    decrypt_actor: String,
    decrypt_device: String,
    seed_fallback_allowed: bool,
    state_store: SyncSignal<LocalStateStore>,
    selected_board_space_id: Signal<String>,
    mut collection_view_columns: Signal<Option<Vec<KanbanColumn>>>,
    mut projection_source: Signal<BoardProjectionSource>,
    mut board_status: Signal<String>,
) {
    if view.trim().is_empty() {
        board_status
            .set("enter a Board View ID before refreshing collection projection".to_owned());
        return;
    }

    spawn(async move {
        let events_res = if lifecycle_realm_id.trim().is_empty() {
            None
        } else {
            let realm_id = lifecycle_realm_id.clone();
            with_authed_api(&base_url, api_token.clone(), |api| async move {
                api.event_submitter()?.backfill(&realm_id).await
            })
            .await
            .ok()
        };
        let remote_update_operations = events_res
            .as_ref()
            .map(|resp| strand_update_operations_from_events(&resp.event_values()))
            .unwrap_or_default();
        match with_authed_sdk_client(&base_url, api_token, |http| async move {
            crate::transport::realm_read::collection_projection(&http, &view).await
        })
        .await
        {
            Ok(projection) => {
                let columns = {
                    let decrypt_store = state_store.read();
                    let decrypt_ctx = MlsDecryptCtx {
                        state_store: &decrypt_store,
                        realm_id: &decrypt_realm_id,
                        actor_id: &decrypt_actor,
                        device_id: &decrypt_device,
                        circle_id: None,
                    };
                    overlay_collection_projection_with_operations(
                        &projection,
                        &decrypt_store,
                        &selected_board_space_id(),
                        &remote_update_operations,
                        Some(&decrypt_ctx),
                    )
                };
                if !columns.is_empty() {
                    collection_view_columns.set(Some(columns));
                }
                projection_source.set(BoardProjectionSource::ApiDerived);
                board_status.set(format!(
                    "API projection · {} groups · view={}",
                    projection.groups.len(),
                    projection.view_id.as_str()
                ));
            }
            Err(err) => {
                if seed_fallback_allowed {
                    let columns = overlay_local_card_creates(
                        seed_columns(),
                        &state_store.read(),
                        &selected_board_space_id(),
                    );
                    collection_view_columns.set(Some(columns));
                    projection_source.set(BoardProjectionSource::SeedFallback);
                    board_status.set(format!(
                        "Board data unavailable: {}; showing sample fallback",
                        err.display()
                    ));
                } else {
                    projection_source.set(BoardProjectionSource::Unavailable);
                    board_status.set(format!(
                        "Board view unavailable: {}; keeping lifecycle projection",
                        err.display()
                    ));
                }
            }
        }
    });
}
