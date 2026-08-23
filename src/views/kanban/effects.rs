use super::*;

#[component]
pub(super) fn KanbanEffects(
    controller: KanbanController,
    columns: Memo<Vec<KanbanColumn>>,
    route: Route,
    local_realm_id: String,
    base_url: String,
    token: Signal<String>,
    selected_realm_id: String,
    projection_realm_id: String,
    authority: arkret_sdk::PrincipalAuthorityKey,
    principal_id: String,
    device_id: String,
    sync_cursor: Signal<String>,
    realm_live_epoch: Signal<u64>,
) -> Element {
    let mut state_store = crate::app::SessionContext::get().state_store;
    let navigator = use_navigator();
    // Board-create operation ids still pending as of the last reconciliation
    // pass. Remembered across passes so the receipt migration below can detect
    // the pending -> accepted TRANSITION (an accepted row is no longer
    // pending, so it cannot be found by scanning the pending set).
    let mut awaiting_board_ops = use_signal(BTreeSet::<String>::new);
    let KanbanController {
        mut board_space_options,
        mut selected_board,
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

    // A pending Board create is rendered from the op log without touching the
    // selection or the URL. A row leaves the pending set exactly when its
    // receipt/backfill merge records the final Event id, so the migration is
    // detected as a TRANSITION: diff the remembered pending operation ids
    // against the current set and resolve the departed ones through the
    // holder-local alias. When nothing is selected (the create handler clears
    // the selection; a user who switched away is never hijacked), commit the
    // accepted Space id selection + canonical route in one step. The confirmed
    // option appears from the same op-log projection, so a repeated receipt or
    // a backfill-first ordering cannot duplicate it. Declared FIRST so the
    // transition wins over the options-seeding effect below on the pass where
    // the receipt lands.
    {
        let route_realm_id = selected_realm_id.clone();
        let pending_realm_id = local_realm_id.clone();
        use_effect(move || {
            let raw_operations = state_store.read().load().raw_operations;
            let pending = pending_board_creates_from_ops(&raw_operations, &pending_realm_id);
            let aliases = event_derived_target_aliases(&raw_operations);
            let (accepted, still_pending) =
                accepted_board_create_transition(&awaiting_board_ops.peek(), &pending, &aliases);
            if *awaiting_board_ops.peek() != still_pending {
                awaiting_board_ops.set(still_pending);
            }
            let Some(space_id) = accepted else {
                return;
            };
            if selected_board.peek().is_some() {
                return;
            }
            selected_board.set(Some(space_id.clone()));
            let _ = navigator.replace(kanban_board_route(&route_realm_id, space_id.as_str()));
        });
    }

    {
        let realm = local_realm_id.clone();
        use_effect(move || {
            let raw_operations = state_store.read().load().raw_operations;
            let containers = space_container_views_from_ops(&raw_operations, &realm);
            let strands = strand_views_from_ops(&raw_operations);
            // `board_space_options_from_projection` fails closed on non-SpaceId
            // rows, so a pending Board create never enters the confirmed option
            // set; it is rendered from `pending_board_creates_from_ops` until
            // the receipt reconciles it.
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
            // Seeding the first confirmed Board must yield while a create is
            // pending: the create handler cleared the selection precisely so
            // the pending surface (title + creating state) can show instead of
            // snapping back to the previous Board.
            if selected_board.peek().is_none()
                && pending_board_creates_from_ops(&raw_operations, &realm).is_empty()
                && let Some(first) = options.first()
            {
                selected_board.set(Some(first.id.clone()));
            }
        });
    }

    use_effect(move || {
        let commands = command_queue();
        if commands.is_empty() {
            return;
        }
        command_queue.set(std::collections::VecDeque::new());
        for command in commands {
            match command {
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
            let raw_operations = state_store.read().load().raw_operations;
            let aliases = event_derived_target_aliases(&raw_operations);
            let strand_id = resolve_event_derived_target_alias(&aliases, &strand_id);
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
                card_edit_body.set(draft.description_body);
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
            // `route_board_id` already failed closed on anything that is not a
            // canonical Space id, so the routed value is trusted here.
            if selected_board().as_ref() != Some(&board_id) {
                selected_board.set(Some(board_id));
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
            let aliases = event_derived_target_aliases(&raw_operations);
            let strand_id = resolve_event_derived_target_alias(&aliases, &strand_id);
            let Some(strand_board) = strand_views_from_ops(&raw_operations)
                .into_iter()
                .find(|view| view.strand_id == strand_id)
                .and_then(|view| view.board_space_id)
            else {
                return;
            };
            // The projection may still reference a holder-local handle; only a
            // canonical Space id may drive the selection.
            let Ok(strand_board) = arkret_sdk::SpaceId::new(strand_board) else {
                return;
            };
            if selected_board().as_ref() != Some(&strand_board) {
                selected_board.set(Some(strand_board));
            }
        });
    }

    // One-shot durable event backfill. Board rendering is event-sourced; there
    // is no user-selected collection View or manual projection refresh path.
    let mut bootstrapped = use_signal(|| false);
    let auto_base = base_url.clone();
    let auto_token = token;
    let auto_lifecycle_realm_id = local_realm_id.clone();
    use_future(move || {
        let base = auto_base.clone();
        let lifecycle_realm_id = auto_lifecycle_realm_id.clone();
        async move {
            if bootstrapped() {
                return;
            }
            bootstrapped.set(true);
            let api_token = auto_token();
            if api_token.trim().is_empty() {
                return;
            }
            // Backfill the realm's durable events into the op log. This is how the event-sourced
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
            // `ingest_kanban_events` handles the backfill event shape
            // (`event_kind`/`kind`, `operation_id`/`event_id`) and dedups by id.
            let complete_events = match events_res.as_ref() {
                Some(response) => match response.complete_events("kanban event projection") {
                    Ok(events) => events,
                    Err(error) => {
                        board_status.set(error.to_string());
                        return;
                    }
                },
                None => Vec::new(),
            };
            if !complete_events.is_empty() {
                let mut guard = state_store.write();
                crate::sync_engine::ingest_kanban_projection_events(
                    &mut guard,
                    &lifecycle_realm_id,
                    &complete_events,
                );
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
            let initial_cursor = sync_cursor.peek().clone();
            let initial_sync_ready = crate::app::account_sync_ready(&initial_cursor);
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
                initial_sync_ready,
                initial_epoch,
                &initial_mls_unlock,
            )
        }
    });
    let live_base = base_url.clone();
    let live_token = token;
    let live_lifecycle_realm_id = local_realm_id.clone();
    let live_lifecycle_local_realm_id = local_realm_id.clone();
    use_effect(move || {
        let base = live_base.clone();
        let lifecycle_realm_id = live_lifecycle_realm_id.clone();
        let lifecycle_local_realm_id = live_lifecycle_local_realm_id.clone();
        let api_token = live_token();
        if api_token.trim().is_empty() {
            return;
        }
        // Observe the cursor so the first successful account sync wakes this
        // effect, but reduce it to a readiness transition before constructing
        // the refresh key. Cursor tokens are checkpoints, not render
        // revisions; re-minting the same frontier must not backfill events.
        let account_sync_ready = crate::app::account_sync_ready(&sync_cursor());
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
            account_sync_ready,
            live_epoch,
            &mls_unlock,
        ) else {
            return;
        };
        live_refresh_key_seen.set(refresh_key);
        spawn(async move {
            // Event-sourced live reconcile. Pull the durable event log and fold
            // it into `raw_operations`; the columns memo renders that log.
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
                let Ok(events) = backfill.complete_events("kanban live reconciliation") else {
                    tracing::warn!("kanban backfill contains non-reducer event rows");
                    return;
                };
                let mut store = state_store.write();
                crate::sync_engine::ingest_kanban_projection_events(
                    &mut store,
                    &lifecycle_local_realm_id,
                    &events,
                );
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
        let restore_authority = authority.clone();
        let restore_actor = principal_id.clone();
        let restore_device = device_id.clone();
        let restore_sync_cursor = sync_cursor;
        let restore_realm_live_epoch = realm_live_epoch;
        use_effect(move || {
            let Some(card) = selected_card() else {
                return;
            };
            if !private_narrative_restore_needed(card.description_locked, card.synthesis_locked) {
                return;
            }
            let api_token = restore_token();
            if restore_base.trim().is_empty()
                || api_token.trim().is_empty()
                || restore_realm_id.trim().is_empty()
                || restore_actor.trim().is_empty()
                || restore_device.as_str().trim().is_empty()
            {
                return;
            }
            let secure_store = crate::secure_key_store::default_secure_key_store("inkson");
            if !matches!(
                crate::mls::runtime::load_account_mls_secret(
                    secure_store.as_ref(),
                    &restore_authority
                ),
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
                "{}|{}|{}|{}|{}|{}|description={}|synthesis={}",
                restore_base.trim().trim_end_matches('/'),
                restore_actor.trim(),
                restore_device.as_str().trim(),
                restore_realm_id.trim(),
                card.primary_strand_id,
                projection_shape,
                card.description_locked,
                card.synthesis_locked
            );
            // Wake when account bootstrap first becomes ready, but never use
            // the opaque cursor token as a data revision. Durable Realm
            // changes are represented by the explicit live epoch.
            let account_sync_ready = crate::app::account_sync_ready(&restore_sync_cursor());
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
            let authority = restore_authority.clone();
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
                    let device_for_fetch = device.to_string();
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
                                .await?
                                .complete_events("kanban MLS sidecar restore projection")?;
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
                            &authority,
                            &actor,
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
                        .is_some_and(|card| !card.description_locked && !card.synthesis_locked);
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
                let Ok(events) = backfill.complete_events("kanban cold-start projection") else {
                    tracing::warn!("kanban backfill contains non-reducer event rows");
                    return;
                };
                // Event-sourced cold start:
                // fold the durable event log into `raw_operations`. The `columns`
                // memo + the container/selection sync effect re-project the board
                // purely from events; this spawn ONLY ingests. The per-session
                // server strand/space projection endpoints are dropped as content
                // sources — they cannot carry another member's encrypted content.
                let mut store = state_store.write();
                crate::sync_engine::ingest_kanban_projection_events(
                    &mut store,
                    &lifecycle_local_realm_id,
                    &events,
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

fn private_narrative_restore_needed(description_locked: bool, synthesis_locked: bool) -> bool {
    description_locked || synthesis_locked
}

#[cfg(test)]
mod private_narrative_restore_tests {
    use super::private_narrative_restore_needed;

    #[test]
    fn description_only_lock_triggers_backup_restore() {
        assert!(private_narrative_restore_needed(true, false));
        assert!(private_narrative_restore_needed(false, true));
        assert!(!private_narrative_restore_needed(false, false));
    }
}
