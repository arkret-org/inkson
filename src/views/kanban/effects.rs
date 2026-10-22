use super::projection_reads::ProjectionReadSet;
use super::*;

fn kanban_read_account_scope(
    account: Option<crate::config::ActiveAccountContext>,
) -> Option<(
    String,
    arkret_sdk::AccountId,
    arkret_sdk::DeviceId,
    url::Url,
)> {
    account.map(|account| {
        (
            account.profile_id,
            account.authority,
            account.device_id,
            account.server_url,
        )
    })
}

struct KanbanProjectionSnapshot {
    containers: Option<Vec<crate::state::projection_views::SpaceContainerProjectionView>>,
    strands: Option<Vec<crate::state::projection_views::StrandProjectionView>>,
}

async fn fetch_kanban_projection_snapshot(
    api: crate::transport::TransportClient,
    realm_id: &str,
    needed: ProjectionReadSet,
) -> anyhow::Result<KanbanProjectionSnapshot> {
    let http = api.sdk_http_client()?;
    // Read independent, complete derived Space/Strand pages concurrently.
    // These rows are not an authoring basis or a governance head;
    // accepted Events remain the canonical truth source.
    let (spaces, strands) = futures_util::future::join(
        async {
            if needed.spaces {
                Some(crate::transport::realm_read::list_realm_spaces(&http, realm_id).await)
            } else {
                None
            }
        },
        async {
            if needed.strands {
                Some(crate::transport::realm_read::list_realm_strands(&http, realm_id).await)
            } else {
                None
            }
        },
    )
    .await;
    let spaces = match spaces {
        Some(Ok(spaces)) => Some(spaces.into_iter().map(Into::into).collect::<Vec<_>>()),
        None => None,
        Some(Err(error)) => {
            if crate::api_error::is_auth_expired_error(&error) {
                return Err(error);
            }
            tracing::warn!(%error, %realm_id, "kanban Space baseline unavailable");
            None
        }
    };
    let strands = match strands {
        Some(Ok(strands)) => Some(strands.into_iter().map(Into::into).collect::<Vec<_>>()),
        None => None,
        Some(Err(error)) => {
            if crate::api_error::is_auth_expired_error(&error) {
                return Err(error);
            }
            tracing::warn!(%error, %realm_id, "kanban Strand baseline unavailable");
            None
        }
    };
    // The Realm follower owns admitted, paginated Event history for every
    // visible stream. A panel-local first-page scan duplicates that work and
    // cannot recover Events beyond that page or in independent Circle streams.
    Ok(KanbanProjectionSnapshot {
        containers: spaces,
        strands,
    })
}

#[component]
pub(super) fn KanbanEffects(
    controller: KanbanController,
    columns: Memo<Vec<KanbanColumn>>,
    current_inventory: Memo<Result<Option<KanbanCurrentInventory>, String>>,
    route: Route,
    local_realm_id: String,
    base_url: String,
    token: Signal<String>,
    selected_realm_id: String,
    projection_realm_id: String,
    authority: arkret_sdk::AccountId,
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
        card_detail_sidebar_tab: _,
        mut card_synthesis_history_open_id,
        mut card_synthesis_selected_revision_id,
        member_handle_fetching: _,
        mut command_queue,
        board_status,
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
            // The confirmed-options effect can observe the accepted Space in
            // the same render pass and seed this exact selection first.  That
            // ordering must not suppress the second half of the migration:
            // installing the canonical Board route.  A genuinely different
            // user selection still wins and is never hijacked.
            if selected_board
                .peek()
                .as_ref()
                .is_some_and(|selected| selected != &space_id)
            {
                return;
            }
            if selected_board.peek().is_none() {
                selected_board.set(Some(space_id.clone()));
            }
            let _ = navigator.replace(kanban_board_route(&route_realm_id, space_id.as_str()));
        });
    }

    {
        let realm = local_realm_id.clone();
        use_effect(move || {
            let operations = state_store.read().load().raw_operations;
            let (projected, raw_operations) = match current_inventory() {
                Ok(Some(inventory)) => (
                    inventory.containers,
                    std::borrow::Cow::Owned(kanban_pending_operations(&operations)),
                ),
                Ok(None) => (
                    lifecycle_container_projection(),
                    std::borrow::Cow::Borrowed(operations.as_slice()),
                ),
                Err(_) => (Vec::new(), std::borrow::Cow::Borrowed(&[][..])),
            };
            let entries = state_store.read().realm_current_state_entries(&realm);
            let mut containers = space_container_views_from_projection_and_ops(
                &projected,
                &raw_operations,
                &realm,
                &entries,
            );
            if let Some(endpoint) = crate::secure_key_store::active_device_seed_scope() {
                let state = state_store.read();
                for view in &mut containers {
                    if let Some(title) = crate::views::metadata::current_title(
                        &state,
                        &realm,
                        &view.space_id,
                        &endpoint.authority,
                        &endpoint.device_id,
                    ) {
                        view.title = title;
                    }
                }
            }
            // `board_space_options_from_projection` fails closed on non-SpaceId
            // rows, so a pending Board create never enters the confirmed option
            // set; it is rendered from `pending_board_creates_from_ops` until
            // the receipt reconciles it.
            let options = board_space_options_from_projection(&containers);
            if *board_space_options.peek() != options {
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
                } => {
                    // Remember this create before starting the detached submit.
                    // A local Coland can accept the Event before Dioxus gets a
                    // render pass that observes the queued op-log row. Without
                    // this producer-side marker, that fast queued -> accepted
                    // transition is indistinguishable from a cold-start row and
                    // the canonical Board route is never installed.
                    if *operation.kind() == arkret_sdk::EventKind::SpaceCreate
                        && operation
                            .typed_payload::<arkret_wire::event_spec::SpaceCreate>()
                            .is_ok_and(|payload| {
                                payload.object.kind == "board"
                                    && payload.object.realm_id.as_str() == realm_id
                            })
                    {
                        awaiting_board_ops
                            .write()
                            .insert(operation.local_operation_id().to_string());
                    }
                    submit_kanban_operation_event(
                        base_url,
                        token,
                        realm_id,
                        *operation,
                        scope_security_encrypted,
                        state_store,
                        board_status,
                    );
                }
            }
        }
    });

    use_effect(move || {
        if !state_store.read().has_pending_local_projection_commands() {
            return;
        }
        state_store.write().project_pending_local_commands();
    });

    let detail_realm = local_realm_id.clone();
    use_effect(move || {
        // Preserve an accepted editor basis while allowing a pending create's
        // receipt to install its event-derived identity. Editor signals retain
        // the user's draft through that transition.
        let preserve_edit_basis =
            editing_card_detail() || due_picker_open() || assignee_picker_open();
        let raw_operations = state_store.read().load().raw_operations;
        let refreshing_content = {
            let store = state_store.read();
            !store.current_reset_required()
                && store.realm_tree_projection(&detail_realm).is_some()
                && store.current_product_view().is_some_and(|view| {
                    view.realm_id == detail_realm
                        && !view.complete_cut
                        && selected_card.peek().as_ref().is_some_and(|card| {
                            arkret_sdk::StrandId::new(card.id.clone()).is_ok_and(|id| {
                                strand_current_basis(&view.entries, &id)
                                    == StrandCurrentBasis::Missing
                            })
                        })
                })
        };
        sync_selected_card_from_columns(
            selected_card,
            &columns(),
            &raw_operations,
            preserve_edit_basis,
            refreshing_content,
        );
    });

    {
        let card_route = route.clone();
        use_effect(move || {
            let Some(card) = selected_card() else {
                return;
            };
            let raw_operations = state_store.read().load().raw_operations;
            let Some(accepted_route) =
                card_task_route_after_acceptance(&card_route, &card, &raw_operations)
            else {
                return;
            };
            let _ = navigator.replace(accepted_route);
        });
    }

    {
        let routed_strand_id = route_card_strand_id(&route);
        use_effect(move || {
            let routed_tab = card_detail_tab_from_current_route();
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
                if *card_detail_tab.peek() != routed_tab {
                    card_detail_tab.set(routed_tab);
                }
                if routed_tab == CardDetailContentTab::Discussion
                    && let Some(card) = selected_card.peek().as_ref()
                    && card_detail_discussion_mounted_for.peek().as_deref()
                        != Some(card.primary_strand_id.as_str())
                {
                    card_detail_discussion_mounted_for.set(Some(card.primary_strand_id.clone()));
                }
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
            let (projected, overlay) = match current_inventory() {
                Ok(Some(inventory)) => (
                    inventory.strands,
                    std::borrow::Cow::Owned(kanban_pending_operations(&raw_operations)),
                ),
                Ok(None) => (
                    lifecycle_strand_projection(),
                    std::borrow::Cow::Borrowed(raw_operations.as_slice()),
                ),
                Err(_) => return,
            };
            let Some(strand_board) = strand_views_from_projection_and_ops(&projected, &overlay)
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

    // The admitted current view contains the whole Realm inventory. Prefer
    // local projection; HTTP only bootstraps a still-missing display baseline.
    // The ordinary follower owns subsequent current/history recovery.
    let session = crate::app::SessionContext::get();
    let read_scope = use_memo(use_reactive(
        (&base_url, &local_realm_id),
        move |(base, realm)| {
            (
                base,
                realm,
                (session.session_generation)(),
                kanban_read_account_scope((session.active_account)()),
            )
        },
    ));
    let read_owner = use_hook(|| {
        std::rc::Rc::new(std::cell::RefCell::new(
            super::projection_reads::ProjectionReadOwner::default(),
        ))
    });
    use_effect(move || {
        let scope = read_scope();
        let credential = token();
        let account = scope.3.as_ref().map(|(_, account, ..)| account);
        let enabled = !credential.trim().is_empty()
            && !scope.0.trim().is_empty()
            && !scope.1.trim().is_empty()
            && account.is_some_and(|account| {
                state_store.read().active_authority().as_ref() == Some(account)
            })
            && !state_store.read().account_scope_read_denied(&scope.1);
        if read_owner
            .borrow_mut()
            .set_scope(enabled.then_some(scope.clone()))
        {
            lifecycle_container_projection.set(Vec::new());
            lifecycle_strand_projection.set(Vec::new());
        }
        if !enabled {
            return;
        }
        match current_inventory() {
            Ok(Some(inventory)) => {
                read_owner.borrow_mut().cancel_pending();
                read_owner.borrow_mut().cover(ProjectionReadSet::all());
                if *lifecycle_container_projection.peek() != inventory.containers {
                    lifecycle_container_projection.set(inventory.containers);
                }
                if *lifecycle_strand_projection.peek() != inventory.strands {
                    lifecycle_strand_projection.set(inventory.strands);
                }
                return;
            }
            Err(error) => {
                read_owner.borrow_mut().cancel_pending();
                tracing::warn!(%error, "admitted Kanban inventory is unavailable");
                if !lifecycle_container_projection.peek().is_empty() {
                    lifecycle_container_projection.set(Vec::new());
                }
                if !lifecycle_strand_projection.peek().is_empty() {
                    lifecycle_strand_projection.set(Vec::new());
                }
                return;
            }
            Ok(None) => {}
        }
        if !read_owner.borrow().missing().any() {
            return;
        }
        let request = (
            scope,
            crate::app::account_sync_ready(&sync_cursor()),
            realm_live_epoch(),
            state_store.read().current_generation(),
        );
        if !read_owner.borrow_mut().queue.request(request) {
            return;
        }
        let owner = read_owner.clone();
        let task = spawn(async move {
            loop {
                let next = owner.borrow_mut().queue.next();
                let Some((scope, ..)) = next else {
                    owner.borrow_mut().finish();
                    return;
                };
                if *read_scope.peek() != scope
                    || *session.session_generation.peek() != scope.2
                    || kanban_read_account_scope(session.active_account.peek().clone()) != scope.3
                    || token.peek().trim().is_empty()
                {
                    continue;
                }
                let needed = owner.borrow().missing();
                if !needed.any() {
                    continue;
                }
                let realm = scope.1.clone();
                let list_fence = state_store.peek().realm_list_read_fence(&realm);
                if state_store.peek().account_scope_read_denied(&realm) {
                    continue;
                }
                let Some((_, expected_account, expected_device, _)) = scope.3.clone() else {
                    continue;
                };
                let credential = token.peek().clone();
                let result = with_authed_api(&scope.0, credential, move |api| async move {
                    let http = api.sdk_http_client()?;
                    let bound =
                        crate::transport::own_station_results::client_for_http(&http).await?;
                    let active_device_scope = crate::secure_key_store::active_device_seed_scope();
                    anyhow::ensure!(
                        bound.session()?.account_id() == &expected_account
                            && active_device_scope.as_ref().is_some_and(|active| {
                                active.authority == expected_account
                                    && active.device_id == expected_device
                            }),
                        "Kanban inventory belongs to another Account or Device session"
                    );
                    let snapshot = fetch_kanban_projection_snapshot(api, &realm, needed).await?;
                    bound.check_session()?;
                    Ok(snapshot)
                })
                .await;
                // An old account, Station, session or route may finish after
                // its replacement. Never install its display rows there.
                if *read_scope.peek() != scope
                    || *session.session_generation.peek() != scope.2
                    || kanban_read_account_scope(session.active_account.peek().clone()) != scope.3
                    || token.peek().trim().is_empty()
                {
                    continue;
                }
                let store = state_store.peek();
                if store.account_scope_read_denied(&scope.1)
                    || store
                        .require_realm_list_read_fence(&scope.1, Some(&list_fence))
                        .is_err()
                    || store.current_product_view_stamp(&scope.1).is_some()
                {
                    continue;
                }
                drop(store);
                match result {
                    Ok(snapshot) => {
                        owner.borrow_mut().cover(ProjectionReadSet {
                            spaces: snapshot.containers.is_some(),
                            strands: snapshot.strands.is_some(),
                        });
                        if let Some(containers) = snapshot.containers {
                            lifecycle_container_projection.set(containers);
                        }
                        if let Some(strands) = snapshot.strands {
                            lifecycle_strand_projection.set(strands);
                        }
                    }
                    Err(error) => {
                        tracing::warn!(error = %error.display_diagnostic(), "kanban inventory read failed")
                    }
                }
            }
        });
        read_owner.borrow_mut().attach(task);
    });

    // Locked author-private fields can become readable after another device
    // uploads the account-private plaintext sidecar. A device that already has
    // the account MLS secret should restore that sidecar silently with active
    // device proof. Retained admitted Events and current values reproject locally.
    {
        let restore_base = base_url.clone();
        let restore_token = token;
        let restore_realm_id = selected_realm_id.clone();
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
            let actor = restore_actor.clone();
            let authority = restore_authority.clone();
            let device = restore_device.clone();
            let restore_scope = read_scope.peek().clone();
            spawn(async move {
                for attempt in 0..5u32 {
                    if attempt > 0 {
                        crate::runtime_helpers::sleep_for(std::time::Duration::from_millis(
                            500 * (1 << (attempt - 1)),
                        ))
                        .await;
                    }
                    if *read_scope.peek() != restore_scope {
                        return;
                    }
                    let actor_for_fetch = actor.clone();
                    let device_for_fetch = device.to_string();
                    let result =
                        with_authed_api(&base, api_token.clone(), move |api| async move {
                            let payload = crate::mls::account_recovery::fetch_mls_restore_payload_with_unlock_proof(
                                &api,
                                &actor_for_fetch,
                                &device_for_fetch,
                            )
                            .await?;
                            Ok(payload)
                        })
                        .await;
                    if *read_scope.peek() != restore_scope {
                        return;
                    }
                    let payload = match result {
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
                        let report = crate::mls::account_recovery::restore_mls_history_with_local_secret_from_payload(
                            &payload,
                            &crate::app::runtime_adapter::state_store_handle(state_store),
                            secure_store.as_ref(),
                            &authority,
                            &actor,
                        ).await;
                        report.private_plaintext_restored || report.restored > 0
                    };

                    // Restoring the sidecar writes the local store, which
                    // invalidates the columns memo without another Event scan.
                    let card_unlocked = selected_card()
                        .is_some_and(|card| !card.description_locked && !card.synthesis_locked);
                    if restored_private_plaintext || card_unlocked {
                        break;
                    }
                }
            });
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

#[cfg(all(test, not(target_arch = "wasm32")))]
mod projection_read_tests {
    use std::io::{Read, Write};
    use std::time::{Duration, Instant};

    use super::*;

    #[tokio::test]
    async fn independent_inventory_reads_start_together_without_an_event_scan() {
        let realm = "ak:realm:AeEFmfOZxsx5kLi2kpOJu8m7TFXZ_G8E4019rUp4wmT6";
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let base = format!("http://{}/", listener.local_addr().unwrap());
        let server = std::thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(10);
            let mut requests = Vec::new();
            // Neither response is available until both requests have arrived.
            while requests.len() < 2 {
                match listener.accept() {
                    Ok((mut connection, _)) => {
                        connection
                            .set_read_timeout(Some(Duration::from_secs(5)))
                            .unwrap();
                        let mut bytes = Vec::new();
                        let mut buffer = [0; 4096];
                        while !bytes.windows(4).any(|value| value == b"\r\n\r\n") {
                            let count = connection.read(&mut buffer).unwrap();
                            assert!(count > 0);
                            bytes.extend_from_slice(&buffer[..count]);
                        }
                        requests.push((connection, String::from_utf8(bytes).unwrap()));
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        assert!(Instant::now() < deadline, "inventory reads were serialized");
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    Err(error) => panic!("{error}"),
                }
            }
            let mut paths = Vec::new();
            for (mut connection, request) in requests {
                let path = request.lines().next().unwrap().to_owned();
                let collection = if path.contains("/spaces?") {
                    "spaces"
                } else {
                    assert!(path.contains("/strands?"), "unexpected request: {path}");
                    "strands"
                };
                let body =
                    json!({"realm_id": realm, (collection): [], "total": 0, "has_more": false})
                        .to_string();
                write!(connection, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{}", body.len(), body).unwrap();
                paths.push(path);
            }
            paths
        });
        let http = arkret_sdk::http_client::ClientBuilder::new(url::Url::parse(&base).unwrap())
            .allow_insecure_localhost()
            .auth(arkret_sdk::http_client::Auth::Bearer(
                "inventory-fixture".into(),
            ))
            .build()
            .unwrap();
        let api = crate::transport::TransportClient::from_http(
            http,
            crate::transport::RequestContext::new(""),
        );
        let snapshot = fetch_kanban_projection_snapshot(api, realm, ProjectionReadSet::all())
            .await
            .unwrap();
        assert_eq!(snapshot.containers, Some(Vec::new()));
        assert_eq!(snapshot.strands, Some(Vec::new()));
        assert_eq!(server.join().unwrap().len(), 2);
    }
}
