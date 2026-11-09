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

async fn fetch_kanban_display_bootstrap(
    http: arkret_sdk::http_client::Client,
    realm_id: &str,
    needed: ProjectionReadSet,
    read_fence: Option<crate::state::RealmListReadFence>,
    current: &crate::state::CurrentIndex,
) -> anyhow::Result<Option<KanbanProjectionSnapshot>> {
    // A cold page can mount before the Account owner publishes its memory
    // view. A complete durable cut already owns this baseline; let that owner
    // finish its normal publication instead of issuing duplicate display IO.
    if current.read_complete_cut(realm_id).await?.is_some() {
        return Ok(None);
    }
    fetch_kanban_projection_snapshot(http, realm_id, needed, read_fence)
        .await
        .map(Some)
}

async fn fetch_kanban_projection_snapshot(
    http: arkret_sdk::http_client::Client,
    realm_id: &str,
    needed: ProjectionReadSet,
    read_fence: Option<crate::state::RealmListReadFence>,
) -> anyhow::Result<KanbanProjectionSnapshot> {
    // Read independent, complete derived Space/Strand pages concurrently.
    // These rows are not an authoring basis or a governance head;
    // accepted Events remain the canonical truth source.
    let (spaces, strands) = futures_util::future::join(
        async {
            if needed.spaces {
                Some(match read_fence.as_ref() {
                    Some(fence) => {
                        crate::transport::realm_read::list_realm_spaces_scoped(
                            &http, realm_id, fence,
                        )
                        .await
                    }
                    None => crate::transport::realm_read::list_realm_spaces(&http, realm_id).await,
                })
            } else {
                None
            }
        },
        async {
            if needed.strands {
                Some(match read_fence.as_ref() {
                    Some(fence) => {
                        crate::transport::realm_read::list_realm_strands_scoped(
                            &http, realm_id, fence,
                        )
                        .await
                    }
                    None => crate::transport::realm_read::list_realm_strands(&http, realm_id).await,
                })
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

pub(super) fn mount_effects(
    scope: &Scope,
    app: Rc<InksonContext>,
    controller: KanbanController,
    columns: glory::Bond<Vec<KanbanColumn>>,
    current_inventory: glory::Bond<Result<Option<KanbanCurrentInventory>, String>>,
    route: Route,
    local_realm_id: String,
    base_url: String,
    token: Cage<String>,
    selected_realm_id: String,
    _projection_realm_id: String,
    sync_cursor: Cage<String>,
    realm_live_epoch: Cage<u64>,
) {
    let state_store = app.state_store.clone();
    let weak = scope.downgrade();
    let KanbanController {
        board_space_options,
        selected_board,
        lifecycle_container_projection,
        lifecycle_strand_projection,
        selected_card,
        card_edit_title,
        card_edit_description,
        card_edit_body,
        card_edit_synthesis,
        card_edit_synthesis_target_id,
        card_edit_labels,
        card_edit_assignee,
        card_edit_due,
        card_edit_calendar,
        calendar_rsvp_occurrence,
        editing_card_detail,
        card_edit_scope,
        card_detail_edit_status,
        assignee_picker_open,
        assignee_picker_dirty,
        assignee_filter,
        assignee_selected_actor_ids,
        assignee_edit_status,
        due_picker_open,
        due_edit_value,
        due_calendar_month,
        due_edit_status,
        card_detail_actions_open,
        card_detail_discussion_mounted_for,
        card_detail_tab,
        card_detail_sidebar_tab: _,
        card_synthesis_history_open_id,
        card_synthesis_selected_revision_id,
        member_handle_fetching: _,
        command_queue,
        awaiting_board_ops,
        board_status,
        ..
    } = controller;

    // A pending Board create is rendered from the op log without touching the
    // selection or the URL. A row leaves the pending set exactly when its
    // receipt/backfill merge records the final Event id, so the migration is
    // detected as a TRANSITION: diff the remembered pending operation ids
    // against the current set and resolve the departed ones through the
    // holder-local alias. While the user remains at this Realm's Board root,
    // commit the
    // accepted Space id selection + canonical route in one step. The confirmed
    // option appears from the same op-log projection, so a repeated receipt or
    // a backfill-first ordering cannot duplicate it. Declared FIRST so the
    // transition wins over the options-seeding effect below on the pass where
    // the receipt lands.
    {
        let route_realm_id = selected_realm_id.clone();
        let pending_realm_id = local_realm_id.clone();
        {
            let app = app.clone();
            let state_store = state_store.clone();
            let _weak = weak.clone();
            scope.effect(move || {
                let _ = app.state_revision.get();
                let raw_operations = state_store.read(|store| store.load()).raw_operations;
                let pending = pending_board_creates_from_ops(&raw_operations, &pending_realm_id);
                let aliases = event_derived_target_aliases(&raw_operations);
                let (accepted, still_pending) = accepted_board_create_transition(
                    &awaiting_board_ops.get_untracked(),
                    &pending,
                    &aliases,
                );
                if awaiting_board_ops.get_untracked() != still_pending {
                    awaiting_board_ops.revise(|value| {
                        let next = still_pending;
                        *value = next;
                    });
                }
                let Some(space_id) = accepted else {
                    return;
                };
                // A retained controller may have seeded an older Board while
                // the create was in flight. Only the actual route distinguishes
                // that cache from an explicit user navigation.
                let accepted_route = kanban_board_route(&route_realm_id, space_id.as_str());
                let current_route = app.route.get_untracked();
                if current_route != kanban_board_route(&route_realm_id, "")
                    && current_route != accepted_route
                {
                    return;
                }
                if selected_board.get_untracked().as_ref() != Some(&space_id) {
                    selected_board.revise(|value| {
                        let next = Some(space_id.clone());
                        *value = next;
                    });
                }
                app.replace_route(accepted_route);
            });
        };
    }

    {
        let realm = local_realm_id.clone();
        {
            let app = app.clone();
            let state_store = state_store.clone();
            let _weak = weak.clone();
            scope.effect(move || {
                let _ = app.state_revision.get();
                let operations = state_store.read(|store| store.load()).raw_operations;
                let (projected, raw_operations) = match current_inventory.get() {
                    Ok(Some(inventory)) => (
                        inventory.containers,
                        std::borrow::Cow::Owned(kanban_pending_operations(&operations)),
                    ),
                    Ok(None) => (
                        lifecycle_container_projection.get(),
                        std::borrow::Cow::Borrowed(operations.as_slice()),
                    ),
                    Err(_) => (Vec::new(), std::borrow::Cow::Borrowed(&[][..])),
                };
                let entries = state_store.read(|store| store.realm_current_state_entries(&realm));
                let mut containers = space_container_views_from_projection_and_ops(
                    &projected,
                    &raw_operations,
                    &realm,
                    &entries,
                );
                if let Some(endpoint) = crate::secure_key_store::active_device_seed_scope() {
                    for view in &mut containers {
                        if let Some(title) = state_store.read(|state| {
                            crate::views::metadata::current_title(
                                state,
                                &realm,
                                &view.space_id,
                                &endpoint.authority,
                                &endpoint.device_id,
                            )
                        }) {
                            view.title = title;
                        }
                    }
                }
                // `board_space_options_from_projection` fails closed on non-SpaceId
                // rows, so a pending Board create never enters the confirmed option
                // set; it is rendered from `pending_board_creates_from_ops` until
                // the receipt reconciles it.
                let options = board_space_options_from_projection(&containers);
                if board_space_options.get_untracked() != options {
                    board_space_options.revise(|value| {
                        let next = options.clone();
                        *value = next;
                    });
                }
                // Seeding the first confirmed Board must yield while a create is
                // pending: the create handler cleared the selection precisely so
                // the pending surface (title + creating state) can show instead of
                // snapping back to the previous Board.
                if selected_board.get_untracked().is_none()
                    && pending_board_creates_from_ops(&raw_operations, &realm).is_empty()
                    && let Some(first) = options.first()
                {
                    selected_board.revise(|value| {
                        let next = Some(first.id.clone());
                        *value = next;
                    });
                }
            });
        };
    }

    {
        let app = app.clone();
        let state_store = state_store.clone();
        let _weak = weak.clone();
        scope.effect(move || {
            let _ = app.state_revision.get();
            let commands = command_queue.get();
            if commands.is_empty() {
                return;
            }
            command_queue.revise(|value| {
                let next = std::collections::VecDeque::new();
                *value = next;
            });
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
                            awaiting_board_ops.revise(|value| {
                                value.insert(operation.local_operation_id().to_string())
                            });
                        }
                        submit_kanban_operation_event(
                            app.clone(),
                            base_url,
                            token,
                            realm_id,
                            *operation,
                            scope_security_encrypted,
                            state_store.clone(),
                            board_status,
                        );
                    }
                }
            }
        });
    };

    {
        let app = app.clone();
        let state_store = state_store.clone();
        let _weak = weak.clone();
        scope.effect(move || {
            let _ = app.state_revision.get();
            if !state_store.read(|store| store.has_pending_local_projection_commands()) {
                return;
            }
            state_store.write(|store| store.project_pending_local_commands());
        });
    };

    let detail_realm = local_realm_id.clone();
    {
        let app = app.clone();
        let state_store = state_store.clone();
        let _weak = weak.clone();
        scope.effect(move || {
            let _ = app.state_revision.get();
            // Preserve an accepted editor basis while allowing a pending create's
            // receipt to install its event-derived identity. Editor signals retain
            // the user's draft through that transition.
            let preserve_edit_basis = editing_card_detail.get()
                || due_picker_open.get()
                || (assignee_picker_open.get() && assignee_picker_dirty.get());
            let raw_operations = state_store.read(|store| store.load()).raw_operations;
            let refreshing_content = {
                state_store.read(|store| {
                    !store.current_reset_required()
                        && store.realm_tree_projection(&detail_realm).is_some()
                        && store.current_product_view().is_some_and(|view| {
                            view.realm_id == detail_realm
                                && !view.complete_cut
                                && selected_card.get_untracked().as_ref().is_some_and(|card| {
                                    arkret_sdk::StrandId::new(card.id.clone()).is_ok_and(|id| {
                                        strand_current_basis(&view.entries, &id)
                                            == StrandCurrentBasis::Missing
                                    })
                                })
                        })
                })
            };
            sync_selected_card_from_columns(
                selected_card,
                &columns.get(),
                &raw_operations,
                preserve_edit_basis,
                refreshing_content,
            );
        });
    };

    {
        let card_route = route.clone();
        {
            let app = app.clone();
            let state_store = state_store.clone();
            let _weak = weak.clone();
            scope.effect(move || {
                let _ = app.state_revision.get();
                let Some(card) = selected_card.get() else {
                    return;
                };
                let raw_operations = state_store.read(|store| store.load()).raw_operations;
                let Some(accepted_route) =
                    card_task_route_after_acceptance(&card_route, &card, &raw_operations)
                else {
                    return;
                };
                app.replace_route(accepted_route);
            });
        };
    }

    {
        let routed_strand_id = route_card_strand_id(&route);
        {
            let app = app.clone();
            let state_store = state_store.clone();
            let _weak = weak.clone();
            scope.effect(move || {
                let _ = app.state_revision.get();
                let routed_tab = card_detail_tab_from_current_route(&app);
                let Some(strand_id) = routed_strand_id.clone() else {
                    return;
                };
                let raw_operations = state_store.read(|store| store.load()).raw_operations;
                let aliases = event_derived_target_aliases(&raw_operations);
                let strand_id = resolve_event_derived_target_alias(&aliases, &strand_id);
                if selected_card
                    .get()
                    .as_ref()
                    .is_some_and(|card| card_matches_strand_id(card, &strand_id))
                {
                    if let Some(edit_scope) = super::card_detail_surface::content_edit_scope_for_tab(
                        editing_card_detail.get_untracked(), card_edit_scope.get_untracked(), routed_tab,
                    ) && card_edit_scope.get_untracked() != edit_scope {
                        card_edit_scope.revise(|value| *value = edit_scope);
                    }
                    if card_detail_tab.get_untracked() != routed_tab {
                        card_detail_tab.revise(|value| {
                            let next = routed_tab;
                            *value = next;
                        });
                    }
                    if routed_tab == CardDetailContentTab::Discussion
                        && let Some(card) = selected_card.get_untracked().as_ref()
                        && card_detail_discussion_mounted_for
                            .get_untracked()
                            .as_deref()
                            != Some(card.primary_strand_id.as_str())
                    {
                        card_detail_discussion_mounted_for.revise(|value| {
                            let next = Some(card.primary_strand_id.clone());
                            *value = next;
                        });
                    }
                    return;
                }
                if let Some(card) = find_card_by_strand_id(&columns.get(), &strand_id) {
                    let draft = card_detail_draft_from_card(&card);
                    card_edit_title.revise(|value| {
                        let next = draft.title;
                        *value = next;
                    });
                    card_edit_description.revise(|value| {
                        let next = draft.description;
                        *value = next;
                    });
                    card_edit_body.revise(|value| {
                        let next = draft.description_body;
                        *value = next;
                    });
                    card_edit_synthesis.revise(|value| {
                        let next = draft.synthesis;
                        *value = next;
                    });
                    card_edit_synthesis_target_id.revise(|value| {
                        let next = None;
                        *value = next;
                    });
                    card_edit_labels.revise(|value| {
                        let next = draft.labels.join(", ");
                        *value = next;
                    });
                    card_edit_assignee.revise(|value| {
                        let next = draft.assignee;
                        *value = next;
                    });
                    card_edit_due.revise(|value| {
                        let next = draft.due;
                        *value = next;
                    });
                    let calendar = draft.calendar.clone();
                    card_edit_calendar.revise(|value| {
                        let next = calendar.clone();
                        *value = next;
                    });
                    calendar_rsvp_occurrence.revise(|value| {
                        let next = calendar_occurrence_hint(&calendar);
                        *value = next;
                    });
                    editing_card_detail.revise(|value| {
                        let next = false;
                        *value = next;
                    });
                    card_detail_edit_status.revise(|value| {
                        let next = String::new();
                        *value = next;
                    });
                    assignee_picker_open.revise(|value| {
                        let next = false;
                        *value = next;
                    });
                    assignee_filter.revise(|value| {
                        let next = String::new();
                        *value = next;
                    });
                    assignee_selected_actor_ids.revise(|value| {
                        let next = card_assigned_actor_ids(&card).into_iter().collect();
                        *value = next;
                    });
                    assignee_edit_status.revise(|value| {
                        let next = String::new();
                        *value = next;
                    });
                    due_picker_open.revise(|value| {
                        let next = false;
                        *value = next;
                    });
                    due_edit_value.revise(|value| {
                        let next = editor_value_for_optional_card_field(&card.due);
                        *value = next;
                    });
                    due_calendar_month.revise(|value| {
                        let next = due_calendar_month_for_value(&card.due);
                        *value = next;
                    });
                    due_edit_status.revise(|value| {
                        let next = String::new();
                        *value = next;
                    });
                    card_detail_actions_open.revise(|value| {
                        let next = false;
                        *value = next;
                    });
                    if routed_tab == CardDetailContentTab::Discussion {
                        card_detail_discussion_mounted_for.revise(|value| {
                            let next = Some(card.primary_strand_id.clone());
                            *value = next;
                        });
                    }
                    card_detail_tab.revise(|value| {
                        let next = routed_tab;
                        *value = next;
                    });
                    card_synthesis_history_open_id.revise(|value| {
                        let next = None;
                        *value = next;
                    });
                    card_synthesis_selected_revision_id.revise(|value| {
                        let next = None;
                        *value = next;
                    });
                    selected_card.revise(|value| {
                        let next = Some(card);
                        *value = next;
                    });
                }
            });
        };
    }

    {
        let routed_board_id = route_board_id(&route);
        {
            let app = app.clone();
            let _state_store = state_store.clone();
            let _weak = weak.clone();
            scope.effect(move || {
                let _ = app.state_revision.get();
                let Some(board_id) = routed_board_id.clone() else {
                    return;
                };
                // `route_board_id` already failed closed on anything that is not a
                // canonical Space id, so the routed value is trusted here.
                if selected_board.get().as_ref() != Some(&board_id) {
                    selected_board.revise(|value| {
                        let next = Some(board_id);
                        *value = next;
                    });
                }
            });
        };
    }

    {
        let routed_strand_id = route_card_strand_id(&route);
        {
            let app = app.clone();
            let state_store = state_store.clone();
            let _weak = weak.clone();
            scope.effect(move || {
                let _ = app.state_revision.get();
                let Some(strand_id) = routed_strand_id.clone() else {
                    return;
                };
                let raw_operations = state_store.read(|store| store.load()).raw_operations;
                let aliases = event_derived_target_aliases(&raw_operations);
                let strand_id = resolve_event_derived_target_alias(&aliases, &strand_id);
                let (projected, overlay) = match current_inventory.get() {
                    Ok(Some(inventory)) => (
                        inventory.strands,
                        std::borrow::Cow::Owned(kanban_pending_operations(&raw_operations)),
                    ),
                    Ok(None) => (
                        lifecycle_strand_projection.get(),
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
                if selected_board.get().as_ref() != Some(&strand_board) {
                    selected_board.revise(|value| {
                        let next = Some(strand_board);
                        *value = next;
                    });
                }
            });
        };
    }

    // The admitted current view contains the whole Realm inventory. Prefer
    // local projection; HTTP only bootstraps a still-missing display baseline.
    // The ordinary follower owns subsequent current/history recovery.
    let session = app.clone();
    let read_scope = {
        let app = app.clone();
        let base = base_url.clone();
        let realm = local_realm_id.clone();
        scope.bond(move || {
            (
                base.clone(),
                realm.clone(),
                app.session_generation.get(),
                kanban_read_account_scope(app.active_account.get()),
            )
        })
    };
    #[cfg(all(target_arch = "wasm32", feature = "spec-conformance"))]
    tracing::warn!(owner = ?scope.id(), generation = app.session_generation.get_untracked(), board_selected = controller.selected_board.get_untracked().is_some(), "kanban projection owner mounted");
    let read_owner = controller.inventory_owner.get_untracked();
    {
        let app = app.clone();
        let state_store = state_store.clone();
        let weak = weak.clone();
        let read_owner = read_owner.clone();
        let session = session.clone();
        scope.effect(move || {
 let _=app.state_revision.get();
        let scope = read_scope.get();
        let credential = token.get();
        let account = scope.3.as_ref().map(|(_, account, ..)| account);
        let enabled = !credential.trim().is_empty()
            && !scope.0.trim().is_empty()
            && !scope.1.trim().is_empty()
            && account.is_some_and(|account| {
                state_store.read(|store|store.active_authority()).as_ref() == Some(account)
            })
            && !state_store.read(|store|store.account_scope_read_denied(&scope.1));
        if read_owner
            .borrow_mut()
            .set_scope(enabled.then_some(scope.clone()))
        {
            #[cfg(all(target_arch = "wasm32", feature = "spec-conformance"))]
            tracing::warn!(generation = scope.2, enabled, has_account = scope.3.is_some(), "kanban projection scope reset");
            lifecycle_container_projection.revise(|value|{let next=Vec::new();*value=next;});
            lifecycle_strand_projection.revise(|value|{let next=Vec::new();*value=next;});
        }
        if !enabled {
            return;
        }
        match current_inventory.get() {
            Ok(Some(inventory)) => {
                read_owner.borrow_mut().cancel_pending();
                read_owner.borrow_mut().cover(ProjectionReadSet::all());
                if lifecycle_container_projection.get_untracked() != inventory.containers {
                    lifecycle_container_projection.revise(|value|{let next=inventory.containers;*value=next;});
                }
                if lifecycle_strand_projection.get_untracked() != inventory.strands {
                    lifecycle_strand_projection.revise(|value|{let next=inventory.strands;*value=next;});
                }
                return;
            }
            Err(error) => {
                read_owner.borrow_mut().invalidate();
                tracing::warn!(%error, "admitted Kanban inventory is unavailable");
                if !lifecycle_container_projection.get_untracked().is_empty() {
                    lifecycle_container_projection.revise(|value|{let next=Vec::new();*value=next;});
                }
                if !lifecycle_strand_projection.get_untracked().is_empty() {
                    lifecycle_strand_projection.revise(|value|{let next=Vec::new();*value=next;});
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
            crate::app::account_sync_ready(&sync_cursor.get()),
            realm_live_epoch.get(),
            state_store.read(|store|store.current_generation()),
        );
        if !read_owner.borrow_mut().queue.request(request) {
            return;
        }
        let owner = read_owner.clone();
        let session=session.clone();let state_store=state_store.clone();
        let task = {let Some(scope)=weak.upgrade()else{return;};scope.owner().spawn(async move {
            loop {
                let next = owner.borrow_mut().queue.next();
                let Some(request) = next else {
                    owner.borrow_mut().finish();
                    return;
                };
                let (scope, ..) = request.clone();
                if read_scope.get_untracked() != scope
                    || session.session_generation.get_untracked() != scope.2
                    || kanban_read_account_scope(session.active_account.get_untracked().clone()) != scope.3
                    || token.get_untracked().trim().is_empty()
                {
                    continue;
                }
                let needed = owner.borrow().missing();
                if !needed.any() {
                    continue;
                }
                let realm = scope.1.clone();
                let list_fence = state_store.read(|store|store.realm_list_read_fence(&realm));
                if state_store.read(|store|store.account_scope_read_denied(&realm)) {
                    continue;
                }
                let Some((_, expected_account, expected_device, _)) = scope.3.clone() else {
                    continue;
                };
                let credential = token.get_untracked().clone();
                let request_fence = list_fence.clone();
                let request_store = state_store.clone();
                #[cfg(all(target_arch = "wasm32", feature = "spec-conformance"))]
                tracing::warn!(generation = scope.2, live_epoch = request.2, spaces = needed.spaces, strands = needed.strands, "kanban projection fetch begins");
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
                    let current = crate::state::CurrentIndex::open_committed(
                        &expected_account,
                        request_store.read(|store| store.current_index_location()),
                        || request_store.read(|store| {
                            anyhow::ensure!(store.active_authority().as_ref() == Some(&expected_account)
                                && !store.current_reset_required(), "Kanban inventory current scope changed");
                            Ok(store.current_generation())
                        }),
                    ).await?;
                    let snapshot = fetch_kanban_display_bootstrap(
                        bound.http_client()?,
                        &realm,
                        needed,
                        Some(request_fence),
                        &current,
                    )
                    .await?;
                    bound.check_session()?;
                    Ok(snapshot)
                })
                .await;
                // An old account, Station, session or route may finish after
                // its replacement. Never install its display rows there.
                if read_scope.get_untracked() != scope
                    || session.session_generation.get_untracked() != scope.2
                    || kanban_read_account_scope(session.active_account.get_untracked().clone()) != scope.3
                    || token.get_untracked().trim().is_empty()
                {
                    continue;
                }
                if state_store.read(|store|store.account_scope_read_denied(&scope.1)
                    || store
                        .require_realm_list_read_fence(&scope.1, Some(&list_fence))
                        .is_err()
                    || store.current_product_view_stamp(&scope.1).is_some()
                ){continue;}
                match result {
                    Ok(None) => {}
                    Ok(Some(snapshot)) => {
                        owner.borrow_mut().cover_if_latest(
                            &request,
                            ProjectionReadSet {
                                spaces: snapshot.containers.is_some(),
                                strands: snapshot.strands.is_some(),
                            },
                        );
                        if let Some(containers) = snapshot.containers {
                            lifecycle_container_projection.revise(|value|{let next=containers;*value=next;});
                        }
                        if let Some(strands) = snapshot.strands {
                            lifecycle_strand_projection.revise(|value|{let next=strands;*value=next;});
                        }
                    }
                    Err(error) => {
                        tracing::warn!(error = %error.display_diagnostic(), "kanban inventory read failed")
                    }
                }
            }
        })};
        if let Ok(task)=task{read_owner.borrow_mut().attach(task);}
    });
    };

    {
        let owner = read_owner.clone();
        let _ = scope.on_cleanup(move || owner.borrow_mut().cancel_pending());
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod projection_read_tests {
    use std::io::{Read, Write};
    use std::time::{Duration, Instant};

    use super::*;

    #[tokio::test]
    async fn cold_complete_current_cut_does_not_refetch_display_lists() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering};

        use arkret_sdk::http_client::own_station_results::{
            OwnStationSessionSnapshot, OwnStationSessionSource, OwnStationStateClient,
        };
        for mode in [
            "complete", "missing", "partial", "foreign", "reset", "poison",
        ] {
            let realm = "ak:realm:AY789mrKRCQEVlbVgiTgLdjVO5oCMJiUCrF-D-JlRNxI";
            let requested_realm = if mode == "foreign" {
                "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19"
            } else {
                realm
            };
            let commit = "ak:realm_commit:AT33EWBTXdTx5CjY-ogbIIF2T4vh-v7jCMCQ80Fss2Rq";
            let directory = tempfile::tempdir().unwrap();
            let mut store =
                crate::state::LocalStateStore::with_path(directory.path().join("state.json"));
            assert!(store.switch_test_account("did:web:alice.example"));
            let account = store.active_authority().unwrap();
            let index =
                crate::state::CurrentIndex::open(&account, 0, store.current_index_location())
                    .await
                    .unwrap();
            let heads = json!([{"stream_ref":{"kind":"realm","realm_id":realm},
            "stream_position":1,"commit_id":commit}]);
            let frame = serde_json::from_value(json!({"kind":"delta","cursor":"ak:cursor:YQ",
            "realms":{realm:{"current":{"realm_id":realm,"governance_generation":"1",
                "stream_heads":heads,"entries":[]},
                "baseline":{"snapshot_cursor":"ak:cursor:YQ","cut_revision":1,
                    "coverage":{"realm_id":realm,"stream_heads":heads,
                        "complete_for_authorized_streams":true},"complete":mode != "partial"}}}}))
            .unwrap();
            if mode != "missing" {
                let stage = index.stage_frame(0, &frame).await.unwrap();
                store.commit_current_stage_for_test(stage).unwrap();
            }
            if mode == "reset" {
                let reset = serde_json::from_value(json!({"kind":"resync_required"})).unwrap();
                let stage = index.stage_frame(1, &reset).await.unwrap();
                store.commit_current_stage_for_test(stage).unwrap();
            }
            drop(index);
            let current = crate::state::CurrentIndex::open_committed(
                &account,
                store.current_index_location(),
                || Ok(store.current_generation()),
            )
            .await
            .unwrap();
            assert_eq!(
                current
                    .read_complete_cut(requested_realm)
                    .await
                    .unwrap()
                    .is_some(),
                mode == "complete" || mode == "poison",
                "{mode}"
            );
            if mode == "poison" {
                current.poison();
            }
            assert!(
                store.current_product_view().is_none(),
                "a cold presentation has no in-memory view"
            );
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            listener.set_nonblocking(true).unwrap();
            let base = format!("http://{}/", listener.local_addr().unwrap());
            let stopped = Arc::new(AtomicBool::new(false));
            let stop = stopped.clone();
            let server = std::thread::spawn(move || {
                let deadline = Instant::now() + Duration::from_secs(10);
                let mut count = 0;
                while !stop.load(Ordering::Acquire) && count < 2 {
                    match listener.accept() {
                        Ok((mut connection, _)) => {
                            connection.set_nonblocking(false).unwrap();
                            connection
                                .set_read_timeout(Some(Duration::from_secs(2)))
                                .unwrap();
                            let mut bytes = Vec::new();
                            let mut buffer = [0; 4096];
                            while !bytes.windows(4).any(|value| value == b"\r\n\r\n") {
                                let n = connection.read(&mut buffer).unwrap();
                                assert!(n > 0);
                                bytes.extend_from_slice(&buffer[..n]);
                            }
                            let headers = String::from_utf8(bytes).unwrap();
                            let collection = if headers.starts_with("GET /_arkret/self/realms/")
                                && headers.lines().next().unwrap().contains("/spaces?")
                            {
                                "spaces"
                            } else {
                                assert!(headers.lines().next().unwrap().contains("/strands?"));
                                "strands"
                            };
                            let body = json!({"realm_id":requested_realm,(collection):[],"total_count":0,"has_more":false}).to_string();
                            write!(connection,"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{}",body.len(),body).unwrap();
                            count += 1;
                        }
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            assert!(
                                Instant::now() < deadline,
                                "owned inventory fixture did not terminate"
                            );
                            std::thread::sleep(Duration::from_millis(5));
                        }
                        Err(error) => panic!("{error}"),
                    }
                }
                count
            });
            let binding = arkret_sdk::StationConnectionBinding {
                service_id: account.station_id.clone(),
                base_url: base.clone(),
                trust_domain: arkret_sdk::TrustDomainId::new("ak:trust_domain:station.example")
                    .unwrap(),
                authentication_metadata: arkret_sdk::AuthenticationMetadata::minimal(),
            };
            struct Source(OwnStationSessionSnapshot);
            impl OwnStationSessionSource for Source {
                fn snapshot(&self) -> arkret_sdk::http_client::Result<OwnStationSessionSnapshot> {
                    Ok(self.0.clone())
                }
            }
            let session = OwnStationSessionSnapshot::new(
                binding.clone(),
                account.clone(),
                account.station_id,
                arkret_wire::SessionGrantId::from_issuance_digest([34; 32]),
                1,
                "cold-inventory-fixture".into(),
            )
            .unwrap()
            .with_provider_identity(Default::default());
            let raw = arkret_sdk::http_client::ClientBuilder::new(url::Url::parse(&base).unwrap())
                .allow_insecure_localhost()
                .auth(arkret_sdk::http_client::Auth::Bearer(
                    "cold-inventory-fixture".into(),
                ))
                .build()
                .unwrap();
            let http = OwnStationStateClient::new(raw, binding, Arc::new(Source(session)))
                .unwrap()
                .http_client()
                .unwrap();
            let result = fetch_kanban_display_bootstrap(
                http,
                requested_realm,
                ProjectionReadSet::all(),
                None,
                &current,
            )
            .await;
            stopped.store(true, Ordering::Release);
            let requests = server.join().unwrap();
            if mode == "poison" {
                assert_eq!(
                    requests, 0,
                    "a poisoned index fails closed before display HTTP"
                );
                assert!(result.is_err());
            } else if mode == "complete" {
                assert_eq!(
                    requests, 0,
                    "a durable complete cut already owns the display baseline"
                );
                assert!(result.unwrap().is_none());
            } else {
                assert_eq!(
                    requests, 2,
                    "a missing complete cut still bootstraps both display lists: {mode}"
                );
                let snapshot = result.unwrap().unwrap();
                assert_eq!(snapshot.containers, Some(Vec::new()));
                assert_eq!(snapshot.strands, Some(Vec::new()));
            }
            assert!(
                store.current_product_view().is_none(),
                "bootstrap must not publish a second product view"
            );
        }
    }

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
                        connection.set_nonblocking(false).unwrap();
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
                    json!({"realm_id": realm, (collection): [], "total_count": 0, "has_more": false})
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
        use arkret_sdk::http_client::own_station_results::{
            OwnStationSessionSnapshot, OwnStationSessionSource, OwnStationStateClient,
        };
        struct Source(OwnStationSessionSnapshot);
        impl OwnStationSessionSource for Source {
            fn snapshot(&self) -> arkret_sdk::http_client::Result<OwnStationSessionSnapshot> {
                Ok(self.0.clone())
            }
        }
        let account = arkret_sdk::AccountId {
            principal_id: arkret_sdk::DidCoreId::new("ak:did_core:web:alice.example").unwrap(),
            station_id: arkret_sdk::DidCoreId::new("ak:did_core:web:station.example").unwrap(),
        };
        let binding = arkret_sdk::StationConnectionBinding {
            service_id: account.station_id.clone(),
            base_url: base,
            trust_domain: arkret_sdk::TrustDomainId::new("ak:trust_domain:station.example")
                .unwrap(),
            authentication_metadata: arkret_sdk::AuthenticationMetadata::minimal(),
        };
        let session = OwnStationSessionSnapshot::new(
            binding.clone(),
            account.clone(),
            account.station_id,
            arkret_wire::SessionGrantId::from_issuance_digest([33; 32]),
            1,
            "inventory-fixture".into(),
        )
        .unwrap()
        .with_provider_identity(Default::default());
        let http = OwnStationStateClient::new(http, binding, std::sync::Arc::new(Source(session)))
            .unwrap()
            .http_client()
            .unwrap();
        let snapshot =
            fetch_kanban_projection_snapshot(http, realm, ProjectionReadSet::all(), None)
                .await
                .unwrap();
        assert_eq!(snapshot.containers, Some(Vec::new()));
        assert_eq!(snapshot.strands, Some(Vec::new()));
        assert_eq!(server.join().unwrap().len(), 2);
    }
}
