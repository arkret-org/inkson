use card_detail_surface::{CardTrackEditContext, SuspendedTrackEdit};
mod drag_drop_controller;
mod drag_surface;
use drag_drop_controller::*;
mod realm_loading;
mod surface;
use std::collections::{BTreeMap, BTreeSet};
use std::rc::Rc;

use glory::{Cage, Scope};
use serde_json::{Map, Value, json};
use surface::board_surface;

use crate::presentation::{InksonContext, SharedStateStore, View};
use crate::rank::rank_for_drop;
use crate::routes::Route;
use crate::state::LocalStateStore;
use crate::transport::auth::{with_authed_api, with_authed_sdk_client};
use crate::views::helpers::short_protocol_id;
use crate::views::settings::widgets::*;
mod pool;
pub use pool::KanbanStatePool;
mod card_detail_surface;
mod controller;
mod due_calendar;
mod editors;
mod effects;
mod model;
mod projection_reads;
use controller::{KanbanCommand, KanbanController, new_kanban_controller};
use due_calendar::*;
pub(crate) use model::strand_views_from_ops;
use model::*;
mod assignment;
mod board_select;
mod card_detail;
mod card_patch;
mod members;
mod mls_encrypt;
mod plaintext_guard;
use assignment::*;
use board_select::*;
use card_detail::*;
use card_detail_surface::{CardDetailContext, card_detail};
#[cfg(test)]
use card_detail_surface::{content_edit_scope_for_tab, suspend_track_edit};
use card_patch::*;
use editors::*;
use members::*;
use mls_encrypt::*;
use plaintext_guard::*;
#[cfg(test)]
mod tests;
/// Holder-local queue key for one Strand's placement on one Board.
///
/// A Strand can sit on several Boards with independent placements, so the Board
/// id is part of the key. This addresses the local optimistic queue only; it is
/// never sent and never derived from.
pub(crate) fn strand_position_queue_key(board_space_id: &str, strand_id: &str) -> String {
    format!("{board_space_id}#{strand_id}")
}

/// Placement the author observed before writing, copied into the payload's own
/// `expected_position` compare-and-swap guard.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum StrandPositionExpectation {
    /// The Strand is not yet placed on the target Board.
    Initial,
    /// The Strand currently sits at `(list_space_id, rank)` on that Board.
    At { list_space_id: String, rank: String },
}

/// Placement this write asks for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum StrandPositionEffect {
    SetPosition { list_space_id: String, rank: String },
}

#[cfg(test)]
pub(crate) use crate::state::projection::kanban_ops::kanban_operations_from_events;

async fn toast_editor_upload_via_api(
    base_url: &str,
    token: String,
    realm_id: &str,
    allow_image_upload: bool,
    request: &Value,
) -> Result<(String, Option<String>), String> {
    use base64::Engine as _;
    if !allow_image_upload {
        return Err("image upload is unavailable for this encrypted scope".to_owned());
    }
    let content_base64 = request
        .get("content_base64")
        .and_then(Value::as_str)
        .ok_or_else(|| "upload request missing content_base64".to_owned())?;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(content_base64)
        .map_err(|error| format!("invalid base64 content: {error}"))?;
    if bytes.is_empty() {
        return Err("upload request carries no bytes".to_owned());
    }
    let media_type = request
        .get("media_type")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|media_type| !media_type.is_empty())
        .unwrap_or("application/octet-stream")
        .to_owned();
    let filename = request
        .get("filename")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|filename| !filename.is_empty())
        .map(ToOwned::to_owned);
    let realm_id = realm_id.trim();
    let realm_id = (!realm_id.is_empty()).then(|| realm_id.to_owned());
    let outcome = crate::transport::auth::with_endpoint_clients(
        base_url,
        token,
        None,
        move |clients| async move {
            clients
                .blob()
                .upload_bytes_scoped(bytes, &media_type, realm_id.as_deref(), filename.as_deref())
                .await
        },
    )
    .await
    .map_err(|error| error.display())?;
    Ok((outcome.blob_ref.to_string(), outcome.media_type))
}

fn spawn_write(app: Rc<InksonContext>, future: impl std::future::Future<Output = ()> + 'static) {
    let Some(scope) = app.state_scope() else {
        return;
    };
    let key = format!("kanban-{}", crate::operation::uuid_v7());
    let complete = app.clone();
    let task_key = key.clone();
    if let Ok(task) = scope.owner().spawn(async move {
        future.await;
        complete.kanban_state.finish(&task_key);
    }) {
        app.kanban_state.track(key, task);
    }
}
#[derive(Clone)]
struct Board {
    app: Rc<InksonContext>,
    controller: KanbanController,
    realm: String,
    local_realm: String,
    projection_realm: String,
    principal: arkret_sdk::DidCoreId,
    authority: arkret_sdk::AccountId,
    device: arkret_sdk::DeviceId,
    columns: glory::Bond<Vec<KanbanColumn>>,
    security: glory::Bond<Option<bool>>,
    ready: glory::Bond<bool>,
    synthesis: glory::Bond<Vec<CardSynthesisTrackEntry>>,
    page: Cage<usize>,
}
pub fn page(scope: &Scope, app: Rc<InksonContext>, route: Route) -> View {
    let Some(account) = app.active_account.get_untracked() else {
        return empty();
    };
    let realm = match &route {
        Route::KanbanRealm { realm_id }
        | Route::KanbanBoard { realm_id, .. }
        | Route::KanbanTask { realm_id, .. }
        | Route::KanbanBoardTask { realm_id, .. } => realm_id.clone(),
        _ => app.selected_realm_id.get_untracked(),
    };
    let projection = crate::models::projection_realm_id_for_known_node(
        &app.realm_tree_nodes.get_untracked(),
        &realm,
    )
    .unwrap_or_else(|| realm.clone());
    let local_realm = local_projection_realm_id(&realm, &projection);
    let typed = match arkret_sdk::RealmId::new(local_realm.clone()) {
        Ok(realm) => realm,
        Err(_) => return realm_loading::surface(scope, app, local_realm.trim().is_empty()),
    };
    let fallback = kanban_seed_fallback_allowed(&app.base_url.get_untracked());
    let seed = if fallback { seed_columns() } else { Vec::new() };
    let initial = app.state_store.read(|store| {
        let state = store.load();
        let entries = store.realm_current_state_entries(&local_realm);
        let options = overlay_local_board_space_options(
            initial_board_space_options(fallback),
            &state.raw_operations,
            &local_realm,
            &entries,
        );
        let pending =
            !pending_board_creates_from_ops(&state.raw_operations, &local_realm).is_empty();
        (options, pending)
    });
    let board_id = route_board_id(&route).or_else(|| {
        if initial.1 {
            None
        } else {
            initial.0.first().map(|option| option.id.clone())
        }
    });
    let target = pool::KanbanTarget {
        authority: account.authority.clone(),
        device: account.device_id.clone(),
        realm: typed.clone(),
        board: board_id.clone(),
    };
    let Some(controller) = app.kanban_state.board(target, |owner| {
        new_kanban_controller(owner, &route, initial.0, board_id)
    }) else {
        return empty();
    };
    let inventory = {
        let app = app.clone();
        let realm = local_realm.clone();
        let selected = controller.selected_board;
        scope.bond(move || {
            let _ = app.state_revision.get();
            let active = app.active_account.get();
            let board = selected.get();
            app.state_store.read(|store| {
                if active.as_ref().is_none_or(|account| {
                    store.active_authority().as_ref() != Some(&account.authority)
                }) {
                    return Err("active Account does not own this Board view".into());
                }
                if store.current_product_view_stamp(&realm).is_none() {
                    return Ok(None);
                }
                let Some(view) = store.current_product_view() else {
                    return Ok(None);
                };
                if view.realm_id != realm {
                    return Ok(None);
                }
                kanban_inventory_from_current(&view, board.as_ref())
                    .map_err(|error| error.to_string())
            })
        })
    };
    let columns = {
        let selected_board = controller.selected_board;
        let lifecycle_container_projection = controller.lifecycle_container_projection;
        let lifecycle_strand_projection = controller.lifecycle_strand_projection;
        let current_inventory = inventory;
        let seed_realm_id = local_realm.clone();
        let decrypt_realm_id = realm.clone();
        let decrypt_authority = account.authority.clone();
        let decrypt_device = account.device_id.to_string();
        let self_actor_id = account.principal_id().to_string();
        let seed_columns = seed;
        let app = app.clone();
        scope.bond(move || {
            let _ = app.state_revision.get();
            let active = app.active_account.get();
            let inventory = current_inventory.get();
            app.state_store.read(|decrypt_store| {
                let board_id = selected_board
                    .get()
                    .map(|board_id| board_id.to_string())
                    .unwrap_or_default();

                if active.as_ref().is_none_or(|active| {
                    decrypt_store.active_authority().as_ref() != Some(&active.authority)
                }) {
                    return Vec::new();
                }
                let raw_operations = decrypt_store.load().raw_operations;
                if decrypt_store.account_scope_read_denied(&seed_realm_id) {
                    return Vec::new();
                }
                let (projected_containers, projected_strands, complete_current) =
                    match inventory.clone() {
                        Ok(Some(inventory)) => (inventory.containers, inventory.strands, true),
                        Ok(None) => (
                            lifecycle_container_projection.get(),
                            lifecycle_strand_projection.get(),
                            false,
                        ),
                        Err(_) => return Vec::new(),
                    };
                let decrypt_ctx = mls_decrypt_ctx_if_ready(
                    decrypt_store,
                    &decrypt_realm_id,
                    &decrypt_authority,
                    &decrypt_device,
                );
                if !complete_current && raw_operations.is_empty() && !seed_columns.is_empty() {
                    // Demo / seed-fallback columns: layer local optimistic ops on top.
                    let cols = overlay_local_card_create_records(
                        seed_columns.clone(),
                        &raw_operations,
                        &board_id,
                    );
                    let cols = overlay_local_card_update_records(
                        cols,
                        &raw_operations,
                        decrypt_ctx.as_ref(),
                    );
                    return overlay_local_card_assignment_records(cols, &raw_operations);
                }
                let entries = decrypt_store.realm_current_state_entries(&seed_realm_id);
                let (mut cols, ..) = project_board_with_current_inventory_for_actor(
                    &raw_operations,
                    &projected_containers,
                    &projected_strands,
                    &board_id,
                    &seed_realm_id,
                    decrypt_ctx.as_ref(),
                    &self_actor_id,
                    &entries,
                    complete_current,
                );
                install_current_card_sources(
                    &mut cols,
                    &entries,
                    &projected_strands,
                    &raw_operations,
                    decrypt_ctx.as_ref(),
                    &self_actor_id,
                );
                let cols = overlay_pending_card_updates(
                    cols,
                    &raw_operations,
                    &entries,
                    decrypt_ctx.as_ref(),
                );
                overlay_local_card_assignment_records_at_current(
                    cols,
                    &raw_operations,
                    complete_current,
                )
            })
        })
    };
    let security = {
        let app = app.clone();
        let realm = realm.clone();
        let projection = projection.clone();
        scope.bond(move || {
            let _ = app.state_revision.get();
            app.state_store.read(|store| {
                let state = store.load();
                let current = store.current_product_view();
                let scope = if projection.is_empty() {
                    &realm
                } else {
                    &projection
                };
                crate::views::helpers::scope_mls_activation(
                    &state.realm_tree_projections,
                    current.as_ref(),
                    scope,
                )
                .or_else(|| {
                    crate::views::helpers::scope_mls_activation(
                        &state.realm_tree_projections,
                        current.as_ref(),
                        &realm,
                    )
                })
            })
        })
    };
    let send = crate::views::secure_send::scope_send_probe(
        scope,
        app.clone(),
        glory::Lotus::from(Some(arkret_sdk::ScopeRef::Realm { realm_id: typed })),
        glory::Lotus::from(account.device_id.clone()),
    );
    let ready = {
        let app = app.clone();
        let realm = realm.clone();
        scope.bond(move || {
            let _ = app.state_revision.get();
            send.get().gate.is_some()
                && app.state_store.read(|store| {
                    store.station_realm_digest_suite(&realm).is_some()
                        && !store.realm_detail_invalidated(&realm)
                        && store.realm_allows_spaces(&realm)
                })
        })
    };
    let synthesis = {
        let app = app.clone();
        let realm = realm.clone();
        let projection_realm = projection.clone();
        let authority = account.authority.clone();
        let device = account.device_id.to_string();
        scope.bond(move || {
            let _ = app.state_revision.get();
            let _ = app.realm_live_epoch.get();
            let want = controller.card_detail_tab.get() == CardDetailContentTab::Synthesis
                || controller.editing_card_detail.get()
                    && controller.card_edit_scope.get() == CardEditScope::Synthesis;
            let Some(card) = controller.selected_card.get() else {
                return Vec::new();
            };
            if !want {
                return Vec::new();
            }
            app.state_store.read(|store| {
                let snapshot = store.load();
                let projection = snapshot.realm_tree_projections.get(&realm);
                let realm_context =
                    member_roster_realm_context(&realm, &projection_realm, projection);
                let rows = realm_member_roster(projection);
                let author = CardAuthorDisplayContext {
                    realm_id: &realm_context,
                    member_rows: &rows,
                };
                let decrypt = mls_decrypt_ctx_if_ready(store, &realm, &authority, &device);
                card_synthesis_track_entries_with_author_context_and_decrypt(
                    &card,
                    &snapshot.raw_operations,
                    store,
                    Some(author),
                    decrypt.as_ref(),
                )
            })
        })
    };
    let board = Board {
        app: app.clone(),
        controller,
        realm: realm.clone(),
        local_realm: local_realm.clone(),
        projection_realm: projection.clone(),
        principal: account.principal_id().clone(),
        authority: account.authority.clone(),
        device: account.device_id.clone(),
        columns,
        security,
        ready,
        synthesis,
        page: scope.cage(0),
    };
    effects::mount_effects(
        scope,
        app.clone(),
        controller,
        columns,
        inventory,
        route,
        local_realm,
        app.base_url.get_untracked(),
        app.token,
        realm,
        projection,
        account.authority.clone(),
        account.principal_id().to_string(),
        account.device_id.to_string(),
        app.sync_cursor,
        app.realm_live_epoch,
    );
    let demand = {
        let selected = controller.selected_card;
        let page = board.page;
        scope.bond(move || card_current_page(&columns.get(), page.get(), selected.get().as_ref()))
    };
    {
        let app = app.clone();
        let realm = board.local_realm.clone();
        let authority = board.authority.clone();
        scope.effect(move || {
            let (strands, _) = demand.get();
            let spaces = kanban_space_current_selectors(
                controller.selected_board.get().as_ref(),
                &columns.get(),
            );
            app.state_store.read(|store| {
                store.set_product_current_demand(&authority, &realm, Some(strands), spaces)
            });
        });
    }
    {
        let app = app.clone();
        let realm = board.local_realm.clone();
        let authority = board.authority.clone();
        let _ = scope.on_cleanup(move || {
            app.state_store.read(|store| {
                store.set_product_current_demand(&authority, &realm, None, Vec::new())
            })
        });
    }
    board_surface(scope, board)
}
#[allow(unused_variables)]
impl Board {
    fn retry_board(&self, operation_id: crate::operation::LocalOperationId) {
        if !self.controller.command_queue.is_alive() || !self.ready.get_untracked() {
            return;
        }
        let Some(account) = self.app.active_account.get_untracked() else {
            return;
        };
        if account.authority != self.authority
            || self.app.device_id.get_untracked() != self.device.to_string()
            || self.app.selected_realm_id.get_untracked() != self.realm
        {
            return;
        }
        let pending = self.app.state_store.read(|store| {
            pending_board_creates_from_ops(&store.load().raw_operations, &self.local_realm)
                .into_iter()
                .find(|pending| pending.operation_id == operation_id)
        });
        let Some(pending) = pending.filter(PendingBoardCreate::is_retryable) else {
            return;
        };
        let operation = crate::operation::ak_ops::space_create(
            &self.realm,
            self.principal.as_ref(),
            "board",
            &pending.title,
            None,
            None,
        )
        .and_then(|builder| builder.build_sdk_event("inkson"))
        .map(|operation| operation.with_local_operation_id(operation_id));
        match operation {
            Ok(operation) => {
                let security = self.security.get_untracked();
                if let Some(reason) = kanban_plaintext_block_reason(security, &operation) {
                    self.controller.board_status.revise(|value| *value = reason);
                    return;
                }
                self.controller.enqueue_operation(
                    self.app.base_url.get_untracked(),
                    self.app.token,
                    self.realm.clone(),
                    operation,
                    security,
                );
                self.controller
                    .board_status
                    .revise(|value| *value = "Retrying Board creation".into());
                self.controller
                    .board_popover
                    .revise(|value| *value = BoardToolbarPopover::None);
            }
            Err(error) => self
                .controller
                .board_status
                .revise(|value| *value = format!("cannot retry Board creation: {error:#}")),
        }
    }
    fn create_board(&self) {
        let app = self.app.clone();
        let controller = self.controller;
        let state_store = app.state_store.clone();
        let base_url = app.base_url.get_untracked();
        let token = app.token;
        let principal_id = self.principal.to_string();
        let device_id = self.device.to_string();
        let selected_realm_id = self.realm.clone();
        let projection_realm_id = self.projection_realm.clone();
        let local_realm_id = self.local_realm.clone();
        let board_route_realm_id = card_detail_route_realm_id(&self.realm);
        let selected_scope_security_encrypted = self.security.get_untracked();
        let card_write_ready = self.ready.get_untracked();
        let columns = self.columns;
        let board_space_options = controller.board_space_options;
        let selected_board = controller.selected_board;
        let lifecycle_container_projection = controller.lifecycle_container_projection;
        let lifecycle_strand_projection = controller.lifecycle_strand_projection;
        let new_board_title = controller.new_board_title;
        let new_column_title = controller.new_column_title;
        let new_card_title = controller.new_card_title;
        let adding_card_to = controller.adding_card_to;
        let selected_card = controller.selected_card;
        let mls_sidecar_restore_key_seen = controller.mls_sidecar_restore_key_seen;
        let board_popover = controller.board_popover;
        let archive_board_confirm_open = controller.archive_board_confirm_open;
        let list_archive_confirm = controller.list_archive_confirm;
        let editing_card_detail = controller.editing_card_detail;
        let card_edit_scope = controller.card_edit_scope;
        let card_detail_sidebar_visible = controller.card_detail_sidebar_visible;
        let card_detail_actions_open = controller.card_detail_actions_open;
        let card_detail_tab = controller.card_detail_tab;
        let card_detail_discussion_mounted_for = controller.card_detail_discussion_mounted_for;
        let card_detail_sidebar_tab = controller.card_detail_sidebar_tab;
        let card_detail_docked = controller.card_detail_docked;
        let card_detail_dock_width = controller.card_detail_dock_width;
        let card_detail_resizing = controller.card_detail_resizing;
        let card_detail_resize_start_x = controller.card_detail_resize_start_x;
        let card_detail_resize_start_width = controller.card_detail_resize_start_width;
        let member_handle_fetching = controller.member_handle_fetching;
        let card_edit_title = controller.card_edit_title;
        let card_edit_description = controller.card_edit_description;
        let card_edit_body = controller.card_edit_body;
        let card_edit_synthesis = controller.card_edit_synthesis;
        let card_edit_synthesis_target_id = controller.card_edit_synthesis_target_id;
        let card_detail_edit_status = controller.card_detail_edit_status;
        let assignee_picker_open = controller.assignee_picker_open;
        let assignee_filter = controller.assignee_filter;
        let assignee_selected_actor_ids = controller.assignee_selected_actor_ids;
        let assignee_edit_status = controller.assignee_edit_status;
        let due_picker_open = controller.due_picker_open;
        let due_edit_value = controller.due_edit_value;
        let due_calendar_month = controller.due_calendar_month;
        let due_edit_status = controller.due_edit_status;
        let card_edit_calendar = controller.card_edit_calendar;
        let calendar_rsvp_occurrence = controller.calendar_rsvp_occurrence;
        let card_synthesis_history_open_id = controller.card_synthesis_history_open_id;
        let card_synthesis_selected_revision_id = controller.card_synthesis_selected_revision_id;
        let card_edit_labels = controller.card_edit_labels;
        let card_edit_assignee = controller.card_edit_assignee;
        let card_edit_due = controller.card_edit_due;
        let dragging_card = controller.dragging_card;
        let dragging_column = controller.dragging_column;
        let drop_target_column = controller.drop_target_column;
        let editing_column_id = controller.editing_column_id;
        let editing_column_title = controller.editing_column_title;
        let board_status = controller.board_status;
        let command_queue = controller.command_queue;
        if !card_write_ready {
            return;
        }
        let handler = {
            let base = base_url.clone();
            let realm = selected_realm_id.clone();
            let actor = principal_id.clone();
            let create_route_realm_id = board_route_realm_id.clone();
            move |_| {
                let title = new_board_title.get().trim().to_owned();
                if title.is_empty() {
                    board_status.revise(|value| {
                        let next = "board title is required".to_owned();
                        *value = next;
                    });
                    return;
                }
                if actor.trim().is_empty() {
                    board_status.revise(|value| {
                        let next = "sign in before creating a Board".to_owned();
                        *value = next;
                    });
                    return;
                }
                let op = match crate::operation::ak_ops::space_create(
                    &realm, &actor, "board", &title, None, None,
                ) {
                    Ok(builder) => builder.build_sdk_event("inkson"),
                    Err(err) => {
                        board_status.revise(|value| {
                            let next = format!("cannot create board: {err:#}");
                            *value = next;
                        });
                        return;
                    }
                };
                let op = match op {
                    Ok(event) => event,
                    Err(err) => {
                        board_status.revise(|value| {
                            let next = format!("cannot create board: {err}");
                            *value = next;
                        });
                        return;
                    }
                };
                if let Some(reason) =
                    kanban_plaintext_block_reason(selected_scope_security_encrypted, &op)
                {
                    board_status.revise(|value| {
                        let next = reason;
                        *value = next;
                    });
                    return;
                }
                // The Board Space is named by `retype(event_id)` of the
                // FINAL create Event, which does not exist yet, so the
                // create only enqueues the durable `LocalOperation`.
                // Clear the confirmed selection and fall back to the
                // realm-level route: the op-log-derived
                // `pending_board_creates` memo then renders the new
                // Board's title + creating state immediately, and the
                // route reconciler cannot pin the previous Board back.
                // The transition effect commits the accepted `SpaceId`
                // selection + canonical route once the receipt lands.
                adding_card_to.revise(|value| {
                    let next = None;
                    *value = next;
                });
                controller.enqueue_operation(
                    base.clone(),
                    token,
                    realm.clone(),
                    op,
                    selected_scope_security_encrypted,
                );
                selected_board.revise(|value| {
                    let next = None;
                    *value = next;
                });
                app.replace_route(kanban_board_route(&create_route_realm_id, ""));
                board_status.revise(|value| {
                    let next = "Creating Board; lists will be available after server confirmation."
                        .to_owned();
                    *value = next;
                });
                new_board_title.revise(|value| {
                    let next = "Board".to_owned();
                    *value = next;
                });
                board_popover.revise(|value| {
                    let next = BoardToolbarPopover::None;
                    *value = next;
                });
            }
        };
        handler(());
    }
    fn add_column(&self) {
        let app = self.app.clone();
        let controller = self.controller;
        let state_store = app.state_store.clone();
        let base_url = app.base_url.get_untracked();
        let token = app.token;
        let principal_id = self.principal.to_string();
        let device_id = self.device.to_string();
        let selected_realm_id = self.realm.clone();
        let projection_realm_id = self.projection_realm.clone();
        let local_realm_id = self.local_realm.clone();
        let board_route_realm_id = card_detail_route_realm_id(&self.realm);
        let selected_scope_security_encrypted = self.security.get_untracked();
        let card_write_ready = self.ready.get_untracked();
        let columns = self.columns;
        let board_space_options = controller.board_space_options;
        let selected_board = controller.selected_board;
        let lifecycle_container_projection = controller.lifecycle_container_projection;
        let lifecycle_strand_projection = controller.lifecycle_strand_projection;
        let new_board_title = controller.new_board_title;
        let new_column_title = controller.new_column_title;
        let new_card_title = controller.new_card_title;
        let adding_card_to = controller.adding_card_to;
        let selected_card = controller.selected_card;
        let mls_sidecar_restore_key_seen = controller.mls_sidecar_restore_key_seen;
        let board_popover = controller.board_popover;
        let archive_board_confirm_open = controller.archive_board_confirm_open;
        let list_archive_confirm = controller.list_archive_confirm;
        let editing_card_detail = controller.editing_card_detail;
        let card_edit_scope = controller.card_edit_scope;
        let card_detail_sidebar_visible = controller.card_detail_sidebar_visible;
        let card_detail_actions_open = controller.card_detail_actions_open;
        let card_detail_tab = controller.card_detail_tab;
        let card_detail_discussion_mounted_for = controller.card_detail_discussion_mounted_for;
        let card_detail_sidebar_tab = controller.card_detail_sidebar_tab;
        let card_detail_docked = controller.card_detail_docked;
        let card_detail_dock_width = controller.card_detail_dock_width;
        let card_detail_resizing = controller.card_detail_resizing;
        let card_detail_resize_start_x = controller.card_detail_resize_start_x;
        let card_detail_resize_start_width = controller.card_detail_resize_start_width;
        let member_handle_fetching = controller.member_handle_fetching;
        let card_edit_title = controller.card_edit_title;
        let card_edit_description = controller.card_edit_description;
        let card_edit_body = controller.card_edit_body;
        let card_edit_synthesis = controller.card_edit_synthesis;
        let card_edit_synthesis_target_id = controller.card_edit_synthesis_target_id;
        let card_detail_edit_status = controller.card_detail_edit_status;
        let assignee_picker_open = controller.assignee_picker_open;
        let assignee_filter = controller.assignee_filter;
        let assignee_selected_actor_ids = controller.assignee_selected_actor_ids;
        let assignee_edit_status = controller.assignee_edit_status;
        let due_picker_open = controller.due_picker_open;
        let due_edit_value = controller.due_edit_value;
        let due_calendar_month = controller.due_calendar_month;
        let due_edit_status = controller.due_edit_status;
        let card_edit_calendar = controller.card_edit_calendar;
        let calendar_rsvp_occurrence = controller.calendar_rsvp_occurrence;
        let card_synthesis_history_open_id = controller.card_synthesis_history_open_id;
        let card_synthesis_selected_revision_id = controller.card_synthesis_selected_revision_id;
        let card_edit_labels = controller.card_edit_labels;
        let card_edit_assignee = controller.card_edit_assignee;
        let card_edit_due = controller.card_edit_due;
        let dragging_card = controller.dragging_card;
        let dragging_column = controller.dragging_column;
        let drop_target_column = controller.drop_target_column;
        let editing_column_id = controller.editing_column_id;
        let editing_column_title = controller.editing_column_title;
        let board_status = controller.board_status;
        let command_queue = controller.command_queue;
        if !card_write_ready {
            return;
        }
        let handler = {
            // Lists are Space containers in v1. The local column is
            // visible but remains in sending/failed state
            // until `ak.self.events.command.submit.v1` returns.
            let base = base_url.clone();
            let realm = selected_realm_id.clone();
            let actor = principal_id.clone();
            move |_| {
                let title = new_column_title.get().trim().to_owned();
                if title.is_empty() {
                    return;
                }
                if actor.trim().is_empty() {
                    board_status.revise(|value| {
                        let next = "sign in before adding lists".to_owned();
                        *value = next;
                    });
                    return;
                }
                let Some(board_space_id) = selected_board.get() else {
                    board_status.revise(|value| {
                        let next =
                            "Board is still being created; add a list after server confirmation."
                                .to_owned();
                        *value = next;
                    });
                    return;
                };
                let col_count = columns
                    .get()
                    .iter()
                    .filter(|column| column.state == SpaceContainerLifecycleState::Active)
                    .count();
                let rank = format!("r{:03}", col_count + 1);
                let op = match crate::operation::ak_ops::space_create(
                    &realm,
                    &actor,
                    "list",
                    &title,
                    Some(board_space_id.as_str()),
                    Some(&rank),
                ) {
                    Ok(builder) => builder.build_sdk_event("inkson"),
                    Err(err) => {
                        board_status.revise(|value| {
                            let next = format!("cannot create list: {err:#}");
                            *value = next;
                        });
                        return;
                    }
                };
                let op = match op {
                    Ok(event) => event,
                    Err(err) => {
                        board_status.revise(|value| {
                            let next = format!("cannot create list: {err}");
                            *value = next;
                        });
                        return;
                    }
                };
                if let Some(reason) =
                    kanban_plaintext_block_reason(selected_scope_security_encrypted, &op)
                {
                    board_status.revise(|value| {
                        let next = reason;
                        *value = next;
                    });
                    return;
                }
                // The new list`ak.space.createtely: `submit_kanban_operation_event`
                // appends the `ak.space.create` op, which the `columns` memo folds.
                controller.enqueue_operation(
                    base.clone(),
                    token,
                    realm.clone(),
                    op,
                    selected_scope_security_encrypted,
                );
                new_column_title.revise(|value| {
                    let next = String::new();
                    *value = next;
                });
            }
        };
        handler(());
    }
    fn create_card(&self, column: KanbanColumn) {
        let app = self.app.clone();
        let controller = self.controller;
        let state_store = app.state_store.clone();
        let base_url = app.base_url.get_untracked();
        let token = app.token;
        let principal_id = self.principal.to_string();
        let device_id = self.device.to_string();
        let selected_realm_id = self.realm.clone();
        let projection_realm_id = self.projection_realm.clone();
        let local_realm_id = self.local_realm.clone();
        let board_route_realm_id = card_detail_route_realm_id(&self.realm);
        let selected_scope_security_encrypted = self.security.get_untracked();
        let card_write_ready = self.ready.get_untracked();
        let columns = self.columns;
        let board_space_options = controller.board_space_options;
        let selected_board = controller.selected_board;
        let lifecycle_container_projection = controller.lifecycle_container_projection;
        let lifecycle_strand_projection = controller.lifecycle_strand_projection;
        let new_board_title = controller.new_board_title;
        let new_column_title = controller.new_column_title;
        let new_card_title = controller.new_card_title;
        let adding_card_to = controller.adding_card_to;
        let selected_card = controller.selected_card;
        let mls_sidecar_restore_key_seen = controller.mls_sidecar_restore_key_seen;
        let board_popover = controller.board_popover;
        let archive_board_confirm_open = controller.archive_board_confirm_open;
        let list_archive_confirm = controller.list_archive_confirm;
        let editing_card_detail = controller.editing_card_detail;
        let card_edit_scope = controller.card_edit_scope;
        let card_detail_sidebar_visible = controller.card_detail_sidebar_visible;
        let card_detail_actions_open = controller.card_detail_actions_open;
        let card_detail_tab = controller.card_detail_tab;
        let card_detail_discussion_mounted_for = controller.card_detail_discussion_mounted_for;
        let card_detail_sidebar_tab = controller.card_detail_sidebar_tab;
        let card_detail_docked = controller.card_detail_docked;
        let card_detail_dock_width = controller.card_detail_dock_width;
        let card_detail_resizing = controller.card_detail_resizing;
        let card_detail_resize_start_x = controller.card_detail_resize_start_x;
        let card_detail_resize_start_width = controller.card_detail_resize_start_width;
        let member_handle_fetching = controller.member_handle_fetching;
        let card_edit_title = controller.card_edit_title;
        let card_edit_description = controller.card_edit_description;
        let card_edit_body = controller.card_edit_body;
        let card_edit_synthesis = controller.card_edit_synthesis;
        let card_edit_synthesis_target_id = controller.card_edit_synthesis_target_id;
        let card_detail_edit_status = controller.card_detail_edit_status;
        let assignee_picker_open = controller.assignee_picker_open;
        let assignee_filter = controller.assignee_filter;
        let assignee_selected_actor_ids = controller.assignee_selected_actor_ids;
        let assignee_edit_status = controller.assignee_edit_status;
        let due_picker_open = controller.due_picker_open;
        let due_edit_value = controller.due_edit_value;
        let due_calendar_month = controller.due_calendar_month;
        let due_edit_status = controller.due_edit_status;
        let card_edit_calendar = controller.card_edit_calendar;
        let calendar_rsvp_occurrence = controller.calendar_rsvp_occurrence;
        let card_synthesis_history_open_id = controller.card_synthesis_history_open_id;
        let card_synthesis_selected_revision_id = controller.card_synthesis_selected_revision_id;
        let card_edit_labels = controller.card_edit_labels;
        let card_edit_assignee = controller.card_edit_assignee;
        let card_edit_due = controller.card_edit_due;
        let dragging_card = controller.dragging_card;
        let dragging_column = controller.dragging_column;
        let drop_target_column = controller.drop_target_column;
        let editing_column_id = controller.editing_column_id;
        let editing_column_title = controller.editing_column_title;
        let board_status = controller.board_status;
        let command_queue = controller.command_queue;
        if !card_write_ready {
            return;
        }
        let handler = {
            // Card create submits a real
            // ak.strand.create envelope, which
            // carries NO placement. The first
            // Board/List placement is a
            // separate ak.strand.move that
            // `submit_kanban_card_create`
            // authors once the create receipt
            // names the Strand.
            let base = base_url.clone();
            let col_id = column.id.clone();
            let realm = selected_realm_id.clone();
            let actor = principal_id.clone();
            move |_| {
                let title = new_card_title.get().trim().to_owned();
                if title.is_empty() {
                    return;
                }
                let Some(board_space_id) = selected_board.get() else {
                    board_status.revise(|value| {
                        let next = "select or create a Board Space before adding cards".to_owned();
                        *value = next;
                    });
                    return;
                };
                // Insert the new card at the end of the column.
                // Look up the column's current tail rank and ask
                // `rank_between` for a strictly-greater rank. If
                // exhausted, fall back to the alphabet midpoint —
                // the user can trigger a rebalance from the next
                // failed insert.
                let last_rank = columns
                    .get()
                    .iter()
                    .find(|c| c.id == col_id)
                    .and_then(|c| c.cards.last().map(|card| card.rank.clone()));
                let rank =
                    rank_for_drop(last_rank.as_deref(), None).unwrap_or_else(|_| "U".to_owned());
                // The create command appends the `ak.strand.create`
                // op (write_state queued), which the `columns` memo
                // folds over the current baseline. `rank` and the
                // two Space ids ride the row's holder-local
                // `effect` only: they are the optimistic overlay's
                // placement and the input to the follow-up Move,
                // never members of the create payload.
                // No `strand_id` here: the card Strand is named by
                // its own create Event, so the command boundary
                // fills the subject in once the envelope exists.
                let command = KanbanCardCreateCommand {
                    board_space_id: board_space_id.to_string(),
                    list_space_id: col_id.clone(),
                    title,
                    rank,
                };
                submit_kanban_card_create(
                    app.clone(),
                    base.clone(),
                    token,
                    realm.clone(),
                    actor.clone(),
                    command,
                    selected_scope_security_encrypted,
                    state_store.clone(),
                    board_status,
                );
                // Continuous-create (design/kanban-baseline.md M1):
                // keep the composer open and clear the field so the
                // user can add several cards without re-opening it.
                // The textarea stays mounted, so focus is retained;
                // the ✕ cancel button closes it explicitly.
                new_card_title.revise(|value| {
                    let next = String::new();
                    *value = next;
                });
            }
        };
        handler(());
    }
    fn archive_board(&self) {
        let app = self.app.clone();
        let controller = self.controller;
        let state_store = app.state_store.clone();
        let base_url = app.base_url.get_untracked();
        let token = app.token;
        let principal_id = self.principal.to_string();
        let device_id = self.device.to_string();
        let selected_realm_id = self.realm.clone();
        let projection_realm_id = self.projection_realm.clone();
        let local_realm_id = self.local_realm.clone();
        let board_route_realm_id = card_detail_route_realm_id(&self.realm);
        let selected_scope_security_encrypted = self.security.get_untracked();
        let card_write_ready = self.ready.get_untracked();
        let columns = self.columns;
        let board_space_options = controller.board_space_options;
        let selected_board = controller.selected_board;
        let lifecycle_container_projection = controller.lifecycle_container_projection;
        let lifecycle_strand_projection = controller.lifecycle_strand_projection;
        let new_board_title = controller.new_board_title;
        let new_column_title = controller.new_column_title;
        let new_card_title = controller.new_card_title;
        let adding_card_to = controller.adding_card_to;
        let selected_card = controller.selected_card;
        let mls_sidecar_restore_key_seen = controller.mls_sidecar_restore_key_seen;
        let board_popover = controller.board_popover;
        let archive_board_confirm_open = controller.archive_board_confirm_open;
        let list_archive_confirm = controller.list_archive_confirm;
        let editing_card_detail = controller.editing_card_detail;
        let card_edit_scope = controller.card_edit_scope;
        let card_detail_sidebar_visible = controller.card_detail_sidebar_visible;
        let card_detail_actions_open = controller.card_detail_actions_open;
        let card_detail_tab = controller.card_detail_tab;
        let card_detail_discussion_mounted_for = controller.card_detail_discussion_mounted_for;
        let card_detail_sidebar_tab = controller.card_detail_sidebar_tab;
        let card_detail_docked = controller.card_detail_docked;
        let card_detail_dock_width = controller.card_detail_dock_width;
        let card_detail_resizing = controller.card_detail_resizing;
        let card_detail_resize_start_x = controller.card_detail_resize_start_x;
        let card_detail_resize_start_width = controller.card_detail_resize_start_width;
        let member_handle_fetching = controller.member_handle_fetching;
        let card_edit_title = controller.card_edit_title;
        let card_edit_description = controller.card_edit_description;
        let card_edit_body = controller.card_edit_body;
        let card_edit_synthesis = controller.card_edit_synthesis;
        let card_edit_synthesis_target_id = controller.card_edit_synthesis_target_id;
        let card_detail_edit_status = controller.card_detail_edit_status;
        let assignee_picker_open = controller.assignee_picker_open;
        let assignee_filter = controller.assignee_filter;
        let assignee_selected_actor_ids = controller.assignee_selected_actor_ids;
        let assignee_edit_status = controller.assignee_edit_status;
        let due_picker_open = controller.due_picker_open;
        let due_edit_value = controller.due_edit_value;
        let due_calendar_month = controller.due_calendar_month;
        let due_edit_status = controller.due_edit_status;
        let card_edit_calendar = controller.card_edit_calendar;
        let calendar_rsvp_occurrence = controller.calendar_rsvp_occurrence;
        let card_synthesis_history_open_id = controller.card_synthesis_history_open_id;
        let card_synthesis_selected_revision_id = controller.card_synthesis_selected_revision_id;
        let card_edit_labels = controller.card_edit_labels;
        let card_edit_assignee = controller.card_edit_assignee;
        let card_edit_due = controller.card_edit_due;
        let dragging_card = controller.dragging_card;
        let dragging_column = controller.dragging_column;
        let drop_target_column = controller.drop_target_column;
        let editing_column_id = controller.editing_column_id;
        let editing_column_title = controller.editing_column_title;
        let board_status = controller.board_status;
        let command_queue = controller.command_queue;
        if !card_write_ready {
            return;
        }
        let handler = {
            // Confirmed end-of-week bulk archive:
            // cascade-archive every active card +
            // list, then the board Space itself
            // (client-driven cascade; v1 has no
            // server Space->Strand cascade).
            let base = base_url.clone();
            let realm = selected_realm_id.clone();
            let actor = principal_id.clone();
            move |_| {
                archive_board_confirm_open.revise(|value| {
                    let next = false;
                    *value = next;
                });
                dispatch_board_archive_cascade(
                    app.clone(),
                    base.clone(),
                    token,
                    realm.clone(),
                    actor.clone(),
                    selected_board
                        .get()
                        .map(|board_id| board_id.to_string())
                        .unwrap_or_default(),
                    columns.get(),
                    state_store.clone(),
                    board_status,
                );
            }
        };
        handler(());
    }
    fn archive_list(&self, confirm_list_id: String) {
        let app = self.app.clone();
        let controller = self.controller;
        let state_store = app.state_store.clone();
        let base_url = app.base_url.get_untracked();
        let token = app.token;
        let principal_id = self.principal.to_string();
        let device_id = self.device.to_string();
        let selected_realm_id = self.realm.clone();
        let projection_realm_id = self.projection_realm.clone();
        let local_realm_id = self.local_realm.clone();
        let board_route_realm_id = card_detail_route_realm_id(&self.realm);
        let selected_scope_security_encrypted = self.security.get_untracked();
        let card_write_ready = self.ready.get_untracked();
        let columns = self.columns;
        let board_space_options = controller.board_space_options;
        let selected_board = controller.selected_board;
        let lifecycle_container_projection = controller.lifecycle_container_projection;
        let lifecycle_strand_projection = controller.lifecycle_strand_projection;
        let new_board_title = controller.new_board_title;
        let new_column_title = controller.new_column_title;
        let new_card_title = controller.new_card_title;
        let adding_card_to = controller.adding_card_to;
        let selected_card = controller.selected_card;
        let mls_sidecar_restore_key_seen = controller.mls_sidecar_restore_key_seen;
        let board_popover = controller.board_popover;
        let archive_board_confirm_open = controller.archive_board_confirm_open;
        let list_archive_confirm = controller.list_archive_confirm;
        let editing_card_detail = controller.editing_card_detail;
        let card_edit_scope = controller.card_edit_scope;
        let card_detail_sidebar_visible = controller.card_detail_sidebar_visible;
        let card_detail_actions_open = controller.card_detail_actions_open;
        let card_detail_tab = controller.card_detail_tab;
        let card_detail_discussion_mounted_for = controller.card_detail_discussion_mounted_for;
        let card_detail_sidebar_tab = controller.card_detail_sidebar_tab;
        let card_detail_docked = controller.card_detail_docked;
        let card_detail_dock_width = controller.card_detail_dock_width;
        let card_detail_resizing = controller.card_detail_resizing;
        let card_detail_resize_start_x = controller.card_detail_resize_start_x;
        let card_detail_resize_start_width = controller.card_detail_resize_start_width;
        let member_handle_fetching = controller.member_handle_fetching;
        let card_edit_title = controller.card_edit_title;
        let card_edit_description = controller.card_edit_description;
        let card_edit_body = controller.card_edit_body;
        let card_edit_synthesis = controller.card_edit_synthesis;
        let card_edit_synthesis_target_id = controller.card_edit_synthesis_target_id;
        let card_detail_edit_status = controller.card_detail_edit_status;
        let assignee_picker_open = controller.assignee_picker_open;
        let assignee_filter = controller.assignee_filter;
        let assignee_selected_actor_ids = controller.assignee_selected_actor_ids;
        let assignee_edit_status = controller.assignee_edit_status;
        let due_picker_open = controller.due_picker_open;
        let due_edit_value = controller.due_edit_value;
        let due_calendar_month = controller.due_calendar_month;
        let due_edit_status = controller.due_edit_status;
        let card_edit_calendar = controller.card_edit_calendar;
        let calendar_rsvp_occurrence = controller.calendar_rsvp_occurrence;
        let card_synthesis_history_open_id = controller.card_synthesis_history_open_id;
        let card_synthesis_selected_revision_id = controller.card_synthesis_selected_revision_id;
        let card_edit_labels = controller.card_edit_labels;
        let card_edit_assignee = controller.card_edit_assignee;
        let card_edit_due = controller.card_edit_due;
        let dragging_card = controller.dragging_card;
        let dragging_column = controller.dragging_column;
        let drop_target_column = controller.drop_target_column;
        let editing_column_id = controller.editing_column_id;
        let editing_column_title = controller.editing_column_title;
        let board_status = controller.board_status;
        let command_queue = controller.command_queue;
        if !card_write_ready {
            return;
        }
        let handler = {
            let base = base_url.clone();
            let realm = selected_realm_id.clone();
            let actor = principal_id.clone();
            let space_container_id = confirm_list_id.clone();
            move |_| {
                list_archive_confirm.revise(|value| {
                    let next = None;
                    *value = next;
                });
                dispatch_space_container_lifecycle(
                    app.clone(),
                    base.clone(),
                    token,
                    realm.clone(),
                    actor.clone(),
                    space_container_id.clone(),
                    SpaceContainerLifecycleState::Archived,
                    state_store.clone(),
                    board_status,
                );
            }
        };
        handler(());
    }
    fn open_card(&self, card: KanbanCard) {
        let app = self.app.clone();
        let controller = self.controller;
        let state_store = app.state_store.clone();
        let base_url = app.base_url.get_untracked();
        let token = app.token;
        let principal_id = self.principal.to_string();
        let device_id = self.device.to_string();
        let selected_realm_id = self.realm.clone();
        let projection_realm_id = self.projection_realm.clone();
        let local_realm_id = self.local_realm.clone();
        let board_route_realm_id = card_detail_route_realm_id(&self.realm);
        let selected_scope_security_encrypted = self.security.get_untracked();
        let card_write_ready = self.ready.get_untracked();
        let columns = self.columns;
        let board_space_options = controller.board_space_options;
        let selected_board = controller.selected_board;
        let lifecycle_container_projection = controller.lifecycle_container_projection;
        let lifecycle_strand_projection = controller.lifecycle_strand_projection;
        let new_board_title = controller.new_board_title;
        let new_column_title = controller.new_column_title;
        let new_card_title = controller.new_card_title;
        let adding_card_to = controller.adding_card_to;
        let selected_card = controller.selected_card;
        let mls_sidecar_restore_key_seen = controller.mls_sidecar_restore_key_seen;
        let board_popover = controller.board_popover;
        let archive_board_confirm_open = controller.archive_board_confirm_open;
        let list_archive_confirm = controller.list_archive_confirm;
        let editing_card_detail = controller.editing_card_detail;
        let card_edit_scope = controller.card_edit_scope;
        let card_detail_sidebar_visible = controller.card_detail_sidebar_visible;
        let card_detail_actions_open = controller.card_detail_actions_open;
        let card_detail_tab = controller.card_detail_tab;
        let card_detail_discussion_mounted_for = controller.card_detail_discussion_mounted_for;
        let card_detail_sidebar_tab = controller.card_detail_sidebar_tab;
        let card_detail_docked = controller.card_detail_docked;
        let card_detail_dock_width = controller.card_detail_dock_width;
        let card_detail_resizing = controller.card_detail_resizing;
        let card_detail_resize_start_x = controller.card_detail_resize_start_x;
        let card_detail_resize_start_width = controller.card_detail_resize_start_width;
        let member_handle_fetching = controller.member_handle_fetching;
        let card_edit_title = controller.card_edit_title;
        let card_edit_description = controller.card_edit_description;
        let card_edit_body = controller.card_edit_body;
        let card_edit_synthesis = controller.card_edit_synthesis;
        let card_edit_synthesis_target_id = controller.card_edit_synthesis_target_id;
        let card_detail_edit_status = controller.card_detail_edit_status;
        let assignee_picker_open = controller.assignee_picker_open;
        let assignee_filter = controller.assignee_filter;
        let assignee_selected_actor_ids = controller.assignee_selected_actor_ids;
        let assignee_edit_status = controller.assignee_edit_status;
        let due_picker_open = controller.due_picker_open;
        let due_edit_value = controller.due_edit_value;
        let due_calendar_month = controller.due_calendar_month;
        let due_edit_status = controller.due_edit_status;
        let card_edit_calendar = controller.card_edit_calendar;
        let calendar_rsvp_occurrence = controller.calendar_rsvp_occurrence;
        let card_synthesis_history_open_id = controller.card_synthesis_history_open_id;
        let card_synthesis_selected_revision_id = controller.card_synthesis_selected_revision_id;
        let card_edit_labels = controller.card_edit_labels;
        let card_edit_assignee = controller.card_edit_assignee;
        let card_edit_due = controller.card_edit_due;
        let dragging_card = controller.dragging_card;
        let dragging_column = controller.dragging_column;
        let drop_target_column = controller.drop_target_column;
        let editing_column_id = controller.editing_column_id;
        let editing_column_title = controller.editing_column_title;
        let board_status = controller.board_status;
        let command_queue = controller.command_queue;
        let handler = {
            let c = card.clone();
            let route_realm_id = card_detail_route_realm_id(&selected_realm_id);
            move |_| {
                let draft = card_detail_draft_from_card(&c);
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
                    let next = card_assigned_actor_ids(&c).into_iter().collect();
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
                    let next = editor_value_for_optional_card_field(&c.due);
                    *value = next;
                });
                due_calendar_month.revise(|value| {
                    let next = due_calendar_month_for_value(&c.due);
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
                card_detail_tab.revise(|value| {
                    let next = CardDetailContentTab::default();
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
                    let next = Some(c.clone());
                    *value = next;
                });
                app.navigate(kanban_card_task_route(
                    &route_realm_id,
                    selected_board
                        .get()
                        .as_ref()
                        .map(arkret_sdk::SpaceId::as_str)
                        .unwrap_or(""),
                    &c.id,
                ));
                replace_card_detail_tab_query(app.clone(), CardDetailContentTab::default());
            }
        };
        handler(());
    }
    fn select(&self, board: Option<arkret_sdk::SpaceId>) {
        let controller = self.controller;
        select_kanban_board(
            self.app.clone(),
            board,
            controller.selected_board,
            controller.board_popover,
            controller.selected_card,
            self.realm.clone(),
            controller.adding_card_to,
            controller.board_status,
        );
    }
    fn lifecycle_card(&self, card: &KanbanCard, target: StrandLifecycleState) {
        dispatch_strand_lifecycle(
            self.app.clone(),
            self.app.base_url.get_untracked(),
            self.app.token,
            self.realm.clone(),
            self.principal.to_string(),
            card.id.clone(),
            target,
            self.app.state_store.clone(),
            self.controller.board_status,
        );
    }
    fn restore_list(&self, column: &KanbanColumn) {
        dispatch_space_container_lifecycle(
            self.app.clone(),
            self.app.base_url.get_untracked(),
            self.app.token,
            self.realm.clone(),
            self.principal.to_string(),
            column.id.clone(),
            SpaceContainerLifecycleState::Active,
            self.app.state_store.clone(),
            self.controller.board_status,
        );
    }
    fn rename_column(&self, column: &KanbanColumn) {
        if !self.ready.get_untracked() {
            return;
        }
        let title = self
            .controller
            .editing_column_title
            .get_untracked()
            .trim()
            .to_owned();
        if title.is_empty() {
            return;
        }
        submit_column_rename(
            self.app.clone(),
            self.app.base_url.get_untracked(),
            self.app.token,
            self.realm.clone(),
            self.principal.to_string(),
            column.id.clone(),
            title,
            self.security.get_untracked(),
            self.app.state_store.clone(),
            self.controller.board_status,
        );
        self.controller
            .editing_column_id
            .revise(|value| *value = None);
    }
}
