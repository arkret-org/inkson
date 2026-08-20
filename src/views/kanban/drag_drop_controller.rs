//! Drag/drop command controller for optimistic board moves and retries.

use arkret_wire::event_kind_str;

use super::*;
// Imports the drag-and-drop helpers relied on while they lived in the
// monolithic `kanban/mod.rs`; re-added here after the structural split since
// the component-only parent no longer brings them into scope.
use crate::move_builder::{
    StrandPositionEffect, StrandPositionExpectation, strand_position_cell_id,
};
use crate::rank::RankError;
use crate::state::MoveSubmissionState;

pub(super) fn submit_kanban_operation_event(
    base_url: String,
    token: Signal<String>,
    realm_id: String,
    operation: crate::operation::LocalOperation,
    // R4: three-state security signal (see `kanban_plaintext_block_reason`).
    scope_security_encrypted: Option<bool>,
    mut state_store: SyncSignal<LocalStateStore>,
    mut board_status: Signal<String>,
) {
    if let Some(reason) = kanban_plaintext_block_reason(scope_security_encrypted, &operation) {
        board_status.set(reason);
        return;
    }
    let operation_id = operation.local_operation_id().to_string();
    let kind = operation.kind().as_str().to_owned();
    let actor_id = operation.actor_id().to_string();
    let created_at = arkret_sdk::canonical::format_timestamp_canonical(operation.created_at());
    {
        let mut store = state_store.write();
        store.enqueue_local_projection_command(
            operation_id.clone(),
            Some(realm_id),
            json!({
                "kind": kind,
                "operation_id": operation_id,
                "actor_id": actor_id,
                "created_at": created_at,
                "write_state": "queued",
                "body": operation.payload().clone(),
                // A create names its object only once accepted, so until then the
                // record keys it by the write's holder-local handle.
                "local_target_ref": operation.local_object_handle(),
            }),
        );
        // Land the op-log row inside this same write: the op-log-derived
        // pending Board surface (and the seed suppression reading it) must
        // observe the create before the options-sync effect re-runs, which
        // happens as soon as this store write marks subscribers dirty. The
        // deferred drain in `KanbanEffects` then simply no-ops.
        store.project_pending_local_commands();
    }
    board_status.set(format!(
        "submitting {kind} operation {}",
        short_protocol_id(&operation_id)
    ));
    let api_token = token();
    let operation_id_for_status = operation_id.clone();
    let operation_id_for_reconcile = operation_id.clone();
    // X13: use `spawn_forever`, NOT `spawn`. The "New board" handler calls
    // `navigator.replace(...)` to route to the new board IMMEDIATELY after
    // calling this — a `spawn`-ed task is tied to the current component scope
    // and gets dropped/cancelled when that route change unmounts the panel,
    // so the `ak.space.create` POST never left the client (board stuck
    // `write_state:"queued"`, never reaching the server → other devices saw a
    // nameless `ak:space:...` board). `spawn_forever` (ScopeId::ROOT) detaches
    // the task so the submit completes regardless of navigation/unmount.
    // ("Add List" never navigated, which is why lists were `accepted` while
    // boards stayed `queued`.)
    //
    // X13.6 — but a DETACHED task may outlive the scope that owns the
    // `Signal`s it captured (component unmount, or a `dx serve` hot-reload
    // tearing scopes down mid-flight). Do not touch component-owned Signals
    // after the await from this root task. `state_store` is the app-owned
    // SessionContext signal and deliberately survives route unmounts, so it is
    // the one safe reconciliation target here.
    //
    // NOTE: `spawn_forever` is NOT in the dioxus prelude (only `spawn` is);
    // reach it via the re-exported core crate.
    dioxus::core::spawn_forever(async move {
        let result = with_authed_api(&base_url, api_token, |api| async move {
            api.event_submitter()?.submit_sdk_event(&operation).await
        })
        .await;
        match result {
            Ok(resp) => {
                // `build_sdk_event` names an event-derived create from its
                // draft Event id. Final authoring attaches actor-chain/HLC/CBA
                // fields and refreshes that content-bound id, so preserve the
                // accepted id on the optimistic row. The projection uses it to
                // migrate the temporary object id, and backfill can then merge
                // the canonical Event into this row instead of appending a
                // duplicate List/Board.
                state_store.write().update_raw_operation_write_state(
                    &operation_id_for_reconcile,
                    "accepted",
                    Some(resp.event_id.clone()),
                    None,
                );
                tracing::debug!(
                    operation_id = %short_protocol_id(&operation_id_for_status),
                    event_id = %short_protocol_id(&resp.event_id),
                    kind = %kind,
                    "detached kanban operation accepted"
                );
            }
            Err(err) => {
                tracing::warn!(
                    operation_id = %short_protocol_id(&operation_id_for_status),
                    kind = %kind,
                    error = %err.display(),
                    "detached kanban operation failed"
                );
            }
        }
    });
}

pub(super) fn submit_column_order_updates(
    base_url: String,
    token: Signal<String>,
    realm_id: String,
    actor_id: String,
    ordered_columns: Vec<KanbanColumn>,
    // R4: three-state security signal (see `kanban_plaintext_block_reason`).
    scope_security_encrypted: Option<bool>,
    state_store: SyncSignal<LocalStateStore>,
    mut board_status: Signal<String>,
) {
    if actor_id.trim().is_empty() {
        board_status.set("sign in before reordering lists".to_owned());
        return;
    }
    if realm_id.trim().is_empty() {
        board_status.set("select a Realm before reordering lists".to_owned());
        return;
    }
    let updates = ordered_columns
        .into_iter()
        .map(|column| (column.id, column.rank))
        .collect::<Vec<_>>();
    if updates.is_empty() {
        return;
    }
    let update_count = updates.len();
    board_status.set(format!(
        "Column order sending... ({update_count} rank updates)"
    ));
    for (column_id, rank) in updates {
        let op = match crate::operation::ak_ops::space_update_patch(
            &realm_id,
            &actor_id,
            &column_id,
            json!({ "rank": rank }),
        ) {
            Ok(builder) => match builder.build_sdk_event("inkson") {
                Ok(event) => event,
                Err(err) => {
                    board_status.set(format!("Column order failed: {err}"));
                    return;
                }
            },
            Err(err) => {
                board_status.set(format!("Column order failed: {err:#}"));
                return;
            }
        };
        submit_kanban_operation_event(
            base_url.clone(),
            token,
            realm_id.clone(),
            op,
            scope_security_encrypted,
            state_store,
            board_status,
        );
    }
}

/// Rename a list (column) by submitting a `ak.space.update` title patch.
/// The optimistic projection folds the patch into the `columns` memo, so the
/// new title renders immediately while the envelope is in flight
/// (design/kanban-baseline.md M1).
pub(super) fn submit_column_rename(
    base_url: String,
    token: Signal<String>,
    realm_id: String,
    actor_id: String,
    column_id: String,
    title: String,
    // R4: three-state security signal (see `kanban_plaintext_block_reason`).
    scope_security_encrypted: Option<bool>,
    state_store: SyncSignal<LocalStateStore>,
    mut board_status: Signal<String>,
) {
    let title = title.trim().to_owned();
    if title.is_empty() {
        return;
    }
    if actor_id.trim().is_empty() {
        board_status.set("sign in before renaming lists".to_owned());
        return;
    }
    if realm_id.trim().is_empty() {
        board_status.set("select a Realm before renaming lists".to_owned());
        return;
    }
    let op = match crate::operation::ak_ops::space_update_patch(
        &realm_id,
        &actor_id,
        &column_id,
        json!({ "title": title }),
    ) {
        Ok(builder) => match builder.build_sdk_event("inkson") {
            Ok(event) => event,
            Err(err) => {
                board_status.set(format!("List rename failed: {err}"));
                return;
            }
        },
        Err(err) => {
            board_status.set(format!("List rename failed: {err:#}"));
            return;
        }
    };
    submit_kanban_operation_event(
        base_url,
        token,
        realm_id,
        op,
        scope_security_encrypted,
        state_store,
        board_status,
    );
}

/// Closed command accepted by the card-create boundary.
///
/// Keeping these fields typed prevents UI call sites from selecting an event
/// kind independently of the JSON body that the builder expects.
pub(super) struct KanbanCardCreateCommand {
    pub board_space_id: String,
    pub list_space_id: String,
    pub title: String,
    pub rank: String,
}

/// Build and submit a card-create event.
pub(super) fn submit_kanban_card_create(
    base_url: String,
    token: Signal<String>,
    realm_id: String,
    actor_id: String,
    command: KanbanCardCreateCommand,
    // R4: three-state security signal (see `kanban_plaintext_block_reason`).
    scope_security_encrypted: Option<bool>,
    mut state_store: SyncSignal<LocalStateStore>,
    mut board_status: Signal<String>,
) {
    let kind = event_kind_str::STRAND_CREATE;
    let seal_ref = state_store.read().seal_ref_for_realm_move(&realm_id);
    if actor_id.trim().is_empty() {
        board_status.set("sign in before updating cards".to_owned());
        return;
    }
    let envelope = crate::operation::ak_ops::kanban_card_strand_create(
        &realm_id,
        &actor_id,
        &command.board_space_id,
        &command.list_space_id,
        &command.title,
        &command.rank,
    );
    let envelope = match envelope {
        Ok(builder) => builder.build_sdk_event("inkson"),
        Err(err) => {
            board_status.set(format!("cannot submit card update: {err:#}"));
            return;
        }
    };
    let event = match envelope {
        Ok(event) => event,
        Err(err) => {
            board_status.set(format!("cannot submit card update: {err}"));
            return;
        }
    };
    if let Some(reason) = kanban_plaintext_block_reason(scope_security_encrypted, &event) {
        board_status.set(reason);
        return;
    }
    let wire_kind = event.kind().as_str().to_owned();
    // A create names its Strand by `retype(event_id)` of the FINAL Event, which
    // does not exist yet. Until the receipt lands, the optimistic row is keyed
    // by the write's holder-local operation id; `event_derived_target_aliases`
    // migrates it to the accepted event-derived id.
    let subject = event.local_object_handle().to_owned();
    let cell_id = strand_position_cell_id(&command.board_space_id, &subject);
    let value = json!({
        "board_space_id": command.board_space_id,
        "list_space_id": command.list_space_id,
        "title": command.title,
        "rank": command.rank,
        "strand_kind": "card",
        "strand_id": subject,
    });
    let op_id = event.local_operation_id().to_string();
    state_store.write().enqueue_local_projection_command(
        op_id.clone(),
        Some(realm_id.clone()),
        json!({
            "kind": kind,
            "operation_id": op_id,
            "actor_id": actor_id.clone(),
            "created_at": arkret_sdk::canonical::format_timestamp_canonical(event.created_at()),
            "cell": cell_id,
            "effect": value,
            "wire_kind": wire_kind.clone(),
            "body": event.payload().clone(),
            // A create payload carries no object id, so the record has to say
            // which handle this write's object is keyed by until the accepted
            // Event names it.
            "local_target_ref": subject,
            "write_state": "queued",
        }),
    );
    board_status.set(format!(
        "submitting {wire_kind} event {}",
        short_protocol_id(&op_id)
    ));
    let api_token = token();
    let realm_for_record = realm_id.clone();
    let seal_for_record = seal_ref.clone();
    let kind_for_record = kind.to_owned();
    let op_for_track = op_id.clone();
    let submit_event = event;
    spawn(async move {
        match with_authed_api(&base_url, api_token, |api| async move {
            api.event_submitter()?.submit_sdk_event(&submit_event).await
        })
        .await
        {
            Ok(resp) => {
                state_store.write().update_raw_operation_write_state(
                    &op_for_track,
                    "accepted",
                    Some(resp.event_id.clone()),
                    None,
                );
                let state = MoveSubmissionState::from_submit_state("accepted", None);
                state_store.write().record_move_submission_with_event_id(
                    op_for_track.clone(),
                    Some(resp.event_id.clone()),
                    realm_for_record,
                    kind_for_record.clone(),
                    state,
                    None,
                    Some(seal_for_record),
                );
                board_status.set(format!(
                    "{kind_for_record} event {} accepted by server; pending seal (event_id={})",
                    short_protocol_id(&op_for_track),
                    short_protocol_id(&resp.event_id)
                ));
            }
            Err(err) => {
                tracing::warn!(
                    operation_id = %short_protocol_id(&op_for_track),
                    kind = %kind_for_record,
                    error = %err.display(),
                    "kanban submit failed; card quarantined",
                );
                state_store.write().update_raw_operation_write_state(
                    &op_for_track,
                    "quarantined",
                    None,
                    Some(err.display().to_string()),
                );
                board_status.set(format!("quarantined event: {}", err.display()));
            }
        }
    });
}

/// `(prev_rank, next_rank)` for a drop landing. `None` on either side
/// means the drop is at the start / end of the column.
#[derive(Clone, Debug, PartialEq)]
pub(super) struct ColumnNeighbours {
    pub(super) prev_rank: Option<String>,
    pub(super) next_rank: Option<String>,
}

/// End-to-end handler for a drag-drop landing. Computes the new rank,
/// decides cross-list move vs in-list reorder, updates the local
/// pending state, and submits the spec-compliant CAS Move.
///
/// Spec mapping ([views.md §2.6](../../arkret-spec/spec/v1/zh/models/views.md)):
///
/// - Cross-column drop ⇒ `ak.strand.move` Event kind.
/// - Same-column drop ⇒ `ak.strand.reorder`.
/// - Both compile to the same `ak:cell:ak.component.strand.position.v1:<board>:<strand>`
///   cas-register cell; the difference is whether `effect.list_space_id` equals
///   `expected.list_space_id`.
pub(super) fn dispatch_strand_position_move(
    base_url: String,
    token: Signal<String>,
    realm_id: String,
    board_space_id: String,
    actor_id: String,
    dragged: DraggedCard,
    target_column_id: String,
    neighbours: ColumnNeighbours,
    state_store: SyncSignal<LocalStateStore>,
    mut board_status: Signal<String>,
) {
    // Don't emit a Move when the drag and drop land on the same exact
    // position: same column, dragged card already sits between
    // `prev_rank` and `next_rank` because we'd be re-asserting its
    // existing rank. UX-wise this is what a user expects (no spurious
    // state mismatch ping).
    if dragged.from_column_id == target_column_id {
        let same_slot = neighbours.prev_rank.as_deref() == Some(dragged.from_rank.as_str())
            || neighbours.next_rank.as_deref() == Some(dragged.from_rank.as_str());
        if same_slot {
            return;
        }
    }
    let new_rank = match rank_for_drop(
        neighbours.prev_rank.as_deref(),
        neighbours.next_rank.as_deref(),
    ) {
        Ok(r) => r,
        Err(RankError::Exhausted) => {
            board_status.set(
                "rank exhausted between neighbours — request ak.container.rebalance before retrying"
                    .to_owned(),
            );
            return;
        }
        Err(other) => {
            board_status.set(format!("rank generation failed: {other}"));
            return;
        }
    };
    // The move shows immediately because `submit_strand_position_cas_move`
    // appends the canonical move/reorder op to `raw_operations` (write_state
    // `submitted`), which the `columns` `use_memo` folds via `project_board` —
    // no direct signal mutation. It is not marked accepted until the server
    // returns from ak.events.submit.
    let expected = StrandPositionExpectation::At {
        list_space_id: dragged.from_column_id.clone(),
        rank: dragged.from_rank.clone(),
    };
    let effect = StrandPositionEffect::SetPosition {
        list_space_id: target_column_id.clone(),
        rank: new_rank.clone(),
    };
    let kind = if dragged.from_column_id == target_column_id {
        event_kind_str::STRAND_REORDER
    } else {
        event_kind_str::STRAND_MOVE
    };
    submit_strand_position_cas_move(
        base_url,
        token,
        realm_id,
        board_space_id,
        actor_id,
        dragged.card_id,
        kind,
        expected,
        effect,
        state_store,
        board_status,
    );
}

/// Map the authoritative SDK projection lifecycle into the UI lifecycle.
pub(super) fn space_container_state_from_projection(
    state: &arkret_sdk::ProjectionSpaceState,
) -> SpaceContainerLifecycleState {
    match state {
        arkret_sdk::ProjectionSpaceState::Archived => SpaceContainerLifecycleState::Archived,
        arkret_sdk::ProjectionSpaceState::Tombstoned => SpaceContainerLifecycleState::Tombstoned,
        arkret_sdk::ProjectionSpaceState::Active => SpaceContainerLifecycleState::Active,
    }
}

/// Map the authoritative SDK projection lifecycle into the UI lifecycle.
pub(super) fn strand_lifecycle_from_projection(
    state: &arkret_sdk::ProjectionObjectState,
) -> StrandLifecycleState {
    match state {
        arkret_sdk::ProjectionObjectState::Archived => StrandLifecycleState::Archived,
        arkret_sdk::ProjectionObjectState::Redacted => StrandLifecycleState::Redacted,
        arkret_sdk::ProjectionObjectState::Active => StrandLifecycleState::Active,
    }
}

/// Dispatch a `ak.space.archive` or `ak.space.restore` operation against
/// the given list (container Space) and mark the local row pending while
/// the column's `SpaceContainerLifecycleState` in the UI signal. Spec:
/// `models/realm-and-space.md §4.4`. Soland's lifecycle
/// envelope validator and the SDK reducer's lifecycle guard
/// both enforce wire / state shape; this helper only handles the
/// submit + local pending projection. If the submit fails the local
/// state is rolled back to the prior value.
pub(super) fn dispatch_space_container_lifecycle(
    base_url: String,
    token: Signal<String>,
    realm_id: String,
    actor_id: String,
    space_container_id: String,
    target: SpaceContainerLifecycleState,
    mut state_store: SyncSignal<LocalStateStore>,
    mut board_status: Signal<String>,
) {
    // Only Active <-> Archived are dispatchable; Tombstone is server-only.
    let builder = match target {
        SpaceContainerLifecycleState::Archived => {
            crate::operation::ak_ops::realm_archive(&realm_id, &actor_id, &space_container_id)
        }
        SpaceContainerLifecycleState::Active => {
            crate::operation::ak_ops::space_restore(&realm_id, &actor_id, &space_container_id)
        }
        SpaceContainerLifecycleState::Tombstoned => {
            board_status.set("lifecycle update failed: tombstone is not dispatchable".to_owned());
            return;
        }
    };
    let builder = match builder {
        Ok(builder) => builder,
        Err(err) => {
            board_status.set(format!("lifecycle update failed: {err}"));
            return;
        }
    };
    let event = match builder.build_sdk_event("inkson") {
        Ok(event) => event,
        Err(err) => {
            board_status.set(format!("lifecycle update failed: {err}"));
            return;
        }
    };
    let kind = event.kind().as_str().to_owned();
    let operation_id = event.local_operation_id().to_string();
    // Append the lifecycle op so the `columns` `use_memo` folds the optimistic
    // state immediately via `project_board` (`apply_space_*`). On submit
    // failure we mark the op `dropped`, which `raw_operation_allows_overlay`
    // excludes — reverting the optimistic flip without a direct signal write.
    state_store.write().enqueue_local_projection_command(
        operation_id.clone(),
        Some(realm_id.clone()),
        json!({
            "kind": kind,
            "operation_id": operation_id,
            "actor_id": actor_id,
            "created_at": arkret_sdk::canonical::format_timestamp_canonical(event.created_at()),
            "write_state": "queued",
            "body": event.payload().clone(),
        }),
    );
    let base = base_url.clone();
    let api_token = token();
    let operation_id_for_track = operation_id.clone();
    spawn(async move {
        let result = with_authed_api(&base, api_token, |api| async move {
            api.event_submitter()?.submit_sdk_event(&event).await
        })
        .await;
        match result {
            Ok(resp) => {
                if let Ok(mut store) = state_store.try_write() {
                    store.update_raw_operation_write_state(
                        &operation_id_for_track,
                        "accepted",
                        Some(resp.event_id.clone()),
                        None,
                    );
                }
                board_status.set(format!("{kind} accepted; list state = {target:?}"));
            }
            Err(err) => {
                // Revert the optimistic flip by dropping the op from the log.
                if let Ok(mut store) = state_store.try_write() {
                    store.update_raw_operation_write_state(
                        &operation_id_for_track,
                        "dropped",
                        None,
                        Some(err.display().to_string()),
                    );
                }
                board_status.set(format!("{kind} failed: {}", err.display()));
            }
        }
    });
}

/// Dispatch `ak.strand.archive` or `ak.strand.restore` for a card and
/// mark its `StrandLifecycleState` pending locally. Mirrors
/// `dispatch_space_container_lifecycle` but at the Strand object layer. Spec:
/// `strand-and-message.md §3`, `common-fields.md §5.1`. SDK reducer
/// enforces `state == archived` for restore (`strand_not_archived`) and
/// `state == active` for archive (`strand_not_active` — once SDK round
/// 10 lands; today only restore is reducer-enforced).
pub(super) fn dispatch_strand_lifecycle(
    base_url: String,
    token: Signal<String>,
    realm_id: String,
    actor_id: String,
    strand_id: String,
    target: StrandLifecycleState,
    mut state_store: SyncSignal<LocalStateStore>,
    mut board_status: Signal<String>,
) {
    // Only Active <-> Archived are dispatchable; Redaction is server-only.
    let builder = match target {
        StrandLifecycleState::Archived => {
            crate::operation::ak_ops::strand_archive(&realm_id, &actor_id, &strand_id)
        }
        StrandLifecycleState::Active => {
            crate::operation::ak_ops::strand_restore(&realm_id, &actor_id, &strand_id)
        }
        StrandLifecycleState::Redacted => {
            board_status.set("lifecycle update failed: redaction is not dispatchable".to_owned());
            return;
        }
    };
    let event = match builder.and_then(|builder| builder.build_sdk_event("inkson")) {
        Ok(event) => event,
        Err(err) => {
            board_status.set(format!("lifecycle update failed: {err:#}"));
            return;
        }
    };
    let kind = event.kind().as_str().to_owned();
    let operation_id = event.local_operation_id().to_string();
    // Append the lifecycle op so the `columns` `use_memo` folds the optimistic
    // flip via `project_board` (`ak.strand.archive` / `ak.strand.restore`). On
    // submit failure we mark it `dropped` to revert — no direct signal write.
    state_store.write().enqueue_local_projection_command(
        operation_id.clone(),
        Some(realm_id.clone()),
        json!({
            "kind": kind,
            "operation_id": operation_id,
            "actor_id": actor_id,
            "created_at": arkret_sdk::canonical::format_timestamp_canonical(event.created_at()),
            "write_state": "queued",
            "body": event.payload().clone(),
        }),
    );
    let base = base_url.clone();
    let api_token = token();
    let operation_id_for_track = operation_id.clone();
    spawn(async move {
        let result = with_authed_api(&base, api_token, |api| async move {
            api.event_submitter()?.submit_sdk_event(&event).await
        })
        .await;
        match result {
            Ok(resp) => {
                if let Ok(mut store) = state_store.try_write() {
                    store.update_raw_operation_write_state(
                        &operation_id_for_track,
                        "accepted",
                        Some(resp.event_id.clone()),
                        None,
                    );
                }
                board_status.set(format!("{kind} accepted; card lifecycle = {target:?}"));
            }
            Err(err) => {
                if let Ok(mut store) = state_store.try_write() {
                    store.update_raw_operation_write_state(
                        &operation_id_for_track,
                        "dropped",
                        None,
                        Some(err.display().to_string()),
                    );
                }
                board_status.set(format!("{kind} failed: {}", err.display()));
            }
        }
    });
}

/// Archive an entire board at end-of-week: cascade-archive every active
/// card and list, then archive the board container Space itself. v1 has
/// no server-side Space->Strand archive cascade (Strand lifecycle is
/// independent of its enclosing Space per `strand-and-message.md` §3), so
/// the client drives the cascade explicitly: each `ak.strand.archive`
/// and `ak.space.archive` is its own durable event. The board Space is
/// archived last so that, if any child archive is rejected, the board is
/// not left archived while cards remain active.
#[allow(clippy::too_many_arguments)]
pub(super) fn dispatch_board_archive_cascade(
    base_url: String,
    token: Signal<String>,
    realm_id: String,
    actor_id: String,
    board_space_id: String,
    mut state_store: SyncSignal<LocalStateStore>,
    mut board_status: Signal<String>,
) {
    if board_space_id.trim().is_empty() {
        board_status.set("select a Board Space before archiving the board".to_owned());
        return;
    }

    // Resolve the board's active children from the event-folded projection
    // (the `columns` `use_memo` derives the same set), then build the cascade
    // of archive events: child cards, child lists, board container last.
    let raw_operations = state_store.read().load().raw_operations;
    let active_card_ids: Vec<String> = strand_views_from_ops(&raw_operations)
        .into_iter()
        .filter(|view| {
            view.board_space_id.as_deref() == Some(board_space_id.as_str())
                && view.state == arkret_sdk::ProjectionObjectState::Active
        })
        .map(|view| view.strand_id)
        .collect();
    let active_list_ids: Vec<String> = space_container_views_from_ops(&raw_operations, &realm_id)
        .into_iter()
        .filter(|view| {
            view.kind == "list"
                && view.parent_space_id.as_deref() == Some(board_space_id.as_str())
                && view.state == arkret_sdk::ProjectionSpaceState::Active
        })
        .map(|view| view.space_id)
        .collect();

    // Build every archive event up front so a build error aborts before any
    // optimistic op is appended.
    let mut events: Vec<crate::operation::LocalOperation> = Vec::new();
    for strand_id in &active_card_ids {
        match crate::operation::ak_ops::strand_archive(&realm_id, &actor_id, strand_id)
            .and_then(|builder| builder.build_sdk_event("inkson"))
        {
            Ok(event) => events.push(event),
            Err(err) => {
                board_status.set(format!("cannot archive board: {err}"));
                return;
            }
        }
    }
    for list_id in active_list_ids
        .iter()
        .chain(std::iter::once(&board_space_id))
    {
        match crate::operation::ak_ops::realm_archive(&realm_id, &actor_id, list_id)
            .and_then(|builder| builder.build_sdk_event("inkson"))
        {
            Ok(event) => events.push(event),
            Err(err) => {
                board_status.set(format!("cannot archive board: {err}"));
                return;
            }
        }
    }

    // Append all archive ops so the board empties immediately via the memo;
    // a partial-cascade failure reverts every op by marking it `dropped`.
    let operation_ids: Vec<String> = {
        let mut store = state_store.write();
        events
            .iter()
            .map(|event| {
                let operation_id = event.local_operation_id().to_string();
                store.enqueue_local_projection_command(
                    operation_id.clone(),
                    Some(realm_id.clone()),
                    json!({
                        "kind": event.kind().as_str(),
                        "operation_id": operation_id,
                        "actor_id": actor_id,
                        "created_at": arkret_sdk::canonical::format_timestamp_canonical(
                            event.created_at()
                        ),
                        "write_state": "queued",
                        "body": event.payload_value(),
                    }),
                );
                operation_id
            })
            .collect()
    };

    board_status.set(crate::i18n::tr("kanban.archive_board_pending"));

    let base = base_url.clone();
    let api_token = token();
    spawn(async move {
        let events_for_submit = events;
        let outcome = with_authed_api(&base, api_token, |api| async move {
            for event in &events_for_submit {
                api.event_submitter()?.submit_sdk_event(event).await?;
            }
            Ok::<(), anyhow::Error>(())
        })
        .await;

        match outcome {
            Ok(()) => {
                if let Ok(mut store) = state_store.try_write() {
                    for operation_id in &operation_ids {
                        store.update_raw_operation_write_state(
                            operation_id,
                            "accepted",
                            None,
                            None,
                        );
                    }
                }
                board_status.set(crate::i18n::tr("kanban.archive_board_done"));
            }
            Err(err) => {
                // Revert the optimistic cascade so a partial archive does not
                // leave a half-archived board.
                if let Ok(mut store) = state_store.try_write() {
                    for operation_id in &operation_ids {
                        store.update_raw_operation_write_state(
                            operation_id,
                            "dropped",
                            None,
                            Some(err.display().to_string()),
                        );
                    }
                }
                board_status.set(format!(
                    "{} {}",
                    crate::i18n::tr("kanban.archive_board_action"),
                    err.display()
                ));
            }
        }
    });
}

/// Build, sign, and submit a `ak.strand.move` / `ak.strand.reorder` CAS event.
#[allow(clippy::too_many_arguments)]
pub(super) fn submit_strand_position_cas_move(
    base_url: String,
    token: Signal<String>,
    realm_id: String,
    board_space_id: String,
    actor_id: String,
    strand_id: String,
    kind: &'static str,
    expected: StrandPositionExpectation,
    effect: StrandPositionEffect,
    mut state_store: SyncSignal<LocalStateStore>,
    mut board_status: Signal<String>,
) {
    let seal_ref = state_store.read().seal_ref_for_realm_move(&realm_id);
    if actor_id.trim().is_empty() {
        board_status.set("sign in before moving cards".to_owned());
        return;
    }
    let expected_json = match &expected {
        StrandPositionExpectation::Initial => serde_json::Value::Null,
        StrandPositionExpectation::At {
            list_space_id,
            rank,
        } => {
            json!({"list_space_id": list_space_id, "rank": rank})
        }
    };
    let effect_json = match &effect {
        StrandPositionEffect::SetPosition {
            list_space_id,
            rank,
        } => {
            json!({"list_space_id": list_space_id, "rank": rank})
        }
        StrandPositionEffect::Remove => serde_json::Value::Null,
    };
    let envelope = match crate::operation::ak_ops::strand_position_cas_update(
        &realm_id,
        &actor_id,
        kind,
        &board_space_id,
        &strand_id,
        expected_json.clone(),
        effect_json.clone(),
    ) {
        Ok(builder) => builder.build_sdk_event("inkson"),
        Err(err) => {
            board_status.set(format!("cannot submit {kind}: {err:#}"));
            return;
        }
    };
    let event = match envelope {
        Ok(event) => event,
        Err(err) => {
            board_status.set(format!("cannot submit {kind}: {err}"));
            return;
        }
    };
    let move_id = event.local_operation_id().to_string();
    let cell_id = strand_position_cell_id(&board_space_id, &strand_id);
    state_store.write().enqueue_local_projection_command(
        move_id.clone(),
        Some(realm_id.clone()),
        json!({
            "kind": kind,
            "move_id": move_id,
            "cell": cell_id,
            "board_space_id": board_space_id,
            "strand_id": strand_id,
            "expected_position": match &expected {
                StrandPositionExpectation::Initial => serde_json::Value::Null,
                StrandPositionExpectation::At {
                    list_space_id,
                    rank,
                } => json!({"space_id": list_space_id, "rank": rank}),
            },
            "target_position": match &effect {
                StrandPositionEffect::SetPosition {
                    list_space_id,
                    rank,
                } => json!({"space_id": list_space_id, "rank": rank}),
                StrandPositionEffect::Remove => serde_json::Value::Null,
            },
            // Canonical move/reorder payload so the event-sourced
            // `project_board` reducer (`apply_move_to_view` /
            // `apply_reorder_to_view`) folds the optimistic move immediately —
            // `columns` is a pure `use_memo` over `raw_operations`, so the
            // relocation must live in the op log, not a direct signal mutation.
            "body": event.payload().clone(),
            "write_state": "submitted",
        }),
    );
    board_status.set(format!(
        "submitting {kind} event {}",
        short_protocol_id(&move_id)
    ));
    let api_token = token();
    let move_for_track = move_id.clone();
    let kind_for_record = kind.to_owned();
    let seal_for_record = seal_ref.clone();
    let realm_for_record = realm_id.clone();
    let submit_event = event;
    spawn(async move {
        let submit_result = with_authed_api(&base_url, api_token, |api| async move {
            api.event_submitter()?.submit_sdk_event(&submit_event).await
        })
        .await;
        match submit_result {
            Ok(resp) => {
                // events.submit accepted path: the server has folded the
                // CAS update into the cell. cas_conflict surfaces as an
                // Err arm because the envelope was rejected with a
                // non-200 status — that branch is handled below.
                state_store.write().update_raw_operation_write_state(
                    &move_for_track,
                    "accepted",
                    Some(resp.event_id.clone()),
                    None,
                );
                let submission_state = MoveSubmissionState::from_submit_state("accepted", None);
                state_store.write().record_move_submission_with_event_id(
                    move_for_track.clone(),
                    Some(resp.event_id.clone()),
                    realm_for_record,
                    kind_for_record.clone(),
                    submission_state,
                    None,
                    Some(seal_for_record),
                );
                board_status.set(format!(
                    "{kind_for_record} event {} accepted by server; pending seal (event_id={})",
                    short_protocol_id(&move_for_track),
                    short_protocol_id(&resp.event_id)
                ));
            }
            Err(err) => {
                let err_text = err.display();
                let cas_conflict = err_text.contains("cas_conflict");
                let card_state = if cas_conflict {
                    CardState::Conflict
                } else {
                    CardState::SoftFailed
                };
                state_store.write().update_raw_operation_write_state(
                    &move_for_track,
                    card_state.data_state(),
                    None,
                    Some(err_text.to_string()),
                );
                board_status.set(format!("{kind_for_record} event {err_text}"));
            }
        }
    });
}
