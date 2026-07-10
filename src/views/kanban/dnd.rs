use super::*;
// Imports the drag-and-drop helpers relied on while they lived in the
// monolithic `kanban/mod.rs`; re-added here after the structural split since
// the component-only parent no longer brings them into scope.
use crate::hlc::Hlc;
use crate::local_state::MoveSubmissionState;
use crate::move_builder::{
    StrandPositionEffect, StrandPositionExpectation, strand_position_cell_id,
};
use crate::operation::sdk_event_local_operation_id;
use crate::rank::RankError;

pub(super) fn submit_kanban_operation_event(
    base_url: String,
    token: Signal<String>,
    realm_id: String,
    operation: arkret_sdk::Event,
    // R4: three-state security signal (see `kanban_plaintext_block_reason`).
    scope_security_encrypted: Option<bool>,
    mut state_store: Signal<LocalStateStore>,
    mut board_status: Signal<String>,
) {
    if let Some(reason) = kanban_plaintext_block_reason(scope_security_encrypted, &operation) {
        board_status.set(reason);
        return;
    }
    let operation_id = sdk_event_local_operation_id(&operation).to_owned();
    let kind = operation.kind.as_str().to_owned();
    let actor_id = operation.actor_id.to_string();
    let created_at = operation.created_at.to_rfc3339();
    state_store.write().append_raw_operation(
        operation_id.clone(),
        Some(realm_id),
        json!({
            "kind": kind,
            "operation_id": operation_id,
            "actor_id": actor_id,
            "created_at": created_at,
            "write_state": "queued",
            "body": operation.payload.clone(),
        }),
    );
    board_status.set(format!(
        "submitting {kind} operation {}",
        short_protocol_id(&operation_id)
    ));
    let api_token = token();
    let operation_id_for_status = operation_id.clone();
    // X13: use `spawn_forever`, NOT `spawn`. The "New board" handler calls
    // `navigator.replace(...)` to route to the new board IMMEDIATELY after
    // calling this — a `spawn`-ed task is tied to the current component scope
    // and gets dropped/cancelled when that route change unmounts the panel,
    // so the `ck.space.create` POST never left the client (board stuck
    // `write_state:"queued"`, never reaching the server → other devices saw a
    // nameless `ak:space:...` board). `spawn_forever` (ScopeId::ROOT) detaches
    // the task so the submit completes regardless of navigation/unmount.
    // ("Add List" never navigated, which is why lists were `accepted` while
    // boards stayed `queued`.)
    //
    // X13.6 — but a DETACHED task may outlive the scope that owns the
    // `Signal`s it captured (component unmount, or a `dx serve` hot-reload
    // tearing scopes down mid-flight). Do not touch component-owned Signals
    // after the await from this root task; the POST already reached the server,
    // and the next /sync reconciles local `write_state`.
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
    state_store: Signal<LocalStateStore>,
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
        let op = match crate::operation::ck_ops::space_update_patch(
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

/// Rename a list (column) by submitting a `ck.space.update` title patch.
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
    state_store: Signal<LocalStateStore>,
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
    let op = match crate::operation::ck_ops::space_update_patch(
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

/// Build + submit a Kanban event and record it in the board write queue.
/// Card creates emit real `ck.strand.create` envelopes with an initial
/// `ck.component.strand.position.v1` component; metadata writes go through
/// the canonical `ck.strand.update` patch helper.
pub(super) fn submit_kanban_move(
    base_url: String,
    token: Signal<String>,
    realm_id: String,
    actor_id: String,
    subject: String,
    kind: &'static str,
    value: serde_json::Value,
    // R4: three-state security signal (see `kanban_plaintext_block_reason`).
    scope_security_encrypted: Option<bool>,
    mut state_store: Signal<LocalStateStore>,
    mut write_records: Signal<Vec<BoardWriteRecord>>,
    mut board_status: Signal<String>,
) {
    let hlc = Hlc::now("inkson").to_string();
    let seal_ref = state_store.read().seal_ref_for_realm_move(&realm_id);
    if actor_id.trim().is_empty() {
        board_status.set("sign in before updating cards".to_owned());
        return;
    }
    let envelope = if kind == "ak.strand.create" {
        let Some(board_space_id) = value.get("board_space_id").and_then(Value::as_str) else {
            board_status.set("cannot create card: missing board_space_id".to_owned());
            return;
        };
        let Some(list_space_id) = value.get("list_space_id").and_then(Value::as_str) else {
            board_status.set("cannot create card: missing list_space_id".to_owned());
            return;
        };
        let Some(title) = value.get("title").and_then(Value::as_str) else {
            board_status.set("cannot create card: missing title".to_owned());
            return;
        };
        let Some(rank) = value.get("rank").and_then(Value::as_str) else {
            board_status.set("cannot create card: missing rank".to_owned());
            return;
        };
        crate::operation::ck_ops::kanban_card_strand_create(
            &realm_id,
            &actor_id,
            &subject,
            board_space_id,
            list_space_id,
            title,
            rank,
        )
    } else {
        crate::operation::ck_ops::strand_position_update(
            &realm_id,
            &actor_id,
            &subject,
            value.clone(),
        )
    };
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
    let wire_kind = event.kind.as_str().to_owned();
    let op_id = sdk_event_local_operation_id(&event).to_owned();
    let cell_id = value
        .get("board_space_id")
        .and_then(Value::as_str)
        .map(|board_space_id| strand_position_cell_id(board_space_id, &subject))
        .unwrap_or_else(|| format!("ak:cell:ck.component.strand.position.v1:{subject}"));
    let effect_summary = if kind == "ak.strand.create" {
        serde_json::to_string(&event.payload).unwrap_or_else(|_| "{}".to_owned())
    } else {
        serde_json::to_string(&value).unwrap_or_else(|_| "{}".to_owned())
    };
    let record = BoardWriteRecord {
        state: CardState::Queued,
        move_id: op_id.clone(),
        kind: kind.to_owned(),
        cell_id: cell_id.clone(),
        effect_summary: effect_summary.clone(),
        seal_ref: seal_ref.clone(),
        hlc: hlc.clone(),
        note: format!("submitting {wire_kind} event via ak.self.events.command.submit"),
        signed_move_json: None,
        rebase_attempts: 0,
    };
    write_records.write().push(record);
    state_store.write().append_raw_operation(
        op_id.clone(),
        Some(realm_id.clone()),
        json!({
            "kind": kind,
            "operation_id": op_id,
            "actor_id": actor_id.clone(),
            "created_at": event.created_at.to_rfc3339(),
            "cell": cell_id,
            "effect": value,
            "wire_kind": wire_kind.clone(),
            "body": event.payload.clone(),
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
                if let Some(record) = write_records
                    .write()
                    .iter_mut()
                    .find(|r| r.move_id == op_for_track)
                {
                    record.state = CardState::Accepted;
                    record.note = format!(
                        "event accepted; pending seal event_id={}",
                        short_protocol_id(&resp.event_id)
                    );
                }
                board_status.set(format!(
                    "{kind_for_record} event {} accepted by server; pending seal (event_id={})",
                    short_protocol_id(&op_for_track),
                    short_protocol_id(&resp.event_id)
                ));
            }
            Err(err) => {
                state_store.write().update_raw_operation_write_state(
                    &op_for_track,
                    "quarantined",
                    None,
                    Some(err.display().to_string()),
                );
                if let Some(record) = write_records
                    .write()
                    .iter_mut()
                    .find(|r| r.move_id == op_for_track)
                {
                    record.state = CardState::Quarantined;
                    record.note = format!("submit failed: {}", err.display());
                }
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
/// - Cross-column drop ⇒ `ck.strand.move` Event kind.
/// - Same-column drop ⇒ `ck.strand.reorder`.
/// - Both compile to the same `ak:cell:ck.component.strand.position.v1:<board>:<strand>`
///   cas-register cell; the difference is whether `effect.list_space_id` equals
///   `expected.list_space_id`.
pub(super) fn dispatch_strand_position_move(
    base_url: String,
    token: Signal<String>,
    realm_id: String,
    board_space_id: String,
    board_view_id: String,
    actor_id: String,
    dragged: DraggedCard,
    target_column_id: String,
    neighbours: ColumnNeighbours,
    state_store: Signal<LocalStateStore>,
    write_records: Signal<Vec<BoardWriteRecord>>,
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
        "ak.strand.reorder"
    } else {
        "ak.strand.move"
    };
    submit_strand_position_cas_move(
        base_url,
        token,
        realm_id,
        board_space_id,
        board_view_id,
        actor_id,
        dragged.card_id,
        kind,
        expected,
        effect,
        state_store,
        write_records,
        board_status,
    );
}

/// Map soland's wire state strings into `SpaceContainerLifecycleState`.
/// Anything we don't recognise stays `Active`
/// (the safe default — server can correct on next sync).
pub(super) fn space_container_state_from_wire(state: &str) -> SpaceContainerLifecycleState {
    match state {
        "archived" => SpaceContainerLifecycleState::Archived,
        "tombstoned" => SpaceContainerLifecycleState::Tombstoned,
        _ => SpaceContainerLifecycleState::Active,
    }
}

/// Sibling at the Strand object layer. The wire enum is exactly
/// `{active, archived, redacted}` (`strand.schema.json` state) — `redacted`
/// is the only irreversible terminal. There is NO `deleted` state in the
/// spec; if the server ever sends `"deleted"` we log a warning and degrade
/// to `Active` (the safe non-terminal default — server can correct on next
/// sync) rather than silently treating it as a terminal.
pub(super) fn strand_lifecycle_from_wire(state: &str) -> StrandLifecycleState {
    match state {
        "archived" => StrandLifecycleState::Archived,
        "redacted" => StrandLifecycleState::Redacted,
        "deleted" => {
            tracing::warn!(
                wire_state = "deleted",
                "Strand wire state `deleted` is not in the spec enum (active/archived/redacted); \
                 degrading to Active. Redact, not delete, is the terminal per strand.schema.json."
            );
            StrandLifecycleState::Active
        }
        _ => StrandLifecycleState::Active,
    }
}

/// Cap-Gate-3: helper that reads the app-provided `CapabilityEngine`
/// signal and returns the UI gate for a Space-container-scoped action. Wraps
/// `engine.read().ui_gate(...)` so kanban callers don't have to spell
/// out the `UiResourceRef` / `UiCapabilityEvalContext` every time.
pub(super) fn capability_gate_for_space_container(
    engine: &Signal<crate::capability::CapabilityEngine>,
    actor: &str,
    space_container_id: &str,
    action: &str,
) -> crate::capability::CapabilityGate {
    let resource = crate::capability::UiResourceRef {
        space_id: Some(space_container_id.to_owned()),
        object_ref: Some(space_container_id.to_owned()),
        object_type: Some("space_container".to_owned()),
        ..Default::default()
    };
    let ctx = crate::capability::UiCapabilityEvalContext {
        space_id: Some(space_container_id.to_owned()),
        space_container_id: Some(space_container_id.to_owned()),
        action: Some(action.to_owned()),
        ..Default::default()
    };
    engine.read().ui_gate(actor, action, &resource, &ctx)
}

/// Cap-Gate-3 sibling at the Strand object layer.
pub(super) fn capability_gate_for_strand(
    engine: &Signal<crate::capability::CapabilityEngine>,
    actor: &str,
    board_space_id: &str,
    strand_id: &str,
    action: &str,
) -> crate::capability::CapabilityGate {
    let board_space_id = board_space_id.trim();
    let resource_space_id = (!board_space_id.is_empty()).then(|| board_space_id.to_owned());
    let resource = crate::capability::UiResourceRef {
        space_id: resource_space_id.clone(),
        object_ref: Some(strand_id.to_owned()),
        object_type: Some("Strand".to_owned()),
        ..Default::default()
    };
    let ctx = crate::capability::UiCapabilityEvalContext {
        space_id: resource_space_id,
        action: Some(action.to_owned()),
        ..Default::default()
    };
    engine.read().ui_gate(actor, action, &resource, &ctx)
}

/// Dispatch a `ck.space.archive` or `ck.space.restore` operation against
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
    mut state_store: Signal<LocalStateStore>,
    mut board_status: Signal<String>,
) {
    // Only Active <-> Archived are dispatchable; Tombstone is server-only.
    let builder = match target {
        SpaceContainerLifecycleState::Archived => {
            crate::operation::ck_ops::realm_archive(&realm_id, &actor_id, &space_container_id)
        }
        SpaceContainerLifecycleState::Active => {
            crate::operation::ck_ops::space_restore(&realm_id, &actor_id, &space_container_id)
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
    let kind = event.kind.as_str().to_owned();
    let operation_id = sdk_event_local_operation_id(&event).to_owned();
    // Append the lifecycle op so the `columns` `use_memo` folds the optimistic
    // state immediately via `project_board` (`apply_space_*`). On submit
    // failure we mark the op `dropped`, which `raw_operation_allows_overlay`
    // excludes — reverting the optimistic flip without a direct signal write.
    state_store.write().append_raw_operation(
        operation_id.clone(),
        Some(realm_id.clone()),
        json!({
            "kind": kind,
            "operation_id": operation_id,
            "actor_id": actor_id,
            "created_at": event.created_at.to_rfc3339(),
            "write_state": "queued",
            "body": event.payload.clone(),
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

/// Dispatch `ck.strand.archive` or `ck.strand.restore` for a card and
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
    mut state_store: Signal<LocalStateStore>,
    mut board_status: Signal<String>,
) {
    // Only Active <-> Archived are dispatchable; Redaction is server-only.
    let builder = match target {
        StrandLifecycleState::Archived => {
            crate::operation::ck_ops::strand_archive(&realm_id, &actor_id, &strand_id)
        }
        StrandLifecycleState::Active => {
            crate::operation::ck_ops::strand_restore(&realm_id, &actor_id, &strand_id)
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
    let kind = event.kind.as_str().to_owned();
    let operation_id = sdk_event_local_operation_id(&event).to_owned();
    // Append the lifecycle op so the `columns` `use_memo` folds the optimistic
    // flip via `project_board` (`ck.strand.archive` / `ck.strand.restore`). On
    // submit failure we mark it `dropped` to revert — no direct signal write.
    state_store.write().append_raw_operation(
        operation_id.clone(),
        Some(realm_id.clone()),
        json!({
            "kind": kind,
            "operation_id": operation_id,
            "actor_id": actor_id,
            "created_at": event.created_at.to_rfc3339(),
            "write_state": "queued",
            "body": event.payload.clone(),
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
/// the client drives the cascade explicitly: each `ck.strand.archive`
/// and `ck.space.archive` is its own durable event. The board Space is
/// archived last so that, if any child archive is rejected, the board is
/// not left archived while cards remain active.
#[allow(clippy::too_many_arguments)]
pub(super) fn dispatch_board_archive_cascade(
    base_url: String,
    token: Signal<String>,
    realm_id: String,
    actor_id: String,
    board_space_id: String,
    mut state_store: Signal<LocalStateStore>,
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
                && view.state == "active"
        })
        .map(|view| view.strand_id)
        .collect();
    let active_list_ids: Vec<String> = space_container_views_from_ops(&raw_operations, &realm_id)
        .into_iter()
        .filter(|view| {
            view.kind == "list"
                && view.parent_space_id.as_deref() == Some(board_space_id.as_str())
                && view.state == "active"
        })
        .map(|view| view.space_id)
        .collect();

    // Build every archive event up front so a build error aborts before any
    // optimistic op is appended.
    let mut events: Vec<arkret_sdk::Event> = Vec::new();
    for strand_id in &active_card_ids {
        match crate::operation::ck_ops::strand_archive(&realm_id, &actor_id, strand_id)
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
        match crate::operation::ck_ops::realm_archive(&realm_id, &actor_id, list_id)
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
                let operation_id = sdk_event_local_operation_id(event).to_owned();
                store.append_raw_operation(
                    operation_id.clone(),
                    Some(realm_id.clone()),
                    json!({
                        "kind": event.kind.as_str(),
                        "operation_id": operation_id,
                        "actor_id": actor_id,
                        "created_at": event.created_at.to_rfc3339(),
                        "write_state": "queued",
                        "body": event.payload.clone(),
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

/// Build, sign, and submit a `ck.strand.move` / `ck.strand.reorder` CAS
/// Move via the new spec-compliant builder. Tracks the submission in
/// `write_records` and, on failed precondition, kicks off automatic
/// rebase via [`rebase_strand_position_after_conflict`] up to
/// [`MAX_CONFLICT_REBASE_ATTEMPTS`] times.
#[allow(clippy::too_many_arguments)]
pub(super) fn submit_strand_position_cas_move(
    base_url: String,
    token: Signal<String>,
    realm_id: String,
    board_space_id: String,
    board_view_id: String,
    actor_id: String,
    strand_id: String,
    kind: &'static str,
    expected: StrandPositionExpectation,
    effect: StrandPositionEffect,
    state_store: Signal<LocalStateStore>,
    write_records: Signal<Vec<BoardWriteRecord>>,
    board_status: Signal<String>,
) {
    submit_strand_position_cas_move_with_attempt(
        base_url,
        token,
        realm_id,
        board_space_id,
        board_view_id,
        actor_id,
        strand_id,
        kind,
        expected,
        effect,
        0,
        state_store,
        write_records,
        board_status,
    );
}

/// Internal variant of [`submit_strand_position_cas_move`] that threads
/// the rebase attempt counter. `attempt` is the **next** attempt number
/// (`0` for the user-initiated drop, `1` for the first rebase, …);
/// reaching [`MAX_CONFLICT_REBASE_ATTEMPTS`] without an Accepted /
/// PendingSeal result quarantines the record for manual review.
#[allow(clippy::too_many_arguments)]
pub(super) fn submit_strand_position_cas_move_with_attempt(
    base_url: String,
    token: Signal<String>,
    realm_id: String,
    board_space_id: String,
    board_view_id: String,
    actor_id: String,
    strand_id: String,
    kind: &'static str,
    expected: StrandPositionExpectation,
    effect: StrandPositionEffect,
    attempt: u8,
    mut state_store: Signal<LocalStateStore>,
    mut write_records: Signal<Vec<BoardWriteRecord>>,
    mut board_status: Signal<String>,
) {
    let hlc = Hlc::now("inkson").to_string();
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
    let envelope = match crate::operation::ck_ops::strand_position_cas_update(
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
    let move_id = sdk_event_local_operation_id(&event).to_owned();
    let cell_id = strand_position_cell_id(&board_space_id, &strand_id);
    let effect_summary = match &effect {
        StrandPositionEffect::SetPosition {
            list_space_id,
            rank,
        } => format!("set {{list_space_id={list_space_id}, rank={rank}}}"),
        StrandPositionEffect::Remove => "set null (remove)".to_owned(),
    };
    let record = BoardWriteRecord {
        state: CardState::Submitted,
        move_id: move_id.clone(),
        kind: kind.to_owned(),
        cell_id: cell_id.clone(),
        effect_summary,
        seal_ref: seal_ref.clone(),
        hlc: hlc.clone(),
        note: if attempt == 0 {
            format!("submitting {kind} via ak.self.events.command.submit")
        } else {
            format!("rebase attempt {attempt} of {kind}")
        },
        signed_move_json: None,
        rebase_attempts: attempt,
    };
    write_records.write().push(record);
    state_store.write().append_raw_operation(
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
            "body": event.payload.clone(),
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
    let base_for_rebase = base_url.clone();
    let realm_for_rebase = realm_id.clone();
    let board_for_rebase = board_space_id.clone();
    let view_for_rebase = board_view_id.clone();
    let strand_for_rebase = strand_id.clone();
    let effect_for_rebase = effect.clone();
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
                if let Some(record) = write_records
                    .write()
                    .iter_mut()
                    .find(|r| r.move_id == move_for_track)
                {
                    record.state = CardState::Accepted;
                    record.note = format!(
                        "event accepted; pending seal event_id={}",
                        short_protocol_id(&resp.event_id)
                    );
                }
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
                if let Some(record) = write_records
                    .write()
                    .iter_mut()
                    .find(|r| r.move_id == move_for_track)
                {
                    record.state = card_state;
                    record.note = format!("events.submit failed: {err_text}");
                }
                board_status.set(format!("{kind_for_record} event {err_text}"));
                // Auto-rebase the CAS event after a cas_conflict: re-fetch
                // the cell's current head via the projection endpoint,
                // build a fresh `expected_position`, and re-submit up to
                // MAX_CONFLICT_REBASE_ATTEMPTS times.
                if matches!(card_state, CardState::Conflict)
                    && attempt + 1 < MAX_CONFLICT_REBASE_ATTEMPTS
                {
                    rebase_strand_position_after_conflict(
                        base_for_rebase,
                        token,
                        realm_for_rebase,
                        board_for_rebase,
                        view_for_rebase,
                        actor_id.clone(),
                        strand_for_rebase,
                        kind_for_record,
                        effect_for_rebase,
                        attempt + 1,
                        state_store,
                        write_records,
                        board_status,
                    );
                } else if matches!(card_state, CardState::Conflict) {
                    if let Some(record) = write_records
                        .write()
                        .iter_mut()
                        .find(|r| r.move_id == move_for_track)
                    {
                        record.state = CardState::Quarantined;
                        record.note = format!(
                            "cas_conflict exhausted {MAX_CONFLICT_REBASE_ATTEMPTS} rebase attempts"
                        );
                    }
                    state_store.write().update_raw_operation_write_state(
                        &move_for_track,
                        "quarantined",
                        None,
                        Some(format!(
                            "cas_conflict exhausted {MAX_CONFLICT_REBASE_ATTEMPTS} rebase attempts"
                        )),
                    );
                    board_status.set(format!(
                        "{kind_for_record} quarantined after {MAX_CONFLICT_REBASE_ATTEMPTS} rebase attempts"
                    ));
                }
            }
        }
    });
}

/// Re-fetch the kanban projection after a CAS conflict to discover the
/// strand's current cell state, then re-submit the move with a refreshed
/// `expected_position`. Effect (target list + rank) is preserved — the
/// user's drop intent doesn't change just because someone else moved
/// the card concurrently.
///
/// Spec ([operations-sync.md §8](../../arkret-spec/spec/v1/zh/sync/operations-sync.md)):
/// the conflict-recovery path takes a snapshot + state witness +
/// inclusion proof; this MVP approximation just refetches the
/// collection projection (which the soland reducer derives from the
/// same cell store) and reads the strand's current `list_space_id` /
/// `rank` from it.
#[allow(clippy::too_many_arguments)]
pub(super) fn rebase_strand_position_after_conflict(
    base_url: String,
    token: Signal<String>,
    realm_id: String,
    board_space_id: String,
    board_view_id: String,
    actor_id: String,
    strand_id: String,
    kind: String,
    effect: StrandPositionEffect,
    attempt: u8,
    state_store: Signal<LocalStateStore>,
    write_records: Signal<Vec<BoardWriteRecord>>,
    mut board_status: Signal<String>,
) {
    board_status.set(format!(
        "rebase {kind} attempt {attempt}/{MAX_CONFLICT_REBASE_ATTEMPTS} — refetching projection"
    ));
    spawn(async move {
        if board_view_id.trim().is_empty() {
            board_status.set(
                "rebase aborted: enter a Board View ID so projection can provide the current cell head"
                    .to_owned(),
            );
            return;
        }
        let view_for_projection = board_view_id.clone();
        let new_expected = match with_authed_sdk_client(&base_url, token(), |http| async move {
            crate::realm_read_api::collection_projection(&http, &view_for_projection).await
        })
        .await
        {
            Ok(projection) => locate_strand_position_in_projection(&projection, &strand_id),
            Err(err) => {
                board_status.set(format!(
                    "rebase aborted (projection refresh failed): {}",
                    err.display()
                ));
                return;
            }
        };
        // The static lifetime requirement on `kind` is satisfied by
        // mapping the dynamic String back to one of the known
        // classifiers. Anything else falls through to ak.strand.move
        // because that's the spec wire shape for drag operations.
        let kind_static: &'static str = match kind.as_str() {
            "ak.strand.reorder" => "ak.strand.reorder",
            "ak.strand.move" => "ak.strand.move",
            _ => "ak.strand.move",
        };
        submit_strand_position_cas_move_with_attempt(
            base_url,
            token,
            realm_id,
            board_space_id,
            board_view_id,
            actor_id,
            strand_id,
            kind_static,
            new_expected,
            effect,
            attempt,
            state_store,
            write_records,
            board_status,
        );
    });
}

/// Walk the projection groups looking for the strand's current cell
/// pre-state. Returns `Initial` if the strand isn't on the board (i.e.
/// the cell is in initial state) so the next CAS Move uses
/// `head_eq null`.
pub(super) fn locate_strand_position_in_projection(
    projection: &crate::projection_views::CollectionProjectionView,
    strand_id: &str,
) -> StrandPositionExpectation {
    for group in &projection.groups {
        for item in &group.items {
            let item_id = item.object.get("id").and_then(|v| v.as_str()).unwrap_or("");
            if item_id == strand_id {
                if let Some(rank) = item.position_rank() {
                    return StrandPositionExpectation::At {
                        list_space_id: group.key.clone(),
                        rank,
                    };
                }
                // Item present but no position metadata → treat as if
                // the cell were initial so we use `head_eq null`. This
                // is conservative; soland's reducer will reject if the
                // cell actually has a non-null head.
                return StrandPositionExpectation::Initial;
            }
        }
    }
    StrandPositionExpectation::Initial
}

/// Quarantines the first queued / soft-failed / conflicted board write for
/// manual review.
///
/// This is NOT a replay yet: event submit is the only write surface now, and
/// a failed write needs the UI to reconstruct the equivalent
/// `ck.strand.update` / `ck.component.strand.position.v1` envelope via
/// `ck_ops::strand_position_*` rather than replay stale bytes. That
/// reconstruction is tracked by **YOU-07-002 (kanban write replay)**; until it
/// lands, the matching toolbar control is labelled "Quarantine for Review"
/// (not "Replay") so the UI never promises a replay it can't perform.
pub(super) fn quarantine_first_failed_write(
    mut write_records: Signal<Vec<BoardWriteRecord>>,
    mut board_status: Signal<String>,
) {
    let Some(idx) = write_records.read().iter().position(|record| {
        record.state == CardState::Queued
            || record.state == CardState::SoftFailed
            || record.state == CardState::Conflict
    }) else {
        board_status.set("no queued write to quarantine".to_owned());
        return;
    };
    if let Some(record) = write_records.write().get_mut(idx) {
        record.state = CardState::Quarantined;
        record.note =
            "automatic replay not wired (YOU-07-002); quarantined for manual review".to_owned();
    }
    board_status.set(
        "write quarantined for manual review — automatic replay not yet available (YOU-07-002)"
            .to_owned(),
    );
}
