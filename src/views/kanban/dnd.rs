use super::*;

pub(super) fn submit_kanban_operation_event(
    base_url: String,
    token: Signal<String>,
    realm_id: String,
    operation: crate::operation::EventEnvelope,
    // R4: three-state security signal (see `kanban_plaintext_block_reason`).
    scope_security_encrypted: Option<bool>,
    mut state_store: Signal<LocalStateStore>,
    mut board_status: Signal<String>,
) {
    if let Some(reason) = kanban_plaintext_block_reason(scope_security_encrypted, &operation) {
        board_status.set(reason);
        return;
    }
    let operation_id = operation.local_operation_id().to_owned();
    let kind = operation.kind.clone();
    let actor_id = operation.actor_id.clone();
    let created_at = operation.created_at.clone();
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
    // nameless `ck:space:...` board). `spawn_forever` (ScopeId::ROOT) detaches
    // the task so the submit completes regardless of navigation/unmount.
    // ("Add List" never navigated, which is why lists were `accepted` while
    // boards stayed `queued`.)
    //
    // X13.6 — but a DETACHED task may outlive the scope that owns the
    // `Signal`s it captured (component unmount, or a `dx serve` hot-reload
    // tearing scopes down mid-flight). Accessing a dropped signal PANICS in
    // Dioxus 0.7 (`Result::unwrap()` on `Dropped(ValueDroppedError)`), which is
    // exactly the crash this caused. So every post-await signal touch goes
    // through `try_write()` and silently no-ops when the signal is gone. The
    // POST already reached the server before any signal access, so a missed
    // local `write_state` flip is cosmetic only — the next /sync reconciles it.
    //
    // NOTE: `spawn_forever` is NOT in the dioxus prelude (only `spawn` is);
    // reach it via the re-exported core crate.
    dioxus::core::spawn_forever(async move {
        let operation_for_submit = operation.clone();
        let result = with_authed_api(&base_url, api_token, |api| async move {
            api.submit_event_envelope(&operation_for_submit).await
        })
        .await;
        match result {
            Ok(resp) => {
                if let Ok(mut store) = state_store.try_write() {
                    store.update_raw_operation_write_state(
                        &operation_id_for_status,
                        "accepted",
                        Some(resp.event_id.clone()),
                        None,
                    );
                }
                if let Ok(mut status) = board_status.try_write() {
                    *status = format!(
                        "{kind} operation accepted by server (event_id={})",
                        short_protocol_id(&resp.event_id)
                    );
                }
            }
            Err(err) => {
                if let Ok(mut store) = state_store.try_write() {
                    store.update_raw_operation_write_state(
                        &operation_id_for_status,
                        "failed",
                        None,
                        Some(err.display().to_string()),
                    );
                }
                if let Ok(mut status) = board_status.try_write() {
                    *status = format!("{kind} operation failed: {}", err.display());
                }
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
            Ok(builder) => builder.build("yougen"),
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
    mut columns: Signal<Vec<KanbanColumn>>,
    mut state_store: Signal<LocalStateStore>,
    mut write_records: Signal<Vec<BoardWriteRecord>>,
    mut board_status: Signal<String>,
) {
    let hlc = Hlc::now("yougen").to_string();
    let seal_ref = state_store.read().seal_ref_for_realm_move(&realm_id);
    if actor_id.trim().is_empty() {
        board_status.set("sign in before updating cards".to_owned());
        return;
    }
    let envelope = if kind == "ck.strand.create" {
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
        Ok(builder) => builder.build("yougen"),
        Err(err) => {
            board_status.set(format!("cannot submit card update: {err:#}"));
            return;
        }
    };
    if let Some(reason) = kanban_plaintext_block_reason(scope_security_encrypted, &envelope) {
        board_status.set(reason);
        return;
    }
    let wire_kind = envelope.kind.clone();
    let op_id = envelope.local_operation_id().to_owned();
    let cell_id = value
        .get("board_space_id")
        .and_then(Value::as_str)
        .map(|board_space_id| strand_position_cell_id(board_space_id, &subject))
        .unwrap_or_else(|| format!("ck:cell:ck.component.strand.position.v1:{subject}"));
    let effect_summary = if kind == "ck.strand.create" {
        serde_json::to_string(&envelope.payload).unwrap_or_else(|_| "{}".to_owned())
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
        note: format!("submitting {wire_kind} event via ck.self.events.command.submit"),
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
            "created_at": envelope.created_at.clone(),
            "cell": cell_id,
            "effect": value,
            "wire_kind": wire_kind.clone(),
            "body": envelope.payload.clone(),
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
    spawn(async move {
        match with_authed_api(&base_url, api_token, |api| async move {
            api.submit_event_envelope(&envelope).await
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
                set_card_state_in_columns(&mut columns, &subject, CardState::Accepted);
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
                set_card_state_in_columns(&mut columns, &subject, CardState::Quarantined);
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
/// Spec mapping ([views.md §2.6](../../cokret-spec/spec/v1/zh/models/views.md)):
///
/// - Cross-column drop ⇒ `ck.strand.move` Event kind.
/// - Same-column drop ⇒ `ck.strand.reorder`.
/// - Both compile to the same `ck:cell:ck.component.strand.position.v1:<board>:<strand>`
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
    mut columns: Signal<Vec<KanbanColumn>>,
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
                "rank exhausted between neighbours — request ck.container.rebalance before retrying"
                    .to_owned(),
            );
            return;
        }
        Err(other) => {
            board_status.set(format!("rank generation failed: {other}"));
            return;
        }
    };
    // Show the move immediately as `sending...`; it is not marked
    // accepted until the server returns from ck.events.submit.
    let card_opt = {
        let mut cols = columns.write();
        relocate_card(
            &mut cols,
            &dragged.card_id,
            &dragged.from_column_id,
            &target_column_id,
            &new_rank,
        )
    };
    let Some(_card) = card_opt else {
        board_status.set("internal: dragged card not found in source column".to_owned());
        return;
    };
    let expected = StrandPositionExpectation::At {
        list_space_id: dragged.from_column_id.clone(),
        rank: dragged.from_rank.clone(),
    };
    let effect = StrandPositionEffect::SetPosition {
        list_space_id: target_column_id.clone(),
        rank: new_rank.clone(),
    };
    let kind = if dragged.from_column_id == target_column_id {
        "ck.strand.reorder"
    } else {
        "ck.strand.move"
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
        columns,
        state_store,
        write_records,
        board_status,
    );
}

/// Pure guard for Space-container lifecycle transitions. Refuses two illegal cases:
/// (1) same-state self-transition — UI structure already gates this
/// (Archive button only renders on Active columns and vice versa), but
/// keeping a programmatic guard avoids no-op server roundtrips if a future
/// code path bypasses the UI filter; (2) UI-emitted Tombstone — terminal
/// state is server-only. Extracted as a pure fn so the policy is unit-tested
/// without spinning up a Dioxus runtime.
pub(super) fn validate_space_container_lifecycle_transition(
    space_container_id: &str,
    prior: SpaceContainerLifecycleState,
    target: SpaceContainerLifecycleState,
) -> Result<(), String> {
    if matches!(target, SpaceContainerLifecycleState::Tombstoned) {
        return Err("Tombstone is server-only; UI dispatch refused".to_owned());
    }
    if prior == target {
        return Err(format!(
            "list {} already in {target:?} state; refused",
            short_protocol_id(space_container_id)
        ));
    }
    Ok(())
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
/// out the `ResourceRef` / `EvalContext` every time.
pub(super) fn capability_gate_for_space_container(
    engine: &Signal<crate::capability::CapabilityEngine>,
    actor: &str,
    space_container_id: &str,
    action: &str,
) -> crate::capability::CapabilityGate {
    let resource = crate::capability::ResourceRef {
        space_id: Some(space_container_id.to_owned()),
        object_ref: Some(space_container_id.to_owned()),
        object_type: Some("space_container".to_owned()),
        ..Default::default()
    };
    let ctx = crate::capability::EvalContext {
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
    let resource = crate::capability::ResourceRef {
        space_id: resource_space_id.clone(),
        object_ref: Some(strand_id.to_owned()),
        object_type: Some("Strand".to_owned()),
        ..Default::default()
    };
    let ctx = crate::capability::EvalContext {
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
    mut columns: Signal<Vec<KanbanColumn>>,
    mut board_status: Signal<String>,
) {
    // Pending state update. Capture prior state for rollback on error
    // and apply the same-state / Tombstone guard inside the write
    // critical section so prior is observed atomically.
    let prior_state = {
        let mut cols = columns.write();
        let Some(col) = cols.iter_mut().find(|c| c.id == space_container_id) else {
            board_status.set(format!(
                "internal: list {} not in board state",
                short_protocol_id(&space_container_id)
            ));
            return;
        };
        let prior = col.state;
        if let Err(msg) =
            validate_space_container_lifecycle_transition(&space_container_id, prior, target)
        {
            board_status.set(msg);
            return;
        }
        col.state = target;
        prior
    };

    // Only Active <-> Archived reach here (validator rejects Tombstone).
    let builder = match target {
        SpaceContainerLifecycleState::Archived => {
            crate::operation::ck_ops::realm_archive(&realm_id, &actor_id, &space_container_id)
        }
        SpaceContainerLifecycleState::Active => {
            crate::operation::ck_ops::space_restore(&realm_id, &actor_id, &space_container_id)
        }
        SpaceContainerLifecycleState::Tombstoned => {
            // Invariant: `validate_space_container_lifecycle_transition` (called above)
            // already rejects any move to Tombstone, so by construction the
            // only targets that reach this match are Active|Archived. If we
            // ever land here something upstream broke the contract — fail
            // loud rather than emitting a silently-wrong Move.
            panic!(
                "invariant violation: validate_space_container_lifecycle_transition guarantees target is Active|Archived; got {target:?}"
            )
        }
    };
    let op = builder.build("yougen");

    let kind = op.kind.clone();
    let base = base_url.clone();
    let api_token = token();
    spawn(async move {
        let result = with_authed_api(&base, api_token, |api| async move {
            api.submit_event_envelope(&op).await
        })
        .await;
        match result {
            Ok(_) => {
                board_status.set(format!(
                    "{kind} accepted; list optimistic state = {target:?}"
                ));
            }
            Err(err) => {
                // Rollback optimistic state on submit failure.
                if let Some(col) = columns
                    .write()
                    .iter_mut()
                    .find(|c| c.id == space_container_id)
                {
                    col.state = prior_state;
                }
                board_status.set(format!("{kind} failed: {}", err.display()));
            }
        }
    });
}

/// Pure guard for Strand lifecycle transitions. Mirrors
/// `validate_space_container_lifecycle_transition` at the Strand layer — refuses
/// same-state self-transitions and UI-emitted Redacted targets.
pub(super) fn validate_strand_lifecycle_transition(
    strand_id: &str,
    prior: StrandLifecycleState,
    target: StrandLifecycleState,
) -> Result<(), String> {
    if matches!(target, StrandLifecycleState::Redacted) {
        return Err("Redaction is server-only; UI dispatch refused".to_owned());
    }
    if prior == target {
        return Err(format!(
            "card {} already in {target:?} state; refused",
            short_protocol_id(strand_id)
        ));
    }
    Ok(())
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
    mut columns: Signal<Vec<KanbanColumn>>,
    mut board_status: Signal<String>,
) {
    // Locate the card across columns; capture prior state for rollback
    // and apply the same-state / Tombstone guard inside the write
    // critical section.
    let prior_state = {
        let mut cols = columns.write();
        let mut found = None;
        for col in cols.iter_mut() {
            if let Some(card) = col.cards.iter_mut().find(|c| c.id == strand_id) {
                let prior = card.lifecycle;
                if let Err(msg) = validate_strand_lifecycle_transition(&strand_id, prior, target) {
                    board_status.set(msg);
                    return;
                }
                card.lifecycle = target;
                found = Some(prior);
                break;
            }
        }
        match found {
            Some(prior) => prior,
            None => {
                board_status.set(format!(
                    "internal: card {} not in board state",
                    short_protocol_id(&strand_id)
                ));
                return;
            }
        }
    };

    let builder = match target {
        StrandLifecycleState::Archived => {
            crate::operation::ck_ops::strand_archive(&realm_id, &actor_id, &strand_id)
        }
        StrandLifecycleState::Active => {
            crate::operation::ck_ops::strand_restore(&realm_id, &actor_id, &strand_id)
        }
        StrandLifecycleState::Redacted => {
            // Invariant: `validate_strand_lifecycle_transition` (called above)
            // already rejects any move to Redacted, so by construction the
            // only targets that reach this match are Active|Archived. If we
            // ever land here something upstream broke the contract — fail
            // loud rather than emitting a silently-wrong Move.
            panic!(
                "invariant violation: validate_strand_lifecycle_transition guarantees target is Active|Archived; got {target:?}"
            )
        }
    };
    let op = match builder {
        Ok(builder) => builder.build("yougen"),
        Err(err) => {
            // Roll back the optimistic lifecycle flip applied above.
            for col in columns.write().iter_mut() {
                if let Some(card) = col.cards.iter_mut().find(|c| c.id == strand_id) {
                    card.lifecycle = prior_state;
                    break;
                }
            }
            board_status.set(format!("lifecycle update failed: {err:#}"));
            return;
        }
    };

    let kind = op.kind.clone();
    let base = base_url.clone();
    let api_token = token();
    spawn(async move {
        let result = with_authed_api(&base, api_token, |api| async move {
            api.submit_event_envelope(&op).await
        })
        .await;
        match result {
            Ok(_) => {
                board_status.set(format!(
                    "{kind} accepted; card optimistic lifecycle = {target:?}"
                ));
            }
            Err(err) => {
                // Rollback on failure.
                for col in columns.write().iter_mut() {
                    if let Some(card) = col.cards.iter_mut().find(|c| c.id == strand_id) {
                        card.lifecycle = prior_state;
                        break;
                    }
                }
                board_status.set(format!("{kind} failed: {}", err.display()));
            }
        }
    });
}

/// Locate `card_id` in `from_column`, remove it, re-insert into
/// `target_column` such that the resulting column is sorted by `rank`
/// (we keep it lexicographically sorted on the assumption every card
/// has a valid rank). Returns the relocated card or `None` if the
/// source isn't found.
pub(super) fn relocate_card(
    columns: &mut [KanbanColumn],
    card_id: &str,
    from_column_id: &str,
    target_column_id: &str,
    new_rank: &str,
) -> Option<KanbanCard> {
    let source_idx = columns.iter().position(|c| c.id == from_column_id)?;
    let card_idx = columns[source_idx]
        .cards
        .iter()
        .position(|c| c.id == card_id)?;
    let mut card = columns[source_idx].cards.remove(card_idx);
    card.rank = new_rank.to_owned();
    card.state = CardState::Queued;
    let target_idx = columns
        .iter()
        .position(|c| c.id == target_column_id)
        .or(Some(source_idx))?;
    let insert_idx = columns[target_idx]
        .cards
        .iter()
        .position(|c| c.rank.as_str() > new_rank)
        .unwrap_or(columns[target_idx].cards.len());
    columns[target_idx].cards.insert(insert_idx, card.clone());
    Some(card)
}

pub(super) fn set_card_state_in_columns(
    columns: &mut Signal<Vec<KanbanColumn>>,
    card_id: &str,
    state: CardState,
) {
    for column in columns.write().iter_mut() {
        if let Some(card) = column.cards.iter_mut().find(|card| card.id == card_id) {
            card.state = state;
            break;
        }
    }
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
    columns: Signal<Vec<KanbanColumn>>,
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
        columns,
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
    mut columns: Signal<Vec<KanbanColumn>>,
    mut state_store: Signal<LocalStateStore>,
    mut write_records: Signal<Vec<BoardWriteRecord>>,
    mut board_status: Signal<String>,
) {
    let hlc = Hlc::now("yougen").to_string();
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
        Ok(builder) => builder.build("yougen"),
        Err(err) => {
            board_status.set(format!("cannot submit {kind}: {err:#}"));
            return;
        }
    };
    let move_id = envelope.local_operation_id().to_owned();
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
            format!("submitting {kind} via ck.self.events.command.submit")
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
    spawn(async move {
        let submit_result = with_authed_api(&base_url, api_token, |api| async move {
            api.submit_event_envelope(&envelope).await
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
                set_card_state_in_columns(&mut columns, &strand_id, CardState::Accepted);
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
                set_card_state_in_columns(&mut columns, &strand_id, card_state);
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
                        columns,
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
                    set_card_state_in_columns(&mut columns, &strand_id, CardState::Quarantined);
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
/// Spec ([operations-sync.md §8](../../cokret-spec/spec/v1/zh/sync/operations-sync.md)):
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
    columns: Signal<Vec<KanbanColumn>>,
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
        let new_expected = match with_authed_api(&base_url, token(), |api| async move {
            api.collection_projection(&view_for_projection).await
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
        // classifiers. Anything else falls through to ck.strand.move
        // because that's the spec wire shape for drag operations.
        let kind_static: &'static str = match kind.as_str() {
            "ck.strand.reorder" => "ck.strand.reorder",
            "ck.strand.move" => "ck.strand.move",
            _ => "ck.strand.move",
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
            columns,
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
    projection: &crate::api::CollectionProjectionView,
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

/// Marks the first queued / soft-failed write as Quarantined. Event
/// submit is the only write surface now, and a failed event needs the UI
/// to reconstruct the equivalent envelope (TODO: wire that through
/// ck_ops::strand_position_*) rather than replay stale bytes.
pub(super) fn replay_first_move(
    _base_url: String,
    _token: Signal<String>,
    mut write_records: Signal<Vec<BoardWriteRecord>>,
    mut board_status: Signal<String>,
) {
    let Some(idx) = write_records.read().iter().position(|record| {
        record.state == CardState::Queued
            || record.state == CardState::SoftFailed
            || record.state == CardState::Conflict
    }) else {
        board_status.set("no queued write to replay".to_owned());
        return;
    };
    if let Some(record) = write_records.write().get_mut(idx) {
        record.state = CardState::Quarantined;
        record.note =
            "replay via ck.self.events.command.submit not yet wired; quarantining for manual review"
                .to_owned();
    }
    board_status.set(
        "replay not available — write quarantined (TODO: rebuild ck.strand.update envelope)"
            .to_owned(),
    );
}
