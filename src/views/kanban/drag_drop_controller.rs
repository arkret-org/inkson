//! Drag/drop command controller for optimistic board moves and retries.

use arkret_wire::event_kind_str;
use serde::Serialize;

use super::*;

fn current_cell_basis_from_store(
    state_store: &LocalStateStore,
    realm_id: &str,
    family: &str,
    subject: &str,
    missing_witness_family: Option<&str>,
) -> Result<Vec<arkret_sdk::Hash>, String> {
    let entries = state_store
        .realm_tree_projection(realm_id)
        .and_then(|projection| projection.get("current").cloned())
        .and_then(|value| serde_json::from_value::<arkret_sdk::CurrentEntries>(value).ok())
        .map(|current| current.entries)
        .ok_or_else(|| "canonical current state is still loading".to_owned())?;
    let cell = format!("ak:cell:{family}:{subject}");
    match current_register_basis(&entries, &cell) {
        CurrentRegisterBasis::Heads(refs) => Ok(refs),
        CurrentRegisterBasis::Removed => Ok(Vec::new()),
        CurrentRegisterBasis::Missing
            if missing_witness_family.is_some_and(|witness_family| {
                let witness = format!("ak:cell:{witness_family}:{subject}");
                !matches!(
                    current_register_basis(&entries, &witness),
                    CurrentRegisterBasis::Missing | CurrentRegisterBasis::Unavailable
                )
            }) =>
        {
            Ok(Vec::new())
        }
        CurrentRegisterBasis::Missing => Err("canonical current cell is still loading".to_owned()),
        CurrentRegisterBasis::Unavailable => {
            Err("canonical current cell is unavailable".to_owned())
        }
    }
}
// Imports the drag-and-drop helpers relied on while they lived in the
// monolithic `kanban/mod.rs`; re-added here after the structural split since
// the component-only parent no longer brings them into scope.
use crate::move_builder::{
    StrandPositionEffect, StrandPositionExpectation, strand_position_cell_id,
};
use crate::rank::RankError;
use crate::state::MoveSubmissionState;

/// Closed set of operation bodies `submit_kanban_operation_event` enqueues:
/// board (container Space) creation and list patches (column order, rename).
///
/// Reading the erased payload back through its typed marker keeps the queued
/// record's `body` a closed discriminated shape instead of an open JSON map.
#[derive(Serialize)]
#[serde(untagged)]
enum QueuedSpaceOperationBody {
    Create(Box<arkret_sdk::SpaceCreatePayload>),
    Update(arkret_sdk::SpacePatchPayload),
}

/// Queued op-log record written by `submit_kanban_operation_event`; field
/// order matches the wire layout the previous `json!` literal produced.
#[derive(Serialize)]
struct QueuedSpaceOperationRecord<'a> {
    kind: arkret_sdk::EventKind,
    operation_id: &'a str,
    actor_id: &'a str,
    created_at: &'a str,
    write_state: &'static str,
    body: QueuedSpaceOperationBody,
    local_target_ref: &'a str,
}

fn queued_space_operation_body(
    operation: &crate::operation::LocalOperation,
) -> anyhow::Result<QueuedSpaceOperationBody> {
    Ok(match operation.kind() {
        arkret_sdk::EventKind::SpaceCreate => QueuedSpaceOperationBody::Create(Box::new(
            operation.typed_payload::<arkret_wire::event_spec::SpaceCreate>()?,
        )),
        arkret_sdk::EventKind::SpaceUpdate => QueuedSpaceOperationBody::Update(
            operation.typed_payload::<arkret_wire::event_spec::SpaceUpdate>()?,
        ),
        other => anyhow::bail!("unsupported queued space operation kind {}", other.as_str()),
    })
}

/// Queued op-log record written by `submit_kanban_card_create`.
///
/// `body` is the ONLY part of this row that ever reaches the wire, and it is
/// the typed `ak.strand.create` payload — which carries no placement. `cell`
/// and `effect` are holder-local columns of the durable op log: they name the
/// position cell this write is heading for and remember the column the user
/// dropped the card into, so the board can render the card during the round
/// trip and so the follow-up `ak.strand.move` has its target. Neither is ever
/// copied into a payload; `strand.schema.json` forbids `board_space_id` /
/// `list_space_id` / `rank` on a Strand, and placement has exactly one command
/// surface, `ak.strand.move` / `ak.strand.reorder`.
#[derive(Serialize)]
struct QueuedCardCreateRecord<'a> {
    kind: &'static str,
    operation_id: &'a str,
    actor_id: &'a str,
    created_at: String,
    cell: String,
    effect: serde_json::Value,
    wire_kind: &'a str,
    body: arkret_sdk::StrandCreatePayload,
    local_target_ref: &'a str,
    write_state: &'static str,
}

/// Closed set of lifecycle bodies: Space container archive/restore and
/// Strand archive/restore.
#[derive(Serialize)]
#[serde(untagged)]
enum QueuedLifecycleBody {
    Space(arkret_sdk::SpaceStateTransitionPayload),
    Strand(arkret_sdk::ObjectLifecyclePayload),
}

/// Queued op-log record written by the lifecycle dispatchers and the board
/// archive cascade.
#[derive(Serialize)]
struct QueuedLifecycleRecord<'a> {
    kind: arkret_sdk::EventKind,
    operation_id: &'a str,
    actor_id: &'a str,
    created_at: String,
    write_state: &'static str,
    body: QueuedLifecycleBody,
}

fn queued_lifecycle_record(
    event: &crate::operation::LocalOperation,
    actor_id: &str,
) -> anyhow::Result<serde_json::Value> {
    let body = match event.kind() {
        arkret_sdk::EventKind::SpaceArchive => QueuedLifecycleBody::Space(
            event.typed_payload::<arkret_wire::event_spec::SpaceArchive>()?,
        ),
        arkret_sdk::EventKind::SpaceRestore => QueuedLifecycleBody::Space(
            event.typed_payload::<arkret_wire::event_spec::SpaceRestore>()?,
        ),
        arkret_sdk::EventKind::StrandArchive => QueuedLifecycleBody::Strand(
            event.typed_payload::<arkret_wire::event_spec::StrandArchive>()?,
        ),
        arkret_sdk::EventKind::StrandRestore => QueuedLifecycleBody::Strand(
            event.typed_payload::<arkret_wire::event_spec::StrandRestore>()?,
        ),
        other => anyhow::bail!("unsupported lifecycle operation kind {}", other.as_str()),
    };
    let operation_id = event.local_operation_id().to_string();
    Ok(serde_json::to_value(QueuedLifecycleRecord {
        kind: event.kind().clone(),
        operation_id: &operation_id,
        actor_id,
        created_at: arkret_sdk::canonical::format_timestamp_canonical(event.created_at()),
        write_state: "queued",
        body,
    })?)
}

/// Closed set of bodies for a queued strand-position update.
#[derive(Serialize)]
#[serde(untagged)]
enum QueuedStrandPositionBody {
    Move(arkret_sdk::StrandMovePayload),
    Reorder(arkret_sdk::StrandReorderPayload),
}

/// Queued op-log record written by `submit_strand_position_move`.
#[derive(Serialize)]
struct QueuedStrandPositionRecord<'a> {
    kind: &'static str,
    move_id: &'a str,
    cell: String,
    board_space_id: &'a str,
    strand_id: &'a str,
    expected_position: serde_json::Value,
    target_position: serde_json::Value,
    body: QueuedStrandPositionBody,
    write_state: &'static str,
}

fn queued_strand_position_body(
    event: &crate::operation::LocalOperation,
    kind: &str,
) -> anyhow::Result<QueuedStrandPositionBody> {
    if kind == event_kind_str::STRAND_MOVE {
        Ok(QueuedStrandPositionBody::Move(
            event.typed_payload::<arkret_wire::event_spec::StrandMove>()?,
        ))
    } else if kind == event_kind_str::STRAND_REORDER {
        Ok(QueuedStrandPositionBody::Reorder(
            event.typed_payload::<arkret_wire::event_spec::StrandReorder>()?,
        ))
    } else {
        anyhow::bail!("unsupported strand position kind {kind}")
    }
}

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
    let body = match queued_space_operation_body(&operation) {
        Ok(body) => body,
        Err(err) => {
            board_status.set(format!("cannot queue {kind} operation: {err:#}"));
            return;
        }
    };
    {
        let mut store = state_store.write();
        let record = match serde_json::to_value(QueuedSpaceOperationRecord {
            kind: operation.kind().clone(),
            operation_id: &operation_id,
            actor_id: &actor_id,
            created_at: &created_at,
            write_state: "queued",
            body,
            // A create names its object only once accepted, so until then the
            // record keys it by the write's holder-local handle.
            local_target_ref: operation.local_object_handle(),
        }) {
            Ok(record) => record,
            Err(err) => {
                board_status.set(format!("cannot queue {kind} operation: {err}"));
                return;
            }
        };
        // The holder-local operation id is the durable retry key. Upsert it
        // instead of appending a second optimistic row so a failed create can
        // return to `queued` and be driven again without duplicating a Board.
        store.upsert_raw_operation(operation_id.clone(), Some(realm_id), record);
    }
    board_status.set(format!(
        "submitting {kind} operation {}",
        short_protocol_id(&operation_id)
    ));
    let api_token = token();
    let operation_id_for_status = operation_id.clone();
    let operation_id_for_reconcile = operation_id.clone();
    // `spawn_forever` executes at the Dioxus root and therefore has no current
    // component scope from which `EventSubmitter::from_current_session` can
    // consume SessionContext. Carry the governance store explicitly across
    // that lifetime boundary; otherwise a perfectly pinned checkpoint is
    // reported as absent before the Event ever reaches the durable queue.
    let submit_state_store = crate::app::runtime_adapter::state_store_handle(state_store);
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
        let result = with_authed_api(&base_url, api_token.clone(), |api| async move {
            api.event_submitter()?
                .with_state_store(submit_state_store)
                .submit_sdk_event(&operation)
                .await
        })
        .await;
        match result {
            Ok(resp) => {
                // `build_sdk_event` names an event-derived create from its
                // draft Event id. Final authoring attaches actor-chain/HLC/CBS
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
                let error = err.display().to_string();
                state_store.write().update_raw_operation_write_state(
                    &operation_id_for_reconcile,
                    "failed",
                    None,
                    Some(error.clone()),
                );
                tracing::warn!(
                    operation_id = %short_protocol_id(&operation_id_for_status),
                    kind = %kind,
                    error,
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
    // Reordering rewrites every List's rank. Do not emit a partial reorder
    // while any List still has only its holder-local create handle.
    if updates
        .iter()
        .any(|(column_id, _)| arkret_sdk::SpaceId::new(column_id.clone()).is_err())
    {
        board_status.set("Wait for all lists to finish creating before reordering.".to_owned());
        return;
    }
    let update_count = updates.len();
    board_status.set(format!(
        "Column order sending... ({update_count} rank updates)"
    ));
    for (column_id, rank) in updates {
        let basis_refs = match current_cell_basis_from_store(
            &state_store.read(),
            &realm_id,
            "ak.component.space.metadata.v1",
            &column_id,
            None,
        ) {
            Ok(refs) => refs,
            Err(error) => {
                board_status.set(format!("Column order blocked: {error}"));
                return;
            }
        };
        let op = match crate::operation::ak_ops::space_update_patch(
            &realm_id,
            &actor_id,
            &column_id,
            json!({ "rank": rank }),
        ) {
            Ok(builder) => match builder.causal_refs(basis_refs).build_sdk_event("inkson") {
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
    let basis_refs = match current_cell_basis_from_store(
        &state_store.read(),
        &realm_id,
        "ak.component.space.metadata.v1",
        &column_id,
        None,
    ) {
        Ok(refs) => refs,
        Err(error) => {
            board_status.set(format!("List rename blocked: {error}"));
            return;
        }
    };
    let op = match crate::operation::ak_ops::space_update_patch(
        &realm_id,
        &actor_id,
        &column_id,
        json!({ "title": title }),
    ) {
        Ok(builder) => match builder.causal_refs(basis_refs).build_sdk_event("inkson") {
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

#[allow(clippy::too_many_arguments)]
pub(super) fn submit_space_metadata_resolution(
    base_url: String,
    token: Signal<String>,
    realm_id: String,
    actor_id: String,
    column_id: String,
    title: String,
    rank: String,
    basis_refs: Vec<arkret_sdk::Hash>,
    scope_security_encrypted: Option<bool>,
    state_store: SyncSignal<LocalStateStore>,
    board_status: Signal<String>,
) {
    let builder = match crate::operation::ak_ops::space_update_patch(
        &realm_id,
        &actor_id,
        &column_id,
        json!({ "title": title, "rank": rank }),
    ) {
        Ok(builder) => builder,
        Err(error) => {
            let mut status = board_status;
            status.set(format!("List conflict resolution failed: {error:#}"));
            return;
        }
    };
    let operation = match builder.causal_refs(basis_refs).build_sdk_event("inkson") {
        Ok(operation) => operation,
        Err(error) => {
            let mut status = board_status;
            status.set(format!("List conflict resolution failed: {error}"));
            return;
        }
    };
    submit_kanban_operation_event(
        base_url,
        token,
        realm_id,
        operation,
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
    if actor_id.trim().is_empty() {
        board_status.set("sign in before updating cards".to_owned());
        return;
    }
    // realm-and-space.md §3.6 types the placement's List reference as
    // `id:space`. A List whose create has not been accepted yet is still keyed
    // by its holder-local operation handle, and that handle is not a Space id:
    // signing it into the envelope would put a fabricated reference on the
    // wire, which the server can only reject or store unreadably. Hold the
    // create until the List receipt lands, exactly as the add-list action holds
    // for the Board receipt.
    if arkret_sdk::SpaceId::new(command.board_space_id.as_str()).is_err()
        || arkret_sdk::SpaceId::new(command.list_space_id.as_str()).is_err()
    {
        board_status.set(
            "This list is still being created; add cards after server confirmation.".to_owned(),
        );
        return;
    }
    if command.rank.is_empty()
        || command.rank.len() > 128
        || !command
            .rank
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric())
    {
        board_status.set("cannot submit card: invalid position rank".to_owned());
        return;
    }
    let envelope =
        crate::operation::ak_ops::kanban_card_strand_create(&realm_id, &actor_id, &command.title);
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
    // Holder-local `effect` (see [`QueuedCardCreateRecord`]): the intended
    // placement, kept beside the queued write so the board can show the card
    // before the follow-up `ak.strand.move` is authored. It is never serialized
    // into the create payload.
    let effect = json!({
        "board_space_id": command.board_space_id,
        "list_space_id": command.list_space_id,
        "title": command.title,
        "rank": command.rank,
        "strand_kind": "card",
        "strand_id": subject,
    });
    let op_id = event.local_operation_id().to_string();
    let body = match event.typed_payload::<arkret_wire::event_spec::StrandCreate>() {
        Ok(body) => body,
        Err(err) => {
            board_status.set(format!("cannot queue card create: {err:#}"));
            return;
        }
    };
    let record = match serde_json::to_value(QueuedCardCreateRecord {
        kind,
        operation_id: &op_id,
        actor_id: &actor_id,
        created_at: arkret_sdk::canonical::format_timestamp_canonical(event.created_at()),
        cell: cell_id,
        effect,
        wire_kind: &wire_kind,
        body,
        // A create payload carries no object id, so the record has to say
        // which handle this write's object is keyed by until the accepted
        // Event names it.
        local_target_ref: &subject,
        write_state: "queued",
    }) {
        Ok(record) => record,
        Err(err) => {
            board_status.set(format!("cannot queue card create: {err}"));
            return;
        }
    };
    // Persist the optimistic create before starting the request. The user can
    // open this card immediately, which changes the route and may unmount the
    // Kanban component before a component-scoped projector effect gets a turn.
    // A durable row is also the reconciliation target for the detached submit
    // task below, so neither projection nor receipt handling depends on the
    // lifetime of this event-handler scope.
    state_store
        .write()
        .upsert_raw_operation(op_id.clone(), Some(realm_id.clone()), record);
    board_status.set(format!(
        "submitting {wire_kind} event {}",
        short_protocol_id(&op_id)
    ));
    let api_token = token();
    let realm_for_record = realm_id.clone();
    let board_for_position = command.board_space_id.clone();
    let list_for_position = command.list_space_id.clone();
    let rank_for_position = command.rank.clone();
    let actor_for_position = actor_id.clone();
    let kind_for_record = kind.to_owned();
    let op_for_track = op_id.clone();
    let submit_event = event;
    // Opening the optimistic card changes `/board/<id>` to
    // `/board/<id>/task/<local-id>`. A normal `spawn` is owned by the current
    // Kanban scope and is cancelled when that route transition unmounts it. In
    // the failure window the POST can already be accepted while the response
    // is never reconciled, leaving the local UUID permanently queued. Keep the
    // request at the root and capture only the app-owned state store across the
    // await; component-owned Signals such as `board_status` must not cross this
    // lifetime boundary.
    let submit_state_store = crate::app::runtime_adapter::state_store_handle(state_store);
    dioxus::core::spawn_forever(async move {
        let result = with_authed_api(&base_url, api_token.clone(), |api| async move {
            api.event_submitter()?
                .with_state_store(submit_state_store)
                .submit_sdk_event(&submit_event)
                .await
        })
        .await;
        match result {
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
                    realm_for_record.clone(),
                    kind_for_record.clone(),
                    state,
                    None,
                    None,
                );
                tracing::debug!(
                    operation_id = %short_protocol_id(&op_for_track),
                    event_id = %short_protocol_id(&resp.event_id),
                    kind = %kind_for_record,
                    "detached kanban card create accepted"
                );

                let accepted_event_id = match arkret_sdk::EventId::new(resp.event_id.clone()) {
                    Ok(event_id) => event_id,
                    Err(error) => {
                        tracing::error!(%error, "accepted card create returned an invalid Event id");
                        return;
                    }
                };
                let strand_id =
                    arkret_sdk::StrandId::from_event_id(&accepted_event_id).into_string();
                let move_event = match crate::operation::ak_ops::strand_position_update(
                    &realm_for_record,
                    &actor_for_position,
                    event_kind_str::STRAND_MOVE,
                    &board_for_position,
                    &strand_id,
                    serde_json::Value::Null,
                    json!({"list_space_id": list_for_position, "rank": rank_for_position}),
                )
                .and_then(|builder| builder.build_sdk_event("inkson"))
                {
                    Ok(event) => event,
                    Err(error) => {
                        tracing::error!(%error, %strand_id, "card created without placement; move authoring failed");
                        return;
                    }
                };
                let move_id = move_event.local_operation_id().to_string();
                let move_body = match queued_strand_position_body(
                    &move_event,
                    event_kind_str::STRAND_MOVE,
                ) {
                    Ok(body) => body,
                    Err(error) => {
                        tracing::error!(%error, %strand_id, "card created without placement; move payload failed");
                        return;
                    }
                };
                let move_record = match serde_json::to_value(QueuedStrandPositionRecord {
                    kind: event_kind_str::STRAND_MOVE,
                    move_id: &move_id,
                    cell: strand_position_cell_id(&board_for_position, &strand_id),
                    board_space_id: &board_for_position,
                    strand_id: &strand_id,
                    expected_position: serde_json::Value::Null,
                    target_position: json!({"space_id": list_for_position, "rank": rank_for_position}),
                    body: move_body,
                    write_state: "submitted",
                }) {
                    Ok(record) => record,
                    Err(error) => {
                        tracing::error!(%error, %strand_id, "card created without placement; move queue encoding failed");
                        return;
                    }
                };
                state_store.write().enqueue_local_projection_command(
                    move_id.clone(),
                    Some(realm_for_record.clone()),
                    move_record,
                );
                let move_submit_state_store =
                    crate::app::runtime_adapter::state_store_handle(state_store);
                let move_result = with_authed_api(&base_url, api_token, |api| async move {
                    api.event_submitter()?
                        .with_state_store(move_submit_state_store)
                        .submit_sdk_event(&move_event)
                        .await
                })
                .await;
                match move_result {
                    Ok(move_response) => {
                        state_store.write().update_raw_operation_write_state(
                            &move_id,
                            "accepted",
                            Some(move_response.event_id.clone()),
                            None,
                        );
                        state_store.write().record_move_submission_with_event_id(
                            move_id.clone(),
                            Some(move_response.event_id),
                            realm_for_record,
                            event_kind_str::STRAND_MOVE.to_owned(),
                            MoveSubmissionState::from_submit_state("accepted", None),
                            None,
                            None,
                        );
                    }
                    Err(error) => {
                        let error = error.display().to_string();
                        state_store.write().update_raw_operation_write_state(
                            &move_id,
                            "soft_failed",
                            None,
                            Some(error.clone()),
                        );
                        tracing::warn!(%error, %strand_id, "card create accepted; placement move remains retryable");
                    }
                }
            }
            Err(err) => {
                let error = err.display().to_string();
                tracing::warn!(
                    operation_id = %short_protocol_id(&op_for_track),
                    kind = %kind_for_record,
                    error,
                    "kanban submit failed; card quarantined",
                );
                state_store.write().update_raw_operation_write_state(
                    &op_for_track,
                    "quarantined",
                    None,
                    Some(error),
                );
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
/// pending state, and submits an Event whose causal refs cover the observed
/// position frontier.
///
/// Spec mapping ([views.md §2.6](../../arkret-spec/spec/v1/zh/models/views.md)):
///
/// - Cross-column drop ⇒ `ak.strand.move` Event kind.
/// - Same-column drop ⇒ `ak.strand.reorder`.
/// - Both compile to the same `ak:cell:ak.component.strand.position.v1:<board>:<strand>`
///   causal-register cell; the difference is whether `effect.list_space_id` equals
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
    if dragged.position_basis_refs.is_empty() {
        board_status.set("Card position is not current yet; refresh before moving it.".to_owned());
        return;
    }
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
    // `submit_strand_position_move` appends the canonical move/reorder op to
    // `raw_operations`; the current position result remains authoritative, so
    // the UI does not claim a settled destination until sync observes it.
    let expected = if dragged.position_basis_refs.len() == 1 {
        StrandPositionExpectation::At {
            list_space_id: dragged.from_column_id.clone(),
            rank: dragged.from_rank.clone(),
            head_ref: dragged.position_basis_refs[0].clone(),
        }
    } else {
        StrandPositionExpectation::Conflict {
            head_refs: dragged.position_basis_refs.clone(),
        }
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
    submit_strand_position_move(
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
    let lifecycle_basis_refs = match current_cell_basis_from_store(
        &state_store.read(),
        &realm_id,
        "ak.component.space.lifecycle.v1",
        &space_container_id,
        Some("ak.component.space.metadata.v1"),
    ) {
        Ok(refs) => refs,
        Err(error) => {
            board_status.set(format!("lifecycle update blocked: {error}"));
            return;
        }
    };
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
        SpaceContainerLifecycleState::Conflict
        | SpaceContainerLifecycleState::Unavailable
        | SpaceContainerLifecycleState::PositionConflict => {
            board_status
                .set("lifecycle update failed: canonical Space state is unresolved".to_owned());
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
    let event = match builder
        .causal_refs(lifecycle_basis_refs)
        .build_sdk_event("inkson")
    {
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
    let record = match queued_lifecycle_record(&event, &actor_id) {
        Ok(record) => record,
        Err(err) => {
            board_status.set(format!("lifecycle update failed: {err:#}"));
            return;
        }
    };
    state_store.write().enqueue_local_projection_command(
        operation_id.clone(),
        Some(realm_id.clone()),
        record,
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
    lifecycle_basis_refs: Vec<arkret_sdk::Hash>,
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
        StrandLifecycleState::Redacted
        | StrandLifecycleState::Conflict
        | StrandLifecycleState::Unavailable => {
            board_status
                .set("lifecycle update failed: target state is not dispatchable".to_owned());
            return;
        }
    };
    let event = match builder
        .map(|builder| builder.causal_refs(lifecycle_basis_refs))
        .and_then(|builder| builder.build_sdk_event("inkson"))
    {
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
    let record = match queued_lifecycle_record(&event, &actor_id) {
        Ok(record) => record,
        Err(err) => {
            board_status.set(format!("lifecycle update failed: {err:#}"));
            return;
        }
    };
    state_store.write().enqueue_local_projection_command(
        operation_id.clone(),
        Some(realm_id.clone()),
        record,
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
    projected_columns: Vec<KanbanColumn>,
    mut state_store: SyncSignal<LocalStateStore>,
    mut board_status: Signal<String>,
) {
    if board_space_id.trim().is_empty() {
        board_status.set("select a Board Space before archiving the board".to_owned());
        return;
    }

    // Resolve children from the same merged current-object/Event projection
    // the user is looking at. A later joiner may not possess the historical
    // create Events, so consulting the raw Event log alone would omit visible
    // pre-join cards and lists from the cascade.
    let active_cards: Vec<(String, Vec<arkret_sdk::Hash>)> = projected_columns
        .iter()
        .flat_map(|column| column.cards.iter())
        .filter(|card| card.lifecycle == StrandLifecycleState::Active)
        .map(|card| {
            (
                card.primary_strand_id.clone(),
                card.lifecycle_basis_refs.clone(),
            )
        })
        .collect();
    let active_list_ids: Vec<String> = projected_columns
        .iter()
        .filter(|column| column.state == SpaceContainerLifecycleState::Active)
        .map(|column| column.id.clone())
        .collect();

    // Build every archive event up front so a build error aborts before any
    // optimistic op is appended.
    let mut events: Vec<crate::operation::LocalOperation> = Vec::new();
    for (strand_id, lifecycle_basis_refs) in &active_cards {
        match crate::operation::ak_ops::strand_archive(&realm_id, &actor_id, strand_id)
            .map(|builder| builder.causal_refs(lifecycle_basis_refs.clone()))
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
        let lifecycle_basis_refs = match current_cell_basis_from_store(
            &state_store.read(),
            &realm_id,
            "ak.component.space.lifecycle.v1",
            list_id,
            Some("ak.component.space.metadata.v1"),
        ) {
            Ok(refs) => refs,
            Err(error) => {
                board_status.set(format!("cannot archive board: {error}"));
                return;
            }
        };
        match crate::operation::ak_ops::realm_archive(&realm_id, &actor_id, list_id)
            .map(|builder| builder.causal_refs(lifecycle_basis_refs))
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
    // Serialize every queued record up front so a typing failure aborts
    // before any optimistic op is appended.
    let mut records: Vec<serde_json::Value> = Vec::with_capacity(events.len());
    for event in &events {
        match queued_lifecycle_record(event, &actor_id) {
            Ok(record) => records.push(record),
            Err(err) => {
                board_status.set(format!("cannot archive board: {err:#}"));
                return;
            }
        }
    }
    let operation_ids: Vec<String> = {
        let mut store = state_store.write();
        events
            .iter()
            .zip(records)
            .map(|(event, record)| {
                let operation_id = event.local_operation_id().to_string();
                store.enqueue_local_projection_command(
                    operation_id.clone(),
                    Some(realm_id.clone()),
                    record,
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

/// Build, sign, and submit an ordinary causal `ak.strand.move` or
/// `ak.strand.reorder` Event.
#[allow(clippy::too_many_arguments)]
pub(super) fn submit_strand_position_move(
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
    if actor_id.trim().is_empty() {
        board_status.set("sign in before moving cards".to_owned());
        return;
    }
    let expected_json = match &expected {
        StrandPositionExpectation::Initial => serde_json::Value::Null,
        StrandPositionExpectation::At {
            list_space_id,
            rank,
            ..
        } => {
            json!({"list_space_id": list_space_id, "rank": rank})
        }
        StrandPositionExpectation::Conflict { .. } => serde_json::Value::Null,
    };
    let causal_refs = expected.causal_refs();
    let effect_json = match &effect {
        StrandPositionEffect::SetPosition {
            list_space_id,
            rank,
        } => {
            json!({"list_space_id": list_space_id, "rank": rank})
        }
        StrandPositionEffect::Remove => serde_json::Value::Null,
    };
    let envelope = match crate::operation::ak_ops::strand_position_update(
        &realm_id,
        &actor_id,
        kind,
        &board_space_id,
        &strand_id,
        expected_json.clone(),
        effect_json.clone(),
    ) {
        Ok(builder) => builder.causal_refs(causal_refs).build_sdk_event("inkson"),
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
    let body = match queued_strand_position_body(&event, kind) {
        Ok(body) => body,
        Err(err) => {
            board_status.set(format!("cannot submit {kind}: {err:#}"));
            return;
        }
    };
    let record = match serde_json::to_value(QueuedStrandPositionRecord {
        kind,
        move_id: &move_id,
        cell: cell_id,
        board_space_id: &board_space_id,
        strand_id: &strand_id,
        expected_position: match &expected {
            StrandPositionExpectation::Initial => serde_json::Value::Null,
            StrandPositionExpectation::At {
                list_space_id,
                rank,
                ..
            } => json!({"space_id": list_space_id, "rank": rank}),
            StrandPositionExpectation::Conflict { .. } => serde_json::Value::Null,
        },
        target_position: match &effect {
            StrandPositionEffect::SetPosition {
                list_space_id,
                rank,
            } => json!({"space_id": list_space_id, "rank": rank}),
            StrandPositionEffect::Remove => serde_json::Value::Null,
        },
        // Canonical move/reorder payload retained in the durable local op log.
        // The Board may use it as a discovery overlay, but canonical current
        // position always replaces its lossy arrival-ordered placement.
        body,
        write_state: "submitted",
    }) {
        Ok(record) => record,
        Err(err) => {
            board_status.set(format!("cannot submit {kind}: {err}"));
            return;
        }
    };
    state_store.write().enqueue_local_projection_command(
        move_id.clone(),
        Some(realm_id.clone()),
        record,
    );
    board_status.set(format!(
        "submitting {kind} event {}",
        short_protocol_id(&move_id)
    ));
    let api_token = token();
    let move_for_track = move_id.clone();
    let kind_for_record = kind.to_owned();
    let realm_for_record = realm_id.clone();
    let submit_event = event;
    spawn(async move {
        let submit_result = with_authed_api(&base_url, api_token, |api| async move {
            api.event_submitter()?.submit_sdk_event(&submit_event).await
        })
        .await;
        match submit_result {
            Ok(resp) => {
                // events.submit accepted path: the ordinary Event is durable.
                // The canonical current result decides whether it is the sole
                // position head or remains concurrent with another write.
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
                    None,
                );
                board_status.set(format!(
                    "{kind_for_record} event {} accepted by server; awaiting current projection (event_id={})",
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
