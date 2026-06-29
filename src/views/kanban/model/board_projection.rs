//! Event-sourced kanban board projection (spec
//! `cotask/specs/active/2026-06-29-kanban-event-sourced-projection.md`).
//!
//! The board is a CLIENT-SIDE derived projection over the realm event log, per
//! `service-surface.md` §("View projection 是派生结果、不是真相源；客户端应基于
//! 已同步、已授权、已解密的 Event 集合自维护本地投影"). This module folds the
//! realm's kanban events — `ck.space.create`, `ck.strand.create`,
//! `ck.strand.update`, `ck.strand.move` / `ck.strand.reorder`,
//! `ck.strand.archive` / `ck.strand.restore`, `ck.relation.*` — into the same
//! [`KanbanColumn`] shape the renderer consumes, WITHOUT depending on the
//! per-session server projection endpoints (which are visibility-filtered and,
//! for E2EE realms, cannot carry decrypted content).
//!
//! Why event-sourced: the server's `list_strand_projections` is filtered
//! per-session and never carries another member's card content for an encrypted
//! realm, whereas the durable event log (reachable via `backfill` /
//! `events/subscribe`) carries every member's events. Folding the log
//! client-side is the only spec-correct way to show cross-member cards.
//!
//! Reuse boundary: this module folds CREATE + MOVE/REORDER + ARCHIVE (placement
//! and lifecycle, which decide which column a card lands in). Content UPDATES
//! (title / summary / body / fields) and ASSIGNMENTS are layered by the
//! existing, decryption-aware overlays ([`overlay_local_card_update_records`],
//! [`overlay_local_card_assignment_records`]) so we do not duplicate the
//! private-field decrypt logic.

use super::*;

/// Every kanban-relevant event kind the client folds into the board.
pub(crate) const KANBAN_EVENT_KINDS: &[&str] = &[
    "ck.space.create",
    "ck.strand.create",
    "ck.strand.update",
    "ck.strand.move",
    "ck.strand.reorder",
    "ck.strand.archive",
    "ck.strand.restore",
    "ck.relation.create",
    "ck.relation.tombstone",
];

/// Normalize a batch of canonical realm events (from `backfill` /
/// `events/subscribe`) into [`RawOperationRecord`]s for EVERY kanban-relevant
/// kind — the single ingest funnel that replaces the old per-kind extractors
/// (`strand_update_operations_from_events` only saw updates,
/// `space_create_operations_from_events` only saw space-creates; remote
/// `ck.strand.create` had no recovery path).
pub(crate) fn kanban_operations_from_events(events: &[Value]) -> Vec<RawOperationRecord> {
    events
        .iter()
        .filter_map(kanban_operation_from_event)
        .collect()
}

fn kanban_operation_from_event(event: &Value) -> Option<RawOperationRecord> {
    let kind = json_path_string(Some(event), &["event_kind"])
        .or_else(|| json_path_string(Some(event), &["kind"]))?;
    if !KANBAN_EVENT_KINDS.contains(&kind.as_str()) {
        return None;
    }
    raw_operation_from_event(event, &kind)
}

/// Causally-ordered view of the operations: by `received_at` (HLC-free fallback)
/// then `operation_id` for determinism. Returns borrows so callers fold without
/// cloning the whole set.
fn ordered_operations(ops: &[RawOperationRecord]) -> Vec<&RawOperationRecord> {
    let mut ordered: Vec<&RawOperationRecord> = ops.iter().collect();
    ordered.sort_by(|left, right| {
        left.received_at
            .cmp(&right.received_at)
            .then_with(|| left.operation_id.cmp(&right.operation_id))
    });
    ordered
}

fn op_kind(record: &RawOperationRecord) -> Option<String> {
    json_path_string(Some(&record.payload), &["kind"])
        .or_else(|| json_path_string(Some(&record.payload), &["wire_kind"]))
}

fn op_body(record: &RawOperationRecord) -> Option<&Value> {
    record
        .payload
        .get("body")
        .or_else(|| record.payload.get("payload"))
}

/// Strand id a move / reorder / archive / restore op targets.
fn op_strand_target_id(record: &RawOperationRecord) -> Option<String> {
    let body = op_body(record);
    json_path_string(body, &["strand_id"])
        .or_else(|| json_path_string(body, &["target_ref"]))
        .or_else(|| json_path_string(body, &["object", "id"]))
        .or_else(|| json_path_string(Some(&record.payload), &["strand_id"]))
        .or_else(|| json_path_string(Some(&record.payload), &["target_ref"]))
}

/// Build the base [`StrandProjectionView`] from a `ck.strand.create` op. Mirrors
/// soland's `apply_strand_create` field extraction (title from
/// `metadata.title`, position from the `ck.component.strand.position.v1`
/// component / `fields`), tolerating both the canonical envelope
/// (`object.metadata.*`) and the local optimistic shape (`object.*`).
fn strand_view_from_create_op(record: &RawOperationRecord) -> Option<crate::api::StrandProjectionView> {
    let body = op_body(record)?;
    let object = body.get("object").unwrap_or(body);
    let metadata = object.get("metadata");
    let object_fields = metadata
        .and_then(|metadata| metadata.get("fields"))
        .or_else(|| object.get("fields"));

    let strand_id = json_path_string(Some(object), &["id"])
        .or_else(|| json_path_string(Some(body), &["strand_id"]))
        .or_else(|| json_path_string(Some(body), &["effect", "strand_id"]))?;

    let metadata_str = |keys: &[&str]| -> Option<String> {
        for key in keys {
            if let Some(value) = metadata
                .and_then(|metadata| json_path_string(Some(metadata), &[key]))
                .or_else(|| json_path_string(Some(object), &[key]))
            {
                return Some(value);
            }
        }
        None
    };

    let title = metadata_str(&["title"]).unwrap_or_else(|| strand_id.clone());
    let summary = metadata_str(&["summary"]);

    let position = strand_position_component(Some(body));
    let field_str = |keys: &[&str]| -> Option<String> {
        for key in keys {
            if let Some(value) = json_path_string(position, &[key])
                .or_else(|| object_fields.and_then(|fields| json_path_string(Some(fields), &[key])))
            {
                return Some(value);
            }
        }
        None
    };
    let board_space_id = field_str(&["board_space_id"]);
    let list_space_id = field_str(&["list_space_id"]);
    let rank = field_str(&["rank"]);

    let fields = object_fields
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    let card_body = object_fields
        .and_then(|fields| fields.get("body"))
        .or_else(|| object.get("body"))
        .cloned();

    let created_by = json_path_string(Some(&record.payload), &["actor_id"])
        .or_else(|| json_path_string(Some(object), &["created_by"]));
    let created_at = json_path_string(Some(&record.payload), &["created_at"])
        .or_else(|| json_path_string(Some(object), &["created_at"]));
    let realm_id = record
        .realm_id
        .clone()
        .or_else(|| json_path_string(Some(object), &["realm_id"]))
        .unwrap_or_default();

    Some(crate::api::StrandProjectionView {
        strand_id,
        realm_id,
        title,
        summary,
        body: card_body,
        board_space_id,
        list_space_id,
        rank,
        assigned_actor_ids: Vec::new(),
        assigned_to_relations: Vec::new(),
        fields,
        state: "active".to_owned(),
        created_by,
        created_at,
        updated_by: None,
        updated_at: None,
    })
}

/// Fold a `ck.strand.move` op (cross-list move; `target_space_id` is the new
/// List Space) into the running view.
fn apply_move_to_view(view: &mut crate::api::StrandProjectionView, record: &RawOperationRecord) {
    let body = op_body(record);
    if let Some(target) = json_path_string(body, &["target_space_id"]) {
        view.list_space_id = Some(target);
    }
    if let Some(board) = json_path_string(body, &["board_space_id"]) {
        view.board_space_id = Some(board);
    }
    if let Some(rank) = json_path_string(body, &["rank"]) {
        view.rank = Some(rank);
    }
}

/// Fold a `ck.strand.reorder` op (same List Space; only `rank` changes) into the
/// running view.
fn apply_reorder_to_view(view: &mut crate::api::StrandProjectionView, record: &RawOperationRecord) {
    let body = op_body(record);
    if let Some(rank) = json_path_string(body, &["rank"]) {
        view.rank = Some(rank);
    }
    if let Some(board) = json_path_string(body, &["board_space_id"]) {
        view.board_space_id = Some(board);
    }
    // `space_id` is the (unchanged) List Space; carry it if the create op never
    // recorded a list (e.g. a reorder observed before the create on this peer).
    if view.list_space_id.is_none()
        && let Some(space_id) = json_path_string(body, &["space_id"])
    {
        view.list_space_id = Some(space_id);
    }
}

/// Reduce the operation stream into the current set of strands. Folds CREATE
/// (base view) + MOVE / REORDER (placement) + ARCHIVE / RESTORE (lifecycle) in
/// causal order; content updates and assignments are layered later at the card
/// level. Archived strands are dropped from the board.
pub(crate) fn strand_views_from_ops(ops: &[RawOperationRecord]) -> Vec<crate::api::StrandProjectionView> {
    // Preserve first-seen (create) order for stable output; placement/sort is
    // applied by `columns_from_lifecycle_projection`.
    let mut order: Vec<String> = Vec::new();
    let mut by_id: std::collections::BTreeMap<String, crate::api::StrandProjectionView> =
        std::collections::BTreeMap::new();

    for record in ordered_operations(ops) {
        if !raw_operation_allows_overlay(&record.payload) {
            continue;
        }
        let Some(kind) = op_kind(record) else {
            continue;
        };
        match kind.as_str() {
            "ck.strand.create" => {
                if let Some(view) = strand_view_from_create_op(record) {
                    if !by_id.contains_key(&view.strand_id) {
                        order.push(view.strand_id.clone());
                    }
                    by_id.insert(view.strand_id.clone(), view);
                }
            }
            "ck.strand.move" => {
                if let Some(id) = op_strand_target_id(record)
                    && let Some(view) = by_id.get_mut(&id)
                {
                    apply_move_to_view(view, record);
                }
            }
            "ck.strand.reorder" => {
                if let Some(id) = op_strand_target_id(record)
                    && let Some(view) = by_id.get_mut(&id)
                {
                    apply_reorder_to_view(view, record);
                }
            }
            "ck.strand.archive" => {
                if let Some(id) = op_strand_target_id(record)
                    && let Some(view) = by_id.get_mut(&id)
                {
                    view.state = "archived".to_owned();
                }
            }
            "ck.strand.restore" => {
                if let Some(id) = op_strand_target_id(record)
                    && let Some(view) = by_id.get_mut(&id)
                {
                    view.state = "active".to_owned();
                }
            }
            _ => {}
        }
    }

    order
        .into_iter()
        .filter_map(|id| by_id.remove(&id))
        .filter(|view| view.state == "active")
        .collect()
}

/// Reduce the operation stream into the current set of space containers
/// (boards + lists). Reuses [`local_space_create_from_raw_operation`] so the
/// extraction matches the optimistic-overlay path exactly.
pub(crate) fn space_container_views_from_ops(
    ops: &[RawOperationRecord],
    realm_id: &str,
) -> Vec<crate::api::SpaceContainerProjectionView> {
    let mut order: Vec<String> = Vec::new();
    let mut by_id: std::collections::BTreeMap<String, crate::api::SpaceContainerProjectionView> =
        std::collections::BTreeMap::new();
    for record in ordered_operations(ops) {
        let Some(local) = local_space_create_from_raw_operation(record) else {
            continue;
        };
        if !local_space_create_matches_realm(&local, realm_id) {
            continue;
        }
        if !by_id.contains_key(&local.id) {
            order.push(local.id.clone());
        }
        by_id.insert(
            local.id.clone(),
            crate::api::SpaceContainerProjectionView {
                space_id: local.id,
                realm_id: local
                    .realm_id
                    .unwrap_or_else(|| trim_realm_id(realm_id)),
                kind: local.kind,
                title: local.title,
                state: "active".to_owned(),
                rank: local.rank,
                parent_space_id: local.parent_space_id,
            },
        );
    }
    order
        .into_iter()
        .filter_map(|id| by_id.remove(&id))
        .collect()
}

/// The single event-sourced board projection. Folds the realm operation stream
/// (remote backfill / subscribe events + local optimistic ops, already
/// deduped by `upsert_raw_operation`) into columns, then layers content updates
/// and assignments via the existing decryption-aware overlays.
pub(crate) fn project_board(
    ops: &[RawOperationRecord],
    preferred_board_id: &str,
    realm_id: &str,
    decrypt_ctx: Option<&MlsDecryptCtx<'_>>,
) -> (Vec<KanbanColumn>, Vec<BoardSpaceOption>, Option<String>) {
    let containers = space_container_views_from_ops(ops, realm_id);
    let strands = strand_views_from_ops(ops);
    let (columns, board_options, board_id) =
        columns_from_lifecycle_projection(&containers, &strands, preferred_board_id, decrypt_ctx);
    let columns = overlay_local_card_update_records(columns, ops, decrypt_ctx);
    let columns = overlay_local_card_assignment_records(columns, ops);
    (columns, board_options, board_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    const REALM: &str = "ck:realm:019f1071-0000-7000-8000-000000000000";
    const BOARD: &str = "ck:space:019f1071-e3e3-75b1-be7e-bdfa1b8f73ff";
    const LIST_A: &str = "ck:space:019f1071-f553-7410-a2c9-53028e995ed3";
    const LIST_B: &str = "ck:space:019f1071-aaaa-7410-a2c9-53028e995ed3";

    fn space_create_event(id: &str, kind: &str, title: &str, parent: Option<&str>) -> Value {
        let mut object = json!({
            "id": id,
            "kind": kind,
            "title": title,
            "realm_id": REALM,
        });
        if let Some(parent) = parent {
            object["parent_space_id"] = json!(parent);
        }
        json!({
            "event_id": format!("ck:event:{id}"),
            "kind": "ck.space.create",
            "realm_id": REALM,
            "actor_id": "did:web:creator.example",
            "created_at": "2026-06-28T00:00:00Z",
            "payload": { "object": object },
        })
    }

    /// Mirrors the real canonical `ck.strand.create` envelope: position lives in
    /// `payload.object.metadata.fields.{board_space_id,list_space_id,rank}`.
    fn strand_create_event(
        id: &str,
        actor: &str,
        title: &str,
        board: &str,
        list: &str,
        rank: &str,
        created_at: &str,
    ) -> Value {
        json!({
            "event_id": format!("ck:event:{id}"),
            "kind": "ck.strand.create",
            "realm_id": REALM,
            "actor_id": actor,
            "created_at": created_at,
            "payload": {
                "object": {
                    "id": id,
                    "schema": "ck.schema.strand.v1",
                    "realm_id": REALM,
                    "created_by": actor,
                    "created_at": created_at,
                    "metadata": {
                        "title": title,
                        "fields": {
                            "rank": rank,
                            "strand_kind": "card",
                            "board_space_id": board,
                            "list_space_id": list,
                        }
                    }
                }
            }
        })
    }

    fn strand_move_event(id: &str, board: &str, target_list: &str, rank: &str) -> Value {
        json!({
            "event_id": format!("ck:event:move-{id}"),
            "kind": "ck.strand.move",
            "realm_id": REALM,
            "actor_id": "did:web:mover.example",
            "created_at": "2026-06-28T01:00:00Z",
            "payload": {
                "board_space_id": board,
                "strand_id": id,
                "target_space_id": target_list,
                "rank": rank,
            }
        })
    }

    fn strand_archive_event(id: &str) -> Value {
        json!({
            "event_id": format!("ck:event:archive-{id}"),
            "kind": "ck.strand.archive",
            "realm_id": REALM,
            "actor_id": "did:web:archiver.example",
            "created_at": "2026-06-28T02:00:00Z",
            "payload": { "target_ref": id },
        })
    }

    fn card_titles(columns: &[KanbanColumn]) -> Vec<(String, Vec<String>)> {
        columns
            .iter()
            .map(|column| {
                (
                    column.title.clone(),
                    column.cards.iter().map(|card| card.title.clone()).collect(),
                )
            })
            .collect()
    }

    /// The decisive cross-member test: two different members each create a card
    /// in the same list; the event-sourced projection MUST show BOTH, regardless
    /// of which session observed which create. This is exactly the symptom the
    /// old `list_strand_projections`-only card path failed (each member saw only
    /// their own card).
    #[test]
    fn two_members_card_creates_both_project_into_the_shared_list() {
        let events = vec![
            space_create_event(BOARD, "board", "Board1", None),
            space_create_event(LIST_A, "list", "Todos", Some(BOARD)),
            strand_create_event(
                "ck:strand:019f1072-0001-73b2-9c7e-1bb33a924b5c",
                "did:web:alice.example",
                "alice card",
                BOARD,
                LIST_A,
                "U",
                "2026-06-28T00:01:00Z",
            ),
            strand_create_event(
                "ck:strand:019f1072-0002-73b2-9c7e-1bb33a924b5c",
                "did:web:bob.example",
                "bob card",
                BOARD,
                LIST_A,
                "V",
                "2026-06-28T00:02:00Z",
            ),
        ];
        let ops = kanban_operations_from_events(&events);
        let (columns, options, board_id) = project_board(&ops, BOARD, REALM, None);

        assert_eq!(board_id.as_deref(), Some(BOARD));
        assert!(options.iter().any(|option| option.id == BOARD));
        assert_eq!(columns.len(), 1, "one list column");
        let titles = card_titles(&columns);
        assert_eq!(titles[0].0, "Todos");
        assert_eq!(
            titles[0].1,
            vec!["alice card".to_owned(), "bob card".to_owned()],
            "BOTH members' cards must appear, ordered by rank"
        );
    }

    #[test]
    fn strand_move_relocates_card_to_target_list() {
        let strand = "ck:strand:019f1072-0003-73b2-9c7e-1bb33a924b5c";
        let events = vec![
            space_create_event(BOARD, "board", "Board1", None),
            space_create_event(LIST_A, "list", "Todos", Some(BOARD)),
            space_create_event(LIST_B, "list", "Doing", Some(BOARD)),
            strand_create_event(
                strand,
                "did:web:alice.example",
                "moving card",
                BOARD,
                LIST_A,
                "U",
                "2026-06-28T00:01:00Z",
            ),
            strand_move_event(strand, BOARD, LIST_B, "U"),
        ];
        let ops = kanban_operations_from_events(&events);
        let (columns, _, _) = project_board(&ops, BOARD, REALM, None);

        let todos = columns.iter().find(|column| column.title == "Todos").unwrap();
        let doing = columns.iter().find(|column| column.title == "Doing").unwrap();
        assert!(todos.cards.is_empty(), "card left the origin list");
        assert_eq!(doing.cards.len(), 1, "card moved into the target list");
        assert_eq!(doing.cards[0].title, "moving card");
    }

    #[test]
    fn strand_archive_removes_card_from_board() {
        let strand = "ck:strand:019f1072-0004-73b2-9c7e-1bb33a924b5c";
        let events = vec![
            space_create_event(BOARD, "board", "Board1", None),
            space_create_event(LIST_A, "list", "Todos", Some(BOARD)),
            strand_create_event(
                strand,
                "did:web:alice.example",
                "doomed card",
                BOARD,
                LIST_A,
                "U",
                "2026-06-28T00:01:00Z",
            ),
            strand_archive_event(strand),
        ];
        let ops = kanban_operations_from_events(&events);
        let (columns, _, _) = project_board(&ops, BOARD, REALM, None);
        let todos = columns.iter().find(|column| column.title == "Todos").unwrap();
        assert!(todos.cards.is_empty(), "archived card is removed from the board");
    }

    #[test]
    fn ingest_funnel_only_accepts_kanban_kinds() {
        let events = vec![
            space_create_event(BOARD, "board", "Board1", None),
            json!({ "kind": "ck.message.create", "realm_id": REALM, "payload": {} }),
            json!({ "kind": "ck.mls.commit", "realm_id": REALM, "payload": {} }),
        ];
        let ops = kanban_operations_from_events(&events);
        assert_eq!(ops.len(), 1, "non-kanban kinds are dropped by the funnel");
    }
}
