//! Event-sourced kanban board projection (spec
//! `arkret-work/specs/active/2026-06-29-kanban-event-sourced-projection.md`).
//!
//! The board is a CLIENT-SIDE derived projection over the realm event log, per
//! `service-surface.md` §("View projection 是派生结果、不是真相源；客户端应基于
//! 已同步、已授权、已解密的 Event 集合自维护本地投影"). This module folds the
//! realm's kanban events — `ak.space.create`, `ak.strand.create`,
//! `ak.strand.update`, `ak.strand.move` / `ak.strand.reorder`,
//! `ak.strand.archive` / `ak.strand.restore`, `ak.relation.*` — into the same
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

/// Space (container) id a space update / archive / restore op targets.
fn op_space_target_id(record: &RawOperationRecord) -> Option<String> {
    let body = op_body(record);
    json_path_string(body, &["space_id"])
        .or_else(|| json_path_string(body, &["target_ref"]))
        .or_else(|| json_path_string(body, &["object", "id"]))
        .or_else(|| json_path_string(Some(&record.payload), &["space_id"]))
        .or_else(|| json_path_string(Some(&record.payload), &["target_ref"]))
}

/// Read a `ak.patch.v1` entry as a string, tolerating both the canonical
/// `{"$op":"set","value":...}` form and a plain scalar shorthand. Returns
/// `Some(None)` for an explicit `unset`, `Some(Some(v))` for a set, and
/// `None` when the key is absent.
fn patch_entry_string(patch: &Value, keys: &[&str]) -> Option<Option<String>> {
    let entry = keys.iter().find_map(|key| patch.get(*key))?;
    match entry.get("$op").and_then(Value::as_str) {
        Some("set") => Some(
            entry
                .get("value")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned),
        ),
        Some("unset") => Some(None),
        Some(_) => None,
        // Plain shorthand: the entry is the scalar value itself.
        None => entry.as_str().map(|value| Some(value.to_owned())),
    }
}

/// Fold a `ak.space.update` patch op (structural metadata: `rank`, `title`)
/// into the running container view.
fn apply_space_update_to_view(
    view: &mut crate::state::projection_views::SpaceContainerProjectionView,
    record: &RawOperationRecord,
) {
    let Some(patch) = op_body(record).and_then(|body| body.get("patch")) else {
        return;
    };
    if let Some(rank) = patch_entry_string(patch, &["rank", "metadata.rank"]) {
        view.rank = rank;
    }
    if let Some(Some(title)) = patch_entry_string(patch, &["title", "metadata.title"]) {
        view.title = title;
    }
}

/// Build the base [`StrandProjectionView`] from a `ak.strand.create` op. Mirrors
/// soland's `apply_strand_create` field extraction (title from
/// `metadata.title`, position from the `ak.component.strand.position.v1`
/// component / `fields`), tolerating both the canonical envelope
/// (`object.metadata.*`) and the local optimistic shape (`object.*`).
fn strand_view_from_create_op(
    record: &RawOperationRecord,
) -> Option<crate::state::projection_views::StrandProjectionView> {
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

    Some(crate::state::projection_views::StrandProjectionView {
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

/// Fold a `ak.strand.move` op (cross-list move; `target_space_id` is the new
/// List Space) into the running view.
fn apply_move_to_view(
    view: &mut crate::state::projection_views::StrandProjectionView,
    record: &RawOperationRecord,
) {
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

/// Fold a `ak.strand.reorder` op (same List Space; only `rank` changes) into the
/// running view.
fn apply_reorder_to_view(
    view: &mut crate::state::projection_views::StrandProjectionView,
    record: &RawOperationRecord,
) {
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
/// level. Archived strands are retained so maintenance views can restore them;
/// the board renderer hides non-active cards from the active columns.
pub(crate) fn strand_views_from_ops(
    ops: &[RawOperationRecord],
) -> Vec<crate::state::projection_views::StrandProjectionView> {
    // Preserve first-seen (create) order for stable output; placement/sort is
    // applied by `columns_from_lifecycle_projection`.
    let mut order: Vec<String> = Vec::new();
    let mut by_id: std::collections::BTreeMap<
        String,
        crate::state::projection_views::StrandProjectionView,
    > = std::collections::BTreeMap::new();

    for record in ordered_operations(ops) {
        if !raw_operation_allows_overlay(&record.payload) {
            continue;
        }
        let Some(kind) = op_kind(record) else {
            continue;
        };
        match kind.as_str() {
            "ak.strand.create" => {
                if let Some(view) = strand_view_from_create_op(record) {
                    if !by_id.contains_key(&view.strand_id) {
                        order.push(view.strand_id.clone());
                    }
                    by_id.insert(view.strand_id.clone(), view);
                }
            }
            "ak.strand.move" => {
                if let Some(id) = op_strand_target_id(record)
                    && let Some(view) = by_id.get_mut(&id)
                {
                    apply_move_to_view(view, record);
                }
            }
            "ak.strand.reorder" => {
                if let Some(id) = op_strand_target_id(record)
                    && let Some(view) = by_id.get_mut(&id)
                {
                    apply_reorder_to_view(view, record);
                }
            }
            "ak.strand.archive" => {
                if let Some(id) = op_strand_target_id(record)
                    && let Some(view) = by_id.get_mut(&id)
                {
                    view.state = "archived".to_owned();
                }
            }
            "ak.strand.restore" => {
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
        .collect()
}

/// Reduce the operation stream into the current set of space containers
/// (boards + lists). Reuses [`local_space_create_from_raw_operation`] so the
/// extraction matches the optimistic-overlay path exactly.
pub(crate) fn space_container_views_from_ops(
    ops: &[RawOperationRecord],
    realm_id: &str,
) -> Vec<crate::state::projection_views::SpaceContainerProjectionView> {
    let mut order: Vec<String> = Vec::new();
    let mut by_id: std::collections::BTreeMap<
        String,
        crate::state::projection_views::SpaceContainerProjectionView,
    > = std::collections::BTreeMap::new();
    for record in ordered_operations(ops) {
        if !raw_operation_allows_overlay(&record.payload) {
            continue;
        }
        // CREATE establishes the container; UPDATE / ARCHIVE / RESTORE fold
        // structural metadata + lifecycle on top, mirroring soland's
        // `apply_space_*`. A space op observed before its create is ignored
        // (no container to patch yet).
        if let Some(local) = local_space_create_from_raw_operation(record) {
            if !local_space_create_matches_realm(&local, realm_id) {
                continue;
            }
            if !by_id.contains_key(&local.id) {
                order.push(local.id.clone());
            }
            by_id.insert(
                local.id.clone(),
                crate::state::projection_views::SpaceContainerProjectionView {
                    space_id: local.id,
                    realm_id: local.realm_id.unwrap_or_else(|| trim_realm_id(realm_id)),
                    kind: local.kind,
                    title: local.title,
                    state: "active".to_owned(),
                    rank: local.rank,
                    parent_space_id: local.parent_space_id,
                },
            );
            continue;
        }
        let Some(kind) = op_kind(record) else {
            continue;
        };
        match kind.as_str() {
            "ak.space.update" => {
                if let Some(id) = op_space_target_id(record)
                    && let Some(view) = by_id.get_mut(&id)
                {
                    apply_space_update_to_view(view, record);
                }
            }
            "ak.space.archive" => {
                if let Some(id) = op_space_target_id(record)
                    && let Some(view) = by_id.get_mut(&id)
                {
                    view.state = "archived".to_owned();
                }
            }
            "ak.space.restore" => {
                if let Some(id) = op_space_target_id(record)
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

    const REALM: &str = "ak:realm:019f1071-0000-7000-8000-000000000000";
    const BOARD: &str = "ak:space:019f1071-e3e3-75b1-be7e-bdfa1b8f73ff";
    const LIST_A: &str = "ak:space:019f1071-f553-7410-a2c9-53028e995ed3";
    const LIST_B: &str = "ak:space:019f1071-aaaa-7410-a2c9-53028e995ed3";

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
            "event_id": format!("ak:event:{id}"),
            "kind": "ak.space.create",
            "realm_id": REALM,
            "actor_id": "did:web:creator.example",
            "created_at": "2026-06-28T00:00:00.000Z",
            "payload": { "object": object },
        })
    }

    /// Mirrors the real canonical `ak.strand.create` envelope: position lives in
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
            "event_id": format!("ak:event:{id}"),
            "kind": "ak.strand.create",
            "realm_id": REALM,
            "actor_id": actor,
            "created_at": created_at,
            "payload": {
                "object": {
                    "id": id,
                    "schema": "ak.schema.strand.v1",
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
            "event_id": format!("ak:event:move-{id}"),
            "kind": "ak.strand.move",
            "realm_id": REALM,
            "actor_id": "did:web:mover.example",
            "created_at": "2026-06-28T01:00:00.000Z",
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
            "event_id": format!("ak:event:archive-{id}"),
            "kind": "ak.strand.archive",
            "realm_id": REALM,
            "actor_id": "did:web:archiver.example",
            "created_at": "2026-06-28T02:00:00.000Z",
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

    fn sdk_realm_id() -> arkret_sdk::RealmId {
        arkret_sdk::RealmId::new(REALM).unwrap()
    }

    fn sdk_actor_id() -> arkret_sdk::Did {
        arkret_sdk::Did::new("did:webvh:z6mkfixture:alice.example").unwrap()
    }

    fn sdk_event(
        event_id: &str,
        kind: &str,
        actor_seq: u64,
        created_at: &str,
        payload: Value,
    ) -> arkret_sdk::Event {
        let mut event = arkret_sdk::Event::new(
            kind,
            sdk_realm_id(),
            sdk_actor_id(),
            actor_seq,
            arkret_sdk::Hlc::new("01970e589d21-0004-a13f9c2e").unwrap(),
            payload,
        )
        .unwrap();
        event.event_id = arkret_sdk::EventId::new(event_id).unwrap();
        event.created_at = created_at.parse().unwrap();
        event
    }

    #[derive(Default)]
    struct ClientCoreKanbanProjector {
        raw_operations: Vec<RawOperationRecord>,
    }

    impl garth::projection::RealmStateReducer for ClientCoreKanbanProjector {
        fn apply_domain_events(
            &mut self,
            _realm_id: &arkret_sdk::RealmId,
            events: &[arkret_sdk::Event],
        ) -> garth::Result<()> {
            let values: Vec<_> = events
                .iter()
                .map(|event| serde_json::to_value(event).unwrap())
                .collect();
            self.raw_operations
                .extend(kanban_operations_from_events(&values));
            Ok(())
        }
    }

    #[test]
    fn client_core_domain_projector_golden_matches_inkson_board_projection() {
        let events = vec![
            sdk_event(
                "ak:event:01904100-0000-7000-8000-000000000111",
                "ak.space.create",
                1,
                "2026-07-08T00:00:00.000Z",
                json!({
                    "object": {
                        "id": BOARD,
                        "kind": "board",
                        "title": "Board1",
                        "realm_id": REALM
                    }
                }),
            ),
            sdk_event(
                "ak:event:01904100-0000-7000-8000-000000000112",
                "ak.space.create",
                2,
                "2026-07-08T00:00:01.000Z",
                json!({
                    "object": {
                        "id": LIST_A,
                        "kind": "list",
                        "title": "Todos",
                        "realm_id": REALM,
                        "parent_space_id": BOARD
                    }
                }),
            ),
            sdk_event(
                "ak:event:01904100-0000-7000-8000-000000000113",
                "ak.strand.create",
                3,
                "2026-07-08T00:00:02.000Z",
                json!({
                    "object": {
                        "id": "ak:strand:01904100-0000-7000-8000-000000000301",
                        "schema": "ak.schema.strand.v1",
                        "realm_id": REALM,
                        "created_by": "did:webvh:z6mkfixture:alice.example",
                        "created_at": "2026-07-08T00:00:02.000Z",
                        "metadata": {
                            "title": "golden card",
                            "fields": {
                                "rank": "U",
                                "strand_kind": "card",
                                "board_space_id": BOARD,
                                "list_space_id": LIST_A
                            }
                        }
                    }
                }),
            ),
        ];
        let direct_values: Vec<_> = events
            .iter()
            .map(|event| serde_json::to_value(event).unwrap())
            .collect();
        let direct_ops = kanban_operations_from_events(&direct_values);
        let (direct_columns, ..) = project_board(&direct_ops, BOARD, REALM, None);

        let mut projector = ClientCoreKanbanProjector::default();
        let mut mount = garth::projection::ProjectionMount::new(sdk_realm_id());
        mount
            .apply_events_with_domain(&events, &mut projector)
            .unwrap();
        let (projected_columns, ..) = project_board(&projector.raw_operations, BOARD, REALM, None);

        assert_eq!(projected_columns.len(), direct_columns.len());
        assert_eq!(projected_columns[0].title, "Todos");
        assert_eq!(projected_columns[0].cards.len(), 1);
        assert_eq!(projected_columns[0].cards[0].title, "golden card");
        assert_eq!(projected_columns[0].cards, direct_columns[0].cards);
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
                "ak:strand:019f1072-0001-73b2-9c7e-1bb33a924b5c",
                "did:web:alice.example",
                "alice card",
                BOARD,
                LIST_A,
                "U",
                "2026-06-28T00:01:00.000Z",
            ),
            strand_create_event(
                "ak:strand:019f1072-0002-73b2-9c7e-1bb33a924b5c",
                "did:web:bob.example",
                "bob card",
                BOARD,
                LIST_A,
                "V",
                "2026-06-28T00:02:00.000Z",
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
        let strand = "ak:strand:019f1072-0003-73b2-9c7e-1bb33a924b5c";
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
                "2026-06-28T00:01:00.000Z",
            ),
            strand_move_event(strand, BOARD, LIST_B, "U"),
        ];
        let ops = kanban_operations_from_events(&events);
        let (columns, ..) = project_board(&ops, BOARD, REALM, None);

        let todos = columns
            .iter()
            .find(|column| column.title == "Todos")
            .unwrap();
        let doing = columns
            .iter()
            .find(|column| column.title == "Doing")
            .unwrap();
        assert!(todos.cards.is_empty(), "card left the origin list");
        assert_eq!(doing.cards.len(), 1, "card moved into the target list");
        assert_eq!(doing.cards[0].title, "moving card");
    }

    #[test]
    fn strand_archive_marks_card_archived_for_maintenance_drawer() {
        let strand = "ak:strand:019f1072-0004-73b2-9c7e-1bb33a924b5c";
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
                "2026-06-28T00:01:00.000Z",
            ),
            strand_archive_event(strand),
        ];
        let ops = kanban_operations_from_events(&events);
        let (columns, ..) = project_board(&ops, BOARD, REALM, None);
        let todos = columns
            .iter()
            .find(|column| column.title == "Todos")
            .unwrap();
        assert_eq!(todos.cards.len(), 1);
        assert_eq!(todos.cards[0].lifecycle, StrandLifecycleState::Archived);
        assert!(
            todos
                .cards
                .iter()
                .all(|card| card.lifecycle != StrandLifecycleState::Active),
            "archived card remains available to the drawer but leaves active board rendering"
        );
    }

    /// Build a locally-appended optimistic op record directly (the shape
    /// `submit_kanban_*` / `submit_kanban_operation_event` write into
    /// `raw_operations`), so the tests prove `project_board` folds the
    /// OPTIMISTIC op shape — not just the canonical backfilled envelope.
    fn local_op(operation_id: &str, received_at: &str, payload: Value) -> RawOperationRecord {
        RawOperationRecord {
            operation_id: operation_id.to_owned(),
            realm_id: Some(REALM.to_owned()),
            received_at: chrono::DateTime::parse_from_rfc3339(received_at)
                .unwrap()
                .with_timezone(&chrono::Utc),
            payload,
        }
    }

    /// The local `ak.strand.create` op (from `submit_kanban_move`) carries the
    /// canonical create body (`body.object.metadata.fields.*`) PLUS a top-level
    /// `effect`; folding it must surface the card immediately (optimistic).
    #[test]
    fn local_optimistic_card_create_op_projects_into_its_list() {
        let strand = "ak:strand:019f1072-1001-73b2-9c7e-1bb33a924b5c";
        let ops = vec![
            kanban_operations_from_events(&[
                space_create_event(BOARD, "board", "Board1", None),
                space_create_event(LIST_A, "list", "Todos", Some(BOARD)),
            ]),
            vec![local_op(
                "op-create-1",
                "2026-06-28T00:05:00.000Z",
                json!({
                    "kind": "ak.strand.create",
                    "operation_id": "op-create-1",
                    "actor_id": "did:web:alice.example",
                    "created_at": "2026-06-28T00:05:00.000Z",
                    "wire_kind": "ak.strand.create",
                    "write_state": "queued",
                    "effect": {
                        "strand_id": strand,
                        "board_space_id": BOARD,
                        "list_space_id": LIST_A,
                        "title": "queued card",
                        "rank": "U",
                    },
                    "body": {
                        "object": {
                            "id": strand,
                            "realm_id": REALM,
                            "created_by": "did:web:alice.example",
                            "metadata": {
                                "title": "queued card",
                                "fields": {
                                    "strand_kind": "card",
                                    "board_space_id": BOARD,
                                    "list_space_id": LIST_A,
                                    "rank": "U",
                                }
                            }
                        }
                    },
                }),
            )],
        ]
        .concat();
        let (columns, ..) = project_board(&ops, BOARD, REALM, None);
        let todos = columns
            .iter()
            .find(|column| column.title == "Todos")
            .unwrap();
        assert_eq!(
            todos.cards.len(),
            1,
            "optimistic create folds into the list"
        );
        assert_eq!(todos.cards[0].title, "queued card");
    }

    /// The local CAS move op (from `submit_strand_position_cas_move`) carries
    /// the canonical `strand_move_payload` in `body`; folding it relocates the
    /// card without waiting for a server round-trip.
    #[test]
    fn local_optimistic_cas_move_op_relocates_card() {
        let strand = "ak:strand:019f1072-1002-73b2-9c7e-1bb33a924b5c";
        let mut ops = kanban_operations_from_events(&[
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
                "2026-06-28T00:01:00.000Z",
            ),
        ]);
        ops.push(local_op(
            "op-move-1",
            "2026-06-28T00:06:00.000Z",
            json!({
                "kind": "ak.strand.move",
                "move_id": "op-move-1",
                "board_space_id": BOARD,
                "strand_id": strand,
                "write_state": "submitted",
                "body": {
                    "board_space_id": BOARD,
                    "strand_id": strand,
                    "target_space_id": LIST_B,
                    "rank": "U",
                },
            }),
        ));
        let (columns, ..) = project_board(&ops, BOARD, REALM, None);
        let todos = columns
            .iter()
            .find(|column| column.title == "Todos")
            .unwrap();
        let doing = columns
            .iter()
            .find(|column| column.title == "Doing")
            .unwrap();
        assert!(todos.cards.is_empty(), "card left the origin list");
        assert_eq!(
            doing.cards.len(),
            1,
            "optimistic move folds into the target list"
        );
    }

    /// Column reorder appends a `ak.space.update` patch op carrying the new
    /// `rank`; folding it must re-sort the columns (both the canonical
    /// `{$op:set}` patch form and the plain scalar shorthand).
    #[test]
    fn local_space_update_rank_reorders_columns() {
        for rank_entry in [json!({ "$op": "set", "value": "r001" }), json!("r001")] {
            let mut ops = kanban_operations_from_events(&[space_create_event(
                BOARD, "board", "Board1", None,
            )]);
            // Two lists, A before B by rank.
            ops.extend(kanban_operations_from_events(&[
                space_create_event(LIST_A, "list", "First", Some(BOARD)),
                space_create_event(LIST_B, "list", "Second", Some(BOARD)),
            ]));
            // Give A rank r002 and B rank r003 via create-time rank patches so
            // the initial order is A, B; then bump B to r001 (front).
            ops.push(local_op(
                "op-rank-a",
                "2026-06-28T00:02:00.000Z",
                json!({
                    "kind": "ak.space.update",
                    "write_state": "queued",
                    "body": { "space_id": LIST_A, "patch": { "rank": { "$op": "set", "value": "r002" } } },
                }),
            ));
            ops.push(local_op(
                "op-rank-b",
                "2026-06-28T00:03:00.000Z",
                json!({
                    "kind": "ak.space.update",
                    "write_state": "queued",
                    "body": { "space_id": LIST_B, "patch": { "rank": rank_entry.clone() } },
                }),
            ));
            let (columns, ..) = project_board(&ops, BOARD, REALM, None);
            assert_eq!(columns.len(), 2);
            assert_eq!(
                columns[0].title, "Second",
                "B moved to the front by its new rank ({rank_entry})"
            );
            assert_eq!(columns[1].title, "First");
        }
    }

    /// List archive appends a `ak.space.archive` op; folding it flips the
    /// column's lifecycle to Archived (kept in the projection for the Archived
    /// section, not dropped).
    #[test]
    fn local_space_archive_marks_column_archived() {
        let mut ops = kanban_operations_from_events(&[
            space_create_event(BOARD, "board", "Board1", None),
            space_create_event(LIST_A, "list", "Todos", Some(BOARD)),
        ]);
        ops.push(local_op(
            "op-archive-1",
            "2026-06-28T00:04:00.000Z",
            json!({
                "kind": "ak.space.archive",
                "write_state": "queued",
                "body": { "space_id": LIST_A },
            }),
        ));
        let (columns, ..) = project_board(&ops, BOARD, REALM, None);
        let todos = columns
            .iter()
            .find(|column| column.title == "Todos")
            .unwrap();
        assert_eq!(
            todos.state,
            SpaceContainerLifecycleState::Archived,
            "archived list keeps its column but flips lifecycle"
        );
    }

    /// Lock the REAL wire shapes: build the optimistic ops through the same
    /// `ak_ops` builders the submit helpers use (`body = event.payload`) so the
    /// reducer is proven against the actual serialized payloads, not hand-rolled
    /// JSON. Guards against a builder/reducer drift (e.g. a patch entry that
    /// serializes differently than `patch_entry_string` expects).
    fn local_op_from_builder(
        operation_id: &str,
        received_at: &str,
        kind: &str,
        body: std::collections::BTreeMap<String, Value>,
    ) -> RawOperationRecord {
        local_op(
            operation_id,
            received_at,
            json!({
                "kind": kind,
                "operation_id": operation_id,
                "write_state": "queued",
                "body": body,
            }),
        )
    }

    #[test]
    fn real_space_update_builder_rank_reorders_columns() {
        let actor = "did:web:alice.example";
        let space_update_body = |space_id: &str, rank: &str| {
            crate::operation::ak_ops::space_update_patch(
                REALM,
                actor,
                space_id,
                json!({ "rank": rank }),
            )
            .unwrap()
            .build_sdk_event("inkson")
            .unwrap()
            .payload
        };
        let mut ops = kanban_operations_from_events(&[
            space_create_event(BOARD, "board", "Board1", None),
            space_create_event(LIST_A, "list", "First", Some(BOARD)),
            space_create_event(LIST_B, "list", "Second", Some(BOARD)),
        ]);
        ops.push(local_op_from_builder(
            "op-rank-a",
            "2026-06-28T00:02:00.000Z",
            "ak.space.update",
            space_update_body(LIST_A, "r002"),
        ));
        ops.push(local_op_from_builder(
            "op-rank-b",
            "2026-06-28T00:03:00.000Z",
            "ak.space.update",
            space_update_body(LIST_B, "r001"),
        ));
        let (columns, ..) = project_board(&ops, BOARD, REALM, None);
        assert_eq!(columns.len(), 2);
        assert_eq!(
            columns[0].title, "Second",
            "real ak.space.update rank patch folds and re-sorts the columns"
        );
    }

    #[test]
    fn real_cas_move_builder_relocates_card() {
        let strand = "ak:strand:019f1072-2002-73b2-9c7e-1bb33a924b5c";
        let move_body = crate::operation::ak_ops::strand_position_cas_update(
            REALM,
            "did:web:alice.example",
            "ak.strand.move",
            BOARD,
            strand,
            json!({ "list_space_id": LIST_A, "rank": "U" }),
            json!({ "list_space_id": LIST_B, "rank": "U" }),
        )
        .unwrap()
        .build_sdk_event("inkson")
        .unwrap()
        .payload;
        let mut ops = kanban_operations_from_events(&[
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
                "2026-06-28T00:01:00.000Z",
            ),
        ]);
        ops.push(local_op_from_builder(
            "op-move-real",
            "2026-06-28T00:06:00.000Z",
            "ak.strand.move",
            move_body,
        ));
        let (columns, ..) = project_board(&ops, BOARD, REALM, None);
        let todos = columns
            .iter()
            .find(|column| column.title == "Todos")
            .unwrap();
        let doing = columns
            .iter()
            .find(|column| column.title == "Doing")
            .unwrap();
        assert!(todos.cards.is_empty(), "card left the origin list");
        assert_eq!(
            doing.cards.len(),
            1,
            "real CAS move payload folds into the target list"
        );
    }

    #[test]
    fn ingest_funnel_only_accepts_kanban_kinds() {
        let events = vec![
            space_create_event(BOARD, "board", "Board1", None),
            json!({ "kind": "ak.message.create", "realm_id": REALM, "payload": {} }),
            json!({ "kind": "ak.mls.commit", "realm_id": REALM, "payload": {} }),
        ];
        let ops = kanban_operations_from_events(&events);
        assert_eq!(ops.len(), 1, "non-kanban kinds are dropped by the funnel");
    }
}
