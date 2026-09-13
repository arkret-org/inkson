//! Kanban presentation and pending local-operation overlays.
//!
//! Complete object content and source identities come from installed current
//! entries. Legacy lifecycle rows/Event annotations provide layout and audit
//! context only; they are never an authoring basis or a canonical MV winner.
//! The production caller installs current before applying pending UI overlays.

use arkret_wire::event_kind_str;

use super::*;
use crate::move_builder::strand_position_cell_id;

pub(crate) const POSITION_UNAVAILABLE_COLUMN_ID: &str =
    "inkson:diagnostic:strand-position-unavailable";

/// Stable presentation order for local annotations; this is not causal order.
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

/// Build the base [`StrandProjectionView`] from a `ak.strand.create` op.
///
/// A create carries NO Board / List placement. `strand.schema.json` forbids
/// `board_space_id` / `list_space_id` / `rank` inside `metadata.fields`, and
/// `strand_create_payload` is `additionalProperties: false`, so a create can
/// carry a position neither as a metadata field nor as a `components[]` entry.
/// The `ak.component.strand.position.v1` cell's only command surface is
/// `ak.strand.move` / `ak.strand.reorder`, folded by [`apply_move_to_view`] /
/// [`apply_reorder_to_view`]. Between the accepted create and its first Move a
/// Strand is a legal UNPLACED object: it exists, and it is in no List.
fn strand_view_from_create_op(
    record: &RawOperationRecord,
) -> Option<crate::state::projection_views::StrandProjectionView> {
    let body = op_body(record)?;
    let object = body.get("object").unwrap_or(body);
    let metadata = object.get("metadata");
    // Canonical location only: `strand.schema.json` forbids a top-level
    // `fields` object, so a payload that carries one is a schema violation, not
    // an alternative spelling to fall back on.
    let object_fields = metadata.and_then(|metadata| metadata.get("fields"));

    // A create payload carries no `object.id`: the Strand is
    // `retype(event_id)` of the ACCEPTED create, or — while the write is in
    // flight — the record's holder-local handle. Both come off the record via
    // `raw_operation_create_target_id`; a payload member claiming to name the
    // object would be an id the receiver never derives.
    let strand_id = raw_operation_create_target_id(&record.payload)?;

    // Same rule for `title` / `summary`: both are forbidden as Strand top-level
    // fields; `metadata.*` (or `encrypted_metadata`) is the only wire home.
    let metadata_str = |keys: &[&str]| -> Option<String> {
        for key in keys {
            if let Some(value) =
                metadata.and_then(|metadata| json_path_string(Some(metadata), &[key]))
            {
                return Some(value);
            }
        }
        None
    };

    let title = metadata_str(&["title"]).unwrap_or_else(|| strand_id.clone());
    let summary = metadata_str(&["summary"]);

    let fields = object_fields
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    // Both slots decode to their authoritative SDK type here. A create payload
    // that carries something else on them violates `strand.schema.json`, and
    // dropping it is the fail-closed read: the card renders with no synthesis
    // instead of forwarding an unvalidated value to the decrypt / display path.
    let content = object
        .get(KANBAN_CONTENT_PATH)
        .and_then(|value| serde_json::from_value::<arkret_sdk::ContentBlock>(value.clone()).ok());
    let encrypted_content = object.get(KANBAN_ENCRYPTED_CONTENT_PATH).and_then(|value| {
        serde_json::from_value::<arkret_sdk::EncryptedEnvelope>(value.clone()).ok()
    });
    let tracks = object
        .get("tracks")
        .and_then(|value| {
            serde_json::from_value::<std::collections::BTreeMap<String, arkret_sdk::StrandTrack>>(
                value.clone(),
            )
            .ok()
        })
        .unwrap_or_default();

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
        content,
        encrypted_content,
        tracks,
        // Unplaced until a Move folds in: the create Event has no placement to
        // read, and inventing one here would re-open the create-time carrier
        // the Strand schema closed.
        board_space_id: None,
        list_space_id: None,
        rank: None,
        assigned_actor_ids: Vec::new(),
        assigned_to_relations: Vec::new(),
        fields,
        // Locally folded board rows carry no activation axis or schedule
        // winner; the projection read supplies it, and until it does RSVP
        // authoring stays fail-closed rather than signing an unobserved basis.
        schema_refs: Vec::new(),
        rsvps: Vec::new(),
        schedule_revision_source: None,
        state: arkret_sdk::ProjectionObjectState::Active,
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

fn operation_actor_principal_id(record: &RawOperationRecord) -> Option<String> {
    let actor = record.payload.get("actor_id")?;
    if let Ok(actor) = serde_json::from_value::<arkret_sdk::ActorId>(actor.clone()) {
        return Some(actor.signing_principal_id().as_str().to_owned());
    }
    let actor = actor.as_str()?.trim();
    if let Ok(actor) = serde_json::from_str::<arkret_sdk::ActorId>(actor) {
        return Some(actor.signing_principal_id().as_str().to_owned());
    }
    arkret_sdk::DidCoreId::new(actor.to_owned())
        .ok()
        .map(|actor| actor.as_str().to_owned())
}

/// Fold an accepted `ak.rsvp.set` into the Strand's local causal-register
/// projection. The canonical Strand list deliberately omits RSVP cells, so
/// the Event log is the client-side source for this component.
fn apply_rsvp_set_to_view(
    view: &mut crate::state::projection_views::StrandProjectionView,
    record: &RawOperationRecord,
) {
    let Some(body) = op_body(record) else {
        return;
    };
    if body.get("event_ref").and_then(Value::as_str) != Some(view.strand_id.as_str()) {
        return;
    }
    let occurrence = match body.get("occurrence") {
        None | Some(Value::Null) => None,
        Some(Value::String(value)) => Some(value.clone()),
        _ => return,
    };
    let Some(actor_id) = operation_actor_principal_id(record) else {
        return;
    };
    let Some(entry) = body.get("entry").cloned() else {
        return;
    };
    if serde_json::from_value::<arkret_sdk::RsvpEntry>(entry.clone()).is_err() {
        return;
    }
    let source_event_id = record
        .payload
        .get("event_id")
        .and_then(Value::as_str)
        .unwrap_or(record.operation_id.as_str());
    let Ok(event_id) = arkret_sdk::EventId::new(source_event_id.to_owned()) else {
        // A queued holder-local operation has no content-derived Event id yet.
        // The accepted Event replaces it through the ordinary sync funnel.
        return;
    };
    let source_event_digest = event_id.event_digest().to_string();
    // A holder-local accepted RSVP was built immediately after a complete
    // Event-log read. Retain that observed schedule winner until the regular
    // synchronized Strand projection catches up. This is not inferred from a
    // remote RSVP assertion: only the local authoring path writes the marker.
    if view.schedule_revision_source.is_none()
        && let Some(observed) = record
            .payload
            .get("locally_observed_schedule_winner")
            .and_then(Value::as_str)
    {
        view.schedule_revision_source = arkret_sdk::Hash::new(observed.to_owned())
            .ok()
            .map(|value| value.to_string());
    }
    let causal_refs = record
        .payload
        .get("causal_refs")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect::<std::collections::BTreeSet<_>>();

    let cell = if let Some(cell) = view
        .rsvps
        .iter_mut()
        .find(|cell| cell.occurrence == occurrence && cell.actor_id == actor_id)
    {
        cell
    } else {
        view.rsvps
            .push(crate::state::projection_views::RsvpCellProjectionView {
                occurrence,
                actor_id,
                winner: None,
                retained_writes: Vec::new(),
            });
        let Some(cell) = view.rsvps.last_mut() else {
            return;
        };
        cell
    };
    if cell
        .retained_writes
        .iter()
        .any(|write| write.source_event_id == event_id.as_str())
    {
        return;
    }
    cell.retained_writes
        .push(crate::state::projection_views::RsvpRetainedWrite {
            source_event_id: event_id.to_string(),
            source_event_digest,
            entry,
            causal_refs: causal_refs
                .into_iter()
                .filter_map(|reference| arkret_sdk::Hash::new(reference.to_owned()).ok())
                .collect(),
        });
    let retained_ids = cell
        .retained_writes
        .iter()
        .map(|write| write.source_event_digest.as_str())
        .collect::<BTreeSet<_>>();
    let writes = cell
        .retained_writes
        .iter()
        .filter_map(|write| {
            let event_id = arkret_sdk::EventId::new(write.source_event_id.clone()).ok()?;
            let supersedes = write
                .causal_refs
                .iter()
                .filter(|reference| retained_ids.contains(reference.as_str()))
                .cloned()
                .collect::<Vec<_>>();
            Some(
                arkret_sdk::StateWrite::new(
                    event_id,
                    arkret_sdk::LatticeOp {
                        op_type: arkret_sdk::LatticeOpType::Set,
                        value: Some(write.entry.clone()),
                        ..arkret_sdk::LatticeOp::empty()
                    },
                )
                .with_supersedes(supersedes),
            )
        })
        .collect::<Vec<_>>();
    let Ok(state) = arkret_sdk::causal_register_state(&writes) else {
        cell.winner = None;
        return;
    };
    cell.winner = cell
        .retained_writes
        .iter()
        .find(|write| write.source_event_id == state.winner.event_id.as_str())
        .map(
            |write| crate::state::projection_views::RsvpWinnerProjectionView {
                source_event_id: write.source_event_id.clone(),
                source_event_digest: write.source_event_digest.clone(),
                entry: write.entry.clone(),
            },
        );
}

/// Reduce the operation stream into the current set of strands. Folds CREATE
/// (base view) + MOVE / REORDER (placement) + ARCHIVE / RESTORE (lifecycle) in
/// causal order; content updates and assignments are layered later at the card
/// level. Archived strands are retained so maintenance views can restore them;
/// the board renderer hides non-active cards from the active columns.
pub(crate) fn strand_views_from_ops(
    ops: &[RawOperationRecord],
) -> Vec<crate::state::projection_views::StrandProjectionView> {
    strand_views_from_projection_and_ops(&[], ops)
}

/// Merge the server's current-object Strand baseline with the visible Event
/// stream. The baseline supplies current rows whose create Event predates a
/// `since_join` membership floor; subsequent/local Events still fold on top.
pub(crate) fn strand_views_from_projection_and_ops(
    projected: &[crate::state::projection_views::StrandProjectionView],
    ops: &[RawOperationRecord],
) -> Vec<crate::state::projection_views::StrandProjectionView> {
    let aliases = event_derived_target_aliases(ops);
    // Preserve first-seen (create) order for stable output; placement/sort is
    // applied by `columns_from_lifecycle_projection`.
    let mut order = projected
        .iter()
        .map(|view| view.strand_id.clone())
        .collect::<Vec<_>>();
    let mut by_id = projected
        .iter()
        .cloned()
        .map(|view| (view.strand_id.clone(), view))
        .collect::<std::collections::BTreeMap<_, _>>();

    for record in ordered_operations(ops) {
        if !raw_operation_allows_overlay(&record.payload) {
            continue;
        }
        let Some(kind) = op_kind(record) else {
            continue;
        };
        match kind.as_str() {
            event_kind_str::STRAND_CREATE => {
                if let Some(mut view) = strand_view_from_create_op(record) {
                    view.strand_id = resolve_event_derived_target_alias(&aliases, &view.strand_id);
                    if let Some(current) = by_id.get_mut(&view.strand_id) {
                        // The endpoint row is the authoritative current
                        // structural/metadata view. It intentionally omits
                        // private content, tracks and open profile fields, so
                        // enrich only those omitted slots from a visible create
                        // Event without replacing the newer baseline title,
                        // position or lifecycle.
                        if current.content.is_none() {
                            current.content = view.content;
                        }
                        if current.encrypted_content.is_none() {
                            current.encrypted_content = view.encrypted_content;
                        }
                        if current.tracks.is_empty() {
                            current.tracks = view.tracks;
                        }
                        if current.fields.is_empty() {
                            current.fields = view.fields;
                        }
                        continue;
                    } else {
                        order.push(view.strand_id.clone());
                    }
                    by_id.insert(view.strand_id.clone(), view);
                }
            }
            event_kind_str::STRAND_MOVE => {
                if let Some(id) = op_strand_target_id(record)
                    .map(|id| resolve_event_derived_target_alias(&aliases, &id))
                    && let Some(view) = by_id.get_mut(&id)
                {
                    apply_move_to_view(view, record);
                    view.board_space_id = view
                        .board_space_id
                        .as_deref()
                        .map(|id| resolve_event_derived_target_alias(&aliases, id));
                    view.list_space_id = view
                        .list_space_id
                        .as_deref()
                        .map(|id| resolve_event_derived_target_alias(&aliases, id));
                }
            }
            event_kind_str::STRAND_REORDER => {
                if let Some(id) = op_strand_target_id(record)
                    .map(|id| resolve_event_derived_target_alias(&aliases, &id))
                    && let Some(view) = by_id.get_mut(&id)
                {
                    apply_reorder_to_view(view, record);
                    view.board_space_id = view
                        .board_space_id
                        .as_deref()
                        .map(|id| resolve_event_derived_target_alias(&aliases, id));
                    view.list_space_id = view
                        .list_space_id
                        .as_deref()
                        .map(|id| resolve_event_derived_target_alias(&aliases, id));
                }
            }
            event_kind_str::STRAND_ARCHIVE => {
                if let Some(id) = op_strand_target_id(record)
                    .map(|id| resolve_event_derived_target_alias(&aliases, &id))
                    && let Some(view) = by_id.get_mut(&id)
                {
                    view.state = arkret_sdk::ProjectionObjectState::Archived;
                }
            }
            event_kind_str::STRAND_RESTORE => {
                if let Some(id) = op_strand_target_id(record)
                    .map(|id| resolve_event_derived_target_alias(&aliases, &id))
                    && let Some(view) = by_id.get_mut(&id)
                {
                    view.state = arkret_sdk::ProjectionObjectState::Active;
                }
            }
            event_kind_str::RSVP_SET => {
                if let Some(id) = op_body(record)
                    .and_then(|body| json_path_string(Some(body), &["event_ref"]))
                    .map(|id| resolve_event_derived_target_alias(&aliases, &id))
                    && let Some(view) = by_id.get_mut(&id)
                {
                    apply_rsvp_set_to_view(view, record);
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
#[cfg(test)]
pub(crate) fn space_container_views_from_ops(
    ops: &[RawOperationRecord],
    realm_id: &str,
) -> Vec<crate::state::projection_views::SpaceContainerProjectionView> {
    space_container_views_from_projection_and_ops(&[], ops, realm_id)
}

/// Merge the current Space projection baseline with visible/local Events.
/// A current Board/List remains renderable even when its create Event is
/// outside the caller's `since_join` history window.
pub(crate) fn space_container_views_from_projection_and_ops(
    projected: &[crate::state::projection_views::SpaceContainerProjectionView],
    ops: &[RawOperationRecord],
    realm_id: &str,
) -> Vec<crate::state::projection_views::SpaceContainerProjectionView> {
    let aliases = event_derived_target_aliases(ops);
    let mut order = projected
        .iter()
        .filter(|view| trim_realm_id(&view.realm_id) == trim_realm_id(realm_id))
        .map(|view| view.space_id.clone())
        .collect::<Vec<_>>();
    let mut by_id = projected
        .iter()
        .filter(|view| trim_realm_id(&view.realm_id) == trim_realm_id(realm_id))
        .cloned()
        .map(|view| (view.space_id.clone(), view))
        .collect::<std::collections::BTreeMap<_, _>>();
    for record in ordered_operations(ops) {
        if !raw_operation_allows_overlay(&record.payload) {
            continue;
        }
        // CREATE establishes the container; UPDATE / ARCHIVE / RESTORE fold
        // structural metadata + lifecycle on top, mirroring soland's
        // `apply_space_*`. A space op observed before its create is ignored
        // (no container to patch yet).
        if let Some(mut local) = local_space_create_from_raw_operation(record) {
            if !local_space_create_matches_realm(&local, realm_id) {
                continue;
            }
            local.id = resolve_event_derived_target_alias(&aliases, &local.id);
            local.parent_space_id = local
                .parent_space_id
                .as_deref()
                .map(|id| resolve_event_derived_target_alias(&aliases, id));
            if by_id.contains_key(&local.id) {
                // The endpoint row is already the current materialized Space.
                // Keep it and continue folding later update/lifecycle Events;
                // replacing it with the historical create would regress title
                // or state when a full-history member opens the Board.
                continue;
            } else {
                order.push(local.id.clone());
            }
            by_id.insert(
                local.id.clone(),
                crate::state::projection_views::SpaceContainerProjectionView {
                    space_id: local.id,
                    realm_id: local.realm_id.unwrap_or_else(|| trim_realm_id(realm_id)),
                    kind: local.kind,
                    title: local.title,
                    state: arkret_sdk::ProjectionSpaceState::Active,
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
            event_kind_str::SPACE_UPDATE => {
                if let Some(id) = op_space_target_id(record)
                    .map(|id| resolve_event_derived_target_alias(&aliases, &id))
                    && let Some(view) = by_id.get_mut(&id)
                {
                    apply_space_update_to_view(view, record);
                }
            }
            event_kind_str::SPACE_ARCHIVE => {
                if let Some(id) = op_space_target_id(record)
                    .map(|id| resolve_event_derived_target_alias(&aliases, &id))
                    && let Some(view) = by_id.get_mut(&id)
                {
                    view.state = arkret_sdk::ProjectionSpaceState::Archived;
                }
            }
            event_kind_str::SPACE_RESTORE => {
                if let Some(id) = op_space_target_id(record)
                    .map(|id| resolve_event_derived_target_alias(&aliases, &id))
                    && let Some(view) = by_id.get_mut(&id)
                {
                    view.state = arkret_sdk::ProjectionSpaceState::Active;
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
#[cfg(test)]
pub(crate) fn project_board(
    ops: &[RawOperationRecord],
    preferred_board_id: &str,
    realm_id: &str,
    decrypt_ctx: Option<&MlsDecryptCtx<'_>>,
) -> (Vec<KanbanColumn>, Vec<BoardSpaceOption>, Option<String>) {
    project_board_with_projection(ops, &[], &[], preferred_board_id, realm_id, decrypt_ctx)
}

/// Default-actor form of [`project_board_with_projection_for_actor`].
/// Only the projection tests need it: production always knows the signed-in
/// actor, because the board marks the viewer's own RSVP winner.
#[cfg(test)]
pub(crate) fn project_board_with_projection(
    ops: &[RawOperationRecord],
    projected_containers: &[crate::state::projection_views::SpaceContainerProjectionView],
    projected_strands: &[crate::state::projection_views::StrandProjectionView],
    preferred_board_id: &str,
    realm_id: &str,
    decrypt_ctx: Option<&MlsDecryptCtx<'_>>,
) -> (Vec<KanbanColumn>, Vec<BoardSpaceOption>, Option<String>) {
    project_board_with_projection_for_actor(
        ops,
        projected_containers,
        projected_strands,
        preferred_board_id,
        realm_id,
        decrypt_ctx,
        "",
    )
}

pub(crate) fn project_board_with_projection_for_actor(
    ops: &[RawOperationRecord],
    projected_containers: &[crate::state::projection_views::SpaceContainerProjectionView],
    projected_strands: &[crate::state::projection_views::StrandProjectionView],
    preferred_board_id: &str,
    realm_id: &str,
    decrypt_ctx: Option<&MlsDecryptCtx<'_>>,
    self_actor_id: &str,
) -> (Vec<KanbanColumn>, Vec<BoardSpaceOption>, Option<String>) {
    let aliases = event_derived_target_aliases(ops);
    let preferred_board_id = resolve_event_derived_target_alias(&aliases, preferred_board_id);
    let containers =
        space_container_views_from_projection_and_ops(projected_containers, ops, realm_id);
    let strands = strand_views_from_projection_and_ops(projected_strands, ops);
    let (columns, board_options, board_id) = columns_from_lifecycle_projection_for_actor(
        &containers,
        &strands,
        &preferred_board_id,
        decrypt_ctx,
        self_actor_id,
    );
    // A card's first placement is its own `ak.strand.move`, authored only AFTER
    // the create receipt names the Strand. Between the click and that receipt
    // the fold above legitimately has no List for the new Strand, so without
    // this overlay the card would vanish until the round trip completes. The
    // overlay reads the write's holder-local `effect` — see
    // [`local_card_create_from_raw_operation`] — never a placement smuggled
    // into the create payload.
    let columns =
        overlay_local_card_create_records(columns, ops, board_id.as_deref().unwrap_or_default());
    let columns = overlay_local_card_update_records(columns, ops, decrypt_ctx);
    let columns = overlay_local_card_assignment_records(columns, ops);
    (columns, board_options, board_id)
}

fn take_card(columns: &mut [KanbanColumn], strand_id: &str) -> Option<KanbanCard> {
    for column in columns {
        if let Some(index) = column.cards.iter().position(|card| card.id == strand_id) {
            return Some(column.cards.remove(index));
        }
    }
    None
}

fn projected_card(
    projected: &[crate::state::projection_views::StrandProjectionView],
    strand_id: &str,
    decrypt_ctx: Option<&MlsDecryptCtx<'_>>,
    actor: &str,
) -> Option<KanbanCard> {
    projected
        .iter()
        .find(|strand| strand.strand_id == strand_id)
        .map(|strand| card_from_strand_projection_for_actor(strand, decrypt_ctx, actor))
}

fn push_position_diagnostic(
    diagnostics: &mut Vec<KanbanCard>,
    mut card: KanbanCard,
    state: CardState,
    refs: Vec<arkret_sdk::Hash>,
) {
    card.state = state;
    card.position_basis_refs = refs;
    diagnostics.push(card);
}

/// Replace the lossy placement columns in the convenience Strand projection
/// with the canonical `ak.component.strand.position.v1` current result.
///
/// The convenience projection is only a discovery/content baseline. A complete
/// current value places the card; malformed/duplicate/unavailable results move
/// it into a non-Space diagnostic bucket; removed means it is unplaced.
pub(crate) fn install_current_strand_positions(
    columns: &mut Vec<KanbanColumn>,
    entries: &[arkret_sdk::CurrentResultEntry],
    projected: &[crate::state::projection_views::StrandProjectionView],
    board_space_id: &str,
    decrypt_ctx: Option<&MlsDecryptCtx<'_>>,
    actor: &str,
) {
    columns.retain(|column| column.id != POSITION_UNAVAILABLE_COLUMN_ID);
    let mut by_strand = BTreeMap::<String, Vec<&arkret_sdk::CurrentResultEntry>>::new();
    for entry in entries {
        let arkret_sdk::CurrentTarget::Strand { strand_id } = entry.target() else {
            continue;
        };
        let expected_cell = strand_position_cell_id(board_space_id, strand_id.as_str());
        if entry.selector().cell_id.as_str() == expected_cell {
            by_strand
                .entry(strand_id.as_str().to_owned())
                .or_default()
                .push(entry);
        }
    }

    let mut diagnostics = Vec::new();
    for (strand_id, matching) in by_strand {
        let card = take_card(columns, &strand_id)
            .or_else(|| projected_card(projected, &strand_id, decrypt_ctx, actor));
        let Some(mut card) = card else {
            continue;
        };
        if matching.len() != 1 {
            push_position_diagnostic(&mut diagnostics, card, CardState::Quarantined, Vec::new());
            continue;
        }
        match matching[0].result() {
            arkret_sdk::CurrentOutcome::Value { value, source } => {
                let value = value.as_json();
                let Some(list_space_id) = value.get("list_space_id").and_then(Value::as_str) else {
                    push_position_diagnostic(
                        &mut diagnostics,
                        card,
                        CardState::Quarantined,
                        Vec::new(),
                    );
                    continue;
                };
                let Some(rank) = value.get("rank").and_then(Value::as_str) else {
                    push_position_diagnostic(
                        &mut diagnostics,
                        card,
                        CardState::Quarantined,
                        Vec::new(),
                    );
                    continue;
                };
                card.rank = rank.to_owned();
                card.position_basis_refs = source
                    .as_ref()
                    .map(|source| vec![source.event_id.event_digest()])
                    .unwrap_or_default();
                if matches!(card.state, CardState::Conflict | CardState::Quarantined) {
                    card.state = CardState::Synced;
                }
                if let Some(column) = columns.iter_mut().find(|column| column.id == list_space_id) {
                    column.cards.push(card);
                } else {
                    push_position_diagnostic(
                        &mut diagnostics,
                        card,
                        CardState::Quarantined,
                        Vec::new(),
                    );
                }
            }
            arkret_sdk::CurrentOutcome::Removed => {
                // A removed position is a valid unplaced Strand. Keeping it out
                // of every List is the complete effective projection.
            }
            arkret_sdk::CurrentOutcome::Unavailable { .. } => {
                push_position_diagnostic(
                    &mut diagnostics,
                    card,
                    CardState::Quarantined,
                    Vec::new(),
                );
            }
        }
    }
    for column in columns.iter_mut() {
        sort_kanban_cards(&mut column.cards);
    }
    if !diagnostics.is_empty() {
        sort_kanban_cards(&mut diagnostics);
        columns.push(KanbanColumn {
            id: POSITION_UNAVAILABLE_COLUMN_ID.to_owned(),
            title: "Position unavailable".to_owned(),
            rank: String::new(),
            cards: diagnostics,
            state: SpaceContainerLifecycleState::PositionUnavailable,
        });
    }
}

/// Replace the convenience projection's single Strand lifecycle value with
/// the canonical causal-register result. A missing lifecycle cell is the
/// protocol's initial `active` state; it is trusted only when the same bounded
/// current page contains the Strand object selector, proving the target page
/// has actually arrived.
pub(crate) fn install_current_strand_lifecycles(
    columns: &mut [KanbanColumn],
    entries: &[arkret_sdk::CurrentResultEntry],
) {
    for column in columns {
        for card in &mut column.cards {
            let object_cell = format!("ak:cell:ak.component.strand.object.v1:{}", card.id);
            let lifecycle_cell = format!("ak:cell:ak.component.strand.lifecycle.v1:{}", card.id);
            let target_matches = |entry: &&arkret_sdk::CurrentResultEntry| matches!(entry.target(), arkret_sdk::CurrentTarget::Strand { strand_id } if strand_id.as_str() == card.id);
            let object_is_loaded = entries.iter().any(|entry| {
                entry.selector().cell_id.as_str() == object_cell && target_matches(&entry)
            });
            let mut matching = entries.iter().filter(|entry| {
                entry.selector().cell_id.as_str() == lifecycle_cell && target_matches(entry)
            });
            let Some(entry) = matching.next() else {
                if object_is_loaded {
                    card.lifecycle = StrandLifecycleState::Active;
                    card.lifecycle_basis_refs.clear();
                }
                continue;
            };
            if matching.next().is_some() {
                card.lifecycle = StrandLifecycleState::Unavailable;
                card.lifecycle_basis_refs.clear();
                continue;
            }
            match entry.result() {
                arkret_sdk::CurrentOutcome::Value { value, source } => {
                    card.lifecycle_basis_refs = source
                        .as_ref()
                        .map(|source| vec![source.event_id.event_digest()])
                        .unwrap_or_default();
                    card.lifecycle = match value.as_json().as_str() {
                        Some("active") => StrandLifecycleState::Active,
                        Some("archived") => StrandLifecycleState::Archived,
                        _ => {
                            card.lifecycle_basis_refs.clear();
                            StrandLifecycleState::Unavailable
                        }
                    };
                }
                arkret_sdk::CurrentOutcome::Removed => {
                    card.lifecycle = StrandLifecycleState::Active;
                    card.lifecycle_basis_refs.clear();
                }
                arkret_sdk::CurrentOutcome::Unavailable { .. } => {
                    card.lifecycle = StrandLifecycleState::Unavailable;
                    card.lifecycle_basis_refs.clear();
                }
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum CurrentRegisterBasis {
    Missing,
    Source(Vec<arkret_sdk::Hash>),
    Removed,
    Unavailable,
}

pub(crate) fn current_register_basis(
    entries: &[arkret_sdk::CurrentResultEntry],
    cell_id: &str,
) -> CurrentRegisterBasis {
    let mut matching = entries
        .iter()
        .filter(|entry| entry.selector().cell_id.as_str() == cell_id);
    let Some(entry) = matching.next() else {
        return CurrentRegisterBasis::Missing;
    };
    if matching.next().is_some() {
        return CurrentRegisterBasis::Unavailable;
    }
    match entry.result() {
        arkret_sdk::CurrentOutcome::Value { source, .. } => source
            .as_ref()
            .map(|source| CurrentRegisterBasis::Source(vec![source.event_id.event_digest()]))
            .unwrap_or(CurrentRegisterBasis::Unavailable),
        arkret_sdk::CurrentOutcome::Removed => CurrentRegisterBasis::Removed,
        arkret_sdk::CurrentOutcome::Unavailable { .. } => CurrentRegisterBasis::Unavailable,
    }
}

/// Replace lossy Space title/rank/lifecycle fields with their canonical
/// causal-register results. Missing or unavailable values never acquire an
/// arrival-order title, rank, or lifecycle.
pub(crate) fn install_current_space_cells(
    columns: &mut [KanbanColumn],
    entries: &[arkret_sdk::CurrentResultEntry],
) {
    for column in columns {
        if column.state == SpaceContainerLifecycleState::PositionUnavailable {
            continue;
        }
        let metadata_cell = format!("ak:cell:ak.component.space.metadata.v1:{}", column.id);
        let mut metadata = entries
            .iter()
            .filter(|entry| entry.selector().cell_id.as_str() == metadata_cell);
        if let Some(entry) = metadata.next() {
            if metadata.next().is_some() {
                column.state = SpaceContainerLifecycleState::Unavailable;
            } else {
                match entry.result() {
                    arkret_sdk::CurrentOutcome::Value { value, .. } => {
                        match serde_json::from_value::<arkret_sdk::Space>(value.as_json().clone()) {
                            Ok(space) => {
                                column.title = space.title;
                                column.rank = space.rank.unwrap_or_default();
                            }
                            Err(_) => column.state = SpaceContainerLifecycleState::Unavailable,
                        }
                    }
                    arkret_sdk::CurrentOutcome::Removed
                    | arkret_sdk::CurrentOutcome::Unavailable { .. } => {
                        column.state = SpaceContainerLifecycleState::Unavailable;
                    }
                }
            }
        }

        let lifecycle_cell = format!("ak:cell:ak.component.space.lifecycle.v1:{}", column.id);
        let mut lifecycle = entries
            .iter()
            .filter(|entry| entry.selector().cell_id.as_str() == lifecycle_cell);
        let Some(entry) = lifecycle.next() else {
            continue;
        };
        if lifecycle.next().is_some() {
            column.state = SpaceContainerLifecycleState::Unavailable;
            continue;
        }
        match entry.result() {
            arkret_sdk::CurrentOutcome::Value { value, .. } => {
                if column.state == SpaceContainerLifecycleState::Unavailable {
                    continue;
                }
                column.state = match value.as_json().as_str() {
                    Some("active") => SpaceContainerLifecycleState::Active,
                    Some("archived") => SpaceContainerLifecycleState::Archived,
                    Some("tombstoned") => SpaceContainerLifecycleState::Tombstoned,
                    _ => SpaceContainerLifecycleState::Unavailable,
                };
            }
            arkret_sdk::CurrentOutcome::Removed => {
                if column.state != SpaceContainerLifecycleState::Unavailable {
                    column.state = SpaceContainerLifecycleState::Active;
                }
            }
            arkret_sdk::CurrentOutcome::Unavailable { .. } => {
                column.state = SpaceContainerLifecycleState::Unavailable;
            }
        }
    }
}

fn clear_unavailable_card_content(card: &mut KanbanCard) {
    card.authoring_basis = None;
    card.title = "Card content unavailable".to_owned();
    card.description.clear();
    card.description_body.clear();
    card.synthesis.clear();
    card.labels.clear();
    card.due.clear();
    card.calendar = CalendarCardFields::default();
    card.calendar_schedule_basis_refs.clear();
    card.calendar_rsvp = CalendarRsvpDisplay::default();
    card.locked_strand = None;
    card.state = CardState::Quarantined;
}

/// Install object content from the same current entry that supplies its source
/// identity. Lifecycle/placement remain separate Control cells.
pub(crate) fn card_current_page(
    columns: &[KanbanColumn],
    page: usize,
    selected: Option<&KanbanCard>,
) -> (Vec<arkret_sdk::StrandId>, usize) {
    // Reserve one of the protocol's 32 targets for an open detail outside the page.
    const PAGE_SIZE: usize = 31;
    let mut seen = BTreeSet::new();
    let ids = columns
        .iter()
        .flat_map(|column| &column.cards)
        .filter_map(|card| arkret_sdk::StrandId::new(card.id.clone()).ok())
        .filter(|id| seen.insert(id.clone()))
        .collect::<Vec<_>>();
    let pages = ids.len().div_ceil(PAGE_SIZE).max(1);
    let mut requested = ids
        .into_iter()
        .skip(page.min(pages - 1) * PAGE_SIZE)
        .take(PAGE_SIZE)
        .collect::<Vec<_>>();
    if let Some(id) = selected.and_then(|card| arkret_sdk::StrandId::new(card.id.clone()).ok()) {
        if !requested.contains(&id) {
            requested.push(id);
        }
    }
    requested.sort();
    (requested, pages)
}

/// Content and authoring provenance are installed atomically for each card.
pub(crate) fn install_current_card_sources(
    columns: &mut [KanbanColumn],
    entries: &[arkret_sdk::CurrentResultEntry],
    projected: &[crate::state::projection_views::StrandProjectionView],
    decrypt_ctx: Option<&MlsDecryptCtx<'_>>,
    actor: &str,
) {
    for column in columns {
        let preserve_position_state =
            column.state == SpaceContainerLifecycleState::PositionUnavailable;
        for card in &mut column.cards {
            let mut matching = entries.iter().filter(|entry| {
            entry.selector().cell_id.as_str()
                == format!("ak:cell:ak.component.strand.object.v1:{}", card.id)
                && matches!(entry.target(), arkret_sdk::CurrentTarget::Strand { strand_id } if strand_id.as_str() == card.id)
        });
            let Some(entry) = matching.next() else {
                card.authoring_basis = None;
                if card.state == CardState::Synced {
                    clear_unavailable_card_content(card);
                }
                continue;
            };
            if matching.next().is_some() {
                clear_unavailable_card_content(card);
                continue;
            }
            let arkret_sdk::CurrentOutcome::Value { value, source } = entry.result() else {
                clear_unavailable_card_content(card);
                continue;
            };
            let Some(source) = source.as_ref() else {
                clear_unavailable_card_content(card);
                continue;
            };
            let Ok(strand) = value.as_strand() else {
                card.authoring_basis = None;
                card.state = CardState::Quarantined;
                continue;
            };
            let mut view = projected
                .iter()
                .find(|row| row.strand_id == card.id)
                .cloned()
                .unwrap_or_else(|| {
                    serde_json::from_value(serde_json::json!({
                        "strand_id": card.id, "realm_id": strand.realm_id, "state": "active"
                    }))
                    .expect("complete lifecycle view defaults")
                });
            let metadata = strand.metadata.unwrap_or_default();
            view.title = metadata.title.unwrap_or_default();
            view.summary = metadata.summary;
            view.fields = metadata.fields.into_iter().collect();
            view.content = strand.content;
            view.encrypted_content = strand.encrypted_content;
            view.tracks = strand.tracks;
            view.schema_refs = strand.schema_refs.unwrap_or_default();
            let mut complete = card_from_strand_projection_for_actor(&view, decrypt_ctx, actor);
            complete.rank = card.rank.clone();
            complete.position_basis_refs = card.position_basis_refs.clone();
            if preserve_position_state {
                complete.state = card.state;
            }
            if complete.calendar == card.calendar {
                complete.calendar_schedule_basis_refs = card.calendar_schedule_basis_refs.clone();
            }
            complete.calendar_rsvp = card.calendar_rsvp.clone();
            complete.lifecycle = card.lifecycle;
            complete.lifecycle_basis_refs = card.lifecycle_basis_refs.clone();
            complete.assignee = card.assignee.clone();
            complete.assigned_to_relations = card.assigned_to_relations.clone();
            complete.authoring_basis =
                Some((entry.selector().scope_ref.clone(), source.event_id.clone()));
            *card = complete;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const REALM: &str = "ak:realm:AeEFmfOZxsx5kLi2kpOJu8m7TFXZ_G8E4019rUp4wmT6";
    const BOARD: &str = "ak:space:AS3C70xWY61C92FHN-fwh70BB5DHc-kVXN2_nFVHXamA";
    const LIST_A: &str = "ak:space:AXDc1EwPcJZuThaCiR4FHq4V7rQ4I9QBR1YmEVB4xroH";
    const LIST_B: &str = "ak:space:AVcONsY9NXkyxnm3-GILG2GEKqeoyPiGmxPiVikKKl1t";
    const STRAND: &str = "ak:strand:AhEY3TQwXzS3vBpmyeK7Ki84MdgP5oV7KbS2ZGWOzK6y";

    /// `ak.space.create` is `id_source: event_derived`: the payload carries no
    /// `object.id`, and the Space is `retype(event_id)`. The fixture therefore
    /// names the Space by retyping `id` into the envelope's `event_id`, exactly
    /// as an authored create does.
    fn space_create_event(
        id: &str,
        kind: &str,
        title: &str,
        parent: Option<&str>,
    ) -> arkret_sdk::Event {
        let mut object = arkret_sdk::Space::create_object(
            sdk_realm_id(),
            kind,
            title,
            arkret_sdk::ActorId::account(arkret_sdk::AccountId::new(
                sdk_actor_id(),
                arkret_sdk::DidCoreId::new("ak:did_core:web:station.example").unwrap(),
            )),
        );
        if let Some(parent) = parent {
            object.parent_space_id = Some(arkret_sdk::SpaceId::new(parent).unwrap());
        }
        sdk_event(
            &event_id_naming(id, "ak:space:"),
            arkret_sdk::EventKind::SpaceCreate.as_str(),
            1,
            "2026-06-28T00:00:00.000Z",
            serde_json::to_value(arkret_sdk::SpaceCreatePayload::new(object)).unwrap(),
        )
    }

    /// The `event_id` a create must carry for the receiver to derive `object_id`.
    fn event_id_naming(object_id: &str, kind_prefix: &str) -> String {
        format!(
            "ak:event:{}",
            object_id
                .strip_prefix(kind_prefix)
                .expect("fixture object id carries its kind prefix")
        )
    }

    /// Mirrors the real canonical `ak.strand.create` envelope. It names the
    /// card and NOTHING about where the card sits: `strand.schema.json` forbids
    /// `board_space_id` / `list_space_id` / `rank` in `metadata.fields`, so a
    /// conforming create cannot carry placement. Use
    /// [`strand_create_and_place_events`] whenever the card must land in a list.
    fn strand_create_event(
        id: &str,
        actor: &str,
        title: &str,
        created_at: &str,
    ) -> arkret_sdk::Event {
        let mut object = arkret_sdk::StrandCreateObject::new(
            sdk_realm_id(),
            crate::mls_api_helpers::local_account_actor_id(actor).unwrap(),
        )
        .with_metadata_title(title)
        .with_metadata_field("strand_kind", json!("card"));
        object.created_at = created_at.parse().unwrap();
        sdk_event(
            &event_id_naming(id, "ak:strand:"),
            arkret_sdk::EventKind::StrandCreate.as_str(),
            2,
            created_at,
            serde_json::to_value(crate::operation::ak_ops::strand_create_payload(object).unwrap())
                .unwrap(),
        )
    }

    /// The authored card flow: `ak.strand.create` names the Strand, then the
    /// first `ak.strand.move` places it. The Move is authored only once the
    /// create receipt has named the Strand, so it is always strictly later.
    fn strand_create_and_place_events(
        id: &str,
        actor: &str,
        title: &str,
        board: &str,
        list: &str,
        rank: &str,
        created_at: &str,
    ) -> Vec<arkret_sdk::Event> {
        vec![
            strand_create_event(id, actor, title, created_at),
            strand_move_event(id, board, list, rank, &one_second_after(created_at)),
        ]
    }

    /// Timestamp for the placement Move that follows a create at `created_at`.
    /// The fold orders operations by `received_at`, so the first placement has
    /// to be observably later than the create it places.
    fn one_second_after(created_at: &str) -> String {
        let when = chrono::DateTime::parse_from_rfc3339(created_at)
            .expect("fixture timestamp is RFC3339")
            .checked_add_signed(chrono::Duration::seconds(1))
            .expect("fixture timestamp does not overflow")
            .with_timezone(&chrono::Utc);
        arkret_sdk::canonical::format_timestamp_canonical(when)
    }

    fn strand_move_event(
        id: &str,
        board: &str,
        target_list: &str,
        rank: &str,
        created_at: &str,
    ) -> arkret_sdk::Event {
        let mut event = sdk_event(
            &event_id_naming(id, "ak:strand:"),
            arkret_sdk::EventKind::StrandMove.as_str(),
            3,
            created_at,
            json!({
                "board_space_id": board,
                "strand_id": id,
                "target_space_id": target_list,
                "rank": rank,
            }),
        );
        event.event_id = event
            .derive_event_id_with_digest_suite(arkret_sdk::DigestSuite::Sha256)
            .unwrap();
        event
    }

    fn strand_archive_event(id: &str) -> arkret_sdk::Event {
        let mut event = sdk_event(
            &event_id_naming(id, "ak:strand:"),
            arkret_sdk::EventKind::StrandArchive.as_str(),
            4,
            "2026-06-28T02:00:00.000Z",
            json!({ "target_ref": id }),
        );
        event.event_id = event
            .derive_event_id_with_digest_suite(arkret_sdk::DigestSuite::Sha256)
            .unwrap();
        event
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
        crate::test_support::realm_id(REALM)
    }

    fn sdk_actor_id() -> arkret_sdk::DidCoreId {
        arkret_sdk::DidCoreId::new("ak:did_core:webvh:z6mkfixture:alice.example").unwrap()
    }

    fn sdk_event(
        event_id: &str,
        kind: &str,
        actor_seq: u64,
        created_at: &str,
        payload: Value,
    ) -> arkret_sdk::Event {
        let mut event = arkret_wire::test_support::raw_event(
            kind,
            arkret_sdk::ScopeRef::Realm {
                realm_id: sdk_realm_id(),
            },
            sdk_actor_id(),
            arkret_sdk::DidCoreId::new("ak:did_core:web:principal.example").unwrap(),
            actor_seq,
            arkret_sdk::Hlc::new("01970e589d21-0004-a13f9c2e").unwrap(),
            payload,
        )
        .unwrap();
        event.event_id = arkret_sdk::EventId::new(event_id).unwrap();
        event.created_at = created_at.parse().unwrap();
        event
    }

    fn current_position(
        strand_id: &str,
        event_id: arkret_sdk::EventId,
        list_space_id: &str,
        rank: &str,
    ) -> arkret_sdk::CurrentResultEntry {
        serde_json::from_value(json!({
            "selector": {
                "scope_ref": { "kind": "realm", "realm_id": REALM },
                "cell_id": strand_position_cell_id(BOARD, strand_id)
            },
            "target": { "kind": "strand", "strand_id": strand_id },
            "revision": 7,
            "result": {
                "status": "value",
                "value": { "list_space_id": list_space_id, "rank": rank },
                "source": { "event_id": event_id, "depth": 0 }
            }
        }))
        .unwrap()
    }

    fn current_lifecycle(
        strand_id: &str,
        event_id: arkret_sdk::EventId,
        state: &str,
    ) -> arkret_sdk::CurrentResultEntry {
        serde_json::from_value(json!({
            "selector": {
                "scope_ref": { "kind": "realm", "realm_id": REALM },
                "cell_id": format!("ak:cell:ak.component.strand.lifecycle.v1:{strand_id}")
            },
            "target": { "kind": "strand", "strand_id": strand_id },
            "revision": 8,
            "result": {
                "status": "value",
                "value": state,
                "source": { "event_id": event_id, "depth": 0 }
            }
        }))
        .unwrap()
    }

    fn current_space_metadata(
        space_id: &str,
        event_id: arkret_sdk::EventId,
        title: &str,
        rank: &str,
    ) -> arkret_sdk::CurrentResultEntry {
        serde_json::from_value(json!({
            "selector": {
                "scope_ref": { "kind": "realm", "realm_id": REALM },
                "cell_id": format!("ak:cell:ak.component.space.metadata.v1:{space_id}")
            },
            "target": { "kind": "realm" },
            "revision": 9,
            "result": {
                "status": "value",
                "value": {
                        "id": space_id,
                        "schema": "ak.schema.space.v1",
                        "realm_id": REALM,
                        "kind": "list",
                        "title": title,
                        "rank": rank,
                        "created_by": {"kind":"account","account_id":{
                            "principal_id":"ak:did_core:web:alice.example",
                            "station_id":"ak:did_core:web:station.example"
                        }},
                        "created_at": "2026-09-11T00:00:00.000Z"
                },
                "source": { "event_id": event_id, "depth": 0 }
            }
        }))
        .unwrap()
    }

    #[test]
    fn current_space_metadata_installs_the_protocol_winner() {
        let second = arkret_sdk::EventId::from_digest(arkret_sdk::DigestSuite::Sha256, [2; 32]);
        let entry = current_space_metadata(LIST_A, second, "Beta", "B");
        let mut columns = vec![KanbanColumn {
            id: LIST_A.to_owned(),
            title: "lossy last arrival".to_owned(),
            rank: "z".to_owned(),
            cards: Vec::new(),
            state: SpaceContainerLifecycleState::Active,
        }];

        install_current_space_cells(&mut columns, &[entry]);

        assert_eq!(columns[0].title, "Beta");
        assert_eq!(columns[0].rank, "B");
        assert_eq!(columns[0].state, SpaceContainerLifecycleState::Active);
    }

    #[derive(Default)]
    struct ClientCoreKanbanProjector {
        raw_operations: Vec<RawOperationRecord>,
    }

    impl garth::projection::RealmEventProjector for ClientCoreKanbanProjector {
        fn apply_domain_events(
            &mut self,
            _realm_id: &arkret_sdk::RealmId,
            events: &[arkret_sdk::Event],
        ) -> garth::Result<()> {
            self.raw_operations
                .extend(kanban_operations_from_events(events));
            Ok(())
        }
    }

    #[test]
    fn client_core_domain_projector_golden_matches_inkson_board_projection() {
        // Each create names its object by `retype(event_id)`, and carries no
        // `object.id` — the shape an authored create actually has.
        let card = "ak:strand:AbZt0K_NvenxSDAkOnSDRtorrvUXhGqxSoqT2bFL7m8H";
        let mut events = vec![
            space_create_event(BOARD, "board", "Board1", None),
            space_create_event(LIST_A, "list", "Todos", Some(BOARD)),
        ];
        events.extend(strand_create_and_place_events(
            card,
            "ak:did_core:webvh:z6mkfixture:alice.example",
            "golden card",
            BOARD,
            LIST_A,
            "U",
            "2026-07-08T00:00:02.000Z",
        ));
        let direct_ops = kanban_operations_from_events(&events);
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

    #[test]
    fn current_space_baseline_restores_prejoin_board_title_and_accepts_later_updates() {
        let projected = vec![
            crate::state::projection_views::SpaceContainerProjectionView {
                space_id: BOARD.to_owned(),
                realm_id: REALM.to_owned(),
                kind: "board".to_owned(),
                title: "Release board".to_owned(),
                state: arkret_sdk::ProjectionSpaceState::Active,
                rank: None,
                parent_space_id: None,
            },
            crate::state::projection_views::SpaceContainerProjectionView {
                space_id: LIST_A.to_owned(),
                realm_id: REALM.to_owned(),
                kind: "list".to_owned(),
                title: "Todo".to_owned(),
                state: arkret_sdk::ProjectionSpaceState::Active,
                rank: Some("U".to_owned()),
                parent_space_id: Some(BOARD.to_owned()),
            },
        ];
        let ops = vec![local_op(
            "op-board-rename-after-join",
            "2026-06-28T04:00:00.000Z",
            json!({
                "kind": "ak.space.update",
                "body": {
                    "space_id": BOARD,
                    "patch": {
                        "title": {"$op": "set", "value": "Release board 2"}
                    }
                }
            }),
        )];

        let containers = space_container_views_from_projection_and_ops(&projected, &ops, REALM);
        let options = board_space_options_from_projection(&containers);
        assert_eq!(options.len(), 1);
        assert_eq!(options[0].id.as_str(), BOARD);
        assert_eq!(options[0].title, "Release board 2");

        let projected_strands = vec![
            serde_json::from_value(json!({
                "strand_id": STRAND,
                "realm_id": REALM,
                "title": "Pre-join current card",
                "board_space_id": BOARD,
                "list_space_id": LIST_A,
                "rank": "U",
                "state": "active"
            }))
            .unwrap(),
        ];
        let (columns, _, selected) =
            project_board_with_projection(&ops, &projected, &projected_strands, BOARD, REALM, None);
        assert_eq!(selected.as_deref(), Some(BOARD));
        assert_eq!(columns.len(), 1);
        assert_eq!(columns[0].title, "Todo");
        assert_eq!(columns[0].cards.len(), 1);
        assert_eq!(columns[0].cards[0].title, "Pre-join current card");
    }

    /// The decisive cross-member test: two different members each create a card
    /// in the same list; the event-sourced projection MUST show BOTH, regardless
    /// of which session observed which create. This is exactly the symptom the
    /// old `list_strand_projections`-only card path failed (each member saw only
    /// their own card).
    #[test]
    fn two_members_card_creates_both_project_into_the_shared_list() {
        let mut events = vec![
            space_create_event(BOARD, "board", "Board1", None),
            space_create_event(LIST_A, "list", "Todos", Some(BOARD)),
        ];
        events.extend(strand_create_and_place_events(
            "ak:strand:AaDn_ypTG8vV4ToKfz6JtG2xnepF9QDlafPZCT-UYPyR",
            "ak:did_core:web:alice.example",
            "alice card",
            BOARD,
            LIST_A,
            "U",
            "2026-06-28T00:01:00.000Z",
        ));
        events.extend(strand_create_and_place_events(
            "ak:strand:AfHHAbZEhEweHE9b7WfITgHFGzMsezbGka7mm16yesUQ",
            "ak:did_core:web:bob.example",
            "bob card",
            BOARD,
            LIST_A,
            "V",
            "2026-06-28T00:02:00.000Z",
        ));
        let ops = kanban_operations_from_events(&events);
        let (columns, options, board_id) = project_board(&ops, BOARD, REALM, None);

        assert_eq!(board_id.as_deref(), Some(BOARD));
        assert!(options.iter().any(|option| option.id.as_str() == BOARD));
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
        let strand = "ak:strand:AbUSKDI2pz1ELsNdkqfrIZykyrA9jKL9yISLtXB_6qU5";
        let mut events = vec![
            space_create_event(BOARD, "board", "Board1", None),
            space_create_event(LIST_A, "list", "Todos", Some(BOARD)),
            space_create_event(LIST_B, "list", "Doing", Some(BOARD)),
        ];
        events.extend(strand_create_and_place_events(
            strand,
            "ak:did_core:web:alice.example",
            "moving card",
            BOARD,
            LIST_A,
            "U",
            "2026-06-28T00:01:00.000Z",
        ));
        events.push(strand_move_event(
            strand,
            BOARD,
            LIST_B,
            "U",
            "2026-06-28T01:00:00.000Z",
        ));
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
        let strand = "ak:strand:AdVU7b0NwVjyucaE-ZRGksbrifDFqHbytR9znwTjsAwy";
        let mut events = vec![
            space_create_event(BOARD, "board", "Board1", None),
            space_create_event(LIST_A, "list", "Todos", Some(BOARD)),
        ];
        events.extend(strand_create_and_place_events(
            strand,
            "ak:did_core:web:alice.example",
            "doomed card",
            BOARD,
            LIST_A,
            "U",
            "2026-06-28T00:01:00.000Z",
        ));
        events.push(strand_archive_event(strand));
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

    /// The queued `ak.strand.create` row `submit_kanban_card_create` writes.
    ///
    /// Its `body` is the real wire payload and therefore carries NO placement:
    /// the card is placed by the `ak.strand.move` authored after the create
    /// receipt. `effect` is the holder-local column that remembers where the
    /// user dropped the card, so the board can render it during the round trip.
    /// The Strand is `retype(event_id)` of the FINAL create, which does not
    /// exist yet, so the row keys the card by the write's holder-local handle.
    fn queued_card_create_op(
        operation_id: &str,
        received_at: &str,
        list_space_id: &str,
        title: &str,
        rank: &str,
    ) -> RawOperationRecord {
        local_op(
            operation_id,
            received_at,
            json!({
                "kind": "ak.strand.create",
                "operation_id": operation_id,
                "actor_id": "ak:did_core:web:alice.example",
                "created_at": received_at,
                "cell": format!("ak:cell:ak.component.strand.position.v1:{BOARD}:{operation_id}"),
                "effect": {
                    "board_space_id": BOARD,
                    "list_space_id": list_space_id,
                    "title": title,
                    "rank": rank,
                    "strand_kind": "card",
                    "strand_id": operation_id,
                },
                "wire_kind": "ak.strand.create",
                "body": {
                    "object": {
                        "realm_id": REALM,
                        "created_by": "ak:did_core:web:alice.example",
                        "metadata": {
                            "title": title,
                            "fields": { "strand_kind": "card" }
                        }
                    }
                },
                "local_target_ref": operation_id,
                "write_state": "queued",
            }),
        )
    }

    /// The window this projection exists for: the create is queued, its first
    /// `ak.strand.move` cannot be authored yet (the Strand has no canonical id
    /// until the receipt lands) and the server projection knows nothing. The
    /// card MUST still appear in the column the user dropped it into.
    #[test]
    fn local_optimistic_card_create_op_projects_into_its_list() {
        let ops = [
            kanban_operations_from_events(&[
                space_create_event(BOARD, "board", "Board1", None),
                space_create_event(LIST_A, "list", "Todos", Some(BOARD)),
                space_create_event(LIST_B, "list", "Doing", Some(BOARD)),
            ]),
            vec![queued_card_create_op(
                "op-create-1",
                "2026-06-28T00:05:00.000Z",
                LIST_A,
                "queued card",
                "U",
            )],
        ]
        .concat();
        let (columns, ..) = project_board(&ops, BOARD, REALM, None);
        let todos = columns
            .iter()
            .find(|column| column.title == "Todos")
            .unwrap();
        let doing = columns
            .iter()
            .find(|column| column.title == "Doing")
            .unwrap();
        assert_eq!(
            todos.cards.len(),
            1,
            "optimistic create lands in the dropped-on list before its Move exists"
        );
        assert_eq!(todos.cards[0].title, "queued card");
        assert_eq!(todos.cards[0].id, "op-create-1");
        assert!(
            doing.cards.is_empty(),
            "the optimistic card belongs to exactly one column"
        );
    }

    /// A create Event on its own places nothing. Without the queued write's
    /// holder-local `effect` — i.e. for any create observed from the log,
    /// local or remote — the Strand stays unplaced until an `ak.strand.move`
    /// is folded. This is the read-side half of the create-time-placement
    /// decision: no create payload member may reintroduce a position.
    #[test]
    fn strand_create_without_move_places_no_card() {
        let strand = "ak:strand:AZ4uMkJmy1EmXWTZbtWEDsSNwt-63nCC5vNVKUCLdG9U";
        let ops = kanban_operations_from_events(&[
            space_create_event(BOARD, "board", "Board1", None),
            space_create_event(LIST_A, "list", "Todos", Some(BOARD)),
            strand_create_event(
                strand,
                "ak:did_core:web:alice.example",
                "unplaced card",
                "2026-06-28T00:01:00.000Z",
            ),
        ]);
        let views = strand_views_from_ops(&ops);
        let view = views
            .iter()
            .find(|view| view.strand_id == strand)
            .expect("the create still names a Strand");
        assert_eq!(view.title, "unplaced card");
        assert_eq!(view.board_space_id, None);
        assert_eq!(view.list_space_id, None);
        assert_eq!(view.rank, None);

        let (columns, ..) = project_board(&ops, BOARD, REALM, None);
        let todos = columns
            .iter()
            .find(|column| column.title == "Todos")
            .unwrap();
        assert!(
            todos.cards.is_empty(),
            "an unplaced Strand belongs to no List"
        );
    }

    /// The same create, now with its placement Move: the card appears, proving
    /// the Move is the only placement carrier the fold honours.
    #[test]
    fn strand_move_places_a_created_card() {
        let strand = "ak:strand:AZ4uMkJmy1EmXWTZbtWEDsSNwt-63nCC5vNVKUCLdG9U";
        let mut events = vec![
            space_create_event(BOARD, "board", "Board1", None),
            space_create_event(LIST_A, "list", "Todos", Some(BOARD)),
        ];
        events.extend(strand_create_and_place_events(
            strand,
            "ak:did_core:web:alice.example",
            "placed card",
            BOARD,
            LIST_A,
            "U",
            "2026-06-28T00:01:00.000Z",
        ));
        let ops = kanban_operations_from_events(&events);
        let (columns, ..) = project_board(&ops, BOARD, REALM, None);
        let todos = columns
            .iter()
            .find(|column| column.title == "Todos")
            .unwrap();
        assert_eq!(todos.cards.len(), 1);
        assert_eq!(todos.cards[0].title, "placed card");
    }

    #[test]
    fn canonical_position_winner_overrides_arrival_order_projection() {
        let mut events = vec![
            space_create_event(BOARD, "board", "Board1", None),
            space_create_event(LIST_A, "list", "Todos", Some(BOARD)),
            space_create_event(LIST_B, "list", "Doing", Some(BOARD)),
        ];
        events.extend(strand_create_and_place_events(
            STRAND,
            "ak:did_core:web:alice.example",
            "card",
            BOARD,
            LIST_A,
            "A",
            "2026-06-28T00:01:00.000Z",
        ));
        events.push(strand_move_event(
            STRAND,
            BOARD,
            LIST_B,
            "B",
            "2026-06-28T00:02:00.000Z",
        ));
        let ops = kanban_operations_from_events(&events);
        let projected = strand_views_from_ops(&ops);
        let (mut columns, ..) = project_board(&ops, BOARD, REALM, None);
        assert!(
            columns
                .iter()
                .find(|column| column.id == LIST_B)
                .unwrap()
                .cards
                .iter()
                .any(|card| card.id == STRAND)
        );

        let head = arkret_sdk::EventId::from_digest(arkret_sdk::DigestSuite::Sha256, [0x31; 32]);
        let current = current_position(STRAND, head.clone(), LIST_A, "C");
        install_current_strand_positions(&mut columns, &[current], &projected, BOARD, None, "");

        let card = columns
            .iter()
            .find(|column| column.id == LIST_A)
            .unwrap()
            .cards
            .iter()
            .find(|card| card.id == STRAND)
            .expect("the sole canonical head places the card");
        assert_eq!(card.rank, "C");
        assert_eq!(card.position_basis_refs, vec![head.event_digest()]);
        assert!(
            !columns
                .iter()
                .find(|column| column.id == LIST_B)
                .unwrap()
                .cards
                .iter()
                .any(|card| card.id == STRAND)
        );
    }

    #[test]
    fn concurrent_position_winner_is_placed_without_conflict_ui() {
        let mut events = vec![
            space_create_event(BOARD, "board", "Board1", None),
            space_create_event(LIST_A, "list", "Todos", Some(BOARD)),
            space_create_event(LIST_B, "list", "Doing", Some(BOARD)),
        ];
        events.extend(strand_create_and_place_events(
            STRAND,
            "ak:did_core:web:alice.example",
            "conflicted card",
            BOARD,
            LIST_A,
            "A",
            "2026-06-28T00:01:00.000Z",
        ));
        let ops = kanban_operations_from_events(&events);
        let projected = strand_views_from_ops(&ops);
        let (mut columns, ..) = project_board(&ops, BOARD, REALM, None);
        let head_b = arkret_sdk::EventId::from_digest(arkret_sdk::DigestSuite::Sha256, [0x42; 32]);
        let current = current_position(STRAND, head_b.clone(), LIST_B, "B");
        install_current_strand_positions(&mut columns, &[current], &projected, BOARD, None, "");

        let card = columns
            .iter()
            .find(|column| column.id == LIST_B)
            .expect("winner list exists")
            .cards
            .iter()
            .find(|card| card.id == STRAND)
            .expect("deterministic winner places the card");
        assert_eq!(card.state, CardState::Synced);
        assert_eq!(card.position_basis_refs, vec![head_b.event_digest()]);
    }

    #[test]
    fn canonical_lifecycle_winner_overrides_arrival_order_projection() {
        let mut events = vec![
            space_create_event(BOARD, "board", "Board1", None),
            space_create_event(LIST_A, "list", "Todos", Some(BOARD)),
        ];
        events.extend(strand_create_and_place_events(
            STRAND,
            "ak:did_core:web:alice.example",
            "card",
            BOARD,
            LIST_A,
            "A",
            "2026-06-28T00:01:00.000Z",
        ));
        let ops = kanban_operations_from_events(&events);
        let (mut columns, ..) = project_board(&ops, BOARD, REALM, None);
        let head = arkret_sdk::EventId::from_digest(arkret_sdk::DigestSuite::Sha256, [0x51; 32]);
        let current = current_lifecycle(STRAND, head.clone(), "archived");

        install_current_strand_lifecycles(&mut columns, &[current]);

        let card = columns
            .iter()
            .flat_map(|column| &column.cards)
            .find(|card| card.id == STRAND)
            .unwrap();
        assert_eq!(card.lifecycle, StrandLifecycleState::Archived);
        assert_eq!(card.lifecycle_basis_refs, vec![head.event_digest()]);
    }

    #[test]
    fn concurrent_lifecycle_winner_is_used_without_conflict_ui() {
        let mut events = vec![
            space_create_event(BOARD, "board", "Board1", None),
            space_create_event(LIST_A, "list", "Todos", Some(BOARD)),
        ];
        events.extend(strand_create_and_place_events(
            STRAND,
            "ak:did_core:web:alice.example",
            "card",
            BOARD,
            LIST_A,
            "A",
            "2026-06-28T00:01:00.000Z",
        ));
        let ops = kanban_operations_from_events(&events);
        let (mut columns, ..) = project_board(&ops, BOARD, REALM, None);
        let head_b = arkret_sdk::EventId::from_digest(arkret_sdk::DigestSuite::Sha256, [0x62; 32]);
        let current = current_lifecycle(STRAND, head_b.clone(), "archived");

        install_current_strand_lifecycles(&mut columns, &[current]);

        let card = columns
            .iter()
            .flat_map(|column| &column.cards)
            .find(|card| card.id == STRAND)
            .unwrap();
        assert_eq!(card.lifecycle, StrandLifecycleState::Archived);
        assert_eq!(card.lifecycle_basis_refs, vec![head_b.event_digest()]);
    }

    /// Live incident (2026-08-19): final authoring changes a create's
    /// content-bound Event id, so the accepted Board id differs from the
    /// draft-time handle in `unsigned.local_target_ref`, and a List created
    /// while the accept receipt was in flight references the DRAFT handle as
    /// its parent. With no local optimistic rows (fresh device / merged rows),
    /// the unsigned hint is the only alias source. It must resolve the board
    /// selection AND the dangling parent — otherwise the switcher shows the
    /// raw draft id and the board renders "No lists yet".
    #[test]
    fn accepted_create_draft_handle_hint_aliases_selection_and_children() {
        let draft_board = "ak:space:AaDn_ypTG8vV4ToKfz6JtG2xnepF9QDlafPZCT-UYPyR";
        let mut board_create = space_create_event(BOARD, "board", "Board1", None);
        board_create
            .unsigned
            .insert("local_target_ref".to_owned(), json!(draft_board));
        let list_create = space_create_event(LIST_A, "list", "Todos", Some(draft_board));

        let ops = kanban_operations_from_events(&[board_create, list_create]);
        let (columns, options, board_id) = project_board(&ops, draft_board, REALM, None);

        assert_eq!(
            board_id.as_deref(),
            Some(BOARD),
            "the draft handle resolves to the accepted Board id"
        );
        assert_eq!(
            options.len(),
            1,
            "no phantom fallback board is minted for the draft parent"
        );
        assert_eq!(options[0].id.as_str(), BOARD);
        assert_eq!(options[0].title, "Board1", "the Board keeps its title");
        assert_eq!(columns.len(), 1, "the draft-parented list attaches");
        assert_eq!(columns[0].title, "Todos");
    }

    /// The unsigned draft-handle hint is producer-controlled. A hint that
    /// claims ANOTHER accepted object's id must never alias that object away.
    #[test]
    fn draft_handle_hint_cannot_alias_an_accepted_object_away() {
        let mut second_board = space_create_event(LIST_B, "board", "Board2", None);
        second_board
            .unsigned
            .insert("local_target_ref".to_owned(), json!(BOARD));
        let ops = kanban_operations_from_events(&[
            space_create_event(BOARD, "board", "Board1", None),
            second_board,
        ]);
        let aliases = event_derived_target_aliases(&ops);
        assert!(
            !aliases.contains_key(BOARD),
            "an accepted Board id must not be redirected by an unsigned hint"
        );
        let (_, options, board_id) = project_board(&ops, BOARD, REALM, None);
        assert_eq!(board_id.as_deref(), Some(BOARD));
        assert!(options.iter().any(|option| option.title == "Board1"));
        assert!(options.iter().any(|option| option.title == "Board2"));
    }

    #[test]
    fn accepted_create_identity_migration_dedupes_list_and_card_backfill() {
        let temporary_list = LIST_A;
        let canonical_list = LIST_B;
        let temporary_card = "ak:strand:AaDn_ypTG8vV4ToKfz6JtG2xnepF9QDlafPZCT-UYPyR";
        let canonical_card = "ak:strand:AfHHAbZEhEweHE9b7WfITgHFGzMsezbGka7mm16yesUQ";
        let list_operation_alias = "ak:operation:01904100-0000-7000-8000-000000000091";
        let card_operation_alias = "ak:operation:01904100-0000-7000-8000-000000000092";
        let mut canonical_list_create =
            space_create_event(canonical_list, "list", "Todo", Some(BOARD));
        canonical_list_create.unsigned.insert(
            "local_operation_idempotency_alias".to_owned(),
            json!(list_operation_alias),
        );
        let mut canonical_card_create = strand_create_event(
            canonical_card,
            "ak:did_core:web:alice.example",
            "same card",
            "2026-06-28T00:02:00.000Z",
        );
        canonical_card_create.unsigned.insert(
            "local_operation_idempotency_alias".to_owned(),
            json!(card_operation_alias),
        );
        // The placement Move may still reference the optimistic List id when
        // both writes were authored close together. The accepted List alias
        // must migrate this placement as well as the List row itself.
        let canonical_card_place = strand_move_event(
            canonical_card,
            BOARD,
            temporary_list,
            "U",
            "2026-06-28T00:02:01.000Z",
        );

        let mut ops = kanban_operations_from_events(&[
            space_create_event(BOARD, "board", "Board1", None),
            canonical_list_create,
            canonical_card_create,
            canonical_card_place,
        ]);
        ops.push(local_op(
            list_operation_alias,
            "2026-06-28T00:00:01.000Z",
            json!({
                "kind": "ak.space.create",
                "operation_id": list_operation_alias,
                "local_target_ref": temporary_list,
                "write_state": "queued",
                "body": {
                    "object": {
                        "kind": "list",
                        "title": "Todo",
                        "realm_id": REALM,
                        "parent_space_id": BOARD,
                    }
                },
            }),
        ));
        ops.push(local_op(
            card_operation_alias,
            "2026-06-28T00:01:01.000Z",
            json!({
                "kind": "ak.strand.create",
                "operation_id": card_operation_alias,
                "local_target_ref": temporary_card,
                "write_state": "queued",
                // Holder-local placement of the optimistic card, keyed by the
                // still-optimistic List handle: both sides of the alias have to
                // migrate, or the accepted card and its optimistic twin end up
                // in two different columns.
                "effect": {
                    "board_space_id": BOARD,
                    "list_space_id": temporary_list,
                    "title": "same card",
                    "rank": "U",
                    "strand_kind": "card",
                    "strand_id": temporary_card,
                },
                "body": {
                    "object": {
                        "schema": "ak.schema.strand.v1",
                        "realm_id": REALM,
                        "metadata": {
                            "title": "same card",
                            "fields": { "strand_kind": "card" }
                        }
                    }
                },
            }),
        ));

        let (columns, ..) = project_board(&ops, BOARD, REALM, None);
        assert_eq!(columns.len(), 1, "List alias and backfill are one List");
        assert_eq!(columns[0].id, canonical_list);
        assert_eq!(
            columns[0].cards.len(),
            1,
            "Card alias and backfill are one Card"
        );
        assert_eq!(columns[0].cards[0].id, canonical_card);
        assert_eq!(columns[0].cards[0].title, "same card");
    }

    /// The local position update (from `submit_strand_position_move`) carries
    /// the canonical `strand_move_payload` in `body`; folding it relocates the
    /// card without waiting for a server round-trip.
    #[test]
    fn local_optimistic_position_update_relocates_card() {
        let strand = "ak:strand:AehHUAw7pG3uDCWpiYTXKGpYyIQ9S_ZjiBFq0AkbTrVN";
        let mut events = vec![
            space_create_event(BOARD, "board", "Board1", None),
            space_create_event(LIST_A, "list", "Todos", Some(BOARD)),
            space_create_event(LIST_B, "list", "Doing", Some(BOARD)),
        ];
        events.extend(strand_create_and_place_events(
            strand,
            "ak:did_core:web:alice.example",
            "moving card",
            BOARD,
            LIST_A,
            "U",
            "2026-06-28T00:01:00.000Z",
        ));
        let mut ops = kanban_operations_from_events(&events);
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
        let actor = "ak:did_core:web:alice.example";
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
            .payload()
            .clone()
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
    fn real_position_update_builder_relocates_card() {
        let strand = "ak:strand:ATNM2hIwr2IImD7_Vm-Ze42J3ky6Xpa4CG1kNnH8_Zf3";
        let move_body = crate::operation::ak_ops::strand_position_update(
            REALM,
            "ak:did_core:web:alice.example",
            "ak.strand.move",
            BOARD,
            strand,
            json!({ "list_space_id": LIST_A, "rank": "U" }),
            json!({ "list_space_id": LIST_B, "rank": "U" }),
        )
        .unwrap()
        .build_sdk_event("inkson")
        .unwrap()
        .payload()
        .clone();
        let mut events = vec![
            space_create_event(BOARD, "board", "Board1", None),
            space_create_event(LIST_A, "list", "Todos", Some(BOARD)),
            space_create_event(LIST_B, "list", "Doing", Some(BOARD)),
        ];
        events.extend(strand_create_and_place_events(
            strand,
            "ak:did_core:web:alice.example",
            "moving card",
            BOARD,
            LIST_A,
            "U",
            "2026-06-28T00:01:00.000Z",
        ));
        let mut ops = kanban_operations_from_events(&events);
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
            sdk_event(
                "ak:event:AZDc1EwPcJZuThaCiR4FHq4V7rQ4I9QBR1YmEVB4xroH",
                arkret_sdk::EventKind::MessageCreate.as_str(),
                8,
                "2026-06-28T03:00:00.000Z",
                json!({}),
            ),
            sdk_event(
                "ak:event:AXDc1EwPcJZuThaCiR4FHq4V7rQ4I9QBR1YmEVB4xroH",
                arkret_sdk::EventKind::MlsCommit.as_str(),
                9,
                "2026-06-28T03:00:01.000Z",
                json!({}),
            ),
        ];
        let ops = kanban_operations_from_events(&events);
        assert_eq!(ops.len(), 1, "non-kanban kinds are dropped by the funnel");
    }
}
