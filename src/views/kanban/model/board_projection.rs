//! Kanban presentation and pending local-operation overlays.
//!
//! Complete object content and its authority-signed revision come from the
//! Realm snapshot's typed current result for each Strand. The projection rows
//! and the folded Event stream supply placement, lifecycle and audit context;
//! they are never a substitute for that current result. The production caller
//! installs current before applying pending UI overlays.

use arkret_wire::event_kind_str;

use super::*;

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

fn accepted_schedule_source(record: &RawOperationRecord) -> Option<String> {
    if let Some(write_state) = record.payload.get("write_state").and_then(Value::as_str)
        && !matches!(write_state, "accepted" | "synced")
    {
        return None;
    }
    let event_id = record
        .payload
        .get("event_id")
        .and_then(Value::as_str)
        .or_else(|| {
            record
                .operation_id
                .starts_with("ak:event:")
                .then_some(record.operation_id.as_str())
        })?;
    arkret_sdk::EventId::new(event_id.to_owned())
        .ok()
        .map(|event_id| event_id.event_digest().to_string())
}

fn patch_touches_calendar_schedule(patch: &Value) -> bool {
    patch.as_object().is_some_and(|entries| {
        entries.keys().any(|path| {
            path == "metadata"
                || path == "metadata.fields"
                || path == "metadata.fields.calendar"
                || path.starts_with("metadata.fields.calendar.")
        })
    })
}

/// Pick only from original coordinates retained by the accepted-page funnel.
/// A current object's revision alone is not an eligible schedule Event.
pub(crate) fn canonical_calendar_source(
    operations: &[RawOperationRecord],
    strand_id: &arkret_sdk::StrandId,
    stream: &arkret_sdk::CommitStreamRef,
    revision: &arkret_sdk::CurrentRevision,
    state: &crate::state::LocalStateStore,
) -> Option<String> {
    let mut winner: Option<(u64, arkret_sdk::EventId)> = None;
    for record in operations {
        let Some(commit) = record.payload.get("accepted_commit").and_then(|value| {
            serde_json::from_value::<arkret_sdk::RealmCommit>(value.clone()).ok()
        }) else {
            continue;
        };
        let Some(event) = record
            .payload
            .get("event")
            .and_then(|value| serde_json::from_value::<arkret_sdk::Event>(value.clone()).ok())
        else {
            continue;
        };
        if commit.event_ref != event.event_id
            || commit.realm_id != event.realm_id
            || &commit.stream_ref != stream
            || arkret_sdk::CommitStreamRef::from_scope(
                &event.scope_ref,
                Some(event.realm_id.clone()),
            )
            .ok()
            .as_ref()
                != Some(stream)
            || commit.stream_position > revision.stream_position
            || (commit.stream_position == revision.stream_position
                && commit.commit_id != revision.commit_id)
        {
            continue;
        }
        let eligible = match event.kind {
            arkret_sdk::EventKind::StrandCreate => {
                &arkret_sdk::StrandId::from_event_id(&event.event_id) == strand_id
                    && event.payload.get("object").is_some_and(|object| {
                        object.pointer("/metadata/fields/calendar").is_some()
                            || (object.get("encrypted_metadata").is_some()
                                && object
                                    .get("schema_refs")
                                    .and_then(Value::as_array)
                                    .is_some_and(|refs| {
                                        refs.iter().any(|value| {
                                            value.as_str() == Some("ak.schema.calendar_event.v1")
                                        })
                                    }))
                    })
            }
            arkret_sdk::EventKind::StrandUpdate => {
                event.payload.get("target_ref").and_then(Value::as_str) == Some(strand_id.as_str())
                    && event.payload.get("patch").is_some_and(|patch| {
                        // This is a replacement of the complete Metadata object,
                        // unlike a signed title-only plaintext path.
                        patch.get("encrypted_metadata").is_some()
                            || patch_touches_calendar_schedule(patch)
                    })
            }
            _ => false,
        };
        if eligible
            && winner
                .as_ref()
                .is_none_or(|(position, _)| commit.stream_position > *position)
        {
            winner = Some((commit.stream_position, event.event_id));
        }
    }
    let (position, event) = winner?;
    state
        .verified_commit_partition_complete_through(stream, position, revision.stream_position)
        .then(|| event.event_digest().to_string())
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
    let has_calendar_schedule = fields.contains_key("calendar");
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
        // The accepted Event establishes the schedule source. A queued draft
        // has no authoritative basis and must keep RSVP authoring closed.
        schema_refs: Vec::new(),
        rsvps: Vec::new(),
        schedule_revision_source: has_calendar_schedule
            .then(|| accepted_schedule_source(record))
            .flatten(),
        state: arkret_sdk::ObjectState::Active,
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

/// Fold an accepted `ak.rsvp.set` into the Strand's local RSVP projection.
///
/// The Realm snapshot carries no RSVP selector, so the Strand's own accepted
/// Event stream is the client-side source. A typed target is updated in Commit
/// order (`authz/event-auth-state-resolution.md` section 6), so the responder's
/// most recently folded write is the current one; earlier writes stay as replay
/// evidence and never become a second displayed answer.
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
            source_event_digest: source_event_digest.clone(),
            entry: entry.clone(),
            ..Default::default()
        });
    cell.winner = Some(crate::state::projection_views::RsvpWinnerProjectionView {
        source_event_id: event_id.to_string(),
        source_event_digest,
        entry,
    });
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
                        if current.schedule_revision_source.is_none() {
                            current.schedule_revision_source = view.schedule_revision_source;
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
                    view.state = arkret_sdk::ObjectState::Archived;
                }
            }
            event_kind_str::STRAND_RESTORE => {
                if let Some(id) = op_strand_target_id(record)
                    .map(|id| resolve_event_derived_target_alias(&aliases, &id))
                    && let Some(view) = by_id.get_mut(&id)
                {
                    view.state = arkret_sdk::ObjectState::Active;
                }
            }
            event_kind_str::STRAND_UPDATE => {
                if let Some(id) = op_strand_target_id(record)
                    .map(|id| resolve_event_derived_target_alias(&aliases, &id))
                    && let Some(view) = by_id.get_mut(&id)
                    && op_body(record)
                        .and_then(|body| body.get("patch"))
                        .is_some_and(patch_touches_calendar_schedule)
                    && let Some(source) = accepted_schedule_source(record)
                {
                    view.schedule_revision_source = Some(source);
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
    space_container_views_from_projection_and_ops(&[], ops, realm_id, &[])
}

/// Merge the current Space projection baseline with visible/local Events.
/// A current Board/List remains renderable even when its create Event is
/// outside the caller's `since_join` history window.
pub(crate) fn space_container_views_from_projection_and_ops(
    projected: &[crate::state::projection_views::SpaceContainerProjectionView],
    ops: &[RawOperationRecord],
    realm_id: &str,
    current_entries: &[arkret_wire::TypedCurrentResult],
) -> Vec<crate::state::projection_views::SpaceContainerProjectionView> {
    let terminal_ids = terminal_space_ids_from_current(current_entries, realm_id);
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
    let current = space_container_views_from_current(current_entries, realm_id);
    let current_ids = current
        .iter()
        .map(|view| view.space_id.clone())
        .collect::<BTreeSet<_>>();
    for view in current {
        if !by_id.contains_key(&view.space_id) {
            order.push(view.space_id.clone());
        }
        by_id.insert(view.space_id.clone(), view);
    }
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
            let Some(local_realm_id) = local.realm_id.take() else {
                continue;
            };
            local.id = resolve_event_derived_target_alias(&aliases, &local.id);
            if terminal_ids.contains(&local.id) {
                continue;
            }
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
                    realm_id: local_realm_id,
                    kind: local.kind,
                    title: local.title,
                    state: arkret_sdk::SpaceState::Active,
                    rank: local.rank,
                    parent_space_id: local.parent_space_id,
                },
            );
            continue;
        }
        let Some(kind) = op_kind(record) else {
            continue;
        };
        if op_space_target_id(record).is_some_and(|id| current_ids.contains(&id))
            && !matches!(
                record.payload.get("write_state").and_then(Value::as_str),
                Some("queued" | "submitting" | "submitted")
            )
        {
            // Current has already selected the accepted metadata/lifecycle.
            // Only a pending local edit may overlay that value.
            continue;
        }
        match kind.as_str() {
            event_kind_str::SPACE_UPDATE => {
                if let Some(id) = op_space_target_id(record)
                    .map(|id| resolve_event_derived_target_alias(&aliases, &id))
                    && let Some(view) = by_id.get_mut(&id)
                    && view.state != arkret_sdk::SpaceState::Tombstoned
                {
                    apply_space_update_to_view(view, record);
                }
            }
            event_kind_str::SPACE_ARCHIVE => {
                if let Some(id) = op_space_target_id(record)
                    .map(|id| resolve_event_derived_target_alias(&aliases, &id))
                    && let Some(view) = by_id.get_mut(&id)
                    && view.state != arkret_sdk::SpaceState::Tombstoned
                {
                    view.state = arkret_sdk::SpaceState::Archived;
                }
            }
            event_kind_str::SPACE_RESTORE => {
                if let Some(id) = op_space_target_id(record)
                    .map(|id| resolve_event_derived_target_alias(&aliases, &id))
                    && let Some(view) = by_id.get_mut(&id)
                    && view.state != arkret_sdk::SpaceState::Tombstoned
                {
                    view.state = arkret_sdk::SpaceState::Active;
                }
            }
            _ => {}
        }
    }
    order
        .into_iter()
        .filter(|id| !terminal_ids.contains(id))
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
        &[],
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
    current_entries: &[arkret_wire::TypedCurrentResult],
) -> (Vec<KanbanColumn>, Vec<BoardSpaceOption>, Option<String>) {
    let aliases = event_derived_target_aliases(ops);
    let preferred_board_id = resolve_event_derived_target_alias(&aliases, preferred_board_id);
    let mut containers = space_container_views_from_projection_and_ops(
        projected_containers,
        ops,
        realm_id,
        current_entries,
    );
    if let Some(ctx) = decrypt_ctx {
        if let Some((account, device)) = ctx.identity {
            if let Ok(device) = arkret_sdk::DeviceId::new(device.to_owned()) {
                for view in &mut containers {
                    if let Some(title) = crate::views::metadata::current_title(
                        ctx.state_store,
                        realm_id,
                        &view.space_id,
                        account,
                        &device,
                    ) {
                        view.title = title;
                    }
                }
            }
        }
    }
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

/// Readiness of the Station's typed current result for one Strand.
///
/// The snapshot carries the whole Strand object under
/// `CurrentSelector::Strand`, signed at an exact `RealmCommit` revision, so
/// this is what an authoring surface consults before it writes: it must never
/// author against a Strand it has not observed, and it never re-derives the
/// value from Event order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum StrandCurrentBasis {
    /// The Realm snapshot has not delivered this Strand's current result yet.
    Missing,
    /// Delivered, at this authority-signed revision.
    Revision(arkret_wire::CurrentRevision),
    /// Delivered more than once, or not as a decodable value.
    Unavailable,
}

pub(crate) fn strand_current_basis(
    entries: &[arkret_wire::TypedCurrentResult],
    strand_id: &arkret_sdk::StrandId,
) -> StrandCurrentBasis {
    let selector = arkret_wire::CurrentSelector::Strand {
        strand_id: strand_id.clone(),
    };
    let mut matching = entries.iter().filter(|entry| {
        let arkret_wire::TypedCurrentResult::Value {
            selector: found, ..
        } = entry;
        *found == selector
    });
    let Some(arkret_wire::TypedCurrentResult::Value { revision, .. }) = matching.next() else {
        return StrandCurrentBasis::Missing;
    };
    if matching.next().is_some() {
        return StrandCurrentBasis::Unavailable;
    }
    StrandCurrentBasis::Revision(revision.clone())
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

/// The Strand ids whose typed current result the board should demand, bounded
/// to the protocol's per-request target budget.
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

/// Install object content and its authority-signed revision for each card.
///
/// The Realm snapshot's `CurrentSelector::Strand` result is the complete Strand
/// object the governance Station selected, signed at an exact `RealmCommit`
/// revision. Placement, lifecycle and assignment stay on the projection rows
/// this card was folded from; they are not re-derived here.
pub(crate) fn install_current_card_sources(
    columns: &mut [KanbanColumn],
    entries: &[arkret_wire::TypedCurrentResult],
    projected: &[crate::state::projection_views::StrandProjectionView],
    operations: &[RawOperationRecord],
    decrypt_ctx: Option<&MlsDecryptCtx<'_>>,
    actor: &str,
) {
    for column in columns {
        for card in &mut column.cards {
            let Ok(strand_id) = arkret_sdk::StrandId::new(card.id.clone()) else {
                continue;
            };
            let basis = strand_current_basis(entries, &strand_id);
            let revision = match basis {
                StrandCurrentBasis::Missing => {
                    card.authoring_basis = None;
                    if card.state == CardState::Synced {
                        clear_unavailable_card_content(card);
                    }
                    continue;
                }
                StrandCurrentBasis::Unavailable => {
                    clear_unavailable_card_content(card);
                    continue;
                }
                StrandCurrentBasis::Revision(revision) => revision,
            };
            let Some(strand) = current_strand_value(entries, &strand_id) else {
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
            let opened_metadata = decrypt_ctx.and_then(|ctx| {
                let (account, device) = ctx.identity?;
                let device = arkret_sdk::DeviceId::new(device.to_owned()).ok()?;
                let envelope = strand.encrypted_metadata.as_ref()?;
                let value = crate::views::metadata::open_metadata(
                    ctx.state_store,
                    ctx.realm_id,
                    &card.id,
                    envelope,
                    account,
                    &device,
                )?;
                serde_json::from_value::<arkret_sdk::StrandMetadata>(value).ok()
            });
            let readable = opened_metadata.is_some() || strand.encrypted_metadata.is_none();
            let metadata = opened_metadata
                .or(strand.metadata.clone())
                .unwrap_or_default();
            if readable {
                let mut checked = strand.clone();
                checked.encrypted_metadata = None;
                checked.metadata = Some(metadata.clone());
                if checked.validate_profile_activation().is_err()
                    || arkret_models_collaboration::objects::productivity::validate_calendar_event_metadata_fields(&metadata.fields).is_err()
                {
                    clear_unavailable_card_content(card);
                    continue;
                }
            }
            view.title = metadata.title.unwrap_or_default();
            view.summary = metadata.summary;
            view.fields = metadata.fields.into_iter().collect();
            view.content = strand.content;
            view.encrypted_content = strand.encrypted_content;
            view.tracks = strand.tracks;
            view.schema_refs = strand.schema_refs.unwrap_or_default();
            // Strand current replaces object content, not the independently
            // folded accepted RSVP cells. The endpoint baseline omits them.
            view.rsvps = card.calendar_rsvp_cells.clone();
            view.schedule_revision_source = decrypt_ctx.and_then(|ctx| {
                let source_stream = entries.iter().find_map(|entry| {
                    let arkret_sdk::TypedCurrentResult::Value { selector, source_stream_ref, .. } = entry;
                    matches!(selector, arkret_sdk::CurrentSelector::Strand { strand_id: id } if id == &strand_id)
                        .then_some(source_stream_ref)
                })?;
                canonical_calendar_source(operations, &strand_id, source_stream, &revision, ctx.state_store)
            });
            let mut complete = card_from_strand_projection_for_actor(&view, decrypt_ctx, actor);
            // Current supplies the selected value and revision. Decryption still
            // requires the original authenticated Event carrying that exact
            // value; replaying whole historical patches here would replace newer
            // current fields with stale content.
            if let Some(ctx) = decrypt_ctx {
                for (field, text, locked) in [
                    (
                        strand_projection_description_content(&view),
                        &mut complete.description_body,
                        &mut complete.description_locked,
                    ),
                    (
                        strand_projection_synthesis_content(&view),
                        &mut complete.synthesis,
                        &mut complete.synthesis_locked,
                    ),
                ] {
                    if let Some((value, path)) = field
                        && value_is_mls_envelope(&value)
                        && let Some(plaintext) = operations.iter().rev().find_map(|record| {
                            private_strand_event_field_text(
                                ctx,
                                record.payload.get("event")?,
                                &card.id,
                                path,
                                &value,
                            )
                        })
                    {
                        *text = plaintext;
                        *locked = false;
                    }
                }
            }
            complete.rank = card.rank.clone();
            complete.state = card.state;
            complete.lifecycle = card.lifecycle;
            complete.assignee = card.assignee.clone();
            complete.assigned_to_relations = card.assigned_to_relations.clone();
            complete.authoring_basis = Some(revision);
            *card = complete;
        }
    }
}

/// Decode the Strand object the Station selected as current for `strand_id`.
fn current_strand_value(
    entries: &[arkret_wire::TypedCurrentResult],
    strand_id: &arkret_sdk::StrandId,
) -> Option<arkret_sdk::Strand> {
    crate::current_projection::current_strand(entries, strand_id)
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
        _actor_seq: u64,
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
            payload,
        )
        .unwrap();
        event.event_id = arkret_sdk::EventId::new(event_id).unwrap();
        event.created_at = created_at.parse().unwrap();
        event
    }

    #[test]
    fn current_space_baseline_restores_prejoin_board_title_and_accepts_later_updates() {
        let projected = vec![
            crate::state::projection_views::SpaceContainerProjectionView {
                space_id: BOARD.to_owned(),
                realm_id: REALM.to_owned(),
                kind: "board".to_owned(),
                title: "Release board".to_owned(),
                state: arkret_sdk::SpaceState::Active,
                rank: None,
                parent_space_id: None,
            },
            crate::state::projection_views::SpaceContainerProjectionView {
                space_id: LIST_A.to_owned(),
                realm_id: REALM.to_owned(),
                kind: "list".to_owned(),
                title: "Todo".to_owned(),
                state: arkret_sdk::SpaceState::Active,
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

        let containers =
            space_container_views_from_projection_and_ops(&projected, &ops, REALM, &[]);
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
    fn accepted_create_draft_handle_hint_aliases_selection_and_children() {
        let draft_board = "ak:space:AaDn_ypTG8vV4ToKfz6JtG2xnepF9QDlafPZCT-UYPyR";
        let board_create = space_create_event(BOARD, "board", "Board1", None);
        let list_create = space_create_event(LIST_A, "list", "Todos", Some(draft_board));

        let mut ops = kanban_operations_from_events(&[board_create, list_create]);
        ops[0]
            .payload
            .as_object_mut()
            .unwrap()
            .insert("local_target_ref".to_owned(), json!(draft_board));
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
        let second_board = space_create_event(LIST_B, "board", "Board2", None);
        let mut ops = kanban_operations_from_events(&[
            space_create_event(BOARD, "board", "Board1", None),
            second_board,
        ]);
        ops[1]
            .payload
            .as_object_mut()
            .unwrap()
            .insert("local_target_ref".to_owned(), json!(BOARD));
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
        let canonical_list_create = space_create_event(canonical_list, "list", "Todo", Some(BOARD));
        let canonical_card_create = strand_create_event(
            canonical_card,
            "ak:did_core:web:alice.example",
            "same card",
            "2026-06-28T00:02:00.000Z",
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
        ops[1].payload.as_object_mut().unwrap().insert(
            "local_operation_idempotency_alias".to_owned(),
            json!(list_operation_alias),
        );
        ops[2].payload.as_object_mut().unwrap().insert(
            "local_operation_idempotency_alias".to_owned(),
            json!(card_operation_alias),
        );
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
