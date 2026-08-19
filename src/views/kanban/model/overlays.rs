use arkret_wire::event_kind_str;

use super::*;

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct LocalCardCreate {
    pub(crate) board_space_id: String,
    pub(crate) list_space_id: String,
    pub(crate) card: KanbanCard,
}

pub(crate) fn local_created_card(
    strand_id: String,
    title: String,
    rank: String,
    description: String,
    state: CardState,
) -> KanbanCard {
    KanbanCard {
        id: strand_id.clone(),
        rank,
        title,
        description,
        description_body: String::new(),
        description_locked: false,
        synthesis: String::new(),
        synthesis_locked: false,
        created_by: "inkson".to_owned(),
        created_at: String::new(),
        updated_by: String::new(),
        updated_at: String::new(),
        labels: vec!["draft".to_owned()],
        assignee: "inkson".to_owned(),
        assigned_to_relations: Vec::new(),
        due: "unscheduled".to_owned(),
        calendar_rsvp: CalendarRsvpDisplay::default(),
        calendar_schedule_basis_refs: Vec::new(),
        calendar: CalendarCardFields::default(),
        primary_strand_id: strand_id,
        locked_strand: None,
        external_visibility: "Not shared externally".to_owned(),
        history_visibility: "board default".to_owned(),
        security_encrypted: None,
        state,
        lifecycle: StrandLifecycleState::Active,
    }
}

pub(crate) fn overlay_local_card_creates(
    columns: Vec<KanbanColumn>,
    state_store: &LocalStateStore,
    board_space_id: &str,
) -> Vec<KanbanColumn> {
    overlay_local_card_creates_with_decrypt(columns, state_store, board_space_id, None)
}

pub(crate) fn overlay_local_card_creates_with_decrypt(
    columns: Vec<KanbanColumn>,
    state_store: &LocalStateStore,
    board_space_id: &str,
    decrypt_ctx: Option<&MlsDecryptCtx<'_>>,
) -> Vec<KanbanColumn> {
    overlay_card_projection_with_operations_and_decrypt(
        columns,
        state_store,
        board_space_id,
        &[],
        decrypt_ctx,
    )
}

pub(crate) fn overlay_collection_projection_with_operations(
    projection: &crate::state::projection_views::CollectionProjectionView,
    state_store: &LocalStateStore,
    board_space_id: &str,
    remote_operations: &[RawOperationRecord],
    decrypt_ctx: Option<&MlsDecryptCtx<'_>>,
) -> Vec<KanbanColumn> {
    overlay_card_projection_with_operations_and_decrypt(
        collection_projection_to_columns(projection, decrypt_ctx),
        state_store,
        board_space_id,
        remote_operations,
        decrypt_ctx,
    )
}

#[cfg(test)]
pub(crate) fn overlay_card_projection_with_operations(
    columns: Vec<KanbanColumn>,
    state_store: &LocalStateStore,
    board_space_id: &str,
    remote_operations: &[RawOperationRecord],
) -> Vec<KanbanColumn> {
    overlay_card_projection_with_operations_and_decrypt(
        columns,
        state_store,
        board_space_id,
        remote_operations,
        None,
    )
}

pub(crate) fn overlay_card_projection_with_operations_and_decrypt(
    columns: Vec<KanbanColumn>,
    state_store: &LocalStateStore,
    board_space_id: &str,
    remote_operations: &[RawOperationRecord],
    decrypt_ctx: Option<&MlsDecryptCtx<'_>>,
) -> Vec<KanbanColumn> {
    let state = state_store.load();
    let columns = overlay_local_card_create_records(columns, &state.raw_operations, board_space_id);
    let columns = overlay_local_card_update_records(columns, remote_operations, decrypt_ctx);
    let columns = overlay_local_card_update_records(columns, &state.raw_operations, decrypt_ctx);
    overlay_local_card_assignment_records(columns, &state.raw_operations)
}

pub(crate) fn strand_update_operations_from_events(
    events: &[arkret_sdk::Event],
) -> Vec<RawOperationRecord> {
    events
        .iter()
        .filter_map(strand_update_operation_from_event)
        .collect()
}

pub(crate) fn strand_update_operation_from_event(
    event: &arkret_sdk::Event,
) -> Option<RawOperationRecord> {
    // Single source in the projection layer (YGN-ARCH-01 step 3).
    crate::state::projection::kanban_ops::strand_update_operation_from_event(event)
}

pub(crate) fn sync_selected_card_from_columns(
    mut selected_card: Signal<Option<KanbanCard>>,
    columns: &[KanbanColumn],
) {
    let Some(current) = selected_card.read().clone() else {
        return;
    };
    let Some(next) = find_card_by_strand_id(columns, &current.id) else {
        return;
    };
    if next != current {
        selected_card.set(Some(next));
    }
}

pub(crate) fn raw_operation_allows_overlay(payload: &Value) -> bool {
    let write_state =
        json_path_string(Some(payload), &["write_state"]).unwrap_or_else(|| "queued".to_owned());
    !matches!(write_state.as_str(), "cancelled" | "canceled" | "dropped")
}

pub(crate) fn raw_operation_card_state(payload: &Value) -> CardState {
    let write_state =
        json_path_string(Some(payload), &["write_state"]).unwrap_or_else(|| "queued".to_owned());
    card_state_from_write_state(&write_state)
}

pub(crate) fn raw_operation_kind_matches(payload: &Value, expected: &str) -> bool {
    json_path_string(Some(payload), &["kind"])
        .or_else(|| json_path_string(Some(payload), &["wire_kind"]))
        .as_deref()
        == Some(expected)
}

pub(crate) fn raw_operation_strand_update_target_id(payload: &Value) -> Option<String> {
    if !raw_operation_kind_matches(payload, event_kind_str::STRAND_UPDATE)
        || !raw_operation_allows_overlay(payload)
    {
        return None;
    }
    let body = payload.get("body").or_else(|| payload.get("payload"))?;
    json_path_string(Some(body), &["strand_id"])
        .or_else(|| json_path_string(Some(body), &["target_ref"]))
}

#[cfg(test)]
pub(crate) fn local_operation_state_for_target(
    raw_operations: &[RawOperationRecord],
    kind: &str,
    target_id: &str,
) -> Option<CardState> {
    raw_operations.iter().rev().find_map(|record| {
        if !raw_operation_kind_matches(&record.payload, kind) {
            return None;
        }
        let payload = &record.payload;
        let body = payload.get("body").or_else(|| payload.get("payload"));
        let effect = payload.get("effect");
        let matches_target = json_path_string(body, &["object", "id"])
            .or_else(|| json_path_string(body, &["strand_id"]))
            .or_else(|| json_path_string(body, &["target_ref"]))
            .or_else(|| json_path_string(effect, &["strand_id"]))
            .or_else(|| json_path_string(Some(payload), &["strand_id"]))
            .as_deref()
            == Some(target_id);
        matches_target.then(|| raw_operation_card_state(payload))
    })
}

#[cfg(test)]
pub(crate) fn local_space_create_state_for_target(
    raw_operations: &[RawOperationRecord],
    projected_space_container_ids: &BTreeSet<String>,
    target_id: &str,
) -> Option<CardState> {
    let state =
        local_operation_state_for_target(raw_operations, event_kind_str::SPACE_CREATE, target_id)?;
    if projected_space_container_ids.contains(target_id) {
        Some(CardState::Synced)
    } else {
        Some(state)
    }
}

pub(crate) fn displayed_card_state(
    card: &KanbanCard,
    projected_strand_ids: &BTreeSet<String>,
) -> CardState {
    if projected_strand_ids.contains(&card.id)
        || projected_strand_ids.contains(&card.primary_strand_id)
    {
        CardState::Synced
    } else {
        card.state
    }
}

/// Re-apply locally-queued `ak.strand.update` patches on top of the
/// server projection. Without this overlay, optimistic edits to a
/// card's title / summary / body / fields would vanish on page reload
/// because the server projection is refetched but the local mutation
/// lived only in the in-memory `columns` signal. The reducer copy of
/// each Move is the source of truth once the server confirms, but in
/// the meantime we keep the user's edit visible by replaying the
/// queued payload here. Ops marked as terminally-failed are skipped
/// so a rejected edit doesn't keep clobbering the projection.
pub(crate) fn overlay_local_card_update_records(
    mut columns: Vec<KanbanColumn>,
    raw_operations: &[RawOperationRecord],
    decrypt_ctx: Option<&MlsDecryptCtx<'_>>,
) -> Vec<KanbanColumn> {
    for update in raw_operations
        .iter()
        .filter_map(|record| local_card_update_from_raw_operation(record, decrypt_ctx))
    {
        for column in columns.iter_mut() {
            if let Some(card) = column
                .cards
                .iter_mut()
                .find(|card| card.id == update.strand_id)
            {
                apply_card_update_overlay(card, &update);
            }
        }
    }
    columns
}

pub(crate) fn overlay_local_card_assignment_records(
    mut columns: Vec<KanbanColumn>,
    raw_operations: &[RawOperationRecord],
) -> Vec<KanbanColumn> {
    for record in raw_operations
        .iter()
        .filter(|record| raw_operation_allows_overlay(&record.payload))
    {
        if raw_operation_kind_matches(&record.payload, event_kind_str::RELATION_CREATE) {
            overlay_local_assignment_create(&mut columns, &record.payload);
        } else if raw_operation_kind_matches(&record.payload, event_kind_str::RELATION_TOMBSTONE) {
            overlay_local_assignment_tombstone(&mut columns, &record.payload);
        }
    }
    columns
}

fn overlay_local_assignment_create(columns: &mut [KanbanColumn], payload: &Value) {
    let body = payload.get("body").or_else(|| payload.get("payload"));
    let relation_kind = json_path_string(body, &["relation_kind"])
        .or_else(|| json_path_string(body, &["kind"]))
        .unwrap_or_default();
    if relation_kind != "assigned_to" {
        return;
    }
    let Some(strand_id) = json_path_string(body, &["from_ref"]) else {
        return;
    };
    let Some(actor_id) = json_path_string(body, &["to_ref"])
        .or_else(|| json_path_string(Some(payload), &["assignment_actor_id"]))
    else {
        return;
    };
    let Some(relation_id) = json_path_string(Some(payload), &["assignment_relation_id"])
        .or_else(|| json_path_string(body, &["relation_id"]))
        .or_else(|| json_path_string(body, &["id"]))
    else {
        return;
    };
    for column in columns.iter_mut() {
        if let Some(card) = column.cards.iter_mut().find(|card| card.id == strand_id) {
            let mut actor_ids = card_assigned_actor_ids(card)
                .into_iter()
                .collect::<BTreeSet<_>>();
            actor_ids.insert(actor_id.clone());
            let mut relations = card.assigned_to_relations.clone();
            if !relations
                .iter()
                .any(|relation| relation.relation_id == relation_id)
            {
                relations.push(CardAssignedToRelation {
                    relation_id,
                    actor_id,
                });
            }
            apply_card_assignment_projection(
                card,
                &actor_ids,
                relations,
                raw_operation_card_state(payload),
            );
            break;
        }
    }
}

fn overlay_local_assignment_tombstone(columns: &mut [KanbanColumn], payload: &Value) {
    let body = payload.get("body").or_else(|| payload.get("payload"));
    let Some(relation_id) = json_path_string(body, &["relation_id"])
        .or_else(|| json_path_string(Some(payload), &["assignment_relation_id"]))
    else {
        return;
    };
    for column in columns.iter_mut() {
        if let Some(card) = column.cards.iter_mut().find(|card| {
            card.assigned_to_relations
                .iter()
                .any(|relation| relation.relation_id == relation_id)
        }) {
            let removed_actor = card
                .assigned_to_relations
                .iter()
                .find(|relation| relation.relation_id == relation_id)
                .map(|relation| relation.actor_id.clone())
                .or_else(|| json_path_string(Some(payload), &["assignment_actor_id"]));
            let mut actor_ids = card_assigned_actor_ids(card)
                .into_iter()
                .collect::<BTreeSet<_>>();
            if let Some(actor_id) = removed_actor {
                actor_ids.remove(actor_id.trim());
            }
            let relations = card
                .assigned_to_relations
                .iter()
                .filter(|relation| relation.relation_id != relation_id)
                .cloned()
                .collect::<Vec<_>>();
            apply_card_assignment_projection(
                card,
                &actor_ids,
                relations,
                raw_operation_card_state(payload),
            );
            break;
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) enum PrivateFieldOverlay {
    Set(String),
    Unset,
    Locked,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct LocalCardUpdate {
    pub(crate) strand_id: String,
    pub(crate) title: Option<Option<String>>,
    pub(crate) summary: Option<Option<String>>,
    /// Overlay for the Strand Description (`content` / `encrypted_content`).
    pub(crate) description_body: Option<PrivateFieldOverlay>,
    /// Overlay for the Synthesis track's nested content pair.
    pub(crate) synthesis: Option<PrivateFieldOverlay>,
    pub(crate) fields: Option<Value>,
    pub(crate) fields_replaces_all: bool,
    pub(crate) calendar: Option<CalendarCardFields>,
    pub(crate) state: CardState,
}

pub(crate) fn local_card_update_from_raw_operation(
    record: &RawOperationRecord,
    decrypt_ctx: Option<&MlsDecryptCtx<'_>>,
) -> Option<LocalCardUpdate> {
    let payload = &record.payload;
    let strand_id = raw_operation_strand_update_target_id(payload)?;
    let body = payload.get("body").or_else(|| payload.get("payload"))?;
    let patch = body.get("patch")?.as_object()?;

    fn extract_set_unset(op: &Value) -> Option<Option<String>> {
        let op: arkret_wire::patch::PatchOp = serde_json::from_value(op.clone()).ok()?;
        match op.op() {
            arkret_wire::patch::PatchOpKind::Set => op
                .value()
                .and_then(Value::as_str)
                .map(|s| Some(s.to_owned())),
            arkret_wire::patch::PatchOpKind::Unset => Some(None),
            _ => None,
        }
    }

    fn extract_private_set_unset(
        op: &Value,
        decrypt_ctx: Option<&MlsDecryptCtx<'_>>,
        strand_id: &str,
        field_path: &str,
    ) -> Option<PrivateFieldOverlay> {
        let op: arkret_wire::patch::PatchOp = serde_json::from_value(op.clone()).ok()?;
        match op.op() {
            arkret_wire::patch::PatchOpKind::Unset => Some(PrivateFieldOverlay::Unset),
            arkret_wire::patch::PatchOpKind::Set => {
                let value = op.value()?;
                if value_is_mls_envelope(value) {
                    let text =
                        private_strand_field_text(decrypt_ctx, strand_id, field_path, Some(value));
                    if !text.trim().is_empty() {
                        Some(PrivateFieldOverlay::Set(text))
                    } else {
                        Some(PrivateFieldOverlay::Locked)
                    }
                } else {
                    Some(PrivateFieldOverlay::Set(strand_body_display_text(Some(
                        value,
                    ))))
                }
            }
            _ => None,
        }
    }

    fn extract_private_for_paths(
        patch: &Map<String, Value>,
        paths: &[&'static str],
        decrypt_ctx: Option<&MlsDecryptCtx<'_>>,
        strand_id: &str,
    ) -> Option<PrivateFieldOverlay> {
        paths.iter().find_map(|path| {
            let op = patch_op_for_private_path(patch, path)?;
            extract_private_set_unset(op.as_ref(), decrypt_ctx, strand_id, path)
        })
    }

    // Canonical Strand paths only. `title` / `summary` / `fields` / `body` are
    // explicitly forbidden Strand top-level fields (`strand.schema.json`), so a
    // patch that uses them is a schema violation the server rejects — reading
    // them here would only resurrect the non-spec shape locally.
    let title = patch.get("metadata.title").and_then(extract_set_unset);
    let summary = patch.get("metadata.summary").and_then(extract_set_unset);
    let description_body = extract_private_for_paths(
        patch,
        KANBAN_DESCRIPTION_PRIVATE_FIELD_PATHS,
        decrypt_ctx,
        &strand_id,
    );
    let synthesis = extract_private_for_paths(
        patch,
        KANBAN_SYNTHESIS_PRIVATE_FIELD_PATHS,
        decrypt_ctx,
        &strand_id,
    );
    fn extract_direct_field_patch(patch: &Map<String, Value>, field: &str) -> Option<Value> {
        let metadata_path = format!("metadata.fields.{field}");
        patch.get(&metadata_path).and_then(|op| {
            match serde_json::from_value::<arkret_wire::patch::PatchOp>(op.clone()).ok()? {
                op if op.op() == arkret_wire::patch::PatchOpKind::Set => op.value().cloned(),
                op if op.op() == arkret_wire::patch::PatchOpKind::Unset => Some(Value::Null),
                _ => None,
            }
        })
    }

    let replacement_fields = patch.get("metadata.fields").and_then(|fields_op| {
        let op: arkret_wire::patch::PatchOp = serde_json::from_value(fields_op.clone()).ok()?;
        (op.op() == arkret_wire::patch::PatchOpKind::Set)
            .then(|| op.value().cloned())
            .flatten()
    });
    let mut direct_fields = Map::new();
    for field in [
        CALENDAR_PROFILE_FIELD,
        CALENDAR_PROFILE_REFS_FIELD,
        "labels",
        "due_at",
        "due",
        "start",
        "end",
        "timezone",
        "all_day",
        "recurrence",
        "location",
        // The schedule is patched as one subtree now, so the overlay follows
        // the same single path instead of tracking each schedule field.
        arkret_sdk::CALENDAR_METADATA_FIELDS_NAMESPACE,
    ] {
        if let Some(value) = extract_direct_field_patch(patch, field) {
            direct_fields.insert(field.to_owned(), value);
        }
    }
    let fields_replaces_all = replacement_fields.is_some();
    let fields = replacement_fields
        .or_else(|| (!direct_fields.is_empty()).then(|| Value::Object(direct_fields.clone())));
    let calendar = fields
        .as_ref()
        .and_then(Value::as_object)
        .and_then(|fields| {
            fields_have_calendar_keys(fields)
                .then(|| calendar_fields_from_metadata(fields, decrypt_ctx, &strand_id))
        });

    Some(LocalCardUpdate {
        strand_id,
        title,
        summary,
        description_body,
        synthesis,
        fields,
        fields_replaces_all,
        calendar,
        state: raw_operation_card_state(payload),
    })
}

pub(crate) fn apply_card_update_overlay(card: &mut KanbanCard, update: &LocalCardUpdate) {
    if let Some(slot) = &update.title {
        card.title = slot.clone().unwrap_or_default();
    }
    if let Some(slot) = &update.summary {
        card.description = slot.clone().unwrap_or_default();
    }
    if let Some(slot) = &update.description_body {
        match slot {
            PrivateFieldOverlay::Set(value) => {
                card.description_body = value.clone();
                card.description_locked = false;
            }
            PrivateFieldOverlay::Unset => {
                card.description_body.clear();
                card.description_locked = false;
            }
            PrivateFieldOverlay::Locked => {
                card.description_body.clear();
                card.description_locked = true;
            }
        }
    }
    if let Some(slot) = &update.synthesis {
        match slot {
            PrivateFieldOverlay::Set(value) => {
                card.synthesis = value.clone();
                card.synthesis_locked = false;
            }
            PrivateFieldOverlay::Unset => {
                card.synthesis.clear();
                card.synthesis_locked = false;
            }
            PrivateFieldOverlay::Locked => {
                card.synthesis.clear();
                card.synthesis_locked = true;
            }
        }
    }
    if let Some(fields) = update.fields.as_ref().and_then(Value::as_object) {
        if let Some(labels) = fields.get("labels").and_then(Value::as_array) {
            card.labels = labels
                .iter()
                .filter_map(|v| v.as_str().map(ToOwned::to_owned))
                .collect();
        }
        if let Some(due) = fields
            .get("due_at")
            .or_else(|| fields.get("due"))
            .or_else(|| fields.get("due_date"))
            .and_then(Value::as_str)
        {
            card.due = display_optional_card_field(due);
        } else if update.fields_replaces_all
            || fields.contains_key("due_at")
            || fields.contains_key("due")
            || fields.contains_key("due_date")
        {
            card.due = display_optional_card_field("");
        }
    }
    if let Some(calendar) = &update.calendar {
        if update.fields_replaces_all {
            card.calendar = calendar.clone();
        } else if let Some(fields) = update.fields.as_ref().and_then(Value::as_object) {
            apply_calendar_field_overlay(&mut card.calendar, fields, calendar);
        }
    }
    card.state = update.state;
}

/// Merges a locally queued schedule patch onto the projected card.
///
/// The schedule is written as one object, so touching it replaces the card's
/// whole calendar; a partial merge would let a stale field survive next to a
/// freshly written one and produce a schedule that was never signed.
fn apply_calendar_field_overlay(
    current: &mut CalendarCardFields,
    touched_fields: &Map<String, Value>,
    next: &CalendarCardFields,
) {
    if touched_fields.contains_key(arkret_sdk::CALENDAR_METADATA_FIELDS_NAMESPACE) {
        *current = next.clone();
        return;
    }
    if touched_fields.contains_key("start") {
        current.start = next.start.clone();
    }
    if touched_fields.contains_key("end") {
        current.end = next.end.clone();
    }
    if touched_fields.contains_key("timezone") {
        current.timezone = next.timezone.clone();
    }
    if touched_fields.contains_key("tzdb_version") {
        current.tzdb_version = next.tzdb_version.clone();
    }
    if touched_fields.contains_key("all_day") {
        current.all_day = next.all_day;
    }
    if touched_fields.contains_key("status") {
        current.status = next.status.clone();
    }
    if touched_fields.contains_key("recurrence") {
        current.recurrence_frequency = next.recurrence_frequency.clone();
        current.recurrence_interval = next.recurrence_interval.clone();
        current.recurrence_by_day = next.recurrence_by_day.clone();
        current.recurrence_by_month = next.recurrence_by_month.clone();
        current.recurrence_by_month_day = next.recurrence_by_month_day.clone();
        current.recurrence_by_set_position = next.recurrence_by_set_position.clone();
        current.recurrence_first_day_of_week = next.recurrence_first_day_of_week.clone();
        current.recurrence_count = next.recurrence_count.clone();
        current.recurrence_until = next.recurrence_until.clone();
    }
    if touched_fields.contains_key("location") {
        current.location = next.location.clone();
        current.location_locked = next.location_locked;
        current.location_source = next.location_source.clone();
    }
    if touched_fields.contains_key("call_id") {
        current.call_id = next.call_id.clone();
    }
    if touched_fields.contains_key("attendees") {
        current.attendees_json = next.attendees_json.clone();
    }
}

pub(crate) fn overlay_local_card_create_records(
    mut columns: Vec<KanbanColumn>,
    raw_operations: &[RawOperationRecord],
    board_space_id: &str,
) -> Vec<KanbanColumn> {
    let board_space_id = board_space_id.trim();
    if board_space_id.is_empty() {
        return columns;
    }

    let aliases = event_derived_target_aliases(raw_operations);
    let board_space_id = resolve_event_derived_target_alias(&aliases, board_space_id);
    let mut existing_card_ids = columns
        .iter()
        .flat_map(|column| column.cards.iter().map(|card| card.id.clone()))
        .collect::<BTreeSet<_>>();
    for mut local_create in raw_operations
        .iter()
        .filter_map(local_card_create_from_raw_operation)
    {
        local_create.board_space_id =
            resolve_event_derived_target_alias(&aliases, &local_create.board_space_id);
        local_create.list_space_id =
            resolve_event_derived_target_alias(&aliases, &local_create.list_space_id);
        local_create.card.id = resolve_event_derived_target_alias(&aliases, &local_create.card.id);
        local_create.card.primary_strand_id = local_create.card.id.clone();
        if local_create.board_space_id != board_space_id {
            continue;
        }
        if existing_card_ids.contains(&local_create.card.id) {
            continue;
        }
        let Some(column) = columns
            .iter_mut()
            .find(|column| column.id == local_create.list_space_id)
        else {
            continue;
        };
        existing_card_ids.insert(local_create.card.id.clone());
        column.cards.push(local_create.card);
        sort_kanban_cards(&mut column.cards);
    }

    columns
}

pub(crate) fn local_card_create_from_raw_operation(
    record: &RawOperationRecord,
) -> Option<LocalCardCreate> {
    let payload = &record.payload;
    let kind = json_path_string(Some(payload), &["kind"])
        .or_else(|| json_path_string(Some(payload), &["wire_kind"]))?;
    if kind != event_kind_str::STRAND_CREATE {
        return None;
    }
    if !raw_operation_allows_overlay(payload) {
        return None;
    }

    let effect = payload.get("effect");
    let body = payload.get("body").or_else(|| payload.get("payload"));
    let position_component = strand_position_component(body);
    let strand_id = raw_operation_create_target_id(payload)
        .or_else(|| json_path_string(effect, &["strand_id"]))
        .or_else(|| json_path_string(body, &["strand_id"]))
        .or_else(|| json_path_string(body, &["object", "id"]))?;
    let board_space_id = json_path_string(effect, &["board_space_id"])
        .or_else(|| json_path_string(position_component, &["board_space_id"]))
        .or_else(|| json_path_string(body, &["object", "fields", "board_space_id"]))
        .or_else(|| json_path_string(body, &["fields", "board_space_id"]))?;
    let list_space_id = json_path_string(effect, &["list_space_id"])
        .or_else(|| json_path_string(position_component, &["list_space_id"]))
        .or_else(|| json_path_string(body, &["object", "fields", "list_space_id"]))
        .or_else(|| json_path_string(body, &["fields", "list_space_id"]))?;
    let title = json_path_string(effect, &["title"])
        .or_else(|| json_path_string(body, &["object", "title"]))
        .or_else(|| json_path_string(body, &["title"]))
        .unwrap_or_else(|| strand_id.clone());
    let rank = json_path_string(effect, &["rank"])
        .or_else(|| json_path_string(position_component, &["rank"]))
        .or_else(|| json_path_string(body, &["object", "fields", "rank"]))
        .or_else(|| json_path_string(body, &["rank"]))
        .unwrap_or_else(|| "U".to_owned());
    let description = json_path_string(effect, &["description"])
        .or_else(|| json_path_string(effect, &["summary"]))
        .or_else(|| json_path_string(body, &["object", "summary"]))
        .or_else(|| json_path_string(body, &["summary"]))
        .unwrap_or_default();

    Some(LocalCardCreate {
        board_space_id,
        list_space_id,
        card: local_created_card(
            strand_id,
            title,
            rank,
            description,
            raw_operation_card_state(payload),
        ),
    })
}

pub(crate) fn local_space_create_from_raw_operation(
    record: &RawOperationRecord,
) -> Option<LocalSpaceCreate> {
    let payload = &record.payload;
    let kind = json_path_string(Some(payload), &["kind"])
        .or_else(|| json_path_string(Some(payload), &["wire_kind"]))?;
    if kind != event_kind_str::SPACE_CREATE {
        return None;
    }
    if !raw_operation_allows_overlay(payload) {
        return None;
    }

    let body = payload.get("body").or_else(|| payload.get("payload"))?;
    let object = body.get("object").unwrap_or(body);
    // `local_target_ref` first: a create payload carries no `object.id` — the
    // Space is `retype(create.event_id)`, published on the record by the ingest
    // funnel. `object.id` stays as a fallback for records captured before the
    // id became Event-derived.
    let id = raw_operation_create_target_id(payload)
        .or_else(|| json_path_string(Some(object), &["id"]))
        .or_else(|| json_path_string(Some(body), &["space_id"]))?;
    let space_kind = json_path_string(Some(object), &["kind"])
        .or_else(|| json_path_string(Some(body), &["space_kind"]))?;
    if space_kind != "board" && space_kind != "list" {
        return None;
    }
    let realm_id = json_path_string(Some(object), &["realm_id"]).or_else(|| {
        record
            .realm_id
            .as_ref()
            .map(|record_realm_id| trim_realm_id(record_realm_id))
    });
    let title = json_path_string(Some(object), &["title"])
        .or_else(|| json_path_string(Some(body), &["title"]))
        .unwrap_or_else(|| id.clone());
    let parent_space_id = json_path_string(Some(object), &["parent_space_id"])
        .or_else(|| json_path_string(Some(body), &["parent_space_id"]));
    let rank = json_path_string(Some(object), &["rank"])
        .or_else(|| json_path_string(Some(body), &["rank"]));

    Some(LocalSpaceCreate {
        id,
        realm_id,
        kind: space_kind,
        title,
        parent_space_id,
        rank,
    })
}

/// Resolve the object named by an event-derived create.
///
/// Before acceptance an optimistic row only knows `local_target_ref`, derived
/// from the draft Event id. Final authoring changes content-bound identity when
/// it attaches actor-chain/HLC/CBA fields; the submit receipt is persisted as
/// `event_id`. Prefer that accepted id, or the canonical backfill row's
/// `operation_id`, and fall back to the temporary handle while the write is in
/// flight.
pub(crate) fn raw_operation_create_target_id(payload: &Value) -> Option<String> {
    let kind = json_path_string(Some(payload), &["kind"])
        .or_else(|| json_path_string(Some(payload), &["wire_kind"]))?;
    if kind != event_kind_str::SPACE_CREATE && kind != event_kind_str::STRAND_CREATE {
        return None;
    }
    let final_event_id = json_path_string(Some(payload), &["event_id"]).or_else(|| {
        let operation_id = json_path_string(Some(payload), &["operation_id"])?;
        operation_id
            .starts_with("ak:event:")
            .then_some(operation_id)
    });
    final_event_id
        .and_then(|event_id| arkret_sdk::EventId::new(event_id).ok())
        .and_then(|event_id| {
            arkret_sdk::schema::derived_object_id_for_kind(kind.as_str(), &event_id)
        })
        .or_else(|| json_path_string(Some(payload), &["local_target_ref"]))
}

/// Map temporary optimistic object ids to their accepted content-bound ids.
pub(crate) fn event_derived_target_aliases(
    raw_operations: &[RawOperationRecord],
) -> BTreeMap<String, String> {
    let mut aliases = raw_operations
        .iter()
        .filter_map(|record| {
            let temporary = json_path_string(Some(&record.payload), &["local_target_ref"])?;
            let canonical = raw_operation_create_target_id(&record.payload)?;
            (temporary != canonical).then_some((temporary, canonical))
        })
        .collect::<BTreeMap<_, _>>();
    // Backfilled Events retain the producer's local operation alias as an
    // unsigned reconciliation hint. It is never used to derive canonical
    // protocol identity; it only joins an already-local optimistic row to the
    // server-accepted Event. This also heals rows written by builds that did
    // not persist the submit receipt's final event id.
    for canonical in raw_operations {
        let Some(operation_alias) = json_path_string(
            Some(&canonical.payload),
            &["local_operation_idempotency_alias"],
        ) else {
            continue;
        };
        let Some(temporary) = raw_operations
            .iter()
            .find(|record| record.operation_id == operation_alias)
            .and_then(|record| json_path_string(Some(&record.payload), &["local_target_ref"]))
        else {
            continue;
        };
        let Some(canonical_target) = raw_operation_create_target_id(&canonical.payload) else {
            continue;
        };
        if temporary != canonical_target {
            aliases.insert(temporary, canonical_target);
        }
    }
    aliases
}

pub(crate) fn resolve_event_derived_target_alias(
    aliases: &BTreeMap<String, String>,
    target: &str,
) -> String {
    let mut current = target.to_owned();
    let mut seen = BTreeSet::new();
    while seen.insert(current.clone()) {
        let Some(next) = aliases.get(&current) else {
            break;
        };
        current = next.clone();
    }
    current
}

pub(crate) fn strand_position_component(body: Option<&Value>) -> Option<&Value> {
    body?
        .get("components")?
        .as_array()?
        .iter()
        .find(|component| {
            component.get("family").and_then(Value::as_str)
                == Some(arkret_wire::CellFamilyId::STRAND_POSITION_V1)
        })
}

pub(crate) fn json_path_string(value: Option<&Value>, path: &[&str]) -> Option<String> {
    let mut current = value?;
    for segment in path {
        current = current.get(*segment)?;
    }
    current
        .as_str()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

pub(crate) fn strand_projection_description_content(
    strand: &crate::state::projection_views::StrandProjectionView,
) -> Option<(Value, &'static str)> {
    KANBAN_DESCRIPTION_PRIVATE_FIELD_PATHS
        .iter()
        .find_map(|path| {
            let value = match *path {
                KANBAN_CONTENT_PATH => strand.content.as_ref().map(serde_json::to_value),
                KANBAN_ENCRYPTED_CONTENT_PATH => {
                    strand.encrypted_content.as_ref().map(serde_json::to_value)
                }
                _ => None,
            }?
            .ok()?;
            Some((value, *path))
        })
}

/// Resolve content owned by `tracks.synthesis`, never Strand Description.
pub(crate) fn strand_projection_synthesis_content(
    strand: &crate::state::projection_views::StrandProjectionView,
) -> Option<(Value, &'static str)> {
    let track = strand.tracks.get(arkret_sdk::STRAND_TRACK_NAME_SYNTHESIS)?;
    KANBAN_SYNTHESIS_PRIVATE_FIELD_PATHS
        .iter()
        .find_map(|path| {
            let value = match *path {
                KANBAN_SYNTHESIS_CONTENT_PATH => track.content.as_ref().map(serde_json::to_value),
                KANBAN_ENCRYPTED_SYNTHESIS_CONTENT_PATH => {
                    track.encrypted_content.as_ref().map(serde_json::to_value)
                }
                _ => None,
            }?
            .ok()?;
            Some((value, *path))
        })
}

pub(crate) fn patch_op_for_private_path<'a>(
    patch: &'a Map<String, Value>,
    path: &str,
) -> Option<Cow<'a, Value>> {
    if let Some(op) = patch.get(path) {
        return Some(Cow::Borrowed(op));
    }
    let mut segments = path.split('.');
    let first = segments.next()?;
    let parent_op = patch.get(first)?;
    if parent_op.get("$op").and_then(Value::as_str) != Some("set") {
        return None;
    }
    let mut current = parent_op.get("value")?;
    for segment in segments {
        current = current.get(segment)?;
    }
    if current.get("$op").and_then(Value::as_str).is_some() {
        Some(Cow::Owned(current.clone()))
    } else {
        Some(Cow::Owned(
            json!({ "$op": "set", "value": current.clone() }),
        ))
    }
}
