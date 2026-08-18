use super::*;

pub(crate) fn kanban_seed_fallback_allowed(_base_url: &str) -> bool {
    if truthy_env_value(option_env!("INKSON_ALLOW_KANBAN_SEED_FALLBACK"))
        || std::env::var("INKSON_ALLOW_KANBAN_SEED_FALLBACK")
            .ok()
            .as_deref()
            .is_some_and(|value| truthy_env_value(Some(value)))
    {
        return true;
    }
    false
}

pub(crate) fn truthy_env_value(value: Option<&str>) -> bool {
    value.is_some_and(|value| value == "1" || value.eq_ignore_ascii_case("true"))
}

pub(crate) fn initial_board_space_options(seed_fallback_allowed: bool) -> Vec<BoardSpaceOption> {
    if seed_fallback_allowed {
        vec![BoardSpaceOption {
            id: DEMO_BOARD_SPACE_ID.to_owned(),
            title: "Local demo board".to_owned(),
            state: SpaceContainerLifecycleState::Active,
        }]
    } else {
        Vec::new()
    }
}

pub(crate) fn sort_board_space_options(options: &mut Vec<BoardSpaceOption>) {
    options.sort_by(|left, right| left.id.cmp(&right.id).then(left.title.cmp(&right.title)));
    options.dedup_by(|left, right| left.id == right.id);
    options.sort_by(|left, right| left.title.cmp(&right.title).then(left.id.cmp(&right.id)));
}

pub(crate) fn generated_board_fallback_title(board_id: &str) -> String {
    format!("Board {}", short_protocol_id(board_id))
}

pub(crate) fn should_replace_projected_container_title(
    existing_title: &str,
    container_id: &str,
) -> bool {
    let title = existing_title.trim();
    title.is_empty()
        || title == container_id
        || title == generated_board_fallback_title(container_id)
}

pub(crate) fn board_space_options_from_projection(
    containers: &[crate::state::projection_views::SpaceContainerProjectionView],
) -> Vec<BoardSpaceOption> {
    let mut options = containers
        .iter()
        .filter(|view| {
            view.kind == "board" || (view.kind.trim().is_empty() && view.parent_space_id.is_none())
        })
        .map(|view| BoardSpaceOption {
            id: view.space_id.clone(),
            title: if view.title.trim().is_empty() {
                view.space_id.clone()
            } else {
                view.title.clone()
            },
            state: space_container_state_from_projection(&view.state),
        })
        .collect::<Vec<_>>();
    let mut seen = options
        .iter()
        .map(|option| option.id.clone())
        .collect::<BTreeSet<_>>();
    for parent_space_id in containers
        .iter()
        .filter(|view| view.kind == "list")
        .filter_map(|view| view.parent_space_id.as_deref())
        .map(str::trim)
        .filter(|id| !id.is_empty())
    {
        if !seen.insert(parent_space_id.to_owned()) {
            continue;
        }
        options.push(BoardSpaceOption {
            id: parent_space_id.to_owned(),
            title: generated_board_fallback_title(parent_space_id),
            state: SpaceContainerLifecycleState::Active,
        });
    }
    sort_board_space_options(&mut options);
    options
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct LocalSpaceCreate {
    pub(crate) id: String,
    pub(crate) realm_id: Option<String>,
    pub(crate) kind: String,
    pub(crate) title: String,
    pub(crate) parent_space_id: Option<String>,
    pub(crate) rank: Option<String>,
}

pub(crate) fn local_projection_realm_id(
    selected_realm_id: &str,
    projection_realm_id: &str,
) -> String {
    let candidate = projection_realm_id.trim();
    if candidate.is_empty() {
        trim_realm_id(selected_realm_id)
    } else {
        trim_realm_id(candidate)
    }
}

pub(crate) fn local_space_create_matches_realm(
    local_create: &LocalSpaceCreate,
    realm_id: &str,
) -> bool {
    let realm_id = realm_id.trim();
    realm_id.is_empty()
        || local_create
            .realm_id
            .as_deref()
            .is_none_or(|local_realm_id| trim_realm_id(local_realm_id) == trim_realm_id(realm_id))
}

pub(crate) fn local_space_create_records(
    raw_operations: &[RawOperationRecord],
    realm_id: &str,
) -> Vec<LocalSpaceCreate> {
    raw_operations
        .iter()
        .filter_map(local_space_create_from_raw_operation)
        .filter(|local_create| local_space_create_matches_realm(local_create, realm_id))
        .collect()
}

pub(crate) fn overlay_local_board_space_options(
    mut options: Vec<BoardSpaceOption>,
    raw_operations: &[RawOperationRecord],
    realm_id: &str,
) -> Vec<BoardSpaceOption> {
    for local_create in local_space_create_records(raw_operations, realm_id)
        .into_iter()
        .filter(|local_create| local_create.kind == "board")
    {
        if let Some(existing) = options
            .iter_mut()
            .find(|option| option.id == local_create.id)
        {
            if should_replace_projected_container_title(&existing.title, &existing.id) {
                existing.title = local_create.title;
            }
            if existing.state == SpaceContainerLifecycleState::Tombstoned {
                existing.state = SpaceContainerLifecycleState::Active;
            }
            continue;
        }
        options.push(BoardSpaceOption {
            id: local_create.id,
            title: local_create.title,
            state: SpaceContainerLifecycleState::Active,
        });
    }
    sort_board_space_options(&mut options);
    options
}

/// T20 / YOU-01-009 subtask 3 - Map a spec-registered
/// [`crate::state::projection_views::CollectionProjectionView`]
/// (`view.schema.json#/$defs/collection_projection_view`) into the inkson
/// renderer's [`Vec<KanbanColumn>`] shape.
///
/// Pure adapter so it's unit-testable without a live HTTP client.
/// Position rank, when present, drives stable ordering inside a column.
pub(crate) fn collection_projection_to_columns(
    projection: &crate::state::projection_views::CollectionProjectionView,
    decrypt_ctx: Option<&MlsDecryptCtx<'_>>,
) -> Vec<KanbanColumn> {
    projection
        .groups
        .iter()
        .map(|group| KanbanColumn {
            id: group.key.as_str().to_owned(),
            title: group.title.as_str().to_owned(),
            rank: group.rank.clone().unwrap_or_default(),
            cards: group
                .items
                .iter()
                .map(|item| card_from_projection_item(item, decrypt_ctx))
                .collect(),
            state: SpaceContainerLifecycleState::Active,
        })
        .collect()
}

/// Map a single registered `projection_item` to a [`KanbanCard`].
///
/// Discussion lock metadata is read leniently from the item's free-form
/// `state.discussion` object (`{enabled, visibility, lazy_link}` — the
/// registered `projection_item.state` is an open object; the dedicated
/// `discussion` field of the SDK's draft DTO is not on the registered
/// wire shape): `visibility="locked"` produces a [`LockedStrand`] with an
/// opaque hash; `lazy_link=true` is surfaced via `history_visibility`
/// without leaking room contents.
pub(crate) fn card_from_projection_item(
    item: &crate::state::projection_views::ProjectionRow,
    decrypt_ctx: Option<&MlsDecryptCtx<'_>>,
) -> KanbanCard {
    let object = serde_json::to_value(&item.object).unwrap_or(Value::Null);
    let id = item.object.id.clone();
    let title = item
        .object
        .title
        .as_deref()
        .unwrap_or("(untitled)")
        .to_owned();
    let primary_strand_id = id.clone();
    let discussion = item.state.get("discussion").filter(|d| d.is_object());
    let (external_visibility, history_visibility) = discussion
        .map(|d| {
            let visibility = d.get("visibility").and_then(Value::as_str).unwrap_or("");
            let enabled = d.get("enabled").and_then(Value::as_bool).unwrap_or(false);
            let lazy_link = d.get("lazy_link").and_then(Value::as_bool).unwrap_or(false);
            let ext = match visibility {
                "locked" => "Locked discussion (lazy_link)".to_owned(),
                "readable" => "Discussion readable to current member".to_owned(),
                other => format!("discussion: {other}"),
            };
            let hist = if lazy_link {
                "lazy_link (cross-Space)".to_owned()
            } else if enabled {
                // Tracks do not carry independent access; a private
                // discussion uses a Circle-scoped Strand.
                "Circle-scoped discussion".to_owned()
            } else {
                "synthesis-only".to_owned()
            };
            (ext, hist)
        })
        .unwrap_or_else(|| {
            (
                "No external discussions linked".to_owned(),
                "synthesis-only".to_owned(),
            )
        });
    let locked_strand = discussion.and_then(|d| {
        if d.get("visibility").and_then(Value::as_str) == Some("locked") {
            Some(LockedStrand {
                strand_id_hash: format!("sha256:{}", id),
                reason: "Locked discussion: title and members are not disclosed.".to_owned(),
            })
        } else {
            None
        }
    });
    // Registered `collection_position` rank: the card's authoritative rank
    // in the column from the API's view of the cas-register cell. Falls
    // back to "" so the seed-conversion path still works when the
    // projection omits position metadata (e.g. group-level rank only).
    let rank =
        crate::state::projection_views::projection_row_position_rank(item).unwrap_or_default();
    let object_fields = &item.object.fields;
    let object_str = |keys: &[&str]| -> String {
        for key in keys {
            if let Some(value) = object_fields.get(*key).and_then(Value::as_str) {
                return value.to_owned();
            }
        }
        String::new()
    };
    let created_by = object_str(&["created_by", "actor_id", "author"]);
    let created_at = object_str(&["created_at", "timestamp"]);
    let updated_by = object_str(&["updated_by"]);
    let updated_at = object_str(&["updated_at", "edited_at"]);
    KanbanCard {
        id,
        rank,
        title,
        description: object_str(&["summary", "description"]),
        description_body: String::new(),
        description_locked: false,
        // The registered `projection_item.object`
        // (`view.schema.json#/$defs/projection_item`) carries id / title /
        // fields only — never Strand `content` or `encrypted_content`. The
        // Strand projection read (`card_from_strand_projection`) is the single
        // source for Description or Synthesis content; a collection row simply has neither.
        synthesis: String::new(),
        synthesis_locked: false,
        created_by,
        created_at,
        updated_by,
        updated_at,
        labels: object_fields
            .get("labels")
            .and_then(|labels| labels.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(ToOwned::to_owned))
                    .collect()
            })
            .unwrap_or_default(),
        assignee: "—".to_owned(),
        assigned_to_relations: Vec::new(),
        due: object_fields
            .get("due_at")
            .or_else(|| object_fields.get("due"))
            .or_else(|| object_fields.get("due_date"))
            .and_then(|v| v.as_str())
            .unwrap_or("—")
            .to_owned(),
        calendar_rsvp: CalendarRsvpDisplay::default(),
        calendar_schedule_basis_refs: object_fields
            .get("schedule_revision_heads")
            .and_then(Value::as_array)
            .map(|values| {
                values
                    .iter()
                    .filter_map(Value::as_str)
                    .map(ToOwned::to_owned)
                    .collect()
            })
            .unwrap_or_default(),
        calendar: object
            .get("fields")
            .and_then(Value::as_object)
            .map(|fields| calendar_fields_from_metadata(fields, decrypt_ctx, &primary_strand_id))
            .unwrap_or_default(),
        primary_strand_id,
        locked_strand,
        external_visibility,
        history_visibility,
        security_encrypted: crate::security_state::strand_projection_security_state(&object),
        state: CardState::Synced,
        lifecycle: StrandLifecycleState::Active,
    }
}

pub(crate) fn columns_from_lifecycle_projection(
    containers: &[crate::state::projection_views::SpaceContainerProjectionView],
    strands: &[crate::state::projection_views::StrandProjectionView],
    preferred_board_id: &str,
    decrypt_ctx: Option<&MlsDecryptCtx<'_>>,
) -> (Vec<KanbanColumn>, Vec<BoardSpaceOption>, Option<String>) {
    let board_options = board_space_options_from_projection(containers);
    let selected_board_id = if !preferred_board_id.trim().is_empty()
        && board_options
            .iter()
            .any(|option| option.id == preferred_board_id)
    {
        Some(preferred_board_id.to_owned())
    } else {
        board_options.first().map(|option| option.id.clone())
    };
    let Some(board_id) = selected_board_id else {
        return (Vec::new(), board_options, None);
    };

    let mut cols = containers
        .iter()
        .filter(|view| {
            view.kind == "list" && view.parent_space_id.as_deref() == Some(board_id.as_str())
        })
        .map(|view| KanbanColumn {
            id: view.space_id.clone(),
            title: if view.title.trim().is_empty() {
                view.space_id.clone()
            } else {
                view.title.clone()
            },
            rank: view.rank.clone().unwrap_or_default(),
            cards: Vec::new(),
            state: space_container_state_from_projection(&view.state),
        })
        .collect::<Vec<_>>();
    cols.sort_by(|left, right| {
        left.rank
            .cmp(&right.rank)
            .then(left.title.cmp(&right.title))
            .then(left.id.cmp(&right.id))
    });

    for strand in strands.iter().filter(|strand| {
        strand_projection_field_string(
            strand,
            strand.board_space_id.as_deref(),
            &["board_space_id"],
        )
        .as_deref()
            == Some(board_id.as_str())
    }) {
        let Some(list_space_id) = strand_projection_field_string(
            strand,
            strand.list_space_id.as_deref(),
            &["list_space_id"],
        ) else {
            continue;
        };
        if let Some(column) = cols.iter_mut().find(|col| col.id == list_space_id) {
            column
                .cards
                .push(card_from_strand_projection(strand, decrypt_ctx));
        }
    }

    for column in &mut cols {
        sort_kanban_cards(&mut column.cards);
    }

    (cols, board_options, Some(board_id))
}

pub(crate) fn sort_kanban_cards(cards: &mut [KanbanCard]) {
    cards.sort_by(|left, right| {
        left.rank
            .cmp(&right.rank)
            .then(left.title.cmp(&right.title))
            .then(left.id.cmp(&right.id))
    });
}

pub(crate) fn reorder_column_before(
    columns: &mut Vec<KanbanColumn>,
    dragged_id: &str,
    target_id: &str,
) -> bool {
    if dragged_id == target_id {
        return false;
    }
    let Some(from_index) = columns.iter().position(|column| column.id == dragged_id) else {
        return false;
    };
    let Some(target_index) = columns.iter().position(|column| column.id == target_id) else {
        return false;
    };
    let dragged = columns.remove(from_index);
    let insert_index = if from_index < target_index {
        target_index.saturating_sub(1)
    } else {
        target_index
    };
    columns.insert(insert_index, dragged);
    for (index, column) in columns.iter_mut().enumerate() {
        column.rank = format!("r{:03}", index + 1);
    }
    true
}
