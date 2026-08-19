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

/// Whether a selected Board handle is a protocol Space id that downstream
/// writes may reference.
///
/// A freshly-created Board is selected optimistically by its holder-local
/// operation id. That UUID is useful as a UI key, but it is deliberately not
/// an Arkret identifier and must never be passed to a List create as
/// `parent_space_id`. The accepted create receipt later migrates the selection
/// to `retype(event_id)`, at which point child writes are safe to enable.
pub(crate) fn board_space_id_accepts_children(board_id: &str) -> bool {
    arkret_sdk::SpaceId::new(board_id).is_ok()
}

pub(crate) fn preserve_pending_board_space_options(
    mut projected: Vec<BoardSpaceOption>,
    current: &[BoardSpaceOption],
    aliases: &BTreeMap<String, String>,
) -> Vec<BoardSpaceOption> {
    for pending in current.iter().filter(|option| {
        !board_space_id_accepts_children(&option.id)
            && resolve_event_derived_target_alias(aliases, &option.id) == option.id
    }) {
        if !projected.iter().any(|option| option.id == pending.id) {
            projected.push(pending.clone());
        }
    }
    sort_board_space_options(&mut projected);
    projected
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
