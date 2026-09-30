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

#[allow(clippy::expect_used)]
pub(crate) fn initial_board_space_options(seed_fallback_allowed: bool) -> Vec<BoardSpaceOption> {
    if seed_fallback_allowed {
        vec![BoardSpaceOption {
            id: arkret_sdk::SpaceId::new(DEMO_BOARD_SPACE_ID)
                .expect("demo board seed carries a canonical Space id"),
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
        .filter(|view| view.kind == "board" && view.state != arkret_sdk::SpaceState::Tombstoned)
        // Fail closed: only a canonical `ak:space:` id may become a Board
        // option. A pending create still keyed by its holder-local handle is
        // surfaced by `pending_board_creates_from_ops` instead.
        .filter_map(|view| {
            let id = arkret_sdk::SpaceId::new(view.space_id.clone()).ok()?;
            Some(BoardSpaceOption {
                id,
                title: if view.title.trim().is_empty() {
                    view.space_id.clone()
                } else {
                    view.title.clone()
                },
                state: space_container_state_from_projection(&view.state),
            })
        })
        .collect::<Vec<_>>();
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
        // Pending creates are still keyed by their holder-local handle; they
        // belong to `pending_board_creates_from_ops`, never to the confirmed
        // option set.
        let Ok(local_id) = arkret_sdk::SpaceId::new(local_create.id.clone()) else {
            continue;
        };
        if let Some(existing) = options.iter_mut().find(|option| option.id == local_id) {
            if should_replace_projected_container_title(&existing.title, existing.id.as_str()) {
                existing.title = local_create.title;
            }
            if existing.state == SpaceContainerLifecycleState::Tombstoned {
                existing.state = SpaceContainerLifecycleState::Active;
            }
            continue;
        }
        options.push(BoardSpaceOption {
            id: local_id,
            title: local_create.title,
            state: SpaceContainerLifecycleState::Active,
        });
    }
    sort_board_space_options(&mut options);
    options
}

/// Default-actor form of [`columns_from_lifecycle_projection_for_actor`].
/// Test-only, for the same reason.
#[cfg(test)]
pub(crate) fn columns_from_lifecycle_projection(
    containers: &[crate::state::projection_views::SpaceContainerProjectionView],
    strands: &[crate::state::projection_views::StrandProjectionView],
    preferred_board_id: &str,
    decrypt_ctx: Option<&MlsDecryptCtx<'_>>,
) -> (Vec<KanbanColumn>, Vec<BoardSpaceOption>, Option<String>) {
    columns_from_lifecycle_projection_for_actor(
        containers,
        strands,
        preferred_board_id,
        decrypt_ctx,
        "",
    )
}

pub(crate) fn columns_from_lifecycle_projection_for_actor(
    containers: &[crate::state::projection_views::SpaceContainerProjectionView],
    strands: &[crate::state::projection_views::StrandProjectionView],
    preferred_board_id: &str,
    decrypt_ctx: Option<&MlsDecryptCtx<'_>>,
    self_actor_id: &str,
) -> (Vec<KanbanColumn>, Vec<BoardSpaceOption>, Option<String>) {
    let board_options = board_space_options_from_projection(containers);
    let selected_board_id = if !preferred_board_id.trim().is_empty()
        && board_options
            .iter()
            .any(|option| option.id.as_str() == preferred_board_id)
    {
        Some(preferred_board_id.to_owned())
    } else {
        board_options.first().map(|option| option.id.to_string())
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

    // Placement comes from the projection row's own columns only — see
    // [`strand_projection_placement_string`]. A Strand with no List is not a
    // broken row: it is a created-but-not-yet-moved card, and it belongs in no
    // column until its first `ak.strand.move` is observed.
    for strand in strands.iter().filter(|strand| {
        strand_projection_placement_string(strand.board_space_id.as_deref()).as_deref()
            == Some(board_id.as_str())
    }) {
        let Some(list_space_id) =
            strand_projection_placement_string(strand.list_space_id.as_deref())
        else {
            continue;
        };
        if let Some(column) = cols.iter_mut().find(|col| col.id == list_space_id) {
            column.cards.push(card_from_strand_projection_for_actor(
                strand,
                decrypt_ctx,
                self_actor_id,
            ));
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
