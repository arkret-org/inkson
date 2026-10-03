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
    !realm_id.is_empty()
        && local_create
            .realm_id
            .as_deref()
            .is_some_and(|local_realm_id| trim_realm_id(local_realm_id) == trim_realm_id(realm_id))
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
    current_entries: &[arkret_wire::TypedCurrentResult],
) -> Vec<BoardSpaceOption> {
    let terminal_ids = terminal_space_ids_from_current(current_entries, realm_id);
    options.retain(|option| !terminal_ids.contains(option.id.as_str()));
    for current in board_space_options_from_projection(&space_container_views_from_current(
        current_entries,
        realm_id,
    )) {
        if let Some(existing) = options.iter_mut().find(|option| option.id == current.id) {
            *existing = current;
        } else {
            options.push(current);
        }
    }
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
        if terminal_ids.contains(local_id.as_str()) {
            continue;
        }
        if let Some(existing) = options.iter_mut().find(|option| option.id == local_id) {
            if should_replace_projected_container_title(&existing.title, existing.id.as_str()) {
                existing.title = local_create.title;
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

/// Join the registered Space sibling values from the installed current view.
/// Metadata never supplies a structural parent; missing siblings remain
/// unresolved rather than turning a List into a root or replaying its create.
pub(crate) fn space_container_views_from_current(
    entries: &[arkret_wire::TypedCurrentResult],
    realm_id: &str,
) -> Vec<crate::state::projection_views::SpaceContainerProjectionView> {
    use arkret_wire::{CommitStreamRef, CurrentSelector, TypedCurrentResult};

    let value_for = |selector: &CurrentSelector| {
        entries.iter().find_map(|entry| {
            let TypedCurrentResult::Value {
                selector: candidate,
                source_stream_ref: CommitStreamRef::Realm { realm_id: source },
                value,
                ..
            } = entry
            else {
                return None;
            };
            (source.as_str() == realm_id && candidate == selector).then_some(value)
        })
    };
    let spaces = entries
        .iter()
        .filter_map(|entry| {
            let TypedCurrentResult::Value {
                selector: CurrentSelector::Space { space_id },
                source_stream_ref: CommitStreamRef::Realm { realm_id: source },
                value,
                ..
            } = entry
            else {
                return None;
            };
            if source.as_str() != realm_id
                || value.get("parent_space_id").is_some()
                || value.get("child_scope_policy").is_some()
            {
                return None;
            }
            let parent = value_for(&CurrentSelector::SpaceParent {
                space_id: space_id.clone(),
            })?
            .as_object()?;
            if parent.len() != 1 {
                return None;
            }
            let policy = value_for(&CurrentSelector::SpaceChildScopePolicy {
                space_id: space_id.clone(),
            })?;
            let mut joined = value.clone();
            joined["parent_space_id"] = parent.get("parent_space_id")?.clone();
            joined["child_scope_policy"] = policy.clone();
            let space: arkret_sdk::Space = serde_json::from_value(joined).ok()?;
            if space.id.as_ref() != Some(space_id)
                || space.realm_id.as_str() != realm_id
                || space.scope_circle_id.is_some()
            {
                return None;
            }
            Some(
                crate::state::projection_views::SpaceContainerProjectionView {
                    space_id: space_id.to_string(),
                    realm_id: space.realm_id.to_string(),
                    kind: space.kind,
                    title: space.title,
                    state: space.state?,
                    rank: space.rank,
                    parent_space_id: space.parent_space_id.map(|id| id.to_string()),
                },
            )
        })
        .collect::<Vec<_>>();
    spaces
        .iter()
        .filter(|space| {
            arkret_sdk::validate_space_parent_chain(
                &space.space_id,
                &space.realm_id,
                space.parent_space_id.as_deref(),
                |id| {
                    spaces
                        .iter()
                        .find(|parent| parent.space_id == id)
                        .map(|parent| arkret_sdk::SpaceStructureNode {
                            realm_id: &parent.realm_id,
                            parent_space_id: parent.parent_space_id.as_deref(),
                            active: parent.state == arkret_sdk::SpaceState::Active,
                        })
                },
            )
            .is_ok()
        })
        .cloned()
        .collect()
}

pub(crate) fn kanban_space_current_selectors(
    board: Option<&arkret_sdk::SpaceId>,
    columns: &[KanbanColumn],
) -> Vec<arkret_wire::CurrentSelector> {
    use arkret_wire::CurrentSelector;
    // Three siblings per Space, within the product demand's 256-selector cap.
    // Remaining columns continue to display the complete derived read page.
    board
        .into_iter()
        .cloned()
        .chain(
            columns
                .iter()
                .filter_map(|column| arkret_sdk::SpaceId::new(column.id.clone()).ok()),
        )
        .take(85)
        .flat_map(|space_id| {
            [
                CurrentSelector::Space {
                    space_id: space_id.clone(),
                },
                CurrentSelector::SpaceParent {
                    space_id: space_id.clone(),
                },
                CurrentSelector::SpaceChildScopePolicy { space_id },
            ]
        })
        .collect()
}

/// Settle only the status of the write still displayed by this panel. A root
/// submission may outlive its component; render its durable result instead of
/// capturing a component-owned status signal across the await.
pub(crate) fn kanban_operation_status_text(
    status: &str,
    operations: &[RawOperationRecord],
) -> String {
    operations
        .iter()
        .rev()
        .find_map(|record| {
            let kind = record.payload.get("kind")?.as_str()?;
            if status
                != format!(
                    "submitting {kind} operation {}",
                    short_protocol_id(&record.operation_id)
                )
            {
                return None;
            }
            let write_state = record
                .payload
                .get("write_state")
                .and_then(Value::as_str)
                .or_else(|| {
                    record
                        .payload
                        .get("producer_proof")
                        .filter(|proof| proof.is_object())
                        .map(|_| "synced")
                });
            match write_state {
                Some("accepted" | "synced") => Some(format!("{kind} completed")),
                Some("failed" | "rejected" | "quarantined" | "dropped" | "cancelled") => {
                    Some(format!(
                        "{kind} failed: {}",
                        record
                            .payload
                            .get("error")
                            .and_then(Value::as_str)
                            .unwrap_or("operation did not complete")
                    ))
                }
                _ => None,
            }
        })
        .unwrap_or_else(|| status.to_owned())
}

/// Read only negative lifecycle facts from the installed verified current index.
/// This never grants visibility or reconstructs a missing container from history.
pub(crate) fn terminal_space_ids_from_current(
    entries: &[arkret_wire::TypedCurrentResult],
    realm_id: &str,
) -> std::collections::BTreeSet<String> {
    entries
        .iter()
        .filter_map(|entry| {
            let arkret_wire::TypedCurrentResult::Value {
                selector: arkret_wire::CurrentSelector::Space { space_id },
                source_stream_ref:
                    arkret_wire::CommitStreamRef::Realm {
                        realm_id: source_realm,
                    },
                value,
                ..
            } = entry
            else {
                return None;
            };
            let space: arkret_sdk::Space = serde_json::from_value(value.clone()).ok()?;
            (source_realm.as_str() == realm_id
                && space.realm_id.as_str() == realm_id
                && space.id.as_ref() == Some(space_id)
                && space.state == Some(arkret_sdk::SpaceState::Tombstoned))
            .then(|| space_id.to_string())
        })
        .collect()
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
