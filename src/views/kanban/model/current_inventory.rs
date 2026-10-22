use super::*;

pub(crate) fn kanban_operation_is_pending(record: &RawOperationRecord) -> bool {
    matches!(
        record.payload.get("write_state").and_then(Value::as_str),
        None | Some(
            "queued" | "submitting" | "forwarding" | "submitted" | "pending" | "pending_commit"
        )
    )
}

pub(crate) fn kanban_pending_operations(
    operations: &[RawOperationRecord],
) -> Vec<RawOperationRecord> {
    operations
        .iter()
        .filter(|record| kanban_operation_is_pending(record))
        .cloned()
        .collect()
}

pub(crate) fn overlay_local_card_assignment_records_at_current(
    columns: Vec<KanbanColumn>,
    operations: &[RawOperationRecord],
    complete_current: bool,
) -> Vec<KanbanColumn> {
    if complete_current {
        overlay_local_card_assignment_records(columns, &kanban_pending_operations(operations))
    } else {
        overlay_local_card_assignment_records(columns, operations)
    }
}

/// Display inventory selected by a complete, admitted current cut. These rows
/// carry no authoring authority; commands still need their exact current basis.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct KanbanCurrentInventory {
    pub containers: Vec<crate::state::projection_views::SpaceContainerProjectionView>,
    pub strands: Vec<crate::state::projection_views::StrandProjectionView>,
}

pub(crate) fn kanban_inventory_from_current(
    view: &crate::current_projection::RealmCurrentView,
    preferred_board: Option<&arkret_sdk::SpaceId>,
) -> anyhow::Result<Option<KanbanCurrentInventory>> {
    use arkret_wire::{CommitStreamRef, CurrentSelector, TypedCurrentRow};

    use crate::state::projection_views::{AssignedToRelationProjectionView, StrandProjectionView};

    if !view.ready() {
        return Ok(None);
    }
    let realm = arkret_sdk::RealmId::new(view.realm_id.clone())?;
    let containers = space_container_views_from_current(&view.entries, realm.as_str());
    let boards = board_space_options_from_projection(&containers);
    let preferred = preferred_board
        .filter(|id| boards.iter().any(|board| &board.id == *id))
        .cloned()
        .or_else(|| boards.first().map(|board| board.id.clone()));
    let mut strands = BTreeMap::<arkret_sdk::StrandId, StrandProjectionView>::new();
    let mut positions = BTreeMap::<
        arkret_sdk::StrandId,
        Vec<(
            arkret_sdk::SpaceId,
            arkret_models_collaboration::objects::strand::StrandPositionCurrent,
        )>,
    >::new();
    let mut assignments = BTreeMap::<String, Vec<AssignedToRelationProjectionView>>::new();
    for row in &view.entries {
        let TypedCurrentRow::Value {
            selector,
            source_stream_ref,
            value,
            ..
        } = row;
        anyhow::ensure!(
            source_stream_ref.realm_id() == &realm,
            "Kanban current row belongs to another Realm"
        );
        match selector {
            CurrentSelector::Strand { strand_id } => {
                let strand: arkret_sdk::Strand = serde_json::from_value(value.clone())?;
                anyhow::ensure!(
                    strand.id.as_ref() == Some(strand_id) && strand.realm_id == realm,
                    "Kanban current Strand differs from its selector"
                );
                let scope_matches = match source_stream_ref {
                    CommitStreamRef::Realm { .. } => strand.scope_circle_id.is_none(),
                    CommitStreamRef::Circle { circle_id, .. } => {
                        strand.scope_circle_id.as_ref() == Some(circle_id)
                    }
                    _ => false,
                };
                anyhow::ensure!(
                    scope_matches,
                    "Kanban current Strand differs from its source scope"
                );
                let metadata = strand.metadata.unwrap_or_default();
                let projected = StrandProjectionView {
                    strand_id: strand_id.to_string(),
                    realm_id: realm.to_string(),
                    title: metadata.title.unwrap_or_default(),
                    summary: metadata.summary,
                    content: strand.content,
                    encrypted_content: strand.encrypted_content,
                    tracks: strand.tracks,
                    fields: metadata.fields.into_iter().collect(),
                    schema_refs: strand.schema_refs.unwrap_or_default(),
                    board_space_id: None,
                    list_space_id: None,
                    rank: None,
                    assigned_actor_ids: Vec::new(),
                    assigned_to_relations: Vec::new(),
                    schedule_revision_source: None,
                    rsvps: Vec::new(),
                    state: strand.state.unwrap_or(arkret_sdk::ObjectState::Active),
                    created_by: Some(strand.created_by.signing_principal_id().to_string()),
                    created_at: Some(arkret_sdk::canonical::format_timestamp_canonical(
                        strand.created_at,
                    )),
                    updated_by: strand
                        .updated_by
                        .map(|actor| actor.signing_principal_id().to_string()),
                    updated_at: strand
                        .updated_at
                        .map(arkret_sdk::canonical::format_timestamp_canonical),
                };
                anyhow::ensure!(
                    strands.insert(strand_id.clone(), projected).is_none(),
                    "duplicate current Strand"
                );
            }
            CurrentSelector::StrandPosition {
                board_space_id,
                strand_id,
            } => {
                anyhow::ensure!(
                    matches!(source_stream_ref, CommitStreamRef::Realm { .. }),
                    "Kanban position must be selected by its Realm"
                );
                let position: Option<
                    arkret_models_collaboration::objects::strand::StrandPositionCurrent,
                > = serde_json::from_value(value.clone())?;
                if let Some(position) = position {
                    positions
                        .entry(strand_id.clone())
                        .or_default()
                        .push((board_space_id.clone(), position));
                }
            }
            CurrentSelector::Relation {
                primary_conflict_domain,
            } => {
                let relation: arkret_wire::relation::Relation =
                    serde_json::from_value(value.clone())?;
                relation.validate_current_for_domain(&realm, primary_conflict_domain)?;
                if relation.relation_kind != arkret_sdk::RelationKind::AssignedTo
                    || relation.state != Some(arkret_sdk::RelationState::Active)
                {
                    continue;
                }
                let Some(strand) = relation.from_ref.as_object_ref() else {
                    continue;
                };
                let Some(actor) = relation.to_ref.as_actor_id() else {
                    continue;
                };
                let id = relation
                    .id
                    .ok_or_else(|| anyhow::anyhow!("current assignment has no accepted id"))?;
                assignments.entry(strand.to_owned()).or_default().push(
                    AssignedToRelationProjectionView {
                        relation_id: id.to_string(),
                        actor_id: actor.clone(),
                    },
                );
            }
            _ => {}
        }
    }
    for (id, strand) in &mut strands {
        if let Some(candidates) = positions.get_mut(id) {
            candidates.sort_by(|left, right| left.0.cmp(&right.0));
            let position = candidates
                .iter()
                .find(|(board, _)| Some(board) == preferred.as_ref())
                .or_else(|| candidates.first());
            if let Some((board, position)) = position {
                strand.board_space_id = Some(board.to_string());
                strand.list_space_id = Some(position.list_space_id.to_string());
                strand.rank = Some(position.rank.clone());
            }
        }
        strand.assigned_to_relations = assignments.remove(id.as_str()).unwrap_or_default();
        strand
            .assigned_to_relations
            .sort_by(|left, right| left.relation_id.cmp(&right.relation_id));
        for relation in &strand.assigned_to_relations {
            if !strand.assigned_actor_ids.contains(&relation.actor_id) {
                strand.assigned_actor_ids.push(relation.actor_id.clone());
            }
        }
    }
    Ok(Some(KanbanCurrentInventory {
        containers,
        strands: strands.into_values().collect(),
    }))
}

#[cfg(test)]
mod tests {
    use arkret_wire::{CurrentRevision, CurrentSelector, TypedCurrentRow};

    use super::*;

    const REALM: &str = "ak:realm:AeEFmfOZxsx5kLi2kpOJu8m7TFXZ_G8E4019rUp4wmT6";

    fn event(index: u32) -> arkret_sdk::EventId {
        let mut digest = [0; 32];
        digest[..4].copy_from_slice(&index.to_be_bytes());
        arkret_sdk::EventId::from_digest(arkret_sdk::DigestSuite::Sha256, digest)
    }
    fn actor() -> arkret_sdk::ActorId {
        crate::test_support::account_actor("ak:did_core:web:alice.example")
    }
    fn row(selector: CurrentSelector, value: impl serde::Serialize) -> TypedCurrentRow {
        TypedCurrentRow::Value {
            selector,
            source_stream_ref: arkret_sdk::CommitStreamRef::Realm {
                realm_id: arkret_sdk::RealmId::new(REALM).unwrap(),
            },
            revision: CurrentRevision {
                commit_id: arkret_sdk::RealmCommitId::from_digest([9; 32]),
                stream_position: 9,
            },
            value: serde_json::to_value(value).unwrap(),
        }
    }
    fn space(
        id: &arkret_sdk::SpaceId,
        kind: &str,
        parent: Option<&arkret_sdk::SpaceId>,
    ) -> Vec<TypedCurrentRow> {
        let value = arkret_sdk::Space::new(
            id.clone(),
            arkret_sdk::RealmId::new(REALM).unwrap(),
            kind,
            kind,
            actor(),
        );
        vec![
            row(
                CurrentSelector::Space {
                    space_id: id.clone(),
                },
                value,
            ),
            row(
                CurrentSelector::SpaceParent {
                    space_id: id.clone(),
                },
                json!({"parent_space_id": parent}),
            ),
            row(
                CurrentSelector::SpaceChildScopePolicy {
                    space_id: id.clone(),
                },
                Value::Null,
            ),
        ]
    }
    fn view(
        count: u32,
    ) -> (
        crate::current_projection::RealmCurrentView,
        arkret_sdk::SpaceId,
        arkret_sdk::SpaceId,
        arkret_sdk::SpaceId,
    ) {
        let board = arkret_sdk::SpaceId::from_event_id(&event(10_000));
        let first = arkret_sdk::SpaceId::from_event_id(&event(10_001));
        let second = arkret_sdk::SpaceId::from_event_id(&event(10_002));
        let mut entries = vec![
            row(
                CurrentSelector::RealmProfile,
                arkret_models_collaboration::events_payloads::realm::RealmProfile::new("Realm")
                    .unwrap(),
            ),
            row(
                CurrentSelector::RealmPolicyBundle,
                arkret_models_collaboration::events_payloads::realm::RealmPolicyBundlePayload::new(
                    1,
                ),
            ),
        ];
        entries.extend(space(&board, "board", None));
        entries.extend(space(&first, "list", Some(&board)));
        entries.extend(space(&second, "list", Some(&board)));
        for index in 0..count {
            let id = arkret_sdk::StrandId::from_event_id(&event(index));
            entries.push(row(
                CurrentSelector::Strand {
                    strand_id: id.clone(),
                },
                arkret_sdk::Strand::new(
                    id.clone(),
                    arkret_sdk::RealmId::new(REALM).unwrap(),
                    format!("Card {index}"),
                    actor(),
                ),
            ));
            entries.push(row(
                CurrentSelector::StrandPosition {
                    board_space_id: board.clone(),
                    strand_id: id,
                },
                arkret_models_collaboration::objects::strand::StrandPositionCurrent {
                    list_space_id: first.clone(),
                    rank: format!("U{index:06}"),
                },
            ));
        }
        (
            crate::current_projection::RealmCurrentView::new(REALM, entries, true).unwrap(),
            board,
            first,
            second,
        )
    }

    #[test]
    fn complete_current_renders_501_cards_without_any_create_history() {
        let (view, board, first, _) = view(501);
        let inventory = kanban_inventory_from_current(&view, Some(&board))
            .unwrap()
            .unwrap();
        assert_eq!(inventory.strands.len(), 501);
        let (columns, ..) = project_board_with_current_inventory_for_actor(
            &[],
            &inventory.containers,
            &inventory.strands,
            board.as_str(),
            REALM,
            None,
            "",
            &view.entries,
            true,
        );
        let column = columns
            .iter()
            .find(|column| column.id == first.as_str())
            .unwrap();
        assert_eq!(column.cards.len(), 501);
        assert!(column.cards.iter().any(|card| card.title == "Card 500"));
        let mut incomplete = view;
        incomplete.complete_cut = false;
        assert!(
            kanban_inventory_from_current(&incomplete, Some(&board))
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn current_only_move_archive_and_null_placement_do_not_need_history() {
        let (mut view, board, first, second) = view(2);
        let id = arkret_sdk::StrandId::from_event_id(&event(1));
        for entry in &mut view.entries {
            let TypedCurrentRow::Value {
                selector, value, ..
            } = entry;
            match selector {
                CurrentSelector::Strand { strand_id } if strand_id == &id => {
                    value["state"] = json!("archived")
                }
                CurrentSelector::StrandPosition { strand_id, .. } if strand_id == &id => {
                    value["list_space_id"] = json!(second)
                }
                _ => {}
            }
        }
        let stale = RawOperationRecord {
            operation_id: event(20_000).to_string(),
            realm_id: Some(REALM.into()),
            received_at: "2026-10-22T00:00:00.000Z".parse().unwrap(),
            payload: json!({"kind":"ak.strand.move","write_state":"synced","body":{
                "strand_id":id,"board_space_id":board,"target_space_id":first,"rank":"U"}}),
        };
        let inventory = kanban_inventory_from_current(&view, Some(&board))
            .unwrap()
            .unwrap();
        let (columns, ..) = project_board_with_current_inventory_for_actor(
            &[stale],
            &inventory.containers,
            &inventory.strands,
            board.as_str(),
            REALM,
            None,
            "",
            &view.entries,
            true,
        );
        let moved = &columns
            .iter()
            .find(|column| column.id == second.as_str())
            .unwrap()
            .cards[0];
        assert_eq!(moved.id, id.as_str());
        assert_eq!(moved.lifecycle, StrandLifecycleState::Archived);
        for entry in &mut view.entries {
            let TypedCurrentRow::Value {
                selector, value, ..
            } = entry;
            if matches!(selector, CurrentSelector::StrandPosition { strand_id, .. } if strand_id == &id)
            {
                *value = Value::Null;
            }
        }
        let inventory = kanban_inventory_from_current(&view, Some(&board))
            .unwrap()
            .unwrap();
        assert!(
            inventory
                .strands
                .iter()
                .find(|row| row.strand_id == id.as_str())
                .unwrap()
                .list_space_id
                .is_none()
        );
    }

    #[test]
    fn a_mismatched_current_object_is_rejected_instead_of_replaced_by_history() {
        let (mut view, board, ..) = view(1);
        for entry in &mut view.entries {
            let TypedCurrentRow::Value {
                selector, value, ..
            } = entry;
            if matches!(selector, CurrentSelector::Strand { .. }) {
                value["id"] = json!(arkret_sdk::StrandId::from_event_id(&event(999)));
            }
        }
        assert!(kanban_inventory_from_current(&view, Some(&board)).is_err());
    }

    fn operation(index: u32, kind: &str, body: Value) -> RawOperationRecord {
        RawOperationRecord {
            operation_id: event(index).to_string(),
            realm_id: Some(REALM.into()),
            received_at: "2026-10-22T00:00:00.000Z".parse().unwrap(),
            payload: json!({"kind":kind,"write_state":"synced","event_id":event(index),"actor_id":actor(),"body":body}),
        }
    }

    #[test]
    fn history_cannot_reintroduce_a_strand_absent_from_complete_current() {
        let (view, board, first, _) = view(1);
        let ghost = arkret_sdk::StrandId::from_event_id(&event(999));
        let object =
            arkret_sdk::StrandCreateObject::new(arkret_sdk::RealmId::new(REALM).unwrap(), actor())
                .with_metadata_title("Old hidden card");
        let create = operation(999, "ak.strand.create", json!({"object":object}));
        let placement = operation(
            1000,
            "ak.strand.move",
            json!({"strand_id":ghost,
            "board_space_id":board,"target_space_id":first,"rank":"V"}),
        );
        let operations = vec![create, placement];
        assert_eq!(
            strand_views_from_projection_and_ops(&[], &operations).len(),
            1,
            "the old journal really contains a renderable historical Strand"
        );
        let inventory = kanban_inventory_from_current(&view, Some(&board))
            .unwrap()
            .unwrap();
        let (columns, ..) = project_board_with_current_inventory_for_actor(
            &operations,
            &inventory.containers,
            &inventory.strands,
            board.as_str(),
            REALM,
            None,
            "",
            &view.entries,
            true,
        );
        assert_eq!(
            columns
                .iter()
                .map(|column| column.cards.len())
                .sum::<usize>(),
            1
        );
        assert!(
            columns
                .iter()
                .flat_map(|column| &column.cards)
                .all(|card| card.id != ghost.as_str())
        );
    }

    #[test]
    fn current_assignments_preserve_station_identity_and_exclude_tombstones_and_old_events() {
        let (mut view, board, ..) = view(1);
        let strand = arkret_sdk::StrandId::from_event_id(&event(0));
        let assignee = |station: &str| {
            crate::test_support::authority_at_station("ak:did_core:web:assignee.example", station)
        };
        let actors = [
            "ak:did_core:web:station-a.example",
            "ak:did_core:web:station-b.example",
            "ak:did_core:web:station-c.example",
        ]
        .map(|station| arkret_sdk::ActorId::account(assignee(station)));
        for (index, target) in actors.iter().enumerate() {
            let relation = arkret_wire::relation::Relation {
                schema: arkret_wire::relation::Relation::SCHEMA.into(),
                id: Some(arkret_sdk::RelationId::from_event_id(&event(
                    20_000 + index as u32,
                ))),
                realm_id: arkret_sdk::RealmId::new(REALM).unwrap(),
                scope_circle_id: None,
                effective_scope: None,
                relation_kind: arkret_sdk::RelationKind::AssignedTo,
                from_ref: strand.to_string().into(),
                to_ref: target.clone().into(),
                rank: None,
                fields: BTreeMap::new(),
                state: Some(if index == 2 {
                    arkret_sdk::RelationState::Tombstoned
                } else {
                    arkret_sdk::RelationState::Active
                }),
                state_changed_at: (index == 2).then(|| "2026-10-22T00:00:00.000Z".parse().unwrap()),
                created_by: actor(),
                created_at: "2026-10-22T00:00:00.000Z".parse().unwrap(),
                updated_by: None,
                updated_at: None,
            };
            let domain = crate::operation::ak_ops::relation_actor_domain(
                "assigned_to",
                strand.as_str(),
                target,
            )
            .unwrap();
            view.entries.push(row(
                CurrentSelector::Relation {
                    primary_conflict_domain: domain,
                },
                relation,
            ));
        }
        let mut stale = operation(
            30_000,
            "ak.relation.create",
            json!({
            "relation_kind":"assigned_to", "from_ref":strand,"to_ref":actors[2]}),
        );
        stale.payload["assignment_relation_id"] =
            json!(arkret_sdk::RelationId::from_event_id(&event(30_000)));
        let inventory = kanban_inventory_from_current(&view, Some(&board))
            .unwrap()
            .unwrap();
        assert_eq!(inventory.strands[0].assigned_actor_ids.len(), 2);
        assert!(
            actors[..2]
                .iter()
                .all(|actor| inventory.strands[0].assigned_actor_ids.contains(actor))
        );
        let (columns, ..) = project_board_with_current_inventory_for_actor(
            &[stale],
            &inventory.containers,
            &inventory.strands,
            board.as_str(),
            REALM,
            None,
            "",
            &view.entries,
            true,
        );
        let relations = &columns
            .iter()
            .flat_map(|column| &column.cards)
            .next()
            .unwrap()
            .assigned_to_relations;
        assert_eq!(relations.len(), 2);
        assert!(
            relations
                .iter()
                .all(|relation| relation.actor_id != actors[2])
        );
    }
}
