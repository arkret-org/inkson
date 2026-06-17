use super::*;

/// T20 wire-up — `collection_projection_to_columns` adapter maps the
/// spec-registered `collection_projection_view` response
/// (`view.schema.json`) into the renderer's KanbanColumn vec. This
/// is the core integration point; if the spec wire shape changes,
/// this test fails and points at the renderer adapter.
#[test]
fn collection_projection_maps_to_kanban_columns() {
    use crate::api::{
        CollectionProjectionGroupView, CollectionProjectionView, ProjectionItemView,
        StateFrontierView,
    };
    let projection = CollectionProjectionView {
        projection: "collection".to_owned(),
        renderer: Some("board".to_owned()),
        view_id: "ck:view:01904100-0000-7000-8000-000000000001".to_owned(),
        realm_id: None,
        frontier: StateFrontierView {
            state_digest: "sha256:0000000000000000000000000000000000000000000000000000000000000000"
                .to_owned(),
            event_ids: vec!["ck:event:01904100-0000-7000-8000-000000000042".to_owned()],
            actor_frontiers: Vec::new(),
        },
        groups: vec![
            CollectionProjectionGroupView {
                key: "ck:space:01c3b617-7000-7000-8000-000000000000".to_owned(),
                title: "Review".to_owned(),
                rank: Some("mV".to_owned()),
                source: None,
                items: vec![ProjectionItemView {
                    object: serde_json::json!({
                        "id": "ck:strand:01d2b330-0000-7000-8000-000000000000",
                        "type": "strand",
                        "title": "Legal review",
                        "summary": "ensure GDPR sign-off",
                        "body": {
                            "kind": "ck.content.text",
                            "body": "Review processor wording before beta."
                        },
                    }),
                    render: None,
                    display: None,
                    position: None,
                    state: Some(serde_json::json!({
                        "discussion": {
                            "enabled": true,
                            "visibility": "locked",
                            "lazy_link": true,
                        }
                    })),
                }],
                next_cursor: None,
                limited: false,
                wip_state: None,
                total_estimate: None,
            },
            CollectionProjectionGroupView {
                key: "ck:space:01t0d0000000000000000000000".to_owned(),
                title: "To do".to_owned(),
                rank: Some("aA".to_owned()),
                source: None,
                items: Vec::new(),
                next_cursor: None,
                limited: false,
                wip_state: None,
                total_estimate: None,
            },
        ],
        items: Vec::new(),
        next_cursor: None,
        total_estimate: None,
        stale: None,
    };

    let cols = collection_projection_to_columns(&projection, None);
    assert_eq!(cols.len(), 2, "two groups → two columns");
    assert_eq!(cols[0].id, "ck:space:01c3b617-7000-7000-8000-000000000000");
    assert_eq!(cols[0].title, "Review");
    assert_eq!(cols[0].rank, "mV");
    assert_eq!(cols[0].cards.len(), 1);
    let card = &cols[0].cards[0];
    assert_eq!(card.id, "ck:strand:01d2b330-0000-7000-8000-000000000000");
    assert_eq!(card.title, "Legal review");
    assert_eq!(card.description, "ensure GDPR sign-off");
    assert_eq!(card.body, "Review processor wording before beta.");
    // Locked discussion + lazy_link should populate locked_strand
    // and the cross-Space hint without leaking room contents.
    assert!(
        card.locked_strand.is_some(),
        "locked discussion → LockedStrand"
    );
    assert_eq!(
        card.history_visibility, "lazy_link (cross-Space)",
        "lazy_link=true must be reflected without exposing members"
    );
    assert!(matches!(card.state, CardState::Synced));
    // Empty group still produces an empty-cards column (board renders it).
    assert_eq!(cols[1].cards.len(), 0);
}

#[test]
fn collection_projection_overlay_applies_remote_encrypted_strand_updates() {
    use crate::api::{
        CollectionProjectionGroupView, CollectionProjectionView, ProjectionItemView,
        StateFrontierView,
    };
    let board_id = "ck:space:0196419b-0000-7000-8000-000000000001";
    let strand_id = "ck:strand:0196419b-0000-7000-8000-000000000003";
    let projection = CollectionProjectionView {
        projection: "collection".to_owned(),
        renderer: Some("board".to_owned()),
        view_id: "ck:view:01904100-0000-7000-8000-000000000001".to_owned(),
        realm_id: None,
        frontier: StateFrontierView::default(),
        groups: vec![CollectionProjectionGroupView {
            key: board_id.to_owned(),
            title: "Todo".to_owned(),
            rank: Some("U".to_owned()),
            source: None,
            items: vec![ProjectionItemView {
                object: json!({
                    "id": strand_id,
                    "type": "strand",
                    "title": "Encrypted card",
                }),
                render: None,
                display: None,
                position: None,
                state: None,
            }],
            next_cursor: None,
            limited: false,
            wip_state: None,
            total_estimate: None,
        }],
        items: Vec::new(),
        next_cursor: None,
        total_estimate: None,
        stale: None,
    };
    let envelope = json!({
        "scheme": "mls-rfc9420",
        "ciphertext": "AAAA",
        "content_type": KANBAN_STRAND_PATCH_VALUE_CONTENT_TYPE,
        "group_id": "g",
        "epoch": 0,
    });
    let events = vec![json!({
        "event_id": "ck:event:0196419b-0000-7000-8000-00000000f003",
        "operation_id": "ck:operation:0196419b-0000-7000-8000-00000000f003",
        "event_kind": "ck.strand.update",
        "actor_id": "did:web:alice.example",
        "created_at": "2026-05-22T10:00:00Z",
        "realm_id": TEST_REALM_ID,
        "payload": {
            "strand_id": strand_id,
            "patch": {
                "body": { "$op": "set", "value": envelope.clone() },
                "synthesis": { "$op": "set", "value": envelope }
            }
        }
    })];
    let remote_operations = strand_update_operations_from_events(&events);
    let store = LocalStateStore::default();
    let ctx = MlsDecryptCtx {
        state_store: &store,
        realm_id: TEST_REALM_ID,
        actor_id: "did:web:alice.example",
        device_id: "ck:device:0196419b-0000-7000-8000-000000000001",
    };

    let cols = overlay_collection_projection_with_operations(
        &projection,
        &store,
        board_id,
        &remote_operations,
        Some(&ctx),
    );

    let card = &cols[0].cards[0];
    assert_eq!(card.body, "");
    assert!(card.body_locked);
    assert_eq!(card.synthesis, "");
    assert!(card.synthesis_locked);
}

/// T20 — when no `state.discussion` metadata is present on the
/// registered projection item, the card renders as synthesis-only
/// without a locked_strand.
#[test]
fn projection_item_without_discussion_renders_synthesis_only() {
    use crate::api::ProjectionItemView;
    let item = ProjectionItemView {
        object: serde_json::json!({
            "id": "ck:strand:01doc",
            "title": "DID method allowlist",
        }),
        render: None,
        display: None,
        position: None,
        state: None,
    };
    let card = card_from_projection_item(&item, None);
    assert!(card.locked_strand.is_none());
    assert_eq!(card.history_visibility, "synthesis-only");
    assert_eq!(card.external_visibility, "No external discussions linked");
}

#[test]
fn board_space_options_pick_board_spaces_from_projection() {
    let options = board_space_options_from_projection(&[
        crate::api::SpaceContainerProjectionView {
            space_id: "ck:space:0196419b-0000-7000-8000-000000000001".to_owned(),
            realm_id: "ck:realm:0196419b-0000-7000-8000-000000000000".to_owned(),
            kind: "board".to_owned(),
            title: "Release".to_owned(),
            state: "active".to_owned(),
            rank: None,
            parent_space_id: None,
        },
        crate::api::SpaceContainerProjectionView {
            space_id: "ck:space:0196419b-0000-7000-8000-000000000002".to_owned(),
            realm_id: "ck:realm:0196419b-0000-7000-8000-000000000000".to_owned(),
            kind: "list".to_owned(),
            title: "Todo".to_owned(),
            state: "active".to_owned(),
            rank: Some("U".to_owned()),
            parent_space_id: Some("ck:space:0196419b-0000-7000-8000-000000000001".to_owned()),
        },
    ]);

    assert_eq!(options.len(), 1);
    assert_eq!(
        options[0].id,
        "ck:space:0196419b-0000-7000-8000-000000000001"
    );
    assert_eq!(options[0].title, "Release");
}

#[test]
fn local_space_create_overlay_restores_board_and_list_until_projection_catches_up() {
    let realm_id = "ck:realm:0196419b-0000-7000-8000-000000000000";
    let board_id = "ck:space:0196419b-0000-7000-8000-000000000001";
    let list_id = "ck:space:0196419b-0000-7000-8000-000000000002";
    let raw_operations = vec![
        RawOperationRecord {
            operation_id: "sha256:local-board-create".to_owned(),
            realm_id: Some(realm_id.to_owned()),
            received_at: chrono::Utc::now(),
            payload: json!({
                "kind": "ck.space.create",
                "operation_id": "sha256:local-board-create",
                "body": {
                    "object": {
                        "id": board_id,
                        "schema": "ck.schema.space.v1",
                        "realm_id": realm_id,
                        "kind": "board",
                        "title": "Design board"
                    }
                },
                "write_state": "queued"
            }),
        },
        RawOperationRecord {
            operation_id: "sha256:local-list-create".to_owned(),
            realm_id: Some(realm_id.to_owned()),
            received_at: chrono::Utc::now(),
            payload: json!({
                "kind": "ck.space.create",
                "operation_id": "sha256:local-list-create",
                "body": {
                    "object": {
                        "id": list_id,
                        "schema": "ck.schema.space.v1",
                        "realm_id": realm_id,
                        "kind": "list",
                        "title": "Todo",
                        "parent_space_id": board_id,
                        "rank": "U"
                    }
                },
                "write_state": "queued"
            }),
        },
    ];

    let (columns, options, selected_board) = columns_from_lifecycle_projection_with_local(
        &[],
        &[],
        board_id,
        &raw_operations,
        realm_id,
        None,
    );

    assert_eq!(selected_board.as_deref(), Some(board_id));
    assert_eq!(options.len(), 1);
    assert_eq!(options[0].id, board_id);
    assert_eq!(options[0].title, "Design board");
    assert_eq!(columns.len(), 1);
    assert_eq!(columns[0].id, list_id);
    assert_eq!(columns[0].title, "Todo");
}

#[test]
fn remote_space_create_backfill_restores_board_title_when_projection_only_has_list() {
    let realm_id = "ck:realm:0196419b-0000-7000-8000-000000000000";
    let board_id = "ck:space:0196419b-0000-7000-8000-000000000001";
    let list_id = "ck:space:0196419b-0000-7000-8000-000000000002";
    let events = vec![json!({
        "event_id": "ck:event:0196419b-0000-7000-8000-000000000101",
        "event_kind": "ck.space.create",
        "realm_id": realm_id,
        "actor_id": "did:web:alice.example",
        "created_at": "2026-05-31T00:00:00Z",
        "payload": {
            "object": {
                "id": board_id,
                "schema": "ck.schema.space.v1",
                "realm_id": realm_id,
                "kind": "board",
                "title": "Board"
            }
        }
    })];
    let remote_operations = space_create_operations_from_events(&events);
    let containers = vec![crate::api::SpaceContainerProjectionView {
        space_id: list_id.to_owned(),
        realm_id: realm_id.to_owned(),
        kind: "list".to_owned(),
        title: "Todos".to_owned(),
        state: "active".to_owned(),
        rank: Some("U".to_owned()),
        parent_space_id: Some(board_id.to_owned()),
    }];

    let (columns, options, selected_board) = columns_from_lifecycle_projection_with_local(
        &containers,
        &[],
        board_id,
        &remote_operations,
        realm_id,
        None,
    );

    assert_eq!(selected_board.as_deref(), Some(board_id));
    assert_eq!(options.len(), 1);
    assert_eq!(options[0].id, board_id);
    assert_eq!(options[0].title, "Board");
    assert_eq!(columns.len(), 1);
    assert_eq!(columns[0].title, "Todos");
}

#[test]
fn local_space_create_state_becomes_synced_once_projection_contains_target() {
    let board_id = "ck:space:0196419b-0000-7000-8000-000000000001";
    let raw_operations = vec![RawOperationRecord {
        operation_id: "sha256:local-board-create".to_owned(),
        realm_id: Some("ck:realm:0196419b-0000-7000-8000-000000000000".to_owned()),
        received_at: chrono::Utc::now(),
        payload: json!({
            "kind": "ck.space.create",
            "operation_id": "sha256:local-board-create",
            "body": {
                "object": {
                    "id": board_id,
                    "schema": "ck.schema.space.v1",
                    "kind": "board",
                    "title": "Design board"
                }
            },
            "write_state": "queued"
        }),
    }];
    let projected_ids = BTreeSet::from([board_id.to_owned()]);

    let state = local_space_create_state_for_target(&raw_operations, &projected_ids, board_id);

    assert_eq!(state, Some(CardState::Synced));
}

#[test]
fn displayed_card_state_uses_server_strand_projection_over_local_queue() {
    let strand_id = "ck:strand:0196419b-0000-7000-8000-000000000003";
    let mut card = test_card(strand_id, "U");
    card.state = CardState::Queued;
    let projected_strand_ids = BTreeSet::from([strand_id.to_owned()]);

    assert_eq!(
        displayed_card_state(&card, &projected_strand_ids),
        CardState::Synced
    );
}

#[test]
fn lifecycle_projection_builds_persisted_board_columns_and_cards() {
    let board_id = "ck:space:0196419b-0000-7000-8000-000000000001";
    let list_id = "ck:space:0196419b-0000-7000-8000-000000000002";
    let containers = vec![
        crate::api::SpaceContainerProjectionView {
            space_id: board_id.to_owned(),
            realm_id: "ck:realm:0196419b-0000-7000-8000-000000000000".to_owned(),
            kind: "board".to_owned(),
            title: "Release".to_owned(),
            state: "active".to_owned(),
            rank: None,
            parent_space_id: None,
        },
        crate::api::SpaceContainerProjectionView {
            space_id: list_id.to_owned(),
            realm_id: "ck:realm:0196419b-0000-7000-8000-000000000000".to_owned(),
            kind: "list".to_owned(),
            title: "Todo".to_owned(),
            state: "active".to_owned(),
            rank: Some("U".to_owned()),
            parent_space_id: Some(board_id.to_owned()),
        },
    ];
    let strands = vec![crate::api::StrandProjectionView {
        strand_id: "ck:strand:0196419b-0000-7000-8000-000000000003".to_owned(),
        realm_id: "ck:realm:0196419b-0000-7000-8000-000000000000".to_owned(),
        title: "Persisted card".to_owned(),
        summary: Some("Loaded from projection".to_owned()),
        body: Some(json!({
            "kind": "ck.content.text",
            "body": "Projection body content"
        })),
        board_space_id: Some(board_id.to_owned()),
        list_space_id: Some(list_id.to_owned()),
        rank: Some("U".to_owned()),
        assigned_actor_ids: vec!["did:web:alice.example".to_owned()],
        assigned_to_relations: vec![crate::api::AssignedToRelationProjectionView {
            relation_id: "ck:relation:0196419b-0000-7000-8000-000000000004".to_owned(),
            actor_id: "did:web:alice.example".to_owned(),
        }],
        fields: Map::from_iter([
            ("labels".to_owned(), json!(["demo", "db"])),
            ("due_at".to_owned(), json!("2026-05-22")),
        ]),
        created_by: Some("did:web:acme.example:users:alice".to_owned()),
        created_at: Some("2026-05-22T10:00:00Z".to_owned()),
        updated_at: None,
        state: "active".to_owned(),
    }];

    let (columns, options, selected_board) =
        columns_from_lifecycle_projection(&containers, &strands, "", None);

    assert_eq!(selected_board.as_deref(), Some(board_id));
    assert_eq!(options.len(), 1);
    assert_eq!(columns.len(), 1);
    assert_eq!(columns[0].title, "Todo");
    assert_eq!(columns[0].cards.len(), 1);
    let card = &columns[0].cards[0];
    assert_eq!(card.title, "Persisted card");
    assert_eq!(card.description, "Loaded from projection");
    assert_eq!(card.body, "Projection body content");
    assert_eq!(card.labels, vec!["demo".to_owned(), "db".to_owned()]);
    assert_eq!(card.assignee, "did:web:alice.example");
    assert_eq!(
        card.assigned_to_relations,
        vec![CardAssignedToRelation {
            relation_id: "ck:relation:0196419b-0000-7000-8000-000000000004".to_owned(),
            actor_id: "did:web:alice.example".to_owned(),
        }]
    );
    assert_eq!(card.due, "2026-05-22");
}

#[test]
fn lifecycle_projection_infers_board_from_list_parent() {
    let board_id = "ck:space:0196419b-0000-7000-8000-000000000001";
    let list_id = "ck:space:0196419b-0000-7000-8000-000000000002";
    let containers = vec![crate::api::SpaceContainerProjectionView {
        space_id: list_id.to_owned(),
        realm_id: "ck:realm:0196419b-0000-7000-8000-000000000000".to_owned(),
        kind: "list".to_owned(),
        title: "Todo".to_owned(),
        state: "active".to_owned(),
        rank: Some("U".to_owned()),
        parent_space_id: Some(board_id.to_owned()),
    }];

    let (columns, options, selected_board) =
        columns_from_lifecycle_projection(&containers, &[], "", None);

    assert_eq!(selected_board.as_deref(), Some(board_id));
    assert_eq!(options.len(), 1);
    assert_eq!(options[0].id, board_id);
    assert_eq!(columns.len(), 1);
    assert_eq!(columns[0].id, list_id);
    assert_eq!(columns[0].title, "Todo");
}

#[test]
fn local_strand_create_overlay_restores_card_until_projection_catches_up() {
    let board_id = "ck:space:0196419b-0000-7000-8000-000000000001";
    let list_id = "ck:space:0196419b-0000-7000-8000-000000000002";
    let strand_id = "ck:strand:0196419b-0000-7000-8000-000000000003";
    let raw_operations = vec![RawOperationRecord {
        operation_id: "sha256:local-create".to_owned(),
        realm_id: Some("ck:realm:0196419b-0000-7000-8000-000000000000".to_owned()),
        received_at: chrono::Utc::now(),
        payload: json!({
            "kind": "ck.strand.create",
            "operation_id": "sha256:local-create",
            "effect": {
                "strand_id": strand_id,
                "board_space_id": board_id,
                "list_space_id": list_id,
                "title": "Refresh-surviving card",
                "rank": "U",
                "strand_kind": "card"
            },
            "write_state": "queued"
        }),
    }];
    let projected_columns = vec![KanbanColumn {
        id: list_id.to_owned(),
        title: "Todo".to_owned(),
        rank: "U".to_owned(),
        cards: Vec::new(),
        state: SpaceContainerLifecycleState::Active,
    }];

    let overlaid =
        overlay_local_card_create_records(projected_columns.clone(), &raw_operations, board_id);
    assert_eq!(overlaid[0].cards.len(), 1);
    assert_eq!(overlaid[0].cards[0].id, strand_id);
    assert_eq!(overlaid[0].cards[0].title, "Refresh-surviving card");
    assert_eq!(overlaid[0].cards[0].state, CardState::Queued);

    let overlaid_again =
        overlay_local_card_create_records(overlaid.clone(), &raw_operations, board_id);
    assert_eq!(
        overlaid_again[0].cards.len(),
        1,
        "overlay must be idempotent across repeated projection refreshes"
    );

    let mut projected_with_server_card = projected_columns;
    projected_with_server_card[0]
        .cards
        .push(test_card(strand_id, "U"));
    let de_duped =
        overlay_local_card_create_records(projected_with_server_card, &raw_operations, board_id);
    assert_eq!(
        de_duped[0].cards.len(),
        1,
        "server projection wins once the reducer has materialized the card"
    );
    assert_eq!(de_duped[0].cards[0].state, CardState::Synced);
}

#[test]
fn remote_strand_update_events_overlay_detail_fields_on_projection() {
    let board_id = "ck:space:0196419b-0000-7000-8000-000000000001";
    let strand_id = "ck:strand:0196419b-0000-7000-8000-000000000003";
    let mut card = test_card(strand_id, "U");
    card.description = "old summary".to_owned();
    card.body = String::new();
    card.synthesis = String::new();
    let columns = vec![KanbanColumn {
        id: "ck:space:0196419b-0000-7000-8000-000000000002".to_owned(),
        title: "Todo".to_owned(),
        rank: "U".to_owned(),
        cards: vec![card],
        state: SpaceContainerLifecycleState::Active,
    }];
    let events = vec![json!({
        "event_id": "ck:event:0196419b-0000-7000-8000-00000000f001",
        "operation_id": "ck:operation:0196419b-0000-7000-8000-00000000f001",
        "event_kind": "ck.strand.update",
        "actor_id": "did:web:alice.example",
        "created_at": "2026-05-22T10:00:00Z",
        "realm_id": "ck:realm:0196419b-0000-7000-8000-000000000000",
        "payload": {
            "strand_id": strand_id,
            "patch": {
                "metadata.summary": { "$op": "set", "value": "new summary" },
                "fields.body": { "$op": "set", "value": "new long description" },
                "tracks.synthesis.body": { "$op": "set", "value": "new synthesis note" },
                "metadata.fields": {
                    "$op": "set",
                    "value": {
                        "labels": ["remote"],
                        "due_at": "2026-05-30"
                    }
                }
            }
        }
    })];
    let remote_operations = strand_update_operations_from_events(&events);

    let projected = overlay_card_projection_with_operations(
        columns,
        &LocalStateStore::default(),
        board_id,
        &remote_operations,
    );

    let card = &projected[0].cards[0];
    assert_eq!(card.description, "new summary");
    assert_eq!(card.body, "new long description");
    assert_eq!(card.synthesis, "new synthesis note");
    assert_eq!(card.labels, vec!["remote"]);
    assert_eq!(card.due, "2026-05-30");
    assert_eq!(card.state, CardState::Synced);
}

#[test]
fn remote_encrypted_strand_update_overlay_marks_private_fields_locked() {
    let board_id = "ck:space:0196419b-0000-7000-8000-000000000001";
    let strand_id = "ck:strand:0196419b-0000-7000-8000-000000000003";
    let mut card = test_card(strand_id, "U");
    card.body = String::new();
    card.synthesis = String::new();
    let columns = vec![KanbanColumn {
        id: "ck:space:0196419b-0000-7000-8000-000000000002".to_owned(),
        title: "Todo".to_owned(),
        rank: "U".to_owned(),
        cards: vec![card],
        state: SpaceContainerLifecycleState::Active,
    }];
    let envelope = json!({
        "scheme": "mls-rfc9420",
        "ciphertext": "AAAA",
        "content_type": KANBAN_STRAND_PATCH_VALUE_CONTENT_TYPE,
        "group_id": "g",
        "epoch": 0,
    });
    let events = vec![json!({
        "event_id": "ck:event:0196419b-0000-7000-8000-00000000f002",
        "operation_id": "ck:operation:0196419b-0000-7000-8000-00000000f002",
        "event_kind": "ck.strand.update",
        "actor_id": "did:web:alice.example",
        "created_at": "2026-05-22T10:00:00Z",
        "realm_id": "ck:realm:0196419b-0000-7000-8000-000000000000",
        "payload": {
            "strand_id": strand_id,
            "patch": {
                "body": { "$op": "set", "value": envelope.clone() },
                "tracks.synthesis.body": { "$op": "set", "value": {
                    "encrypted_content": envelope
                } }
            }
        }
    })];
    let remote_operations = strand_update_operations_from_events(&events);
    let store = LocalStateStore::default();
    let ctx = MlsDecryptCtx {
        state_store: &store,
        realm_id: TEST_REALM_ID,
        actor_id: "did:web:alice.example",
        device_id: "ck:device:0196419b-0000-7000-8000-000000000001",
    };

    let projected = overlay_card_projection_with_operations_and_decrypt(
        columns,
        &store,
        board_id,
        &remote_operations,
        Some(&ctx),
    );

    let card = &projected[0].cards[0];
    assert_eq!(card.body, "");
    assert!(card.body_locked);
    assert_eq!(card.synthesis, "");
    assert!(card.synthesis_locked);
    assert_eq!(card.state, CardState::Synced);
}

#[test]
fn kanban_seed_fallback_requires_explicit_opt_in() {
    assert!(!kanban_seed_fallback_allowed_for_url("https://local.host"));
    assert!(!kanban_seed_fallback_allowed_for_url(
        "http://127.0.0.1:8787"
    ));
    assert!(!kanban_seed_fallback_allowed_for_url(
        "https://cokret.example"
    ));
    assert!(truthy_env_value(Some("1")));
    assert!(truthy_env_value(Some("true")));
    assert!(!truthy_env_value(Some("0")));
    assert!(!truthy_env_value(None));
}
