use super::*;

#[test]
fn pending_board_handle_cannot_be_used_as_a_list_parent() {
    assert!(!board_space_id_accepts_children(
        "01a01bdd-804b-7ad0-bee8-194898437ad7"
    ));
    assert!(board_space_id_accepts_children(
        "ak:space:AaDn_ypTG8vV4ToKfz6JtG2xnepF9QDlafPZCT-UYPyR"
    ));
}

#[test]
fn pending_board_keeps_its_title_until_the_accepted_alias_arrives() {
    let pending_id = "01a01bdd-804b-7ad0-bee8-194898437ad7";
    let accepted_id = "ak:space:AaDn_ypTG8vV4ToKfz6JtG2xnepF9QDlafPZCT-UYPyR";
    let pending = BoardSpaceOption {
        id: pending_id.to_owned(),
        title: "Design board".to_owned(),
        state: SpaceContainerLifecycleState::Active,
    };

    let waiting = preserve_pending_board_space_options(
        Vec::new(),
        std::slice::from_ref(&pending),
        &BTreeMap::new(),
    );
    assert_eq!(waiting, vec![pending.clone()]);

    let accepted = BoardSpaceOption {
        id: accepted_id.to_owned(),
        title: "Design board".to_owned(),
        state: SpaceContainerLifecycleState::Active,
    };
    let aliases = BTreeMap::from([(pending_id.to_owned(), accepted_id.to_owned())]);
    let reconciled = preserve_pending_board_space_options(
        vec![accepted.clone()],
        std::slice::from_ref(&pending),
        &aliases,
    );
    assert_eq!(reconciled, vec![accepted]);
}

#[test]
fn board_space_options_pick_board_spaces_from_projection() {
    let options = board_space_options_from_projection(&[
        crate::state::projection_views::SpaceContainerProjectionView {
            space_id: "ak:space:Aepgr15HbtERKfqPAh9SrfWBdihSvX_c94JvujvBS2f-".to_owned(),
            realm_id: "ak:realm:AcbFC8Nil95DfV11kMMMvRtzRdEC3g-tFtBE8_VQQ74j".to_owned(),
            kind: "board".to_owned(),
            title: "Release".to_owned(),
            state: arkret_sdk::ProjectionSpaceState::Active,
            rank: None,
            parent_space_id: None,
        },
        crate::state::projection_views::SpaceContainerProjectionView {
            space_id: "ak:space:AQM8rE4gp8l4axkSbbb9_dkqwWE8ZPYHwFsC24o2mrIL".to_owned(),
            realm_id: "ak:realm:AcbFC8Nil95DfV11kMMMvRtzRdEC3g-tFtBE8_VQQ74j".to_owned(),
            kind: "list".to_owned(),
            title: "Todo".to_owned(),
            state: arkret_sdk::ProjectionSpaceState::Active,
            rank: Some("U".to_owned()),
            parent_space_id: Some(
                "ak:space:Aepgr15HbtERKfqPAh9SrfWBdihSvX_c94JvujvBS2f-".to_owned(),
            ),
        },
    ]);

    assert_eq!(options.len(), 1);
    assert_eq!(
        options[0].id,
        "ak:space:Aepgr15HbtERKfqPAh9SrfWBdihSvX_c94JvujvBS2f-"
    );
    assert_eq!(options[0].title, "Release");
}

#[test]
fn local_space_create_state_becomes_synced_once_projection_contains_target() {
    let board_id = "ak:space:Aepgr15HbtERKfqPAh9SrfWBdihSvX_c94JvujvBS2f-";
    let raw_operations = vec![RawOperationRecord {
        operation_id: "sha256:local-board-create".to_owned(),
        realm_id: Some("ak:realm:AcbFC8Nil95DfV11kMMMvRtzRdEC3g-tFtBE8_VQQ74j".to_owned()),
        received_at: chrono::Utc::now(),
        payload: json!({
            "kind": "ak.space.create",
            "operation_id": "sha256:local-board-create",
            "body": {
                "object": {
                    "id": board_id,
                    "schema": "ak.schema.space.v1",
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
    let strand_id = "ak:strand:AV624IkuHj3HmxAYE6uyYmBa4Est3gGGdnOsjn71z5L2";
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
    let board_id = "ak:space:Aepgr15HbtERKfqPAh9SrfWBdihSvX_c94JvujvBS2f-";
    let list_id = "ak:space:AQM8rE4gp8l4axkSbbb9_dkqwWE8ZPYHwFsC24o2mrIL";
    let containers = vec![
        crate::state::projection_views::SpaceContainerProjectionView {
            space_id: board_id.to_owned(),
            realm_id: "ak:realm:AcbFC8Nil95DfV11kMMMvRtzRdEC3g-tFtBE8_VQQ74j".to_owned(),
            kind: "board".to_owned(),
            title: "Release".to_owned(),
            state: arkret_sdk::ProjectionSpaceState::Active,
            rank: None,
            parent_space_id: None,
        },
        crate::state::projection_views::SpaceContainerProjectionView {
            space_id: list_id.to_owned(),
            realm_id: "ak:realm:AcbFC8Nil95DfV11kMMMvRtzRdEC3g-tFtBE8_VQQ74j".to_owned(),
            kind: "list".to_owned(),
            title: "Todo".to_owned(),
            state: arkret_sdk::ProjectionSpaceState::Active,
            rank: Some("U".to_owned()),
            parent_space_id: Some(board_id.to_owned()),
        },
    ];
    let strands = vec![crate::state::projection_views::StrandProjectionView {
        strand_id: "ak:strand:AV624IkuHj3HmxAYE6uyYmBa4Est3gGGdnOsjn71z5L2".to_owned(),
        realm_id: "ak:realm:AcbFC8Nil95DfV11kMMMvRtzRdEC3g-tFtBE8_VQQ74j".to_owned(),
        title: "Persisted card".to_owned(),
        summary: Some("Loaded from projection".to_owned()),
        content: Some(
            arkret_sdk::ContentBlock::text("Projection description content")
                .with_field("format", json!("markdown")),
        ),
        encrypted_content: None,
        tracks: BTreeMap::from([(
            arkret_sdk::STRAND_TRACK_NAME_SYNTHESIS.to_owned(),
            arkret_sdk::StrandTrack {
                content: Some(arkret_sdk::ContentBlock::text(
                    "Projection synthesis content",
                )),
                ..Default::default()
            },
        )]),
        board_space_id: Some(board_id.to_owned()),
        list_space_id: Some(list_id.to_owned()),
        rank: Some("U".to_owned()),
        assigned_actor_ids: vec!["did:web:alice.example".to_owned()],
        assigned_to_relations: vec![
            crate::state::projection_views::AssignedToRelationProjectionView {
                relation_id: "ak:relation:ASc_XP_IqOBAY6GgbPMLFCeZmi0uBNaWvHazHgmn-B8K".to_owned(),
                actor_id: "did:web:alice.example".to_owned(),
            },
        ],
        schema_refs: Vec::new(),
        rsvps: Vec::new(),
        schedule_revision_heads: Vec::new(),
        fields: Map::from_iter([
            ("labels".to_owned(), json!(["demo", "db"])),
            ("due_at".to_owned(), json!("2026-05-22")),
        ]),
        created_by: Some("did:web:acme.example:users:alice".to_owned()),
        created_at: Some("2026-05-22T10:00:00.000Z".to_owned()),
        updated_by: None,
        updated_at: None,
        state: arkret_sdk::ProjectionObjectState::Active,
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
    assert_eq!(card.description_body, "Projection description content");
    assert_eq!(card.synthesis, "Projection synthesis content");
    assert_eq!(card.labels, vec!["demo".to_owned(), "db".to_owned()]);
    assert_eq!(card.assignee, "did:web:alice.example");
    assert_eq!(
        card.assigned_to_relations,
        vec![CardAssignedToRelation {
            relation_id: "ak:relation:ASc_XP_IqOBAY6GgbPMLFCeZmi0uBNaWvHazHgmn-B8K".to_owned(),
            actor_id: "did:web:alice.example".to_owned(),
        }]
    );
    assert_eq!(card.due, "2026-05-22");
}

#[test]
fn lifecycle_projection_infers_board_from_list_parent() {
    let board_id = "ak:space:Aepgr15HbtERKfqPAh9SrfWBdihSvX_c94JvujvBS2f-";
    let list_id = "ak:space:AQM8rE4gp8l4axkSbbb9_dkqwWE8ZPYHwFsC24o2mrIL";
    let containers = vec![
        crate::state::projection_views::SpaceContainerProjectionView {
            space_id: list_id.to_owned(),
            realm_id: "ak:realm:AcbFC8Nil95DfV11kMMMvRtzRdEC3g-tFtBE8_VQQ74j".to_owned(),
            kind: "list".to_owned(),
            title: "Todo".to_owned(),
            state: arkret_sdk::ProjectionSpaceState::Active,
            rank: Some("U".to_owned()),
            parent_space_id: Some(board_id.to_owned()),
        },
    ];

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
    let board_id = "ak:space:Aepgr15HbtERKfqPAh9SrfWBdihSvX_c94JvujvBS2f-";
    let list_id = "ak:space:AQM8rE4gp8l4axkSbbb9_dkqwWE8ZPYHwFsC24o2mrIL";
    let strand_id = "ak:strand:AV624IkuHj3HmxAYE6uyYmBa4Est3gGGdnOsjn71z5L2";
    let raw_operations = vec![RawOperationRecord {
        operation_id: "sha256:local-create".to_owned(),
        realm_id: Some("ak:realm:AcbFC8Nil95DfV11kMMMvRtzRdEC3g-tFtBE8_VQQ74j".to_owned()),
        received_at: chrono::Utc::now(),
        payload: json!({
            "kind": "ak.strand.create",
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
    assert_eq!(overlaid[0].cards[0].description, "");
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
    let board_id = "ak:space:Aepgr15HbtERKfqPAh9SrfWBdihSvX_c94JvujvBS2f-";
    let strand_id = "ak:strand:AV624IkuHj3HmxAYE6uyYmBa4Est3gGGdnOsjn71z5L2";
    let mut card = test_card(strand_id, "U");
    card.description = "old summary".to_owned();
    card.synthesis = String::new();
    let columns = vec![KanbanColumn {
        id: "ak:space:AQM8rE4gp8l4axkSbbb9_dkqwWE8ZPYHwFsC24o2mrIL".to_owned(),
        title: "Todo".to_owned(),
        rank: "U".to_owned(),
        cards: vec![card],
        state: SpaceContainerLifecycleState::Active,
    }];
    let events = vec![json!({
        "event_id": "ak:event:AZUYAeUiTiKHqTOGKrrTfa2xZPZj09T6IRYuDuCNc9ZQ",
        "operation_id": "ak:operation:0196419b-0000-7000-8000-00000000f001",
        "event_kind": "ak.strand.update",
        "actor_id": "ak:did_core:web:alice.example",
        "created_at": "2026-05-22T10:00:00.000Z",
        "realm_id": "ak:realm:AcbFC8Nil95DfV11kMMMvRtzRdEC3g-tFtBE8_VQQ74j",
        "payload": {
            "target_ref": strand_id,
            "patch": {
                "metadata.summary": { "$op": "set", "value": "new summary" },
                "tracks.synthesis.content": {
                    "$op": "set",
                    "value": {
                        "kind": "ak.content.text",
                        "format": "markdown",
                        "body": "new synthesis note"
                    }
                },
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
    let events = crate::state::projection::kanban_ops::sdk_events_from_values(&events);
    let remote_operations = strand_update_operations_from_events(&events);

    let projected = overlay_card_projection_with_operations(
        columns,
        &LocalStateStore::default(),
        board_id,
        &remote_operations,
    );

    let card = &projected[0].cards[0];
    assert_eq!(card.description, "new summary");
    assert_eq!(card.synthesis, "new synthesis note");
    assert_eq!(card.labels, vec!["remote"]);
    assert_eq!(card.due, "2026-05-30");
    assert_eq!(card.state, CardState::Synced);
}

#[test]
fn remote_encrypted_strand_update_overlay_marks_private_fields_locked() {
    let board_id = "ak:space:Aepgr15HbtERKfqPAh9SrfWBdihSvX_c94JvujvBS2f-";
    let strand_id = "ak:strand:AV624IkuHj3HmxAYE6uyYmBa4Est3gGGdnOsjn71z5L2";
    let mut card = test_card(strand_id, "U");
    card.synthesis = String::new();
    let columns = vec![KanbanColumn {
        id: "ak:space:AQM8rE4gp8l4axkSbbb9_dkqwWE8ZPYHwFsC24o2mrIL".to_owned(),
        title: "Todo".to_owned(),
        rank: "U".to_owned(),
        cards: vec![card],
        state: SpaceContainerLifecycleState::Active,
    }];
    let envelope = json!({
        "scheme": "mls_rfc9420",
        "ciphertext": "AAAA",
        "content_type": KANBAN_STRAND_PATCH_VALUE_CONTENT_TYPE,
        "group_id": "g",
        "epoch": 0,
    });
    let events = vec![json!({
        "event_id": "ak:event:AYiSAxDIS8PlP8d9iucotDVTdZ9-CahOJVw2Km3R38HU",
        "operation_id": "ak:operation:0196419b-0000-7000-8000-00000000f002",
        "event_kind": "ak.strand.update",
        "actor_id": "ak:did_core:web:alice.example",
        "created_at": "2026-05-22T10:00:00.000Z",
        "realm_id": "ak:realm:AcbFC8Nil95DfV11kMMMvRtzRdEC3g-tFtBE8_VQQ74j",
        "payload": {
            "target_ref": strand_id,
            "patch": {
                "tracks.synthesis.encrypted_content": { "$op": "set", "value": envelope }
            }
        }
    })];
    let events = crate::state::projection::kanban_ops::sdk_events_from_values(&events);
    let remote_operations = strand_update_operations_from_events(&events);
    let store = LocalStateStore::default();
    let ctx = MlsDecryptCtx {
        state_store: &store,
        realm_id: TEST_REALM_ID,
        actor_id: "did:web:alice.example",
        device_id: "ak:device:0196419b-0000-7000-8000-000000000001",
        circle_id: None,
    };

    let projected = overlay_card_projection_with_operations_and_decrypt(
        columns,
        &store,
        board_id,
        &remote_operations,
        Some(&ctx),
    );

    let card = &projected[0].cards[0];
    assert_eq!(card.synthesis, "");
    assert!(card.synthesis_locked);
    assert_eq!(card.state, CardState::Synced);
}

/// Non-spec Strand paths are NOT a second way to spell content.
///
/// `strand.schema.json` forbids top-level `body` / `title` / `summary` /
/// `fields`, and neither `metadata.fields.synthesis` nor `tracks.<name>.body`
/// is a wire path at all. A patch that uses them is a schema violation the
/// server rejects, so the local overlay must ignore it outright — otherwise
/// a rejected write would still paint the board and read back as if accepted.
#[test]
fn non_spec_strand_patch_paths_are_ignored_by_the_local_overlay() {
    let board_id = "ak:space:Aepgr15HbtERKfqPAh9SrfWBdihSvX_c94JvujvBS2f-";
    let strand_id = "ak:strand:AV624IkuHj3HmxAYE6uyYmBa4Est3gGGdnOsjn71z5L2";
    let mut card = test_card(strand_id, "U");
    card.title = "kept title".to_owned();
    card.description = "kept summary".to_owned();
    card.synthesis = "kept synthesis".to_owned();
    card.labels = vec!["kept".to_owned()];
    let columns = vec![KanbanColumn {
        id: "ak:space:AQM8rE4gp8l4axkSbbb9_dkqwWE8ZPYHwFsC24o2mrIL".to_owned(),
        title: "Todo".to_owned(),
        rank: "U".to_owned(),
        cards: vec![card],
        state: SpaceContainerLifecycleState::Active,
    }];
    let events = vec![json!({
        "event_id": "ak:event:AZUYAeUiTiKHqTOGKrrTfa2xZPZj09T6IRYuDuCNc9ZQ",
        "operation_id": "ak:operation:0196419b-0000-7000-8000-00000000f004",
        "event_kind": "ak.strand.update",
        "actor_id": "ak:did_core:web:alice.example",
        "created_at": "2026-05-22T10:00:00.000Z",
        "realm_id": "ak:realm:AcbFC8Nil95DfV11kMMMvRtzRdEC3g-tFtBE8_VQQ74j",
        "payload": {
            "target_ref": strand_id,
            "patch": {
                "title": { "$op": "set", "value": "forbidden title" },
                "summary": { "$op": "set", "value": "forbidden summary" },
                "body": { "$op": "set", "value": "forbidden body" },
                "synthesis": { "$op": "set", "value": "forbidden synthesis" },
                "fields.body": { "$op": "set", "value": "forbidden fields body" },
                "fields.synthesis": { "$op": "set", "value": "forbidden fields synthesis" },
                "tracks.synthesis.body": { "$op": "set", "value": "forbidden track body" },
                "tracks.discussion.body": { "$op": "set", "value": "forbidden discussion body" },
                "fields": { "$op": "set", "value": { "labels": ["forbidden"] } }
            }
        }
    })];
    let events = crate::state::projection::kanban_ops::sdk_events_from_values(&events);
    let remote_operations = strand_update_operations_from_events(&events);

    let projected = overlay_card_projection_with_operations(
        columns,
        &LocalStateStore::default(),
        board_id,
        &remote_operations,
    );

    let card = &projected[0].cards[0];
    assert_eq!(card.title, "kept title");
    assert_eq!(card.description, "kept summary");
    assert_eq!(card.synthesis, "kept synthesis");
    assert!(!card.synthesis_locked);
    assert_eq!(card.labels, vec!["kept".to_owned()]);
}

/// A projection row that only carries the retired locations exposes NO
/// content: reading them back would resurrect the non-spec shape locally.
#[test]
fn non_spec_projection_paths_expose_no_strand_content() {
    let strand = crate::state::projection_views::StrandProjectionView {
        strand_id: "ak:strand:AV624IkuHj3HmxAYE6uyYmBa4Est3gGGdnOsjn71z5L2".to_owned(),
        realm_id: TEST_REALM_ID.to_owned(),
        title: "Card".to_owned(),
        summary: None,
        content: None,
        encrypted_content: None,
        tracks: Default::default(),
        board_space_id: None,
        list_space_id: None,
        rank: None,
        assigned_actor_ids: Vec::new(),
        assigned_to_relations: Vec::new(),
        schema_refs: Vec::new(),
        rsvps: Vec::new(),
        schedule_revision_heads: Vec::new(),
        fields: Map::from_iter([
            ("body".to_owned(), json!("non-spec body")),
            ("synthesis".to_owned(), json!("non-spec synthesis")),
        ]),
        created_by: None,
        created_at: None,
        updated_by: None,
        updated_at: None,
        state: arkret_sdk::ProjectionObjectState::Active,
    };

    assert!(strand_projection_synthesis_content(&strand).is_none());
    let card = card_from_strand_projection(&strand, None);
    assert_eq!(card.synthesis, "");
    assert!(!card.synthesis_locked);
}

/// The demo-seed opt-in is spelled `INKSON_ALLOW_KANBAN_SEED_FALLBACK=1` /
/// `=true` and nothing else — an empty or unset variable MUST NOT seed a board
/// that the server never returned.
#[test]
fn kanban_seed_fallback_opt_in_accepts_only_explicit_truthy_values() {
    assert!(truthy_env_value(Some("1")));
    assert!(truthy_env_value(Some("true")));
    assert!(!truthy_env_value(Some("0")));
    assert!(!truthy_env_value(None));
}
