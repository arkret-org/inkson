use super::*;

#[test]
fn local_card_update_overlay_replays_queued_summary_and_body_on_top_of_projection() {
    // Simulate: server projection returns the pre-edit card; the user
    // had queued a ck.strand.update locally that bumped summary + body.
    // After page refresh, the overlay must re-apply that patch so the
    // user doesn't see their edits silently disappear.
    let mut card = test_card("ck:strand:edit-me", "U");
    card.title = "old title".to_owned();
    card.description = "old summary".to_owned();
    card.body = "old body".to_owned();
    card.synthesis = "old synthesis".to_owned();
    let columns = vec![KanbanColumn {
        id: "ck:space:list-a".to_owned(),
        title: "A".to_owned(),
        rank: "U".to_owned(),
        cards: vec![card],
        state: SpaceContainerLifecycleState::Active,
    }];
    let queued = RawOperationRecord {
        operation_id: "op-1".to_owned(),
        realm_id: Some("ck:realm:r1".to_owned()),
        received_at: chrono::Utc::now(),
        payload: json!({
            "kind": "ck.strand.update",
            "operation_id": "op-1",
            "write_state": "queued",
            "body": {
                "strand_id": "ck:strand:edit-me",
                "patch": {
                    "title": { "$op": "set", "value": "new title" },
                    "summary": { "$op": "set", "value": "new summary" },
                    "body": { "$op": "set", "value": "new body" },
                    "synthesis": { "$op": "set", "value": "new synthesis" },
                },
            },
        }),
    };
    let overlaid = overlay_local_card_update_records(columns, &[queued], None);
    let card = &overlaid[0].cards[0];
    assert_eq!(card.title, "new title");
    assert_eq!(card.description, "new summary");
    assert_eq!(card.body, "new body");
    assert_eq!(card.synthesis, "new synthesis");
    assert_eq!(card.state, CardState::Queued);
}

#[test]
fn overlay_local_card_update_records_clears_due_from_fields_replacement() {
    let mut card = test_card("ck:strand:edit-me", "U");
    card.due = "2026-06-11".to_owned();
    let columns = vec![KanbanColumn {
        id: "ck:space:list-a".to_owned(),
        title: "A".to_owned(),
        rank: "U".to_owned(),
        cards: vec![card],
        state: SpaceContainerLifecycleState::Active,
    }];
    let queued = RawOperationRecord {
        operation_id: "op-clear-due".to_owned(),
        realm_id: Some("ck:realm:r1".to_owned()),
        received_at: chrono::Utc::now(),
        payload: json!({
            "kind": "ck.strand.update",
            "operation_id": "op-clear-due",
            "write_state": "queued",
            "body": {
                "strand_id": "ck:strand:edit-me",
                "patch": {
                    "metadata.fields": {
                        "$op": "set",
                        "value": { "labels": [] }
                    },
                },
            },
        }),
    };
    let overlaid = overlay_local_card_update_records(columns, &[queued], None);
    assert_eq!(overlaid[0].cards[0].due, "—");
}

#[test]
fn card_synthesis_track_entries_preserve_append_history() {
    let mut card = test_card("ck:strand:edit-me", "U");
    card.synthesis = "second synthesis".to_owned();
    card.created_by = "did:web:acme.example:users:alice".to_owned();
    card.created_at = "2026-05-22T09:00:00Z".to_owned();
    card.updated_at = "2026-05-22T11:00:00Z".to_owned();
    let received_at = |value: &str| {
        chrono::DateTime::parse_from_rfc3339(value)
            .unwrap()
            .with_timezone(&chrono::Utc)
    };
    let raw_operations = vec![
        RawOperationRecord {
            operation_id: "op-1".to_owned(),
            realm_id: Some("ck:realm:r1".to_owned()),
            received_at: received_at("2026-05-22T10:00:00Z"),
            payload: json!({
                "kind": "ck.strand.update",
                "operation_id": "op-1",
                "actor_id": "did:web:acme.example:users:alice",
                "created_at": "2026-05-22T10:00:00Z",
                "write_state": "queued",
                "body": {
                    "strand_id": "ck:strand:edit-me",
                    "patch": {
                        "synthesis": { "$op": "set", "value": "first synthesis" }
                    }
                }
            }),
        },
        RawOperationRecord {
            operation_id: "op-2".to_owned(),
            realm_id: Some("ck:realm:r1".to_owned()),
            received_at: received_at("2026-05-22T11:00:00Z"),
            payload: json!({
                "kind": "ck.strand.update",
                "operation_id": "op-2",
                "actor_id": "did:web:acme.example:users:bob",
                "created_at": "2026-05-22T11:00:00Z",
                "write_state": "queued",
                "body": {
                    "strand_id": "ck:strand:edit-me",
                    "patch": {
                        "synthesis": { "$op": "set", "value": "second synthesis" }
                    }
                }
            }),
        },
    ];

    let entries = card_synthesis_track_entries(&card, &raw_operations, &LocalStateStore::default());
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].body, "second synthesis");
    assert_eq!(entries[0].author_label, "bob:acme.example");
    assert_eq!(entries[0].timestamp_label, "2026-05-22 11:00");
    assert!(entries[0].edited);
    assert_eq!(entries[0].revisions.len(), 2);
    assert_eq!(entries[0].revisions[0].body, "first synthesis");
    assert_eq!(entries[0].revisions[0].author_label, "alice:acme.example");
    assert_eq!(entries[0].revisions[1].body, "second synthesis");
}

#[test]
fn card_synthesis_track_entries_replay_full_set_events_without_reattributing_history() {
    let mut card = test_card("ck:strand:edit-me", "U");
    card.synthesis = join_synthesis_entry_bodies(vec![
        "alice synthesis".to_owned(),
        "bob synthesis".to_owned(),
    ]);
    card.created_by = "did:web:acme.example:users:alice".to_owned();
    card.created_at = "2026-05-22T09:00:00Z".to_owned();
    card.updated_by = "did:web:acme.example:users:bob".to_owned();
    card.updated_at = "2026-05-22T11:00:00Z".to_owned();
    let received_at = |value: &str| {
        chrono::DateTime::parse_from_rfc3339(value)
            .unwrap()
            .with_timezone(&chrono::Utc)
    };
    let raw_operations = vec![
        RawOperationRecord {
            operation_id: "op-1".to_owned(),
            realm_id: Some("ck:realm:r1".to_owned()),
            received_at: received_at("2026-05-22T10:00:00Z"),
            payload: json!({
                "kind": "ck.strand.update",
                "operation_id": "op-1",
                "actor_id": "did:web:acme.example:users:alice",
                "created_at": "2026-05-22T10:00:00Z",
                "write_state": "synced",
                "body": {
                    "strand_id": "ck:strand:edit-me",
                    "patch": {
                        "synthesis": { "$op": "set", "value": "alice synthesis" }
                    }
                }
            }),
        },
        RawOperationRecord {
            operation_id: "op-2".to_owned(),
            realm_id: Some("ck:realm:r1".to_owned()),
            received_at: received_at("2026-05-22T11:00:00Z"),
            payload: json!({
                "kind": "ck.strand.update",
                "operation_id": "op-2",
                "actor_id": "did:web:acme.example:users:bob",
                "created_at": "2026-05-22T11:00:00Z",
                "write_state": "synced",
                "body": {
                    "strand_id": "ck:strand:edit-me",
                    "patch": {
                        "synthesis": {
                            "$op": "set",
                            "value": "alice synthesis\n\n---\n\nbob synthesis"
                        }
                    }
                }
            }),
        },
    ];

    let entries = card_synthesis_track_entries(&card, &raw_operations, &LocalStateStore::default());

    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].body, "alice synthesis");
    assert_eq!(entries[0].author_label, "alice:acme.example");
    assert_eq!(entries[1].body, "bob synthesis");
    assert_eq!(entries[1].author_label, "bob:acme.example");
}

#[test]
fn projection_synthesis_revision_prefers_updated_by_over_creator() {
    let mut card = test_card("ck:strand:edit-me", "U");
    card.synthesis = "bob synthesis".to_owned();
    card.created_by = "did:web:acme.example:users:alice".to_owned();
    card.created_at = "2026-05-22T09:00:00Z".to_owned();
    card.updated_by = "did:web:acme.example:users:bob".to_owned();
    card.updated_at = "2026-05-22T11:00:00Z".to_owned();

    let entries = card_synthesis_track_entries(&card, &[], &LocalStateStore::default());

    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].body, "bob synthesis");
    assert_eq!(entries[0].actor_id, "did:web:acme.example:users:bob");
    assert_eq!(entries[0].author_label, "bob:acme.example");
    assert_eq!(entries[0].timestamp_label, "2026-05-22 11:00");
}

#[test]
fn card_synthesis_author_prefers_cached_member_primary_handle() {
    let actor = "did:web:auth.local.host:users:01kth8q1w1f9c9pt3a0zfvf6gb";
    let subject = "did:web:auth.local.host:principals:alice";
    let digest = "sha256:abababababababababababababababababababababababababababababababab";
    let mut card = test_card("ck:strand:edit-me", "U");
    card.synthesis = "wqefqqwf".to_owned();
    card.created_by = actor.to_owned();

    let projection = json!({
        "realm_id": TEST_REALM_ID,
        "members": [{
            "actor_id": actor,
            "membership": "join",
            "subject_id": subject,
            "member_display_state_digest": digest
        }]
    });
    let rows = realm_member_roster(Some(&projection));
    let mut store = temp_state_store("synthesis-primary-handle");
    store.save_member_handle_lookup(
        subject,
        Some(TEST_REALM_ID.to_owned()),
        Some(digest.to_owned()),
        Some("abbc:auth.local.host".to_owned()),
        1,
        None,
        None,
    );
    let context = CardAuthorDisplayContext {
        realm_id: TEST_REALM_ID,
        member_rows: &rows,
    };

    let entries =
        card_synthesis_track_entries_with_author_context(&card, &[], &store, Some(context));

    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].author_label, "abbc:auth.local.host");
    assert_ne!(
        entries[0].author_label,
        "01kth8q1w1f9c9pt3a0zfvf6gb:auth.local.host"
    );
}

#[test]
fn synthesis_new_entry_appends_without_replacing_existing_entries() {
    let mut card = test_card("ck:strand:edit-me", "U");
    card.synthesis = join_synthesis_entry_bodies(vec![
        "first active synthesis".to_owned(),
        "second active synthesis".to_owned(),
    ]);

    let entries = card_synthesis_track_entries(&card, &[], &LocalStateStore::default());
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].body, "first active synthesis");
    assert_eq!(entries[1].body, "second active synthesis");

    let updated = synthesis_body_after_entry_edit(&entries, None, "third active synthesis");
    let bodies = split_synthesis_entry_bodies(&updated);
    assert_eq!(
        bodies,
        vec![
            "first active synthesis".to_owned(),
            "second active synthesis".to_owned(),
            "third active synthesis".to_owned(),
        ]
    );
}

#[test]
fn strand_participant_dids_filters_by_target_strand_and_pulls_unique_actors() {
    let ops = vec![
        RawOperationRecord {
            operation_id: "op-a".to_owned(),
            realm_id: Some("ck:realm:r1".to_owned()),
            received_at: chrono::Utc::now(),
            payload: json!({
                "kind": "ck.strand.update",
                "body": {
                    "strand_id": "ck:strand:target",
                    "actor_id": "did:web:alice.example",
                },
            }),
        },
        // Same strand, different actor — both should appear.
        RawOperationRecord {
            operation_id: "op-b".to_owned(),
            realm_id: Some("ck:realm:r1".to_owned()),
            received_at: chrono::Utc::now(),
            payload: json!({
                "kind": "ck.message.create",
                "body": {
                    "target_ref": "ck:strand:target",
                    // Canonical actor key only; forbidden `sender`
                    // fields are hard-rejected.
                    "actor_id": "did:web:bob.example",
                },
            }),
        },
        // Different strand — must be excluded so we don't bleed
        // unrelated realm actors into the per-card participant list.
        RawOperationRecord {
            operation_id: "op-c".to_owned(),
            realm_id: Some("ck:realm:r1".to_owned()),
            received_at: chrono::Utc::now(),
            payload: json!({
                "kind": "ck.strand.update",
                "body": {
                    "strand_id": "ck:strand:other",
                    "actor_id": "did:web:carol.example",
                },
            }),
        },
    ];
    let dids = strand_participant_dids(&ops, "ck:strand:target");
    assert_eq!(
        dids,
        vec![
            "did:web:alice.example".to_owned(),
            "did:web:bob.example".to_owned(),
        ]
    );
    assert!(strand_participant_dids(&ops, "").is_empty());
}

#[test]
fn card_detail_update_patch_emits_body_set_and_unset_ops() {
    let mut current = test_card("ck:strand:f1", "U");
    current.title = "Keep".to_owned();
    current.body = "old long-form body".to_owned();
    let mut draft = card_detail_draft_from_card(&current);
    draft.body = "new long-form body".to_owned();
    let patch = card_detail_update_patch(&current, &draft).unwrap();
    assert_eq!(patch["body"]["$op"], "set");
    assert_eq!(patch["body"]["value"], "new long-form body");

    let mut draft_clear = card_detail_draft_from_card(&current);
    draft_clear.body = String::new();
    let patch = card_detail_update_patch(&current, &draft_clear).unwrap();
    assert_eq!(patch["body"]["$op"], "unset");
}

#[test]
fn card_detail_update_patch_unsets_empty_optional_fields() {
    let mut current = test_card("ck:strand:f1", "U");
    current.title = "Keep".to_owned();
    current.description = "old summary".to_owned();
    current.labels = vec!["old".to_owned()];
    current.assignee = "did:web:bob.example".to_owned();
    current.due = "2026-05-19".to_owned();
    let draft = CardDetailDraft {
        title: "Keep".to_owned(),
        description: String::new(),
        body: String::new(),
        synthesis: String::new(),
        labels: Vec::new(),
        assignee: String::new(),
        due: String::new(),
        calendar: CalendarCardFields::default(),
    };

    let patch = card_detail_update_patch(&current, &draft).unwrap();
    assert_eq!(patch["metadata.summary"]["$op"], "unset");
    assert_eq!(
        patch["metadata.fields.labels"]["value"]
            .as_array()
            .unwrap()
            .len(),
        0
    );
    assert_eq!(patch["metadata.fields.due_at"]["$op"], "unset");
    assert!(patch.get("metadata.fields.assignee").is_none());
}

#[test]
fn description_edit_scope_preserves_metadata_fields() {
    let mut current = test_card("ck:strand:f1", "U");
    current.title = "Keep".to_owned();
    current.description = "old summary".to_owned();
    current.body = "old long-form body".to_owned();
    current.synthesis = "old synthesis".to_owned();
    current.labels = vec!["feature".to_owned()];
    current.due = "2026-05-19".to_owned();

    let (draft, synthesis_revision) = card_detail_draft_for_edit_scope(
        &current,
        CardEditScope::Description,
        &[],
        None,
        "",
        "",
        "new long-form body",
        "",
        "",
        "",
        "",
    );

    assert!(synthesis_revision.is_none());
    assert_eq!(draft.title, current.title);
    assert_eq!(draft.description, current.description);
    assert_eq!(draft.synthesis, current.synthesis);
    assert_eq!(draft.labels, current.labels);
    assert_eq!(draft.due, "2026-05-19");
    let patch = card_detail_update_patch(&current, &draft).unwrap();
    let object = patch.as_object().unwrap();
    assert_eq!(object.len(), 1);
    assert_eq!(patch["body"]["$op"], "set");
    assert_eq!(patch["body"]["value"], "new long-form body");
    assert!(patch.get("metadata.fields.labels").is_none());
    assert!(patch.get("metadata.fields.due_at").is_none());
    assert_eq!(
        card_detail_activity_summary(&current, &draft),
        "Card details updated"
    );
}

#[test]
fn apply_card_detail_draft_marks_card_queued() {
    let mut card = test_card("ck:strand:f1", "U");
    let draft = CardDetailDraft {
        title: "New title".to_owned(),
        description: "New summary".to_owned(),
        body: "Body content".to_owned(),
        synthesis: "Synthesis content".to_owned(),
        labels: vec!["ops".to_owned()],
        assignee: String::new(),
        due: "2026-05-20".to_owned(),
        calendar: CalendarCardFields::default(),
    };

    apply_card_detail_draft(&mut card, &draft);
    assert_eq!(card.title, "New title");
    assert_eq!(card.description, "New summary");
    assert_eq!(card.body, "Body content");
    assert_eq!(card.synthesis, "Synthesis content");
    assert_eq!(card.labels, vec!["ops".to_owned()]);
    assert_eq!(card.assignee, "—");
    assert_eq!(card.due, "2026-05-20");
    assert_eq!(card.state, CardState::Queued);
}

/// `relocate_card` is the optimistic local mutation that runs as
/// soon as the user drops a card — before the server sees the
/// Move. It MUST:
///   1. remove the card from the source column,
///   2. assign the new rank,
///   3. insert into the target column such that ascending-rank ordering is preserved (otherwise the
///      next drag uses wrong neighbours for `rank_between`).
#[test]
fn relocate_card_preserves_rank_ordering_after_move() {
    let mut cols = vec![
        KanbanColumn {
            id: "ck:space:list-a".to_owned(),
            title: "A".to_owned(),
            rank: "U".to_owned(),
            cards: vec![
                test_card("ck:strand:a1", "U"),
                test_card("ck:strand:a2", "f"),
            ],
            state: SpaceContainerLifecycleState::Active,
        },
        KanbanColumn {
            id: "ck:space:list-b".to_owned(),
            title: "B".to_owned(),
            rank: "f".to_owned(),
            cards: vec![
                test_card("ck:strand:b1", "U"),
                test_card("ck:strand:b3", "z"),
            ],
            state: SpaceContainerLifecycleState::Active,
        },
    ];
    // Move a1 from A → B, dropped at rank "m" (between b1=U and b3=z).
    let moved = relocate_card(
        &mut cols,
        "ck:strand:a1",
        "ck:space:list-a",
        "ck:space:list-b",
        "m",
    )
    .unwrap();
    assert_eq!(moved.id, "ck:strand:a1");
    assert_eq!(moved.rank, "m");
    // Source column no longer contains a1, still has a2.
    let a = &cols[0];
    assert_eq!(a.cards.len(), 1);
    assert_eq!(a.cards[0].id, "ck:strand:a2");
    // Target column has b1 (U) < a1 (m) < b3 (z), ordering preserved.
    let b = &cols[1];
    assert_eq!(b.cards.len(), 3);
    assert_eq!(b.cards[0].id, "ck:strand:b1");
    assert_eq!(b.cards[1].id, "ck:strand:a1");
    assert_eq!(b.cards[2].id, "ck:strand:b3");
}

/// In-list reorder: removing from a column then re-inserting into
/// the **same** column (target == source) at a new rank should
/// land at the right position.
#[test]
fn relocate_card_handles_in_list_reorder() {
    let mut cols = vec![KanbanColumn {
        id: "ck:space:list-a".to_owned(),
        title: "A".to_owned(),
        rank: "U".to_owned(),
        cards: vec![
            test_card("ck:strand:a1", "U"),
            test_card("ck:strand:a2", "f"),
            test_card("ck:strand:a3", "p"),
        ],
        state: SpaceContainerLifecycleState::Active,
    }];
    // Move a3 to the top of the same list (rank "0" — before "U").
    let moved = relocate_card(
        &mut cols,
        "ck:strand:a3",
        "ck:space:list-a",
        "ck:space:list-a",
        "0",
    )
    .unwrap();
    assert_eq!(moved.rank, "0");
    let a = &cols[0];
    assert_eq!(a.cards.len(), 3);
    assert_eq!(a.cards[0].id, "ck:strand:a3");
    assert_eq!(a.cards[1].id, "ck:strand:a1");
    assert_eq!(a.cards[2].id, "ck:strand:a2");
}

/// `locate_strand_position_in_projection` is the post-conflict rebase
/// adapter — it must find the strand's current cell pre-state from a
/// freshly-fetched projection. When the strand is present with a
/// position, return `At { list_space_id, rank }`; absent ⇒ `Initial`.
#[test]
fn locate_strand_position_finds_present_strand_with_rank() {
    use crate::api::{
        CollectionProjectionGroupView, CollectionProjectionView, ProjectionItemView,
        StateFrontierView,
    };
    let projection = CollectionProjectionView {
        projection: "collection".to_owned(),
        renderer: Some("board".to_owned()),
        view_id: "ck:view:01904100-0000-7000-8000-000000000001".to_owned(),
        realm_id: None,
        frontier: StateFrontierView::default(),
        groups: vec![CollectionProjectionGroupView {
            key: "ck:space:01list-review".to_owned(),
            title: "Review".to_owned(),
            rank: Some("U".to_owned()),
            source: None,
            items: vec![ProjectionItemView {
                object: serde_json::json!({
                    "id": "ck:strand:01wanted",
                    "title": "Find me",
                }),
                render: None,
                display: None,
                // Registered `collection_position` relation model.
                position: Some(serde_json::json!({
                    "model": "relation",
                    "scope_container_id": "ck:space:01board",
                    "container_id": "ck:space:01list-review",
                    "relation_kind": "contains",
                    "relation_id": "ck:relation:01rel",
                    "rank": "h3",
                })),
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
    let expected = locate_strand_position_in_projection(&projection, "ck:strand:01wanted");
    assert_eq!(
        expected,
        StrandPositionExpectation::At {
            list_space_id: "ck:space:01list-review".to_owned(),
            rank: "h3".to_owned(),
        }
    );
}

/// When the strand isn't in the projection, the rebase must use
/// `head_eq null` (Initial) — soland's reducer rejects if the cell
/// is actually non-initial, which is the safe behaviour.
#[test]
fn locate_strand_position_missing_strand_returns_initial() {
    use crate::api::{CollectionProjectionView, StateFrontierView};
    let projection = CollectionProjectionView {
        projection: "collection".to_owned(),
        renderer: Some("board".to_owned()),
        view_id: "ck:view:01904100-0000-7000-8000-000000000001".to_owned(),
        realm_id: None,
        frontier: StateFrontierView::default(),
        groups: Vec::new(),
        items: Vec::new(),
        next_cursor: None,
        total_estimate: None,
        stale: None,
    };
    let expected = locate_strand_position_in_projection(&projection, "ck:strand:01missing");
    assert_eq!(expected, StrandPositionExpectation::Initial);
}

#[test]
fn seed_columns_reflect_three_lifecycle_states_for_demo_drift_check() {
    // Seed must include at least one Synced, one Queued (= optimistic
    // queued write) and one Conflict so the kanban demo exercises the
    // full WriteState rendering path. If a refactor changes seeds, fix
    // this test along with the matching screenshot fixtures.
    let cols = seed_columns();
    let mut states: Vec<&'static str> = cols
        .iter()
        .flat_map(|c| c.cards.iter().map(|card| card.state.data_state()))
        .collect();
    states.sort();
    states.dedup();
    assert!(states.contains(&"synced"), "seed missing Synced demo card");
    assert!(states.contains(&"queued"), "seed missing Queued demo card");
    assert!(
        states.contains(&"conflict"),
        "seed missing Conflict demo card"
    );
}

#[test]
fn seed_strand_ids_are_valid_object_patch_targets() {
    for strand_id in [
        DEMO_STRAND_LEGAL_REVIEW_ID,
        DEMO_STRAND_ONBOARDING_COPY_ID,
        DEMO_STRAND_SECURITY_SIGNOFF_ID,
    ] {
        let event = crate::operation::ck_ops::strand_update_patch(
            DEMO_BOARD_SPACE_ID,
            "did:web:acme.example:users:alice",
            strand_id,
            json!({"synthesis": {"$op": "set", "value": "demo synthesis"}}),
        )
        .expect("builds")
        .build("yougen");
        assert_eq!(event.kind.as_str(), "ck.strand.update");
        assert_eq!(sdk_event_local_target_ref(&event), Some(strand_id));
    }
}
