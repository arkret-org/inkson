use super::*;

#[cfg(not(target_arch = "wasm32"))]
#[tokio::test]
async fn sidecar_private_editor_rejects_realm_scoped_image_uploads() {
    let error = toast_editor_upload_via_api(
        "http://127.0.0.1:1",
        "unused".to_owned(),
        TEST_REALM_ID,
        false,
        &json!({
            "content_base64": "cHJpdmF0ZQ==",
            "media_type": "image/png"
        }),
    )
    .await
    .unwrap_err();

    assert_eq!(
        error,
        "image upload is unavailable for this encrypted scope"
    );
}

#[test]
fn sidecar_private_track_card_uses_only_private_strand_updates() {
    let source_id = "ak:strand:0196419b-0000-7000-8000-000000000011";
    let private_id = "ak:strand:0196419b-0000-7000-8000-000000000012";
    let mut source = test_card(source_id, "U");
    source.primary_strand_id = source_id.to_owned();
    source.body = "shared body".to_owned();
    source.synthesis = "shared synthesis".to_owned();
    let operation = |id: &str, strand_id: &str, body: &str| RawOperationRecord {
        operation_id: id.to_owned(),
        realm_id: Some(TEST_REALM_ID.to_owned()),
        received_at: chrono::Utc::now(),
        payload: json!({
            "kind": "ak.strand.update",
            "operation_id": id,
            "write_state": "accepted",
            "body": {
                "strand_id": strand_id,
                "patch": { "body": { "$op": "set", "value": body } }
            }
        }),
    };
    let operations = vec![
        operation("source-op", source_id, "new shared body"),
        operation("private-op", private_id, "private overlay"),
    ];

    let private = sidecar_private_track_card(&source, private_id, &operations, None);

    assert_eq!(private.id, private_id);
    assert_eq!(private.primary_strand_id, private_id);
    assert_eq!(private.body, "private overlay");
    assert!(private.synthesis.is_empty());
    assert_eq!(private.security_encrypted, Some(true));
}

#[test]
fn local_card_update_overlay_replays_queued_summary_and_body_on_top_of_projection() {
    // Simulate: server projection returns the pre-edit card; the user
    // had queued a ak.strand.update locally that bumped summary + body.
    // After page refresh, the overlay must re-apply that patch so the
    // user doesn't see their edits silently disappear.
    let mut card = test_card("ak:strand:edit-me", "U");
    card.title = "old title".to_owned();
    card.description = "old summary".to_owned();
    card.body = "old body".to_owned();
    card.synthesis = "old synthesis".to_owned();
    let columns = vec![KanbanColumn {
        id: "ak:space:list-a".to_owned(),
        title: "A".to_owned(),
        rank: "U".to_owned(),
        cards: vec![card],
        state: SpaceContainerLifecycleState::Active,
    }];
    let queued = RawOperationRecord {
        operation_id: "op-1".to_owned(),
        realm_id: Some("ak:realm:r1".to_owned()),
        received_at: chrono::Utc::now(),
        payload: json!({
            "kind": "ak.strand.update",
            "operation_id": "op-1",
            "write_state": "queued",
            "body": {
                "strand_id": "ak:strand:edit-me",
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
    let mut card = test_card("ak:strand:edit-me", "U");
    card.due = "2026-06-11".to_owned();
    let columns = vec![KanbanColumn {
        id: "ak:space:list-a".to_owned(),
        title: "A".to_owned(),
        rank: "U".to_owned(),
        cards: vec![card],
        state: SpaceContainerLifecycleState::Active,
    }];
    let queued = RawOperationRecord {
        operation_id: "op-clear-due".to_owned(),
        realm_id: Some("ak:realm:r1".to_owned()),
        received_at: chrono::Utc::now(),
        payload: json!({
            "kind": "ak.strand.update",
            "operation_id": "op-clear-due",
            "write_state": "queued",
            "body": {
                "strand_id": "ak:strand:edit-me",
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
    let mut card = test_card("ak:strand:edit-me", "U");
    card.synthesis = "second synthesis".to_owned();
    card.created_by = "did:web:acme.example:users:alice".to_owned();
    card.created_at = "2026-05-22T09:00:00.000Z".to_owned();
    card.updated_at = "2026-05-22T11:00:00.000Z".to_owned();
    let received_at = |value: &str| {
        chrono::DateTime::parse_from_rfc3339(value)
            .unwrap()
            .with_timezone(&chrono::Utc)
    };
    let raw_operations = vec![
        RawOperationRecord {
            operation_id: "op-1".to_owned(),
            realm_id: Some("ak:realm:r1".to_owned()),
            received_at: received_at("2026-05-22T10:00:00.000Z"),
            payload: json!({
                "kind": "ak.strand.update",
                "operation_id": "op-1",
                "actor_id": "did:web:acme.example:users:alice",
                "created_at": "2026-05-22T10:00:00.000Z",
                "write_state": "queued",
                "body": {
                    "strand_id": "ak:strand:edit-me",
                    "patch": {
                        "synthesis": { "$op": "set", "value": "first synthesis" }
                    }
                }
            }),
        },
        RawOperationRecord {
            operation_id: "op-2".to_owned(),
            realm_id: Some("ak:realm:r1".to_owned()),
            received_at: received_at("2026-05-22T11:00:00.000Z"),
            payload: json!({
                "kind": "ak.strand.update",
                "operation_id": "op-2",
                "actor_id": "did:web:acme.example:users:bob",
                "created_at": "2026-05-22T11:00:00.000Z",
                "write_state": "queued",
                "body": {
                    "strand_id": "ak:strand:edit-me",
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
    assert_eq!(entries[0].author_label, "did:web:acme.example:users:bob");
    assert_eq!(entries[0].timestamp_label, "2026-05-22 11:00");
    assert!(entries[0].edited);
    assert_eq!(entries[0].revisions.len(), 2);
    assert_eq!(entries[0].revisions[0].body, "first synthesis");
    assert_eq!(
        entries[0].revisions[0].author_label,
        "did:web:acme.example:users:alice"
    );
    assert_eq!(entries[0].revisions[1].body, "second synthesis");
}

#[test]
fn card_synthesis_track_entries_replay_full_set_events_without_reattributing_history() {
    let mut card = test_card("ak:strand:edit-me", "U");
    card.synthesis = join_synthesis_entry_bodies(vec![
        "alice synthesis".to_owned(),
        "bob synthesis".to_owned(),
    ]);
    card.created_by = "did:web:acme.example:users:alice".to_owned();
    card.created_at = "2026-05-22T09:00:00.000Z".to_owned();
    card.updated_by = "did:web:acme.example:users:bob".to_owned();
    card.updated_at = "2026-05-22T11:00:00.000Z".to_owned();
    let received_at = |value: &str| {
        chrono::DateTime::parse_from_rfc3339(value)
            .unwrap()
            .with_timezone(&chrono::Utc)
    };
    let raw_operations = vec![
        RawOperationRecord {
            operation_id: "op-1".to_owned(),
            realm_id: Some("ak:realm:r1".to_owned()),
            received_at: received_at("2026-05-22T10:00:00.000Z"),
            payload: json!({
                "kind": "ak.strand.update",
                "operation_id": "op-1",
                "actor_id": "did:web:acme.example:users:alice",
                "created_at": "2026-05-22T10:00:00.000Z",
                "write_state": "synced",
                "body": {
                    "strand_id": "ak:strand:edit-me",
                    "patch": {
                        "synthesis": { "$op": "set", "value": "alice synthesis" }
                    }
                }
            }),
        },
        RawOperationRecord {
            operation_id: "op-2".to_owned(),
            realm_id: Some("ak:realm:r1".to_owned()),
            received_at: received_at("2026-05-22T11:00:00.000Z"),
            payload: json!({
                "kind": "ak.strand.update",
                "operation_id": "op-2",
                "actor_id": "did:web:acme.example:users:bob",
                "created_at": "2026-05-22T11:00:00.000Z",
                "write_state": "synced",
                "body": {
                    "strand_id": "ak:strand:edit-me",
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
    assert_eq!(entries[0].author_label, "did:web:acme.example:users:alice");
    assert_eq!(entries[1].body, "bob synthesis");
    assert_eq!(entries[1].author_label, "did:web:acme.example:users:bob");
}

#[test]
fn local_event_sourced_ops_recover_authors_without_per_tab_backfill() {
    // Option B, event-sourced: the synthesis track is projected straight from
    // the LOCAL `raw_operations` log. The per-realm events engine folds the
    // full realm history into that log via `kanban_operations_from_events`
    // (the same ingest funnel `realm_events_engine` uses), each
    // `ak.strand.update` carrying its authoritative per-event `actor_id`. So
    // multi-author attribution is recovered from local state with NO per-tab
    // realm backfill.
    let mut card = test_card("ak:strand:edit-me", "U");
    card.synthesis = join_synthesis_entry_bodies(vec![
        "alice synthesis".to_owned(),
        "bob synthesis".to_owned(),
    ]);
    card.created_by = "did:web:acme.example:users:alice".to_owned();
    card.created_at = "2026-05-22T09:00:00.000Z".to_owned();
    card.updated_by = "did:web:acme.example:users:bob".to_owned();
    card.updated_at = "2026-05-22T11:00:00.000Z".to_owned();

    // Canonical realm events as `account.subscribe` / `events/subscribe`
    // deliver them, folded through the SAME funnel the engine ingests with.
    let history_events = vec![
        json!({
            "event_kind": "ak.strand.update",
            "event_id": "op-1",
            "actor_id": "did:web:acme.example:users:alice",
            "created_at": "2026-05-22T10:00:00.000Z",
            "realm_id": "ak:realm:r1",
            "payload": {
                "strand_id": "ak:strand:edit-me",
                "patch": { "synthesis": { "$op": "set", "value": "alice synthesis" } }
            }
        }),
        json!({
            "event_kind": "ak.strand.update",
            "event_id": "op-2",
            "actor_id": "did:web:acme.example:users:bob",
            "created_at": "2026-05-22T11:00:00.000Z",
            "realm_id": "ak:realm:r1",
            "payload": {
                "strand_id": "ak:strand:edit-me",
                "patch": {
                    "synthesis": { "$op": "set", "value": "alice synthesis\n\n---\n\nbob synthesis" }
                }
            }
        }),
    ];
    let local_ops = kanban_operations_from_events(&history_events);
    assert_eq!(
        local_ops.len(),
        2,
        "both strand.update events folded locally"
    );

    let entries = card_synthesis_track_entries(&card, &local_ops, &LocalStateStore::default());

    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].body, "alice synthesis");
    assert_eq!(entries[0].author_label, "did:web:acme.example:users:alice");
    assert_eq!(entries[1].body, "bob synthesis");
    assert_eq!(entries[1].author_label, "did:web:acme.example:users:bob");

    // Sanity: with no local ops at all, the multi-author projection fallback
    // cannot attribute either entry — exactly the "Unknown author" symptom the
    // event-sourced local log exists to fix.
    let fallback = card_synthesis_track_entries(&card, &[], &LocalStateStore::default());
    assert_eq!(fallback.len(), 2);
    assert!(
        fallback
            .iter()
            .all(|entry| entry.author_label == "Unknown author"),
        "without local ops a multi-author card falls back to Unknown author"
    );
}

#[test]
fn engine_ingest_dedupes_resent_strand_update_by_operation_id() {
    // The engine re-folds overlapping history on every resubscribe. The store's
    // `upsert_raw_operation` dedupes by `operation_id`, and `synthesis_entries`
    // group/replay by entry id, so a re-delivered update must not double the
    // track. This is the event-sourced replacement for the old
    // history-merge dedup guarantee.
    let mut card = test_card("ak:strand:edit-me", "U");
    card.synthesis = "alice synthesis".to_owned();
    card.created_by = "did:web:acme.example:users:alice".to_owned();
    card.created_at = "2026-05-22T09:00:00.000Z".to_owned();
    card.updated_by = "did:web:acme.example:users:alice".to_owned();
    card.updated_at = "2026-05-22T10:00:00.000Z".to_owned();

    let event = json!({
        "event_kind": "ak.strand.update",
        "event_id": "op-1",
        "actor_id": "did:web:acme.example:users:alice",
        "created_at": "2026-05-22T10:00:00.000Z",
        "realm_id": "ak:realm:r1",
        "payload": {
            "strand_id": "ak:strand:edit-me",
            "patch": { "synthesis": { "$op": "set", "value": "alice synthesis" } }
        }
    });

    let mut store = LocalStateStore::default();
    // Fold the same event twice, as a resubscribe would.
    crate::sync_engine::ingest_kanban_projection_events(
        &mut store,
        "ak:realm:r1",
        &[event.clone()],
    );
    crate::sync_engine::ingest_kanban_projection_events(&mut store, "ak:realm:r1", &[event]);

    let raw_ops = store.load().raw_operations;
    assert_eq!(raw_ops.len(), 1, "resent update deduped by operation_id");

    let entries = card_synthesis_track_entries(&card, &raw_ops, &store);
    assert_eq!(entries.len(), 1, "no duplicate synthesis entry");
    assert_eq!(entries[0].body, "alice synthesis");
    assert_eq!(entries[0].author_label, "did:web:acme.example:users:alice");
}

#[test]
fn projection_synthesis_revision_uses_card_author_only_when_single_author() {
    // Single-author card (created_by == updated_by): the projection fallback
    // may confidently attribute the entry to that author.
    let mut card = test_card("ak:strand:edit-me", "U");
    card.synthesis = "bob synthesis".to_owned();
    card.created_by = "did:web:acme.example:users:bob".to_owned();
    card.created_at = "2026-05-22T09:00:00.000Z".to_owned();
    card.updated_by = "did:web:acme.example:users:bob".to_owned();
    card.updated_at = "2026-05-22T11:00:00.000Z".to_owned();

    let entries = card_synthesis_track_entries(&card, &[], &LocalStateStore::default());

    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].body, "bob synthesis");
    assert_eq!(entries[0].actor_id, "did:web:acme.example:users:bob");
    assert_eq!(entries[0].author_label, "did:web:acme.example:users:bob");
    assert_eq!(entries[0].timestamp_label, "2026-05-22 11:00");
}

#[test]
fn projection_synthesis_revision_leaves_multi_author_card_unattributed() {
    // Multi-author card with no per-entry provenance (no raw ops, no fetched
    // history): the projection fallback must NOT guess `updated_by` for every
    // entry, which was the cross-member misattribution bug. It leaves the entry
    // unattributed ("Unknown author") instead, which option B then fills in by
    // fetching the strand event history on card open.
    let mut card = test_card("ak:strand:edit-me", "U");
    card.synthesis = "bob synthesis".to_owned();
    card.created_by = "did:web:acme.example:users:alice".to_owned();
    card.created_at = "2026-05-22T09:00:00.000Z".to_owned();
    card.updated_by = "did:web:acme.example:users:bob".to_owned();
    card.updated_at = "2026-05-22T11:00:00.000Z".to_owned();

    let entries = card_synthesis_track_entries(&card, &[], &LocalStateStore::default());

    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].body, "bob synthesis");
    assert_eq!(entries[0].actor_id, "");
    assert_eq!(entries[0].author_label, "Unknown author");
}

#[test]
fn card_synthesis_author_prefers_cached_member_primary_handle() {
    let actor = "did:web:auth.local.host:users:01kth8q1w1f9c9pt3a0zfvf6gb";
    let subject = "did:web:auth.local.host:principals:alice";
    let digest = "sha256:abababababababababababababababababababababababababababababababab";
    let mut card = test_card("ak:strand:edit-me", "U");
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
    let mut card = test_card("ak:strand:edit-me", "U");
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
            realm_id: Some("ak:realm:r1".to_owned()),
            received_at: chrono::Utc::now(),
            payload: json!({
                "kind": "ak.strand.update",
                "body": {
                    "strand_id": "ak:strand:target",
                    "actor_id": "did:web:alice.example",
                },
            }),
        },
        // Same strand, different actor — both should appear.
        RawOperationRecord {
            operation_id: "op-b".to_owned(),
            realm_id: Some("ak:realm:r1".to_owned()),
            received_at: chrono::Utc::now(),
            payload: json!({
                "kind": "ak.message.create",
                "body": {
                    "target_ref": "ak:strand:target",
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
            realm_id: Some("ak:realm:r1".to_owned()),
            received_at: chrono::Utc::now(),
            payload: json!({
                "kind": "ak.strand.update",
                "body": {
                    "strand_id": "ak:strand:other",
                    "actor_id": "did:web:carol.example",
                },
            }),
        },
    ];
    let dids = strand_participant_dids(&ops, "ak:strand:target");
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
    let mut current = test_card("ak:strand:f1", "U");
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
    let mut current = test_card("ak:strand:f1", "U");
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
    let mut current = test_card("ak:strand:f1", "U");
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
    let mut card = test_card("ak:strand:f1", "U");
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

/// `locate_strand_position_in_projection` is the post-conflict rebase
/// adapter — it must find the strand's current cell pre-state from a
/// freshly-fetched projection. When the strand is present with a
/// position, return `At { list_space_id, rank }`; absent ⇒ `Initial`.
#[test]
fn locate_strand_position_finds_present_strand_with_rank() {
    use crate::state::projection_views::{
        CollectionProjectionGroupView, CollectionProjectionView, ProjectionItemView,
        StateFrontierView,
    };
    let projection = CollectionProjectionView {
        projection: "collection".to_owned(),
        renderer: Some("board".to_owned()),
        view_id: "ak:view:01904100-0000-7000-8000-000000000001".to_owned(),
        realm_id: None,
        frontier: StateFrontierView::default(),
        groups: vec![CollectionProjectionGroupView {
            key: "ak:space:01list-review".to_owned(),
            title: "Review".to_owned(),
            rank: Some("U".to_owned()),
            source: None,
            items: vec![ProjectionItemView {
                object: serde_json::json!({
                    "id": "ak:strand:01wanted",
                    "title": "Find me",
                }),
                render: None,
                display: None,
                // Registered `collection_position` relation model.
                position: Some(serde_json::json!({
                    "model": "relation",
                    "scope_container_id": "ak:space:01board",
                    "container_id": "ak:space:01list-review",
                    "relation_kind": "contains",
                    "relation_id": "ak:relation:01rel",
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
    let expected = locate_strand_position_in_projection(&projection, "ak:strand:01wanted");
    assert_eq!(
        expected,
        StrandPositionExpectation::At {
            list_space_id: "ak:space:01list-review".to_owned(),
            rank: "h3".to_owned(),
        }
    );
}

/// When the strand isn't in the projection, the rebase must use
/// `head_eq null` (Initial) — soland's reducer rejects if the cell
/// is actually non-initial, which is the safe behaviour.
#[test]
fn locate_strand_position_missing_strand_returns_initial() {
    use crate::state::projection_views::{CollectionProjectionView, StateFrontierView};
    let projection = CollectionProjectionView {
        projection: "collection".to_owned(),
        renderer: Some("board".to_owned()),
        view_id: "ak:view:01904100-0000-7000-8000-000000000001".to_owned(),
        realm_id: None,
        frontier: StateFrontierView::default(),
        groups: Vec::new(),
        items: Vec::new(),
        next_cursor: None,
        total_estimate: None,
        stale: None,
    };
    let expected = locate_strand_position_in_projection(&projection, "ak:strand:01missing");
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
        // SDK RealmId is strictly `ak:realm:<uuid7>` now; the realm arg can
        // no longer be the demo Space id.
        let event = crate::operation::ak_ops::strand_update_patch(
            "ak:realm:0196419b-0000-7000-8000-00000000b0a0",
            "did:web:acme.example:users:alice",
            strand_id,
            json!({"synthesis": {"$op": "set", "value": "demo synthesis"}}),
        )
        .expect("builds")
        .build("inkson");
        assert_eq!(event.kind.as_str(), "ak.strand.update");
        assert_eq!(sdk_event_local_target_ref(&event), Some(strand_id));
    }
}
