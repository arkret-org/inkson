use super::*;

/// Canonical `content` patch op: `strand.schema.json` types the Strand's
/// synthesis slot as a ContentBlock, so a bare string is a schema violation.
fn content_patch_value(body: &str) -> serde_json::Value {
    json!({
        "$op": "set",
        "value": { "kind": "ak.content.text", "format": "markdown", "body": body }
    })
}

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
fn sidecar_transition_suspends_only_track_edits_without_mixing_drafts() {
    let private = suspend_track_edit(
        CardEditScope::Synthesis,
        "private draft".to_owned(),
        Some("private-entry".to_owned()),
    )
    .unwrap();

    assert_eq!(private.scope, CardEditScope::Synthesis);
    assert_eq!(private.synthesis, "private draft");
    assert_eq!(
        private.synthesis_target_id.as_deref(),
        Some("private-entry")
    );
    assert!(suspend_track_edit(CardEditScope::Summary, "summary".to_owned(), None).is_none());
    assert!(suspend_track_edit(CardEditScope::Calendar, String::new(), None).is_none());
}

#[test]
fn local_card_update_overlay_replays_queued_summary_and_content_on_top_of_projection() {
    // Simulate: server projection returns the pre-edit card; the user
    // had queued a ak.strand.update locally that bumped summary + content.
    // After page refresh, the overlay must re-apply that patch so the
    // user doesn't see their edits silently disappear.
    let mut card = test_card(
        "ak:strand:AiRwjMAZ14M9aj2p96Vy4ORV9RjgnslFIV7wS1_2Zhig",
        "U",
    );
    card.title = "old title".to_owned();
    card.description = "old summary".to_owned();
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
        realm_id: Some("ak:realm:AhqX99K03QXK2MTH4KkLKdcUAjZEYYcxENCdxK3f6nN0".to_owned()),
        received_at: chrono::Utc::now(),
        payload: json!({
            "kind": "ak.strand.update",
            "operation_id": "op-1",
            "write_state": "queued",
            "body": {
                "strand_id": "ak:strand:AiRwjMAZ14M9aj2p96Vy4ORV9RjgnslFIV7wS1_2Zhig",
                "patch": {
                    "metadata.title": { "$op": "set", "value": "new title" },
                    "metadata.summary": { "$op": "set", "value": "new summary" },
                    "content": content_patch_value("new synthesis"),
                },
            },
        }),
    };
    let overlaid = overlay_local_card_update_records(columns, &[queued], None);
    let card = &overlaid[0].cards[0];
    assert_eq!(card.title, "new title");
    assert_eq!(card.description, "new summary");
    assert_eq!(card.synthesis, "new synthesis");
    assert_eq!(card.state, CardState::Queued);
}

#[test]
fn overlay_local_card_update_records_clears_due_from_fields_replacement() {
    let mut card = test_card(
        "ak:strand:AiRwjMAZ14M9aj2p96Vy4ORV9RjgnslFIV7wS1_2Zhig",
        "U",
    );
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
        realm_id: Some("ak:realm:AhqX99K03QXK2MTH4KkLKdcUAjZEYYcxENCdxK3f6nN0".to_owned()),
        received_at: chrono::Utc::now(),
        payload: json!({
            "kind": "ak.strand.update",
            "operation_id": "op-clear-due",
            "write_state": "queued",
            "body": {
                "strand_id": "ak:strand:AiRwjMAZ14M9aj2p96Vy4ORV9RjgnslFIV7wS1_2Zhig",
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
    let mut card = test_card(
        "ak:strand:AiRwjMAZ14M9aj2p96Vy4ORV9RjgnslFIV7wS1_2Zhig",
        "U",
    );
    card.synthesis = "second synthesis".to_owned();
    card.created_by = "ak:did_core:web:acme.example:users:alice".to_owned();
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
            realm_id: Some("ak:realm:AhqX99K03QXK2MTH4KkLKdcUAjZEYYcxENCdxK3f6nN0".to_owned()),
            received_at: received_at("2026-05-22T10:00:00.000Z"),
            payload: json!({
                "kind": "ak.strand.update",
                "operation_id": "op-1",
                "actor_id": "ak:did_core:web:acme.example:users:alice",
                "created_at": "2026-05-22T10:00:00.000Z",
                "write_state": "queued",
                "body": {
                    "strand_id": "ak:strand:AiRwjMAZ14M9aj2p96Vy4ORV9RjgnslFIV7wS1_2Zhig",
                    "patch": {
                        "content": content_patch_value("first synthesis")
                    }
                }
            }),
        },
        RawOperationRecord {
            operation_id: "op-2".to_owned(),
            realm_id: Some("ak:realm:AhqX99K03QXK2MTH4KkLKdcUAjZEYYcxENCdxK3f6nN0".to_owned()),
            received_at: received_at("2026-05-22T11:00:00.000Z"),
            payload: json!({
                "kind": "ak.strand.update",
                "operation_id": "op-2",
                "actor_id": "ak:did_core:web:acme.example:users:bob",
                "created_at": "2026-05-22T11:00:00.000Z",
                "write_state": "queued",
                "body": {
                    "strand_id": "ak:strand:AiRwjMAZ14M9aj2p96Vy4ORV9RjgnslFIV7wS1_2Zhig",
                    "patch": {
                        "content": content_patch_value("second synthesis")
                    }
                }
            }),
        },
    ];

    let entries = card_synthesis_track_entries(&card, &raw_operations, &LocalStateStore::default());
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].body, "second synthesis");
    assert_eq!(entries[0].author_label, "ak:did_core:web:...sers:bob");
    assert_eq!(entries[0].timestamp_label, "2026-05-22 11:00");
    assert!(entries[0].edited);
    assert_eq!(entries[0].revisions.len(), 2);
    assert_eq!(entries[0].revisions[0].body, "first synthesis");
    assert_eq!(
        entries[0].revisions[0].author_label,
        "ak:did_core:web:...rs:alice"
    );
    assert_eq!(entries[0].revisions[1].body, "second synthesis");
}

#[test]
fn card_synthesis_track_entries_replay_full_set_events_without_reattributing_history() {
    let mut card = test_card(
        "ak:strand:AiRwjMAZ14M9aj2p96Vy4ORV9RjgnslFIV7wS1_2Zhig",
        "U",
    );
    card.synthesis = join_synthesis_entry_bodies(vec![
        "alice synthesis".to_owned(),
        "bob synthesis".to_owned(),
    ]);
    card.created_by = "ak:did_core:web:acme.example:users:alice".to_owned();
    card.created_at = "2026-05-22T09:00:00.000Z".to_owned();
    card.updated_by = "ak:did_core:web:acme.example:users:bob".to_owned();
    card.updated_at = "2026-05-22T11:00:00.000Z".to_owned();
    let received_at = |value: &str| {
        chrono::DateTime::parse_from_rfc3339(value)
            .unwrap()
            .with_timezone(&chrono::Utc)
    };
    let raw_operations = vec![
        RawOperationRecord {
            operation_id: "op-1".to_owned(),
            realm_id: Some("ak:realm:AhqX99K03QXK2MTH4KkLKdcUAjZEYYcxENCdxK3f6nN0".to_owned()),
            received_at: received_at("2026-05-22T10:00:00.000Z"),
            payload: json!({
                "kind": "ak.strand.update",
                "operation_id": "op-1",
                "actor_id": "ak:did_core:web:acme.example:users:alice",
                "created_at": "2026-05-22T10:00:00.000Z",
                "write_state": "synced",
                "body": {
                    "strand_id": "ak:strand:AiRwjMAZ14M9aj2p96Vy4ORV9RjgnslFIV7wS1_2Zhig",
                    "patch": {
                        "content": content_patch_value("alice synthesis")
                    }
                }
            }),
        },
        RawOperationRecord {
            operation_id: "op-2".to_owned(),
            realm_id: Some("ak:realm:AhqX99K03QXK2MTH4KkLKdcUAjZEYYcxENCdxK3f6nN0".to_owned()),
            received_at: received_at("2026-05-22T11:00:00.000Z"),
            payload: json!({
                "kind": "ak.strand.update",
                "operation_id": "op-2",
                "actor_id": "ak:did_core:web:acme.example:users:bob",
                "created_at": "2026-05-22T11:00:00.000Z",
                "write_state": "synced",
                "body": {
                    "strand_id": "ak:strand:AiRwjMAZ14M9aj2p96Vy4ORV9RjgnslFIV7wS1_2Zhig",
                    "patch": {
                        "content": content_patch_value("alice synthesis\n\n---\n\nbob synthesis")
                    }
                }
            }),
        },
    ];

    let entries = card_synthesis_track_entries(&card, &raw_operations, &LocalStateStore::default());

    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].body, "alice synthesis");
    assert_eq!(entries[0].author_label, "ak:did_core:web:...rs:alice");
    assert_eq!(entries[1].body, "bob synthesis");
    assert_eq!(entries[1].author_label, "ak:did_core:web:...sers:bob");
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
    let strand_id = "ak:strand:AV624IkuHj3HmxAYE6uyYmBa4Est3gGGdnOsjn71z5L2";
    let mut card = test_card(strand_id, "U");
    card.synthesis = join_synthesis_entry_bodies(vec![
        "alice synthesis".to_owned(),
        "bob synthesis".to_owned(),
    ]);
    card.created_by = "ak:did_core:web:acme.example:users:alice".to_owned();
    card.created_at = "2026-05-22T09:00:00.000Z".to_owned();
    card.updated_by = "ak:did_core:web:acme.example:users:bob".to_owned();
    card.updated_at = "2026-05-22T11:00:00.000Z".to_owned();

    // Canonical realm events as `account.subscribe` / `events/subscribe`
    // deliver them, folded through the SAME funnel the engine ingests with.
    let history_events = vec![
        json!({
            "event_kind": "ak.strand.update",
            "event_id": "ak:event:AZUYAeUiTiKHqTOGKrrTfa2xZPZj09T6IRYuDuCNc9ZQ",
            "actor_id": "ak:did_core:web:acme.example:users:alice",
            "created_at": "2026-05-22T10:00:00.000Z",
            "realm_id": TEST_REALM_ID,
            "payload": {
                "target_ref": strand_id,
                "patch": { "content": content_patch_value("alice synthesis") }
            }
        }),
        json!({
            "event_kind": "ak.strand.update",
            "event_id": "ak:event:AYiSAxDIS8PlP8d9iucotDVTdZ9-CahOJVw2Km3R38HU",
            "actor_id": "ak:did_core:web:acme.example:users:bob",
            "created_at": "2026-05-22T11:00:00.000Z",
            "realm_id": TEST_REALM_ID,
            "payload": {
                "target_ref": strand_id,
                "patch": {
                    "content": content_patch_value("alice synthesis\n\n---\n\nbob synthesis")
                }
            }
        }),
    ];
    let history_events =
        crate::state::projection::kanban_ops::sdk_events_from_values(&history_events);
    let local_ops = kanban_operations_from_events(&history_events);
    assert_eq!(
        local_ops.len(),
        2,
        "both strand.update events folded locally"
    );

    let entries = card_synthesis_track_entries(&card, &local_ops, &LocalStateStore::default());

    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].body, "alice synthesis");
    assert_eq!(entries[0].author_label, "ak:did_core:web:...rs:alice");
    assert_eq!(entries[1].body, "bob synthesis");
    assert_eq!(entries[1].author_label, "ak:did_core:web:...sers:bob");

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
    let mut card = test_card(
        "ak:strand:AiRwjMAZ14M9aj2p96Vy4ORV9RjgnslFIV7wS1_2Zhig",
        "U",
    );
    card.synthesis = "alice synthesis".to_owned();
    card.created_by = "did:web:acme.example:users:alice".to_owned();
    card.created_at = "2026-05-22T09:00:00.000Z".to_owned();
    card.updated_by = "did:web:acme.example:users:alice".to_owned();
    card.updated_at = "2026-05-22T10:00:00.000Z".to_owned();

    let event = json!({
        "event_kind": "ak.strand.update",
        "event_id": "op-1",
        "actor_id": "ak:did_core:web:acme.example:users:alice",
        "created_at": "2026-05-22T10:00:00.000Z",
        "realm_id": "ak:realm:AhqX99K03QXK2MTH4KkLKdcUAjZEYYcxENCdxK3f6nN0",
        "payload": {
            "strand_id": "ak:strand:AiRwjMAZ14M9aj2p96Vy4ORV9RjgnslFIV7wS1_2Zhig",
            "patch": { "content": content_patch_value("alice synthesis") }
        }
    });

    let mut store = LocalStateStore::default();
    let events =
        crate::state::projection::kanban_ops::sdk_events_from_values(std::slice::from_ref(&event));
    // Fold the same event twice, as a resubscribe would.
    crate::sync_engine::ingest_kanban_projection_events(
        &mut store,
        "ak:realm:AhqX99K03QXK2MTH4KkLKdcUAjZEYYcxENCdxK3f6nN0",
        &events,
    );
    crate::sync_engine::ingest_kanban_projection_events(
        &mut store,
        "ak:realm:AhqX99K03QXK2MTH4KkLKdcUAjZEYYcxENCdxK3f6nN0",
        &events,
    );

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
    let mut card = test_card(
        "ak:strand:AiRwjMAZ14M9aj2p96Vy4ORV9RjgnslFIV7wS1_2Zhig",
        "U",
    );
    card.synthesis = "bob synthesis".to_owned();
    card.created_by = "ak:did_core:web:acme.example:users:bob".to_owned();
    card.created_at = "2026-05-22T09:00:00.000Z".to_owned();
    card.updated_by = "ak:did_core:web:acme.example:users:bob".to_owned();
    card.updated_at = "2026-05-22T11:00:00.000Z".to_owned();

    let entries = card_synthesis_track_entries(&card, &[], &LocalStateStore::default());

    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].body, "bob synthesis");
    assert_eq!(
        entries[0].actor_id,
        "ak:did_core:web:acme.example:users:bob"
    );
    assert_eq!(entries[0].author_label, "ak:did_core:web:...sers:bob");
    assert_eq!(entries[0].timestamp_label, "2026-05-22 11:00");
}

#[test]
fn projection_synthesis_revision_leaves_multi_author_card_unattributed() {
    // Multi-author card with no per-entry provenance (no raw ops, no fetched
    // history): the projection fallback must NOT guess `updated_by` for every
    // entry, which was the cross-member misattribution bug. It leaves the entry
    // unattributed ("Unknown author") instead, which option B then fills in by
    // fetching the strand event history on card open.
    let mut card = test_card(
        "ak:strand:AiRwjMAZ14M9aj2p96Vy4ORV9RjgnslFIV7wS1_2Zhig",
        "U",
    );
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
    let actor = "ak:did_core:web:auth.local.host:users:01kth8q1w1f9c9pt3a0zfvf6gb";
    let subject = "ak:did_core:web:auth.local.host:principals:alice";
    let digest = "sha256:abababababababababababababababababababababababababababababababab";
    let mut card = test_card(
        "ak:strand:AiRwjMAZ14M9aj2p96Vy4ORV9RjgnslFIV7wS1_2Zhig",
        "U",
    );
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
fn late_join_synthesis_author_resolves_handle_from_roster_actor_did() {
    let actor = "ak:did_core:webvh:zQmHistoricalAuthor";
    let mut card = test_card(
        "ak:strand:AFjQnGmj11wy2rA2YjgbfhdhIJlFu9cPeZN5Ld0XzQp4",
        "U",
    );
    card.synthesis = "historical synthesis".to_owned();
    card.created_by = actor.to_owned();

    let projection = json!({
        "realm_id": TEST_REALM_ID,
        "members": [{
            "actor_id": actor,
            "membership": "join"
        }]
    });
    let rows = realm_member_roster(Some(&projection));
    let mut store = temp_state_store("late-join-synthesis-author");
    store.save_member_handle_lookup(
        actor,
        Some(TEST_REALM_ID.to_owned()),
        None,
        Some("alice:local.host".to_owned()),
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

    assert_eq!(entries[0].author_label, "alice:local.host");
}

#[test]
fn synthesis_author_uses_the_same_persisted_self_handle_as_member_surfaces() {
    let actor = "did:webvh:zQmCurrentAccount";
    let mut card = test_card(
        "ak:strand:AF3DijehNxWqPlABWhHV2X7qV7ZeRCJQ7el0rZYaSQXs",
        "U",
    );
    card.synthesis = "shared identity resolution".to_owned();
    card.created_by = actor.to_owned();

    let projection = json!({
        "realm_id": TEST_REALM_ID,
        "members": [{
            "actor_id": actor,
            "membership": "join"
        }]
    });
    let rows = realm_member_roster(Some(&projection));
    let mut store = temp_state_store("synthesis-current-account-handle");
    store.switch_active_account(actor);
    store.set_primary_handle_for_did(actor, "alice:local.host");
    let context = CardAuthorDisplayContext {
        realm_id: TEST_REALM_ID,
        member_rows: &rows,
    };

    let entries =
        card_synthesis_track_entries_with_author_context(&card, &[], &store, Some(context));

    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].author_label, "alice:local.host");
}

#[test]
fn synthesis_new_entry_appends_without_replacing_existing_entries() {
    let mut card = test_card(
        "ak:strand:AiRwjMAZ14M9aj2p96Vy4ORV9RjgnslFIV7wS1_2Zhig",
        "U",
    );
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
            realm_id: Some("ak:realm:AhqX99K03QXK2MTH4KkLKdcUAjZEYYcxENCdxK3f6nN0".to_owned()),
            received_at: chrono::Utc::now(),
            payload: json!({
                "kind": "ak.strand.update",
                "body": {
                    "strand_id": "ak:strand:AOh8dxjVYDgM4sgWMvKYvKA-rHBR4-IIEc7fiwGJ7P1w",
                    "actor_id": "ak:did_core:web:alice.example",
                },
            }),
        },
        // Same strand, different actor — both should appear.
        RawOperationRecord {
            operation_id: "op-b".to_owned(),
            realm_id: Some("ak:realm:AhqX99K03QXK2MTH4KkLKdcUAjZEYYcxENCdxK3f6nN0".to_owned()),
            received_at: chrono::Utc::now(),
            payload: json!({
                "kind": "ak.message.create",
                "body": {
                    "target_ref": "ak:strand:AOh8dxjVYDgM4sgWMvKYvKA-rHBR4-IIEc7fiwGJ7P1w",
                    // Canonical actor key only; forbidden `sender`
                    // fields are hard-rejected.
                    "actor_id": "ak:did_core:web:bob.example",
                },
            }),
        },
        // Different strand — must be excluded so we don't bleed
        // unrelated realm actors into the per-card participant list.
        RawOperationRecord {
            operation_id: "op-c".to_owned(),
            realm_id: Some("ak:realm:AhqX99K03QXK2MTH4KkLKdcUAjZEYYcxENCdxK3f6nN0".to_owned()),
            received_at: chrono::Utc::now(),
            payload: json!({
                "kind": "ak.strand.update",
                "body": {
                    "strand_id": "ak:strand:A4EpRDvQloG8EYOGEPnGhe1SLpxBiLQbOvlptwBvvPkA",
                    "actor_id": "ak:did_core:web:carol.example",
                },
            }),
        },
    ];
    let dids = strand_participant_dids(
        &ops,
        "ak:strand:AOh8dxjVYDgM4sgWMvKYvKA-rHBR4-IIEc7fiwGJ7P1w",
    );
    assert_eq!(
        dids,
        vec![
            "ak:did_core:web:alice.example".to_owned(),
            "ak:did_core:web:bob.example".to_owned(),
        ]
    );
    assert!(strand_participant_dids(&ops, "").is_empty());
}

/// Canonical ContentBlock round-trip: the editor's plain text becomes a
/// `content` ContentBlock on the wire, and the projection reads that block back
/// as the same text. The forbidden top-level `body` never appears.
#[test]
fn card_detail_update_patch_emits_a_canonical_content_block() {
    let strand_id = "ak:strand:ACO0mgcDtIZrNCmU08vIqkIuP8CD6VrARiuEFskkdlWs";
    let mut current = test_card(strand_id, "U");
    current.title = "Keep".to_owned();
    current.synthesis = "old synthesis".to_owned();
    let mut draft = card_detail_draft_from_card(&current);
    draft.synthesis = "new synthesis".to_owned();

    let patch = card_detail_update_patch(&current, &draft).unwrap();
    assert!(patch.get("body").is_none(), "top-level body is forbidden");
    assert!(patch.get("synthesis").is_none());
    assert_eq!(patch["content"]["$op"], "set");
    assert_eq!(patch["content"]["value"]["kind"], "ak.content.text");
    assert_eq!(patch["content"]["value"]["format"], "markdown");
    assert_eq!(patch["content"]["value"]["body"], "new synthesis");

    // The emitted value decodes as the SDK ContentBlock (the spec type), and
    // the projection read renders exactly the text that went in.
    let block: arkret_sdk::ContentBlock =
        serde_json::from_value(patch["content"]["value"].clone()).expect("canonical ContentBlock");
    assert_eq!(block.body, "new synthesis");
    let strand = strand_projection_with_content(strand_id, patch["content"]["value"].clone());
    assert_eq!(
        card_from_strand_projection(&strand, None).synthesis,
        "new synthesis"
    );
}

/// Clearing the text writes an EMPTY ContentBlock, never `$op: unset`:
/// `event-and-patch.md` §4.2.4 forbids unsetting redactable content fields.
#[test]
fn clearing_card_content_writes_an_empty_block_instead_of_unset() {
    let mut current = test_card(
        "ak:strand:ACO0mgcDtIZrNCmU08vIqkIuP8CD6VrARiuEFskkdlWs",
        "U",
    );
    current.title = "Keep".to_owned();
    current.synthesis = "old synthesis".to_owned();
    let mut draft = card_detail_draft_from_card(&current);
    draft.synthesis = String::new();

    let patch = card_detail_update_patch(&current, &draft).unwrap();
    assert_eq!(patch["content"]["$op"], "set");
    assert_eq!(patch["content"]["value"]["body"], "");
    assert!(patch.get("encrypted_content").is_none());
}

/// Inline `ak.content.text` is bounded by the schema; the board has no Blob
/// upload path for `ak.content.long_text`, so it refuses rather than emitting
/// an invalid block.
#[test]
fn oversized_card_content_is_refused_instead_of_emitting_an_invalid_block() {
    let mut current = test_card(
        "ak:strand:ACO0mgcDtIZrNCmU08vIqkIuP8CD6VrARiuEFskkdlWs",
        "U",
    );
    current.title = "Keep".to_owned();
    let mut draft = card_detail_draft_from_card(&current);
    draft.synthesis = "x".repeat(KANBAN_CONTENT_TEXT_MAX_CHARS + 1);

    let error = card_detail_update_patch(&current, &draft).unwrap_err();
    assert!(error.contains("ak.content.text"), "{error}");
}

/// `content` round-trips as the SDK ContentBlock: the value the patch emitted
/// decodes into the projection field, and the card reads the same text back.
fn strand_projection_with_content(
    strand_id: &str,
    content: serde_json::Value,
) -> crate::state::projection_views::StrandProjectionView {
    let content: arkret_sdk::ContentBlock =
        serde_json::from_value(content).expect("projection content is a canonical ContentBlock");
    crate::state::projection_views::StrandProjectionView {
        strand_id: strand_id.to_owned(),
        realm_id: TEST_REALM_ID.to_owned(),
        title: "Keep".to_owned(),
        summary: None,
        content: Some(content),
        encrypted_content: None,
        board_space_id: None,
        list_space_id: None,
        rank: None,
        assigned_actor_ids: Vec::new(),
        assigned_to_relations: Vec::new(),
        schema_refs: Vec::new(),
        rsvps: Vec::new(),
        schedule_revision_heads: Vec::new(),
        fields: Map::new(),
        created_by: None,
        created_at: None,
        updated_by: None,
        updated_at: None,
        state: arkret_sdk::ProjectionObjectState::Active,
    }
}

#[test]
fn card_detail_update_patch_unsets_empty_optional_fields() {
    let mut current = test_card(
        "ak:strand:ACO0mgcDtIZrNCmU08vIqkIuP8CD6VrARiuEFskkdlWs",
        "U",
    );
    current.title = "Keep".to_owned();
    current.description = "old summary".to_owned();
    current.labels = vec!["old".to_owned()];
    current.assignee = "did:web:bob.example".to_owned();
    current.due = "2026-05-19".to_owned();
    let draft = CardDetailDraft {
        title: "Keep".to_owned(),
        // The summary is carried over unchanged, so it must not appear in the
        // patch at all; clearing it is covered by its own test.
        description: "old summary".to_owned(),
        synthesis: String::new(),
        labels: Vec::new(),
        assignee: String::new(),
        due: String::new(),
        calendar: CalendarCardFields::default(),
    };

    let patch = card_detail_update_patch(&current, &draft).unwrap();
    assert!(patch.get("metadata.summary").is_none());
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

/// `metadata.summary` is NOT a redactable content-carrier slot:
/// `redactable-field-registry.json` registers only `content` /
/// `encrypted_content`, and `event-and-patch.md` §4.2.4 names
/// `metadata.summary` among the ordinary optional members whose one
/// non-terminal clear path is `$op: unset`. `strand.schema.json` types it as
/// the `short_text` profile (`minLength: 1`), so there is no empty value to
/// `set` — unlike `content`, which clears as an empty ContentBlock.
#[test]
fn clearing_card_summary_emits_unset() {
    let mut current = test_card(
        "ak:strand:ACO0mgcDtIZrNCmU08vIqkIuP8CD6VrARiuEFskkdlWs",
        "U",
    );
    current.title = "Keep".to_owned();
    current.description = "old summary".to_owned();
    let mut draft = card_detail_draft_from_card(&current);
    draft.description = String::new();
    // A second changed field proves the unset is not the patch's only entry by
    // accident.
    draft.labels = vec!["kept".to_owned()];

    let patch = card_detail_update_patch(&current, &draft).unwrap();
    assert_eq!(patch["metadata.summary"]["$op"], "unset");
    assert!(patch["metadata.summary"].get("value").is_none());

    // The SDK accepts the same op on the wire type, so this patch reaches a
    // compliant reducer.
    let wire: arkret_sdk::Patch =
        serde_json::from_value(patch.clone()).expect("patch decodes as ak.patch.v1");
    arkret_sdk::validate_patch_semantic_safety(&wire).expect("metadata.summary unset is accepted");

    // The registered slots are the ones that stay refused.
    for slot in arkret_wire::generated::REDACTABLE_FIELD_PATHS {
        let mut rejected = arkret_sdk::Patch::new();
        rejected
            .insert_op(*slot, arkret_sdk::PatchOp::unset())
            .unwrap();
        let rejection = arkret_sdk::validate_patch_semantic_safety(&rejected).unwrap_err();
        assert!(
            rejection
                .to_string()
                .contains("patch_unset_redactable_field"),
            "{slot}: {rejection}"
        );
    }
}

#[test]
fn synthesis_edit_scope_preserves_metadata_fields() {
    let mut current = test_card(
        "ak:strand:ACO0mgcDtIZrNCmU08vIqkIuP8CD6VrARiuEFskkdlWs",
        "U",
    );
    current.title = "Keep".to_owned();
    current.description = "old summary".to_owned();
    current.synthesis = "old synthesis".to_owned();
    current.labels = vec!["feature".to_owned()];
    current.due = "2026-05-19".to_owned();

    let (draft, synthesis_revision) = card_detail_draft_for_edit_scope(
        &current,
        CardEditScope::Synthesis,
        &[],
        None,
        "",
        "",
        "new synthesis",
        "",
        "",
        "",
    );

    assert_eq!(synthesis_revision.as_deref(), Some("new synthesis"));
    assert_eq!(draft.title, current.title);
    assert_eq!(draft.description, current.description);
    assert_eq!(draft.synthesis, "new synthesis");
    assert_eq!(draft.labels, current.labels);
    assert_eq!(draft.due, "2026-05-19");
    let patch = card_detail_update_patch(&current, &draft).unwrap();
    let object = patch.as_object().unwrap();
    assert_eq!(object.len(), 1);
    assert_eq!(patch["content"]["$op"], "set");
    assert_eq!(patch["content"]["value"]["body"], "new synthesis");
    assert!(patch.get("metadata.fields.labels").is_none());
    assert!(patch.get("metadata.fields.due_at").is_none());
    assert_eq!(
        card_detail_activity_summary(&current, &draft),
        "Card details updated"
    );
}

#[test]
fn apply_card_detail_draft_marks_card_queued() {
    let mut card = test_card(
        "ak:strand:ACO0mgcDtIZrNCmU08vIqkIuP8CD6VrARiuEFskkdlWs",
        "U",
    );
    let draft = CardDetailDraft {
        title: "New title".to_owned(),
        description: "New summary".to_owned(),
        synthesis: "Synthesis content".to_owned(),
        labels: vec!["ops".to_owned()],
        assignee: String::new(),
        due: "2026-05-20".to_owned(),
        calendar: CalendarCardFields::default(),
    };

    apply_card_detail_draft(&mut card, &draft);
    assert_eq!(card.title, "New title");
    assert_eq!(card.description, "New summary");
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
    let projection: arkret_sdk::CollectionProjectionView =
        serde_json::from_value(serde_json::json!({
            "projection": "collection",
            "renderer": "board",
            "view_id": "ak:view:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19",
            "frontier": {
                "state_digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000"
            },
            "groups": [{
                "key": "ak:space:AZngJaVQawCL7GPGhC0eyhLzcUFP-HyKX0TkoAd94RR-",
                "title": "Review",
                "rank": "U",
                "items": [{
                    "object": {
                        "id": "ak:strand:AYDxHFPmRofiVfTHU1jCJ3yOIqB7sFhRtXuTT3aAGt8r",
                        "kind": "strand",
                        "title": "Find me"
                    },
                    "position": {
                    "model": "relation",
                    "scope_container_id": "ak:space:Af2HCFbsrVezIXsZGcgB3mjkpqGK-C4DmteWaG3H0Xbh",
                    "container_id": "ak:space:AZngJaVQawCL7GPGhC0eyhLzcUFP-HyKX0TkoAd94RR-",
                    "relation_kind": "contains",
                    "relation_id": "ak:relation:Ab0jbIKlPZ-M3WbarZlCPLYtkCWggYwWZeRDlW-ShdQ9",
                    "rank": "h3"
                }}],
                "limited": false
            }]
        }))
        .unwrap();
    let expected = locate_strand_position_in_projection(
        &projection,
        "ak:strand:AYDxHFPmRofiVfTHU1jCJ3yOIqB7sFhRtXuTT3aAGt8r",
    );
    assert_eq!(
        expected,
        StrandPositionExpectation::At {
            list_space_id: "ak:space:AZngJaVQawCL7GPGhC0eyhLzcUFP-HyKX0TkoAd94RR-".to_owned(),
            rank: "h3".to_owned(),
        }
    );
}

/// When the strand isn't in the projection, the rebase must use
/// `head_eq null` (Initial) — soland's reducer rejects if the cell
/// is actually non-initial, which is the safe behaviour.
#[test]
fn locate_strand_position_missing_strand_returns_initial() {
    let projection: arkret_sdk::CollectionProjectionView =
        serde_json::from_value(serde_json::json!({
            "projection": "collection",
            "renderer": "board",
            "view_id": "ak:view:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19",
            "frontier": {
                "state_digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000"
            },
            "groups": []
        }))
        .unwrap();
    let expected = locate_strand_position_in_projection(
        &projection,
        "ak:strand:AIAbwRfAw3zu-66yOfsjuxIhm7pwbG1Kyy559Vp3bDWM",
    );
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
        // SDK RealmId is strictly a full event-derived `ak:realm:<event-token>`; the realm arg can
        // no longer be the demo Space id.
        let event = crate::operation::ak_ops::strand_update_patch(
            "ak:realm:AY61QviMxoJ0ALEn5U39bA7Qbi1BxHCrOq4950m2JRjM",
            "did:web:acme.example:users:alice",
            strand_id,
            json!({"content": content_patch_value("demo synthesis")}),
        )
        .expect("builds")
        .build("inkson");
        assert_eq!(event.kind.as_str(), "ak.strand.update");
        assert_eq!(sdk_event_local_target_ref(&event), Some(strand_id));
    }
}
