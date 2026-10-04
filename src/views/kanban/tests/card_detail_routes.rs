use super::*;

#[test]
fn card_edit_waits_for_the_complete_accepted_current() {
    let event_id =
        arkret_sdk::EventId::from_digest(arkret_sdk::canonical::DigestSuite::Sha256, [0x24; 32]);
    let strand_id = arkret_sdk::StrandId::from_event_id(&event_id);
    let mut card = test_card(strand_id.as_str(), "U");
    card.state = CardState::Synced;
    assert!(!card_detail_write_ready(&card));
    card.authoring_basis = Some(arkret_wire::CurrentRevision {
        commit_id: arkret_wire::RealmCommitId::from_digest([0x24; 32]),
        stream_position: 1,
    });
    assert!(card_detail_write_ready(&card));
    for state in [
        CardState::Optimistic,
        CardState::Queued,
        CardState::Submitted,
        CardState::Accepted,
        CardState::SoftFailed,
        CardState::Quarantined,
        CardState::Conflict,
    ] {
        card.state = state;
        assert!(!card_detail_write_ready(&card));
    }
    card.state = CardState::Synced;
    card.id = "0196419b-0000-7000-8000-000000000001".to_owned();
    assert!(!card_detail_write_ready(&card));
}

#[test]
fn accepted_card_route_migrates_only_its_local_handle_with_a_complete_basis() {
    let local_id = "0196419b-0000-7000-8000-000000000001";
    let event_id =
        arkret_sdk::EventId::from_digest(arkret_sdk::canonical::DigestSuite::Sha256, [0x25; 32]);
    let strand_id = arkret_sdk::StrandId::from_event_id(&event_id);
    let mut card = test_card(strand_id.as_str(), "U");
    card.state = CardState::Synced;
    card.authoring_basis = Some(arkret_wire::CurrentRevision {
        commit_id: arkret_wire::RealmCommitId::from_digest([0x25; 32]),
        stream_position: 1,
    });
    let receipt = RawOperationRecord {
        operation_id: local_id.to_owned(),
        realm_id: Some(TEST_REALM_ID.to_owned()),
        received_at: chrono::Utc::now(),
        payload: json!({
            "kind": "ak.strand.create",
            "event_id": event_id,
            "local_temporary_target_ref": local_id,
            "write_state": "synced"
        }),
    };
    let board_id = arkret_sdk::SpaceId::from_event_id(&event_id).to_string();
    let route = Route::KanbanBoardTask {
        realm_id: TEST_REALM_ID.to_owned(),
        board_id: board_id.clone(),
        task_id: local_id.to_owned(),
    };
    let accepted_route = Route::KanbanBoardTask {
        realm_id: TEST_REALM_ID.to_owned(),
        board_id,
        task_id: strand_id.to_string(),
    };
    assert_eq!(card_task_route_after_acceptance(&route, &card, &[]), None);
    assert_eq!(
        card_task_route_after_acceptance(&route, &card, &[receipt.clone()]),
        Some(accepted_route.clone())
    );
    assert_eq!(
        card_task_route_after_acceptance(&accepted_route, &card, &[receipt.clone()]),
        None
    );
    let without_board = Route::KanbanTask {
        realm_id: TEST_REALM_ID.to_owned(),
        task_id: local_id.to_owned(),
    };
    assert_eq!(
        card_task_route_after_acceptance(&without_board, &card, &[receipt.clone()]),
        Some(Route::KanbanTask {
            realm_id: TEST_REALM_ID.to_owned(),
            task_id: strand_id.to_string(),
        })
    );
    let unrelated = Route::KanbanTask {
        realm_id: TEST_REALM_ID.to_owned(),
        task_id: "0196419b-0000-7000-8000-000000000002".to_owned(),
    };
    assert_eq!(
        card_task_route_after_acceptance(&unrelated, &card, &[receipt.clone()]),
        None
    );
    card.authoring_basis = None;
    assert_eq!(
        card_task_route_after_acceptance(&route, &card, &[receipt.clone()]),
        None
    );
    card.authoring_basis = Some(arkret_wire::CurrentRevision {
        commit_id: arkret_wire::RealmCommitId::from_digest([0x25; 32]),
        stream_position: 1,
    });
    card.state = CardState::Accepted;
    assert_eq!(
        card_task_route_after_acceptance(&route, &card, &[receipt]),
        None
    );
}

#[test]
fn discussion_waits_for_event_derived_strand_identity() {
    let mut pending = test_card("0196419b-0000-7000-8000-000000000001", "U");
    pending.primary_strand_id = "0196419b-0000-7000-8000-000000000001".to_owned();
    assert!(!card_discussion_target_ready(&pending));

    let event_id =
        arkret_sdk::EventId::from_digest(arkret_sdk::canonical::DigestSuite::Sha256, [0x23; 32]);
    let canonical_strand_id = arkret_sdk::StrandId::from_event_id(&event_id);
    let mut canonical = test_card(canonical_strand_id.as_str(), "U");
    canonical.primary_strand_id = canonical_strand_id.to_string();
    assert!(card_discussion_target_ready(&canonical));
}

#[test]
fn card_detail_deep_link_targets_kanban_task_route() {
    assert_eq!(
        strand_detail_deep_link_path(
            "ak:space:ops",
            "ak:strand:ARLfbkLnSkVpiiEUORJ1StQffis7S7-xfOV6V1_PuAPg"
        ),
        "/kanban/ak:space:ops/task/ak:strand:ARLfbkLnSkVpiiEUORJ1StQffis7S7-xfOV6V1_PuAPg"
    );
    assert_eq!(
        strand_detail_deep_link_path("", "ak:strand:ARLfbkLnSkVpiiEUORJ1StQffis7S7-xfOV6V1_PuAPg"),
        format!(
            "/kanban/{DEMO_BOARD_SPACE_ID}/task/ak:strand:ARLfbkLnSkVpiiEUORJ1StQffis7S7-xfOV6V1_PuAPg"
        )
    );
}

#[test]
fn card_detail_tab_deep_link_round_trips() {
    assert_eq!(
        card_detail_tab_slug(CardDetailContentTab::Description),
        "description"
    );
    assert_eq!(
        card_detail_tab_slug(CardDetailContentTab::Synthesis),
        "synthesis"
    );
    assert_eq!(
        card_detail_tab_from_slug("SYNTHESIS"),
        Some(CardDetailContentTab::Synthesis)
    );
    assert_eq!(
        card_detail_tab_from_slug("discussion"),
        Some(CardDetailContentTab::Discussion)
    );
    assert_eq!(
        card_detail_tab_from_slug("description"),
        Some(CardDetailContentTab::Description)
    );
    assert_eq!(
        CardDetailContentTab::default(),
        CardDetailContentTab::Description
    );
}

#[test]
fn card_detail_tab_reads_url_query() {
    assert_eq!(
        card_detail_tab_from_href(
            "http://127.0.0.1:8080/kanban/ak:realm:r/task/ak:strand:f?tab=description"
        ),
        Some(CardDetailContentTab::Description)
    );
    assert_eq!(
        card_detail_tab_from_href(
            "http://127.0.0.1:8080/kanban/ak:realm:r/task/ak:strand:f?tab=discussion"
        ),
        Some(CardDetailContentTab::Discussion)
    );
    assert_eq!(
        card_detail_tab_from_href(
            "http://127.0.0.1:8080/kanban/ak:realm:r/task/ak:strand:f?tab=synthesis"
        ),
        Some(CardDetailContentTab::Synthesis)
    );
    assert_eq!(
        card_detail_tab_from_href(
            "http://127.0.0.1:8080/kanban/ak:realm:r/task/ak:strand:f?tab=bad"
        ),
        None
    );
}

#[test]
fn card_detail_share_link_carries_current_tab() {
    assert_eq!(
        strand_detail_deep_link_path_with_tab(
            "ak:space:ops",
            "ak:strand:ARLfbkLnSkVpiiEUORJ1StQffis7S7-xfOV6V1_PuAPg",
            CardDetailContentTab::Discussion
        ),
        "/kanban/ak:space:ops/task/ak:strand:ARLfbkLnSkVpiiEUORJ1StQffis7S7-xfOV6V1_PuAPg?tab=discussion"
    );
}

#[test]
fn route_card_strand_id_reads_task_segment_only() {
    assert_eq!(
        route_card_strand_id(&Route::KanbanTask {
            realm_id: "ak:realm:At9cQzHAltYPBAr08k50aWUnPgEYe-038vPA2q3wBT5U".to_owned(),
            task_id: "ak:strand:ARLfbkLnSkVpiiEUORJ1StQffis7S7-xfOV6V1_PuAPg".to_owned(),
        }),
        Some("ak:strand:ARLfbkLnSkVpiiEUORJ1StQffis7S7-xfOV6V1_PuAPg".to_owned())
    );
    assert_eq!(
        route_card_strand_id(&Route::KanbanBoardTask {
            realm_id: "ak:realm:At9cQzHAltYPBAr08k50aWUnPgEYe-038vPA2q3wBT5U".to_owned(),
            board_id: "ak:space:board".to_owned(),
            task_id: "ak:strand:ARLfbkLnSkVpiiEUORJ1StQffis7S7-xfOV6V1_PuAPg".to_owned(),
        }),
        Some("ak:strand:ARLfbkLnSkVpiiEUORJ1StQffis7S7-xfOV6V1_PuAPg".to_owned())
    );
    assert_eq!(route_card_strand_id(&Route::Kanban), None);
}

#[test]
fn route_board_id_reads_board_segment_only() {
    let board = "ak:space:AaDn_ypTG8vV4ToKfz6JtG2xnepF9QDlafPZCT-UYPyR";
    let parsed = arkret_sdk::SpaceId::new(board).ok();
    assert_eq!(
        route_board_id(&Route::KanbanBoard {
            realm_id: "ak:realm:At9cQzHAltYPBAr08k50aWUnPgEYe-038vPA2q3wBT5U".to_owned(),
            board_id: board.to_owned(),
        }),
        parsed
    );
    assert_eq!(
        route_board_id(&Route::KanbanBoardTask {
            realm_id: "ak:realm:At9cQzHAltYPBAr08k50aWUnPgEYe-038vPA2q3wBT5U".to_owned(),
            board_id: board.to_owned(),
            task_id: "ak:strand:ARLfbkLnSkVpiiEUORJ1StQffis7S7-xfOV6V1_PuAPg".to_owned(),
        }),
        parsed
    );
    // The board-less routes carry no board id — it is resolved from
    // the projection on arrival.
    assert_eq!(
        route_board_id(&Route::KanbanTask {
            realm_id: "ak:realm:At9cQzHAltYPBAr08k50aWUnPgEYe-038vPA2q3wBT5U".to_owned(),
            task_id: "ak:strand:ARLfbkLnSkVpiiEUORJ1StQffis7S7-xfOV6V1_PuAPg".to_owned(),
        }),
        None
    );
    assert_eq!(
        route_board_id(&Route::KanbanRealm {
            realm_id: "ak:realm:At9cQzHAltYPBAr08k50aWUnPgEYe-038vPA2q3wBT5U".to_owned(),
        }),
        None
    );
}

/// The URL segment is untrusted: a holder-local operation id (or any malformed
/// value) must fail closed to `None` instead of entering the Board selection.
#[test]
fn route_board_id_fails_closed_on_non_space_id_segments() {
    let route_with = |board_id: &str| Route::KanbanBoard {
        realm_id: "ak:realm:At9cQzHAltYPBAr08k50aWUnPgEYe-038vPA2q3wBT5U".to_owned(),
        board_id: board_id.to_owned(),
    };
    assert_eq!(route_board_id(&route_with("")), None);
    assert_eq!(
        route_board_id(&route_with("01a01bdd-804b-7ad0-bee8-194898437ad7")),
        None,
        "a pending create's holder-local id is never a Board route"
    );
    assert_eq!(route_board_id(&route_with("ak:space:board")), None);
    assert_eq!(
        route_board_id(&route_with(
            "ak:strand:ARLfbkLnSkVpiiEUORJ1StQffis7S7-xfOV6V1_PuAPg"
        )),
        None
    );
}

#[test]
fn kanban_board_route_carries_board_or_falls_back() {
    assert_eq!(
        kanban_board_route(
            "ak:realm:At9cQzHAltYPBAr08k50aWUnPgEYe-038vPA2q3wBT5U",
            "ak:space:board"
        ),
        Route::KanbanBoard {
            realm_id: "ak:realm:At9cQzHAltYPBAr08k50aWUnPgEYe-038vPA2q3wBT5U".to_owned(),
            board_id: "ak:space:board".to_owned(),
        }
    );
    assert_eq!(
        kanban_board_route("ak:realm:At9cQzHAltYPBAr08k50aWUnPgEYe-038vPA2q3wBT5U", ""),
        Route::KanbanRealm {
            realm_id: "ak:realm:At9cQzHAltYPBAr08k50aWUnPgEYe-038vPA2q3wBT5U".to_owned(),
        }
    );
}

#[test]
fn kanban_card_task_route_carries_board_or_falls_back() {
    assert_eq!(
        kanban_card_task_route(
            "ak:realm:At9cQzHAltYPBAr08k50aWUnPgEYe-038vPA2q3wBT5U",
            "ak:space:board",
            "ak:strand:ARLfbkLnSkVpiiEUORJ1StQffis7S7-xfOV6V1_PuAPg"
        ),
        Route::KanbanBoardTask {
            realm_id: "ak:realm:At9cQzHAltYPBAr08k50aWUnPgEYe-038vPA2q3wBT5U".to_owned(),
            board_id: "ak:space:board".to_owned(),
            task_id: "ak:strand:ARLfbkLnSkVpiiEUORJ1StQffis7S7-xfOV6V1_PuAPg".to_owned(),
        }
    );
    assert_eq!(
        kanban_card_task_route(
            "ak:realm:At9cQzHAltYPBAr08k50aWUnPgEYe-038vPA2q3wBT5U",
            "",
            "ak:strand:ARLfbkLnSkVpiiEUORJ1StQffis7S7-xfOV6V1_PuAPg"
        ),
        Route::KanbanTask {
            realm_id: "ak:realm:At9cQzHAltYPBAr08k50aWUnPgEYe-038vPA2q3wBT5U".to_owned(),
            task_id: "ak:strand:ARLfbkLnSkVpiiEUORJ1StQffis7S7-xfOV6V1_PuAPg".to_owned(),
        }
    );
}

#[test]
fn find_card_by_strand_id_matches_card_or_primary_strand() {
    let columns = seed_columns();
    assert_eq!(
        find_card_by_strand_id(&columns, DEMO_STRAND_LEGAL_REVIEW_ID).map(|card| card.title),
        Some("Legal review for public beta".to_owned())
    );
    assert_eq!(
        find_card_by_strand_id(&columns, DEMO_STRAND_REVIEW_DISCUSSION_ID).map(|card| card.id),
        Some(DEMO_STRAND_LEGAL_REVIEW_ID.to_owned())
    );
}

#[test]
fn open_pending_card_editor_resolves_its_receipt_without_rebasing_accepted_edits() {
    let local_id = "0196419b-0000-7000-8000-000000000001";
    let event_id =
        arkret_sdk::EventId::from_digest(arkret_sdk::canonical::DigestSuite::Sha256, [0x23; 32]);
    let strand_id = arkret_sdk::StrandId::from_event_id(&event_id);
    let pending = test_card(local_id, "U");
    let mut accepted = pending.clone();
    accepted.id = strand_id.to_string();
    accepted.primary_strand_id = strand_id.to_string();
    accepted.authoring_basis = Some(arkret_wire::CurrentRevision {
        commit_id: arkret_wire::RealmCommitId::from_digest([1; 32]),
        stream_position: 1,
    });
    let mut columns = seed_columns();
    columns[0].cards = vec![accepted.clone()];
    let receipt = RawOperationRecord {
        operation_id: local_id.to_owned(),
        realm_id: Some(TEST_REALM_ID.to_owned()),
        received_at: chrono::Utc::now(),
        payload: json!({
            "kind": "ak.strand.create",
            "event_id": event_id,
            "local_temporary_target_ref": local_id,
            "write_state": "synced"
        }),
    };
    assert_eq!(
        selected_card_projection_update(&pending, &columns, &[], true),
        None,
        "a visible projection alone cannot promote a holder-local handle"
    );
    assert!(card_detail_write_ready(&accepted));
    let mut incomplete = accepted.clone();
    incomplete.state = CardState::Accepted;
    incomplete.authoring_basis = None;
    columns[0].cards = vec![incomplete.clone()];
    assert!(!card_detail_write_ready(&incomplete));
    assert_eq!(
        selected_card_projection_update(&pending, &columns, &[receipt.clone()], true),
        None,
        "a canonical identity alone is not an editable accepted current"
    );
    columns[0].cards = vec![accepted.clone()];
    assert_eq!(
        selected_card_projection_update(&pending, &columns, &[receipt], true),
        Some(accepted.clone())
    );
    assert_eq!(
        selected_card_projection_update(&incomplete, &columns, &[], true),
        Some(accepted.clone()),
        "an editor opened after ID acceptance still waits for its first complete basis"
    );
    let mut pending_receipt = accepted.clone();
    pending_receipt.state = CardState::Accepted;
    assert!(!card_detail_write_ready(&pending_receipt));
    columns[0].cards[0].description = "do not rebase captured content".to_owned();
    assert_eq!(
        selected_card_projection_update(&pending_receipt, &columns, &[], true),
        Some(accepted.clone()),
        "receipt state settles without replacing the captured value/source"
    );
    columns[0].cards[0]
        .authoring_basis
        .as_mut()
        .unwrap()
        .stream_position = 2;
    assert_eq!(
        selected_card_projection_update(&pending_receipt, &columns, &[], true),
        None,
        "a new source cannot settle an older captured editor basis"
    );
    columns[0].cards[0].description = "remote replacement".to_owned();
    assert_eq!(
        selected_card_projection_update(&accepted, &columns, &[], true),
        None,
        "an accepted editor keeps its captured source/value"
    );
    assert_eq!(
        selected_card_projection_update(&accepted, &columns, &[], false),
        Some(columns[0].cards[0].clone())
    );
}
