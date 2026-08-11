use super::*;

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
        card_detail_tab_from_slug("SYNTHESIS"),
        Some(CardDetailContentTab::Synthesis)
    );
    assert_eq!(
        card_detail_tab_from_slug("discussion"),
        Some(CardDetailContentTab::Discussion)
    );
    assert_eq!(card_detail_tab_from_slug("activity"), None);
}

#[test]
fn card_detail_tab_reads_url_query() {
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
    assert_eq!(
        route_board_id(&Route::KanbanBoard {
            realm_id: "ak:realm:At9cQzHAltYPBAr08k50aWUnPgEYe-038vPA2q3wBT5U".to_owned(),
            board_id: "ak:space:board".to_owned(),
        }),
        Some("ak:space:board".to_owned())
    );
    assert_eq!(
        route_board_id(&Route::KanbanBoardTask {
            realm_id: "ak:realm:At9cQzHAltYPBAr08k50aWUnPgEYe-038vPA2q3wBT5U".to_owned(),
            board_id: "ak:space:board".to_owned(),
            task_id: "ak:strand:ARLfbkLnSkVpiiEUORJ1StQffis7S7-xfOV6V1_PuAPg".to_owned(),
        }),
        Some("ak:space:board".to_owned())
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
