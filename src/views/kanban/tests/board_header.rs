use super::*;

#[test]
fn direct_conversation_blocks_spaces_but_collaboration_realm_keeps_boards() {
    let mut store = isolated_store_for_tests("direct-conversation-board-unavailable");
    assert!(store.realm_allows_spaces(TEST_REALM_ID));
    store.save_realm_collaboration_role(
        TEST_REALM_ID.to_owned(),
        Some(arkret_sdk::CollaborationRealmRole::DirectConversation),
    );
    assert!(!store.realm_allows_spaces(TEST_REALM_ID));
    store.save_realm_collaboration_role(TEST_REALM_ID.to_owned(), None);
    assert!(store.realm_allows_spaces(TEST_REALM_ID));
}

const BOARD_A: &str = "ak:space:AVFSR4O2uTcP6zGsyewp0OdaGeDZBXQAUZ9VIEKLSXYo";
const BOARD_B: &str = "ak:space:AZQnaSleDidYaYIvfwYy3au5gnd_DSinxyUHEl7ewtxk";

fn space_id(value: &str) -> arkret_sdk::SpaceId {
    arkret_sdk::SpaceId::new(value.to_owned()).expect("fixture space id")
}

fn option(id: &str, title: &str) -> BoardSpaceOption {
    BoardSpaceOption {
        rank: None,
        id: space_id(id),
        title: title.to_owned(),
        state: SpaceContainerLifecycleState::Active,
    }
}

#[test]
fn board_ranks_survive_renames_and_allow_drops_between_legacy_boards() {
    const BOARD_C: &str = "ak:space:Aepgr15HbtERKfqPAh9SrfWBdihSvX_c94JvujvBS2f-";
    let a = option(BOARD_A, "Zulu");
    let b = option(BOARD_B, "Alpha");
    let mut c = option(BOARD_C, "Last");
    c.rank = Some("z".into());
    let mut boards = vec![c, b, a];
    sort_board_space_options(&mut boards);
    assert_eq!(boards[0].id.as_str(), BOARD_A);
    assert_eq!(boards[1].id.as_str(), BOARD_B);
    assert!(boards[0].ordering_rank().starts_with("4156"));
    assert_eq!(boards[0].ordering_rank().len(), 88);
    let id = boards[2].id.clone();
    let moved = board_drop_rank(&boards, &id, &boards[1].id, false)
        .unwrap()
        .unwrap();
    assert!(boards[0].ordering_rank().as_ref() < moved.as_str());
    assert!(moved.as_str() < boards[1].ordering_rank().as_ref());
    boards[2].rank = Some(moved);
    sort_board_space_options(&mut boards);
    assert_eq!(boards[1].id, id);
    assert_eq!(
        board_drop_rank(&boards, &id, &boards[2].id, false).unwrap(),
        None
    );
    let last = board_drop_rank(&boards, &id, &boards[2].id, true)
        .unwrap()
        .unwrap();
    assert!(last.as_str() > boards[2].ordering_rank().as_ref());
    let first = board_drop_rank(&boards, &id, &boards[0].id, false)
        .unwrap()
        .unwrap();
    assert!(first.as_str() < boards[0].ordering_rank().as_ref());
}

#[test]
fn explicit_rank_equal_to_a_legacy_key_uses_space_id() {
    let a = option(BOARD_A, "Zulu");
    let mut b = option(BOARD_B, "Alpha");
    b.rank = Some(a.ordering_rank().into_owned());
    let mut boards = vec![b, a];
    sort_board_space_options(&mut boards);
    assert_eq!(boards[0].id.as_str(), BOARD_A);
    assert!(boards[0].rank.is_none());
}

fn pending(title: &str, state: CardState) -> PendingBoardCreate {
    PendingBoardCreate {
        rank: None,
        operation_id: crate::operation::LocalOperationId::new(),
        title: title.to_owned(),
        state,
        error: None,
    }
}

#[test]
fn new_board_follows_legacy_confirmed_and_pending_boards() {
    let options = [option(BOARD_A, "Legacy")];
    let first = board_append_rank(&options, &[]).unwrap();
    assert!(first.as_str() > options[0].ordering_rank().as_ref());
    let mut queued = pending("First create", CardState::Queued);
    queued.rank = Some(first.clone());
    assert!(board_append_rank(&options, &[queued]).unwrap() > first);
    assert_eq!(
        board_append_rank(&[], &[]).unwrap(),
        rank_for_drop(None, None).unwrap()
    );
}

#[test]
fn a_confirmed_board_is_named_by_its_option_title() {
    let header = board_header(
        Some(&space_id(BOARD_A)),
        &[option(BOARD_B, "Roadmap"), option(BOARD_A, "Sprint")],
        Vec::new(),
    );
    assert_eq!(header.title, "Sprint");
    assert!(header.active_pending_board.is_none());
}

#[test]
fn a_confirmed_board_whose_title_has_not_arrived_keeps_the_title_unresolved() {
    let header = board_header(Some(&space_id(BOARD_A)), &[], Vec::new());
    assert!(header.title.is_empty());
    assert_eq!(
        kanban_title_label(&header.title, BOARD_A, "Title pending sync"),
        "Title pending sync"
    );
}

#[test]
fn kanban_titles_do_not_render_projection_ids_while_metadata_is_pending() {
    for title in ["", "  ", BOARD_A] {
        assert_eq!(
            kanban_title_label(title, BOARD_A, "Title pending sync"),
            "Title pending sync"
        );
    }
    assert_eq!(
        kanban_title_label("Sprint", BOARD_A, "Title pending sync"),
        "Sprint"
    );
}

#[test]
fn a_confirmed_selection_never_stands_in_for_a_pending_create() {
    // Creates can still be in flight while an older Board is open; the header
    // belongs to the Board the user is actually looking at.
    let header = board_header(
        Some(&space_id(BOARD_A)),
        &[option(BOARD_A, "Sprint")],
        vec![pending("Fresh", CardState::Queued)],
    );
    assert_eq!(header.title, "Sprint");
    assert!(header.active_pending_board.is_none());
}

#[test]
fn the_newest_pending_create_owns_the_surface_until_a_board_is_confirmed() {
    let header = board_header(
        None,
        &[],
        vec![
            pending("Older", CardState::Queued),
            pending("Newest", CardState::Queued),
        ],
    );
    assert_eq!(header.title, "Newest (creating)");
    assert_eq!(
        header.active_pending_board.map(|pending| pending.title),
        Some("Newest".to_owned())
    );
}

#[test]
fn a_failed_pending_create_says_so_in_the_header() {
    let header = board_header(None, &[], vec![pending("Broken", CardState::SoftFailed)]);
    assert_eq!(header.title, "Broken (create failed)");
}

#[test]
fn nothing_selected_and_nothing_pending_prompts_for_a_selection() {
    let header = board_header(None, &[], Vec::new());
    assert_eq!(header.title, "Select board");
    assert!(header.active_pending_board.is_none());
}
