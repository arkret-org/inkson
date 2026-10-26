use super::model::*;
use crate::views::helpers::short_protocol_id;

#[allow(clippy::too_many_arguments)]
pub(super) fn select_kanban_board(
    app: Rc<InksonContext>,
    board_id: Option<arkret_sdk::SpaceId>,
    selected_board: Cage<Option<arkret_sdk::SpaceId>>,
    board_popover: Cage<BoardToolbarPopover>,
    selected_card: Cage<Option<KanbanCard>>,
    board_route_realm_id: String,
    adding_card_to: Cage<Option<String>>,
    board_status: Cage<String>,
) {
    // Board switching is pure selection: set `selected_board` and the
    // URL, then let the `columns` `use_memo` (keyed on the selection + the op
    // log) re-project the chosen board. No reproject / `columns.set` here.
    selected_board.revise(|value| {
        let next = board_id.clone();
        *value = next;
    });
    board_popover.revise(|value| {
        let next = BoardToolbarPopover::None;
        *value = next;
    });
    // Closing any open card too: a board switch should not keep a card from a
    // different board mounted.
    selected_card.revise(|value| {
        let next = None;
        *value = next;
    });
    match &board_id {
        None => {
            adding_card_to.revise(|value| {
                let next = None;
                *value = next;
            });
            board_status.revise(|value| {
                let next = "Select or create a board before adding lists".to_owned();
                *value = next;
            });
        }
        Some(board_id) => {
            board_status.revise(|value| {
                let next = format!("Board selected · {}", short_protocol_id(board_id.as_str()));
                *value = next;
            });
        }
    }
    replace_kanban_board_url(
        app.clone(),
        &board_route_realm_id,
        board_id
            .as_ref()
            .map(arkret_sdk::SpaceId::as_str)
            .unwrap_or(""),
    );
}

pub(super) fn replace_kanban_board_url(app: Rc<InksonContext>, realm_id: &str, board_id: &str) {
    app.replace_route(kanban_board_route(realm_id, board_id));
}

pub(super) fn seed_columns() -> Vec<KanbanColumn> {
    vec![
        KanbanColumn {
            id: "ak:space:01list-todo000000000000000000".to_owned(),
            title: "To Do".to_owned(),
            rank: "U".to_owned(),
            cards: vec![KanbanCard {
                id: DEMO_STRAND_LEGAL_REVIEW_ID.to_owned(),
                // Seed cards seed `cards[i].rank` from the
                // lexofractional alphabet so the next rank_between
                // call has well-formed neighbours to work with. "U" is
                // the alphabet midpoint; subsequent seeds at "f" and
                // "p" keep them strictly ascending.
                rank: "U".to_owned(),
                title: "Legal review for public beta".to_owned(),
                description: "Finalize external processor wording before launch checklist can move.".to_owned(),
                description_body: String::new(),
                description_locked: false,
                synthesis: String::new(),
                synthesis_locked: false,
                created_by: "ak:did_core:web:acme.example:users:alice".to_owned(),
                created_at: "2026-05-08T08:00:00.000Z".to_owned(),
                updated_by: String::new(),
                updated_at: String::new(),
                labels: vec!["legal".to_owned(), "beta".to_owned()],
                assignee: "Alice".to_owned(),
                assigned_to_relations: Vec::new(),
                due: "May 08".to_owned(),
                calendar_rsvp: CalendarRsvpDisplay::default(),
                calendar_rsvp_cells: Vec::new(),
                authoring_basis: None,
                calendar_schedule_basis_refs: Vec::new(),
                calendar: CalendarCardFields::default(),
                primary_strand_id: DEMO_STRAND_REVIEW_DISCUSSION_ID.to_owned(),
                locked_strand: Some(LockedStrand {
                    strand_id_hash: "sha256:locked-private-decision".to_owned(),
                reason: "You can see that a restricted discussion is linked, but not its name or members.".to_owned(),
                }),
                external_visibility: "External counsel discussion only".to_owned(),
                history_access: "since joining".to_owned(),
                security_encrypted: None,
                state: CardState::Synced,
                lifecycle: StrandLifecycleState::Active,
            }],
            state: SpaceContainerLifecycleState::Active,
        },
        KanbanColumn {
            id: "ak:space:01list-progress00000000000000".to_owned(),
            title: "In Progress".to_owned(),
            rank: "f".to_owned(),
            cards: vec![KanbanCard {
                id: DEMO_STRAND_ONBOARDING_COPY_ID.to_owned(),
                rank: "U".to_owned(),
                title: "Onboarding copy".to_owned(),
                description: "Waiting on discussion-scoped feedback from support and docs reviewers.".to_owned(),
                description_body: String::new(),
                description_locked: false,
                synthesis: String::new(),
                synthesis_locked: false,
                created_by: "ak:did_core:web:acme.example:users:bob".to_owned(),
                created_at: "2026-05-09T09:00:00.000Z".to_owned(),
                updated_by: String::new(),
                updated_at: String::new(),
                labels: vec!["copy".to_owned(), "support".to_owned()],
                assignee: "Bob".to_owned(),
                assigned_to_relations: Vec::new(),
                due: "May 10".to_owned(),
                calendar_rsvp: CalendarRsvpDisplay::default(),
                calendar_rsvp_cells: Vec::new(),
                authoring_basis: None,
                calendar_schedule_basis_refs: Vec::new(),
                calendar: CalendarCardFields::default(),
                primary_strand_id: DEMO_STRAND_SUPPORT_DISCUSSION_ID.to_owned(),
                locked_strand: None,
                external_visibility: "Board only".to_owned(),
                history_access: "all history for current members".to_owned(),
                security_encrypted: None,
                state: CardState::Queued,
                lifecycle: StrandLifecycleState::Active,
            }],
            state: SpaceContainerLifecycleState::Active,
        },
        KanbanColumn {
            id: "ak:space:01list-done00000000000000000".to_owned(),
            title: "Done".to_owned(),
            rank: "p".to_owned(),
            cards: vec![KanbanCard {
                id: DEMO_STRAND_SECURITY_SIGNOFF_ID.to_owned(),
                rank: "U".to_owned(),
                title: "Security sign-off".to_owned(),
                description: "Projection detected a stale column head after an offline move.".to_owned(),
                description_body: String::new(),
                description_locked: false,
                synthesis: String::new(),
                synthesis_locked: false,
                created_by: "ak:did_core:web:acme.example:users:carol".to_owned(),
                created_at: "2026-05-01T10:00:00.000Z".to_owned(),
                updated_by: String::new(),
                updated_at: String::new(),
                labels: vec!["security".to_owned(), "reviewed".to_owned()],
                assignee: "Carol".to_owned(),
                assigned_to_relations: Vec::new(),
                due: "May 01".to_owned(),
                calendar_rsvp: CalendarRsvpDisplay::default(),
                calendar_rsvp_cells: Vec::new(),
                authoring_basis: None,
                calendar_schedule_basis_refs: Vec::new(),
                calendar: CalendarCardFields::default(),
                primary_strand_id: DEMO_STRAND_SECURITY_REVIEW_ID.to_owned(),
                locked_strand: Some(LockedStrand {
                    strand_id_hash: "sha256:locked-incident-notes".to_owned(),
                    reason: "Incident notes require separate discussion capability.".to_owned(),
                }),
                external_visibility: "Internal discussions only".to_owned(),
                history_access: "since joining".to_owned(),
                security_encrypted: None,
                state: CardState::Conflict,
                lifecycle: StrandLifecycleState::Active,
            }],
            state: SpaceContainerLifecycleState::Active,
        },
    ]
}
