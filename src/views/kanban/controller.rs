use super::*;

#[derive(Clone)]
pub(super) enum KanbanCommand {
    SubmitOperation {
        base_url: String,
        token: Cage<String>,
        realm_id: String,
        operation: Box<crate::operation::LocalOperation>,
        scope_security_encrypted: Option<bool>,
    },
}

#[derive(Clone, Copy)]
pub(super) struct KanbanController {
    pub(super) inventory_owner: Cage<super::projection_reads::SharedInventoryOwner>,
    pub(super) card_edit_context_seen: Cage<CardTrackEditContext>,
    pub(super) suspended_shared_track_edits: Cage<BTreeMap<String, SuspendedTrackEdit>>,
    pub board_space_options: Cage<Vec<BoardSpaceOption>>,
    /// The confirmed Board selection. `None` means "no confirmed Board
    /// selected" — including while a create is still pending; a pending Board
    /// is NEVER represented here, only in the op-log-derived
    /// `PendingBoardCreate` state.
    pub selected_board: Cage<Option<arkret_sdk::SpaceId>>,
    pub lifecycle_container_projection:
        Cage<Vec<crate::state::projection_views::SpaceContainerProjectionView>>,
    pub lifecycle_strand_projection:
        Cage<Vec<crate::state::projection_views::StrandProjectionView>>,
    pub new_board_title: Cage<String>,
    pub new_column_title: Cage<String>,
    pub new_card_title: Cage<String>,
    pub adding_card_to: Cage<Option<String>>,
    pub selected_card: Cage<Option<KanbanCard>>,
    pub mls_sidecar_restore_key_seen: Cage<String>,
    pub board_popover: Cage<BoardToolbarPopover>,
    pub archive_board_confirm_open: Cage<bool>,
    pub list_archive_confirm: Cage<Option<(String, String, usize)>>,
    pub editing_card_detail: Cage<bool>,
    pub card_edit_scope: Cage<CardEditScope>,
    pub card_detail_sidebar_visible: Cage<bool>,
    pub card_detail_actions_open: Cage<bool>,
    pub card_detail_tab: Cage<CardDetailContentTab>,
    pub card_detail_discussion_mounted_for: Cage<Option<String>>,
    pub card_detail_sidebar_tab: Cage<CardDetailSidebarTab>,
    pub card_detail_docked: Cage<bool>,
    pub card_detail_dock_width: Cage<f64>,
    pub card_detail_resizing: Cage<bool>,
    pub card_detail_resize_start_x: Cage<f64>,
    pub card_detail_resize_start_width: Cage<f64>,
    pub member_handle_fetching: Cage<BTreeSet<String>>,
    pub card_edit_title: Cage<String>,
    pub card_edit_description: Cage<String>,
    pub card_edit_body: Cage<String>,
    pub card_edit_synthesis: Cage<String>,
    pub card_edit_synthesis_target_id: Cage<Option<String>>,
    pub card_detail_edit_status: Cage<String>,
    pub assignee_picker_open: Cage<bool>,
    pub assignee_filter: Cage<String>,
    pub assignee_selected_actor_ids: Cage<BTreeSet<arkret_sdk::ActorId>>,
    pub assignee_edit_status: Cage<String>,
    pub due_picker_open: Cage<bool>,
    pub due_edit_value: Cage<String>,
    pub due_calendar_month: Cage<chrono::NaiveDate>,
    pub due_edit_status: Cage<String>,
    pub card_edit_calendar: Cage<CalendarCardFields>,
    pub calendar_rsvp_occurrence: Cage<String>,
    pub card_synthesis_history_open_id: Cage<Option<String>>,
    pub card_synthesis_selected_revision_id: Cage<Option<String>>,
    pub card_edit_labels: Cage<String>,
    pub card_edit_assignee: Cage<String>,
    pub card_edit_due: Cage<String>,
    pub dragging_card: Cage<Option<DraggedCard>>,
    pub dragging_column: Cage<Option<DraggedColumn>>,
    pub drop_target_column: Cage<Option<String>>,
    pub editing_column_id: Cage<Option<String>>,
    pub editing_column_title: Cage<String>,
    pub board_status: Cage<String>,
    pub command_queue: Cage<std::collections::VecDeque<KanbanCommand>>,
}

impl KanbanController {
    pub fn enqueue_operation(
        self,
        base_url: String,
        token: Cage<String>,
        realm_id: String,
        operation: crate::operation::LocalOperation,
        scope_security_encrypted: Option<bool>,
    ) {
        self.command_queue.revise(|queue| {
            queue.push_back(KanbanCommand::SubmitOperation {
                base_url,
                token,
                realm_id,
                operation: Box::new(operation),
                scope_security_encrypted,
            })
        });
    }
}

pub(super) fn new_kanban_controller(
    scope: &Scope,
    route: &Route,
    initial_board_options: Vec<BoardSpaceOption>,
    initial_board: Option<arkret_sdk::SpaceId>,
) -> KanbanController {
    KanbanController {
        inventory_owner: scope.cage(std::rc::Rc::new(std::cell::RefCell::new(
            super::projection_reads::ProjectionReadOwner::default(),
        ))),
        card_edit_context_seen: scope.cage(CardTrackEditContext::default()),
        suspended_shared_track_edits: scope.cage(BTreeMap::new()),
        board_space_options: scope.cage(initial_board_options),
        selected_board: scope.cage(initial_board),
        lifecycle_container_projection: scope.cage(Vec::new()),
        lifecycle_strand_projection: scope.cage(Vec::new()),
        new_board_title: scope.cage("Board".to_owned()),
        new_column_title: scope.cage(String::new()),
        new_card_title: scope.cage(String::new()),
        adding_card_to: scope.cage(None),
        selected_card: scope.cage(None),
        mls_sidecar_restore_key_seen: scope.cage(String::new()),
        board_popover: scope.cage(BoardToolbarPopover::default()),
        archive_board_confirm_open: scope.cage(false),
        list_archive_confirm: scope.cage(None),
        editing_card_detail: scope.cage(false),
        card_edit_scope: scope.cage(CardEditScope::default()),
        card_detail_sidebar_visible: scope.cage(true),
        card_detail_actions_open: scope.cage(false),
        card_detail_tab: scope.cage(card_detail_tab_from_route(route)),
        card_detail_discussion_mounted_for: scope.cage(None),
        card_detail_sidebar_tab: scope.cage(CardDetailSidebarTab::default()),
        card_detail_docked: scope.cage(read_card_detail_docked()),
        card_detail_dock_width: scope.cage(read_card_detail_dock_width()),
        card_detail_resizing: scope.cage(false),
        card_detail_resize_start_x: scope.cage(0.0),
        card_detail_resize_start_width: scope.cage(0.0),
        member_handle_fetching: scope.cage(BTreeSet::new()),
        card_edit_title: scope.cage(String::new()),
        card_edit_description: scope.cage(String::new()),
        card_edit_body: scope.cage(String::new()),
        card_edit_synthesis: scope.cage(String::new()),
        card_edit_synthesis_target_id: scope.cage(None),
        card_detail_edit_status: scope.cage(String::new()),
        assignee_picker_open: scope.cage(false),
        assignee_filter: scope.cage(String::new()),
        assignee_selected_actor_ids: scope.cage(BTreeSet::new()),
        assignee_edit_status: scope.cage(String::new()),
        due_picker_open: scope.cage(false),
        due_edit_value: scope.cage(String::new()),
        due_calendar_month: scope.cage(default_due_calendar_month()),
        due_edit_status: scope.cage(String::new()),
        card_edit_calendar: scope.cage(CalendarCardFields::default()),
        calendar_rsvp_occurrence: scope.cage(String::new()),
        card_synthesis_history_open_id: scope.cage(None),
        card_synthesis_selected_revision_id: scope.cage(None),
        card_edit_labels: scope.cage(String::new()),
        card_edit_assignee: scope.cage(String::new()),
        card_edit_due: scope.cage(String::new()),
        dragging_card: scope.cage(None),
        dragging_column: scope.cage(None),
        drop_target_column: scope.cage(None),
        editing_column_id: scope.cage(None),
        editing_column_title: scope.cage(String::new()),
        board_status: scope.cage(String::new()),
        command_queue: scope.cage(std::collections::VecDeque::new()),
    }
}

impl KanbanController {
    pub(super) fn retire_session(&self) {
        if let Ok(owner) = self.inventory_owner.try_with_untracked(Clone::clone) {
            owner.borrow_mut().set_scope(None);
        }
        let _ = self
            .suspended_shared_track_edits
            .try_revise(|value| value.clear());
        let _ = self
            .card_edit_context_seen
            .try_revise(|value| *value = CardTrackEditContext::default());
        let _ = self.new_board_title.try_revise(String::clear);
        let _ = self.new_column_title.try_revise(String::clear);
        let _ = self.new_card_title.try_revise(String::clear);
        let _ = self.mls_sidecar_restore_key_seen.try_revise(String::clear);
        let _ = self.card_edit_title.try_revise(String::clear);
        let _ = self.card_edit_description.try_revise(String::clear);
        let _ = self.card_edit_body.try_revise(String::clear);
        let _ = self.card_edit_synthesis.try_revise(String::clear);
        let _ = self.card_detail_edit_status.try_revise(String::clear);
        let _ = self.assignee_filter.try_revise(String::clear);
        let _ = self.assignee_edit_status.try_revise(String::clear);
        let _ = self.due_edit_value.try_revise(String::clear);
        let _ = self.due_edit_status.try_revise(String::clear);
        let _ = self.calendar_rsvp_occurrence.try_revise(String::clear);
        let _ = self.card_edit_labels.try_revise(String::clear);
        let _ = self.card_edit_assignee.try_revise(String::clear);
        let _ = self.card_edit_due.try_revise(String::clear);
        let _ = self.editing_column_title.try_revise(String::clear);
        let _ = self.board_status.try_revise(String::clear);
        let _ = self.selected_card.try_revise(|value| *value = None);
        let _ = self
            .card_edit_calendar
            .try_revise(|value| *value = CalendarCardFields::default());
        let _ = self.command_queue.try_revise(|value| value.clear());
    }
}
