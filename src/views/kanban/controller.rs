use super::*;

#[derive(Clone)]
pub(super) enum KanbanCommand {
    RefreshProjection,
    SubmitOperation {
        base_url: String,
        token: Signal<String>,
        realm_id: String,
        operation: arkret_sdk::Event,
        scope_security_encrypted: Option<bool>,
    },
}

#[derive(Clone, Copy, PartialEq)]
pub(super) struct KanbanController {
    pub board_space_options: Signal<Vec<BoardSpaceOption>>,
    pub selected_board_space_id: Signal<String>,
    pub collection_view_columns: Signal<Option<Vec<KanbanColumn>>>,
    pub board_view_id: Signal<String>,
    pub lifecycle_container_projection:
        Signal<Vec<crate::state::projection_views::SpaceContainerProjectionView>>,
    pub lifecycle_strand_projection:
        Signal<Vec<crate::state::projection_views::StrandProjectionView>>,
    pub projection_source: Signal<BoardProjectionSource>,
    pub new_board_title: Signal<String>,
    pub new_column_title: Signal<String>,
    pub new_card_title: Signal<String>,
    pub adding_card_to: Signal<Option<String>>,
    pub selected_card: Signal<Option<KanbanCard>>,
    pub mls_sidecar_restore_key_seen: Signal<String>,
    pub board_popover: Signal<BoardToolbarPopover>,
    pub archive_board_confirm_open: Signal<bool>,
    pub list_archive_confirm: Signal<Option<(String, String, usize)>>,
    pub editing_card_detail: Signal<bool>,
    pub card_edit_scope: Signal<CardEditScope>,
    pub card_detail_sidebar_visible: Signal<bool>,
    pub card_detail_actions_open: Signal<bool>,
    pub card_detail_tab: Signal<CardDetailContentTab>,
    pub card_detail_discussion_mounted_for: Signal<Option<String>>,
    pub card_detail_sidebar_tab: Signal<CardDetailSidebarTab>,
    pub card_detail_docked: Signal<bool>,
    pub card_detail_dock_width: Signal<f64>,
    pub card_detail_resizing: Signal<bool>,
    pub card_detail_resize_start_x: Signal<f64>,
    pub card_detail_resize_start_width: Signal<f64>,
    pub member_handle_fetching: Signal<BTreeSet<String>>,
    pub card_edit_title: Signal<String>,
    pub card_edit_description: Signal<String>,
    pub card_edit_body: Signal<String>,
    pub card_edit_synthesis: Signal<String>,
    pub card_edit_synthesis_target_id: Signal<Option<String>>,
    pub card_detail_edit_status: Signal<String>,
    pub assignee_picker_open: Signal<bool>,
    pub assignee_filter: Signal<String>,
    pub assignee_selected_actor_ids: Signal<BTreeSet<String>>,
    pub assignee_edit_status: Signal<String>,
    pub due_picker_open: Signal<bool>,
    pub due_edit_value: Signal<String>,
    pub due_calendar_month: Signal<chrono::NaiveDate>,
    pub due_edit_status: Signal<String>,
    pub card_edit_calendar: Signal<CalendarCardFields>,
    pub calendar_rsvp_occurrence: Signal<String>,
    pub card_synthesis_history_open_id: Signal<Option<String>>,
    pub card_synthesis_selected_revision_id: Signal<Option<String>>,
    pub card_edit_labels: Signal<String>,
    pub card_edit_assignee: Signal<String>,
    pub card_edit_due: Signal<String>,
    pub dragging_card: Signal<Option<DraggedCard>>,
    pub dragging_column: Signal<Option<DraggedColumn>>,
    pub drop_target_column: Signal<Option<String>>,
    pub editing_column_id: Signal<Option<String>>,
    pub editing_column_title: Signal<String>,
    pub write_records: Signal<Vec<BoardWriteRecord>>,
    pub board_status: Signal<String>,
    pub command_queue: Signal<std::collections::VecDeque<KanbanCommand>>,
}

impl KanbanController {
    pub fn refresh_projection(mut self) {
        self.command_queue
            .write()
            .push_back(KanbanCommand::RefreshProjection);
    }

    pub fn enqueue_operation(
        mut self,
        base_url: String,
        token: Signal<String>,
        realm_id: String,
        operation: arkret_sdk::Event,
        scope_security_encrypted: Option<bool>,
    ) {
        self.command_queue
            .write()
            .push_back(KanbanCommand::SubmitOperation {
                base_url,
                token,
                realm_id,
                operation,
                scope_security_encrypted,
            });
    }
}

pub(super) fn use_kanban_controller(
    initial_board_options: Vec<BoardSpaceOption>,
    initial_board_space_id: String,
    initial_source: BoardProjectionSource,
    event_write_ready: bool,
) -> KanbanController {
    KanbanController {
        board_space_options: use_signal(move || initial_board_options),
        selected_board_space_id: use_signal(move || initial_board_space_id),
        collection_view_columns: use_signal(|| None),
        board_view_id: use_signal(String::new),
        lifecycle_container_projection: use_signal(Vec::new),
        lifecycle_strand_projection: use_signal(Vec::new),
        projection_source: use_signal(|| initial_source),
        new_board_title: use_signal(|| "Board".to_owned()),
        new_column_title: use_signal(String::new),
        new_card_title: use_signal(String::new),
        adding_card_to: use_signal(|| None),
        selected_card: use_signal(|| None),
        mls_sidecar_restore_key_seen: use_signal(String::new),
        board_popover: use_signal(BoardToolbarPopover::default),
        archive_board_confirm_open: use_signal(|| false),
        list_archive_confirm: use_signal(|| None),
        editing_card_detail: use_signal(|| false),
        card_edit_scope: use_signal(CardEditScope::default),
        card_detail_sidebar_visible: use_signal(|| true),
        card_detail_actions_open: use_signal(|| false),
        card_detail_tab: use_signal(card_detail_tab_from_current_url),
        card_detail_discussion_mounted_for: use_signal(|| None),
        card_detail_sidebar_tab: use_signal(CardDetailSidebarTab::default),
        card_detail_docked: use_signal(read_card_detail_docked),
        card_detail_dock_width: use_signal(read_card_detail_dock_width),
        card_detail_resizing: use_signal(|| false),
        card_detail_resize_start_x: use_signal(|| 0.0),
        card_detail_resize_start_width: use_signal(|| 0.0),
        member_handle_fetching: use_signal(BTreeSet::new),
        card_edit_title: use_signal(String::new),
        card_edit_description: use_signal(String::new),
        card_edit_body: use_signal(String::new),
        card_edit_synthesis: use_signal(String::new),
        card_edit_synthesis_target_id: use_signal(|| None),
        card_detail_edit_status: use_signal(String::new),
        assignee_picker_open: use_signal(|| false),
        assignee_filter: use_signal(String::new),
        assignee_selected_actor_ids: use_signal(BTreeSet::new),
        assignee_edit_status: use_signal(String::new),
        due_picker_open: use_signal(|| false),
        due_edit_value: use_signal(String::new),
        due_calendar_month: use_signal(default_due_calendar_month),
        due_edit_status: use_signal(String::new),
        card_edit_calendar: use_signal(CalendarCardFields::default),
        calendar_rsvp_occurrence: use_signal(String::new),
        card_synthesis_history_open_id: use_signal(|| None),
        card_synthesis_selected_revision_id: use_signal(|| None),
        card_edit_labels: use_signal(String::new),
        card_edit_assignee: use_signal(String::new),
        card_edit_due: use_signal(String::new),
        dragging_card: use_signal(|| None),
        dragging_column: use_signal(|| None),
        drop_target_column: use_signal(|| None),
        editing_column_id: use_signal(|| None),
        editing_column_title: use_signal(String::new),
        write_records: use_signal(Vec::new),
        board_status: use_signal(move || {
            if initial_source == BoardProjectionSource::Unavailable {
                "Board data unavailable; sample fallback disabled for this server".to_owned()
            } else if event_write_ready {
                "Event write plane ready".to_owned()
            } else {
                "Event write plane unavailable; board writes queue locally".to_owned()
            }
        }),
        command_queue: use_signal(std::collections::VecDeque::new),
    }
}
