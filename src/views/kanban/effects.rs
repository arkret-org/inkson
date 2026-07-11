use super::*;

#[component]
pub(super) fn KanbanEffects(
    controller: KanbanController,
    columns: Memo<Vec<KanbanColumn>>,
    route: Route,
    local_realm_id: String,
) -> Element {
    let state_store = crate::app::SessionContext::get().state_store;
    let KanbanController {
        mut board_space_options,
        mut selected_board_space_id,
        mut lifecycle_container_projection,
        mut lifecycle_strand_projection,
        mut selected_card,
        mut card_edit_title,
        mut card_edit_description,
        mut card_edit_body,
        mut card_edit_synthesis,
        mut card_edit_synthesis_target_id,
        mut card_edit_labels,
        mut card_edit_assignee,
        mut card_edit_due,
        mut card_edit_calendar,
        mut calendar_rsvp_occurrence,
        mut editing_card_detail,
        mut card_detail_edit_status,
        mut assignee_picker_open,
        mut assignee_filter,
        mut assignee_selected_actor_ids,
        mut assignee_edit_status,
        mut due_picker_open,
        mut due_edit_value,
        mut due_calendar_month,
        mut due_edit_status,
        mut card_detail_actions_open,
        mut card_detail_discussion_mounted_for,
        mut card_detail_tab,
        mut card_synthesis_history_open_id,
        mut card_synthesis_selected_revision_id,
        mut command_queue,
        board_status,
        ..
    } = controller;

    {
        let realm = local_realm_id.clone();
        use_effect(move || {
            let raw_operations = state_store.read().load().raw_operations;
            let containers = space_container_views_from_ops(&raw_operations, &realm);
            let strands = strand_views_from_ops(&raw_operations);
            let options = board_space_options_from_projection(&containers);
            if *lifecycle_container_projection.peek() != containers {
                lifecycle_container_projection.set(containers);
            }
            if *lifecycle_strand_projection.peek() != strands {
                lifecycle_strand_projection.set(strands);
            }
            if !options.is_empty() && *board_space_options.peek() != options {
                board_space_options.set(options.clone());
            }
            if selected_board_space_id.peek().trim().is_empty()
                && let Some(first) = options.first()
            {
                selected_board_space_id.set(first.id.clone());
            }
        });
    }

    use_effect(move || {
        let commands = command_queue();
        if commands.is_empty() {
            return;
        }
        command_queue.set(std::collections::VecDeque::new());
        for command in commands {
            match command {
                KanbanCommand::SubmitOperation {
                    base_url,
                    token,
                    realm_id,
                    operation,
                    scope_security_encrypted,
                } => submit_kanban_operation_event(
                    base_url,
                    token,
                    realm_id,
                    operation,
                    scope_security_encrypted,
                    state_store,
                    board_status,
                ),
            }
        }
    });

    use_effect(move || {
        sync_selected_card_from_columns(selected_card, &columns());
    });

    {
        let routed_strand_id = route_card_strand_id(&route);
        use_effect(move || {
            let Some(strand_id) = routed_strand_id.clone() else {
                return;
            };
            if selected_card()
                .as_ref()
                .is_some_and(|card| card_matches_strand_id(card, &strand_id))
            {
                return;
            }
            if let Some(card) = find_card_by_strand_id(&columns.read(), &strand_id) {
                let draft = card_detail_draft_from_card(&card);
                card_edit_title.set(draft.title);
                card_edit_description.set(draft.description);
                card_edit_body.set(draft.body);
                card_edit_synthesis.set(draft.synthesis);
                card_edit_synthesis_target_id.set(None);
                card_edit_labels.set(draft.labels.join(", "));
                card_edit_assignee.set(draft.assignee);
                card_edit_due.set(draft.due);
                let calendar = draft.calendar.clone();
                card_edit_calendar.set(calendar.clone());
                calendar_rsvp_occurrence.set(calendar_occurrence_hint(&calendar));
                editing_card_detail.set(false);
                card_detail_edit_status.set(String::new());
                assignee_picker_open.set(false);
                assignee_filter.set(String::new());
                assignee_selected_actor_ids
                    .set(card_assigned_actor_ids(&card).into_iter().collect());
                assignee_edit_status.set(String::new());
                due_picker_open.set(false);
                due_edit_value.set(editor_value_for_optional_card_field(&card.due));
                due_calendar_month.set(due_calendar_month_for_value(&card.due));
                due_edit_status.set(String::new());
                card_detail_actions_open.set(false);
                let routed_tab = card_detail_tab_from_current_url();
                if routed_tab == CardDetailContentTab::Discussion {
                    card_detail_discussion_mounted_for.set(Some(card.primary_strand_id.clone()));
                }
                card_detail_tab.set(routed_tab);
                card_synthesis_history_open_id.set(None);
                card_synthesis_selected_revision_id.set(None);
                selected_card.set(Some(card));
            }
        });
    }

    {
        let routed_board_id = route_board_id(&route);
        use_effect(move || {
            let Some(board_id) = routed_board_id.clone() else {
                return;
            };
            if selected_board_space_id() != board_id {
                selected_board_space_id.set(board_id);
            }
        });
    }

    {
        let routed_strand_id = route_card_strand_id(&route);
        use_effect(move || {
            let Some(strand_id) = routed_strand_id.clone() else {
                return;
            };
            let raw_operations = state_store.read().load().raw_operations;
            let Some(strand_board) = strand_views_from_ops(&raw_operations)
                .into_iter()
                .find(|view| view.strand_id == strand_id)
                .and_then(|view| view.board_space_id)
            else {
                return;
            };
            if selected_board_space_id() != strand_board {
                selected_board_space_id.set(strand_board);
            }
        });
    }

    rsx! {}
}
