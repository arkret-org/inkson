use super::*;
use crate::presentation::widgets::reactive_distinct;
fn disclosure(
    scope: &Scope,
    _app: Rc<InksonContext>,
    key: &str,
    label: String,
    open: bool,
    children: Rc<dyn Fn(&Scope) -> View>,
) -> View {
    let expanded = scope.cage(open);
    let body = reactive(
        expanded,
        move |scope, open| if open { children(scope) } else { empty() },
    );
    stack(
        format!("event board-maintenance {key}"),
        vec![
            Box::new(
                sapid::button()
                    .unstyled()
                    .class("board-maintenance-summary")
                    .label(label)
                    .on_press(move || expanded.revise(|value| *value = !*value)),
            ),
            body,
        ],
    )
}
fn board_allowed(scope: &Scope, board: Board) -> View {
    let app = board.app.clone();
    let c = board.controller;
    let title = {
        let board = board.clone();
        scope.bond(move || {
            let _ = board.app.state_revision.get();
            let pending = board.app.state_store.read(|store| {
                pending_board_creates_from_ops(&store.load().raw_operations, &board.local_realm)
            });
            let selected = c.selected_board.get();
            let header = board_header(selected.as_ref(), &c.board_space_options.get(), pending);
            kanban_title_label(
                &header.title,
                selected.as_ref().map_or("", arkret_sdk::SpaceId::as_str),
                &crate::i18n::tr("kanban.title_pending"),
            )
        })
    };
    let switch_name = app.translated(scope, "kanban.ui.switch_board");
    let make_switch = move || {
        glory::ui::button()
            .class("board-select-button board-space-select-button")
            .name(switch_name)
            .fill(vec![
                crate::components::ui_icon("board"),
                super::card_detail_surface::inline_label("board-select-button-label", title),
                crate::components::ui_icon("chevron-down"),
            ])
            .on(glory::render::EventKind::Activate, move |_| {
                c.board_popover.revise(|value| {
                    *value = if *value == BoardToolbarPopover::SelectBoard {
                        BoardToolbarPopover::None
                    } else {
                        BoardToolbarPopover::SelectBoard
                    }
                })
            })
    };
    #[cfg(target_arch = "wasm32")]
    let switch: View = {
        let locale = app.locale;
        let hint = scope.bond(move || {
            let _ = locale.get();
            crate::i18n::tr_args("kanban.ui.switch_board_title", &[("title", title.get())])
        });
        Box::new(
            sapid::tooltip("kanban-board-switch-hint")
                .label(switch_name)
                .text(hint)
                .target(move |target| target.button(make_switch())),
        )
    };
    #[cfg(not(target_arch = "wasm32"))]
    let switch: View = Box::new(make_switch());
    let popover = {
        let board = board.clone();
        reactive(c.board_popover, move |scope, popover| match popover {
            BoardToolbarPopover::None => empty(),
            BoardToolbarPopover::SelectBoard => {
                let revision = board.app.state_revision;
                let source = scope.bond(move || (c.board_space_options.get(), revision.get()));
                let board = board.clone();
                reactive(source, move |scope, (options, _revision)| {
                    let mut rows = vec![Box::new(
                        sapid::button()
                            .unstyled()
                            .class(scope.bond(move || {
                                if c.selected_board.get().is_none() {
                                    "secondary board-select-menu-item is-active"
                                } else {
                                    "secondary board-select-menu-item"
                                }
                                .to_owned()
                            }))
                            .name(crate::i18n::tr("kanban.ui.select_board"))
                            .fill(vec![
                                crate::components::ui_icon("board"),
                                plain(crate::i18n::tr("kanban.ui.select_board")),
                            ])
                            .on_press({
                                let board = board.clone();
                                move || board.select(None)
                            }),
                    ) as View];
                    rows.extend(options.into_iter().map(|option| {
                        let board = board.clone();
                        let label = kanban_title_label(
                            &option.title,
                            option.id.as_str(),
                            &crate::i18n::tr("kanban.title_pending"),
                        );
                        let selected = option.id.clone();
                        Box::new(
                            sapid::button()
                                .unstyled()
                                .class(scope.bond(move || {
                                    if c.selected_board.get().as_ref() == Some(&selected) {
                                        "secondary board-select-menu-item is-active"
                                    } else {
                                        "secondary board-select-menu-item"
                                    }
                                    .to_owned()
                                }))
                                .name(label.clone())
                                .fill(vec![crate::components::ui_icon("board"), plain(label)])
                                .on_press(move || board.select(Some(option.id.clone()))),
                        ) as View
                    }));
                    let pending = board.app.state_store.read(|store| {
                        pending_board_creates_from_ops(
                            &store.load().raw_operations,
                            &board.local_realm,
                        )
                    });
                    for pending in pending {
                        let retry = board.clone();
                        let ready = board.ready;
                        let retryable = pending.is_retryable();
                        let operation_id = pending.operation_id.clone();
                        let label = format!("{} ({})", pending.title, pending.status_hint());
                        rows.push(Box::new(
                            sapid::button()
                                .unstyled()
                                .class("secondary board-select-menu-item board-create-pending")
                                .enabled(scope.bond(move || retryable && ready.get()))
                                .name(label.clone())
                                .fill(vec![crate::components::ui_icon("board"), plain(label)])
                                .on_press(move || retry.retry_board(operation_id.clone())),
                        ));
                    }
                    stack("board-select-menu-panel", rows)
                })
            }
            BoardToolbarPopover::CreateBoard => empty(),
        })
    };
    let add_list = {
        let board = board.clone();
        let active = scope.bond({
            let board = board.clone();
            move || {
                let _ = board.app.state_revision.get();
                c.selected_board.get().is_some()
                    || board.app.state_store.read(|store| {
                        !pending_board_creates_from_ops(
                            &store.load().raw_operations,
                            &board.local_realm,
                        )
                        .is_empty()
                    })
            }
        });
        reactive_distinct(active, move |scope, selected| {
            if selected {
                let board = board.clone();
                let write_ready = board.ready;
                let add_list_ready =
                    scope.bond(move || write_ready.get() && c.selected_board.get().is_some());
                line(
                    "actions board-list-compose board-add-list",
                    vec![
                        crate::views::settings::widgets::input_prompt(
                            scope,
                            board
                                .app
                                .translated(scope, "kanban.ui.new_list_title")
                                .into(),
                            c.new_column_title,
                            Box::new(
                                sapid::text_field()
                                    .unstyled()
                                    .class("input new-column-input")
                                    .name(board.app.translated(scope, "kanban.ui.new_list_title"))
                                    .value(c.new_column_title)
                                    .enabled(board.ready)
                                    .on_value_change(move |next| {
                                        c.new_column_title.revise(|value| *value = next)
                                    }),
                            ),
                        ),
                        action(
                            scope,
                            board.app.clone(),
                            "add-column-button",
                            "kanban.add_list",
                            "secondary btn",
                            add_list_ready,
                            move || board.add_column(),
                        ),
                    ],
                )
            } else {
                empty()
            }
        })
    };
    let create_toggle = action(
        scope,
        app.clone(),
        "new-board-toggle",
        "kanban.ui.new_board",
        "secondary btn board-popover-trigger",
        true,
        move || {
            c.board_popover.revise(|value| {
                *value = if *value == BoardToolbarPopover::CreateBoard {
                    BoardToolbarPopover::None
                } else {
                    BoardToolbarPopover::CreateBoard
                }
            })
        },
    );
    let create_panel = {
        let board = board.clone();
        reactive(c.board_popover, move |scope, open| {
            if open != BoardToolbarPopover::CreateBoard {
                return empty();
            }
            let create = board.clone();
            stack(
                "board-popover-panel board-create-popover",
                vec![
                    input_prompt(
                        scope,
                        board.app.translated(scope, "kanban.ui.board_title").into(),
                        c.new_board_title,
                        input(
                            scope,
                            board.app.clone(),
                            "new-board-title-input",
                            "kanban.ui.board_title",
                            c.new_board_title,
                            true,
                        ),
                    ),
                    action(
                        scope,
                        board.app.clone(),
                        "create-board-space-button",
                        "kanban.ui.create_board",
                        "primary",
                        board.ready,
                        move || create.create_board(),
                    ),
                ],
            )
        })
    };
    let scrim = reactive(c.board_popover, move |_, open| {
        if open == BoardToolbarPopover::None {
            return empty();
        }
        Box::new(
            sapid::button()
                .unstyled()
                .class("board-popover-scrim")
                .name(crate::i18n::tr("common.close"))
                .on_press(move || {
                    c.board_popover
                        .revise(|value| *value = BoardToolbarPopover::None)
                }),
        )
    });
    let archive = action(
        scope,
        app.clone(),
        "archive-board-button",
        "kanban.archive_board_action",
        "secondary btn board-archive-board",
        {
            let ready = board.ready;
            scope.bond(move || ready.get() && c.selected_board.get().is_some())
        },
        move || c.archive_board_confirm_open.revise(|value| *value = true),
    );
    let header = stack(
        "event board-header board-toolbar",
        vec![line(
            "board-toolbar-main",
            vec![
                line(
                    "actions board-toolbar-controls board-space-selector",
                    vec![
                        super::card_detail_surface::inline_label(
                            "board-select-label",
                            app.translated(scope, "kanban.board_header"),
                        ),
                        Box::new(
                            glory::ui::view()
                                .class(scope.bond(move || {
                                    if c.board_popover.get() == BoardToolbarPopover::SelectBoard {
                                        "board-select-menu-host is-open"
                                    } else {
                                        "board-select-menu-host"
                                    }
                                    .to_owned()
                                }))
                                .fill(vec![switch, popover]),
                        ),
                        add_list,
                    ],
                ),
                line(
                    "actions board-toolbar-actions",
                    vec![
                        archive,
                        Box::new(
                            glory::ui::view()
                                .class(scope.bond(move || {
                                    if c.board_popover.get() == BoardToolbarPopover::CreateBoard {
                                        "board-popover-host is-open"
                                    } else {
                                        "board-popover-host"
                                    }
                                    .to_owned()
                                }))
                                .fill(vec![create_toggle, create_panel]),
                        ),
                    ],
                ),
            ],
        )],
    );
    let status = {
        let board = board.clone();
        scope.bond(move || {
            board.app.state_store.read(|store| {
                kanban_operation_status_text(&c.board_status.get(), &store.load().raw_operations)
            })
        })
    };
    let grid = board_grid(scope, board.clone());
    let maintenance = maintenance(scope, board.clone());
    let dialogs = dialogs(scope, board.clone());
    let detail = card_detail(
        scope,
        board.app.clone(),
        c,
        CardDetailContext {
            principal_id: board.principal.clone(),
            authority: board.authority.clone(),
            device_id: board.device.clone(),
            selected_realm_id: board.realm.clone(),
            projection_realm_id: board.projection_realm.clone(),
            synthesis_entries: board.synthesis,
            selected_scope_security_encrypted: board.security,
        },
    );
    stack(
        "timeline kanban-panel",
        vec![
            scrim,
            header,
            paragraph("muted board-status", status),
            grid,
            maintenance,
            dialogs,
            detail,
        ],
    )
}
pub(super) fn board_surface(scope: &Scope, board: Board) -> View {
    let app = board.app.clone();
    let realm = board.realm.clone();
    let allowed = {
        let app = app.clone();
        let realm = realm.clone();
        scope.bond(move || {
            app.state_store
                .read(|store| store.realm_allows_spaces(&realm))
        })
    };
    crate::presentation::widgets::reactive_distinct(allowed, move |scope, allowed| {
        if allowed {
            board_allowed(scope, board.clone())
        } else {
            let app = app.clone();
            let realm = realm.clone();
            stack(
                "timeline kanban-panel direct-conversation-board-unavailable",
                vec![
                    paragraph(
                        "",
                        app.translated(scope, "kanban.direct_conversation_unavailable"),
                    ),
                    action(
                        scope,
                        app.clone(),
                        "kanban-open-conversation",
                        "kanban.ui.discussion",
                        "secondary",
                        true,
                        move || {
                            app.navigate(Route::Chat {
                                realm_id: realm.clone(),
                                message: String::new(),
                            })
                        },
                    ),
                ],
            )
        }
    })
}

fn board_grid(scope: &Scope, board: Board) -> View {
    let columns = board.columns;
    let current = board.page;
    let selected = board.controller.selected_card;
    let page_state = scope
        .bond(move || card_current_page(&columns.get(), current.get(), selected.get().as_ref()));
    let pages = {
        let board = board.clone();
        reactive(page_state, move |scope, (_, count)| {
            if count <= 1 {
                return empty();
            }
            let page = board.page;
            line(
                "actions kanban-card-pages",
                vec![
                    action(
                        scope,
                        board.app.clone(),
                        "kanban-previous-page",
                        "kanban.ui.previous_cards",
                        "secondary",
                        scope.bond(move || page.get() > 0),
                        move || page.revise(|value| *value = value.saturating_sub(1)),
                    ),
                    paragraph(
                        "",
                        scope.bond(move || {
                            crate::i18n::tr_args(
                                "kanban.ui.card_page",
                                &[
                                    ("page", (page.get().min(count - 1) + 1).to_string()),
                                    ("total", count.to_string()),
                                ],
                            )
                        }),
                    ),
                    action(
                        scope,
                        board.app.clone(),
                        "kanban-next-page",
                        "kanban.ui.next_cards",
                        "secondary",
                        scope.bond(move || page.get() < count - 1),
                        move || page.revise(|value| *value += 1),
                    ),
                ],
            )
        })
    };
    let source = scope.bond({
        let board = board.clone();
        move || {
            let _ = board.app.state_revision.get();
            let has_board_surface = board.controller.selected_board.get().is_some()
                || board.app.state_store.read(|store| {
                    !pending_board_creates_from_ops(
                        &store.load().raw_operations,
                        &board.local_realm,
                    )
                    .is_empty()
                });
            (columns.get(), page_state.get().0, has_board_surface)
        }
    });
    let grid = {
        let board = board.clone();
        crate::presentation::widgets::reactive_distinct(
            source,
            move |scope, (columns, ids, has_board_surface)| {
                let ids = ids
                    .into_iter()
                    .map(|id| id.to_string())
                    .collect::<BTreeSet<_>>();
                let active = columns
                    .into_iter()
                    .filter(|column| column.state == SpaceContainerLifecycleState::Active)
                    .collect::<Vec<_>>();
                if active.is_empty() {
                    let selected = has_board_surface;
                    return stack(
                        "board-grid kanban-board-grid",
                        vec![stack(
                            "board-empty-state",
                            vec![crate::components::empty_state(
                            scope,
                            board.app.clone(),
                            crate::components::EmptyStateProps {
                                title: crate::i18n::tr(if selected {
                                    "kanban.ui.no_lists_yet"
                                } else {
                                    "kanban.ui.no_board_selected"
                                }),
                                kind: crate::components::EmptyStateKind::Empty,
                                message: Some(
                                    if selected {
                                        "Add a list before adding cards to this board."
                                    } else {
                                        "Create or select a board before adding lists and cards."
                                    }
                                    .into(),
                                ),
                                badge_override: Some(
                                    if selected {
                                        "empty board"
                                    } else {
                                        "select board"
                                    }
                                    .into(),
                                ),
                                test_id: Some("kanban-empty-board".into()),
                            },
                        )],
                        )],
                    );
                }
                let drag = drag_surface::BoardDrag::new(scope, board.clone());
                let children = active
                    .into_iter()
                    .map(|column| column_view(scope, board.clone(), column, &ids, drag.clone()))
                    .collect::<Vec<_>>();
                let controller = board.controller;
                Box::new(
                    glory::prelude::view()
                        .class(scope.bond(move || {
                            format!(
                                "board-grid kanban-board-grid{}{}",
                                if controller.dragging_card.get().is_some() {
                                    " is-dragging"
                                } else {
                                    ""
                                },
                                if controller.dragging_column.get().is_some() {
                                    " is-column-dragging"
                                } else {
                                    ""
                                }
                            )
                        }))
                        .fill(children),
                )
            },
        )
    };
    stack("kanban-board-container", vec![pages, grid])
}
fn column_view(
    scope: &Scope,
    board: Board,
    column: KanbanColumn,
    ids: &BTreeSet<String>,
    drag: Rc<drag_surface::BoardDrag>,
) -> View {
    let c = board.controller;
    let column_id = column.id.clone();
    let title = kanban_title_label(
        &column.title,
        &column.id,
        &crate::i18n::tr("kanban.title_pending"),
    );
    let node = scope.cage(None);
    drag.column(node, &column);
    let grip = {
        let drag = drag.clone();
        let column_id = column.id.clone();
        Box::new(
            glory::prelude::view()
                .class("column-drag-handle")
                .name(format!("Move list {title}"))
                .semantics(Some(Box::new(glory::render::Semantics {
                    drag_capture: Some(glory::render::DragCapture::Press),
                    ..Default::default()
                })))
                .fill(plain("::"))
                .on(glory::render::EventKind::Drag, move |event| {
                    drag.event(
                        event,
                        drag_surface::DragSubject::Column(DraggedColumn {
                            column_id: column_id.clone(),
                        }),
                    )
                }),
        ) as View
    };
    let title_view = {
        let board = board.clone();
        let column = column.clone();
        reactive(c.editing_column_id, move |_scope, editing| {
            if editing.as_deref() == Some(column.id.as_str()) {
                let rename = board.clone();
                let saved = column.clone();
                Box::new(
                    sapid::text_field()
                        .unstyled()
                        .class("entity-title column-rename-input")
                        .value(c.editing_column_title)
                        .on_value_change(move |next| {
                            c.editing_column_title.revise(|value| *value = next)
                        })
                        .on_commit(move |_| rename.rename_column(&saved)),
                )
            } else {
                let title = kanban_title_label(
                    &column.title,
                    &column.id,
                    &crate::i18n::tr("kanban.title_pending"),
                );
                let column = column.clone();
                Box::new(
                    sapid::button()
                        .unstyled()
                        .class("entity-title kanban-column-title")
                        .label(title)
                        .enabled(board.ready)
                        .on_press(move || {
                            c.editing_column_title
                                .revise(|value| *value = column.title.clone());
                            c.editing_column_id
                                .revise(|value| *value = Some(column.id.clone()));
                        }),
                )
            }
        })
    };
    let active = column
        .cards
        .iter()
        .filter(|card| card.lifecycle == StrandLifecycleState::Active)
        .cloned()
        .collect::<Vec<_>>();
    let mut body = vec![line(
        "event-head board-column-head",
        vec![
            line("board-column-title", vec![grip, title_view]),
            paragraph("badge", active.len().to_string()),
        ],
    )];
    let mut previous = None;
    for card in active {
        let rank = card.rank.clone();
        if ids.contains(&card.id) {
            body.push(card_tile(
                scope,
                board.clone(),
                &column,
                card,
                previous.clone(),
                drag.clone(),
            ));
        }
        previous = Some(rank);
    }
    for card in column
        .cards
        .iter()
        .filter(|card| card.lifecycle == StrandLifecycleState::Redacted)
    {
        body.push(stack(
            "board-card board-card-redacted",
            vec![
                crate::components::ui_icon("eye-off"),
                paragraph(
                    "board-card-redacted-label",
                    crate::i18n::tr("Redacted card"),
                ),
                paragraph("muted", short_protocol_id(&card.id)),
            ],
        ));
    }
    let composer = {
        let board = board.clone();
        let column = column.clone();
        reactive(c.adding_card_to, move |scope, adding| {
            if adding.as_deref() != Some(column.id.as_str()) {
                let column_id = column.id.clone();
                return action(
                    scope,
                    board.app.clone(),
                    "add-card-button",
                    "kanban.add_card",
                    "secondary board-add-card",
                    board.ready,
                    move || {
                        c.adding_card_to
                            .revise(|value| *value = Some(column_id.clone()))
                    },
                );
            }
            let save = board.clone();
            let column = column.clone();
            stack(
                "board-card-composer",
                vec![
                    stack(
                        "board-card-composer-card",
                        vec![crate::views::settings::widgets::input_prompt(
                            scope,
                            board.app.translated(scope, "kanban.ui.card_title").into(),
                            c.new_card_title,
                            Box::new(
                                sapid::text_field()
                                    .unstyled()
                                    .class("board-card-composer-input new-card-title-input")
                                    .name(crate::i18n::tr("kanban.ui.card_title"))
                                    .value(c.new_card_title)
                                    .multiline(true)
                                    .on_value_change(move |next| {
                                        if next.chars().count() <= 512 {
                                            c.new_card_title.revise(|value| *value = next);
                                        }
                                    }),
                            ),
                        )],
                    ),
                    line(
                        "board-card-composer-actions",
                        vec![
                            action(
                                scope,
                                board.app.clone(),
                                "save-card-button",
                                "kanban.ui.save_card",
                                "primary board-card-composer-save",
                                board.ready,
                                move || save.create_card(column.clone()),
                            ),
                            action(
                                scope,
                                board.app.clone(),
                                "cancel-card-composer",
                                "common.cancel",
                                "secondary",
                                true,
                                move || {
                                    c.adding_card_to.revise(|value| *value = None);
                                    c.new_card_title.revise(|value| value.clear());
                                },
                            ),
                        ],
                    ),
                ],
            )
        })
    };
    body.push(composer);
    let id = column.id.clone();
    let name = column.title.clone();
    let count = column
        .cards
        .iter()
        .filter(|card| card.lifecycle == StrandLifecycleState::Active)
        .count();
    body.push(action(
        scope,
        board.app.clone(),
        "list-archive-button",
        "kanban.archive_action",
        "secondary kanban-inline-action",
        board.ready,
        move || {
            c.list_archive_confirm
                .revise(|value| *value = Some((id.clone(), name.clone(), count)))
        },
    ));
    let drag_column_id = column.id.clone();
    Box::new(
        glory::prelude::view()
            .class(scope.bond(move || {
                format!(
                    "event board-column kanban-column{}{}",
                    if c.dragging_card.get().is_some() || c.dragging_column.get().is_some() {
                        " drop-zone-available"
                    } else {
                        ""
                    },
                    if c.drop_target_column.get().as_deref() == Some(column_id.as_str()) {
                        " is-drop-target"
                    } else {
                        ""
                    }
                )
            }))
            .node_ref(node)
            .on(glory::render::EventKind::Drag, move |event| {
                drag.event(
                    event,
                    drag_surface::DragSubject::Column(DraggedColumn {
                        column_id: drag_column_id.clone(),
                    }),
                );
            })
            .fill(body),
    )
}
fn card_tile(
    scope: &Scope,
    board: Board,
    column: &KanbanColumn,
    card: KanbanCard,
    previous: Option<String>,
    drag: Rc<drag_surface::BoardDrag>,
) -> View {
    let c = board.controller;
    let node = scope.cage(None);
    drag.card(node, &column.id, previous, &card);
    let snapshot = DraggedCard {
        card_id: card.id.clone(),
        from_column_id: column.id.clone(),
        from_rank: card.rank.clone(),
    };
    let grip_drag = drag.clone();
    let grip_snapshot = snapshot.clone();
    let grip = Box::new(
        glory::prelude::view()
            .class("board-card-drag-handle")
            .name(format!("Move task {}", card.title))
            .semantics(Some(Box::new(glory::render::Semantics {
                drag_capture: Some(glory::render::DragCapture::Press),
                ..Default::default()
            })))
            .fill(crate::components::ui_icon("grip-vertical"))
            .on(glory::render::EventKind::Drag, move |event| {
                grip_drag.event(
                    event,
                    drag_surface::DragSubject::Card(grip_snapshot.clone()),
                )
            }),
    ) as View;
    let title = kanban_title_label(
        &card.title,
        &card.id,
        &crate::i18n::tr("kanban.title_pending"),
    );
    let open = board.clone();
    let shown = card.clone();
    let mut head = vec![Box::new(
        glory::ui::text()
            .class("entity-title board-card-title")
            .content(title.clone()),
    ) as View];
    if !card.state.is_settled() {
        head.push(super::card_detail_surface::inline_label(
            "badge blue board-card-draft-badge kanban-card-draft-badge",
            crate::i18n::tr("kanban.card.draft"),
        ));
    }
    let mut children = vec![line("event-head board-card-title-row", head)];
    if !card.labels.is_empty() {
        children.push(line(
            "actions board-card-labels",
            card.labels
                .iter()
                .map(|label| super::card_detail_surface::inline_label("badge", label.clone()))
                .collect(),
        ));
    }
    if !card.description.trim().is_empty() {
        children.push(paragraph(
            "muted board-card-description",
            card.description.clone(),
        ));
    }
    let mut meta = vec![];
    if !card.assignee.trim().is_empty() && card.assignee.trim() != "—" {
        meta.push(super::card_detail_surface::inline_label(
            "board-card-meta-item kanban-card-assignee",
            format!("assignees {}", card.assignee),
        ));
    }
    if !card.due.trim().is_empty()
        && card.due.trim() != "—"
        && !card.due.eq_ignore_ascii_case("unscheduled")
    {
        let overdue = due_value_is_overdue(&card.due);
        meta.push(super::card_detail_surface::inline_label(
            if overdue {
                "board-card-meta-item board-card-due-overdue kanban-card-due"
            } else {
                "board-card-meta-item kanban-card-due"
            },
            format!("due {}", card.due),
        ));
        if overdue {
            meta.push(super::card_detail_surface::inline_label(
                "badge danger board-card-overdue-badge kanban-card-overdue-badge",
                "overdue",
            ));
        }
    }
    if !meta.is_empty() {
        children.push(line("card-meta board-card-meta", meta));
    }
    let archive = board.clone();
    let archived = card.clone();
    let settled = card.state.is_settled();
    children.push(line(
        "board-card-footer",
        vec![
            action(
                scope,
                board.app.clone(),
                "card-archive-button",
                "kanban.ui.archive_this_card_ak_strand_archive",
                "secondary kanban-inline-action",
                settled,
                move || archive.lifecycle_card(&archived, StrandLifecycleState::Archived),
            ),
            crate::components::write_state::write_state_badge(
                scope,
                board.app.clone(),
                crate::components::WriteStateBadgeProps {
                    state: card.state.write_state(),
                    icon_only: Some(true),
                },
            ),
            grip,
        ],
    ));
    let id = card.id.clone();
    let keyboard_open = board.clone();
    let keyboard_card = card.clone();
    Box::new(
        glory::prelude::view()
            .class(scope.bond(move || {
                format!(
                    "event board-card kanban-card{}{}",
                    if c.dragging_card
                        .get()
                        .as_ref()
                        .is_some_and(|drag| drag.card_id == id)
                    {
                        " dragging-source"
                    } else {
                        ""
                    },
                    if settled { "" } else { " is-draft" }
                )
            }))
            .node_ref(node)
            .role(glory::render::Role::Group)
            .name(title)
            .focus(glory::render::FocusMode::TabStop)
            .on(glory::render::EventKind::Activate, move |_| {
                open.open_card(shown.clone())
            })
            .on(glory::render::EventKind::Keyboard, move |event| {
                if let glory::render::Event::Keyboard {
                    from,
                    command: glory::render::KeyboardCommand::Submit,
                } = event
                    && node.get_untracked() == Some(from)
                {
                    keyboard_open.open_card(keyboard_card.clone());
                }
            })
            .on(glory::render::EventKind::Drag, move |event| {
                drag.event(event, drag_surface::DragSubject::Card(snapshot.clone()))
            })
            .fill(children),
    )
}

fn maintenance(_scope: &Scope, board: Board) -> View {
    let columns = board.columns;
    reactive(columns, move |scope, columns| {
        let mut sections = vec![];
        let unavailable = columns
            .iter()
            .flat_map(|column| column.cards.iter())
            .filter(|card| card.lifecycle == StrandLifecycleState::Unavailable)
            .cloned()
            .collect::<Vec<_>>();
        if !unavailable.is_empty() {
            let app = board.app.clone();
            sections.push(disclosure(
                scope,
                app.clone(),
                "kanban-lifecycle-unavailable",
                crate::i18n::tr("kanban.ui.canonical_lifecycle_state_is_unavailable"),
                true,
                Rc::new(move |_| {
                    stack(
                        "kanban-lifecycle-unavailable-list",
                        unavailable
                            .iter()
                            .map(|card| {
                                stack(
                                    "event kanban-lifecycle-unavailable-row",
                                    vec![
                                        plain(card.title.clone()),
                                        paragraph(
                                            "muted",
                                            crate::i18n::tr("kanban.ui.refresh_to_retry"),
                                        ),
                                    ],
                                )
                            })
                            .collect(),
                    )
                }),
            ));
        }
        let positions = columns
            .iter()
            .filter(|column| column.state == SpaceContainerLifecycleState::PositionUnavailable)
            .flat_map(|column| column.cards.iter().cloned())
            .collect::<Vec<_>>();
        if !positions.is_empty() {
            sections.push(disclosure(
                scope,
                board.app.clone(),
                "kanban-position-unavailable",
                crate::i18n::tr("kanban.ui.canonical_position_is_unavailable"),
                true,
                Rc::new(move |_| {
                    stack(
                        "",
                        positions
                            .iter()
                            .map(|card| {
                                stack(
                                    "event kanban-position-unavailable-row",
                                    vec![
                                        plain(card.title.clone()),
                                        paragraph(
                                            "muted",
                                            crate::i18n::tr("kanban.ui.refresh_to_retry"),
                                        ),
                                    ],
                                )
                            })
                            .collect(),
                    )
                }),
            ));
        }
        let conflicts = columns
            .iter()
            .filter(|column| column.state == SpaceContainerLifecycleState::Unavailable)
            .cloned()
            .collect::<Vec<_>>();
        if !conflicts.is_empty() {
            sections.push(disclosure(scope,board.app.clone(),"kanban-space-conflicts",crate::i18n::tr_args("kanban.ui.unavailable_lists",&[("count",conflicts.len().to_string())]),true,Rc::new(move|_|stack("",conflicts.iter().map(|column|stack("event",vec![paragraph("entity-title",column.id.clone()),plain(crate::i18n::tr("kanban.ui.canonical_space_state_is_unavailable_refresh_to_retry"))])).collect()))));
        }
        let lists = columns
            .iter()
            .filter(|column| column.state == SpaceContainerLifecycleState::Archived)
            .cloned()
            .collect::<Vec<_>>();
        let count = lists.len();
        let st = board.clone();
        sections.push(disclosure(
            scope,
            board.app.clone(),
            "kanban-archived-lists",
            format!(
                "{} ({count})",
                crate::i18n::tr("kanban.archived_lists_header")
            ),
            false,
            Rc::new(move |scope| {
                if lists.is_empty() {
                    return paragraph("muted", crate::i18n::tr("kanban.archived_lists_empty"));
                }
                stack(
                    "",
                    lists
                        .iter()
                        .map(|column| {
                            let restored = column.clone();
                            let st = st.clone();
                            stack(
                                "event kanban-archived-list-row",
                                vec![
                                    line(
                                        "event-head",
                                        vec![
                                            paragraph("entity-title", column.title.clone()),
                                            plain(crate::i18n::tr_args(
                                                "kanban.ui.list_card_count",
                                                &[
                                                    ("rank", column.rank.clone()),
                                                    ("count", column.cards.len().to_string()),
                                                ],
                                            )),
                                        ],
                                    ),
                                    action(
                                        scope,
                                        st.app.clone(),
                                        "list-restore-button",
                                        "kanban.restore_action",
                                        "secondary",
                                        true,
                                        move || st.restore_list(&restored),
                                    ),
                                ],
                            )
                        })
                        .collect(),
                )
            }),
        ));
        let cards = columns
            .iter()
            .flat_map(|column| {
                column
                    .cards
                    .iter()
                    .filter(|card| card.lifecycle == StrandLifecycleState::Archived)
                    .cloned()
                    .map(move |card| (column.title.clone(), card))
            })
            .collect::<Vec<_>>();
        let count = cards.len();
        let st = board.clone();
        sections.push(disclosure(
            scope,
            board.app.clone(),
            "kanban-archived-cards",
            format!(
                "{} ({count})",
                crate::i18n::tr("kanban.archived_cards_header")
            ),
            count > 0,
            Rc::new(move |scope| {
                if cards.is_empty() {
                    return paragraph("muted", crate::i18n::tr("kanban.archived_cards_empty"));
                }
                stack(
                    "",
                    cards
                        .iter()
                        .map(|(column, card)| {
                            let restored = card.clone();
                            let st = st.clone();
                            stack(
                                "event kanban-archived-card-row",
                                vec![
                                    line(
                                        "event-head",
                                        vec![
                                            paragraph("entity-title", card.title.clone()),
                                            plain(column.clone()),
                                        ],
                                    ),
                                    action(
                                        scope,
                                        st.app.clone(),
                                        "card-restore-button",
                                        "kanban.restore_action",
                                        "secondary",
                                        true,
                                        move || {
                                            st.lifecycle_card(
                                                &restored,
                                                StrandLifecycleState::Active,
                                            )
                                        },
                                    ),
                                ],
                            )
                        })
                        .collect(),
                )
            }),
        ));
        stack("kanban-maintenance", sections)
    })
}
fn dialogs(_scope: &Scope, board: Board) -> View {
    let c = board.controller;
    let archive = {
        let board = board.clone();
        reactive(c.archive_board_confirm_open, move |scope, open| {
            if !open {
                return empty();
            }
            let columns = board.columns.get_untracked();
            let lists = columns
                .iter()
                .filter(|column| column.state == SpaceContainerLifecycleState::Active)
                .count();
            let cards = columns
                .iter()
                .filter(|column| column.state == SpaceContainerLifecycleState::Active)
                .flat_map(|column| column.cards.iter())
                .filter(|card| card.lifecycle == StrandLifecycleState::Active)
                .count();
            let scope_line = crate::i18n::tr("kanban.archive_board_confirm_scope")
                .replace("{lists}", &lists.to_string())
                .replace("{cards}", &cards.to_string());
            let submit = board.clone();
            confirmation(
                scope,
                board.app.clone(),
                "archive-board-confirm-modal",
                board
                    .app
                    .translated(scope, "kanban.archive_board_confirm_title"),
                stack(
                    "danger-confirm-modal",
                    vec![
                        stack(
                            "modal-body workflow-form",
                            vec![stack(
                                "callout danger archive-board-confirm-impact",
                                vec![
                                    paragraph("", scope_line),
                                    paragraph(
                                        "",
                                        crate::i18n::tr("kanban.archive_board_confirm_recover"),
                                    ),
                                ],
                            )],
                        ),
                        line(
                            "modal-foot",
                            vec![
                                action(
                                    scope,
                                    board.app.clone(),
                                    "archive-board-cancel-button",
                                    "kanban.archive_board_confirm_cancel",
                                    "secondary",
                                    true,
                                    move || {
                                        c.archive_board_confirm_open.revise(|value| *value = false)
                                    },
                                ),
                                action(
                                    scope,
                                    board.app.clone(),
                                    "archive-board-confirm-button",
                                    "kanban.archive_board_confirm_confirm",
                                    "destructive",
                                    true,
                                    move || submit.archive_board(),
                                ),
                            ],
                        ),
                    ],
                ),
                move || c.archive_board_confirm_open.revise(|value| *value = false),
            )
        })
    };
    let list = reactive(c.list_archive_confirm, move |scope, target| {
        let Some((id, title, count)) = target else {
            return empty();
        };
        let body = crate::i18n::tr("kanban.archive_list_confirm_body")
            .replace("{title}", &title)
            .replace("{cards}", &count.to_string());
        let submit = board.clone();
        confirmation(
            scope,
            board.app.clone(),
            "list-archive-confirm-modal",
            board
                .app
                .translated(scope, "kanban.archive_list_confirm_title"),
            stack(
                "danger-confirm-modal",
                vec![
                    paragraph("list-archive-confirm-impact", body),
                    line(
                        "modal-foot",
                        vec![
                            action(
                                scope,
                                board.app.clone(),
                                "list-archive-cancel-button",
                                "kanban.archive_list_confirm_cancel",
                                "secondary",
                                true,
                                move || c.list_archive_confirm.revise(|value| *value = None),
                            ),
                            action(
                                scope,
                                board.app.clone(),
                                "list-archive-confirm-button",
                                "kanban.archive_list_confirm_confirm",
                                "destructive",
                                true,
                                move || submit.archive_list(id.clone()),
                            ),
                        ],
                    ),
                ],
            ),
            move || c.list_archive_confirm.revise(|value| *value = None),
        )
    });
    stack("kanban-dialogs", vec![archive, list])
}
