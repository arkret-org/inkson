use glory::render::Role;
use glory::ui::view;

use super::*;

pub(super) fn surface(scope: &Scope, app: Rc<InksonContext>, empty_realm: bool) -> View {
    if !empty_realm {
        return Box::new(
            view()
                .class("event kanban-invalid-realm")
                .role(Role::Alert)
                .fill(plain(app.translated(scope, "kanban.ui.invalid_realm"))),
        );
    }
    let complete = app.sync_bootstrap_complete;
    crate::presentation::widgets::reactive_distinct(complete, move |scope, complete| {
        if complete {
            return unselected_frame(scope, app.clone());
        }
        Box::new(
            view()
                .class("event kanban-loading-realm")
                .role(Role::Status)
                .fill(plain(app.translated(scope, "kanban.ui.loading_realm"))),
        ) as View
    })
}

fn unselected_frame(scope: &Scope, app: Rc<InksonContext>) -> View {
    let popover = scope.cage(BoardToolbarPopover::None);
    let title = scope.cage("Board".to_owned());
    let status = scope.cage(String::new());
    let switch = Box::new(
        glory::ui::button()
            .class("board-select-button board-space-select-button")
            .name(app.translated(scope, "kanban.ui.switch_board"))
            .semantics(scope.bond(move || {
                Some(Box::new(glory::render::Semantics {
                    expanded: Some(popover.get() == BoardToolbarPopover::SelectBoard),
                    ..Default::default()
                }))
            }))
            .fill(vec![
                crate::components::ui_icon("board"),
                plain(app.translated(scope, "kanban.ui.select_board")),
                crate::components::ui_icon("chevron-down"),
            ])
            .on(glory::render::EventKind::Activate, move |_| {
                popover.revise(|value| {
                    *value = if *value == BoardToolbarPopover::SelectBoard {
                        BoardToolbarPopover::None
                    } else {
                        BoardToolbarPopover::SelectBoard
                    };
                })
            }),
    ) as View;
    let select_app = app.clone();
    let options = crate::presentation::widgets::reactive_distinct(popover, move |scope, open| {
        if open != BoardToolbarPopover::SelectBoard {
            return empty();
        }
        stack(
            "board-select-menu-panel",
            vec![action(
                scope,
                select_app.clone(),
                "board-select-menu-item",
                "kanban.ui.select_board",
                "secondary is-active",
                true,
                move || popover.revise(|value| *value = BoardToolbarPopover::None),
            )],
        )
    });
    let create_app = app.clone();
    let create_panel =
        crate::presentation::widgets::reactive_distinct(popover, move |scope, open| {
            if open != BoardToolbarPopover::CreateBoard {
                return empty();
            }
            let unavailable = create_app.clone();
            stack(
                "board-popover-panel board-create-popover",
                vec![
                    input_prompt(
                        scope,
                        create_app.translated(scope, "kanban.ui.board_title").into(),
                        title,
                        input(
                            scope,
                            create_app.clone(),
                            "new-board-title-input",
                            "kanban.ui.board_title",
                            title,
                            true,
                        ),
                    ),
                    action(
                        scope,
                        create_app.clone(),
                        "create-board-space-button",
                        "kanban.ui.create_board",
                        "primary",
                        false,
                        move || {
                            status.revise(|value| *value = unavailable.tr("kanban.ui.select_board"))
                        },
                    ),
                ],
            )
        });
    let close_label = app.translated(scope, "common.close");
    let scrim = crate::presentation::widgets::reactive_distinct(popover, move |_, open| {
        if open == BoardToolbarPopover::None {
            return empty();
        }
        Box::new(
            glory::ui::button()
                .class("board-popover-scrim")
                .name(close_label)
                .on(glory::render::EventKind::Activate, move |_| {
                    popover.revise(|value| *value = BoardToolbarPopover::None)
                }),
        ) as View
    });
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
                            view()
                                .class(scope.bond(move || {
                                    if popover.get() == BoardToolbarPopover::SelectBoard {
                                        "board-select-menu-host is-open"
                                    } else {
                                        "board-select-menu-host"
                                    }
                                    .to_owned()
                                }))
                                .fill(vec![switch, options]),
                        ) as View,
                    ],
                ),
                line(
                    "actions board-toolbar-actions",
                    vec![
                        action(
                            scope,
                            app.clone(),
                            "archive-board-button",
                            "kanban.archive_board_action",
                            "secondary btn board-archive-board",
                            false,
                            move || status.revise(|value| value.clear()),
                        ),
                        Box::new(
                            view()
                                .class(scope.bond(move || {
                                    if popover.get() == BoardToolbarPopover::CreateBoard {
                                        "board-popover-host is-open"
                                    } else {
                                        "board-popover-host"
                                    }
                                    .to_owned()
                                }))
                                .fill(vec![
                                    action(
                                        scope,
                                        app.clone(),
                                        "new-board-toggle",
                                        "kanban.ui.new_board",
                                        "secondary btn board-popover-trigger",
                                        true,
                                        move || {
                                            popover.revise(|value| {
                                                *value =
                                                    if *value == BoardToolbarPopover::CreateBoard {
                                                        BoardToolbarPopover::None
                                                    } else {
                                                        BoardToolbarPopover::CreateBoard
                                                    }
                                            })
                                        },
                                    ),
                                    create_panel,
                                ]),
                        ) as View,
                    ],
                ),
            ],
        )],
    );
    let grid = stack(
        "board-grid kanban-board-grid",
        vec![stack(
            "board-empty-state",
            vec![crate::components::empty_state(
                scope,
                app,
                crate::components::EmptyStateProps {
                    title: crate::i18n::tr("kanban.ui.no_board_selected"),
                    kind: crate::components::EmptyStateKind::Empty,
                    message: Some("Create or select a board before adding lists and cards.".into()),
                    badge_override: Some("select board".into()),
                    test_id: Some("kanban-empty-board".into()),
                },
            )],
        )],
    );
    stack(
        "timeline kanban-panel kanban-unselected-realm",
        vec![scrim, header, paragraph("muted board-status", status), grid],
    )
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use glory::render::{Event, NodeId, Props};

    use super::*;

    fn classes(app: &glory::App, wanted: &str) -> Vec<NodeId> {
        let tree = app.tree();
        let mut pending = tree.roots().to_vec();
        let mut found = vec![];
        while let Some(id) = pending.pop() {
            let node = tree.node(id).unwrap();
            if node
                .descriptor
                .view()
                .classes
                .iter()
                .any(|class| class == wanted)
            {
                found.push(id);
            }
            pending.extend(node.children.iter().copied());
        }
        found
    }

    #[test]
    fn production_empty_realm_keeps_loading_owner_then_renders_the_unselected_frame_without_writes()
    {
        let app = glory::App::memory();
        let directory = tempfile::tempdir().unwrap();
        let account =
            crate::test_support::AccountFixture::new("ak:did_core:web:loading.example").build();
        let context = InksonContext::new(
            app.scope(),
            crate::presentation::BootState {
                config_store: crate::config::LocalConfigStore::with_path(
                    directory.path().join("config.json"),
                ),
                config: crate::config::ClientConfig::authenticated(
                    account,
                    "fixture-session".into(),
                ),
                state_store: SharedStateStore::new(LocalStateStore::with_path(
                    directory.path().join("state.json"),
                )),
                initial_credential: "fixture-session".into(),
                realm_tree_nodes: vec![],
            },
            Route::Kanban,
            |_| Box::pin(std::future::pending()),
        );
        app.mount(super::super::page(
            app.scope(),
            context.clone(),
            Route::Kanban,
        ))
        .unwrap();
        app.flush().unwrap();
        let status = classes(&app, "kanban-loading-realm");
        assert_eq!(status.len(), 1);
        assert_eq!(
            app.tree().node(status[0]).unwrap().descriptor.view().role,
            Some(Role::Status)
        );
        assert!(classes(&app, "kanban-panel").is_empty());
        let owners = app.stats().owners;
        for _ in 0..4 {
            context.state_revision.revise(|revision| *revision += 1);
            app.flush().unwrap();
            assert_eq!(classes(&app, "kanban-loading-realm"), status);
            assert_eq!(app.stats().owners, owners);
        }
        context
            .sync_bootstrap_complete
            .revise(|complete| *complete = true);
        app.flush().unwrap();
        assert!(classes(&app, "kanban-loading-realm").is_empty());
        assert!(app.tree().node(status[0]).is_err());
        assert_eq!(classes(&app, "kanban-unselected-realm").len(), 1);
        assert_eq!(classes(&app, "kanban-panel").len(), 1);
        assert_eq!(classes(&app, "kanban-board-grid").len(), 1);
        assert_eq!(classes(&app, "kanban-empty-board").len(), 1);
        assert!(classes(&app, "board-column").is_empty());
        assert!(classes(&app, "kanban-card").is_empty());
        assert!(context.selected_realm_id.get_untracked().is_empty());
        let archive = classes(&app, "archive-board-button")[0];
        assert!(
            matches!(app.tree().node(archive).unwrap().descriptor.view().props, Props::Button(value) if !value.enabled)
        );
        app.dispatch(archive, Event::Activate).unwrap();
        app.dispatch(classes(&app, "new-board-toggle")[0], Event::Activate)
            .unwrap();
        app.flush().unwrap();
        let field = classes(&app, "new-board-title-input")[0];
        let mut pending = vec![field];
        let input = loop {
            let id = pending.pop().unwrap();
            let tree = app.tree();
            let node = tree.node(id).unwrap();
            if matches!(node.descriptor.view().props, Props::Input(_)) {
                break id;
            }
            pending.extend(node.children.iter().copied());
        };
        let revision = match app.tree().node(input).unwrap().descriptor.view().props {
            Props::Input(value) => value.revision,
            _ => unreachable!(),
        };
        app.dispatch(
            input,
            Event::ValueChanged {
                value: "Board 条目".into(),
                composing: false,
                revision,
            },
        )
        .unwrap();
        app.flush().unwrap();
        assert!(
            matches!(app.tree().node(input).unwrap().descriptor.view().props, Props::Input(value) if value.value == "Board 条目")
        );
        let create = classes(&app, "create-board-space-button")[0];
        assert!(
            matches!(app.tree().node(create).unwrap().descriptor.view().props, Props::Button(value) if !value.enabled)
        );
        app.dispatch(create, Event::Activate).unwrap();
        app.flush().unwrap();
        assert!(
            context
                .state_store
                .read(|store| store.load().raw_operations.is_empty())
        );
        assert!(context.selected_realm_id.get_untracked().is_empty());
        app.dispatch(classes(&app, "new-board-toggle")[0], Event::Activate)
            .unwrap();
        app.dispatch(
            classes(&app, "board-space-select-button")[0],
            Event::Activate,
        )
        .unwrap();
        app.flush().unwrap();
        app.dispatch(classes(&app, "board-select-menu-item")[0], Event::Activate)
            .unwrap();
        app.flush().unwrap();
        assert!(classes(&app, "board-select-menu-panel").is_empty());
        assert!(
            context
                .state_store
                .read(|store| store.load().raw_operations.is_empty())
        );
        app.mount(super::super::page(
            app.scope(),
            context,
            Route::KanbanRealm {
                realm_id: "invalid".into(),
            },
        ))
        .unwrap();
        app.flush().unwrap();
        let invalid = classes(&app, "kanban-invalid-realm");
        assert_eq!(invalid.len(), 1);
        assert_eq!(
            app.tree().node(invalid[0]).unwrap().descriptor.view().role,
            Some(Role::Alert)
        );
        assert_eq!(classes(&app, "kanban-panel").len(), 1);
    }
}
