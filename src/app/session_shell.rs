//! The authenticated application frame retains its controls across routes.
use std::rc::Rc;

use glory::prelude::*;
#[cfg(not(target_arch = "wasm32"))]
use glory::render::{Event, KeyboardCommand};
use glory::render::{EventKind, Role};

use super::shell_state::ShellState;
use super::*;
use crate::presentation::widgets::*;
use crate::presentation::{InksonContext, View};

pub(super) fn block(class: impl Into<String>, children: Vec<View>) -> View {
    Box::new(view().class(class.into()).fill(children))
}
pub(super) fn action(
    class: impl Into<String>,
    label: impl Into<Lotus<String>>,
    handler: impl FnMut() + 'static,
) -> View {
    Box::new(
        sapid::button()
            .unstyled()
            .class(class.into())
            .label(label)
            .on_press(handler),
    )
}
pub(super) fn icon_action(
    class: &str,
    label: impl Into<Lotus<String>>,
    icon: &str,
    handler: impl FnMut() + 'static,
) -> View {
    Box::new(
        sapid::button()
            .unstyled()
            .class(class.to_owned())
            .name(label)
            .fill(crate::components::ui_icon(icon))
            .on_press(handler),
    )
}
pub(super) fn nav(
    context: Rc<InksonContext>,
    route: Route,
    class: impl Into<String>,
    label: impl Into<Lotus<String>>,
    icon: &str,
) -> View {
    let label = label.into();
    let children = if icon.is_empty() {
        vec![plain(label.clone())]
    } else {
        vec![
            block("sidebar-nav-icon", vec![crate::components::ui_icon(icon)]),
            Box::new(text().class("grow truncate").content(label.clone())) as View,
        ]
    };
    Box::new(
        internal_link()
            .target(route.to_string())
            .name(label)
            .class(class.into())
            .fill(children)
            .on(EventKind::Activate, move |_| {
                context.navigate(route.clone())
            }),
    )
}
fn route_boundary(
    scope: &Scope,
    context: Rc<InksonContext>,
    render: impl Fn(&Scope, Route) -> View + 'static,
) -> View {
    let route = context.route;
    let description = context.server_description;
    let generation = context.session_generation;
    let account = context.active_account;
    let selected_realm = context.selected_realm_id;
    let phase = scope.bond(move || {
        let route = route.get();
        let description = description.get();
        let phase = super::route_surface::capability_phase(&route, description.as_ref());
        let route = match route {
            Route::SettingsSection { section, .. } if section == "agents" => {
                Route::SettingsSection {
                    section,
                    filter: String::new(),
                }
            }
            Route::KanbanTask {
                realm_id, task_id, ..
            } => Route::KanbanTask {
                realm_id,
                task_id,
                tab: String::new(),
            },
            Route::KanbanBoardTask {
                realm_id,
                board_id,
                task_id,
                ..
            } => Route::KanbanBoardTask {
                realm_id,
                board_id,
                task_id,
                tab: String::new(),
            },
            route => route,
        };
        let implicit_realm = if matches!(route, Route::Kanban) {
            Some(selected_realm.get())
        } else {
            None
        };
        let account = account.get().map(|account| {
            (
                account.authority,
                account.device_id,
                account.profile_id,
                account.server_url,
                account.principal_control_realm_id,
            )
        });
        (route, phase, generation.get(), account, implicit_realm)
    });
    reactive_distinct(phase, move |scope, _| render(scope, route.get_untracked()))
}

pub(super) fn shell(scope: &Scope, context: Rc<InksonContext>) -> View {
    let ui = ShellState::new(scope, &context);
    super::shell_effects::install(scope, context.clone(), ui.clone());
    #[cfg(target_arch = "wasm32")]
    super::global_shortcuts::install(scope, context.clone(), ui.clone());
    let content = route_boundary(scope, context.clone(), {
        let context = context.clone();
        let ui = ui.clone();
        move |scope, route| super::route_surface::surface(scope, context.clone(), route, ui.clone())
    });
    let class = scope.bond({
        let context = context.clone();
        let ui = ui.clone();
        move || {
            let chrome = super::shell_model::shell_chrome(
                &context.theme.get(),
                context.system_theme_is_night.get(),
                context.locale.get().direction(),
                ui.collapsed.get(),
                ui.resizing.get(),
            );
            format!(
                "{} sidebar-width-{}",
                chrome.shell_class,
                super::sidebar_width::clamp_sidebar_width(ui.width.get()).round() as i32
            )
        }
    });
    let persist = context.clone();
    let collapsed = ui.collapsed;
    scope.effect(move || {
        let value = collapsed.get();
        persist
            .state_store
            .write(|store| store.save_plain_local_data("sidebar_collapsed", value.to_string()));
    });
    #[cfg(not(target_arch = "wasm32"))]
    let keyboard_ui = ui.clone();
    #[cfg(not(target_arch = "wasm32"))]
    let keyboard_ctx = context.clone();
    let frame = view().class(class).role(Role::Group);
    #[cfg(not(target_arch = "wasm32"))]
    let frame = frame.on(EventKind::Keyboard, move |event| {
        if let Event::Keyboard { command, .. } = event {
            match command {
                KeyboardCommand::Palette => keyboard_ui.search_open.revise(|value| *value = true),
                KeyboardCommand::Search => keyboard_ctx.navigate(Route::Search),
                KeyboardCommand::Help => keyboard_ui.shortcut_open.revise(|value| *value = !*value),
                KeyboardCommand::Dismiss => {
                    keyboard_ui.search_open.revise(|value| *value = false);
                    keyboard_ui
                        .notifications_open
                        .revise(|value| *value = false);
                    keyboard_ui.mobile_open.revise(|value| *value = false);
                }
                _ => {}
            }
        }
    });
    let frame = frame
        .on(EventKind::Palette, {
            let ui = ui.clone();
            move |_| ui.search_open.revise(|value| *value = true)
        })
        .fill(vec![
            crate::components::toast_host(scope, context.clone()),
            crate::components::did_resolution_health_banner(
                scope,
                context.clone(),
                context.did_resolution_health,
            ),
            crate::components::agent_runtime_approval_prompt(scope, context.clone()),
            crate::components::recovery_key_setup_prompt(scope, context.clone()),
            health_prompt(scope, context.clone()),
            mobile_bar(scope, context.clone(), ui.clone()),
            mobile_drawer(scope, context.clone(), ui.clone()),
            super::sidebar::sidebar(scope, context.clone(), ui.clone()),
            block(
                "main realm",
                vec![topbar(scope, context.clone(), ui.clone()), content],
            ),
            super::notifications_drawer::notifications_drawer(
                scope,
                context.clone(),
                ui.notifications_open,
            ),
            crate::components::shortcut_help_overlay(scope, context.clone(), ui.shortcut_open),
            super::manage_pages::confirmations(scope, context.clone(), ui.clone()),
        ]);
    Box::new(frame)
}
fn health_prompt(scope: &Scope, context: Rc<InksonContext>) -> View {
    let source = scope.bond({
        let context = context.clone();
        move || {
            let _ = context.state_revision.get();
            let route = context.route.get();
            let recovery = context.account_recovery_configured.get();
            let other = context.account_has_other_devices.get();
            let local = context
                .state_store
                .read(crate::views::recovery::recovery_options_configured);
            let prompt =
                crate::account_health::resolve(crate::account_health::AccountHealthInputs {
                    has_session: !context.token.get().trim().is_empty()
                        && context.active_account.get().is_some(),
                    sync_bootstrap_complete: context.sync_bootstrap_complete.get(),
                    device_check_complete: context.device_authorization_check_complete.get(),
                    on_recovery_route: matches!(route, Route::Recovery | Route::SettingsRecovery),
                    on_onboarding_route: matches!(route, Route::Onboarding),
                    recovery_check_complete: recovery.is_some(),
                    needs_device_authorization: context.needs_device_authorization.get(),
                    account_has_other_devices: other,
                    needs_mls_unlock: context.needs_mls_unlock.get(),
                    needs_mls_backup: context.needs_mls_backup.get(),
                    needs_mls_recovery_setup: context.needs_mls_recovery_setup.get(),
                    recovery_unconfigured: super::recovery_setup_prompt_required_for_account_state(
                        recovery, local, other,
                    ),
                });
            (prompt, context.recovery_key_setup_open.get())
        }
    });
    reactive_distinct(source, move |scope, (prompt, setup_open)| {
        use crate::account_health::AccountHealthPrompt::*;
        match prompt {
            DeviceAuthorization => crate::components::device_authorization_prompt(
                scope,
                context.clone(),
                context.needs_device_authorization,
            ),
            MlsUnlock if !setup_open => {
                crate::components::mls_unlock_prompt(scope, context.clone())
            }
            MlsBackup if !setup_open => {
                crate::components::mls_backup_prompt(scope, context.clone())
            }
            RecoverySetupMissing if !setup_open => {
                crate::components::mls_recovery_setup_missing_banner(scope, context.clone())
            }
            RecoverySetupReminder if !setup_open => block(
                "event recovery-setup-banner",
                vec![
                    block(
                        "event-head",
                        vec![
                            plain(context.translated(scope, "app.recovery.incomplete_title")),
                            paragraph("muted", "first-time setup"),
                        ],
                    ),
                    paragraph(
                        "muted",
                        context.translated(scope, "app.recovery.incomplete_body"),
                    ),
                    block(
                        "actions",
                        vec![
                            action(
                                "btn primary",
                                context.translated(scope, "app.recovery.configure"),
                                {
                                    let context = context.clone();
                                    move || {
                                        context
                                            .recovery_key_setup_open
                                            .revise(|value| *value = true)
                                    }
                                },
                            ),
                            nav(
                                context.clone(),
                                Route::SettingsSection {
                                    section: "encryption".into(),
                                    filter: String::new(),
                                },
                                "secondary",
                                context.translated(scope, "app.recovery.history_status"),
                                "lock",
                            ),
                        ],
                    ),
                    paragraph(
                        "muted",
                        context.translated(scope, "app.recovery.history_status_body"),
                    ),
                ],
            ),
            _ => empty(),
        }
    })
}
fn theme_toggle_button(scope: &Scope, context: Rc<InksonContext>) -> View {
    let chrome = scope.bond({
        let context = context.clone();
        move || {
            let chrome = super::shell_model::shell_chrome(
                &context.theme.get(),
                context.system_theme_is_night.get(),
                context.locale.get().direction(),
                false,
                false,
            );
            (
                chrome.theme_toggle_icon.to_owned(),
                chrome.theme_toggle_title,
            )
        }
    });
    let name = scope.bond(move || chrome.get().1);
    let sun = scope.bond(move || chrome.get().0 == "sun");
    Box::new(
        glory::ui::button()
            .class("btn icon theme-toggle-button")
            .name(name)
            .fill(
                glory::ui::when(sun, || crate::components::ui_icon("sun"))
                    .otherwise(|| crate::components::ui_icon("moon")),
            )
            .on(EventKind::Activate, move |_| {
                let next = super::next_manual_theme(&context.theme.get());
                context.theme.revise(|value| *value = next.clone());
                context
                    .state_store
                    .write(|store| store.save_plain_local_data("theme", next.clone()));
                crate::views::settings::push_client_ui_account_data(
                    context.clone(),
                    context.base_url.get(),
                    context.token.get(),
                    next,
                );
            }),
    )
}
fn mobile_bar(scope: &Scope, context: Rc<InksonContext>, ui: Rc<ShellState>) -> View {
    let theme = theme_toggle_button(scope, context.clone());
    let drawer_id = match glory::render::SemanticId::new("mobile-navigation-drawer") {
        Ok(id) => id,
        Err(error) => {
            scope.report_error(error);
            return empty();
        }
    };
    let open = ui.mobile_open;
    let menu_context = context.clone();
    let name = scope.bond(move || {
        menu_context.tr(if open.get() {
            "app.nav.close_menu"
        } else {
            "app.nav.open_menu"
        })
    });
    let semantics = scope.bond(move || {
        Some(Box::new(glory::render::Semantics {
            expanded: Some(open.get()),
            controls: Some(drawer_id.clone()),
            ..Default::default()
        }))
    });
    let menu = Box::new(
        button()
            .class("btn icon mobile-nav-toggle")
            .name(name)
            .semantics(semantics)
            .fill(
                glory::ui::when(open, || crate::components::ui_icon("x"))
                    .otherwise(|| crate::components::ui_icon("menu")),
            )
            .on(EventKind::Activate, move |_| {
                open.revise(|value| *value = !*value)
            }),
    ) as View;
    block(
        "mobile-shellbar",
        vec![
            menu,
            block("brand", vec![plain("Arkret")]),
            theme,
            icon_action(
                "btn icon",
                context.translated(scope, "shortcuts.title"),
                "keyboard",
                {
                    let ui = ui.clone();
                    move || {
                        ui.mobile_open.revise(|value| *value = false);
                        ui.shortcut_open.revise(|value| *value = true);
                    }
                },
            ),
            icon_action(
                "btn icon topbar-notifications-link",
                context.translated(scope, "nav.notifications"),
                "bell",
                move || {
                    ui.mobile_open.revise(|value| *value = false);
                    ui.account_open.revise(|value| *value = false);
                    ui.server_open.revise(|value| *value = false);
                    ui.search_open.revise(|value| *value = false);
                    ui.search_query.revise(String::clear);
                    ui.notifications_open.revise(|value| *value = !*value);
                },
            ),
        ],
    )
}

fn mobile_drawer(scope: &Scope, context: Rc<InksonContext>, ui: Rc<ShellState>) -> View {
    let drawer_id = match glory::render::SemanticId::new("mobile-navigation-drawer") {
        Ok(id) => id,
        Err(error) => {
            scope.report_error(error);
            return empty();
        }
    };
    let class = scope.bond({
        let ui = ui.clone();
        move || {
            if ui.mobile_open.get() {
                "mobile-drawer mobile-nav-drawer open"
            } else {
                "mobile-drawer mobile-nav-drawer"
            }
            .to_owned()
        }
    });
    let source = scope.bond({
        let context = context.clone();
        let ui = ui.clone();
        move || {
            (
                context.realm_tree_nodes.get(),
                ui.mobile_query.get(),
                context.locale.get(),
                context.state_revision.get(),
            )
        }
    });
    let context_tree = context.clone();
    let ui_tree = ui.clone();
    let tree = reactive(source, move |scope, (nodes, query, ..)| {
        let _ = nodes;
        let rows = super::sidebar::navigation_model(
            &context_tree,
            &context_tree.route.get_untracked(),
            "",
        )
        .realm_tree;
        let children = filtered_mobile_realm_items(&rows, &query)
            .into_iter()
            .map(|item| {
                let target = item.node.projection_realm_id().to_owned();
                let context = context_tree.clone();
                let ui = ui_tree.clone();
                action("secondary", item.node.title.clone(), move || {
                    context
                        .selected_realm_id
                        .revise(|value| *value = target.clone());
                    ui.mobile_open.revise(|value| *value = false);
                    ui.mobile_query.revise(String::clear);
                    context.navigate(Route::Realm {
                        realm_id: target.clone(),
                    });
                })
            })
            .collect::<Vec<_>>();
        if children.is_empty() {
            paragraph("muted", context_tree.translated(scope, "mobile.no_match"))
        } else {
            block("mobile-realm-tree-list", children)
        }
    });
    Box::new(
        view()
            .class(class)
            .role(Role::Navigation)
            .name(context.translated(scope, "app.nav.main_navigation"))
            .semantics(Some(Box::new(glory::render::Semantics {
                id: Some(drawer_id),
                ..Default::default()
            })))
            .fill(vec![
                block(
                    "mobile-status",
                    vec![
                        plain(context.connection_status),
                        paragraph("muted mono", context.sync_cursor),
                        action("btn primary", "Refresh", {
                            let weak = scope.downgrade();
                            let context = context.clone();
                            move || {
                                if let Some(scope) = weak.upgrade() {
                                    super::connection_handlers::refresh_connection(
                                        &scope,
                                        context.clone(),
                                    );
                                }
                            }
                        }),
                    ],
                ),
                block(
                    "mobile-primary-nav",
                    vec![
                        nav(
                            context.clone(),
                            Route::Dashboard,
                            "secondary mobile-dashboard-nav-button",
                            context.translated(scope, "nav.dashboard"),
                            "",
                        ),
                        nav(
                            context.clone(),
                            Route::Directory,
                            "secondary mobile-directory-nav-button",
                            context.translated(scope, "nav.directory"),
                            "",
                        ),
                        nav(
                            context.clone(),
                            Route::Settings,
                            "secondary mobile-settings-nav-button",
                            context.translated(scope, "nav.settings"),
                            "",
                        ),
                    ],
                ),
                input_field(
                    context.clone(),
                    "mobile-realms",
                    context.translated(scope, "mobile.filter_realms"),
                    ui.mobile_query,
                    Purpose::Text,
                ),
                tree,
            ]),
    )
}

#[cfg(test)]
#[path = "mobile_drawer_tests.rs"]
mod mobile_drawer_tests;
fn connection_status_region(scope: &Scope, context: Rc<InksonContext>) -> View {
    let cursor = context.sync_cursor;
    let error = reactive(context.last_error, |_, error| match error {
        Some(error) => Box::new(text().class("last-error").content(error)) as View,
        None => empty(),
    });
    Box::new(
        view()
            .class("sr-only connection-status")
            .role(Role::Status)
            .fill(vec![
                Box::new(
                    text()
                        .class("status-label")
                        .content(context.connection_status),
                ) as View,
                Box::new(
                    text()
                        .class("network-state-badge")
                        .content(context.network_state),
                ),
                Box::new(
                    text()
                        .class("mono sync-cursor")
                        .content(scope.bond(move || format!("cursor {}", cursor.get()))),
                ),
                error,
            ]),
    )
}
fn topbar(scope: &Scope, context: Rc<InksonContext>, ui: Rc<ShellState>) -> View {
    let source = scope.bond({
        let context = context.clone();
        move || {
            (
                context.route.get(),
                context.selected_realm_id.get(),
                context.realm_tree_nodes.get(),
                context.state_revision.get(),
                context.locale.get(),
                context.server_description.get(),
            )
        }
    });
    let title = reactive(source, {
        let context = context.clone();
        move |scope, (route, selected, nodes, _, _, _description)| {
            let _ = (selected, nodes);
            let navigation = super::sidebar::navigation_model(&context, &route, "");
            let id = navigation.active_projection_realm_id.clone();
            let title = navigation
                .selected_preview
                .as_ref()
                .map(|node| node.title.clone())
                .unwrap_or_else(|| context.tr(route_label_key(&route)));
            let mut children =
                vec![Box::new(text().class("topbar-context-title").content(title)) as View];
            if route_uses_realm_context(&route) && !id.is_empty() {
                children.push(Box::new(
                    text()
                        .class("sr-only mono selected-realm-id")
                        .content(id.clone()),
                ));
                let encrypted = navigation.active_realm_security_encrypted;
                children.insert(
                    0,
                    crate::components::security_state_badge(
                        scope,
                        context.clone(),
                        crate::components::SecurityStateBadgeProps {
                            encrypted: encrypted == Some(true),
                            unknown: encrypted.is_none(),
                            compact: false,
                            test_id: None,
                        },
                    ),
                );
                children.push(crate::components::mls_creator_retry::creator_mls_retry(
                    scope,
                    context.clone(),
                    crate::components::mls_creator_retry::CreatorMlsRetryProps {
                        realm_id: id.clone().into(),
                        circle_id: None,
                        refresh_hint: scope
                            .bond({
                                let error = context.last_error;
                                move || error.get().unwrap_or_default()
                            })
                            .into(),
                        token: context.token,
                    },
                ));
                let current = context.state_store.read(|store| {
                    super::resolve_realm_surface(
                        &route,
                        store,
                        &super::principal_id_owned(context.principal_id.get()),
                        Some(&id),
                    )
                });
                let (label, icon) = match current {
                    Some(surface) => (surface.short_label().to_owned(), surface.icon_name()),
                    None if matches!(route, Route::RealmMembers { .. }) => {
                        (context.tr("realm_admin.members"), "users")
                    }
                    None => (context.tr("nav.settings"), "settings"),
                };
                children.push(block(
                    "topbar-current-surface",
                    vec![
                        crate::components::ui_icon(icon),
                        paragraph("topbar-current-surface-label", label),
                    ],
                ));
            }
            block("topbar-context", children)
        }
    });
    let realm_navigation = reactive(source, {
        let context = context.clone();
        move |scope, (route, _, _, _, _, description)| {
            let navigation = super::sidebar::navigation_model(&context, &route, "");
            let id = navigation.active_projection_realm_id;
            if !route_uses_realm_context(&route) || id.is_empty() {
                return empty();
            }
            super::context_bar::context_bar(
                scope,
                context.clone(),
                id,
                route,
                StationFeature::Board.ready(description.as_ref()),
            )
        }
    });
    let search = Box::new(view().class("topbar-command-search").fill(vec![
        super::command_palette::search_trigger(scope, ui.clone()),
        reactive(ui.search_open, {
            let context = context.clone();
            let ui = ui.clone();
            move |scope, open| {
                if !open {
                    empty()
                } else {
                    let source = scope.bond({
                        let context = context.clone();
                        let ui = ui.clone();
                        move || (ui.search_query.get(), context.realm_tree_nodes.get())
                    });
                    block(
                        "topbar-command-search-field",
                        vec![
                            super::command_palette::query_input(scope, context.clone(), ui.clone()),
                            reactive(source, {
                                let context = context.clone();
                                let ui = ui.clone();
                                move |scope, (query, nodes)| {
                                    super::command_palette::command_palette(
                                        scope,
                                        context.clone(),
                                        query,
                                        nodes,
                                        ui.clone(),
                                    )
                                }
                            }),
                        ],
                    )
                }
            }
        }),
    ])) as View;
    block(
        "topbar realm-header",
        vec![
            block(
                "topbar-left",
                vec![
                    icon_action(
                        "btn icon sidebar-collapse-toggle",
                        context.translated(scope, "app.nav.hide_navigation"),
                        "panel-left-close",
                        {
                            let ui = ui.clone();
                            move || {
                                ui.collapsed.revise(|value| *value = !*value);
                            }
                        },
                    ),
                    title,
                ],
            ),
            realm_navigation,
            block(
                "actions",
                vec![
                    search,
                    theme_toggle_button(scope, context.clone()),
                    icon_action(
                        "btn icon",
                        context.translated(scope, "shortcuts.title"),
                        "keyboard",
                        {
                            let ui = ui.clone();
                            move || ui.shortcut_open.revise(|value| *value = !*value)
                        },
                    ),
                    icon_action(
                        "btn icon topbar-notifications-link",
                        context.translated(scope, "nav.notifications"),
                        "bell",
                        {
                            let ui = ui.clone();
                            move || ui.notifications_open.revise(|value| *value = !*value)
                        },
                    ),
                    connection_status_region(scope, context.clone()),
                    account_menu(scope, context, ui),
                ],
            ),
        ],
    )
}
fn account_menu_avatar(
    scope: &Scope,
    context: Rc<InksonContext>,
    principal: String,
    blob: String,
    label: String,
    class: &str,
) -> View {
    crate::components::generated_avatar::identity_avatar_inline(
        scope,
        context,
        crate::components::IdentityAvatarProps {
            seed: principal,
            alt_text: label,
            blob_ref: (!blob.is_empty()).then_some(blob),
            class: class.into(),
            test_id: None,
        },
    )
}
fn account_menu_copy(
    scope: &Scope,
    context: Rc<InksonContext>,
    label: impl Into<Lotus<String>>,
    value: String,
    success: &'static str,
) -> View {
    let label = label.into();
    #[cfg(target_arch = "wasm32")]
    let hint_value = value.clone();
    let owner = scope.downgrade();
    let copy = move |_| {
        let Some(scope) = owner.upgrade() else {
            return;
        };
        let context = context.clone();
        let value = value.clone();
        let owner = scope.downgrade();
        let generation = context.session_generation.get_untracked();
        let account = context.active_account.get_untracked();
        let _ = scope.spawn(async move {
            let result = crate::components::platform_io::copy_text(&value).await;
            if owner.upgrade().is_none() || !context.session_matches(generation, &account) {
                return;
            }
            match result {
                Ok(()) => crate::components::feedback::toast_success(success, vec![]),
                Err(error) => tracing::warn!(%error, "account clipboard write failed"),
            }
        });
    };
    let button = glory::ui::button()
        .class("btn icon account-menu__copy")
        .name(label.clone())
        .fill(crate::components::ui_icon("copy"))
        .on(EventKind::Activate, copy);
    #[cfg(target_arch = "wasm32")]
    {
        if hint_value.trim().is_empty() {
            return Box::new(button);
        }
        let mut button = Some(button);
        Box::new(
            sapid::tooltip(format!("account-{}", success.replace('.', "-")))
                .label(label)
                .text(hint_value)
                .target(move |target| target.button(button.take().expect("one hint target"))),
        )
    }
    #[cfg(not(target_arch = "wasm32"))]
    Box::new(button)
}
fn account_menu_text(class: impl Into<String>, value: impl Into<Lotus<String>>) -> View {
    Box::new(text().class(class.into()).content(value))
}
fn account_menu_identity(
    scope: &Scope,
    class: &str,
    label: String,
    value: &str,
    key: &str,
) -> View {
    let description = match glory::render::SemanticId::new(format!("{key}-description")) {
        Ok(id) => id,
        Err(error) => {
            scope.report_error(error);
            return empty();
        }
    };
    Box::new(
        group().fill((
            text()
                .class(class.to_owned())
                .content(label)
                .semantics(Some(Box::new(glory::render::Semantics {
                    described_by: Some(description.clone()),
                    ..Default::default()
                }))),
            text()
                .class(format!("sr-only {key}-description"))
                .content(value.to_owned())
                .semantics(Some(Box::new(glory::render::Semantics {
                    id: Some(description),
                    ..Default::default()
                }))),
        )),
    )
}
fn account_menu(scope: &Scope, context: Rc<InksonContext>, ui: Rc<ShellState>) -> View {
    let avatar_source = scope.bond({
        let context = context.clone();
        let ui = ui.clone();
        move || {
            let _ = context.state_revision.get();
            let fallback = ui.avatar.get();
            let blob = context
                .state_store
                .read(|store| store.load_plain_local_data("avatar_blob_ref"))
                .unwrap_or(fallback);
            (super::principal_id_owned(context.principal_id.get()), blob)
        }
    });
    let avatar = reactive_distinct(avatar_source, {
        let context = context.clone();
        move |scope, (principal, blob)| {
            account_menu_avatar(
                scope,
                context.clone(),
                principal,
                blob,
                context.tr("topbar.account_menu"),
                "avatar-img topbar-account-avatar",
            )
        }
    });
    let menu_source = scope.bond({
        let context = context.clone();
        let ui = ui.clone();
        move || {
            let _ = context.locale.get();
            let _ = context.state_revision.get();
            let account = super::principal_id_owned(context.principal_id.get());
            let device = context.device_id.get();
            let device_name = ui.device_name.get();
            let has_session = !context.token.get().is_empty();
            let labels = context.state_store.read(|store| {
                super::shell_model::account_identity_labels(
                    super::shell_model::AccountIdentityInput {
                        has_session,
                        personal_handles: &context.personal_handles.get(),
                        personal_handles_status: &context.personal_handles_status.get(),
                        account_display_name: &ui.display_name.get(),
                        device_display_name: &device_name,
                        device_id_label: &short_protocol_id(&device),
                        principal_id_value: &account,
                        store,
                    },
                )
            });
            (
                ui.account_open.get(),
                (account, device, device_name, has_session),
                (
                    labels.label,
                    labels.detail,
                    labels.handles_label,
                    labels.handles_title,
                ),
                avatar_source.get(),
                context.base_url.get(),
                context.locale.get(),
            )
        }
    });
    let body = reactive_distinct(menu_source, {
        let context = context.clone();
        let ui = ui.clone();
        move |scope,
              (
            open,
            (account, device, device_name, has_session),
            (label, detail, handles_label, handles_title),
            (principal, blob),
            server,
            _,
        )| {
            if !open {
                return empty();
            }
            let settings_link = |class: &str, icon: &str| -> View {
                let context = context.clone();
                let ui = ui.clone();
                Box::new(
                    internal_link()
                        .target(Route::Settings.to_string())
                        .class(class.to_owned())
                        .name(context.translated(scope, "app.account.open_settings"))
                        .fill(crate::components::ui_icon(icon))
                        .on(EventKind::Activate, move |_| {
                            ui.account_open.revise(|value| *value = false);
                            context.navigate(Route::Settings);
                        }),
                )
            };
            let head = block(
                "account-menu__head",
                vec![
                    account_menu_avatar(
                        scope,
                        context.clone(),
                        principal,
                        blob,
                        label.clone(),
                        "avatar-img account-menu__avatar",
                    ),
                    block(
                        "grow",
                        vec![
                            account_menu_text("who", label),
                            account_menu_text("handle", detail),
                        ],
                    ),
                    settings_link("btn icon sm ghost account-menu__qr", "qr-code"),
                ],
            );
            let key = |label| account_menu_text("account-menu__key", label);
            let identity_rows = block(
                "account-menu__rows",
                vec![
                    block(
                        "account-menu__row",
                        vec![
                            key(context.tr("app.account.did")),
                            block(
                                "account-menu__value",
                                vec![
                                    account_menu_identity(
                                        scope,
                                        "mono",
                                        short_protocol_id(&account),
                                        &account,
                                        "account-did",
                                    ),
                                    account_menu_copy(
                                        scope,
                                        context.clone(),
                                        context.translated(scope, "settings.account.copy_did"),
                                        account,
                                        "feedback.copied_did",
                                    ),
                                ],
                            ),
                        ],
                    ),
                    block(
                        "account-menu__row",
                        vec![
                            key(context.tr("settings.account.handles")),
                            block(
                                "account-menu__value",
                                vec![
                                    account_menu_identity(
                                        scope,
                                        "mono",
                                        handles_label,
                                        &handles_title,
                                        "account-handles",
                                    ),
                                    account_menu_copy(
                                        scope,
                                        context.clone(),
                                        context.translated(scope, "settings.account.copy_handles"),
                                        handles_title,
                                        "feedback.copied_handles",
                                    ),
                                ],
                            ),
                        ],
                    ),
                    block(
                        "account-menu__row",
                        vec![
                            key(context.tr("settings.devices.column_device")),
                            block(
                                "account-menu__value",
                                vec![
                                    block(
                                        "account-menu__device-text",
                                        vec![
                                            account_menu_text(
                                                "account-menu__device-name",
                                                if device_name.trim().is_empty() {
                                                    context.tr("settings.devices.this_device")
                                                } else {
                                                    device_name
                                                },
                                            ),
                                            account_menu_identity(
                                                scope,
                                                "mono account-menu__device-id",
                                                short_protocol_id(&device),
                                                &device,
                                                "account-device",
                                            ),
                                        ],
                                    ),
                                    account_menu_copy(
                                        scope,
                                        context.clone(),
                                        context
                                            .translated(scope, "settings.account.copy_device_id"),
                                        device,
                                        "feedback.copied_device_id",
                                    ),
                                ],
                            ),
                        ],
                    ),
                    block(
                        "account-menu__row",
                        vec![
                            key(context.tr("app.account.server")),
                            account_menu_text(
                                "account-menu__server",
                                crate::config::normalize_server_url(&server),
                            ),
                        ],
                    ),
                ],
            );
            let refresh = {
                let weak = scope.downgrade();
                let context = context.clone();
                let ui = ui.clone();
                Box::new(
                    sapid::button()
                        .unstyled()
                        .class("btn")
                        .label(context.translated(scope, "common.refresh"))
                        .name(context.translated(scope, "app.account.refresh_session"))
                        .enabled(has_session)
                        .on_press(move || {
                            if let Some(scope) = weak.upgrade() {
                                super::connection_handlers::refresh_current_session(
                                    &scope,
                                    context.base_url.get(),
                                    super::connection_handlers::ManualSessionRefreshContext {
                                        context: context.clone(),
                                        account_session_state: ui.session_status,
                                        personal_handles_lookup_key: ui.handles_key,
                                        account_identity_lookup_key: ui.identity_key,
                                    },
                                );
                            }
                        }),
                ) as View
            };
            let logout = action("btn", context.translated(scope, "app.account.log_out"), {
                let context = context.clone();
                let ui = ui.clone();
                move || super::session_commands::logout(context.clone(), ui.session_status)
            });
            let scrim = Box::new(
                glory::ui::button()
                    .class("account-menu-scrim")
                    .name(context.translated(scope, "common.close"))
                    .on(EventKind::Activate, {
                        let ui = ui.clone();
                        move |_| ui.account_open.revise(|value| *value = false)
                    }),
            ) as View;
            Box::new(glory::ui::group().fill(vec![
                scrim,
                block(
                    "account-menu",
                    vec![
                        head,
                        identity_rows,
                        super::account_switch::account_switcher(
                            scope,
                            context.clone(),
                            true.into(),
                        ),
                        {
                            let settings_context = context.clone();
                            let close = ui.account_open;
                            let settings = Box::new(
                                internal_link()
                                    .class("btn sm account-menu-settings")
                                    .target(Route::Settings.to_string())
                                    .name(context.translated(scope, "nav.settings"))
                                    .fill((
                                        crate::components::ui_icon("settings"),
                                        text().content(context.translated(scope, "nav.settings")),
                                    ))
                                    .on(EventKind::Activate, move |_| {
                                        close.revise(|value| *value = false);
                                        settings_context.navigate(Route::Settings);
                                    }),
                            ) as View;
                            block("account-menu__actions", vec![refresh, logout, settings])
                        },
                    ],
                ),
            ]))
        }
    });
    let online = scope.bond({
        let context = context.clone();
        move || !context.token.get().is_empty()
    });
    let expanded = ui.account_open;
    block(
        "account-menu-wrap",
        vec![
            Box::new(
                glory::ui::button()
                    .class("btn icon account-menu-button")
                    .name(context.translated(scope, "topbar.account_menu"))
                    .semantics(scope.bond(move || {
                        Some(Box::new(glory::render::Semantics {
                            expanded: Some(expanded.get()),
                            ..Default::default()
                        }))
                    }))
                    .fill(glory::ui::group().fill((
                        avatar,
                        reactive(online, move |_, online| {
                            if online {
                                Box::new(text().class("dot-online").content("")) as View
                            } else {
                                empty()
                            }
                        }),
                    )))
                    .on(EventKind::Activate, {
                        let ui = ui.clone();
                        move |_| {
                            ui.search_open.revise(|value| *value = false);
                            ui.search_query.revise(String::clear);
                            ui.server_open.revise(|value| *value = false);
                            ui.account_open.revise(|value| *value = !*value);
                        }
                    }),
            ),
            body,
        ],
    )
}
fn filtered_mobile_realm_items<'a>(
    realm_tree: &'a [crate::realm_tree::RealmTreeItem],
    query: &str,
) -> Vec<&'a crate::realm_tree::RealmTreeItem> {
    let query = query.trim().to_lowercase();
    realm_tree
        .iter()
        .filter(|item| {
            query.is_empty()
                || item.node.title.to_lowercase().contains(&query)
                || item.node.id.to_lowercase().contains(&query)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::filtered_mobile_realm_items;

    #[test]
    fn card_tab_query_preserves_the_page_owned_mention_until_a_real_target_changes() {
        use super::*;

        let app = glory::App::memory();
        let directory = tempfile::tempdir().unwrap();
        let task = |id: &str, tab: &str| Route::KanbanTask {
            realm_id: "realm-a".into(),
            task_id: id.into(),
            tab: tab.into(),
        };
        let context = InksonContext::new(
            app.scope(),
            crate::presentation::BootState {
                config_store: crate::config::LocalConfigStore::with_path(
                    directory.path().join("config.json"),
                ),
                config: crate::config::ClientConfig::default(),
                state_store: crate::presentation::SharedStateStore::new(
                    LocalStateStore::with_path(directory.path().join("state.json")),
                ),
                initial_credential: String::new(),
                realm_tree_nodes: vec![],
            },
            task("task-a", "description"),
            |_| Box::pin(std::future::pending()),
        );
        let input = app.scope().cage(None);
        let mention = app.scope().cage(None::<Cage<Option<String>>>);
        app.mount(route_boundary(
            app.scope(),
            context.clone(),
            move |scope, _| {
                mention.revise(|value| *value = Some(scope.cage(None)));
                Box::new(sapid::text_field().node_ref(input))
            },
        ))
        .unwrap();
        app.flush().unwrap();
        let original = input.get_untracked();
        let original_mention = mention.get_untracked().unwrap();
        original_mention
            .revise(|value| *value = Some("typed recipient at original Station".into()));
        for tab in ["discussion", "synthesis", "description"] {
            context.route.revise(|route| *route = task("task-a", tab));
            app.flush().unwrap();
            assert_eq!(input.get_untracked(), original);
            assert_eq!(
                original_mention.get_untracked().as_deref(),
                Some("typed recipient at original Station")
            );
        }
        context
            .route
            .revise(|route| *route = task("task-b", "discussion"));
        app.flush().unwrap();
        assert_ne!(input.get_untracked(), original);
        assert!(!original_mention.is_alive());
        let board_task = |board: &str, id: &str, tab: &str| Route::KanbanBoardTask {
            realm_id: "realm-a".into(),
            board_id: board.into(),
            task_id: id.into(),
            tab: tab.into(),
        };
        context
            .route
            .revise(|route| *route = board_task("board-a", "task-b", "description"));
        app.flush().unwrap();
        let board_input = input.get_untracked();
        let board_mention = mention.get_untracked().unwrap();
        board_mention.revise(|value| *value = Some("board-scoped recipient".into()));
        context
            .route
            .revise(|route| *route = board_task("board-a", "task-b", "discussion"));
        app.flush().unwrap();
        assert_eq!(input.get_untracked(), board_input);
        assert_eq!(
            board_mention.get_untracked().as_deref(),
            Some("board-scoped recipient")
        );
        context
            .route
            .revise(|route| *route = board_task("board-b", "task-b", "discussion"));
        app.flush().unwrap();
        assert_ne!(input.get_untracked(), board_input);
        assert!(!board_mention.is_alive());
    }

    #[test]
    fn agents_filter_navigation_retains_the_page_but_leaving_or_changing_session_retires_it() {
        use std::cell::Cell;

        use super::*;

        let app = glory::App::memory();
        let dir = tempfile::tempdir().unwrap();
        let agents = |filter: &str| Route::SettingsSection {
            section: "agents".into(),
            filter: filter.into(),
        };
        let context = InksonContext::new(
            app.scope(),
            crate::presentation::BootState {
                config_store: crate::config::LocalConfigStore::with_path(
                    dir.path().join("config.json"),
                ),
                config: crate::config::ClientConfig::default(),
                state_store: crate::presentation::SharedStateStore::new(
                    LocalStateStore::with_path(dir.path().join("state.json")),
                ),
                initial_credential: String::new(),
                realm_tree_nodes: vec![],
            },
            agents("all"),
            |_| Box::pin(std::future::pending()),
        );
        let mounted = Rc::new(Cell::new(0));
        let retired = Rc::new(Cell::new(0));
        let input = app.scope().cage(None);
        app.mount(route_boundary(app.scope(), context.clone(), {
            let mounted = mounted.clone();
            let retired = retired.clone();
            move |scope, _| {
                mounted.set(mounted.get() + 1);
                let retired = retired.clone();
                scope
                    .on_cleanup(move || retired.set(retired.get() + 1))
                    .unwrap();
                Box::new(sapid::text_field().node_ref(input))
            }
        }))
        .unwrap();
        app.flush().unwrap();
        let original = input.get_untracked();
        let owners = app.stats().owners;
        for query in ["paused", "all", "active", "", "all"] {
            context.route.revise(|route| *route = agents(query));
            app.flush().unwrap();
            assert_eq!(mounted.get(), 1);
            assert_eq!(retired.get(), 0);
            assert_eq!(input.get_untracked(), original);
            assert_eq!(app.stats().owners, owners);
        }
        context
            .session_generation
            .revise(|generation| *generation += 1);
        app.flush().unwrap();
        assert_eq!(mounted.get(), 2);
        assert_eq!(retired.get(), 1);
        assert_ne!(input.get_untracked(), original);
        context.route.revise(|route| {
            *route = Route::SettingsSection {
                section: "account".into(),
                filter: String::new(),
            }
        });
        app.flush().unwrap();
        assert_eq!(mounted.get(), 3);
        assert_eq!(retired.get(), 2);
        context.route.revise(|route| *route = agents("paused"));
        app.flush().unwrap();
        assert_eq!(mounted.get(), 4);
        assert_eq!(retired.get(), 3);
        for realm in ["one", "two"] {
            context.route.revise(|route| {
                *route = Route::Realm {
                    realm_id: realm.into(),
                }
            });
            app.flush().unwrap();
        }
        assert_eq!(mounted.get(), 6);
        assert_eq!(retired.get(), 5);
    }

    #[test]
    fn implicit_board_realm_arrival_replaces_the_target_and_explicit_routes_ignore_other_selection()
    {
        use std::cell::Cell;

        use super::*;

        let app = glory::App::memory();
        let dir = tempfile::tempdir().unwrap();
        let context = InksonContext::new(
            app.scope(),
            crate::presentation::BootState {
                config_store: crate::config::LocalConfigStore::with_path(
                    dir.path().join("config.json"),
                ),
                config: crate::config::ClientConfig::default(),
                state_store: crate::presentation::SharedStateStore::new(
                    LocalStateStore::with_path(dir.path().join("state.json")),
                ),
                initial_credential: String::new(),
                realm_tree_nodes: vec![],
            },
            Route::Kanban,
            |_| Box::pin(std::future::pending()),
        );
        let mounted = Rc::new(Cell::new(0));
        let retired = Rc::new(Cell::new(0));
        let reference = app.scope().cage(None);
        app.mount(route_boundary(app.scope(), context.clone(), {
            let mounted = mounted.clone();
            let retired = retired.clone();
            move |scope, _| {
                mounted.set(mounted.get() + 1);
                let retired = retired.clone();
                scope
                    .on_cleanup(move || retired.set(retired.get() + 1))
                    .unwrap();
                Box::new(sapid::text_field().node_ref(reference))
            }
        }))
        .unwrap();
        app.flush().unwrap();
        let initial = reference.get_untracked();
        context
            .selected_realm_id
            .revise(|realm| *realm = "realm-a".into());
        app.flush().unwrap();
        assert_eq!(mounted.get(), 2);
        assert_eq!(retired.get(), 1);
        assert_ne!(reference.get_untracked(), initial);
        let first_realm = reference.get_untracked();
        context
            .selected_realm_id
            .revise(|realm| *realm = "realm-b".into());
        app.flush().unwrap();
        assert_eq!(mounted.get(), 3);
        assert_eq!(retired.get(), 2);
        assert_ne!(reference.get_untracked(), first_realm);
        context.route.revise(|route| {
            *route = Route::KanbanRealm {
                realm_id: "realm-a".into(),
            }
        });
        app.flush().unwrap();
        assert_eq!(mounted.get(), 4);
        let explicit = reference.get_untracked();
        context
            .selected_realm_id
            .revise(|realm| *realm = "unrelated-realm".into());
        app.flush().unwrap();
        assert_eq!(mounted.get(), 4);
        assert_eq!(retired.get(), 3);
        assert_eq!(reference.get_untracked(), explicit);
        context.route.revise(|route| {
            *route = Route::KanbanRealm {
                realm_id: "realm-b".into(),
            }
        });
        app.flush().unwrap();
        assert_eq!(mounted.get(), 5);
        assert_eq!(retired.get(), 4);
        assert_ne!(reference.get_untracked(), explicit);
    }

    #[test]
    fn route_capability_arrival_mounts_the_child_without_remounting_on_an_unrelated_refresh() {
        use std::cell::Cell;

        use super::*;
        fn description(bundles: &[&str], host: &str) -> ServiceDescribe {
            ServiceDescribe::development(
                arkret_sdk::Did::new("did:web:station.example").unwrap(),
                arkret_sdk::TrustDomainId::new("ak:trust_domain:example.net").unwrap(),
                arkret_sdk::ServiceKind::Station,
                bundles.iter().map(|bundle| (*bundle).to_owned()).collect(),
                vec![arkret_sdk::TransportBinding::HttpJson {
                    base_url: format!("https://{host}/"),
                    extension_profile_required: (),
                }],
            )
        }
        let app = glory::App::memory();
        let dir = tempfile::tempdir().unwrap();
        let context = InksonContext::new(
            app.scope(),
            crate::presentation::BootState {
                config_store: crate::config::LocalConfigStore::with_path(
                    dir.path().join("config.json"),
                ),
                config: crate::config::ClientConfig::default(),
                state_store: crate::presentation::SharedStateStore::new(
                    LocalStateStore::with_path(dir.path().join("state.json")),
                ),
                initial_credential: String::new(),
                realm_tree_nodes: vec![],
            },
            Route::Chat {
                realm_id: "realm".into(),
                message: String::new(),
            },
            |_| Box::pin(std::future::pending()),
        );
        let mounts = Rc::new(Cell::new(0));
        let input = app.scope().cage(None);
        let draft = app.scope().cage(String::new());
        app.mount(route_boundary(app.scope(), context.clone(), {
            let context = context.clone();
            let mounts = mounts.clone();
            move |scope, route| {
                let description = context.server_description.get_untracked();
                if matches!(
                    super::super::route_surface::capability_phase(&route, description.as_ref()),
                    super::super::route_surface::CapabilityPhase::Ready
                ) {
                    mounts.set(mounts.get() + 1);
                    Box::new(
                        sapid::text_field()
                            .value(draft)
                            .node_ref(input)
                            .on_value_change(move |value| draft.revise(|draft| *draft = value)),
                    )
                } else {
                    super::super::feature_gate::feature_gate_notice(
                        scope,
                        context.clone(),
                        StationFeature::Discussion,
                        StationFeature::Discussion.missing_requirements(description.as_ref()),
                        description.is_none(),
                    )
                }
            }
        }))
        .unwrap();
        assert_eq!(mounts.get(), 0);
        assert!(input.get_untracked().is_none());
        context.server_description.revise(|value| {
            *value = Some(description(
                &["ak.operation_bundle.station.http_core_current.v1"],
                "one.example",
            ))
        });
        app.flush().unwrap();
        assert_eq!(mounts.get(), 1);
        let original = input
            .get_untracked()
            .expect("the capability-gated child mounted");
        let revision = {
            let tree = app.tree();
            let glory::render::Props::Input(props) =
                tree.node(original).unwrap().descriptor.view().props
            else {
                panic!("expected child editor")
            };
            props.revision
        };
        assert!(
            app.dispatch(
                original,
                glory::render::Event::ValueChanged {
                    value: "unsaved discussion draft".into(),
                    composing: false,
                    revision
                }
            )
            .unwrap()
        );
        context.server_description.revise(|value| {
            *value = Some(description(
                &[
                    "ak.operation_bundle.station.describe.v1",
                    "ak.operation_bundle.station.http_core_current.v1",
                ],
                "two.example",
            ))
        });
        app.flush().unwrap();
        assert_eq!(mounts.get(), 1);
        assert_eq!(input.get_untracked(), Some(original));
        assert_eq!(draft.get_untracked(), "unsaved discussion draft");
        context
            .server_description
            .revise(|value| *value = Some(description(&[], "two.example")));
        app.flush().unwrap();
        assert!(input.get_untracked().is_none());
        assert_eq!(draft.get_untracked(), "unsaved discussion draft");
        context.server_description.revise(|value| {
            *value = Some(description(
                &["ak.operation_bundle.station.http_core_current.v1"],
                "two.example",
            ))
        });
        app.flush().unwrap();
        assert_eq!(mounts.get(), 2);
        assert_ne!(input.get_untracked(), Some(original));
        assert_eq!(draft.get_untracked(), "unsaved discussion draft");
    }

    #[test]
    fn account_identity_keeps_short_display_and_complete_accessible_description() {
        use glory::render::Props;

        use super::*;

        let app = glory::App::memory();
        let full = "ak:device:01964137-0000-7000-8000-0000000000a1";
        let shortened = short_protocol_id(full);
        assert_ne!(shortened, full);
        app.mount(account_menu_identity(
            app.scope(),
            "mono",
            shortened.clone(),
            full,
            "account-device",
        ))
        .unwrap();
        let tree = app.tree();
        let mut pending = tree.roots().to_vec();
        let mut displayed = None;
        let mut description = None;
        while let Some(id) = pending.pop() {
            let node = tree.node(id).unwrap();
            let view = node.descriptor.view();
            if let Props::Text(value) = &view.props {
                if value.content == shortened {
                    displayed = view.semantics.as_ref().and_then(|s| s.described_by.clone());
                }
                if value.content == full {
                    description = view.semantics.as_ref().and_then(|s| s.id.clone());
                }
            }
            pending.extend(node.children.iter().copied());
        }
        assert!(description.is_some());
        assert_eq!(displayed, description);
    }

    #[test]
    fn account_trigger_keeps_its_node_when_the_avatar_revision_changes() {
        use super::*;
        fn class_nodes(app: &glory::App, class: &str) -> Vec<glory::render::NodeId> {
            let tree = app.tree();
            let mut pending: Vec<_> = tree.roots().to_vec();
            let mut found = Vec::new();
            while let Some(id) = pending.pop() {
                let node = tree.node(id).unwrap();
                if node
                    .descriptor
                    .view()
                    .classes
                    .iter()
                    .any(|value| value == class)
                {
                    found.push(id);
                }
                pending.extend(node.children.iter().copied());
            }
            found
        }
        fn trigger(app: &glory::App) -> glory::render::NodeId {
            *class_nodes(app, "account-menu-button")
                .first()
                .expect("account trigger")
        }
        let app = glory::App::memory();
        let dir = tempfile::tempdir().unwrap();
        let context = InksonContext::new(
            app.scope(),
            crate::presentation::BootState {
                config_store: crate::config::LocalConfigStore::with_path(
                    dir.path().join("config.json"),
                ),
                config: crate::config::ClientConfig::default(),
                state_store: crate::presentation::SharedStateStore::new(
                    LocalStateStore::with_path(dir.path().join("state.json")),
                ),
                initial_credential: String::new(),
                realm_tree_nodes: vec![],
            },
            Route::Dashboard,
            |_| Box::pin(std::future::pending()),
        );
        let ui = ShellState::new(app.scope(), &context);
        app.mount(account_menu(app.scope(), context.clone(), ui.clone()))
            .unwrap();
        let button = trigger(&app);
        for open in [true, false, true, false] {
            context
                .state_revision
                .revise(|revision| *revision = revision.wrapping_add(1));
            app.flush().unwrap();
            assert_eq!(trigger(&app), button);
            assert!(
                app.dispatch(button, glory::render::Event::Activate)
                    .unwrap()
            );
            app.flush().unwrap();
            assert_eq!(ui.account_open.get_untracked(), open);
            assert_eq!(trigger(&app), button);
        }
        ui.search_open.revise(|value| *value = true);
        ui.search_query
            .revise(|value| *value = "previous search".into());
        ui.server_open.revise(|value| *value = true);
        app.dispatch(button, glory::render::Event::Activate)
            .unwrap();
        app.flush().unwrap();
        assert!(ui.account_open.get_untracked());
        assert!(!ui.search_open.get_untracked());
        assert!(ui.search_query.get_untracked().is_empty());
        assert!(!ui.server_open.get_untracked());
        assert_eq!(class_nodes(&app, "account-menu__avatar").len(), 1);
        assert_eq!(class_nodes(&app, "account-menu__qr").len(), 1);
        let rows = class_nodes(&app, "account-menu__row");
        assert_eq!(rows.len(), 4);
        for row in rows {
            assert_eq!(app.tree().node(row).unwrap().children.iter().count(), 2);
        }
        let scrim = class_nodes(&app, "account-menu-scrim")[0];
        assert!(app.dispatch(scrim, glory::render::Event::Activate).unwrap());
        app.flush().unwrap();
        assert!(!ui.account_open.get_untracked());
        assert!(class_nodes(&app, "account-menu").is_empty());
        assert_eq!(trigger(&app), button);
    }

    fn item(id: &str, title: &str) -> crate::realm_tree::RealmTreeItem {
        crate::realm_tree::RealmTreeItem {
            node: crate::models::RealmTreeNode {
                id: id.to_owned(),
                title: title.to_owned(),
                description: None,
                tags: Default::default(),
                public: false,
                category: None,
                direct_conversation: false,
                parent_space_id: None,
                child_space_ids: Vec::new(),
                kind: crate::models::RealmTreeNodeKind::Realm,
                realm_id: id.to_owned(),
            },
            depth: 0,
            descendant_count: 0,
        }
    }

    #[test]
    fn mobile_realm_filter_empty_query_keeps_all_rows() {
        let rows = [item("ak:realm:one", "Alpha"), item("ak:realm:two", "Beta")];
        assert_eq!(filtered_mobile_realm_items(&rows, "").len(), 2);
    }

    #[test]
    fn mobile_realm_filter_matches_title_case_insensitively() {
        let rows = [
            item("ak:realm:one", "Alpha Team"),
            item("ak:realm:two", "Beta"),
        ];
        let filtered = filtered_mobile_realm_items(&rows, "aLpHa");
        assert_eq!(
            filtered
                .iter()
                .map(|item| item.node.id.as_str())
                .collect::<Vec<_>>(),
            vec!["ak:realm:one"]
        );
    }

    #[test]
    fn mobile_realm_filter_matches_id_case_insensitively() {
        let rows = [
            item("ak:realm:Project-X", "Alpha"),
            item("ak:realm:two", "Beta"),
        ];
        let filtered = filtered_mobile_realm_items(&rows, "project-x");
        assert_eq!(
            filtered
                .iter()
                .map(|item| item.node.id.as_str())
                .collect::<Vec<_>>(),
            vec!["ak:realm:Project-X"]
        );
    }

    #[test]
    fn mobile_realm_filter_returns_empty_for_no_match() {
        let rows = [item("ak:realm:one", "Alpha")];
        assert!(filtered_mobile_realm_items(&rows, "missing").is_empty());
    }
}
