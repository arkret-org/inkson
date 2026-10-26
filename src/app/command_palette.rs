use super::*;

/// Static list of jumpable destinations surfaced in the command palette.
/// Keep in sync with `routes::Route` — only views the user can act on are
/// listed.
pub(super) fn palette_destinations() -> Vec<(&'static str, &'static str, Route)> {
    vec![
        ("Home", "overview, recent activity", Route::Dashboard),
        (
            "Notifications",
            "inbox, mentions, approvals",
            Route::Notifications,
        ),
        ("Search", "messages across realms", Route::Search),
        ("Directory", "search realms, orgs, actors", Route::Directory),
        (
            "Onboarding",
            "DID, handle, device, recovery",
            Route::Onboarding,
        ),
        (
            "Settings",
            "account, encryption, push, server",
            Route::Settings,
        ),
        (
            "Recovery",
            "Recovery Key (24 words)",
            Route::SettingsRecovery,
        ),
        (
            "Quarantine",
            "review held invites (admin)",
            Route::Quarantine,
        ),
        (
            "New Realm",
            "create security boundary",
            Route::SetupSection {
                section: "realms".to_owned(),
            },
        ),
    ]
}

pub(super) fn palette_filter(query: &str, haystack: &str) -> bool {
    if query.is_empty() {
        return true;
    }
    let needle = query.trim().to_lowercase();
    let hay = haystack.to_lowercase();
    needle.split_whitespace().all(|token| hay.contains(token))
}

pub(super) fn close_palette(ui: &super::shell_state::ShellState) {
    ui.search_open.revise(|value| *value = false);
    ui.search_query.revise(String::clear);
}

fn palette_semantic_ids(
    scope: &glory::Scope,
) -> Option<(glory::render::SemanticId, glory::render::SemanticId)> {
    match (
        glory::render::SemanticId::new("topbar-command-query"),
        glory::render::SemanticId::new("topbar-command-results"),
    ) {
        (Ok(query), Ok(results)) => Some((query, results)),
        (Err(error), _) | (_, Err(error)) => {
            scope.report_error(error);
            None
        }
    }
}

pub(super) fn search_trigger(
    scope: &glory::Scope,
    ui: std::rc::Rc<super::shell_state::ShellState>,
) -> crate::presentation::View {
    let Some((_, results_id)) = palette_semantic_ids(scope) else {
        return crate::presentation::widgets::empty();
    };
    let open = ui.search_open;
    Box::new(
        glory::ui::button()
            .class("btn icon")
            .name("Search")
            .fill(crate::components::ui_icon("search"))
            .semantics(scope.bond(move || {
                Some(Box::new(glory::render::Semantics {
                    controls: open.get().then(|| results_id.clone()),
                    expanded: Some(open.get()),
                    popup: Some(glory::render::PopupKind::Dialog),
                    ..Default::default()
                }))
            }))
            .on(glory::render::EventKind::Activate, move |_| {
                if ui.search_open.get_untracked() {
                    close_palette(&ui);
                } else {
                    ui.search_open.revise(|open| *open = true);
                }
            }),
    )
}

pub(super) fn query_input(
    scope: &glory::Scope,
    context: std::rc::Rc<crate::presentation::InksonContext>,
    ui: std::rc::Rc<super::shell_state::ShellState>,
) -> crate::presentation::View {
    let Some((query_id, results_id)) = palette_semantic_ids(scope) else {
        return crate::presentation::widgets::empty();
    };
    let reference = scope.cage(None);
    let focused = scope.cage(false);
    let weak = scope.downgrade();
    scope.effect(move || {
        if !focused.get_untracked()
            && let Some(node) = reference.get()
            && let Some(scope) = weak.upgrade()
            && scope
                .capabilities()
                .is_ok_and(|capabilities| capabilities.focus)
        {
            match scope.action(glory::render::Action::Focus(node)) {
                Ok(()) => focused.revise(|value| *value = true),
                Err(error) => scope.report_error(error),
            }
        }
    });
    let changed = ui.clone();
    let keyboard_ui = ui.clone();
    Box::new(
        glory::ui::input()
            .class("global-search-input command-query")
            .name(context.translated(scope, "topbar.search_placeholder"))
            .node_ref(reference)
            .value(ui.search_query)
            .semantics(Some(Box::new(glory::render::Semantics {
                id: Some(query_id),
                controls: Some(results_id),
                ..Default::default()
            })))
            .on(glory::render::EventKind::ValueChanged, move |event| {
                if let glory::render::Event::ValueChanged { value, .. } = event {
                    changed.search_query.revise(|query| *query = value);
                    changed.search_open.revise(|open| *open = true);
                }
            })
            .on(glory::render::EventKind::Keyboard, move |event| {
                if let glory::render::Event::Keyboard { command, .. } = event {
                    match command {
                        glory::render::KeyboardCommand::Submit
                            if !keyboard_ui.search_query.get_untracked().trim().is_empty() =>
                        {
                            keyboard_ui.search_open.revise(|open| *open = false);
                            context.navigate(Route::Directory);
                        }
                        glory::render::KeyboardCommand::Dismiss => close_palette(&keyboard_ui),
                        _ => {}
                    }
                }
            }),
    )
}

pub(super) fn command_palette(
    scope: &glory::Scope,
    context: std::rc::Rc<crate::presentation::InksonContext>,
    query: String,
    nodes: Vec<RealmTreeNode>,
    ui: std::rc::Rc<super::shell_state::ShellState>,
) -> crate::presentation::View {
    use crate::presentation::widgets::*;
    let Some((query_id, results_id)) = palette_semantic_ids(scope) else {
        return empty();
    };
    let mut groups = Vec::new();
    let mut realms = Vec::new();
    for node in nodes
        .into_iter()
        .filter(|node| palette_filter(&query, &format!("{} {}", node.title, node.id)))
        .take(10)
    {
        let target = node.projection_realm_id().to_owned();
        let context = context.clone();
        let ui = ui.clone();
        realms.push(Box::new(
            sapid::button()
                .unstyled()
                .class("command-palette-item")
                .label(format!("{} {}", node.title, short_protocol_id(&node.id)))
                .on_press(move || {
                    context
                        .selected_realm_id
                        .revise(|value| *value = target.clone());
                    close_palette(&ui);
                    context.navigate(Route::Realm {
                        realm_id: target.clone(),
                    });
                }),
        ) as crate::presentation::View);
    }
    if !realms.is_empty() {
        realms.insert(
            0,
            paragraph(
                "command-palette-label",
                context.translated(scope, "command_palette.realms"),
            ),
        );
        groups.push(stack("command-palette-group", realms));
    }
    let mut destinations = Vec::new();
    for (label, hint, route) in palette_destinations()
        .into_iter()
        .filter(|(label, hint, _)| palette_filter(&query, &format!("{label} {hint}")))
    {
        let context = context.clone();
        let ui = ui.clone();
        destinations.push(Box::new(
            sapid::button()
                .unstyled()
                .class("command-palette-item")
                .name(format!("Navigate to {label}"))
                .fill((
                    glory::ui::text()
                        .class("command-palette-item-title")
                        .content(label),
                    glory::ui::text()
                        .class("command-palette-item-hint")
                        .content(hint),
                ))
                .on_press(move || {
                    close_palette(&ui);
                    context.navigate(route.clone());
                }),
        ) as crate::presentation::View);
    }
    if !destinations.is_empty() {
        destinations.insert(
            0,
            paragraph(
                "command-palette-label",
                context.translated(scope, "command_palette.jump_to"),
            ),
        );
        groups.push(stack("command-palette-group", destinations));
    }
    if groups.is_empty() {
        groups.push(paragraph(
            "command-palette-empty",
            context.translated(scope, "command_palette.empty"),
        ));
    }
    let close = ui.clone();
    groups.push(stack(
        "command-palette-footer",
        vec![Box::new(
            sapid::button()
                .unstyled()
                .class("btn command-palette-close")
                .label(context.translated(scope, "command_palette.close"))
                .on_press(move || close_palette(&close)),
        )],
    ));
    Box::new(
        glory::ui::view()
            .class("command-palette")
            .role(glory::render::Role::Dialog)
            .name("Command palette")
            .focus(glory::render::FocusMode::Programmatic)
            .style(glory::style::Style::new().position(glory::style::Position::Fixed))
            .semantics(Some(Box::new(glory::render::Semantics {
                id: Some(results_id),
                layer: Some(glory::render::Layer {
                    modal: false,
                    focus: glory::render::LayerFocus::Preserve,
                    placement: glory::render::LayerPlacement::Anchor(
                        glory::render::AnchorPlacement::new(
                            glory::render::AnchorSide::Bottom,
                            glory::render::AnchorAlign::End,
                        )
                        .gap(8.0),
                    ),
                    anchor: Some(query_id),
                    ..Default::default()
                }),
                ..Default::default()
            })))
            .on(glory::render::EventKind::Dismiss, {
                let ui = ui.clone();
                move |_| close_palette(&ui)
            })
            .on(glory::render::EventKind::Keyboard, move |event| {
                if matches!(
                    event,
                    glory::render::Event::Keyboard {
                        command: glory::render::KeyboardCommand::Dismiss,
                        ..
                    }
                ) {
                    close_palette(&ui);
                }
            })
            .fill(groups),
    )
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod keyboard_tests;
