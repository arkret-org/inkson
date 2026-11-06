use super::*;

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
                section: "realms".into(),
            },
        ),
    ]
}

pub(super) fn palette_filter(query: &str, haystack: &str) -> bool {
    let haystack = haystack.to_lowercase();
    query
        .trim()
        .to_lowercase()
        .split_whitespace()
        .all(|token| haystack.contains(token))
}

pub(super) fn close_palette(ui: &super::shell_state::ShellState) {
    ui.search_open.revise(|value| *value = false);
    ui.search_query.revise(String::clear);
}

pub(super) fn search_trigger(
    _scope: &glory::Scope,
    ui: std::rc::Rc<super::shell_state::ShellState>,
) -> crate::presentation::View {
    Box::new(
        sapid::button()
            .unstyled()
            .class("btn icon command-palette-trigger")
            .name("Search")
            .fill(crate::components::ui_icon("search"))
            .on_press(move || {
                if ui.search_open.get_untracked() {
                    close_palette(&ui);
                } else {
                    ui.search_open.revise(|value| *value = true);
                }
            }),
    )
}

pub(super) fn command_palette(
    scope: &glory::Scope,
    context: std::rc::Rc<crate::presentation::InksonContext>,
    ui: std::rc::Rc<super::shell_state::ShellState>,
) -> crate::presentation::View {
    let snapshot = scope.bond({
        let context = context.clone();
        let ui = ui.clone();
        move || {
            let query = ui.search_query.get();
            let _ = context.locale.get();
            let mut actions = Vec::new();
            let mut targets = std::collections::BTreeMap::new();
            if !query.trim().is_empty() {
                actions.push(
                    sapid::command_action("search-directory", context.tr("route.directory"))
                        .description(query.chars().take(256).collect::<String>())
                        .group("search"),
                );
                targets.insert("search-directory".to_owned(), Route::Directory);
            }
            for (index, node) in context
                .realm_tree_nodes
                .get()
                .into_iter()
                .enumerate()
                .filter(|(_, node)| palette_filter(&query, &format!("{} {}", node.title, node.id)))
                .take(10)
            {
                let key = format!("realm-{index}");
                actions.push(
                    sapid::command_action(
                        key.clone(),
                        node.title.chars().take(64).collect::<String>(),
                    )
                    .description(short_protocol_id(&node.id))
                    .group("realms"),
                );
                targets.insert(
                    key,
                    Route::Realm {
                        realm_id: node.projection_realm_id().to_owned(),
                    },
                );
            }
            for (index, (label, hint, route)) in palette_destinations()
                .into_iter()
                .enumerate()
                .filter(|(_, (label, hint, _))| palette_filter(&query, &format!("{label} {hint}")))
            {
                let key = format!("destination-{index}");
                actions.push(
                    sapid::command_action(key.clone(), label)
                        .description(hint)
                        .group("destinations"),
                );
                targets.insert(key, route);
            }
            let results = sapid::CommandResults {
                actions,
                groups: vec![
                    sapid::command_group("search", context.tr("route.directory")),
                    sapid::command_group("realms", context.tr("command_palette.realms")),
                    sapid::command_group("destinations", context.tr("command_palette.jump_to")),
                ],
            };
            (sapid::CommandResponse { query, results }, targets)
        }
    });
    let results = scope.bond(move || snapshot.get().0);
    let opened = ui.clone();
    let searched = ui.clone();
    Box::new(
        sapid::command("global-command-palette")
            .unstyled()
            .class("command-palette")
            .label("Command palette")
            .open(ui.search_open)
            .search(ui.search_query)
            .results(results)
            .on_open_change(move |open| {
                if open {
                    opened.search_open.revise(|value| *value = true);
                } else {
                    close_palette(&opened);
                }
            })
            .on_search_change(move |query| searched.search_query.revise(|value| *value = query))
            .on_action(move |key| {
                if let Some(route) = snapshot.get_untracked().1.get(&key).cloned() {
                    if let Route::Realm { realm_id } = &route {
                        context
                            .selected_realm_id
                            .revise(|value| *value = realm_id.clone());
                    }
                    close_palette(&ui);
                    context.navigate(route);
                }
            }),
    )
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod keyboard_tests;
