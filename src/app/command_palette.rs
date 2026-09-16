use super::*;

/// Static list of jumpable destinations surfaced in the command palette.
/// Keep in sync with `routes::Route` — only views the user can act on are
/// listed.
pub(super) fn palette_destinations() -> Vec<(&'static str, &'static str, Route)> {
    vec![
        ("Home", "overview, recent activity", Route::Dashboard),
        ("Files", "private file transfer", Route::FileTransfer),
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

#[component]
pub(super) fn CommandPalette(
    query: String,
    nodes: Vec<RealmTreeNode>,
    on_navigate: EventHandler<Route>,
    on_pick_realm: EventHandler<String>,
    on_close: EventHandler<()>,
) -> Element {
    let dest_list = palette_destinations();
    let matched_dests: Vec<_> = dest_list
        .iter()
        .filter(|(label, hint, _)| palette_filter(&query, &format!("{label} {hint}")))
        .cloned()
        .collect();
    let matched_nodes: Vec<RealmTreeNode> = nodes
        .iter()
        .filter(|node| palette_filter(&query, &format!("{} {}", node.title, node.id)))
        .take(10)
        .cloned()
        .collect();

    rsx! {
        div {
            class: "command-palette",
            "data-testid": "command-palette",
            role: "listbox",
            "aria-label": "Command palette",
            if matched_nodes.is_empty() && matched_dests.is_empty() {
                div { class: "command-palette-empty", "data-testid": "command-palette-empty",
                    {crate::i18n::tr("command_palette.empty")}
                }
            }
            if !matched_nodes.is_empty() {
                div { class: "command-palette-group",
                    div { class: "command-palette-label", {crate::i18n::tr("command_palette.realms")} }
                    for node in matched_nodes.iter() {
                        {
                            let node_id_label = short_protocol_id(&node.id);
                            let target_realm_id = node.projection_realm_id().to_owned();
                            let node_kind_label = match node.kind {
                                RealmTreeNodeKind::Realm => crate::i18n::tr("friendly.realm"),
                                RealmTreeNodeKind::Space => crate::i18n::tr("friendly.space"),
                            };
                            rsx! {
                                Button {
                                    variant: ButtonVariant::Secondary,
                                    class: "command-palette-item",
                                    "data-testid": "command-palette-realm-tree-node",
                                    role: "option",
                                    "aria-label": "Open {node_kind_label} {node.title}",
                                    onclick: {
                                        let realm_id = target_realm_id.clone();
                                        move |_| on_pick_realm.call(realm_id.clone())
                                    },
                                    span { class: "command-palette-item-title", "{node.title}" }
                                    span { class: "command-palette-item-hint", title: "{node.id}", "{node_id_label}" }
                                }
                            }
                        }
                    }
                }
            }
            if !matched_dests.is_empty() {
                div { class: "command-palette-group",
                    div { class: "command-palette-label", {crate::i18n::tr("command_palette.jump_to")} }
                    for (label, hint, route) in matched_dests.iter() {
                        Button {
                            variant: ButtonVariant::Secondary,
                            class: "command-palette-item",
                            "data-testid": "command-palette-dest",
                            role: "option",
                            "aria-label": "Navigate to {label}",
                            onclick: {
                                let route = route.clone();
                                move |_| on_navigate.call(route.clone())
                            },
                            span { class: "command-palette-item-title", "{label}" }
                            span { class: "command-palette-item-hint", "{hint}" }
                        }
                    }
                }
            }
            div { class: "command-palette-footer",
                Button {
                    variant: ButtonVariant::Ghost,
                    size: ButtonSize::Sm,
                    class: "btn",
                    "data-testid": "command-palette-close",
                    "aria-label": "Close command palette",
                    onclick: move |_| on_close.call(()),
                    {crate::i18n::tr("command_palette.close")}
                }
            }
        }
    }
}
