use super::*;

/// Session-lifetime owner for global effects and the authenticated/auth shell
/// surface. Bootstrap constructs stable service contexts; this component owns
/// effects that must be torn down when the shell itself is unmounted.
#[component]
pub(super) fn SessionShell(
    locale: Signal<UiLocale>,
    i18n_signal: crate::i18n::I18nSignal,
    base_url: Signal<String>,
    token: Signal<String>,
    state_store: SyncSignal<LocalStateStore>,
    last_error: Signal<Option<String>>,
    secure_store_bootstrap_ready: Signal<bool>,
    is_server_admin: Signal<bool>,
    theme: Signal<String>,
    system_theme_is_night: Signal<bool>,
    children: Element,
) -> Element {
    rsx! {
        GlobalEffects {
            locale,
            i18n_signal,
            base_url,
            token,
            state_store,
            last_error,
            secure_store_bootstrap_ready,
            is_server_admin,
            theme,
            system_theme_is_night,
        }
        {children}
    }
}

/// Keeps the auth/app-shell boundary as one stable component node while only
/// mounting the active surface. The small conditional template here prevents
/// either surface's internal RSX from changing the parent template shape.
#[component]
pub(super) fn SessionSurface(
    is_app_shell: bool,
    auth_shell: Element,
    children: Element,
) -> Element {
    rsx! {
        if is_app_shell {
            {children}
        } else {
            {auth_shell}
        }
    }
}

#[component]
pub(super) fn MobileConnectionStatus(
    connection_status: Signal<String>,
    sync_cursor: Signal<String>,
    on_refresh: EventHandler<()>,
) -> Element {
    rsx! {
        div { class: "mobile-status", "data-testid": "mobile-connection-status",
            span { "data-testid": "mobile-status-label", "{connection_status}" }
            span { class: "muted mono", "data-testid": "mobile-sync-cursor", "cursor {sync_cursor}" }
            Button {
                variant: ButtonVariant::Primary,
                "data-testid": "mobile-connect-button",
                title: "Refresh server metadata and sync state",
                "aria-label": "Refresh server metadata and sync state",
                onclick: move |_| on_refresh.call(()),
                "Refresh"
            }
        }
    }
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

#[component]
pub(super) fn MobileRealmTree(
    has_realms: bool,
    realm_tree: Vec<crate::realm_tree::RealmTreeItem>,
    mobile_space_query: Signal<String>,
    selected_realm_id: Signal<String>,
    mobile_nav_open: Signal<bool>,
) -> Element {
    let realm_count_label = format!(
        "{} ({})",
        crate::i18n::tr("command_palette.realms"),
        realm_tree.len()
    );
    rsx! {
        if has_realms {
            div { class: "muted", "{realm_count_label}" }
            Input {
                class: "mobile-realm-tree-filter",
                "data-testid": "mobile-realm-tree-filter",
                value: "{mobile_space_query}",
                placeholder: crate::i18n::tr("mobile.filter_realms"),
                oninput: move |event: FormEvent| mobile_space_query.set(event.value()),
            }
            div { class: "mobile-realm-tree-list", "data-testid": "mobile-realm-tree-list",
                {
                    let query = mobile_space_query();
                    let filtered = filtered_mobile_realm_items(&realm_tree, &query);
                    if filtered.is_empty() {
                        rsx! {
                            div { class: "muted", "data-testid": "mobile-realm-tree-empty", {crate::i18n::tr("mobile.no_match")} }
                        }
                    } else {
                        rsx! {
                            for item in filtered {
                                Link {
                                    class: "secondary",
                                    "data-testid": "mobile-realm-tree-nav-button",
                                    to: Route::Realm {
                                        realm_id: item.node.projection_realm_id().to_owned()
                                    },
                                    onclick: {
                                        let id = item.node.projection_realm_id().to_owned();
                                        move |_| {
                                            selected_realm_id.set(id.clone());
                                            mobile_nav_open.set(false);
                                            mobile_space_query.set(String::new());
                                        }
                                    },
                                    "{item.node.title}"
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

/// Owns the complete mobile drawer template. Keeping the drawer root and its
/// primary links in one component prevents surrounding shell reconciliation
/// from moving those links outside the hidden navigation container.
#[component]
pub(super) fn MobileNavDrawer(
    mobile_nav_open: Signal<bool>,
    status: Element,
    realm_tree: Element,
) -> Element {
    rsx! {
        nav {
            id: "mobile-navigation-drawer",
            class: if mobile_nav_open() { "mobile-drawer open" } else { "mobile-drawer" },
            "data-testid": "mobile-nav-drawer",
            {status}
            div { class: "mobile-primary-nav",
                Link { class: "secondary", "data-testid": "mobile-dashboard-nav-button", to: Route::Dashboard, onclick: move |_| mobile_nav_open.set(false), {crate::i18n::tr("nav.dashboard")} }
                Link { class: "secondary", "data-testid": "mobile-directory-nav-button", to: Route::Directory, onclick: move |_| mobile_nav_open.set(false), {crate::i18n::tr("nav.directory")} }
                Link { class: "secondary", "data-testid": "mobile-settings-nav-button", to: Route::Settings, onclick: move |_| mobile_nav_open.set(false), {crate::i18n::tr("nav.settings")} }
            }
            {realm_tree}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::filtered_mobile_realm_items;

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
