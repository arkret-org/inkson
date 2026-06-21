use super::*;

pub(super) fn contact_manage_scope_summary(contact: &crate::models::ContactListRow) -> String {
    let mut seen = BTreeSet::<String>::new();
    for scope in contact
        .bidirectional_scopes
        .iter()
        .chain(contact.effective_scopes.iter())
        .chain(contact.granted_by_me.iter())
        .chain(contact.granted_to_me.iter())
    {
        if !scope.trim().is_empty() {
            seen.insert(scope.clone());
        }
    }
    if seen.is_empty() {
        "No shared scopes".to_owned()
    } else {
        seen.into_iter().collect::<Vec<_>>().join(", ")
    }
}

#[component]
pub(super) fn RealmsManagePage(
    base_url: String,
    account_did: String,
    token: Signal<String>,
    has_session: bool,
    realm_rows: Vec<RealmManageRow>,
    mut realm_tree_nodes: Signal<Vec<RealmTreeNode>>,
    mut selected_realm_id: Signal<String>,
    mut sync_cursor: Signal<String>,
    mut state_store: Signal<LocalStateStore>,
    mut query: Signal<String>,
    mut selection: Signal<BTreeSet<String>>,
    mut busy: Signal<bool>,
    mut status: Signal<String>,
) -> Element {
    let normalized_query = query().trim().to_ascii_lowercase();
    let filtered_rows = realm_rows
        .iter()
        .filter(|row| {
            sidebar_text_matches_query(
                &normalized_query,
                &[&row.realm_id, &row.title, &row.display_name],
            )
        })
        .cloned()
        .collect::<Vec<_>>();
    let selected_ids = selection.read().clone();
    let selection_count = selected_ids.len();

    rsx! {
        div { class: "settings workspace-manage-page", "data-testid": "realms-manage-page",
            div { class: "settings-shell workspace-manage-shell",
                section { class: "settings-content-stack workspace-manage-main",
                    div { class: "event workspace-manage-hero",
                        div { class: "workspace-manage-title-block",
                            span { class: "workspace-manage-icon", UiIcon { name: "home" } }
                            div {
                                h2 { class: "settings-content-title", "Manage Realms" }
                                div { class: "muted", "Bulk leave Realms and remove their local tree projections after the server confirms." }
                            }
                        }
                        div { class: "workspace-manage-stats",
                            span { class: "pill muted xs", "{filtered_rows.len()} shown" }
                            span { class: "pill muted xs", "{realm_rows.len()} total" }
                            span { class: "pill muted xs", "{selection_count} selected" }
                        }
                    }

                    div { class: "event workspace-manage-toolbar", "data-testid": "realms-manage-toolbar",
                        div { class: "workspace-manage-search",
                            span { class: "workspace-manage-search-icon", UiIcon { name: "search" } }
                            Input {
                                "data-testid": "realms-manage-search-input",
                                value: "{query}",
                                placeholder: "Search Realms",
                                oninput: move |event: FormEvent| query.set(event.value()),
                            }
                        }
                        div { class: "actions workspace-manage-actions",
                            Button {
                                variant: ButtonVariant::Secondary,
                                size: ButtonSize::Sm,
                                r#type: "button",
                                "data-testid": "realms-manage-select-all",
                                disabled: filtered_rows.is_empty() || busy(),
                                onclick: {
                                    let realm_ids = filtered_rows
                                        .iter()
                                        .map(|row| row.realm_id.clone())
                                        .collect::<BTreeSet<_>>();
                                    move |_| selection.set(realm_ids.clone())
                                },
                                "Select shown"
                            }
                            Button {
                                variant: ButtonVariant::Secondary,
                                size: ButtonSize::Sm,
                                r#type: "button",
                                "data-testid": "realms-manage-clear",
                                disabled: selection_count == 0 || busy(),
                                onclick: move |_| selection.set(BTreeSet::new()),
                                "Clear"
                            }
                            Button {
                                variant: ButtonVariant::Destructive,
                                size: ButtonSize::Sm,
                                r#type: "button",
                                "data-testid": "realms-manage-leave-selected",
                                disabled: selection_count == 0 || busy() || !has_session,
                                onclick: {
                                    let base = base_url.clone();
                                    let actor_account_did = account_did.clone();
                                    move |_| {
                                        if busy() {
                                            return;
                                        }
                                        let selected = selection
                                            .read()
                                            .iter()
                                            .cloned()
                                            .collect::<Vec<_>>();
                                        if selected.is_empty() {
                                            return;
                                        }
                                        // Membership events are authored by the account/principal
                                        // DID (the authenticated session actor), not the local device DID,
                                        // or the server rejects them with `actor_session_mismatch`.
                                        let actor_id = actor_account_did.clone();
                                        if actor_id.trim().is_empty() {
                                            status.set("Leave selected failed: account is not connected".to_owned());
                                            return;
                                        }
                                        let current_nodes = realm_tree_nodes();
                                        let ids_to_forget_by_realm = selected
                                            .iter()
                                            .map(|realm_id| {
                                                let mut ids = descendant_node_ids(&current_nodes, realm_id);
                                                if ids.is_empty() {
                                                    ids.push(realm_id.clone());
                                                }
                                                (realm_id.clone(), ids)
                                            })
                                            .collect::<BTreeMap<_, _>>();
                                        let total = selected.len();
                                        let api_token = token();
                                        let base = base.clone();
                                        busy.set(true);
                                        status.set(format!("Leaving {total} Realm(s)..."));
                                        spawn(async move {
                                            let mut succeeded = BTreeSet::<String>::new();
                                            let mut forgotten_ids = BTreeSet::<String>::new();
                                            let mut failed = Vec::<String>::new();
                                            for realm_id in selected {
                                                let realm_for_api = realm_id.clone();
                                                let actor_for_api = actor_id.clone();
                                                match crate::views::helpers::with_authed_api(
                                                    &base,
                                                    api_token.clone(),
                                                    |api| async move {
                                                        api.leave_realm(&realm_for_api, &actor_for_api).await
                                                    },
                                                )
                                                .await
                                                {
                                                    Ok(_) => {
                                                        succeeded.insert(realm_id.clone());
                                                        if let Some(ids) = ids_to_forget_by_realm.get(&realm_id) {
                                                            for id in ids {
                                                                state_store.write().forget_realm_tree_projection(id);
                                                                forgotten_ids.insert(id.clone());
                                                            }
                                                        }
                                                    }
                                                    Err(err) => failed.push(format!(
                                                        "{} ({})",
                                                        short_protocol_id(&realm_id),
                                                        err.display()
                                                    )),
                                                }
                                            }

                                            if !forgotten_ids.is_empty() {
                                                realm_tree_nodes.set(
                                                    realm_tree_nodes()
                                                        .into_iter()
                                                        .filter(|node| !forgotten_ids.contains(&node.id))
                                                        .collect(),
                                                );
                                                if forgotten_ids.contains(&selected_realm_id()) {
                                                    selected_realm_id.set(String::new());
                                                }
                                                sync_cursor.set("-".to_owned());
                                            }
                                            if !succeeded.is_empty() {
                                                let mut next_selection = selection();
                                                for realm_id in &succeeded {
                                                    next_selection.remove(realm_id);
                                                }
                                                selection.set(next_selection);
                                            }

                                            busy.set(false);
                                            if failed.is_empty() {
                                                status.set(format!(
                                                    "Left {} of {total} Realm(s).",
                                                    succeeded.len()
                                                ));
                                            } else {
                                                status.set(format!(
                                                    "Left {} of {total}; failed: {}",
                                                    succeeded.len(),
                                                    failed.join(", ")
                                                ));
                                            }
                                        });
                                    }
                                },
                                if busy() { "Leaving..." } else { "Leave selected" }
                            }
                        }
                    }

                    if !status.read().is_empty() {
                        div { class: "event workspace-manage-status", "data-testid": "realms-manage-status",
                            "{status}"
                        }
                    }

                    div { class: "event workspace-manage-list-card",
                        div { class: "event-head",
                            span { "Realms" }
                            span { "{filtered_rows.len()} rows" }
                        }
                        if realm_rows.is_empty() {
                            div { class: "members-empty", "data-testid": "realms-manage-empty",
                                div { class: "members-empty-title", if has_session { "No Realm tree loaded" } else { "Sign in to load Realms" } }
                                div { class: "muted members-empty-hint", "Realms will appear here after sync loads the collaboration tree." }
                            }
                        } else if filtered_rows.is_empty() {
                            div { class: "members-empty", "data-testid": "realms-manage-no-results",
                                div { class: "members-empty-title", "No matching Realms" }
                                div { class: "muted members-empty-hint", "Adjust the search query to show more rows." }
                            }
                        } else {
                            div { class: "workspace-manage-list", "data-testid": "realms-manage-list",
                                for row in filtered_rows {
                                    {
                                        let realm_id = row.realm_id.clone();
                                        let checked = selected_ids.contains(&realm_id);
                                        let security_label = if row.encrypted { "Encrypted" } else { "Unencrypted" };
                                        let security_icon = if row.encrypted { "lock" } else { "unlock" };
                                        rsx! {
                                            label {
                                                class: "workspace-manage-row",
                                                "data-testid": "realms-manage-row",
                                                "data-realm-id": "{realm_id}",
                                                Checkbox {
                                                    checked: if checked { CheckboxState::Checked } else { CheckboxState::Unchecked },
                                                    on_checked_change: {
                                                        let realm_id = realm_id.clone();
                                                        move |state: CheckboxState| {
                                                            let mut next = selection();
                                                            if bool::from(state) {
                                                                next.insert(realm_id.clone());
                                                            } else {
                                                                next.remove(&realm_id);
                                                            }
                                                            selection.set(next);
                                                        }
                                                    },
                                                }
                                                div { class: "workspace-manage-row-main",
                                                    strong { title: "{row.title}", "{row.display_name}" }
                                                    span { class: "muted mono", title: "{realm_id}", "{realm_id}" }
                                                }
                                                div { class: "workspace-manage-row-meta",
                                                    span { class: "pill muted xs", title: "{security_label}",
                                                        UiIcon { name: security_icon }
                                                        "{security_label}"
                                                    }
                                                    span { class: "pill muted xs", "{row.space_count} spaces" }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

#[component]
pub(super) fn ContactsManagePage(
    base_url: String,
    token: Signal<String>,
    has_session: bool,
    mut contact_rows: Signal<Vec<crate::models::ContactListRow>>,
    mut contacts_loaded: Signal<bool>,
    mut app_status: Signal<String>,
    mut query: Signal<String>,
    mut selection: Signal<BTreeSet<String>>,
    mut busy: Signal<bool>,
    mut status: Signal<String>,
) -> Element {
    {
        let base = base_url.clone();
        use_effect(move || {
            if contacts_loaded() || token().trim().is_empty() {
                return;
            }
            load_direct_contacts_for_sidebar(
                base.clone(),
                token(),
                contact_rows,
                contacts_loaded,
                app_status,
            );
        });
    }

    let rows = contact_rows.read().clone();
    let normalized_query = query().trim().to_ascii_lowercase();
    let filtered_rows = rows
        .iter()
        .filter(|contact| {
            let scopes = contact_manage_scope_summary(contact);
            sidebar_text_matches_query(&normalized_query, &[&contact.peer, &contact.state, &scopes])
        })
        .cloned()
        .collect::<Vec<_>>();
    let selected_ids = selection.read().clone();
    let selection_count = selected_ids.len();

    rsx! {
        div { class: "settings workspace-manage-page", "data-testid": "contacts-manage-page",
            div { class: "settings-shell workspace-manage-shell",
                section { class: "settings-content-stack workspace-manage-main",
                    div { class: "event workspace-manage-hero",
                        div { class: "workspace-manage-title-block",
                            span { class: "workspace-manage-icon", UiIcon { name: "users" } }
                            div {
                                h2 { class: "settings-content-title", "Manage Contacts" }
                                div { class: "muted", "Bulk delete contacts and keep successful rows out of the current contact list." }
                            }
                        }
                        div { class: "workspace-manage-stats",
                            span { class: "pill muted xs", "{filtered_rows.len()} shown" }
                            span { class: "pill muted xs", "{rows.len()} total" }
                            span { class: "pill muted xs", "{selection_count} selected" }
                        }
                    }

                    div { class: "event workspace-manage-toolbar", "data-testid": "contacts-manage-toolbar",
                        div { class: "workspace-manage-search",
                            span { class: "workspace-manage-search-icon", UiIcon { name: "search" } }
                            Input {
                                "data-testid": "contacts-manage-search-input",
                                value: "{query}",
                                placeholder: "Search Contacts",
                                oninput: move |event: FormEvent| query.set(event.value()),
                            }
                        }
                        div { class: "actions workspace-manage-actions",
                            Button {
                                variant: ButtonVariant::Secondary,
                                size: ButtonSize::Sm,
                                r#type: "button",
                                "data-testid": "contacts-manage-select-all",
                                disabled: filtered_rows.is_empty() || busy(),
                                onclick: {
                                    let peers = filtered_rows
                                        .iter()
                                        .map(|contact| contact.peer.clone())
                                        .collect::<BTreeSet<_>>();
                                    move |_| selection.set(peers.clone())
                                },
                                "Select shown"
                            }
                            Button {
                                variant: ButtonVariant::Secondary,
                                size: ButtonSize::Sm,
                                r#type: "button",
                                "data-testid": "contacts-manage-clear",
                                disabled: selection_count == 0 || busy(),
                                onclick: move |_| selection.set(BTreeSet::new()),
                                "Clear"
                            }
                            Button {
                                variant: ButtonVariant::Destructive,
                                size: ButtonSize::Sm,
                                r#type: "button",
                                "data-testid": "contacts-manage-delete-selected",
                                disabled: selection_count == 0 || busy() || !has_session,
                                onclick: {
                                    let base = base_url.clone();
                                    move |_| {
                                        if busy() {
                                            return;
                                        }
                                        let selected = selection
                                            .read()
                                            .iter()
                                            .cloned()
                                            .collect::<Vec<_>>();
                                        if selected.is_empty() {
                                            return;
                                        }
                                        let total = selected.len();
                                        let api_token = token();
                                        let base = base.clone();
                                        busy.set(true);
                                        status.set(format!("Deleting {total} contact(s)..."));
                                        spawn(async move {
                                            let mut succeeded = BTreeSet::<String>::new();
                                            let mut failed = Vec::<String>::new();
                                            for peer in selected {
                                                let peer_for_api = peer.clone();
                                                match crate::views::helpers::with_authed_api(
                                                    &base,
                                                    api_token.clone(),
                                                    |api| async move {
                                                        api.tombstone_contact(&peer_for_api, false).await
                                                    },
                                                )
                                                .await
                                                {
                                                    Ok(_) => {
                                                        succeeded.insert(peer);
                                                    }
                                                    Err(err) => failed.push(format!(
                                                        "{} ({})",
                                                        short_protocol_id(&peer),
                                                        err.display()
                                                    )),
                                                }
                                            }

                                            if !succeeded.is_empty() {
                                                let mut next_selection = selection();
                                                for peer in &succeeded {
                                                    next_selection.remove(peer);
                                                }
                                                selection.set(next_selection);
                                                match crate::views::helpers::with_authed_api(
                                                    &base,
                                                    api_token.clone(),
                                                    |api| async move { api.contacts().await },
                                                )
                                                .await
                                                {
                                                    Ok(response) => {
                                                        contact_rows.set(response.contacts);
                                                        contacts_loaded.set(true);
                                                    }
                                                    Err(err) => app_status.set(format!(
                                                        "contacts refresh: {}",
                                                        err.display()
                                                    )),
                                                }
                                            }

                                            busy.set(false);
                                            if failed.is_empty() {
                                                status.set(format!(
                                                    "Deleted {} of {total} contact(s).",
                                                    succeeded.len()
                                                ));
                                            } else {
                                                status.set(format!(
                                                    "Deleted {} of {total}; failed: {}",
                                                    succeeded.len(),
                                                    failed.join(", ")
                                                ));
                                            }
                                        });
                                    }
                                },
                                if busy() { "Deleting..." } else { "Delete selected" }
                            }
                        }
                    }

                    if !status.read().is_empty() {
                        div { class: "event workspace-manage-status", "data-testid": "contacts-manage-status",
                            "{status}"
                        }
                    }

                    div { class: "event workspace-manage-list-card",
                        div { class: "event-head",
                            span { "Contacts" }
                            span { "{filtered_rows.len()} rows" }
                        }
                        if rows.is_empty() {
                            div { class: "members-empty", "data-testid": "contacts-manage-empty",
                                div { class: "members-empty-title",
                                    {if has_session { crate::i18n::tr("contacts.empty") } else { crate::i18n::tr("contacts.sign_in") }}
                                }
                                div { class: "muted members-empty-hint", "Accepted, pending, and tombstoned contact rows appear here after loading." }
                            }
                        } else if filtered_rows.is_empty() {
                            div { class: "members-empty", "data-testid": "contacts-manage-no-results",
                                div { class: "members-empty-title", "No matching contacts" }
                                div { class: "muted members-empty-hint", "Adjust the search query to show more rows." }
                            }
                        } else {
                            div { class: "workspace-manage-list", "data-testid": "contacts-manage-list",
                                for contact in filtered_rows {
                                    {
                                        let peer = contact.peer.clone();
                                        let checked = selected_ids.contains(&peer);
                                        let scopes_label = contact_manage_scope_summary(&contact);
                                        let direct_label = contact
                                            .direct_conversation
                                            .as_ref()
                                            .map(|summary| format!("DM {}", summary.state))
                                            .unwrap_or_else(|| "No DM".to_owned());
                                        rsx! {
                                            label {
                                                class: "workspace-manage-row",
                                                "data-testid": "contacts-manage-row",
                                                "data-peer": "{peer}",
                                                Checkbox {
                                                    checked: if checked { CheckboxState::Checked } else { CheckboxState::Unchecked },
                                                    on_checked_change: {
                                                        let peer = peer.clone();
                                                        move |state: CheckboxState| {
                                                            let mut next = selection();
                                                            if bool::from(state) {
                                                                next.insert(peer.clone());
                                                            } else {
                                                                next.remove(&peer);
                                                            }
                                                            selection.set(next);
                                                        }
                                                    },
                                                }
                                                div { class: "workspace-manage-row-main",
                                                    strong { title: "{peer}", "{peer}" }
                                                    span { class: "muted", title: "{scopes_label}", "{scopes_label}" }
                                                }
                                                div { class: "workspace-manage-row-meta",
                                                    span { class: "pill muted xs", "{contact.state}" }
                                                    span { class: "pill muted xs", "{direct_label}" }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
