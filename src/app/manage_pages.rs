use super::*;

pub(super) fn contact_manage_scope_summary(contact: &crate::models::ContactListRow) -> String {
    let mut seen = BTreeSet::<String>::new();
    for scope in contact
        .bidirectional_scopes
        .iter()
        .chain(contact.effective_scopes.iter().flatten())
        .chain(contact.granted_to_peer_scopes.iter())
        .chain(contact.granted_by_peer_scopes.iter())
    {
        seen.insert(crate::models::contact_scope_wire(*scope).to_owned());
    }
    if seen.is_empty() {
        crate::i18n::tr("manage.contact_no_scopes")
    } else {
        seen.into_iter().collect::<Vec<_>>().join(", ")
    }
}

#[component]
pub(super) fn RealmsManagePage(
    principal_id: String,
    token: Signal<String>,
    has_session: bool,
    realm_rows: Vec<RealmManageRow>,
    mut realm_tree_nodes: Signal<Vec<RealmTreeNode>>,
    mut selected_realm_id: Signal<String>,
    mut sync_cursor: Signal<String>,
    mut query: Signal<String>,
    mut selection: Signal<BTreeSet<String>>,
    mut busy: Signal<bool>,
) -> Element {
    // A4 — base_url / state_store from session context instead of props.
    let base_url = crate::app::SessionContext::base_url_string();
    let mut state_store = crate::app::SessionContext::get().state_store;
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
        div { class: "settings realm-manage-page", "data-testid": "realms-manage-page",
            div { class: "settings-shell realm-manage-shell",
                section { class: "settings-content-stack realm-manage-main",
                    div { class: "event realm-manage-hero",
                        div { class: "realm-manage-title-block",
                            span { class: "realm-manage-icon", UiIcon { name: "home" } }
                            div {
                                h2 { class: "settings-content-title", {crate::i18n::tr("manage.realms_title")} }
                                div { class: "muted", {crate::i18n::tr("manage.realms_subtitle")} }
                            }
                        }
                        div { class: "realm-manage-stats",
                            span { class: "pill muted xs", {crate::i18n::tr_args("manage.stats_shown", &[("count", filtered_rows.len().to_string())])} }
                            span { class: "pill muted xs", {crate::i18n::tr_args("manage.stats_total", &[("count", realm_rows.len().to_string())])} }
                            span { class: "pill muted xs", {crate::i18n::tr_args("manage.stats_selected", &[("count", selection_count.to_string())])} }
                        }
                    }

                    div { class: "event realm-manage-toolbar", "data-testid": "realms-manage-toolbar",
                        div { class: "realm-manage-search",
                            span { class: "realm-manage-search-icon", UiIcon { name: "search" } }
                            Input {
                                "data-testid": "realms-manage-search-input",
                                value: "{query}",
                                placeholder: crate::i18n::tr("sidebar.search_realms"),
                                oninput: move |event: FormEvent| query.set(event.value()),
                            }
                        }
                        div { class: "actions realm-manage-actions",
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
                                {crate::i18n::tr("manage.select_shown")}
                            }
                            Button {
                                variant: ButtonVariant::Secondary,
                                size: ButtonSize::Sm,
                                r#type: "button",
                                "data-testid": "realms-manage-clear",
                                disabled: selection_count == 0 || busy(),
                                onclick: move |_| selection.set(BTreeSet::new()),
                                {crate::i18n::tr("manage.clear")}
                            }
                            Button {
                                variant: ButtonVariant::Destructive,
                                size: ButtonSize::Sm,
                                r#type: "button",
                                "data-testid": "realms-manage-leave-selected",
                                disabled: selection_count == 0 || busy() || !has_session,
                                onclick: {
                                    let base = base_url.clone();
                                    let actor_principal_id = principal_id.clone();
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
                                        let actor_id = actor_principal_id.clone();
                                        if actor_id.trim().is_empty() {
                                            crate::components::feedback::toast_error(
                                                "feedback.account_not_connected",
                                                vec![],
                                                None,
                                            );
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
                                        crate::components::feedback::toast_info(
                                            "feedback.bulk_realms_leaving",
                                            vec![("total", total.to_string())],
                                        );
                                        spawn(async move {
                                            let mut succeeded = BTreeSet::<String>::new();
                                            let mut forgotten_ids = BTreeSet::<String>::new();
                                            let mut failed = Vec::<String>::new();
                                            for realm_id in selected {
                                                let realm_for_api = realm_id.clone();
                                                let actor_for_api = actor_id.clone();
                                                match crate::transport::auth::with_event_submitter(
                                                    &base,
                                                    api_token.clone(),
                                                    |sub| async move {
                                                        crate::transport::realm_write::leave_realm(&sub, &realm_for_api, &actor_for_api).await
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
                                                sync_cursor.set(String::new());
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
                                                crate::components::feedback::toast_success(
                                                    "feedback.bulk_realms_left",
                                                    vec![
                                                        ("done", succeeded.len().to_string()),
                                                        ("total", total.to_string()),
                                                    ],
                                                );
                                            } else {
                                                crate::components::feedback::toast_error(
                                                    "feedback.bulk_realms_leave_failed",
                                                    vec![
                                                        ("done", succeeded.len().to_string()),
                                                        ("total", total.to_string()),
                                                    ],
                                                    Some(failed.join(", ")),
                                                );
                                            }
                                        });
                                    }
                                },
                                if busy() {
                                    {crate::i18n::tr("manage.leaving")}
                                } else {
                                    {crate::i18n::tr("manage.leave_selected")}
                                }
                            }
                        }
                    }

                    div { class: "event realm-manage-list-card",
                        div { class: "event-head",
                            span { {crate::i18n::tr("manage.realms_list_title")} }
                            span { {crate::i18n::tr_args("manage.rows", &[("count", filtered_rows.len().to_string())])} }
                        }
                        if realm_rows.is_empty() {
                            div { class: "members-empty", "data-testid": "realms-manage-empty",
                                div { class: "members-empty-title",
                                    {if has_session { crate::i18n::tr("sidebar.realms_empty") } else { crate::i18n::tr("sidebar.realms_sign_in") }}
                                }
                                div { class: "muted members-empty-hint", {crate::i18n::tr("manage.realms_empty_hint")} }
                            }
                        } else if filtered_rows.is_empty() {
                            div { class: "members-empty", "data-testid": "realms-manage-no-results",
                                div { class: "members-empty-title", {crate::i18n::tr("sidebar.realms_no_results")} }
                                div { class: "muted members-empty-hint", {crate::i18n::tr("manage.no_results_hint")} }
                            }
                        } else {
                            div { class: "realm-manage-list", "data-testid": "realms-manage-list",
                                for row in filtered_rows {
                                    {
                                        let realm_id = row.realm_id.clone();
                                        let checked = selected_ids.contains(&realm_id);
                                        let security_label = if row.encrypted {
                                            crate::i18n::tr("manage.row_encrypted")
                                        } else {
                                            crate::i18n::tr("manage.row_unencrypted")
                                        };
                                        let security_icon = if row.encrypted { "lock" } else { "unlock" };
                                        rsx! {
                                            label {
                                                class: "realm-manage-row",
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
                                                div { class: "realm-manage-row-main",
                                                    strong { title: "{row.title}", "{row.display_name}" }
                                                    span { class: "muted mono", title: "{realm_id}", "{realm_id}" }
                                                }
                                                div { class: "realm-manage-row-meta",
                                                    span { class: "pill muted xs", title: "{security_label}",
                                                        UiIcon { name: security_icon }
                                                        "{security_label}"
                                                    }
                                                    span { class: "pill muted xs",
                                                        {crate::i18n::tr_args("manage.row_spaces", &[("count", row.space_count.to_string())])}
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
}

#[component]
pub(super) fn ContactsManagePage(
    token: Signal<String>,
    has_session: bool,
    mut contact_rows: Signal<Vec<crate::models::ContactListRow>>,
    mut contacts_loaded: Signal<bool>,
    mut query: Signal<String>,
    mut selection: Signal<BTreeSet<String>>,
    mut busy: Signal<bool>,
) -> Element {
    // A4 — base_url / state_store from session context instead of props.
    let base_url = crate::app::SessionContext::base_url_string();
    let mut state_store = crate::app::SessionContext::get().state_store;
    {
        let base = base_url.clone();
        use_effect(move || {
            if contacts_loaded() || token().trim().is_empty() {
                return;
            }
            load_direct_contacts_for_sidebar(
                base.clone(),
                token(),
                state_store,
                contact_rows,
                contacts_loaded,
            );
        });
    }

    let rows = contact_rows.read().clone();
    let normalized_query = query().trim().to_ascii_lowercase();
    let filtered_rows = rows
        .iter()
        .filter(|contact| {
            let scopes = contact_manage_scope_summary(contact);
            let display_name = crate::views::helpers::actor_display_label(
                &state_store.read(),
                crate::models::contact_peer_id(contact).as_str(),
            );
            let state = crate::models::contact_state_wire(contact.state);
            sidebar_text_matches_query(
                &normalized_query,
                &[
                    crate::models::contact_peer_id(contact).as_str(),
                    state,
                    &display_name,
                    &scopes,
                ],
            )
        })
        .cloned()
        .collect::<Vec<_>>();
    let selected_ids = selection.read().clone();
    let selection_count = selected_ids.len();

    rsx! {
        div { class: "settings realm-manage-page", "data-testid": "contacts-manage-page",
            div { class: "settings-shell realm-manage-shell",
                section { class: "settings-content-stack realm-manage-main",
                    div { class: "event realm-manage-hero",
                        div { class: "realm-manage-title-block",
                            span { class: "realm-manage-icon", UiIcon { name: "users" } }
                            div {
                                h2 { class: "settings-content-title", {crate::i18n::tr("manage.contacts_title")} }
                                div { class: "muted", {crate::i18n::tr("manage.contacts_subtitle")} }
                            }
                        }
                        div { class: "realm-manage-stats",
                            span { class: "pill muted xs", {crate::i18n::tr_args("manage.stats_shown", &[("count", filtered_rows.len().to_string())])} }
                            span { class: "pill muted xs", {crate::i18n::tr_args("manage.stats_total", &[("count", rows.len().to_string())])} }
                            span { class: "pill muted xs", {crate::i18n::tr_args("manage.stats_selected", &[("count", selection_count.to_string())])} }
                        }
                    }

                    div { class: "event realm-manage-toolbar", "data-testid": "contacts-manage-toolbar",
                        div { class: "realm-manage-search",
                            span { class: "realm-manage-search-icon", UiIcon { name: "search" } }
                            Input {
                                "data-testid": "contacts-manage-search-input",
                                value: "{query}",
                                placeholder: crate::i18n::tr("manage.search_contacts"),
                                oninput: move |event: FormEvent| query.set(event.value()),
                            }
                        }
                        div { class: "actions realm-manage-actions",
                            Button {
                                variant: ButtonVariant::Secondary,
                                size: ButtonSize::Sm,
                                r#type: "button",
                                "data-testid": "contacts-manage-select-all",
                                disabled: filtered_rows.is_empty() || busy(),
                                onclick: {
                                    let peers = filtered_rows
                                        .iter()
                                        .map(|contact| crate::models::contact_peer_id(contact).to_string())
                                        .collect::<BTreeSet<_>>();
                                    move |_| selection.set(peers.clone())
                                },
                                {crate::i18n::tr("manage.select_shown")}
                            }
                            Button {
                                variant: ButtonVariant::Secondary,
                                size: ButtonSize::Sm,
                                r#type: "button",
                                "data-testid": "contacts-manage-clear",
                                disabled: selection_count == 0 || busy(),
                                onclick: move |_| selection.set(BTreeSet::new()),
                                {crate::i18n::tr("manage.clear")}
                            }
                            Button {
                                variant: ButtonVariant::Destructive,
                                size: ButtonSize::Sm,
                                r#type: "button",
                                "data-testid": "contacts-manage-delete-selected",
                                disabled: true,
                                title: crate::i18n::tr("manage.delete_unavailable"),
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
                                        crate::components::feedback::toast_info(
                                            "feedback.bulk_contacts_deleting",
                                            vec![("total", total.to_string())],
                                        );
                                        spawn(async move {
                                            let mut succeeded = BTreeSet::<String>::new();
                                            let mut failed = Vec::<String>::new();
                                            for peer in selected {
                                                let peer_for_api = peer.clone();
                                                match crate::transport::auth::with_authed_sdk_client(
                                                    &base,
                                                    api_token.clone(),
                                                    |http| async move {
                                                        crate::transport::account::tombstone_contact(&http, &peer_for_api, false).await
                                                    },
                                                )
                                                .await
                                                {
                                                    Ok(_) => {
                                                        succeeded.insert(peer);
                                                    }
                                                    Err(err) => failed.push(format!(
                                                        "{} ({})",
                                                        crate::views::helpers::actor_display_label(
                                                            &state_store.read(),
                                                            &peer,
                                                        ),
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
                                                match crate::transport::auth::with_authed_sdk_client(
                                                    &base,
                                                    api_token.clone(),
                                                    |http| async move {
                                                        crate::transport::account::contacts(&http).await
                                                    },
                                                )
                                                .await
                                                {
                                                    Ok(response) => {
                                                        state_store
                                                            .write()
                                                            .replace_accepted_human_contacts(&response.contacts);
                                                        contact_rows.set(response.contacts);
                                                        contacts_loaded.set(true);
                                                    }
                                                    Err(err) => {
                                                        crate::components::feedback::toast_error(
                                                            "feedback.contacts_load_failed",
                                                            vec![],
                                                            Some(err.display_diagnostic()),
                                                        )
                                                    }
                                                }
                                            }

                                            busy.set(false);
                                            if failed.is_empty() {
                                                crate::components::feedback::toast_success(
                                                    "feedback.bulk_contacts_deleted",
                                                    vec![
                                                        ("done", succeeded.len().to_string()),
                                                        ("total", total.to_string()),
                                                    ],
                                                );
                                            } else {
                                                crate::components::feedback::toast_error(
                                                    "feedback.bulk_contacts_delete_failed",
                                                    vec![
                                                        ("done", succeeded.len().to_string()),
                                                        ("total", total.to_string()),
                                                    ],
                                                    Some(failed.join(", ")),
                                                );
                                            }
                                        });
                                    }
                                },
                                if busy() {
                                    {crate::i18n::tr("manage.deleting")}
                                } else {
                                    {crate::i18n::tr("manage.delete_selected")}
                                }
                            }
                        }
                    }

                    div { class: "event realm-manage-list-card",
                        div { class: "event-head",
                            span { {crate::i18n::tr("manage.contacts_list_title")} }
                            span { {crate::i18n::tr_args("manage.rows", &[("count", filtered_rows.len().to_string())])} }
                        }
                        if rows.is_empty() {
                            div { class: "members-empty", "data-testid": "contacts-manage-empty",
                                div { class: "members-empty-title",
                                    {if has_session { crate::i18n::tr("contacts.empty") } else { crate::i18n::tr("contacts.sign_in") }}
                                }
                                div { class: "muted members-empty-hint", {crate::i18n::tr("manage.contacts_empty_hint")} }
                            }
                        } else if filtered_rows.is_empty() {
                            div { class: "members-empty", "data-testid": "contacts-manage-no-results",
                                div { class: "members-empty-title", {crate::i18n::tr("manage.contacts_no_results")} }
                                div { class: "muted members-empty-hint", {crate::i18n::tr("manage.no_results_hint")} }
                            }
                        } else {
                            div { class: "realm-manage-list", "data-testid": "contacts-manage-list",
                                for contact in filtered_rows {
                                    {
                                        let peer = crate::models::contact_peer_id(&contact).to_string();
                                        let checked = selected_ids.contains(&peer);
                                        let peer_label = crate::views::helpers::actor_display_label(
                                            &state_store.read(),
                                            &peer,
                                        );
                                        let scopes_label = contact_manage_scope_summary(&contact);
                                        let direct_label = contact
                                            .direct_conversation
                                            .as_ref()
                                            .map(|summary| {
                                                crate::i18n::tr_args(
                                                    "manage.contact_dm",
                                                    &[(
                                                        "state",
                                                        crate::models::direct_conversation_binding_state_wire(
                                                            summary.state,
                                                        )
                                                        .to_owned(),
                                                    )],
                                                )
                                            })
                                            .unwrap_or_else(|| crate::i18n::tr("manage.contact_no_dm"));
                                        let contact_state =
                                            crate::models::contact_state_wire(contact.state);
                                        rsx! {
                                            label {
                                                class: "realm-manage-row",
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
                                                div { class: "realm-manage-row-main",
                                                    strong { title: "{peer}", "{peer_label}" }
                                                    span { class: "muted", title: "{scopes_label}", "{scopes_label}" }
                                                }
                                                div { class: "realm-manage-row-meta",
                                                    span { class: "pill muted xs", "{contact_state}" }
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
