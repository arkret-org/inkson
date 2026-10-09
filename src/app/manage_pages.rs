use super::*;
use crate::components::HelpTip;

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
    principal_control_realm_id: Option<String>,
    token: Signal<String>,
    has_session: bool,
    realm_rows: Vec<RealmManageRow>,
    mut realm_tree_nodes: Signal<Vec<RealmTreeNode>>,
    mut selected_realm_id: Signal<String>,
    mut sync_cursor: Signal<String>,
    mut query: Signal<String>,
) -> Element {
    // A4 — base_url / state_store from session context instead of props.
    let base_url = crate::app::SessionContext::base_url_string();
    let state_store = crate::app::SessionContext::get().state_store;
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
    let mut pending_leave = use_signal(|| None::<(String, String)>);
    let pending_leave_target = pending_leave();

    rsx! {
        div { class: "settings realm-manage-page", "data-testid": "realms-manage-page",
            div { class: "settings-shell realm-manage-shell",
                section { class: "settings-content-stack realm-manage-main",
                    div { class: "event realm-manage-list-card",
                        div { class: "realm-manage-list-tools", "data-testid": "realms-manage-toolbar",
                            div { class: "realm-manage-search",
                                span { class: "realm-manage-search-icon", UiIcon { name: "search" } }
                                Input {
                                    "data-testid": "realms-manage-search-input",
                                    value: "{query}",
                                    placeholder: crate::i18n::tr("sidebar.search_realms"),
                                    oninput: move |event: FormEvent| query.set(event.value()),
                                }
                            }
                            if principal_control_realm_id.is_some() {
                                Link {
                                    class: "btn sm secondary realm-manage-pcr-link",
                                    "data-testid": "realms-manage-principal-control-button",
                                    to: Route::PrincipalControl,
                                    UiIcon { name: "key" }
                                    {crate::i18n::tr("manage.principal_control_button")}
                                }
                            }
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
                                        let realm_label = row.display_name.clone();
                                        let security_label = match row.encrypted {
                                            Some(true) => crate::i18n::tr("manage.row_encrypted"),
                                            Some(false) => crate::i18n::tr("manage.row_unencrypted"),
                                            None => crate::i18n::tr("realm.security_unknown"),
                                        };
                                        let security_icon = match row.encrypted { Some(true) => "lock", Some(false) => "unlock", None => "help-circle" };
                                        rsx! {
                                            div {
                                                class: "realm-manage-row",
                                                "data-testid": "realms-manage-row",
                                                "data-realm-id": "{realm_id}",
                                                tabindex: "0",
                                                "aria-label": "{realm_label}",
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
                                                div { class: "realm-manage-row-actions",
                                                    Link {
                                                        class: "btn sm secondary",
                                                        "data-testid": "realms-manage-row-open",
                                                        to: Route::Realm { realm_id: realm_id.clone() },
                                                        onclick: {
                                                            let realm_id = realm_id.clone();
                                                            move |_| selected_realm_id.set(realm_id.clone())
                                                        },
                                                        {crate::i18n::tr("setup.action.open_realm")}
                                                    }
                                                    Link {
                                                        class: "btn sm secondary",
                                                        "data-testid": "realms-manage-row-settings",
                                                        to: Route::RealmAdmin { realm_id: realm_id.clone() },
                                                        {crate::i18n::tr("realm.settings")}
                                                    }
                                                    Button {
                                                        variant: ButtonVariant::Destructive,
                                                        size: ButtonSize::Sm,
                                                        r#type: "button",
                                                        "data-testid": "realms-manage-row-leave",
                                                        disabled: !has_session,
                                                        onclick: {
                                                            let realm_id = realm_id.clone();
                                                            let realm_label = realm_label.clone();
                                                            move |_| pending_leave.set(Some((realm_id.clone(), realm_label.clone())))
                                                        },
                                                        {crate::i18n::tr("realm_admin.leave_realm")}
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }

                    if let Some((realm_id, realm_label)) = pending_leave_target {
                        crate::components::DismissiblePopup {
                            overlay_class: "modal-backdrop",
                            surface_class: "modal danger-confirm-modal",
                            overlay_test_id: Some("realms-manage-leave-modal".to_owned()),
                            surface_test_id: Some("realms-manage-leave-dialog".to_owned()),
                            aria_label: crate::i18n::tr("realm_admin.leave_confirm_title"),
                            on_dismiss: move |_| pending_leave.set(None),
                            div { class: "modal-head",
                                h3 { {crate::i18n::tr("realm_admin.leave_confirm_title")} }
                                Button {
                                    variant: ButtonVariant::Secondary,
                                    class: "icon-button close",
                                    "aria-label": crate::i18n::tr("common.close"),
                                    onclick: move |_| pending_leave.set(None),
                                    "\u{2715}"
                                }
                            }
                            div { class: "modal-body workflow-form",
                                div { class: "callout danger",
                                    p { {crate::i18n::tr("realm_admin.leave_confirm_body")} }
                                }
                                div { class: "metric",
                                    strong { {crate::i18n::tr("realm_admin.leave_confirm_target")} }
                                    span { "{realm_label}" }
                                    span { class: "muted mono", title: "{realm_id}", "{short_protocol_id(&realm_id)}" }
                                }
                            }
                            div { class: "modal-foot",
                                Button {
                                    variant: ButtonVariant::Secondary,
                                    onclick: move |_| pending_leave.set(None),
                                    {crate::i18n::tr("realm_admin.leave_confirm_cancel")}
                                }
                                Button {
                                    variant: ButtonVariant::Destructive,
                                    "data-testid": "realms-manage-leave-confirm",
                                    onclick: {
                                        let base = base_url.clone();
                                        let realm_id = realm_id.clone();
                                        let principal_id = principal_id.clone();
                                        move |_| {
                                            pending_leave.set(None);
                                            leave_sidebar_realm(
                                                base.clone(),
                                                token(),
                                                realm_id.clone(),
                                                principal_id.clone(),
                                                state_store,
                                                realm_tree_nodes,
                                                selected_realm_id,
                                                sync_cursor,
                                            );
                                        }
                                    },
                                    {crate::i18n::tr("realm_admin.leave_confirm_button")}
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
pub(super) fn PrincipalControlRealmPage(realm_id: Option<String>) -> Element {
    rsx! {
        div { class: "settings realm-manage-page", "data-testid": "principal-control-realm-page",
            div { class: "settings-shell realm-manage-shell",
                section { class: "settings-content-stack realm-manage-main",
                    div { class: "event realm-manage-list-card principal-control-card",
                        div { class: "compact-page-actions",
                            HelpTip { text: crate::i18n::tr("manage.principal_control_subtitle") }
                            Link {
                                class: "btn sm secondary",
                                "data-testid": "principal-control-back-button",
                                to: Route::RealmsManage,
                                UiIcon { name: "chevron-left" }
                                {crate::i18n::tr("manage.back_to_realms")}
                            }
                        }
                        if let Some(realm_id) = realm_id {
                            div { class: "principal-control-field",
                                span { class: "muted", {crate::i18n::tr("manage.principal_control_purpose_label")} }
                                strong { {crate::i18n::tr("manage.principal_control_purpose_value")} }
                            }
                            div { class: "principal-control-field",
                                span { class: "muted", {crate::i18n::tr("manage.principal_control_realm_id")} }
                                code { class: "mono", "data-testid": "principal-control-realm-id", "{realm_id}" }
                            }
                            div { class: "panel-notice",
                                UiIcon { name: "lock" }
                                span { {crate::i18n::tr("manage.principal_control_no_business_surfaces")} }
                            }
                        } else {
                            div { class: "members-empty", "data-testid": "principal-control-realm-unavailable",
                                div { class: "members-empty-title", {crate::i18n::tr("manage.principal_control_unavailable")} }
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
) -> Element {
    // A4 — base_url / state_store from session context instead of props.
    let base_url = crate::app::SessionContext::base_url_string();
    let state_store = crate::app::SessionContext::get().state_store;
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
            let display_name =
                crate::views::helpers::contact_peer_label(&state_store.read(), contact);
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

    rsx! {
        div { class: "settings realm-manage-page", "data-testid": "contacts-manage-page",
            div { class: "settings-shell realm-manage-shell",
                section { class: "settings-content-stack realm-manage-main",
                    div { class: "event realm-manage-list-card",
                        div { class: "realm-manage-list-tools", "data-testid": "contacts-manage-toolbar",
                            div { class: "realm-manage-search",
                                span { class: "realm-manage-search-icon", UiIcon { name: "search" } }
                                Input {
                                    "data-testid": "contacts-manage-search-input",
                                    value: "{query}",
                                    placeholder: crate::i18n::tr("manage.search_contacts"),
                                    oninput: move |event: FormEvent| query.set(event.value()),
                                }
                            }
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
                                        let peer_label = crate::views::helpers::contact_peer_label(
                                            &state_store.read(),
                                            &contact,
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
                                            div {
                                                class: "realm-manage-row",
                                                "data-testid": "contacts-manage-row",
                                                "data-peer": "{peer}",
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
