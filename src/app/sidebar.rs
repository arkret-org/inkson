use arkret_wire::CapabilityActionId;

use super::*;

/// These destinations have different callback ownership. Dioxus 0.7.10 can
/// retain a dropped optional handler when an unkeyed Link changes None -> Some.
/// Keep their identities separate when the sidebar tab changes.
#[component]
pub(super) fn SidebarManageHomeLink(
    direct: bool,
    active: bool,
    on_open_contacts: EventHandler<()>,
) -> Element {
    let destination_key = if direct {
        "manage-contacts"
    } else {
        "manage-realms"
    };
    let class = if active {
        "sidebar-toolbar-action sidebar-toolbar-link is-active"
    } else {
        "sidebar-toolbar-action sidebar-toolbar-link"
    };
    rsx! {
        if direct {
            Link {
                key: "{destination_key}",
                class,
                "data-testid": "realm-sidebar-manage-home-button",
                title: crate::i18n::tr("manage.contacts_title"),
                "aria-label": crate::i18n::tr("manage.contacts_title"),
                to: Route::ContactsManage,
                onclick: move |_| on_open_contacts.call(()),
                UiIcon { name: "home" }
            }
        } else {
            Link {
                key: "{destination_key}",
                class,
                "data-testid": "realm-sidebar-manage-home-button",
                title: crate::i18n::tr("manage.realms_title"),
                "aria-label": crate::i18n::tr("manage.realms_title"),
                to: Route::RealmsManage,
                UiIcon { name: "home" }
            }
        }
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod manage_link_tests {
    use std::cell::RefCell;
    use std::rc::Rc;

    use dioxus_router::{Routable, Router};

    use super::*;

    #[derive(Clone, Debug, PartialEq, Routable)]
    enum TestRoute {
        #[route("/")]
        ManageLinkFixture,
    }

    #[component]
    fn ManageLinkFixture() -> Element {
        let state = use_context::<Signal<(bool, bool)>>();
        let (direct, active) = state();
        rsx! {
            SidebarManageHomeLink {
                direct,
                active,
                on_open_contacts: move |_| {},
            }
        }
    }

    #[test]
    fn contacts_sidebar_link_survives_tab_changes_and_navigation_rerenders() {
        let handle = Rc::new(RefCell::new(None::<Signal<(bool, bool)>>));
        let mut dom = VirtualDom::new_with_props(
            |handle: Rc<RefCell<Option<Signal<(bool, bool)>>>>| {
                let state = use_signal(|| (false, false));
                use_context_provider(|| state);
                *handle.borrow_mut() = Some(state);
                rsx! { Router::<TestRoute> {} }
            },
            handle.clone(),
        );
        dom.rebuild_in_place();
        let mut state = handle.borrow().unwrap();
        // None -> Some onclick when entering Contacts, then rerender on route
        // change. Without separate Link keys the second update panics inside
        // LinkProps::memoize with ValueDroppedError in Dioxus 0.7.10.
        for next in [
            (true, false),
            (true, true),
            (true, false),
            (false, true),
            (true, false),
            (true, true),
        ] {
            dom.in_runtime(|| state.set(next));
            dom.render_immediate(&mut dioxus::core::NoOpMutations);
        }
    }
}

#[component]
pub(super) fn ServerSwitcher(
    server_menu_open: Signal<bool>,
    server_menu_is_open: bool,
    account_menu_open: Signal<bool>,
    sidebar_collapsed: bool,
    active_server_label: String,
    server_options: Vec<String>,
    base_url: Signal<String>,
    on_select: EventHandler<String>,
) -> Element {
    rsx! {
        div { class: "server-switch", "data-testid": "principal-context", "aria-label": "Current server context",
            Button {
                variant: ButtonVariant::Secondary,
                class: "server-switch-button",
                "data-testid": "server-switch-button",
                title: "Switch server",
                "aria-label": "Switch server",
                "aria-expanded": if server_menu_is_open { "true" } else { "false" },
                onclick: move |_| {
                    server_menu_open.toggle();
                    account_menu_open.set(false);
                },
                span { class: "server-switch-icon",
                    UiIcon { name: "server" }
                }
                span { class: "server-switch-title",
                    span { class: "v", "{active_server_label}" }
                }
                span { class: "server-switch-state",
                    if server_menu_is_open {
                        UiIcon { name: "chevron-up" }
                    } else {
                        UiIcon { name: "chevron-down" }
                    }
                }
            }

            if server_menu_is_open && !sidebar_collapsed {
                div { class: "server-switch-menu", "data-testid": "server-switch-menu",
                    div { class: "server-option-list", "aria-label": "Server choices",
                        for option_url in server_options {
                            Button {
                                variant: ButtonVariant::Secondary,
                                class: if same_server_url(&option_url, &base_url()) { "server-option active" } else { "server-option" },
                                "data-testid": "server-option",
                                title: "Switch to {option_url}",
                                "aria-label": "Switch to {option_url}",
                                onclick: {
                                    let option_url = option_url.clone();
                                    move |_| on_select.call(option_url.clone())
                                },
                                span { class: "server-option-text",
                                    span { class: "server-option-main mono", "{option_url}" }
                                }
                                if same_server_url(&option_url, &base_url()) {
                                    span { class: "pill muted xs", "current" }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

pub(super) fn pinned_realm_ids_from_store(store: &LocalStateStore) -> BTreeSet<String> {
    store
        .realm_remarks()
        .into_iter()
        .filter_map(|(realm_id, remark)| remark.pinned.then_some(realm_id))
        .collect()
}

pub(super) fn unread_notification_count(snapshot: &ClientLocalState) -> usize {
    snapshot
        .notification_projection
        .iter()
        .enumerate()
        .filter(|(index, value)| {
            let id = value.notification_id();
            let client_state = snapshot.notification_client_state.get(&id);
            let (projection_read, projection_archived) =
                crate::views::notifications::notification_wire_state(value);
            let archived =
                projection_archived || client_state.map(|state| state.archived).unwrap_or(false);
            let read = projection_read
                || client_state.map(|state| state.read).unwrap_or(false)
                || crate::views::notifications::notification_value_read_by_cursor(
                    *index, value, snapshot,
                );
            !archived && !read
        })
        .count()
}

#[derive(Clone, Debug, PartialEq)]
pub(super) struct RealmManageRow {
    pub(super) realm_id: String,
    pub(super) display_name: String,
    pub(super) title: String,
    pub(super) encrypted: bool,
    pub(super) space_count: usize,
}

pub(super) fn principal_control_realm_ids(state: &ClientLocalState) -> BTreeSet<String> {
    let mut ids = state
        .realm_tree_projections
        .iter()
        .filter(|(_, projection)| {
            crate::realm_tree::realm_projection_is_principal_control(projection)
        })
        .map(|(realm_id, _)| realm_id.clone())
        .collect::<BTreeSet<_>>();
    if let Some(evidence) = state.recovery_material_evidence.as_ref() {
        ids.insert(evidence.principal_control_realm_id.to_string());
    }
    ids
}

pub(super) fn personal_control_realm_id(state: &ClientLocalState) -> Option<String> {
    state
        .recovery_material_evidence
        .as_ref()
        .map(|evidence| evidence.principal_control_realm_id.to_string())
        .or_else(|| {
            state
                .realm_tree_projections
                .iter()
                .find(|(_, projection)| {
                    crate::realm_tree::realm_projection_control_purpose(projection)
                        == Some("principal_control")
                })
                .map(|(realm_id, _)| realm_id.clone())
        })
}

pub(super) fn sidebar_text_matches_query(normalized_query: &str, values: &[&str]) -> bool {
    normalized_query.is_empty()
        || values
            .iter()
            .any(|value| value.to_ascii_lowercase().contains(normalized_query))
}

/// The Contacts sidebar is a chat surface: only lifecycle-active agents with
/// an effective runtime key belong here. A replacement pairing keeps the
/// existing authorization effective, while bootstrap-pending and expired
/// agents stay in Settings → My Agents. Keeping this filter in one place
/// ensures the initial load and the `owned_agents_rev`-driven reload agree.
fn active_agents_only(
    agents: Vec<arkret_sdk::AgentProjection>,
) -> Vec<arkret_sdk::AgentProjection> {
    agents
        .into_iter()
        .filter(|agent| {
            matches!(agent.lifecycle, arkret_sdk::AgentLifecycleState::Active)
                && matches!(
                    crate::views::agents::model::agent_projection_runtime_state(agent),
                    arkret_sdk::AgentRuntimeState::Ready | arkret_sdk::AgentRuntimeState::Replacing
                )
        })
        .collect()
}

/// Re-pull only the signed-in account's owned agents for the Contacts sidebar,
/// leaving human contacts untouched. Driven by `SessionContext::owned_agents_rev`
/// so a provision/pause/resume/deactivate in Settings → My Agents is reflected
/// in the sidebar without waiting for the user to re-open the tab. A transient
/// error keeps the previously loaded rows rather than clearing the sidebar.
pub(super) fn load_own_agents_for_sidebar(
    base: String,
    api_token: String,
    mut own_agent_rows: Signal<Vec<arkret_sdk::AgentProjection>>,
    mut own_agents_loaded: Signal<bool>,
) {
    if api_token.trim().is_empty() {
        own_agent_rows.set(Vec::new());
        own_agents_loaded.set(false);
        return;
    }
    own_agents_loaded.set(true);
    spawn(async move {
        match crate::transport::auth::with_authed_sdk_client(&base, api_token, |http| async move {
            http.agent_list().await.map_err(anyhow::Error::from)
        })
        .await
        {
            Ok(response) => own_agent_rows.set(active_agents_only(response.agent_projections)),
            Err(err) => {
                tracing::warn!(
                    "failed to reload Agents for Contacts sidebar: {}",
                    err.display_diagnostic()
                );
            }
        }
    });
}

pub(super) fn load_direct_contacts_and_agents_for_sidebar(
    base: String,
    api_token: String,
    mut state_store: SyncSignal<LocalStateStore>,
    mut direct_contact_rows: Signal<Vec<crate::models::ContactListRow>>,
    mut direct_contacts_loaded: Signal<bool>,
    mut own_agent_rows: Signal<Vec<arkret_sdk::AgentProjection>>,
    mut own_agents_loaded: Signal<bool>,
) {
    if api_token.trim().is_empty() {
        state_store.write().replace_accepted_human_contacts(&[]);
        direct_contact_rows.set(Vec::new());
        direct_contacts_loaded.set(false);
        own_agent_rows.set(Vec::new());
        own_agents_loaded.set(false);
        return;
    }

    direct_contacts_loaded.set(true);
    own_agents_loaded.set(true);
    spawn(async move {
        match crate::transport::auth::with_authed_sdk_client(&base, api_token, |http| async move {
            let contacts = crate::transport::account::contacts(&http).await;
            let agents = http.agent_list().await.map_err(anyhow::Error::from);
            Ok((contacts, agents))
        })
        .await
        {
            Ok((contacts, agents)) => {
                match contacts {
                    Ok(response) => {
                        state_store
                            .write()
                            .replace_accepted_human_contacts(&response.contacts);
                        direct_contact_rows.set(response.contacts);
                    }
                    Err(err) => {
                        direct_contacts_loaded.set(false);
                        crate::components::feedback::toast_error(
                            "feedback.contacts_load_failed",
                            vec![],
                            Some(err.to_string()),
                        );
                    }
                }
                match agents {
                    Ok(response) => {
                        own_agent_rows.set(active_agents_only(response.agent_projections))
                    }
                    Err(err) => {
                        own_agents_loaded.set(false);
                        tracing::warn!(error = %err, "failed to load Agents for Contacts sidebar");
                    }
                }
            }
            Err(err) => {
                direct_contacts_loaded.set(false);
                own_agents_loaded.set(false);
                crate::components::feedback::toast_error(
                    "feedback.contacts_load_failed",
                    vec![],
                    Some(err.display_diagnostic()),
                );
            }
        }
    });
}

pub(super) fn load_direct_contacts_for_sidebar(
    base: String,
    api_token: String,
    mut state_store: SyncSignal<LocalStateStore>,
    mut direct_contact_rows: Signal<Vec<crate::models::ContactListRow>>,
    mut direct_contacts_loaded: Signal<bool>,
) {
    if api_token.trim().is_empty() {
        state_store.write().replace_accepted_human_contacts(&[]);
        direct_contact_rows.set(Vec::new());
        direct_contacts_loaded.set(false);
        return;
    }
    direct_contacts_loaded.set(true);
    spawn(async move {
        match crate::transport::auth::with_endpoint_clients(
            &base,
            api_token,
            None,
            |clients| async move { clients.account().contacts().await },
        )
        .await
        {
            Ok(response) => {
                state_store
                    .write()
                    .replace_accepted_human_contacts(&response.contacts);
                direct_contact_rows.set(response.contacts);
            }
            Err(err) => {
                direct_contacts_loaded.set(false);
                crate::components::feedback::toast_error(
                    "feedback.contacts_load_failed",
                    vec![],
                    Some(err.display_diagnostic()),
                );
            }
        }
    });
}

pub(super) fn toggle_sidebar_realm_pin(
    realm_id: String,
    existing: Option<crate::account_data::RealmRemark>,
    next_pinned: bool,
    mut state_store: SyncSignal<LocalStateStore>,
    base_url: String,
    api_token: String,
) {
    let Ok(typed_realm_id) = arkret_sdk::RealmId::new(realm_id.clone()) else {
        return;
    };
    let next = crate::account_data::RealmRemark::with_pinned_preserving_fields(
        typed_realm_id,
        existing.as_ref(),
        next_pinned,
        chrono::Utc::now(),
    );
    state_store
        .write()
        .set_realm_remark(realm_id.clone(), next.clone());
    crate::components::feedback::toast_success(
        if next_pinned {
            "realm.pinned"
        } else {
            "realm.unpinned"
        },
        vec![],
    );
    crate::views::settings::push_realm_remark_account_data_with_failure_toast(
        base_url, api_token, realm_id, next,
    );
}

pub(super) fn toggle_sidebar_contact_pin(
    actor_id: String,
    existing: Option<crate::account_data::ContactRemark>,
    next_pinned: bool,
    mut state_store: SyncSignal<LocalStateStore>,
    base_url: String,
    api_token: String,
) {
    let Ok(actor_id) = crate::mls_api_helpers::principal_core_id(&actor_id) else {
        return;
    };
    let next = crate::account_data::ContactRemark::with_pinned_preserving_fields(
        actor_id.clone(),
        existing.as_ref(),
        next_pinned,
        chrono::Utc::now(),
    );
    state_store
        .write()
        .set_contact_remark(actor_id.to_string(), next.clone());
    crate::components::feedback::toast_success(
        if next_pinned {
            "contact.pinned"
        } else {
            "contact.unpinned"
        },
        vec![],
    );
    crate::views::settings::push_contact_remark_account_data(
        base_url,
        api_token,
        actor_id.to_string(),
        next,
    );
}

pub(super) fn leave_sidebar_realm(
    base_url: String,
    api_token: String,
    realm_id: String,
    principal_id: String,
    mut state_store: SyncSignal<LocalStateStore>,
    mut realm_tree_nodes: Signal<Vec<RealmTreeNode>>,
    mut selected_realm_id: Signal<String>,
    mut sync_cursor: Signal<String>,
) {
    // Realm membership events are authored by the account/principal DID — the
    // server rejects any event whose `actor_id` differs from the authenticated
    // session actor
    // session actor (`actor_session_mismatch`). The local device DID is not the
    // session actor, so it must not be used here.
    let actor_id = principal_id.trim().to_owned();
    if actor_id.is_empty() {
        crate::components::feedback::toast_error("feedback.account_not_connected", vec![], None);
        return;
    }
    let current_nodes = realm_tree_nodes();
    let mut ids_to_forget = descendant_node_ids(&current_nodes, &realm_id);
    if ids_to_forget.is_empty() {
        ids_to_forget.push(realm_id.clone());
    }
    let realm_label = short_protocol_id(&realm_id);
    crate::components::feedback::toast_info(
        "feedback.realm_leaving",
        vec![("realm", realm_label.clone())],
    );
    spawn(async move {
        let realm_for_api = realm_id.clone();
        match crate::transport::auth::with_event_submitter(&base_url, api_token, |sub| async move {
            crate::transport::realm_write::leave_realm(&sub, &realm_for_api, &actor_id).await
        })
        .await
        {
            Ok(_) => {
                let forgotten_ids = ids_to_forget.into_iter().collect::<BTreeSet<_>>();
                for id in &forgotten_ids {
                    state_store.write().forget_realm_tree_projection(id);
                }
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
                crate::components::feedback::toast_success(
                    "feedback.realm_left",
                    vec![("realm", realm_label)],
                );
            }
            Err(err) => crate::components::feedback::toast_error(
                "feedback.realm_leave_failed",
                vec![("realm", realm_label)],
                Some(err.display_diagnostic()),
            ),
        }
    });
}

/// Per-Realm UI pre-gate for the sidebar row menu's write actions
/// (Add Member / Settings). Presence of a `realm_id` key in the cache means
/// the authz probe has completed; the booleans mirror the server's
/// authoritative decision so the row menu can hide entries the actor cannot
/// use. This is advisory only — the server still makes the real call.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct SidebarRowRealmPerms {
    pub(super) can_add_member: bool,
    pub(super) can_settings: bool,
}

/// Lazily probe whether `actor` may add members (`ak.invite.create`) or edit
/// settings (`ak.realm.profile`) on `realm_id`, caching the verdict in
/// `perms_cache`.
///
/// Triggered when a sidebar row's kebab menu opens, so at most two authz
/// requests are issued for the single Realm whose menu is open — never the
/// `2*N` that eager per-row probing on every sidebar render would cost.
/// Fail-closed: a transport error or a non-allow body both leave the write
/// actions hidden, and we still cache that verdict so we don't re-probe a
/// Realm the actor plainly cannot manage on every menu open.
pub(super) fn ensure_sidebar_row_perms(
    base_url: String,
    api_token: String,
    actor: String,
    realm_id: String,
    mut perms_cache: Signal<BTreeMap<String, SidebarRowRealmPerms>>,
) {
    if api_token.trim().is_empty() || actor.trim().is_empty() || realm_id.trim().is_empty() {
        return;
    }
    if perms_cache.read().contains_key(&realm_id) {
        return;
    }
    spawn(async move {
        let perms = match crate::transport::auth::authed_api_with_sync(&base_url, api_token, None) {
            Ok(api) => {
                let invite = async {
                    crate::transport::realm_read::authz_check(
                        &api.sdk_http_client()?,
                        &actor,
                        CapabilityActionId::INVITE_CREATE,
                        &realm_id,
                    )
                    .await
                }
                .await;
                let settings = async {
                    crate::transport::realm_read::authz_check(
                        &api.sdk_http_client()?,
                        &actor,
                        CapabilityActionId::REALM_PROFILE,
                        &realm_id,
                    )
                    .await
                }
                .await;
                SidebarRowRealmPerms {
                    can_add_member: invite
                        .as_ref()
                        .map(crate::transport::realm_read::authz_allowed)
                        .unwrap_or(false),
                    can_settings: settings
                        .as_ref()
                        .map(crate::transport::realm_read::authz_allowed)
                        .unwrap_or(false),
                }
            }
            Err(_) => SidebarRowRealmPerms::default(),
        };
        perms_cache.write().insert(realm_id, perms);
    });
}

pub(super) fn delete_sidebar_contact(
    base_url: String,
    api_token: String,
    peer: String,
    mut state_store: SyncSignal<LocalStateStore>,
    mut direct_contact_rows: Signal<Vec<crate::models::ContactListRow>>,
    mut direct_contacts_loaded: Signal<bool>,
) {
    let peer_label = serde_json::from_str::<arkret_sdk::ActorId>(&peer)
        .map(|actor| match actor {
            arkret_sdk::ActorId::Account { account_id } => {
                crate::views::helpers::account_display_label(&state_store.read(), &account_id)
            }
            arkret_sdk::ActorId::Service { service_id } => {
                crate::views::helpers::actor_display_label(&state_store.read(), service_id.as_str())
            }
        })
        .unwrap_or_else(|_| crate::views::helpers::short_protocol_id(&peer));
    crate::components::feedback::toast_info(
        "feedback.contact_deleting",
        vec![("name", peer_label.clone())],
    );
    spawn(async move {
        let peer_for_api = peer.clone();
        match crate::transport::auth::with_authed_sdk_client(
            &base_url,
            api_token,
            |http| async move {
                crate::transport::account::tombstone_contact(&http, &peer_for_api, false).await
            },
        )
        .await
        {
            Ok(_) => {
                let next_rows: Vec<_> = direct_contact_rows()
                    .into_iter()
                    .filter(|row| row.peer.contact_actor_id().to_string() != peer)
                    .collect();
                state_store
                    .write()
                    .replace_accepted_human_contacts(&next_rows);
                direct_contact_rows.set(next_rows);
                direct_contacts_loaded.set(true);
                crate::components::feedback::toast_success(
                    "feedback.contact_deleted",
                    vec![("name", peer_label)],
                );
            }
            Err(err) => crate::components::feedback::toast_error(
                "feedback.contact_delete_failed",
                vec![("name", peer_label)],
                Some(err.display_diagnostic()),
            ),
        }
    });
}

/// One-shot push-token provider bootstrap.
///
/// Runs once on first App render. On wasm32 we install
/// `WebPushTokenProvider::new()` (drives the service-worker +
/// `pushManager.subscribe` path described in `push.rs::WebPushTokenProvider`).
/// On native builds we install `FcmPushTokenProvider` / `ApnsPushTokenProvider`.
/// The host adapter supplies the actual OS token through
/// `set_fcm_push_token` / `set_apns_push_token` after Firebase/APNs returns
/// it; local dev can inject the same token via env vars. Subsequent renders
/// short-circuit via `OnceLock` semantics inside `set_push_token_provider`.
pub(super) fn ensure_default_push_token_provider() {
    if crate::push::push_token_provider().is_some() {
        return;
    }
    #[cfg(target_arch = "wasm32")]
    {
        crate::push::set_push_token_provider(std::sync::Arc::new(
            crate::push::WebPushTokenProvider::new(),
        ));
    }
    #[cfg(all(not(target_arch = "wasm32"), target_os = "android"))]
    {
        crate::push::set_push_token_provider(std::sync::Arc::new(
            crate::push::FcmPushTokenProvider,
        ));
    }
    #[cfg(all(not(target_arch = "wasm32"), target_os = "ios"))]
    {
        crate::push::set_push_token_provider(std::sync::Arc::new(
            crate::push::ApnsPushTokenProvider,
        ));
    }
    #[cfg(all(
        not(target_arch = "wasm32"),
        not(target_os = "android"),
        not(target_os = "ios")
    ))]
    {
        // Desktop / server builds: install the FCM provider as the
        // safe default. It reads `INKSON_FCM_PUSH_TOKEN`,
        // `FCM_PUSH_TOKEN`, or `CHASK_PUSH_KEY` for local bridge
        // testing, and otherwise reports "no token" without emitting a
        // placeholder to the gateway.
        crate::push::set_push_token_provider(std::sync::Arc::new(
            crate::push::FcmPushTokenProvider,
        ));
    }
}
