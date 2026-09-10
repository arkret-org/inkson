use super::*;

pub(super) fn direct_conversation_peer_id(
    contacts: &[crate::models::ContactListRow],
    realm_id: &str,
    strand_id: &str,
) -> String {
    let matches_route = |summary: &crate::models::DirectConversationSummary| {
        summary.state == arkret_sdk::DirectConversationSummaryState::Found
            && summary.realm_id.as_str() == realm_id
            && summary.main_strand_id.as_str() == strand_id
    };
    for contact in contacts {
        if contact
            .direct_conversation
            .as_ref()
            .is_some_and(&matches_route)
        {
            return crate::models::contact_peer_id(contact).to_string();
        }
        if let Some(agent) = contact.contact_agent_projections.iter().find(|agent| {
            agent
                .direct_conversation
                .as_ref()
                .is_some_and(&matches_route)
        }) {
            return agent.actor_id.signing_principal_id().to_string();
        }
    }
    String::new()
}

#[derive(Clone, PartialEq)]
pub(super) struct RouteSurfaceState {
    pub(super) content_route: Route,
    pub(super) navigation: NavigationState,
    pub(super) principal_id: Signal<Option<arkret_sdk::DidCoreId>>,
    pub(super) device_id: Signal<String>,
    pub(super) token: Signal<String>,
    pub(super) account_recovery_configured: Signal<Option<bool>>,
    pub(super) config_store: Signal<LocalConfigStore>,
    pub(super) account_primary_handle: Signal<String>,
    pub(super) personal_handles: Signal<Vec<String>>,
    pub(super) personal_handles_status: Signal<String>,
    pub(super) realm_tree_nodes: Signal<Vec<RealmTreeNode>>,
    pub(super) device_queue: Signal<usize>,
    pub(super) frontier_state: Signal<String>,
    pub(super) sync_cursor: Signal<String>,
    pub(super) resolved_realm_surface: Option<RealmSurface>,
    pub(super) server_description: Signal<Option<ServiceDescribe>>,
    pub(super) event_write_ready: bool,
    pub(super) active_service_id: String,
    pub(super) active_realm_id: String,
    pub(super) active_projection_realm_id: String,
    pub(super) realm_live_epoch: Signal<u64>,
    pub(super) has_session: bool,
    pub(super) personal_control_realm_id: Option<String>,
    pub(super) routed_control_realm_id: Option<String>,
    pub(super) manage_realm_rows: Vec<RealmManageRow>,
    pub(super) realm_manage_query: Signal<String>,
    pub(super) direct_contact_rows: Signal<Vec<crate::models::ContactListRow>>,
    pub(super) direct_contacts_loaded: Signal<bool>,
    pub(super) contact_manage_query: Signal<String>,
    pub(super) secure_store_bootstrap_ready: Signal<bool>,
    pub(super) needs_device_authorization: Signal<bool>,
    pub(super) device_authorization_check_complete: Signal<bool>,
    pub(super) can_list_handles_for_subject: bool,
    pub(super) push_state: Signal<String>,
    pub(super) locale: Signal<UiLocale>,
    pub(super) theme: Signal<String>,
    pub(super) base_url: Signal<String>,
}

#[component]
pub(super) fn RouteSurface(state: RouteSurfaceState) -> Element {
    let sidecar_session = use_context::<crate::sidecar::HostedSidecarStateContext>().0;
    let RouteSurfaceState {
        content_route,
        navigation,
        principal_id: principal_id_signal,
        device_id,
        token,
        account_recovery_configured,
        config_store,
        account_primary_handle,
        personal_handles,
        personal_handles_status,
        realm_tree_nodes,
        device_queue,
        frontier_state,
        sync_cursor,
        resolved_realm_surface,
        server_description,
        event_write_ready,
        active_service_id,
        active_realm_id,
        active_projection_realm_id,
        realm_live_epoch,
        has_session,
        personal_control_realm_id,
        routed_control_realm_id,
        manage_realm_rows,
        realm_manage_query,
        direct_contact_rows,
        direct_contacts_loaded,
        contact_manage_query,
        secure_store_bootstrap_ready,
        needs_device_authorization,
        device_authorization_check_complete,
        can_list_handles_for_subject,
        push_state,
        locale,
        theme,
        base_url,
    } = state;
    let server_description = server_description();
    let NavigationState {
        route,
        view,
        mut selected_realm_id,
        new_space_context_node,
    } = navigation;
    let routed_circle_id = match &content_route {
        Route::CircleDetail { circle_id, .. } => Some(circle_id.clone()),
        _ => None,
    };
    let active_default_strand_id = {
        // Subscribe this route surface before reading the durable projection.
        // Without this read, a newly accepted default-Strand event updates the
        // store but cannot replace the temporary unavailable notice.
        let _realm_projection_epoch = realm_live_epoch();
        let state_store = SessionContext::get().state_store;
        state_store
            .read()
            .load()
            .realm_tree_projections
            .get(&active_realm_id)
            .and_then(crate::views::chat::default_discussion_strand_id)
    };
    // The Realm event stream normally folds set-default into the local
    // projection. If Chat wins that race, recover only from the standard,
    // caller-visible Strand projection's derived marker; never infer a
    // default from ordering, identity reuse, or hidden history.
    let mut default_strand_probe_for = use_signal(String::new);
    if matches!(content_route, Route::Chat { .. })
        && StationFeature::Discussion.ready(server_description.as_ref())
        && active_default_strand_id.is_none()
        && !active_realm_id.is_empty()
        && !token().trim().is_empty()
        && default_strand_probe_for() != active_realm_id
    {
        default_strand_probe_for.set(active_realm_id.clone());
        let realm_id = active_realm_id.clone();
        let base = base_url();
        let api_token = token();
        let mut state_store = SessionContext::get().state_store;
        let mut projection_epoch = realm_live_epoch;
        spawn(async move {
            for attempt in 0..20u32 {
                let result = crate::transport::auth::with_authed_sdk_client(
                    &base,
                    api_token.clone(),
                    |http| {
                        let realm_id = realm_id.clone();
                        async move {
                            http.realm_strands(&realm_id)
                                .await
                                .map_err(anyhow::Error::from)
                        }
                    },
                )
                .await;
                let default_strand_id = match result {
                    Ok(strands) => strands
                        .strands
                        .iter()
                        .find(|strand| strand.is_default)
                        .map(|strand| strand.strand_id.to_string()),
                    Err(error) => {
                        tracing::warn!(
                            realm_id,
                            attempt,
                            error = %error.display_diagnostic(),
                            "default Strand projection hydration failed"
                        );
                        None
                    }
                };
                if let Some(default_strand_id) = default_strand_id {
                    let changed = {
                        let mut store = state_store.write();
                        // A Realm created after this browser session booted can
                        // already be visible in the directory/sidebar while
                        // its sync-tree snapshot has not arrived yet. The
                        // authoritative Strand read is sufficient to seed the
                        // one derived field Chat needs; requiring a preexisting
                        // projection leaves a valid deep link permanently
                        // stuck on "Default Strand is unavailable".
                        let mut projection = store
                            .load()
                            .realm_tree_projections
                            .get(&realm_id)
                            .and_then(Value::as_object)
                            .cloned()
                            .unwrap_or_default();
                        if projection.get("default_strand_id").and_then(Value::as_str)
                            == Some(default_strand_id.as_str())
                        {
                            false
                        } else {
                            projection.insert(
                                "default_strand_id".to_owned(),
                                Value::String(default_strand_id),
                            );
                            store.save_realm_tree_projection(
                                realm_id.clone(),
                                Value::Object(projection),
                            );
                            true
                        }
                    };
                    if changed {
                        projection_epoch.set(projection_epoch().wrapping_add(1));
                    }
                    return;
                }
                if attempt < 19 {
                    let backoff_ms = 250u64.saturating_mul(1u64 << attempt.min(3));
                    crate::runtime_helpers::sleep_for(std::time::Duration::from_millis(backoff_ms))
                        .await;
                }
            }
            tracing::warn!(
                realm_id,
                "default Strand projection hydration exhausted retries"
            );
        });
    }

    // An authenticated AccountHandoff can precede the first principal binding.
    // Onboarding reconciles that holder-bound handoff with the Account Authority;
    // requiring an active Account here would make identity creation unreachable.
    if matches!(content_route, Route::Onboarding) {
        return rsx! {
            div { class: "realm-body",
                crate::views::onboarding::OnboardingPanel {
                    secure_store_ready: secure_store_bootstrap_ready(),
                    token,
                    principal_id: principal_id_signal,
                    device_id,
                    config_store,
                    account_primary_handle,
                    needs_device_authorization,
                    device_authorization_check_complete,
                }
            }
        };
    }

    let Some(principal_core_id) = SessionContext::get()
        .active_account()
        .map(|account| account.principal_id().clone())
    else {
        return rsx! {
            div {
                class: "panel-notice panel-notice-error",
                "The active account context is unavailable. Sign in again to continue."
            }
        };
    };
    let principal_id = principal_core_id.to_string();

    rsx! {
                div { class: "realm-body",
                match content_route {
                    _ if routed_control_realm_id.is_some() => rsx! {
                        PrincipalControlRealmPage {
                            realm_id: routed_control_realm_id.clone(),
                        }
                    },
                    Route::Login | Route::AuthCallback | Route::Register => {
                        unreachable!("auth routes are owned exclusively by SessionSurface")
                    },
                    Route::Dashboard => rsx! {
                        crate::views::dashboard::DashboardPanel {
                            token,
                            realm_tree_nodes,
                            selected_realm_id,
                            view,
                            device_queue: device_queue(),
                            frontier_state: frontier_state(),
                            sync_cursor: sync_cursor(),
                        }
                    },
                    Route::FileTransfer => rsx! {
                        crate::views::file_transfer::FileTransferPanel {
                            token,
                            principal_id: principal_id.clone(),
                            device_id: device_id(),
                        }
                    },
                    Route::Realm { .. } => {
                        match resolved_realm_surface.unwrap_or(RealmSurface::Board) {
                            RealmSurface::Board => {
                                if StationFeature::Board.ready(server_description.as_ref()) {
                                    rsx! {
                                        crate::views::kanban::KanbanPanel {
                                            plaintext_service_id: active_service_id.clone(),
                                            token,
                                            principal_id: principal_core_id.clone(),
                                            account_primary_handle,
                                            device_id: device_id(),
                                            selected_realm_id: active_realm_id.clone(),
                                            projection_realm_id: active_projection_realm_id.clone(),
                                            sync_cursor,
                                            realm_live_epoch,
                                            frontier_state,
                                            event_write_ready,
                                        }
                                    }
                                } else {
                                    rsx! { FeatureGateNotice { feature: StationFeature::Board, missing: (StationFeature::Board).missing_requirements(server_description.as_ref()), pending: server_description.is_none() } }
                                }
                            }
                        }
                    },
                    Route::DirectConversation { realm_id, strand_id } => {
                        if selected_realm_id() != *realm_id {
                            selected_realm_id.set(realm_id.clone());
                        }
                        if StationFeature::Discussion.ready(server_description.as_ref()) {
                            let direct_peer_id = {
                                let contacts = direct_contact_rows.read();
                                direct_conversation_peer_id(&contacts, &realm_id, &strand_id)
                            };
                            let active_sidecar_session = sidecar_session()
                                .filter(|session| session.matches_route(&realm_id, &strand_id));
                            rsx! {
                                crate::views::chat::ChatPanel {
                                    plaintext_service_id: active_service_id.clone(),
                                    principal_id: principal_core_id.clone(),
                                    account_primary_handle: account_primary_handle(),
                                    device_id: device_id(),
                                    token,
                                    selected_realm_id: realm_id.clone(),
                                    sync_cursor,
                                    realm_live_epoch,
                                    frontier_state,
                                    initial_strand_id: strand_id.clone(),
                                    embedded: false,
                                    direct_mode: true,
                                    direct_peer_id,
                                    sidecar_session: active_sidecar_session,
                                }
                            }
                        } else {
                            rsx! { FeatureGateNotice { feature: StationFeature::Discussion, missing: (StationFeature::Discussion).missing_requirements(server_description.as_ref()), pending: server_description.is_none() } }
                        }
                    },
                    Route::Chat { message, .. } => {
                        if let Some(sid) = route.realm_id()
                            && selected_realm_id() != sid
                        {
                            selected_realm_id.set(sid.to_owned());
                        }
                        if StationFeature::Discussion.ready(server_description.as_ref()) {
                            rsx! {
                                crate::views::chat::ChatPanel {
                                    plaintext_service_id: active_service_id.clone(),
                                    principal_id: principal_core_id.clone(),
                                    account_primary_handle: account_primary_handle(),
                                    device_id: device_id(),
                                    token,
                                    selected_realm_id: active_realm_id.clone(),
                                    sync_cursor,
                                    realm_live_epoch,
                                    frontier_state,
                                    initial_strand_id: active_default_strand_id.clone().unwrap_or_default(),
                                    embedded: false,
                                    direct_mode: false,
                                    focus_message_id: message.clone(),
                                }
                            }
                        } else {
                            rsx! { FeatureGateNotice { feature: StationFeature::Discussion, missing: (StationFeature::Discussion).missing_requirements(server_description.as_ref()), pending: server_description.is_none() } }
                        }
                    },
                    Route::Directory => rsx! {
                        crate::views::directory::DirectoryPanel {
                            selected_realm_id,
                            token,
                            view,
                        }
                    },
                    Route::RealmsManage => rsx! {
                        RealmsManagePage {
                            principal_id: principal_id.clone(),
                            principal_control_realm_id: personal_control_realm_id.clone(),
                            token,
                            has_session,
                            realm_rows: manage_realm_rows.clone(),
                            realm_tree_nodes,
                            selected_realm_id,
                            sync_cursor,
                            query: realm_manage_query,
                        }
                    },
                    Route::PrincipalControl => rsx! {
                        PrincipalControlRealmPage {
                            realm_id: personal_control_realm_id.clone(),
                        }
                    },
                    Route::ContactsManage => rsx! {
                        ContactsManagePage {
                            token,
                            has_session,
                            contact_rows: direct_contact_rows,
                            contacts_loaded: direct_contacts_loaded,
                            query: contact_manage_query,
                        }
                    },
                    Route::Contacts => rsx! {
                        crate::views::contacts::ContactsPanel {
                            token,
                        }
                    },
                    Route::Setup | Route::SetupSection { .. } => {
                        if setup_feature(&route).is_none_or(|feature| feature.ready(server_description.as_ref())) {
                            rsx! {
                                crate::views::setup::SetupPanel {
                                    plaintext_service_id: active_service_id.clone(),
                                    secure_store_ready: secure_store_bootstrap_ready(),
                                    token,
                                    account_recovery_configured,
                                    realm_tree_nodes,
                                    selected_realm_id,
                                    new_space_context_node,
                                    section: route.setup_section().map(str::to_owned),
                                }
                            }
                        } else {
                            rsx! { FeatureGateNotice { feature: setup_feature(&route).expect("setup feature is unavailable"), missing: (setup_feature(&route).expect("setup feature is unavailable")).missing_requirements(server_description.as_ref()), pending: server_description.is_none() } }
                        }
                    },
                    Route::Settings
                    | Route::SettingsSection { .. }
                    | Route::NotificationsSettings
                    | Route::SettingsDevices
                    | Route::SettingsDevicesPair
                    | Route::SettingsRecovery
                    | Route::Recovery
                    | Route::Audit
                    | Route::Developer => rsx! {
                        crate::views::settings::SettingsPanel {
                            token,
                            account_primary_handle: account_primary_handle(),
                            personal_handles: personal_handles(),
                            personal_handles_status: personal_handles_status(),
                            can_list_handles_for_subject,
                            config_store,
                            push_state,
                            locale,
                            theme,
                        }
                    },
                    Route::VerifyDevice => {
                        if StationFeature::VerifyDevice.ready(server_description.as_ref()) {
                            rsx! {
                                crate::views::verify_device::VerifyDevicePanel {
                                    token,
                                    device_id: device_id(),
                                    principal_id: principal_core_id.clone(),
                                    selected_realm_id: selected_realm_id(),
                                }
                            }
                        } else {
                            rsx! { FeatureGateNotice { feature: StationFeature::VerifyDevice, missing: (StationFeature::VerifyDevice).missing_requirements(server_description.as_ref()), pending: server_description.is_none() } }
                        }
                    },
                    Route::Circles { realm_id } | Route::CircleDetail { realm_id, .. } => {
                        if selected_realm_id() != *realm_id {
                            selected_realm_id.set(realm_id.clone());
                        }
                        if StationFeature::Circles.ready(server_description.as_ref()) {
                            rsx! {
                                crate::views::circles::CirclesPanel {
                                    realm_id: realm_id.clone(),
                                    selected_circle_id: routed_circle_id.clone(),
                                    principal_id: principal_core_id.clone(),
                                    token,
                                }
                            }
                        } else {
                            rsx! { FeatureGateNotice { feature: StationFeature::Circles, missing: (StationFeature::Circles).missing_requirements(server_description.as_ref()), pending: server_description.is_none() } }
                        }
                    },
                    Route::RealmMembers { .. } => {
                        if let Some(sid) = route.realm_id()
                            && selected_realm_id() != sid
                        {
                            selected_realm_id.set(sid.to_owned());
                        }
                        rsx! {
                            crate::views::realm_admin::RealmMembersPanel {
                                principal_id: principal_id.clone(),
                                token,
                                selected_realm_id: active_realm_id.clone(),
                                sync_cursor,
                                frontier_state,
                            }
                        }
                    },
                    Route::RealmAdmin { .. } | Route::RealmAdminSection { .. } => {
                        if let Some(sid) = route.realm_id()
                            && selected_realm_id() != sid
                        {
                            selected_realm_id.set(sid.to_owned());
                        }
                        rsx! {
                            crate::views::realm_admin::RealmAdminPanel {
                                principal_id: principal_id.clone(),
                                device_id: device_id(),
                                token,
                                selected_realm_id: active_realm_id.clone(),
                                sync_cursor,
                                frontier_state,
                                active_section: route.realm_admin_section().map(str::to_owned),
                            }
                        }
                    },
                    Route::Kanban
                    | Route::KanbanRealm { .. }
                    | Route::KanbanBoard { .. }
                    | Route::KanbanBoardTask { .. }
                    | Route::KanbanTask { .. } => {
                        if let Some(sid) = route.realm_id()
                            && selected_realm_id() != sid
                        {
                            selected_realm_id.set(sid.to_owned());
                        }
                        if StationFeature::Board.ready(server_description.as_ref()) {
                            rsx! {
                                crate::views::kanban::KanbanPanel {
                                    plaintext_service_id: active_service_id.clone(),
                                    token,
                                    principal_id: principal_core_id.clone(),
                                    account_primary_handle,
                                    device_id: device_id(),
                                    selected_realm_id: active_realm_id.clone(),
                                    projection_realm_id: active_projection_realm_id.clone(),
                                    sync_cursor,
                                    realm_live_epoch,
                                    frontier_state,
                                    event_write_ready,
                                }
                            }
                        } else {
                            rsx! { FeatureGateNotice { feature: StationFeature::Board, missing: (StationFeature::Board).missing_requirements(server_description.as_ref()), pending: server_description.is_none() } }
                        }
                    },
                    Route::Notifications => rsx! {
                        crate::views::notifications::NotificationsPanel {
                            principal_id: principal_id.clone(),
                            device_id: device_id(),
                            token,
                        }
                    },
                    Route::Call {
                        call_id,
                        peer,
                        realm_id,
                        video,
                        incoming,
                    } => {
                        if !crate::views::call::media_route_adapter_available() {
                            return rsx! {
                                div {
                                    class: "timeline",
                                    "data-testid": "call-route-unavailable",
                                    div { class: "event error-banner",
                                        div { class: "event-head", span { "Calls unavailable" } }
                                        div {
                                            class: "entity-title",
                                            "This host cannot verify media-service routes yet. No token exchange was attempted."
                                        }
                                    }
                                }
                            };
                        }
                        let call_realm_id = if realm_id.trim().is_empty() {
                            active_realm_id.clone()
                        } else {
                            realm_id.clone()
                        };
                        rsx! {
                            crate::views::call::CallPanel {
                                token,
                                selected_realm_id: call_realm_id,
                                principal_id: principal_id.clone(),
                                device_id: device_id(),
                                call_id: call_id.clone(),
                                peer: peer.clone(),
                                want_video: video == "1",
                                incoming: incoming == "1",
                            }
                        }
                    },
                    Route::Onboarding => {
                        unreachable!("onboarding is rendered before the active Account gate")
                    },
                    Route::Quarantine => rsx! {
                        crate::views::quarantine::QuarantinePanel {}
                    },
                    Route::Applets => rsx! {
                        if crate::views::applets::applets_enabled() {
                            crate::views::applets::AppletsPanel {
                                token,
                                selected_realm_id: selected_realm_id(),
                            }
                        } else {
                            DeferredFeatureGate { feature: "experimental-applets" }
                        }
                    },
                    // A6.1 — global cross-Space message search panel.
                    Route::Search => rsx! {
                        crate::views::global_search::GlobalSearchPanel {
                            principal_id: principal_id_signal,
                            device_id,
                            initial_query: String::new(),
                        }
                    },
                }
            }
    }
}

/// Setup overview is local navigation; only its actionable sections need a server.
fn setup_feature(route: &Route) -> Option<StationFeature> {
    match route.setup_section() {
        Some("realms" | "") | None => Some(StationFeature::CreateRealm),
        Some("new-space") => Some(StationFeature::CreateSpace),
        _ => None,
    }
}

#[cfg(test)]
mod feature_routing_tests {
    use super::*;

    #[test]
    fn setup_gates_only_the_selected_workflow() {
        assert_eq!(
            setup_feature(&Route::Setup),
            Some(StationFeature::CreateRealm)
        );
        assert_eq!(
            setup_feature(&Route::SetupSection {
                section: "realms".into()
            }),
            Some(StationFeature::CreateRealm)
        );
        assert_eq!(
            setup_feature(&Route::SetupSection {
                section: "new-space".into()
            }),
            Some(StationFeature::CreateSpace)
        );
        assert_eq!(
            setup_feature(&Route::SetupSection {
                section: "overview".into()
            }),
            None
        );
        assert_eq!(
            setup_feature(&Route::SetupSection {
                section: "unknown".into()
            }),
            None
        );
    }
}
