use super::*;

#[derive(Clone, PartialEq)]
pub(super) struct RouteSurfaceState {
    pub(super) content_route: Route,
    pub(super) navigation: NavigationState,
    pub(super) account_did: Signal<String>,
    pub(super) device_id: Signal<String>,
    pub(super) token: Signal<String>,
    pub(super) connection_status: Signal<String>,
    pub(super) config_store: Signal<LocalConfigStore>,
    pub(super) account_primary_handle: Signal<String>,
    pub(super) personal_handles: Signal<Vec<String>>,
    pub(super) personal_handles_status: Signal<String>,
    pub(super) realm_tree_nodes: Signal<Vec<RealmTreeNode>>,
    pub(super) device_queue: Signal<usize>,
    pub(super) frontier_state: Signal<String>,
    pub(super) sync_cursor: Signal<String>,
    pub(super) resolved_realm_surface: Option<RealmSurface>,
    pub(super) minimal_ready: bool,
    pub(super) kanban_ready: bool,
    pub(super) full_ready: bool,
    pub(super) e2ee_ready: bool,
    pub(super) event_write_ready: bool,
    pub(super) active_service_id: String,
    pub(super) active_realm_id: String,
    pub(super) active_projection_realm_id: String,
    pub(super) realm_live_epoch: Signal<u64>,
    pub(super) has_session: bool,
    pub(super) manage_realm_rows: Vec<RealmManageRow>,
    pub(super) realm_manage_query: Signal<String>,
    pub(super) manage_realm_selection: Signal<BTreeSet<String>>,
    pub(super) manage_bulk_busy: Signal<bool>,
    pub(super) direct_contact_rows: Signal<Vec<crate::models::ContactListRow>>,
    pub(super) direct_contacts_loaded: Signal<bool>,
    pub(super) contact_manage_query: Signal<String>,
    pub(super) manage_contact_selection: Signal<BTreeSet<String>>,
    pub(super) secure_store_bootstrap_ready: Signal<bool>,
    pub(super) can_list_handles_for_subject: bool,
    pub(super) push_state: Signal<String>,
    pub(super) locale: Signal<Locale>,
    pub(super) theme: Signal<String>,
    pub(super) base_url: Signal<String>,
}

#[component]
pub(super) fn RouteSurface(state: RouteSurfaceState) -> Element {
    let sidecar_session = use_context::<crate::sidecar::SidecarSessionContext>().0;
    let RouteSurfaceState {
        content_route,
        navigation,
        account_did,
        device_id,
        token,
        connection_status,
        config_store,
        account_primary_handle,
        personal_handles,
        personal_handles_status,
        realm_tree_nodes,
        device_queue,
        frontier_state,
        sync_cursor,
        resolved_realm_surface,
        minimal_ready,
        kanban_ready,
        full_ready,
        e2ee_ready,
        event_write_ready,
        active_service_id,
        active_realm_id,
        active_projection_realm_id,
        realm_live_epoch,
        has_session,
        manage_realm_rows,
        realm_manage_query,
        manage_realm_selection,
        manage_bulk_busy,
        direct_contact_rows,
        direct_contacts_loaded,
        contact_manage_query,
        manage_contact_selection,
        secure_store_bootstrap_ready,
        can_list_handles_for_subject,
        push_state,
        locale,
        theme,
        base_url: _,
    } = state;
    let NavigationState {
        route,
        view,
        mut selected_realm_id,
        new_space_context_node,
    } = navigation;
    let navigator = use_navigator();
    let routed_circle_id = match &content_route {
        Route::CircleDetail { circle_id, .. } => Some(circle_id.clone()),
        _ => None,
    };

    rsx! {
                div { class: "workspace-body",
                match content_route {
                    Route::Login => rsx! {
                        crate::views::login::LoginPanel {
                            account_did,
                            device_id,
                            token,
                            connection_status,
                            config_store,
                            account_primary_handle,
                            personal_handles,
                            personal_handles_status,
                            auto_capture_callback: false,
                            on_login: move |_| { let _ = navigator.push(Route::Dashboard); },
                            on_onboarding: move |_| { let _ = navigator.push(Route::Onboarding); },
                        }
                    },
                    Route::AuthCallback => rsx! {
                        crate::views::login::LoginPanel {
                            account_did,
                            device_id,
                            token,
                            connection_status,
                            config_store,
                            account_primary_handle,
                            personal_handles,
                            personal_handles_status,
                            auto_capture_callback: true,
                            on_login: move |_| { let _ = navigator.push(Route::Dashboard); },
                            on_onboarding: move |_| { let _ = navigator.push(Route::Onboarding); },
                        }
                    },
                    Route::Register => rsx! {
                        crate::views::register::RegistrationPanel { device_id }
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
                            account_did: account_did(),
                            device_id: device_id(),
                        }
                    },
                    Route::Realm { .. } => {
                        match resolved_realm_surface.unwrap_or(RealmSurface::Board) {
                            RealmSurface::Board => {
                                if kanban_ready {
                                    rsx! {
                                        crate::views::kanban::KanbanPanel {
                                            plaintext_service_id: active_service_id.clone(),
                                            token,
                                            account_did: account_did(),
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
                                    rsx! { ProfileGateNotice { profile: "kanban_mvp" } }
                                }
                            }
                        }
                    },
                    Route::DirectConversation { realm_id, strand_id } => {
                        if selected_realm_id() != *realm_id {
                            selected_realm_id.set(realm_id.clone());
                        }
                        if minimal_ready {
                            let active_sidecar_session = sidecar_session()
                                .filter(|session| session.matches_route(&realm_id, &strand_id));
                            rsx! {
                                crate::views::chat::ChatPanel {
                                    plaintext_service_id: active_service_id.clone(),
                                    account_did: account_did(),
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
                                    sidecar_session: active_sidecar_session,
                                }
                            }
                        } else {
                            rsx! { ProfileGateNotice { profile: "minimal_client" } }
                        }
                    },
                    Route::Chat { message, .. } => {
                        if let Some(sid) = route.realm_id()
                            && selected_realm_id() != sid
                        {
                            selected_realm_id.set(sid.to_owned());
                        }
                        if minimal_ready {
                            rsx! {
                                crate::views::chat::ChatPanel {
                                    plaintext_service_id: active_service_id.clone(),
                                    account_did: account_did(),
                                    account_primary_handle: account_primary_handle(),
                                    device_id: device_id(),
                                    token,
                                    selected_realm_id: active_realm_id.clone(),
                                    sync_cursor,
                                    realm_live_epoch,
                                    frontier_state,
                                    initial_strand_id: default_strand_id_for_realm(&active_realm_id),
                                    embedded: false,
                                    direct_mode: false,
                                    focus_message_id: message.clone(),
                                }
                            }
                        } else {
                            rsx! { ProfileGateNotice { profile: "minimal_client" } }
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
                            account_did: account_did(),
                            token,
                            has_session,
                            realm_rows: manage_realm_rows.clone(),
                            realm_tree_nodes,
                            selected_realm_id,
                            sync_cursor,
                            query: realm_manage_query,
                            selection: manage_realm_selection,
                            busy: manage_bulk_busy,
                        }
                    },
                    Route::ContactsManage => rsx! {
                        ContactsManagePage {
                            token,
                            has_session,
                            contact_rows: direct_contact_rows,
                            contacts_loaded: direct_contacts_loaded,
                            query: contact_manage_query,
                            selection: manage_contact_selection,
                            busy: manage_bulk_busy,
                        }
                    },
                    Route::Contacts => rsx! {
                        crate::views::contacts::ContactsPanel {
                            token,
                        }
                    },
                    Route::Setup | Route::SetupSection { .. } => {
                        if full_ready {
                            rsx! {
                                crate::views::setup::SetupPanel {
                                    plaintext_service_id: active_service_id.clone(),
                                    secure_store_ready: secure_store_bootstrap_ready(),
                                    token,
                                    account_did,
                                    device_id,
                                    config_store,
                                    realm_tree_nodes,
                                    selected_realm_id,
                                    new_space_context_node,
                                    section: route.setup_section().map(str::to_owned),
                                }
                            }
                        } else {
                            rsx! { ProfileGateNotice { profile: "full_client" } }
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
                            account_did,
                            device_id,
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
                        if e2ee_ready {
                            rsx! {
                                crate::views::verify_device::VerifyDevicePanel {
                                    token,
                                    device_id: device_id(),
                                    account_did: account_did(),
                                    selected_realm_id: selected_realm_id(),
                                }
                            }
                        } else {
                            rsx! { ProfileGateNotice { profile: "e2ee_client" } }
                        }
                    },
                    Route::Circles { realm_id } | Route::CircleDetail { realm_id, .. } => {
                        if selected_realm_id() != *realm_id {
                            selected_realm_id.set(realm_id.clone());
                        }
                        if full_ready {
                            rsx! {
                                crate::views::circles::CirclesPanel {
                                    realm_id: realm_id.clone(),
                                    selected_circle_id: routed_circle_id.clone(),
                                    account_did: account_did(),
                                    token,
                                }
                            }
                        } else {
                            rsx! { ProfileGateNotice { profile: "full_client" } }
                        }
                    },
                    Route::RealmMembers { .. } => {
                        if let Some(sid) = route.realm_id()
                            && selected_realm_id() != sid
                        {
                            selected_realm_id.set(sid.to_owned());
                        }
                        if full_ready {
                            rsx! {
                                crate::views::realm_admin::RealmMembersPanel {
                                    active_service_id: active_service_id.clone(),
                                    account_did: account_did(),
                                    device_id: device_id(),
                                    token,
                                    selected_realm_id: active_realm_id.clone(),
                                    sync_cursor,
                                    frontier_state,
                                }
                            }
                        } else {
                            rsx! { ProfileGateNotice { profile: "full_client" } }
                        }
                    },
                    Route::RealmAdmin { .. } | Route::RealmAdminSection { .. } => {
                        if let Some(sid) = route.realm_id()
                            && selected_realm_id() != sid
                        {
                            selected_realm_id.set(sid.to_owned());
                        }
                        if full_ready {
                            rsx! {
                                crate::views::realm_admin::RealmAdminPanel {
                                    account_did: account_did(),
                                    device_id: device_id(),
                                    token,
                                    selected_realm_id: active_realm_id.clone(),
                                    sync_cursor,
                                    frontier_state,
                                    active_section: route.realm_admin_section().map(str::to_owned),
                                }
                            }
                        } else {
                            rsx! { ProfileGateNotice { profile: "full_client" } }
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
                        if kanban_ready {
                            rsx! {
                                crate::views::kanban::KanbanPanel {
                                    plaintext_service_id: active_service_id.clone(),
                                    token,
                                    account_did: account_did(),
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
                            rsx! { ProfileGateNotice { profile: "kanban_mvp" } }
                        }
                    },
                    Route::Notifications => rsx! {
                        crate::views::notifications::NotificationsPanel {
                            account_did: account_did(),
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
                        let call_realm_id = if realm_id.trim().is_empty() {
                            active_realm_id.clone()
                        } else {
                            realm_id.clone()
                        };
                        rsx! {
                            crate::views::call::CallPanel {
                                token,
                                selected_realm_id: call_realm_id,
                                account_did: account_did(),
                                device_id: device_id(),
                                call_id: call_id.clone(),
                                peer: peer.clone(),
                                want_video: video == "1",
                                incoming: incoming == "1",
                            }
                        }
                    },
                    Route::Onboarding => rsx! {
                        crate::views::onboarding::OnboardingPanel {
                            secure_store_ready: secure_store_bootstrap_ready(),
                            token,
                            account_did,
                            device_id,
                            config_store,
                            account_primary_handle,
                        }
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
                            account_did,
                            device_id,
                            initial_query: String::new(),
                        }
                    },
                }
            }
    }
}
