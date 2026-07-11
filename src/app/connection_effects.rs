use super::*;

#[derive(Clone, Copy, PartialEq)]
pub(super) struct ConnectionEffectState {
    pub connection_status: Signal<String>,
    pub sync_cursor: Signal<String>,
    pub token: Signal<String>,
    pub account_did: Signal<String>,
    pub device_id: Signal<String>,
    pub selected_realm_id: Signal<String>,
    pub realm_tree_nodes: Signal<Vec<RealmTreeNode>>,
    pub projection_events: Signal<Vec<ProjectionEvent>>,
    pub device_queue: Signal<usize>,
    pub frontier_state: Signal<String>,
    pub crypto_state: Signal<String>,
    pub config_store: Signal<LocalConfigStore>,
    pub network_state: Signal<String>,
    pub last_error: Signal<Option<String>>,
    pub server_description: Signal<Option<ServerDescription>>,
    pub server_probe_status: Signal<String>,
    pub account_primary_handle: Signal<String>,
    pub personal_handles: Signal<Vec<String>>,
    pub personal_handles_status: Signal<String>,
    pub theme: Signal<String>,
    pub sync_generation: Signal<u64>,
    pub needs_device_authorization: Signal<bool>,
    pub device_authorization_check_complete: Signal<bool>,
    pub account_has_other_devices: Signal<bool>,
    pub sync_bootstrap_complete: Signal<bool>,
    pub session_boot_state: Signal<SessionBootState>,
    pub secure_store_bootstrap_ready: Signal<bool>,
    pub session_generation: Signal<u64>,
    pub did_resolution_health: Signal<crate::components::DidResolutionHealth>,
    pub bootstrap_pending: Signal<bool>,
}

#[component]
pub(super) fn ConnectionEffects(state: ConnectionEffectState) -> Element {
    let ConnectionEffectState {
        mut connection_status,
        mut sync_cursor,
        mut token,
        account_did,
        device_id,
        mut selected_realm_id,
        mut realm_tree_nodes,
        mut projection_events,
        mut device_queue,
        frontier_state,
        mut crypto_state,
        config_store,
        mut network_state,
        mut last_error,
        server_description,
        server_probe_status,
        account_primary_handle,
        personal_handles,
        personal_handles_status,
        theme,
        mut sync_generation,
        mut needs_device_authorization,
        mut device_authorization_check_complete,
        mut account_has_other_devices,
        mut sync_bootstrap_complete,
        mut session_boot_state,
        secure_store_bootstrap_ready,
        mut session_generation,
        did_resolution_health,
        mut bootstrap_pending,
    } = state;
    let SessionContext {
        mut state_store,
        base_url,
    } = SessionContext::get();
    let runtime_services = use_context::<crate::runtime::services::RuntimeServices>();
    let navigator = use_navigator();
    let call_signal_hub = use_context::<crate::views::call_signals::CallSignalHub>();
    let did_cache = use_context::<Signal<crate::identity::did_resolver::DidResolutionCache>>();

    {
        let invalidator_effects = runtime_services.effects.clone();
        let session_coordinator = runtime_services.session.clone();
        use_hook(move || {
            session_coordinator.set_invalidator(move |reason| {
                invalidator_effects.request_cancel_all();
                session_generation.set(session_generation() + 1);
                state_store.write().set_session_grant(None);
                token.set(String::new());
                crate::config::clear_session_credential_secret(&account_did());
                persist_config(
                    config_store,
                    base_url(),
                    account_did(),
                    device_id(),
                    String::new(),
                );
                sync_cursor.set(String::new());
                selected_realm_id.set(String::new());
                realm_tree_nodes.set(Vec::new());
                projection_events.set(Vec::new());
                device_queue.set(0);
                crypto_state.set("Session expired".to_owned());
                connection_status.set("Session expired; sign in again".to_owned());
                network_state.set("online".to_owned());
                last_error.set(Some(reason));
                needs_device_authorization.set(false);
                device_authorization_check_complete.set(false);
                account_has_other_devices.set(false);
                sync_generation.set(sync_generation() + 1);
                session_boot_state.set(SessionBootState::Unauthenticated);
                let _ = navigator.push(Route::Login);
            });
        });
    }

    use_effect(move || {
        let projections = state_store.read().load().realm_tree_projections;
        let next = realm_tree_nodes_from_sync_realms(&projections);
        if *realm_tree_nodes.peek() != next {
            realm_tree_nodes.set(next);
        }
    });

    let secure_store_ready = secure_store_bootstrap_ready();
    if bootstrap_pending() {
        let base = base_url();
        let mut session = token();
        if session.trim().is_empty() && secure_store_ready {
            let loaded = config_store.read().load();
            if let Some(rehydrated) = rehydrated_session_credential_for_active_config(
                &loaded,
                &base,
                &account_did(),
                &device_id(),
            ) {
                token.set(rehydrated.clone());
                session = rehydrated;
            }
        }
        if !session.trim().is_empty() {
            let stale_for_selected_server = state_store
                .read()
                .session_grant()
                .as_ref()
                .is_some_and(|grant| {
                    !crate::identity::session_refresh::grant_matches_principal_server(grant, &base)
                });
            if stale_for_selected_server {
                token.set(String::new());
                session_boot_state.set(SessionBootState::Unauthenticated);
                persist_config(
                    config_store,
                    base.clone(),
                    account_did(),
                    device_id(),
                    String::new(),
                );
                session.clear();
            }
        }
        let can_restore_session = {
            let store = state_store.read();
            has_bootstrap_refresh_material(&store, &base, &account_did())
        };
        if !base.trim().is_empty()
            && secure_store_ready
            && (!session.trim().is_empty() || can_restore_session)
        {
            bootstrap_pending.set(false);
            sync_bootstrap_complete.set(false);
            let bootstrap_state = session_boot_state_from_bootstrap_material(
                &session,
                can_restore_session,
                &account_did(),
                secure_store_ready,
            );
            session_boot_state.set(bootstrap_state);
            connect(
                base,
                account_did(),
                device_id(),
                ConnectContext {
                    session: runtime_services.session.clone(),
                    connection_status,
                    sync_cursor,
                    token,
                    account_did,
                    device_id,
                    selected_realm_id,
                    realm_tree_nodes,
                    projection_events,
                    device_queue,
                    frontier_state,
                    crypto_state,
                    config_store,
                    state_store,
                    network_state,
                    last_error,
                    server_description,
                    server_probe_status,
                    account_primary_handle,
                    personal_handles,
                    personal_handles_status,
                    theme,
                    sync_generation,
                    needs_device_authorization,
                    device_authorization_check_complete,
                    account_has_other_devices,
                    sync_bootstrap_complete,
                    session_boot_state,
                    call_signal_hub,
                    did_cache,
                    did_resolution_health,
                },
            );
        } else if !base.trim().is_empty() {
            let bootstrap_state = session_boot_state_from_bootstrap_material(
                &session,
                can_restore_session,
                &account_did(),
                secure_store_ready,
            );
            if *session_boot_state.peek() != bootstrap_state {
                session_boot_state.set(bootstrap_state);
            }
        }
    }

    rsx! {}
}
