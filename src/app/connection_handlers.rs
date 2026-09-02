use super::*;
use crate::api_error::is_auth_expired_error;

/// Root-owned connection signals shared by bootstrap effects and explicit UI
/// commands. This is a bundle of existing handles, not a second state store.
#[derive(Clone, Copy, PartialEq)]
pub(super) struct ConnectionRuntimeSignals {
    pub(super) connection_status: Signal<String>,
    pub(super) sync_cursor: Signal<String>,
    pub(super) token: Signal<String>,
    pub(super) principal_id: Signal<Option<arkret_sdk::DidCoreId>>,
    pub(super) device_id: Signal<String>,
    pub(super) selected_realm_id: Signal<String>,
    pub(super) realm_tree_nodes: Signal<Vec<RealmTreeNode>>,
    pub(super) projection_events: Signal<Vec<ProjectionEvent>>,
    pub(super) device_queue: Signal<usize>,
    pub(super) frontier_state: Signal<String>,
    pub(super) crypto_state: Signal<String>,
    pub(super) config_store: Signal<LocalConfigStore>,
    pub(super) network_state: Signal<String>,
    pub(super) last_error: Signal<Option<String>>,
    pub(super) server_description: Signal<Option<ServiceDescribe>>,
    pub(super) server_probe_status: Signal<String>,
    pub(super) account_primary_handle: Signal<String>,
    pub(super) personal_handles: Signal<Vec<String>>,
    pub(super) personal_handles_status: Signal<String>,
    pub(super) theme: Signal<String>,
    pub(super) sync_generation: Signal<u64>,
    pub(super) needs_device_authorization: Signal<bool>,
    pub(super) device_authorization_check_complete: Signal<bool>,
    pub(super) account_has_other_devices: Signal<bool>,
    pub(super) sync_bootstrap_complete: Signal<bool>,
    pub(super) session_boot_state: Signal<SessionBootState>,
    pub(super) bootstrap_pending: Signal<bool>,
    pub(super) did_resolution_health: Signal<crate::components::DidResolutionHealth>,
}

impl ConnectionRuntimeSignals {
    pub(super) fn connect_context(
        self,
        session: crate::runtime::session::SessionCoordinator,
        state_store: SyncSignal<LocalStateStore>,
        did_cache: Signal<arkret_sdk::identity::DidResolutionCache>,
    ) -> ConnectContext {
        ConnectContext {
            session,
            connection_status: self.connection_status,
            sync_cursor: self.sync_cursor,
            token: self.token,
            principal_id: self.principal_id,
            selected_realm_id: self.selected_realm_id,
            realm_tree_nodes: self.realm_tree_nodes,
            projection_events: self.projection_events,
            device_queue: self.device_queue,
            crypto_state: self.crypto_state,
            config_store: self.config_store,
            state_store,
            network_state: self.network_state,
            last_error: self.last_error,
            server_description: self.server_description,
            server_probe_status: self.server_probe_status,
            account_primary_handle: self.account_primary_handle,
            personal_handles: self.personal_handles,
            personal_handles_status: self.personal_handles_status,
            theme: self.theme,
            sync_generation: self.sync_generation,
            needs_device_authorization: self.needs_device_authorization,
            device_authorization_check_complete: self.device_authorization_check_complete,
            account_has_other_devices: self.account_has_other_devices,
            sync_bootstrap_complete: self.sync_bootstrap_complete,
            session_boot_state: self.session_boot_state,
            bootstrap_pending: self.bootstrap_pending,
            did_cache,
            did_resolution_health: self.did_resolution_health,
        }
    }
}

/// Explicit refresh from the mobile connection status. Keep the generation
/// fence and bootstrap-ready reset ahead of the spawned connect attempt.
pub(super) fn refresh_connection(
    base: String,
    runtime: ConnectionRuntimeSignals,
    session: crate::runtime::session::SessionCoordinator,
    state_store: SyncSignal<LocalStateStore>,
    did_cache: Signal<arkret_sdk::identity::DidResolutionCache>,
) {
    let mut sync_generation = runtime.sync_generation;
    let mut sync_bootstrap_complete = runtime.sync_bootstrap_complete;
    sync_generation.set(sync_generation() + 1);
    sync_bootstrap_complete.set(false);
    connect(
        base,
        (runtime.principal_id)(),
        (runtime.device_id)(),
        runtime.connect_context(session, state_store, did_cache),
    );
}

#[derive(Clone)]
pub(super) struct ServerSwitchHandlerContext {
    pub(super) runtime: ConnectionRuntimeSignals,
    pub(super) base_url: Signal<String>,
    pub(super) state_store: SyncSignal<LocalStateStore>,
    pub(super) did_cache: Signal<arkret_sdk::identity::DidResolutionCache>,
    pub(super) personal_handles_lookup_key: Signal<String>,
    pub(super) server_menu_open: Signal<bool>,
    pub(super) session: crate::runtime::session::SessionCoordinator,
}

/// Reset the selected Station first, then connect against the newly selected
/// base. The ordering preserves the cache/grant fence in `select_server`.
pub(super) fn switch_server_and_connect(option_url: String, ctx: ServerSwitchHandlerContext) {
    let next_url = normalize_server_url(&option_url);
    let runtime = ctx.runtime;
    select_server(
        next_url.clone(),
        ServerSelectionContext {
            base_url: ctx.base_url,
            token: runtime.token,
            sync_cursor: runtime.sync_cursor,
            selected_realm_id: runtime.selected_realm_id,
            realm_tree_nodes: runtime.realm_tree_nodes,
            projection_events: runtime.projection_events,
            device_queue: runtime.device_queue,
            frontier_state: runtime.frontier_state,
            crypto_state: runtime.crypto_state,
            config_store: runtime.config_store,
            state_store: ctx.state_store,
            network_state: runtime.network_state,
            last_error: runtime.last_error,
            server_description: runtime.server_description,
            server_probe_status: runtime.server_probe_status,
            connection_status: runtime.connection_status,
            principal_id: runtime.principal_id,
            device_id: runtime.device_id,
            account_primary_handle: runtime.account_primary_handle,
            personal_handles: runtime.personal_handles,
            personal_handles_status: runtime.personal_handles_status,
            personal_handles_lookup_key: ctx.personal_handles_lookup_key,
            sync_generation: runtime.sync_generation,
        },
    );
    let mut server_menu_open = ctx.server_menu_open;
    let mut sync_bootstrap_complete = runtime.sync_bootstrap_complete;
    server_menu_open.set(false);
    sync_bootstrap_complete.set(false);
    connect(
        next_url,
        (runtime.principal_id)(),
        (runtime.device_id)(),
        runtime.connect_context(ctx.session, ctx.state_store, ctx.did_cache),
    );
}

#[derive(Clone)]
pub(super) struct ManualSessionRefreshContext {
    pub(super) session: crate::runtime::session::SessionCoordinator,
    pub(super) token: Signal<String>,
    pub(super) principal_id: Signal<Option<arkret_sdk::DidCoreId>>,
    pub(super) active_account: Signal<Option<crate::config::ActiveAccountContext>>,
    pub(super) account_session_state: Signal<String>,
    pub(super) personal_handles_lookup_key: Signal<String>,
    pub(super) account_identity_lookup_key: Signal<String>,
    pub(super) account_primary_handle: Signal<String>,
    pub(super) personal_handles: Signal<Vec<String>>,
    pub(super) personal_handles_status: Signal<String>,
    pub(super) last_error: Signal<Option<String>>,
    pub(super) config_store: Signal<LocalConfigStore>,
}

/// Refresh the account viewer from a render-time base/session snapshot while
/// reading identity signals at click time and validating the live accepted
/// account again after the network await.
pub(super) fn refresh_current_session(base: String, ctx: ManualSessionRefreshContext) {
    let api_token = (ctx.token)();
    let actor = (ctx.principal_id)();
    let Some(active) = ctx.active_account.peek().clone() else {
        let mut account_session_state = ctx.account_session_state;
        account_session_state.set("Session identity is unavailable; sign in again.".to_owned());
        return;
    };
    let mut personal_handles_lookup_key = ctx.personal_handles_lookup_key;
    let mut account_identity_lookup_key = ctx.account_identity_lookup_key;
    let mut account_session_state = ctx.account_session_state;
    personal_handles_lookup_key.set(String::new());
    account_identity_lookup_key.set(String::new());
    account_session_state.set("Refreshing session".to_owned());
    spawn(async move {
        let mut principal_id = ctx.principal_id;
        let mut last_error = ctx.last_error;
        let mut account_primary_handle = ctx.account_primary_handle;
        let mut personal_handles = ctx.personal_handles;
        let mut personal_handles_status = ctx.personal_handles_status;
        match self_authed_api(&base, api_token.clone()) {
            Ok(api) => {
                match async { crate::transport::account::account_me(&api.sdk_http_client()?).await }
                    .await
                {
                    Ok(account) => {
                        let canonical_principal = match ctx.active_account.peek().as_ref() {
                            Some(context) if context.principal_id() == &account.principal_id => {
                                Some(context.principal_id().clone())
                            }
                            _ => {
                                last_error.set(Some(
                                "account viewer authority does not match the accepted active context"
                                    .to_owned(),
                            ));
                                account_session_state.set(
                                    "Session identity could not be restored; sign in again."
                                        .to_owned(),
                                );
                                return;
                            }
                        };
                        if let Some(personal_handle) =
                            personal_handle_from_account_handle(&account.handle)
                        {
                            account_primary_handle.set(personal_handle.clone());
                            let handles =
                                merge_personal_handles(&personal_handles(), [personal_handle]);
                            personal_handles_status.set(personal_handles_status_for(&handles));
                            personal_handles.set(handles);
                        } else {
                            account_primary_handle.set(String::new());
                            if personal_handles().is_empty() {
                                personal_handles_status.set("Not published".to_owned());
                            }
                        }
                        principal_id.set(canonical_principal.clone());
                        persist_config(
                            ctx.config_store,
                            active.server_url.to_string(),
                            Some(active.principal_id().clone()),
                            active.device_id.to_string(),
                            api_token,
                        );
                        account_session_state.set(format!(
                            "Session refresh ok: {}",
                            crate::app::principal_id_text(&canonical_principal)
                        ));
                    }
                    Err(error) => {
                        if is_auth_expired_error(&error) {
                            match ctx.session.refresh().await {
                            crate::runtime::session::CurrentSessionRefresh::Credential(fresh) => {
                                let canonical_principal = match self_authed_api(&base, fresh) {
                                    Ok(api) => async {
                                        crate::transport::account::account_me(&api.sdk_http_client()?)
                                            .await
                                    }
                                    .await
                                    .ok()
                                    .and_then(|account| {
                                        ctx.active_account
                                            .peek()
                                            .as_ref()
                                            .filter(|context| {
                                                context.principal_id() == &account.principal_id
                                            })?;
                                        if let Some(personal_handle) =
                                            personal_handle_from_account_handle(&account.handle)
                                        {
                                            account_primary_handle.set(personal_handle.clone());
                                            let handles = merge_personal_handles(
                                                &personal_handles(),
                                                [personal_handle],
                                            );
                                            personal_handles_status
                                                .set(personal_handles_status_for(&handles));
                                            personal_handles.set(handles);
                                        } else {
                                            account_primary_handle.set(String::new());
                                            if personal_handles().is_empty() {
                                                personal_handles_status
                                                    .set("Not published".to_owned());
                                            }
                                        }
                                        Some(active.principal_id().clone())
                                    }),
                                    Err(_) => None,
                                }
                                .or(actor.clone());
                                principal_id.set(canonical_principal.clone());
                                account_session_state.set(format!(
                                    "Session refresh ok: {}",
                                    crate::app::principal_id_text(&canonical_principal)
                                ));
                            }
                            crate::runtime::session::CurrentSessionRefresh::SignInRequired {
                                reason,
                            } => {
                                last_error.set(Some(reason));
                                account_session_state
                                    .set("Sign in again to refresh this session.".to_owned());
                            }
                            crate::runtime::session::CurrentSessionRefresh::LoginRequired {
                                reason,
                            } => {
                                last_error.set(Some(reason));
                                account_session_state
                                    .set("Session expired. Sign in again.".to_owned());
                            }
                            crate::runtime::session::CurrentSessionRefresh::RetryLater {
                                reason,
                            } => {
                                account_session_state
                                    .set(format!("Session refresh pending: {reason}"));
                            }
                        }
                        } else {
                            account_session_state.set(format!("Session refresh failed: {error}"));
                        }
                    }
                }
            }
            Err(error) => account_session_state.set(format!("Invalid server URL: {error}")),
        }
    });
}
