use super::*;

pub(super) fn display_handles_from_directory_response(
    res: &arkret_models_discovery::DirectorySubjectHandleList,
) -> Vec<String> {
    let mut seen = BTreeSet::<String>::new();
    let mut handles = Vec::<String>::new();
    let mut push_handle = |handle: String| {
        if !handle.trim().is_empty() && seen.insert(handle.clone()) {
            handles.push(handle);
        }
    };
    if let Some(primary) = res.primary_handle.as_ref() {
        push_handle(primary.canonical().to_owned());
    }
    for claim in &res.claims {
        push_handle(claim.handle.canonical().to_owned());
    }
    handles
}

pub(crate) fn merge_personal_handles(
    current: &[String],
    incoming: impl IntoIterator<Item = String>,
) -> Vec<String> {
    let mut seen = BTreeSet::<String>::new();
    let mut merged = Vec::<String>::new();
    let mut push_handle = |handle: String| {
        if let Some(canonical) = canonical_personal_handle(&handle)
            && seen.insert(canonical.clone())
        {
            merged.push(canonical);
        }
    };
    for handle in current {
        push_handle(handle.clone());
    }
    for handle in incoming {
        push_handle(handle);
    }
    merged
}

pub(crate) fn personal_handles_status_for(handles: &[String]) -> String {
    match handles.len() {
        0 => "Not published".to_owned(),
        1 => "1 handle".to_owned(),
        count => format!("{count} handles"),
    }
}

fn canonical_personal_handle(handle: &str) -> Option<String> {
    let trimmed = handle.trim().trim_start_matches('@').trim();
    if trimmed.is_empty() {
        return None;
    }
    crate::identity::handle::normalize_user_handle_display(trimmed)
}

/// Build the account's personal **handle** (`<localpart>:<domain>`) from the
/// `account_me` projection, for the account menu label and the recovery-key
/// download filename.
///
/// `account.handle` (see [`crate::transport::account`]'s `primary_handle_from_viewer`)
/// is the **full canonical handle** carried by the signed primary handle claim
/// — it is *not* a bare localpart. Invalid or empty values are treated as an
/// absent primary handle claim; directory handles and server URLs must not be
/// used as recovery-key filename sources.
pub(crate) fn personal_handle_from_account_handle(account_handle: &str) -> Option<String> {
    let trimmed = account_handle.trim().trim_start_matches('@').trim();
    if trimmed.is_empty() {
        return None;
    }
    crate::identity::handle::normalize_user_handle_display(trimmed)
}

pub(super) fn account_handles_display(handles: &[String], fallback: &str) -> String {
    if handles.is_empty() {
        fallback.to_owned()
    } else {
        handles
            .iter()
            .map(|handle| format!("@{handle}"))
            .collect::<Vec<_>>()
            .join(", ")
    }
}

pub(crate) fn server_key(server_url: &str) -> String {
    crate::config::server_url_key(server_url)
}

pub(super) fn same_server_url(left: &str, right: &str) -> bool {
    crate::config::same_server_url(left, right)
}

pub(super) fn server_options_for(
    current_server_url: &str,
    configured_stations: &[url::Url],
) -> Vec<String> {
    crate::config::station_options_for(current_server_url, configured_stations)
}

#[derive(Clone, Copy)]
pub(super) struct ServerSelectionContext {
    pub(super) base_url: Signal<String>,
    pub(super) token: Signal<String>,
    pub(super) sync_cursor: Signal<String>,
    pub(super) selected_realm_id: Signal<String>,
    pub(super) realm_tree_nodes: Signal<Vec<RealmTreeNode>>,
    pub(super) projection_events: Signal<Vec<ProjectionEvent>>,
    pub(super) device_queue: Signal<usize>,
    pub(super) frontier_state: Signal<String>,
    pub(super) crypto_state: Signal<String>,
    pub(super) config_store: Signal<LocalConfigStore>,
    pub(super) state_store: SyncSignal<LocalStateStore>,
    pub(super) network_state: Signal<String>,
    pub(super) last_error: Signal<Option<String>>,
    pub(super) server_description: Signal<Option<ServiceDescribe>>,
    pub(super) server_probe_status: Signal<String>,
    pub(super) connection_status: Signal<String>,
    pub(super) principal_id: Signal<Option<arkret_sdk::DidCoreId>>,
    pub(super) device_id: Signal<String>,
    pub(super) account_primary_handle: Signal<String>,
    pub(super) personal_handles: Signal<Vec<String>>,
    pub(super) personal_handles_status: Signal<String>,
    pub(super) personal_handles_lookup_key: Signal<String>,
    /// SyncEngine generation counter — bumped to retire the
    /// previous-server engine after the cache wipe + URL repoint.
    pub(super) sync_generation: Signal<u64>,
}

pub(super) fn select_server(server_url: String, ctx: ServerSelectionContext) {
    let server_url = normalize_server_url(&server_url);
    let mut base_url = ctx.base_url;
    let mut token = ctx.token;
    let mut sync_cursor = ctx.sync_cursor;
    let mut selected_realm_id = ctx.selected_realm_id;
    let mut realm_tree_nodes = ctx.realm_tree_nodes;
    let mut projection_events = ctx.projection_events;
    let mut device_queue = ctx.device_queue;
    let mut frontier_state = ctx.frontier_state;
    let mut crypto_state = ctx.crypto_state;
    let mut network_state = ctx.network_state;
    let mut last_error = ctx.last_error;
    let mut server_description = ctx.server_description;
    let mut server_probe_status = ctx.server_probe_status;
    let mut status = ctx.connection_status;
    let mut state_store = ctx.state_store;
    let mut sync_generation = ctx.sync_generation;
    let mut account_primary_handle = ctx.account_primary_handle;
    let mut personal_handles = ctx.personal_handles;
    let mut personal_handles_status = ctx.personal_handles_status;
    let mut personal_handles_lookup_key = ctx.personal_handles_lookup_key;
    let server_changed = !same_server_url(&base_url(), &server_url);

    // A space cached against the previous server's view is meaningless
    // on the new server (different service DID, different membership,
    // potentially overlapping ak:space ids that point at unrelated
    // rooms). Wipe the account-scoped cache before re-pointing the URL
    // so the next sync starts from a clean slate. Device-level state
    // (local_identity, push_registration) is preserved.
    {
        let mut store = state_store.write();
        store.clear_account_scoped();
        if server_changed {
            store.set_session_grant(None);
        }
    }
    crate::authorization_lease::clear_leases();
    // Retire the previous server's SyncEngine. The use_effect's
    // base_url tracking would re-spawn anyway, but bumping here ensures
    // the in-flight long-poll exits before the new URL takes over.
    sync_generation.set(sync_generation() + 1);

    if server_changed {
        token.set(String::new());
    }
    let next_token = if server_changed {
        String::new()
    } else {
        token()
    };
    base_url.set(server_url.clone());
    sync_cursor.set(String::new());
    selected_realm_id.set(String::new());
    realm_tree_nodes.set(Vec::new());
    projection_events.set(Vec::new());
    device_queue.set(0);
    frontier_state.set("Not loaded".to_owned());
    crypto_state.set("Refresh session for selected server".to_owned());
    account_primary_handle.set(String::new());
    personal_handles.set(Vec::new());
    personal_handles_status.set("Not published".to_owned());
    personal_handles_lookup_key.set(String::new());
    crate::operation::set_authoring_station_id(None);
    server_description.set(None);
    server_probe_status.set("server not probed".to_owned());
    status.set(ConnectionState::Offline.label().to_owned());
    network_state.set("offline".to_owned());
    last_error.set(None);
    persist_config(
        ctx.config_store,
        server_url,
        (ctx.principal_id)(),
        (ctx.device_id)(),
        next_token,
    );
}
