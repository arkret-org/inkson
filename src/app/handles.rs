use super::*;

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

pub(super) fn select_server(
    server_url: String,
    context: std::rc::Rc<crate::presentation::InksonContext>,
) {
    let server_url = normalize_server_url(&server_url);
    let server_changed = !same_server_url(&context.base_url.get(), &server_url);
    context.state_store.write(|store| {
        store.clear_account_scoped();
        if server_changed {
            store.set_session_grant(None);
        }
    });
    context
        .sync_generation
        .revise(|value| *value = value.wrapping_add(1));
    context.clear_account_projections();
    if server_changed {
        context.token.revise(String::clear);
    }
    context.base_url.revise(|value| *value = server_url.clone());
    context.sync_cursor.revise(String::clear);
    context.device_queue.revise(|value| *value = 0);
    context
        .frontier_state
        .revise(|value| *value = "Not loaded".into());
    context
        .crypto_state
        .revise(|value| *value = "Refresh session for selected server".into());
    crate::operation::set_authoring_station_id(None);
    context.server_description.revise(|value| *value = None);
    context
        .server_probe_status
        .revise(|value| *value = "server not probed".into());
    context
        .connection_status
        .revise(|value| *value = ConnectionState::Offline.label().into());
    context
        .network_state
        .revise(|value| *value = "offline".into());
    context.last_error.revise(|value| *value = None);
    persist_config(
        context.config_store,
        &context.active_account.get(),
        server_url,
        context.principal_id.get(),
        context.device_id.get(),
        context.token.get(),
    );
}
