use dioxus::prelude::*;

use crate::{
    api::ContrixApi,
    config::{ClientConfig, LocalConfigStore},
};

/// Create an authenticated API client from a base URL and optional access token.
pub fn authed_api(base_url: &str, access_token: String) -> anyhow::Result<ContrixApi> {
    authed_api_with_sync(base_url, access_token, None)
}

/// Create an authenticated API client that also forwards the latest sync token
/// for read-your-writes consistency on subsequent reads.
pub fn authed_api_with_sync(
    base_url: &str,
    access_token: String,
    wait_for_sync_token: Option<String>,
) -> anyhow::Result<ContrixApi> {
    let mut api = ContrixApi::new(base_url)?;
    if !access_token.is_empty() {
        api = api.with_bearer(access_token);
    }
    if let Some(sync_token) = wait_for_sync_token {
        api = api.with_wait_for(sync_token);
    }
    Ok(api)
}

/// Derive a lowercase handle string from a DID, suitable for registration.
pub fn handle_from_did(did: &str) -> String {
    did.rsplit(':')
        .next()
        .unwrap_or("chask")
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' || ch == '.' {
                ch.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect()
}

/// Persist the current client configuration (server URL, DID, device ID, token).
pub fn persist_config(
    mut config_store: Signal<LocalConfigStore>,
    server_url: String,
    account_did: String,
    device_id: String,
    session_token: String,
) {
    config_store.write().save(ClientConfig::from_fields(
        server_url,
        account_did,
        device_id,
        session_token,
    ));
}
