use anyhow::Context;
use url::Url;

#[cfg(target_arch = "wasm32")]
use super::OIDC_SCAFFOLD_STORAGE_KEY;
use super::util::{
    PKCE_VERIFIER_BYTES, STATE_NONCE_TOKEN_BYTES, pkce_code_challenge_s256, preferred_pkce_method,
    random_url_safe_token,
};
use super::{
    ARKRET_DEVICE_SCOPE_PREFIX, INKSON_OIDC_CLIENT_ID, OidcDiscoveryDocument, OidcScaffoldBundle,
    PersistedOidcScaffold,
};

/// T1.Y1 — build the authorize scaffold (PKCE state/nonce/verifier + the full
/// `authorization_endpoint` URL) directly from standard OIDC discovery and the
/// chosen `methods[].oidc`, without any Arkret-private bridge. `client_id` is
/// taken from the auth method when published, else falls back to the native
/// inkson client id.
pub fn build_oidc_authorize_scaffold(
    discovery: &OidcDiscoveryDocument,
    method: &arkret_sdk::AuthMethod,
    redirect_uri: &str,
    login_hint: &str,
    device_id: &str,
    principal_audience: &str,
    ui_locale: &str,
) -> anyhow::Result<OidcScaffoldBundle> {
    let client_id = method
        .client_id
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| INKSON_OIDC_CLIENT_ID.to_owned());
    let state = random_url_safe_token(STATE_NONCE_TOKEN_BYTES)?;
    let nonce = random_url_safe_token(STATE_NONCE_TOKEN_BYTES)?;
    let code_verifier = random_url_safe_token(PKCE_VERIFIER_BYTES)?;
    preferred_pkce_method(&discovery.code_challenge_methods_supported)
        .ok_or_else(|| anyhow::anyhow!("OIDC issuer must support PKCE S256"))?;
    let code_challenge = pkce_code_challenge_s256(&code_verifier);
    let authorize_url = build_standard_authorize_url(
        discovery,
        method,
        &client_id,
        redirect_uri,
        login_hint,
        device_id,
        principal_audience,
        ui_locale,
        &state,
        &nonce,
        &code_challenge,
    )?;
    Ok(OidcScaffoldBundle {
        client_id,
        state,
        nonce,
        code_verifier,
        #[cfg(test)]
        code_challenge,
        authorize_url,
        callback_uri: redirect_uri.to_owned(),
        principal_audience: principal_audience.to_owned(),
    })
}

/// Build a standard OpenID Connect authorization-code + PKCE authorize URL
/// from a discovery document and auth method. No Arkret-private scopes are
/// required: `scope` defaults to `openid` plus any `methods[].scopes`, and the
/// stable device binding rides as a `urn:arkret:client:device:{id}` scope.
#[allow(clippy::too_many_arguments)]
fn build_standard_authorize_url(
    discovery: &OidcDiscoveryDocument,
    method: &arkret_sdk::AuthMethod,
    client_id: &str,
    redirect_uri: &str,
    login_hint: &str,
    device_id: &str,
    principal_audience: &str,
    ui_locale: &str,
    state: &str,
    nonce: &str,
    code_challenge: &str,
) -> anyhow::Result<String> {
    let mut url = Url::parse(&discovery.authorization_endpoint).with_context(|| {
        format!(
            "invalid authorization_endpoint: {}",
            discovery.authorization_endpoint
        )
    })?;
    let mut scope_tokens: Vec<String> = vec!["openid".to_owned()];
    for scope in &method.scopes {
        let scope = scope.trim();
        if !scope.is_empty() && !scope_tokens.iter().any(|existing| existing == scope) {
            scope_tokens.push(scope.to_owned());
        }
    }
    // Standard offline_access for refresh tokens when the issuer advertises it.
    if discovery
        .scopes_supported
        .iter()
        .any(|scope| scope == "offline_access")
        && !scope_tokens.iter().any(|scope| scope == "offline_access")
    {
        scope_tokens.push("offline_access".to_owned());
    }
    // Bind this OAuth session to the stable device id so introspection returns
    // a stable `org.arkret.device_id` (avoids per-session device drift →
    // cursor_integrity_invalid). This is a parameterized capability scope,
    // accepted verbatim by the issuer; not gated by discovery scopes_supported.
    let device_id = device_id.trim();
    if !device_id.is_empty() {
        scope_tokens.push(format!("{ARKRET_DEVICE_SCOPE_PREFIX}{device_id}"));
    }
    let scope = scope_tokens.join(" ");
    let pkce_method = preferred_pkce_method(&discovery.code_challenge_methods_supported)
        .ok_or_else(|| anyhow::anyhow!("OIDC issuer must support PKCE S256"))?;
    {
        let mut query = url.query_pairs_mut();
        query.append_pair("response_type", "code");
        query.append_pair("client_id", client_id);
        query.append_pair("redirect_uri", redirect_uri);
        query.append_pair("scope", &scope);
        query.append_pair("state", state);
        query.append_pair("nonce", nonce);
        if !login_hint.trim().is_empty() {
            query.append_pair("login_hint", login_hint);
        }
        query.append_pair("resource", principal_audience);
        if !ui_locale.trim().is_empty() {
            query.append_pair("ui_locales", ui_locale.trim());
        }
        // OIDC Core §3.1.2.1: force re-prompt so an app-level logout is not
        // silently undone by a live IdP SSO cookie.
        query.append_pair("prompt", "login");
        query.append_pair("max_age", "0");
        query.append_pair("code_challenge_method", pkce_method);
        query.append_pair("code_challenge", code_challenge);
    }
    Ok(url.to_string())
}

/// Assemble the durable scaffold record from a freshly-built authorize bundle
/// plus the resolved Account Authority routing. Persisted across the browser
/// redirect so the callback can restore PKCE verifier / state / nonce and the
/// `gate_account_base` to POST the session-grant to.
#[allow(clippy::too_many_arguments)]
pub fn build_persisted_oidc_scaffold(
    bundle: &OidcScaffoldBundle,
    gate_account_base: &str,
    principal_server_url: &str,
    principal_actor_id: &str,
    device_id: &str,
    issuer: &str,
) -> PersistedOidcScaffold {
    PersistedOidcScaffold {
        expected_state: bundle.state.clone(),
        expected_nonce: bundle.nonce.clone(),
        code_verifier: bundle.code_verifier.clone(),
        client_id: bundle.client_id.clone(),
        principal_server_url: principal_server_url.to_owned(),
        principal_actor_id: principal_actor_id.to_owned(),
        device_id: device_id.to_owned(),
        principal_audience: bundle.principal_audience.clone(),
        callback_uri: bundle.callback_uri.clone(),
        authorize_url: bundle.authorize_url.clone(),
        issuer: issuer.to_owned(),
        gate_account_base: gate_account_base.to_owned(),
    }
}

#[cfg(target_arch = "wasm32")]
pub fn persist_oidc_scaffold(payload: &PersistedOidcScaffold) -> anyhow::Result<()> {
    let window =
        web_sys::window().ok_or_else(|| anyhow::anyhow!("browser window is not available"))?;
    let storage = window
        .local_storage()
        .map_err(|error| anyhow::anyhow!("failed to access localStorage: {error:?}"))?
        .ok_or_else(|| anyhow::anyhow!("localStorage is not available"))?;
    storage
        .set_item(OIDC_SCAFFOLD_STORAGE_KEY, &serde_json::to_string(payload)?)
        .map_err(|error| anyhow::anyhow!("failed to persist OIDC scaffold: {error:?}"))?;
    Ok(())
}

#[cfg(not(target_arch = "wasm32"))]
pub fn persist_oidc_scaffold(_payload: &PersistedOidcScaffold) -> anyhow::Result<()> {
    Ok(())
}

#[cfg(target_arch = "wasm32")]
pub fn restore_oidc_scaffold() -> anyhow::Result<Option<PersistedOidcScaffold>> {
    let window =
        web_sys::window().ok_or_else(|| anyhow::anyhow!("browser window is not available"))?;
    let Some(storage) = window
        .local_storage()
        .map_err(|error| anyhow::anyhow!("failed to access localStorage: {error:?}"))?
    else {
        return Ok(None);
    };
    let Some(payload) = storage
        .get_item(OIDC_SCAFFOLD_STORAGE_KEY)
        .map_err(|error| anyhow::anyhow!("failed to load OIDC scaffold: {error:?}"))?
    else {
        return Ok(None);
    };
    Ok(Some(serde_json::from_str(&payload)?))
}

#[cfg(not(target_arch = "wasm32"))]
pub fn restore_oidc_scaffold() -> anyhow::Result<Option<PersistedOidcScaffold>> {
    Ok(None)
}

#[cfg(target_arch = "wasm32")]
pub fn clear_persisted_oidc_scaffold() -> anyhow::Result<()> {
    let window =
        web_sys::window().ok_or_else(|| anyhow::anyhow!("browser window is not available"))?;
    let Some(storage) = window
        .local_storage()
        .map_err(|error| anyhow::anyhow!("failed to access localStorage: {error:?}"))?
    else {
        return Ok(());
    };
    storage
        .remove_item(OIDC_SCAFFOLD_STORAGE_KEY)
        .map_err(|error| anyhow::anyhow!("failed to clear OIDC scaffold: {error:?}"))?;
    Ok(())
}

#[cfg(not(target_arch = "wasm32"))]
pub fn clear_persisted_oidc_scaffold() -> anyhow::Result<()> {
    Ok(())
}
