use dioxus::prelude::*;

use crate::{
    api::ContrixApi,
    coauth::{
        CoauthApi, build_oidc_code_exchange_plan, build_session_grant_introspection_proof_bundle,
        capture_current_browser_callback_url, clear_persisted_oidc_scaffold,
        extract_authorization_code_from_callback, extract_error_description_from_callback,
        extract_error_from_callback, extract_state_from_callback,
        oidc_scaffold_bundle_from_bridge_session, open_oidc_authorize_url, persist_oidc_scaffold,
        resolve_principal_auth_server, restore_oidc_scaffold, session_grant_signing_key_from_pem,
    },
    config::{LocalConfigStore, normalize_device_id, normalize_server_url},
    local_state::{LocalStateStore, OidcTokenBundle, PersistedSessionGrant},
    views::helpers::{persist_config, short_protocol_id},
};

#[derive(Clone, Debug)]
struct CompletedLogin {
    principal_server_url: String,
    actor: String,
    device_id: String,
    access_token: String,
    /// Legacy coauth session_grant fallback. This is only retained when
    /// the active bearer is still a principal-server bridge token.
    grant: Option<PersistedSessionGrant>,
    /// OAuth bearer bundle accepted directly by the principal server.
    /// When present, this is the durable refresh path.
    oidc_tokens: Option<OidcTokenBundle>,
}

#[component]
pub fn LoginPanel(
    base_url: Signal<String>,
    account_did: Signal<String>,
    device_id: Signal<String>,
    token: Signal<String>,
    status: Signal<String>,
    config_store: Signal<LocalConfigStore>,
    state_store: Signal<LocalStateStore>,
    auto_capture_callback: bool,
    on_login: EventHandler<()>,
) -> Element {
    let mut auth_status = use_signal(|| {
        if auto_capture_callback {
            "Completing sign in...".to_owned()
        } else {
            String::new()
        }
    });
    let mut is_busy = use_signal(|| auto_capture_callback);
    let mut callback_started = use_signal(|| false);
    let mut state_store_write = state_store;

    use_future(move || async move {
        if !auto_capture_callback || callback_started() {
            return;
        }
        callback_started.set(true);
        is_busy.set(true);

        let callback_device = device_id();
        let result = finish_oidc_callback(callback_device).await;
        match result {
            Ok(completed) => {
                let principal_server_url = normalize_server_url(&completed.principal_server_url);
                let previous_principal_server_url = normalize_server_url(&base_url());
                let previous_actor = account_did();
                if login_replaces_account_scope(
                    &previous_principal_server_url,
                    &previous_actor,
                    &principal_server_url,
                    &completed.actor,
                ) {
                    state_store_write.write().clear_account_scoped();
                }
                base_url.set(principal_server_url.clone());
                account_did.set(completed.actor.clone());
                device_id.set(completed.device_id.clone());
                token.set(completed.access_token.clone());
                persist_config(
                    config_store,
                    principal_server_url,
                    completed.actor.clone(),
                    completed.device_id.clone(),
                    completed.access_token.clone(),
                );
                persist_completed_login_state(
                    state_store_write,
                    &completed.actor,
                    completed.grant,
                    completed.oidc_tokens,
                );
                status.set("Online".to_owned());
                auth_status.set("Signed in".to_owned());
                on_login.call(());
            }
            Err(error) => auth_status.set(error),
        }
        is_busy.set(false);
    });

    rsx! {
        section { class: "auth-panel", "data-testid": "login-panel", role: "region", "aria-label": "Login",
            div { class: "auth-brand",
                div { class: "auth-logo", "C" }
                div {
                    h1 { if auto_capture_callback { "Completing sign in" } else { "Sign in" } }
                    p { "Contrix" }
                }
            }

            div { class: "auth-form",
                label { "Principal server" }
                input {
                    "data-testid": "login-server-url",
                    "aria-label": "Principal server URL",
                    value: "{base_url}",
                    disabled: is_busy(),
                    oninput: move |event| {
                        let value = normalize_server_url(&event.value());
                        base_url.set(value.clone());
                        token.set(String::new());
                        persist_config(config_store, value, account_did(), device_id(), String::new());
                    },
                }

                button {
                    class: "primary auth-primary",
                    "data-testid": "start-server-login-button",
                    disabled: is_busy(),
                    onclick: move |_| {
                        let principal = base_url();
                        let device = normalize_device_id(&device_id());
                        let actor = account_did();
                        device_id.set(device.clone());
                        is_busy.set(true);
                        auth_status.set("Opening server sign-in...".to_owned());
                        spawn(async move {
                            match start_oidc_flow(&principal, device.trim()).await {
                                Ok(()) => {
                                    persist_config(
                                        config_store,
                                        principal,
                                        actor,
                                        device,
                                        String::new(),
                                    );
                                }
                                Err(error) => {
                                    is_busy.set(false);
                                    auth_status.set(error);
                                }
                            }
                        });
                    },
                    if is_busy() { "Working..." } else { "Continue" }
                }

                if !auth_status().is_empty() {
                    div { class: "auth-status", "data-testid": "auth-status", role: "status", "{auth_status}" }
                }

                // G3.Y0 — session state surface for cotest's
                // `identity/account-device-auth.spec.ts`. These testids
                // expose the live session triple (status / device id /
                // actor DID) so a refresh assertion can see them rotate
                // without scraping log lines.
                {
                    let token_value = token();
                    let device_value = device_id();
                    let actor_value = account_did();
                    let store_snapshot = state_store_write.read();
                    let session_status = compute_session_status(
                        &token_value,
                        store_snapshot.session_grant().as_ref(),
                    );
                    let jkt_display = store_snapshot
                        .dpop_device_key()
                        .map(|record| record.jkt)
                        .unwrap_or_default();
                    drop(store_snapshot);
                    let show_session_diagnostics =
                        session_status != "signed-out" || !jkt_display.is_empty();
                    let device_label = short_protocol_id(&device_value);
                    let actor_label = short_protocol_id(&actor_value);
                    let jkt_label = short_protocol_id(&jkt_display);
                    rsx! {
                        if show_session_diagnostics {
                            div { class: "auth-session-state", "data-testid": "session-state-card",
                                div {
                                    "data-testid": "session-status",
                                    "data-status": session_status,
                                    "{session_status}"
                                }
                                div {
                                    "data-testid": "session-device-id",
                                    title: "{device_value}",
                                    "{device_label}"
                                }
                                div {
                                    "data-testid": "session-actor-did",
                                    title: "{actor_value}",
                                    "{actor_label}"
                                }
                                if !jkt_display.is_empty() {
                                    div {
                                        "data-testid": "session-dpop-jkt",
                                        title: "{jkt_display}",
                                        "{jkt_label}"
                                    }
                                }
                                button {
                                    class: "ghost",
                                    "data-testid": "refresh-now-button",
                                    disabled: is_busy(),
                                    onclick: move |_| {
                                        let principal = base_url();
                                        let actor = account_did();
                                        let device = device_id();
                                        is_busy.set(true);
                                        auth_status.set("Refreshing session...".to_owned());
                                        spawn(async move {
                                            let prepared = {
                                                let mut store = state_store_write.write();
                                                crate::session_refresh::prepare_refresh_for_server(
                                                    &mut store,
                                                    &principal,
                                                )
                                            };
                                            let outcome = match prepared {
                                                crate::session_refresh::RefreshPrepared::Done(o) => o,
                                                crate::session_refresh::RefreshPrepared::Ready { grant, proof } => {
                                                    let result = crate::session_refresh::exchange_refresh(&grant, &proof).await;
                                                    let mut store = state_store_write.write();
                                                    crate::session_refresh::commit_refresh(&mut store, result)
                                                }
                                            };
                                            match outcome {
                                                crate::session_refresh::RefreshOutcome::Refreshed { access_token, .. } => {
                                                    token.set(access_token.clone());
                                                    persist_config(
                                                        config_store,
                                                        principal.clone(),
                                                        actor.clone(),
                                                        device.clone(),
                                                        access_token,
                                                    );
                                                    auth_status.set("Session refreshed".to_owned());
                                                }
                                                crate::session_refresh::RefreshOutcome::Fresh => {
                                                    auth_status.set("Session still fresh".to_owned());
                                                }
                                                crate::session_refresh::RefreshOutcome::NoGrant => {
                                                    auth_status.set("No persisted session grant; sign in first".to_owned());
                                                }
                                                crate::session_refresh::RefreshOutcome::LoginRequired { reason } => {
                                                    token.set(String::new());
                                                    persist_config(
                                                        config_store,
                                                        principal.clone(),
                                                        actor.clone(),
                                                        device.clone(),
                                                        String::new(),
                                                    );
                                                    auth_status.set(format!("Session expired: {reason}"));
                                                }
                                                crate::session_refresh::RefreshOutcome::Transient { reason } => {
                                                    auth_status.set(format!("Refresh failed transiently: {reason}"));
                                                }
                                            }
                                            is_busy.set(false);
                                        });
                                    },
                                    "Refresh now"
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

fn login_replaces_account_scope(
    previous_server_url: &str,
    previous_actor: &str,
    next_server_url: &str,
    next_actor: &str,
) -> bool {
    let previous_actor = previous_actor.trim();
    if previous_actor.is_empty() {
        return false;
    }
    previous_actor != next_actor.trim()
        || normalize_server_url(previous_server_url) != normalize_server_url(next_server_url)
}

fn persist_completed_login_state(
    mut state_store: Signal<LocalStateStore>,
    actor_did: &str,
    grant: Option<PersistedSessionGrant>,
    oidc_tokens: Option<OidcTokenBundle>,
) {
    let mut store = state_store.write();
    if let Some(bundle) = oidc_tokens {
        let secure_store = crate::secure_key_store::default_secure_key_store("yougen");
        store.set_oidc_tokens_with_secure_store(Some(bundle), actor_did, secure_store.as_ref());
        store.set_session_grant(None);
    } else {
        store.set_session_grant(grant);
    }
}

/// Compute the value of the `session-status` testid. The four states
/// the cotest harness asserts against:
///
/// * `signed-in` — an access token is present and a session grant is
///   persisted.
/// * `signed-out` — no token, no grant.
/// * `session-expired` — no live token but a session grant is still
///   persisted (the soft-logout state — the user can re-mint via
///   `refresh-now-button` without going through OIDC).
fn compute_session_status(
    access_token: &str,
    session_grant: Option<&PersistedSessionGrant>,
) -> &'static str {
    let has_token = !access_token.trim().is_empty();
    let has_grant = session_grant.is_some();
    match (has_token, has_grant) {
        (true, _) => "signed-in",
        (false, true) => "session-expired",
        (false, false) => "signed-out",
    }
}

pub(crate) async fn start_oidc_flow(
    principal_server_url: &str,
    device_id: &str,
) -> Result<(), String> {
    let principal_auth = resolve_principal_auth_server(principal_server_url)
        .await
        .map_err(|error| format_sign_in_discovery_error(principal_server_url, &error))?;
    let coauth = CoauthApi::new(&principal_auth.auth_server_url)
        .map_err(|error| format!("Invalid auth server URL: {error}"))?;
    let bridge = coauth
        .auth_bridge_describe()
        .await
        .map_err(|error| format!("Server sign-in metadata failed: {error}"))?;
    let session = coauth
        .start_oidc_browser_bridge(
            &bridge.oauth.browser_bridge_session_path,
            &crate::coauth::current_oidc_redirect_uri(),
            "",
            device_id,
            Some(principal_auth.service_did.as_str()),
            None,
        )
        .await
        .map_err(|error| format!("Sign-in URL preparation failed: {error}"))?;
    let bundle = oidc_scaffold_bundle_from_bridge_session(&session);

    persist_oidc_scaffold(
        &bundle,
        &principal_auth.auth_server_url,
        principal_server_url,
        "",
        device_id,
    )
    .map_err(|error| format!("Could not save sign-in state: {error}"))?;
    open_oidc_authorize_url(&bundle.authorize_url)
        .map_err(|error| format!("Could not open server sign-in: {error}"))
}

fn format_sign_in_discovery_error(principal_server_url: &str, error: &anyhow::Error) -> String {
    let normalized = normalize_server_url(principal_server_url);
    let local_hint = url::Url::parse(&normalized)
        .ok()
        .and_then(|url| url.host_str().map(str::to_owned))
        .is_some_and(|host| {
            matches!(
                host.as_str(),
                "local.host" | "localhost" | "127.0.0.1" | "::1"
            )
        });

    if local_hint {
        format!(
            "Could not reach {normalized} for server sign-in discovery. Start the local Principal Server on local.host:443 and make sure its HTTPS certificate is trusted. Details: {error}"
        )
    } else {
        format!("Could not reach {normalized} for server sign-in discovery: {error}")
    }
}

async fn finish_oidc_callback(device_fallback: String) -> Result<CompletedLogin, String> {
    let callback_url = capture_current_browser_callback_url()
        .map_err(|error| format!("Could not read callback URL: {error}"))?;
    let scaffold = restore_oidc_scaffold()
        .map_err(|error| format!("Could not restore sign-in state: {error}"))?
        .ok_or_else(|| "Sign-in state was not found. Start again from Login.".to_owned())?;

    if let Some(error) = extract_error_from_callback(&callback_url)
        .map_err(|error| format!("Could not read callback error: {error}"))?
    {
        let description = extract_error_description_from_callback(&callback_url)
            .ok()
            .flatten()
            .unwrap_or_else(|| "No description".to_owned());
        return Err(format!("Server sign-in failed: {error}. {description}"));
    }

    let returned_state = extract_state_from_callback(&callback_url)
        .map_err(|error| format!("Could not read callback state: {error}"))?
        .ok_or_else(|| "Callback did not include state.".to_owned())?;
    if returned_state != scaffold.expected_state {
        return Err("Callback state did not match the saved sign-in state.".to_owned());
    }

    let authorization_code = extract_authorization_code_from_callback(&callback_url)
        .map_err(|error| format!("Callback did not include an authorization code: {error}"))?;
    let auth_server_url = if scaffold.auth_server_url.trim().is_empty() {
        scaffold.principal_server_url.clone()
    } else {
        scaffold.auth_server_url.clone()
    };
    let principal_server_url = if scaffold.principal_server_url.trim().is_empty() {
        auth_server_url.clone()
    } else {
        scaffold.principal_server_url.clone()
    };
    let coauth = CoauthApi::new(&auth_server_url)
        .map_err(|error| format!("Invalid auth server URL: {error}"))?;
    let topology = coauth
        .inspect_topology()
        .await
        .map_err(|error| format!("Server sign-in metadata failed: {error}"))?;
    let actor_hint = scaffold.principal_actor_did.trim();
    let device = if scaffold.device_id.trim().is_empty() {
        device_fallback.trim().to_owned()
    } else {
        scaffold.device_id.clone()
    };
    if device.trim().is_empty() {
        return Err("No device identifier is available for this session.".to_owned());
    }
    let device = normalize_device_id(&device);
    let plan = build_oidc_code_exchange_plan(&topology, &principal_server_url, actor_hint, &device)
        .map_err(|error| format!("Sign-in exchange preparation failed: {error}"))?;
    let token_endpoint = topology
        .token_endpoint
        .clone()
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| "Server OIDC discovery did not publish a token endpoint.".to_owned())?;
    let userinfo_endpoint = topology
        .userinfo_endpoint
        .clone()
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| "Server OIDC discovery did not publish a userinfo endpoint.".to_owned())?;
    let login = coauth
        .exchange_oidc_code(
            &topology.oidc_exchange_path,
            &authorization_code,
            &scaffold.code_verifier,
            &scaffold.callback_uri,
            &topology.issuer,
            &token_endpoint,
            &userinfo_endpoint,
            &plan.client_id,
            actor_hint,
            &device,
            Some(&plan.principal_audience),
            Some(&returned_state),
            Some(&scaffold.expected_state),
            Some(&scaffold.expected_nonce),
        )
        .await
        .map_err(|error| format!("Server sign-in exchange failed: {error}"))?;
    if login.status != "success" {
        return Err(format!(
            "Server sign-in returned {}: {}",
            login.status,
            login.error.unwrap_or_else(|| "unknown error".to_owned())
        ));
    }

    let principal_did = login
        .viewer
        .as_ref()
        .map(|viewer| viewer.did.clone())
        .filter(|value| !value.trim().is_empty())
        .or_else(|| {
            (!scaffold.principal_actor_did.trim().is_empty())
                .then(|| scaffold.principal_actor_did.clone())
        })
        .ok_or_else(|| "Server sign-in did not return a principal DID.".to_owned())?;
    let grant = login.session_grant.as_ref();
    let principal_target = grant
        .and_then(|grant| grant.principal_server.as_ref())
        .map(|server| server.endpoint.clone())
        .filter(|value| !value.trim().is_empty())
        .unwrap_or(principal_server_url);
    let principal = ContrixApi::new(&principal_target)
        .map_err(|error| format!("Invalid principal server URL: {error}"))?;
    let oidc_bundle = match login.oidc_tokens.as_ref() {
        Some(tokens) => {
            if tokens
                .refresh_token
                .as_deref()
                .is_some_and(|rt| !rt.trim().is_empty())
                || !requires_oidc_refresh_token(&principal_target)
            {
                Some(tokens.to_persisted_bundle(Some(&plan.principal_audience)))
            } else {
                return Err(
                    "Server sign-in returned OIDC tokens without a refresh_token; refusing a production session without a secure refresh path."
                        .to_owned(),
                );
            }
        }
        None if requires_oidc_refresh_token(&principal_target) => {
            return Err(
                "Server sign-in did not return an OIDC token bundle; refusing a production session without a secure refresh-token handoff."
                    .to_owned(),
            );
        }
        None => None,
    };

    if let Some(bundle) = oidc_bundle.clone()
        && !bundle.access_token.trim().is_empty()
    {
        match principal
            .clone()
            .with_bearer(bundle.access_token.clone())
            .account_me()
            .await
        {
            Ok(account) => {
                let _ = clear_persisted_oidc_scaffold();
                return Ok(CompletedLogin {
                    principal_server_url: principal_target,
                    actor: if account.did.trim().is_empty() {
                        principal_did
                    } else {
                        account.did
                    },
                    device_id: device,
                    access_token: bundle.access_token.clone(),
                    grant: None,
                    oidc_tokens: Some(bundle),
                });
            }
            Err(error) if requires_oidc_refresh_token(&principal_target) => {
                return Err(format!(
                    "Principal server did not accept the OIDC bearer token: {error}"
                ));
            }
            Err(_) => {
                // Local/dev deployments may not have OAuth bearer
                // introspection wired yet. Fall back to the legacy
                // session-grant exchange below, but do not persist the
                // consumed grant as a refresh credential.
            }
        }
    }

    let grant = grant.ok_or_else(|| "Server sign-in did not return a session grant.".to_owned())?;
    let bridge = principal
        .auth_bridge_describe()
        .await
        .map_err(|error| format!("Principal auth bridge describe failed: {error}"))?;
    let grant_id = grant
        .id
        .as_deref()
        .ok_or_else(|| "Server sign-in did not return a session grant id.".to_owned())?;
    let grant_audience = grant
        .audience
        .as_deref()
        .ok_or_else(|| "Server sign-in did not return a session grant audience.".to_owned())?;
    let session_grant_signing_key =
        session_grant_signing_key_from_pem(&grant.session_private_key_pem).map_err(|error| {
            format!("Server sign-in returned an invalid session grant key: {error}")
        })?;
    let proof = build_session_grant_introspection_proof_bundle(
        grant_id,
        &grant.grant_jwt,
        grant_audience,
        &session_grant_signing_key,
    )
    .map_err(|error| format!("Could not sign session grant proof: {error}"))?;
    let session = principal
        .exchange_session_grant_at_with_proof(
            &bridge.auth.session_grant_exchange_path,
            &grant.grant_jwt,
            &principal_did,
            &device,
            Some(&proof),
        )
        .await
        .map_err(|error| format!("Principal session exchange failed: {error}"))?;
    let actor = match principal
        .clone()
        .with_bearer(session.access_token.clone())
        .account_me()
        .await
    {
        Ok(account) if !account.did.trim().is_empty() => account.did,
        _ => session.actor.clone(),
    };
    let _ = clear_persisted_oidc_scaffold();

    Ok(CompletedLogin {
        principal_server_url: principal_target,
        actor,
        device_id: session.device_id,
        access_token: session.access_token,
        grant: None,
        oidc_tokens: oidc_bundle,
    })
}

fn requires_oidc_refresh_token(principal_server_url: &str) -> bool {
    if std::env::var("YOUGEN_ALLOW_SESSION_GRANT_ONLY_LOGIN")
        .ok()
        .is_some_and(|value| value == "1" || value.eq_ignore_ascii_case("true"))
    {
        return false;
    }
    let Ok(url) = url::Url::parse(principal_server_url) else {
        return true;
    };
    !matches!(
        url.host_str().unwrap_or_default(),
        "localhost" | "127.0.0.1" | "::1" | "local.host"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_grant() -> PersistedSessionGrant {
        let now = chrono::Utc::now();
        PersistedSessionGrant {
            grant_jwt: "test.grant.jwt".to_owned(),
            session_private_key_pem: "PEM".to_owned(),
            grant_id: "grant-1".to_owned(),
            audience: "https://principal.example/api".to_owned(),
            principal_did: "did:web:alice.example".to_owned(),
            device_id: "device-1".to_owned(),
            principal_server_url: "https://principal.example".to_owned(),
            session_grant_exchange_path: "api/v1/auth/session-grant/exchange".to_owned(),
            grant_expires_at: Some(now + chrono::Duration::seconds(3600)),
            session_expires_at: Some(now + chrono::Duration::seconds(60)),
            stored_at: now,
        }
    }

    #[test]
    fn session_status_signed_out_without_token_or_grant() {
        assert_eq!(compute_session_status("", None), "signed-out");
        // Whitespace-only token counts as no token.
        assert_eq!(compute_session_status("   ", None), "signed-out");
    }

    #[test]
    fn session_status_session_expired_when_grant_outlives_token() {
        // Soft-logout state: the access token died but the grant is
        // still good. Refresh button should re-mint.
        let grant = dummy_grant();
        assert_eq!(compute_session_status("", Some(&grant)), "session-expired");
    }

    #[test]
    fn session_status_signed_in_when_token_present() {
        let grant = dummy_grant();
        assert_eq!(
            compute_session_status("nonempty.token", Some(&grant)),
            "signed-in"
        );
        // Token without grant (dev-login style) is also signed-in.
        assert_eq!(compute_session_status("dev.token", None), "signed-in");
    }

    #[test]
    fn login_replaces_account_scope_only_for_account_or_server_change() {
        assert!(!login_replaces_account_scope(
            "https://local.host",
            "",
            "https://local.host",
            "did:web:alice.example"
        ));
        assert!(!login_replaces_account_scope(
            "https://local.host",
            "did:web:alice.example",
            "https://local.host/",
            "did:web:alice.example"
        ));
        assert!(login_replaces_account_scope(
            "https://local.host",
            "did:web:alice.example",
            "https://local.host",
            "did:web:bob.example"
        ));
        assert!(login_replaces_account_scope(
            "https://one.example",
            "did:web:alice.example",
            "https://two.example",
            "did:web:alice.example"
        ));
    }
}
