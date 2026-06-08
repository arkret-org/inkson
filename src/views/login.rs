#[cfg(test)]
use chrono::{DateTime, Utc};
use dioxus::prelude::*;

use crate::api::CokretApi;
#[cfg(test)]
use crate::coauth::CoauthSessionGrantInfo;
use crate::coauth::{
    CoauthApi, authorize_url_with_forced_reauthentication, build_oidc_code_exchange_plan,
    build_oidc_scaffold_bundle, capture_current_browser_callback_url,
    clear_persisted_oidc_scaffold, extract_authorization_code_from_callback,
    extract_error_description_from_callback, extract_error_from_callback,
    extract_state_from_callback, open_oidc_authorize_url, persist_oidc_scaffold,
    resolve_principal_auth_server, restore_oidc_scaffold,
};
use crate::config::{LocalConfigStore, normalize_device_id, normalize_server_url};
use crate::local_state::{LocalStateStore, OidcTokenBundle, PersistedSessionGrant};
#[cfg(test)]
use crate::models::DevLoginResponse;
use crate::ui::button::{Button, ButtonVariant};
use crate::ui::card::Card;
use crate::ui::input::Input;
use crate::ui::label::Label;
use crate::views::helpers::{persist_config, short_protocol_id};

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
                let server_changed = {
                    let previous = normalize_server_url(&base_url());
                    !previous.trim().is_empty() && previous != principal_server_url
                };
                {
                    let mut store = state_store_write.write();
                    // Adopt the account-scope for the signed-in actor. If the
                    // browser still holds a *different* identity's scope, this
                    // wipes its grant + OIDC bundle + sync cursor + projections
                    // — the guard that stops a stale/revoked grant or a
                    // foreign-principal cursor from leaking into this session.
                    let wiped = store.adopt_account_scope(&completed.actor);
                    // Same actor but a different principal server: the cached
                    // projections/cursor are scoped to the old server and are
                    // meaningless here, so reset them too.
                    if server_changed && !wiped {
                        store.clear_account_scoped();
                        store.set_session_grant(None);
                        store.set_oidc_tokens(None);
                    }
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
        Card { class: "auth-panel", "data-testid": "login-panel", role: "region", "aria-label": "Login",
            div { class: "auth-brand",
                div { class: "auth-logo", "C" }
                div {
                    h1 { if auto_capture_callback { "Completing sign in" } else { "Sign in" } }
                    p { "Cokret" }
                }
            }

            div { class: "auth-form",
                Label { html_for: "login-server-url-input", "Principal server" }
                Input {
                    id: "login-server-url-input",
                    "data-testid": "login-server-url",
                    "aria-label": "Principal server URL",
                    value: "{base_url}",
                    disabled: is_busy(),
                    oninput: move |event: FormEvent| {
                        let value = normalize_server_url(&event.value());
                        base_url.set(value.clone());
                        token.set(String::new());
                        persist_config(config_store, value, account_did(), device_id(), String::new());
                    },
                }

                Button {
                    variant: ButtonVariant::Primary,
                    class: "auth-primary",
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
                                Button {
                                    variant: ButtonVariant::Ghost,
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
    } else {
        let secure_store = crate::secure_key_store::default_secure_key_store("yougen");
        store.set_oidc_tokens_with_secure_store(None, actor_did, secure_store.as_ref());
    }
    store.set_session_grant(grant);
}

/// Compute the value of the `session-status` testid. The four states
/// the cotest harness asserts against:
///
/// * `signed-in` — an access token is present and a session grant is persisted.
/// * `signed-out` — no token, no grant.
/// * `session-expired` — no live token but a session grant is still persisted (the soft-logout
///   state — the user can re-mint via `refresh-now-button` without going through OIDC).
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
    let topology = coauth
        .inspect_topology()
        .await
        .map_err(|error| format!("Server sign-in metadata failed: {error}"))?;
    let mut bundle = build_oidc_scaffold_bundle(&topology, principal_server_url, "", device_id)
        .map_err(|error| format!("Sign-in URL preparation failed: {error}"))?;
    bundle.authorize_url = authorize_url_with_forced_reauthentication(&bundle.authorize_url)
        .map_err(|error| format!("Sign-in URL preparation failed: {error}"))?;

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
    let tokens = coauth
        .exchange_pkce_code_for_tokens(
            &token_endpoint,
            &plan.client_id,
            &authorization_code,
            &scaffold.code_verifier,
            &scaffold.callback_uri,
        )
        .await
        .map_err(|error| format!("OIDC token exchange failed: {error}"))?;
    let principal_target = principal_server_url;
    if requires_oidc_refresh_token(&principal_target)
        && !tokens
            .refresh_token
            .as_deref()
            .is_some_and(|token| !token.trim().is_empty())
    {
        return Err(
            "Server sign-in returned OIDC tokens without a refresh_token; refusing a production session without a secure refresh path."
                .to_owned(),
        );
    }
    let bundle = tokens.to_persisted_bundle(Some(&plan.principal_audience));
    if bundle.access_token.trim().is_empty() {
        return Err("OIDC token exchange did not return an access token.".to_owned());
    }
    let principal = CokretApi::new(&principal_target)
        .map_err(|error| format!("Invalid principal server URL: {error}"))?;
    let account = principal
        .clone()
        .with_bearer(bundle.access_token.clone())
        .account_me()
        .await
        .map_err(|error| {
            format!("Principal server did not accept the OIDC bearer token: {error}")
        })?;
    let actor = if account.did.trim().is_empty() {
        actor_hint.to_owned()
    } else {
        account.did
    };
    if actor.trim().is_empty() {
        return Err("Principal server did not return an account DID.".to_owned());
    }
    let _ = clear_persisted_oidc_scaffold();

    Ok(CompletedLogin {
        principal_server_url: principal_target,
        actor,
        device_id: device,
        access_token: bundle.access_token.clone(),
        grant: None,
        oidc_tokens: Some(bundle),
    })
}

#[cfg(test)]
fn persisted_session_grant_from_login(
    grant: &CoauthSessionGrantInfo,
    session: &DevLoginResponse,
    principal_server_url: &str,
    actor: &str,
    session_grant_exchange_path: &str,
) -> Result<PersistedSessionGrant, String> {
    persisted_session_grant_from_parts(
        grant,
        principal_server_url,
        actor,
        &session.device_id,
        session_grant_exchange_path,
        parse_rfc3339_utc(&session.expires_at),
    )
}

#[cfg(test)]
fn persisted_session_grant_from_parts(
    grant: &CoauthSessionGrantInfo,
    principal_server_url: &str,
    actor: &str,
    device_id: &str,
    session_grant_exchange_path: &str,
    session_expires_at: Option<DateTime<Utc>>,
) -> Result<PersistedSessionGrant, String> {
    let grant_id = grant
        .id
        .as_deref()
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| "Server sign-in did not return a session grant id.".to_owned())?;
    let audience = grant
        .audience
        .as_deref()
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| "Server sign-in did not return a session grant audience.".to_owned())?;
    Ok(PersistedSessionGrant {
        grant_jwt: grant.grant_jwt.clone(),
        session_private_key_pem: grant.session_private_key_pem.clone(),
        grant_id: grant_id.to_owned(),
        audience: audience.to_owned(),
        principal_id: actor.to_owned(),
        device_id: device_id.to_owned(),
        principal_server_url: principal_server_url.to_owned(),
        session_grant_exchange_path: session_grant_exchange_path.to_owned(),
        grant_expires_at: parse_rfc3339_utc(&grant.expires_at),
        session_expires_at,
        stored_at: Utc::now(),
    })
}

#[cfg(test)]
fn parse_rfc3339_utc(value: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(value.trim())
        .ok()
        .map(|timestamp| timestamp.with_timezone(&Utc))
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
            principal_id: "did:web:alice.example".to_owned(),
            device_id: "device-1".to_owned(),
            principal_server_url: "https://principal.example".to_owned(),
            session_grant_exchange_path: "_cokret/gate/account/session-grants".to_owned(),
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
    fn persisted_session_grant_from_login_carries_refresh_material() {
        let grant = CoauthSessionGrantInfo {
            kind: Some("session_grant".to_owned()),
            id: Some("grant-1".to_owned()),
            grant_jwt: "grant.jwt".to_owned(),
            session_public_key: "public-key".to_owned(),
            session_private_key_pem: "private-key-pem".to_owned(),
            expires_at: "2026-05-29T12:00:00Z".to_owned(),
            audience: Some("https://local.host/api".to_owned()),
            scopes: vec!["urn:cokret:principal-server:session.bind".to_owned()],
            principal_server: None,
        };
        let session = DevLoginResponse {
            access_token: "sx-bridge".to_owned(),
            token_type: "Bearer".to_owned(),
            actor: "did:web:alice.example".to_owned(),
            device_id: "ck:device:01964137-0000-7000-8000-000000000001".to_owned(),
            expires_at: "2026-05-29T11:05:00Z".to_owned(),
        };

        let persisted = persisted_session_grant_from_login(
            &grant,
            &session,
            "https://local.host",
            "did:web:alice.example",
            "_cokret/gate/account/session-grants",
        )
        .expect("persistable grant");

        assert_eq!(persisted.grant_jwt, "grant.jwt");
        assert_eq!(persisted.session_private_key_pem, "private-key-pem");
        assert_eq!(persisted.grant_id, "grant-1");
        assert_eq!(persisted.audience, "https://local.host/api");
        assert_eq!(persisted.principal_id, "did:web:alice.example");
        assert_eq!(
            persisted.device_id,
            "ck:device:01964137-0000-7000-8000-000000000001"
        );
        assert_eq!(persisted.principal_server_url, "https://local.host");
        assert_eq!(
            persisted.session_grant_exchange_path,
            "_cokret/gate/account/session-grants"
        );
        assert_eq!(
            persisted
                .grant_expires_at
                .expect("grant expiry")
                .to_rfc3339(),
            "2026-05-29T12:00:00+00:00"
        );
        assert_eq!(
            persisted
                .session_expires_at
                .expect("session expiry")
                .to_rfc3339(),
            "2026-05-29T11:05:00+00:00"
        );
    }
}
