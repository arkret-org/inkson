use chrono::{DateTime, Utc};
use dioxus::prelude::*;

use crate::api::CokretApi;
use crate::coauth::{
    AuthorityResolver, CoauthApi, CoauthSessionGrantInfo, build_oidc_authorize_scaffold,
    build_persisted_oidc_scaffold, capture_current_browser_callback_url,
    clear_persisted_oidc_scaffold, extract_authorization_code_from_callback,
    extract_error_description_from_callback, extract_error_from_callback,
    extract_state_from_callback, open_oidc_authorize_url, persist_oidc_scaffold,
    restore_oidc_scaffold,
};
use crate::config::{LocalConfigStore, normalize_device_id, normalize_server_url};
use crate::local_state::{LocalStateStore, PersistedSessionGrant};
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
    session_credential: String,
    /// Persisted principal session grant. This is the live credential for
    /// `/_cokret/self/*`; refresh rotates this grant before its own expiry.
    session_grant: Option<PersistedSessionGrant>,
}

// Process-global OIDC-callback completion guard. `callback_started` below is a
// per-component signal, so a Dioxus double-mount (the 0.7.9 reactivity quirk
// that occasionally renders the panel twice) gives each instance its own `false`
// flag and BOTH run `finish_oidc_callback` — double-submitting the session-grant
// and burning the single-use authorization_code (second POST → `invalid grant`
// 400, which derails the whole login). This wasm-global latch ensures the OIDC
// completion runs at most once per page load regardless of instance count. A new
// sign-in navigates away and reloads (fresh wasm), resetting it.
thread_local! {
    static OIDC_CALLBACK_COMPLETION_STARTED: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
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
        // Cross-instance latch: if another mount of this panel already began the
        // OIDC completion, skip so the authorization_code is exchanged once.
        if OIDC_CALLBACK_COMPLETION_STARTED.with(|started| started.replace(true)) {
            return;
        }
        callback_started.set(true);
        is_busy.set(true);

        let callback_device = device_id();
        let result = finish_oidc_callback(callback_device, state_store_write).await;
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
                    // meaningless here, so reset them too. The fresh grant for
                    // THIS server is persisted by `persist_completed_login_state`
                    // immediately below, so clearing here does not strand it.
                    if server_changed && !wiped {
                        store.clear_account_scoped();
                        store.set_session_grant(None);
                    }
                }
                base_url.set(principal_server_url.clone());
                account_did.set(completed.actor.clone());
                device_id.set(completed.device_id.clone());
                token.set(completed.session_credential.clone());
                persist_config(
                    config_store,
                    principal_server_url,
                    completed.actor.clone(),
                    completed.device_id.clone(),
                    completed.session_credential.clone(),
                );
                persist_completed_login_state(state_store_write, completed.session_grant);
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
                            match start_oidc_strand(&principal, device.trim()).await {
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
                                        is_busy.set(true);
                                        auth_status.set("Refreshing session...".to_owned());
                                        spawn(async move {
                                            match crate::session::refresh_current_session().await {
                                                crate::session::CurrentSessionRefresh::Credential(
                                                    session_credential,
                                                ) => {
                                                    token.set(session_credential);
                                                    auth_status.set("Session restored".to_owned());
                                                    on_login.call(());
                                                }
                                                crate::session::CurrentSessionRefresh::SignInRequired { reason } => {
                                                    auth_status.set(format!(
                                                        "Sign in required: {reason}"
                                                    ));
                                                }
                                                crate::session::CurrentSessionRefresh::LoginRequired { reason } => {
                                                    auth_status.set(format!(
                                                        "Session could not be restored: {reason}"
                                                    ));
                                                }
                                                crate::session::CurrentSessionRefresh::RetryLater { reason } => {
                                                    auth_status.set(format!(
                                                        "Session refresh pending: {reason}"
                                                    ));
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
    session_grant: Option<PersistedSessionGrant>,
) {
    let mut store = state_store.write();
    store.set_session_grant(session_grant);
}

/// Compute the value of the `session-status` testid. The four states
/// the cotest harness asserts against:
///
/// * `signed-in` — a live credential is present and a session grant is persisted.
/// * `signed-out` — no token, no grant.
/// * `session-expired` — no live credential but a session grant is still persisted.
fn compute_session_status(
    session_credential: &str,
    session_grant: Option<&PersistedSessionGrant>,
) -> &'static str {
    let has_token = !session_credential.trim().is_empty();
    let has_grant = session_grant.is_some();
    match (has_token, has_grant) {
        (true, _) => "signed-in",
        (false, true) => "session-expired",
        (false, false) => "signed-out",
    }
}

pub(crate) async fn start_oidc_strand(
    principal_server_url: &str,
    device_id: &str,
) -> Result<(), String> {
    // T1.Y1 — discover the Account Authority + auth methods from the Principal
    // Server's root `/_cokret/describe` (service-surface §2.5.1).
    let principal = CokretApi::new(principal_server_url)
        .map_err(|error| format!("Invalid principal server URL: {error}"))?;
    let description = principal
        .describe()
        .await
        .map_err(|error| format_sign_in_discovery_error(principal_server_url, &error))?;
    let resolver = AuthorityResolver::from_description(principal_server_url, &description)
        .map_err(|error| format!("Account Authority discovery failed: {error}"))?;
    let method = resolver
        .oidc_method()
        .map_err(|error| format!("No OIDC sign-in method available: {error}"))?;
    let discovery_url = oidc_discovery_url(&method).ok_or_else(|| {
        "OIDC method published neither openid_configuration nor an issuer.".to_owned()
    })?;
    // Standard OpenID Connect Discovery 1.0 — no Cokret-private OAuth family.
    let discovery = CoauthApi::fetch_oidc_discovery(&discovery_url)
        .await
        .map_err(|error| format!("OIDC discovery failed: {error}"))?;
    let redirect_uri = crate::coauth::current_oidc_redirect_uri();
    let bundle = build_oidc_authorize_scaffold(
        &discovery,
        &method,
        &redirect_uri,
        "",
        device_id,
        &resolver.principal_audience,
    )
    .map_err(|error| format!("Sign-in URL preparation failed: {error}"))?;

    let scaffold = build_persisted_oidc_scaffold(
        &bundle,
        &resolver.gate_account_base,
        principal_server_url,
        "",
        device_id,
        &discovery.issuer,
    );
    persist_oidc_scaffold(&scaffold)
        .map_err(|error| format!("Could not save sign-in state: {error}"))?;
    open_oidc_authorize_url(&bundle.authorize_url)
        .map_err(|error| format!("Could not open server sign-in: {error}"))
}

/// Standard OIDC discovery URL for an auth method: the explicit
/// `openid_configuration` when present, else `{issuer}/.well-known/openid-configuration`.
fn oidc_discovery_url(method: &cokret_sdk::AuthMethod) -> Option<String> {
    if let Some(config) = method
        .openid_configuration
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        return Some(config.to_owned());
    }
    method
        .issuer
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|issuer| {
            format!(
                "{}/.well-known/openid-configuration",
                issuer.trim_end_matches('/')
            )
        })
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

async fn finish_oidc_callback(
    device_fallback: String,
    mut state_store: Signal<LocalStateStore>,
) -> Result<CompletedLogin, String> {
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
    // T1.Y4 — every gate/account call routes through the resolved
    // `gate_account_base` persisted in the scaffold (service-surface §2.5.1).
    let gate_account_base = scaffold.gate_account_base.clone();
    if gate_account_base.trim().is_empty() {
        return Err("Sign-in state is missing the Account Authority base.".to_owned());
    }
    let principal_server_url = if scaffold.principal_server_url.trim().is_empty() {
        gate_account_base.clone()
    } else {
        scaffold.principal_server_url.clone()
    };
    let gate_account = CoauthApi::new(&gate_account_base)
        .map_err(|error| format!("Invalid Account Authority base: {error}"))?;
    let actor_hint = scaffold.principal_actor_id.trim().to_owned();
    let device = if scaffold.device_id.trim().is_empty() {
        device_fallback.trim().to_owned()
    } else {
        scaffold.device_id.clone()
    };
    if device.trim().is_empty() {
        return Err("No device identifier is available for this session.".to_owned());
    }
    let device = normalize_device_id(&device);
    // T1.Y1 — DPoP holder proof bound to the session-grants URL; this is what
    // makes the issued grant device-bound (cnf.jkt) at the Account Authority.
    let session_grants_url = gate_account
        .endpoint_url("session-grants")
        .map_err(|error| format!("session-grants URL preparation failed: {error}"))?;
    let (issue_dpop, dpop_handle) = {
        let mut store = state_store.write();
        let handle = crate::auth_dpop::ensure_device_key(&mut store)
            .map_err(|error| format!("DPoP key failed: {error}"))?;
        let proof = handle
            .mint_proof("POST", &session_grants_url, None)
            .map_err(|error| format!("DPoP proof failed: {error}"))?;
        (proof, handle)
    };
    if scaffold.issuer.trim().is_empty() {
        return Err("Sign-in state is missing the OIDC issuer.".to_owned());
    }
    // The canonical Account Authority session-grants endpoint binds the issued
    // grant to `principal_id`; it MUST equal the DID the authenticated user
    // resolves to. On re-auth we forward the actor hint persisted with the
    // scaffold. On true first sign-in the DID is not yet known client-side, so
    // we forward an empty hint (sent as `None`): the Account Authority derives
    // the principal DID from the OIDC subject and returns it in
    // `SessionGrantOutcome.principal_id` (② contract D5), which the code below
    // adopts as the authoritative actor DID.
    let outcome = gate_account
        .issue_session_grant_oidc(
            &actor_hint,
            &device,
            &scaffold.issuer,
            &scaffold.client_id,
            &scaffold.callback_uri,
            &returned_state,
            &scaffold.expected_nonce,
            &authorization_code,
            &scaffold.code_verifier,
            &scaffold.principal_audience,
            Vec::new(),
            &issue_dpop,
        )
        .await
        .map_err(|error| format!("Account Authority session-grant issue failed: {error}"))?;
    let session_grant = session_grant_info_from_outcome(&outcome, &dpop_handle)
        .map_err(|error| format!("Session grant outcome was incomplete: {error}"))?;
    let principal_target = principal_server_url;
    let principal = CokretApi::new(&principal_target)
        .map_err(|error| format!("Invalid principal server URL: {error}"))?;
    let actor = if outcome.principal_id.as_str().trim().is_empty() {
        actor_hint.clone()
    } else {
        outcome.principal_id.as_str().to_owned()
    };
    if actor.trim().is_empty() {
        return Err("Account Authority did not return an account DID.".to_owned());
    }
    // ②(A+②): the held credential is the
    // `ck.session.grant` itself; every `/_cokret/self/*` request presents it as
    // `Authorization: Bearer <grant>` + a per-request `DPoP` proof bound to the
    // grant's `cnf.jkt`. Verify the credential up front by reading the account
    // viewer through a grant+DPoP-bound client (api-conventions.md §3.3).
    // Mint the session-grant holder proof presented on every `/_cokret/self/*`
    // call: coauth's grant introspection (which the Principal Server invokes)
    // requires it to confirm possession of the grant's session key, otherwise it
    // answers `proof_required` and the grant reads inactive.
    let grant_introspection_proof = dpop_handle
        .mint_session_grant_introspection_proof(
            session_grant.id.as_deref().unwrap_or_default(),
            &session_grant.grant_jwt,
            session_grant.audience.as_deref().unwrap_or_default(),
        )
        .map_err(|error| format!("session-grant introspection proof mint failed: {error}"))?;
    let authed_principal = principal
        .clone()
        .with_bearer(session_grant.grant_jwt.clone())
        .with_dpop_device(dpop_handle.clone())
        .with_session_grant_proof(grant_introspection_proof);
    let account = authed_principal.account_me().await.map_err(|error| {
        format!("Principal server did not accept the session grant + DPoP: {error}")
    })?;
    let canonical_actor = if account.did.trim().is_empty() {
        actor
    } else {
        account.did
    };
    let _ = clear_persisted_oidc_scaffold();

    let resolved_device = device;
    // Persist the principal session grant as the live credential. The refresh
    // path keeps it fresh by rotating it (DPoP holder proof → fresh grant) when
    // near expiry.
    let persisted_session_grant = persisted_session_grant_from_parts(
        &session_grant,
        &principal_target,
        &canonical_actor,
        &resolved_device,
    )
    .ok();

    Ok(CompletedLogin {
        principal_server_url: principal_target,
        actor: canonical_actor,
        device_id: resolved_device,
        // The grant JWT is now the live credential carried in the `token` signal.
        session_credential: session_grant.grant_jwt.clone(),
        session_grant: persisted_session_grant,
    })
}

/// Adapt the SDK [`cokret_sdk::SessionGrantOutcome`] returned by the Account
/// Authority into the local [`CoauthSessionGrantInfo`] the refresh/persistence
/// path expects. The grant is device-bound (`cnf.jkt`), so its signing key for
/// the introspection proof is the device DPoP key, persisted here as
/// `session_private_key_pem`. `grant_id` / `session_public_key` / `audience`
/// ride in the outcome's `scope_details` object.
fn session_grant_info_from_outcome(
    outcome: &cokret_sdk::SessionGrantOutcome,
    dpop_handle: &crate::auth_dpop::DpopHandle,
) -> Result<CoauthSessionGrantInfo, String> {
    let details = &outcome.scope_details;
    let grant_id = details
        .get("grant_id")
        .and_then(|value| value.as_str())
        .map(ToOwned::to_owned);
    let session_public_key = details
        .get("session_public_key")
        .and_then(|value| value.as_str())
        .unwrap_or_default()
        .to_owned();
    let audience = details
        .get("audience")
        .and_then(|value| value.as_str())
        .map(ToOwned::to_owned);
    let session_private_key_pem = dpop_handle
        .session_signing_key_pkcs8_pem()
        .map_err(|error| format!("export device session key: {error}"))?;
    Ok(CoauthSessionGrantInfo {
        kind: Some("session_grant".to_owned()),
        id: grant_id,
        grant_jwt: outcome.session_grant.clone(),
        session_public_key,
        session_private_key_pem,
        expires_at: outcome.expires_at.to_rfc3339(),
        audience,
        scopes: outcome.granted_scope.clone(),
        principal_server: None,
    })
}

fn persisted_session_grant_from_parts(
    grant: &CoauthSessionGrantInfo,
    principal_server_url: &str,
    actor: &str,
    device_id: &str,
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
        grant_expires_at: parse_rfc3339_utc(&grant.expires_at),
        stored_at: Utc::now(),
    })
}

fn parse_rfc3339_utc(value: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(value.trim())
        .ok()
        .map(|timestamp| timestamp.with_timezone(&Utc))
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
            grant_expires_at: Some(now + chrono::Duration::seconds(3600)),
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
        // Soft-logout state: the live credential is absent but the grant is
        // still present. Refresh button can restore/rotate it.
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
        let persisted = persisted_session_grant_from_parts(
            &grant,
            "https://local.host",
            "did:web:alice.example",
            "ck:device:01964137-0000-7000-8000-000000000001",
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
            persisted
                .grant_expires_at
                .expect("grant expiry")
                .to_rfc3339(),
            "2026-05-29T12:00:00+00:00"
        );
    }
}
