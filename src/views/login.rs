use std::collections::HashMap;

use chrono::Utc;
use dioxus::prelude::*;

use crate::{
    api::ContrixApi,
    coauth::{
        CoauthApi, active_oidc_redirect_uri, build_chime_push_grant_plan, build_oidc_code_exchange_plan,
        build_oidc_scaffold_bundle, build_soland_session_grant_plan,
        clear_persisted_oidc_scaffold, capture_current_browser_callback_url,
        persist_oidc_scaffold, restore_oidc_scaffold,
        extract_authorization_code_from_callback, extract_state_from_callback,
        extract_error_description_from_callback, extract_error_from_callback,
        summarize_password_login_bridge,
    },
    config::LocalConfigStore,
    push::summarize_push_gateway_bridge,
    views::helpers::persist_config,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SessionState {
    Disconnected,
    Connected,
    SoftLogout,
}

/// Client-side rate limiter for auth attempts.
/// Tracks failures per action key and enforces a cooldown window.
#[derive(Clone, Debug)]
struct AuthRateLimiter {
    failures: HashMap<String, Vec<f64>>,
    max_attempts: usize,
    window_secs: f64,
}

impl AuthRateLimiter {
    fn new(max_attempts: usize, window_secs: f64) -> Self {
        Self {
            failures: HashMap::new(),
            max_attempts,
            window_secs,
        }
    }

    fn check(&self, key: &str, now: f64) -> Result<(), f64> {
        if let Some(attempts) = self.failures.get(key) {
            let recent: Vec<_> = attempts
                .iter()
                .filter(|&&t| now - t < self.window_secs)
                .collect();
            if recent.len() >= self.max_attempts {
                let oldest = recent.first().unwrap();
                let cooldown_remaining = self.window_secs - (now - *oldest);
                return Err(cooldown_remaining.max(0.0));
            }
        }
        Ok(())
    }

    fn record_failure(&mut self, key: &str, now: f64) {
        let attempts = self.failures.entry(key.to_owned()).or_default();
        attempts.push(now);
        attempts.retain(|&t| now - t < self.window_secs);
    }

    fn clear(&mut self, key: &str) {
        self.failures.remove(key);
    }
}

#[component]
pub fn LoginPanel(
    base_url: Signal<String>,
    account_did: Signal<String>,
    device_id: Signal<String>,
    token: Signal<String>,
    status: Signal<String>,
    config_store: Signal<LocalConfigStore>,
    auto_capture_callback: bool,
    on_login: EventHandler<()>,
) -> Element {
    let mut health_status = use_signal(|| String::new());
    let mut did_validation = use_signal(|| String::new());
    let mut session_state = use_signal(|| SessionState::Disconnected);
    let mut session_info = use_signal(|| String::new());
    let mut token_expiry = use_signal(|| String::new());
    let mut auth_server_url = use_signal(move || base_url());
    let mut coauth_status = use_signal(|| String::new());
    let mut integration_plan_status = use_signal(|| String::new());
    let mut coauth_authorization_code = use_signal(String::new);
    let mut coauth_code_verifier = use_signal(String::new);
    let mut coauth_callback_url = use_signal(String::new);
    let mut coauth_expected_state = use_signal(String::new);
    let mut coauth_imported_state = use_signal(String::new);
    let mut coauth_state_verified = use_signal(|| false);
    let mut coauth_username = use_signal(|| String::new());
    let mut coauth_password = use_signal(|| String::new());
    let mut passkey_status = use_signal(|| String::new());
    let mut oidc_status = use_signal(|| String::new());
    let mut dev_login_status = use_signal(|| String::new());
    let mut refresh_status = use_signal(|| String::new());
    let mut rate_limiter = use_signal(|| AuthRateLimiter::new(5, 60.0));
    let mut auto_capture_bootstrapped = use_signal(|| false);

    use_future(move || async move {
        if !auto_capture_callback || auto_capture_bootstrapped() {
            return;
        }
        auto_capture_bootstrapped.set(true);
        match capture_current_browser_callback_url() {
            Ok(callback_url) => {
                coauth_callback_url.set(callback_url.clone());
                let mut expected_state = coauth_expected_state();
                if expected_state.trim().is_empty() || coauth_code_verifier().trim().is_empty() {
                    if let Ok(Some(scaffold)) = restore_oidc_scaffold() {
                        if auth_server_url() == base_url() {
                            auth_server_url.set(scaffold.auth_server_url.clone());
                        }
                        if base_url().trim().is_empty() {
                            base_url.set(scaffold.principal_server_url.clone());
                        }
                        if account_did().trim().is_empty() {
                            account_did.set(scaffold.principal_actor_did.clone());
                        }
                        if device_id().trim().is_empty() {
                            device_id.set(scaffold.device_id.clone());
                        }
                        if expected_state.trim().is_empty() {
                            expected_state = scaffold.expected_state.clone();
                            coauth_expected_state.set(expected_state.clone());
                        }
                        if coauth_code_verifier().trim().is_empty() {
                            coauth_code_verifier.set(scaffold.code_verifier);
                        }
                    }
                }
                match extract_error_from_callback(&callback_url) {
                    Ok(Some(error_code)) => {
                        let error_description =
                            extract_error_description_from_callback(&callback_url)
                                .ok()
                                .flatten()
                                .unwrap_or_else(|| "missing".to_owned());
                        let returned_state = extract_state_from_callback(&callback_url)
                            .ok()
                            .flatten()
                            .unwrap_or_default();
                        coauth_authorization_code.set(String::new());
                        coauth_imported_state.set(returned_state.clone());
                        coauth_state_verified.set(false);
                        integration_plan_status.set(format!(
                            "Captured OIDC callback automatically from /auth/callback.\nerror={error_code}\nerror_description={error_description}\nexpected_state={}\nreturned_state={}\n\nDo not continue the bridge flow until the browser callback succeeds.",
                            if expected_state.is_empty() { "missing" } else { expected_state.as_str() },
                            if returned_state.is_empty() { "missing" } else { returned_state.as_str() },
                        ));
                    }
                    Ok(None) => match extract_authorization_code_from_callback(&callback_url) {
                        Ok(code) => {
                            let returned_state = extract_state_from_callback(&callback_url)
                                .ok()
                                .flatten()
                                .unwrap_or_default();
                            if expected_state.is_empty() {
                                coauth_authorization_code.set(code);
                                coauth_imported_state.set(returned_state.clone());
                                coauth_state_verified.set(returned_state.is_empty());
                                integration_plan_status.set(format!(
                                    "Captured authorization code automatically from /auth/callback without a prepared expected state.\nreturned_state={}\n\nRun `Prepare OIDC Browser Flow` first if you want the client to verify callback state before `OIDC Code + Push Bridge`.",
                                    if returned_state.is_empty() { "missing" } else { returned_state.as_str() },
                                ));
                            } else if returned_state.is_empty() {
                                coauth_authorization_code.set(String::new());
                                coauth_imported_state.set(String::new());
                                coauth_state_verified.set(false);
                                integration_plan_status.set(format!(
                                    "Captured browser callback is missing state.\nexpected_state={expected_state}\n\nRefuse to continue until the callback returns the prepared state."
                                ));
                            } else if returned_state != expected_state {
                                coauth_authorization_code.set(String::new());
                                coauth_imported_state.set(returned_state.clone());
                                coauth_state_verified.set(false);
                                integration_plan_status.set(format!(
                                    "Captured browser callback state mismatch.\nexpected_state={expected_state}\nreturned_state={returned_state}\n\nRefuse to continue until the returned callback matches the prepared browser flow."
                                ));
                            } else {
                                coauth_authorization_code.set(code);
                                coauth_imported_state.set(returned_state.clone());
                                coauth_state_verified.set(true);
                                integration_plan_status.set(format!(
                                    "Captured authorization code automatically from /auth/callback.\nstate={returned_state}\nstate_verified=true\n\nRun `OIDC Code + Push Bridge` to continue the scaffold flow."
                                ));
                            }
                        }
                        Err(error) => integration_plan_status
                            .set(format!("automatic browser callback capture failed: {error}")),
                    },
                    Err(error) => integration_plan_status
                        .set(format!("automatic browser callback inspection failed: {error}")),
                }
            }
            Err(error) => integration_plan_status
                .set(format!("automatic callback capture unavailable: {error}")),
        }
    });

    rsx! {
        div { class: "timeline", "data-testid": "login-panel", role: "region", "aria-label": "Login",
            div { class: "event",
                div { class: "event-head", span { "Identity entry" } span { "secure account access" } }
                div { class: "muted",
                    "Connect to a Principal Server, identify the account DID, bind the current device, then choose a supported authentication method. Development login is available for local workflows only."
                }
            }

            // Connection test
            div { class: "event", "data-testid": "connection-test",
                div { class: "event-head", span { "Server" } span { "connection test" } }
                div { class: "muted",
                    "Server: this endpoint issues challenges, validates credentials, and returns session tokens. Use an HTTPS origin outside local development."
                }
                div { class: "workflow-form",
                    label { "Server URL" }
                    input {
                        "data-testid": "login-server-url",
                        "aria-label": "Server URL",
                        value: "{base_url}",
                        oninput: move |evt| base_url.set(evt.value()),
                    }
                    div { class: "actions",
                        button {
                            class: "primary",
                            "data-testid": "test-connection-button",
                            onclick: {
                                move |_| {
                                    let base = base_url();
                                    spawn(async move {
                                        match ContrixApi::new(&base) {
                                            Ok(api) => match api.health().await {
                                                Ok(health) => health_status.set(format!(
                                                    "OK: service={}, storage={}",
                                                    health.service, health.storage
                                                )),
                                                Err(e) => health_status.set(format!("Health check failed: {e}")),
                                            },
                                            Err(e) => health_status.set(format!("Invalid URL: {e}")),
                                        }
                                    });
                                }
                            },
                            "Test Connection"
                        }
                    }
                    if !health_status().is_empty() {
                        div { class: "muted", "data-testid": "health-status", "{health_status}" }
                    }
                }
            }

            // Account DID input with validation
            div { class: "event", "data-testid": "account-input",
                div { class: "event-head", span { "Account" } span { "DID" } }
                div { class: "muted",
                    "Account: enter the DID that owns the workspace. The client validates the DID shape before requesting method-specific challenges."
                }
                div { class: "workflow-form",
                    label { "Account DID" }
                    input {
                        "data-testid": "login-account-did",
                        value: "{account_did}",
                        placeholder: "did:web:alice.example",
                        oninput: move |evt| {
                            let val = evt.value();
                            if val.starts_with("did:") {
                                did_validation.set(String::new());
                            } else {
                                did_validation.set("DID must start with 'did:' prefix".to_owned());
                            }
                            account_did.set(val);
                        },
                    }
                    if !did_validation().is_empty() {
                        div { class: "muted", "data-testid": "did-validation", "{did_validation}" }
                    }
                    div { class: "muted",
                        "Device: this label scopes the session to the current browser or machine and appears in audit/recovery flows."
                    }
                    label { "Device ID" }
                    input {
                        "data-testid": "login-device-id",
                        value: "{device_id}",
                        oninput: move |evt| device_id.set(evt.value()),
                    }
                }
            }

            // Login methods
            div { class: "event", "data-testid": "login-methods",
                div { class: "event-head", span { "Login" } span { "choose method" } }
                div { class: "muted",
                    "Method: dev login still bootstraps a local session on the Principal Server. Production passkey and OIDC should originate from coauth, then hand a session grant to soland and the chime-backed push path."
                }
                div { class: "actions",
                    button {
                        class: "primary",
                        "data-testid": "passkey-login-button",
                        onclick: {
                            move |_| {
                                let now = Utc::now().timestamp() as f64;
                                if let Err(cooldown) = rate_limiter.read().check("passkey", now) {
                                    passkey_status.set(format!("Rate limited. Try again in {cooldown:.0}s"));
                                    return;
                                }
                                let base = base_url();
                                let did = account_did();
                                spawn(async move {
                                    match ContrixApi::new(&base) {
                                        Ok(api) => match api.passkey_challenge(&did).await {
                                            Ok(challenge) => {
                                                rate_limiter.write().clear("passkey");
                                                passkey_status.set(format!(
                                                    "Challenge received: rp={}, expires={}",
                                                    challenge.rp_id, challenge.expires_at
                                                ))
                                            }
                                            Err(e) => {
                                                let now = Utc::now().timestamp() as f64;
                                                rate_limiter.write().record_failure("passkey", now);
                                                passkey_status.set(format!("Passkey challenge failed: {e}"))
                                            }
                                        },
                                        Err(e) => passkey_status.set(format!("Invalid URL: {e}")),
                                    }
                                });
                            }
                        },
                        "Passkey Login"
                    }
                    button {
                        class: "secondary",
                        "data-testid": "oidc-login-button",
                        onclick: {
                            move |_| {
                                let now = Utc::now().timestamp() as f64;
                                if let Err(cooldown) = rate_limiter.read().check("oidc", now) {
                                    oidc_status.set(format!("Rate limited. Try again in {cooldown:.0}s"));
                                    return;
                                }
                                let base = base_url();
                                spawn(async move {
                                    match ContrixApi::new(&base) {
                                        Ok(api) => match api.oidc_authorize("default", "http://localhost:3000/callback").await {
                                            Ok(resp) => {
                                                rate_limiter.write().clear("oidc");
                                                oidc_status.set(format!(
                                                    "Redirect: {} (state: {})",
                                                    resp.redirect_url, resp.state
                                                ))
                                            }
                                            Err(e) => {
                                                let now = Utc::now().timestamp() as f64;
                                                rate_limiter.write().record_failure("oidc", now);
                                                oidc_status.set(format!("OIDC failed: {e}"))
                                            }
                                        },
                                        Err(e) => oidc_status.set(format!("Invalid URL: {e}")),
                                    }
                                });
                            }
                        },
                        "OIDC Login"
                    }
                    button {
                        class: "secondary",
                        "data-testid": "dev-login-button",
                        onclick: {
                            move |_| {
                                let now = Utc::now().timestamp() as f64;
                                if let Err(cooldown) = rate_limiter.read().check("dev-login", now) {
                                    dev_login_status.set(format!("Rate limited. Try again in {cooldown:.0}s"));
                                    return;
                                }
                                let base = base_url();
                                let did = account_did();
                                let dev = device_id();
                                spawn(async move {
                                    match ContrixApi::new(&base) {
                                        Ok(api) => {
                                            let result = if did.is_empty() {
                                                api.dev_login("did:web:alice.example", &dev).await
                                            } else {
                                                api.dev_login(&did, &dev).await
                                            };
                                            match result {
                                                Ok(session) => {
                                                    rate_limiter.write().clear("dev-login");
                                                    token.set(session.access_token.clone());
                                                    persist_config(
                                                        config_store,
                                                        base.clone(),
                                                        did.clone(),
                                                        dev.clone(),
                                                        session.access_token.clone(),
                                                    );
                                                    session_state.set(SessionState::Connected);
                                                    session_info.set(format!(
                                                        "DID: {}, Device: {}",
                                                        session.actor, session.device_id
                                                    ));
                                                    token_expiry.set(session.expires_at.clone());
                                                    dev_login_status.set("Logged in via dev-login".to_owned());
                                                    status.set(format!("Online: dev-login as {}", session.actor));
                                                    on_login.call(());
                                                }
                                                Err(e) => {
                                                    let now = Utc::now().timestamp() as f64;
                                                    rate_limiter.write().record_failure("dev-login", now);
                                                    dev_login_status.set(format!("Dev login failed: {e}"))
                                                }
                                            }
                                        }
                                        Err(e) => dev_login_status.set(format!("Invalid URL: {e}")),
                                    }
                                });
                            }
                        },
                        "Dev Login"
                    }
                }
                if !passkey_status().is_empty() {
                    div { class: "muted", "data-testid": "passkey-status", "{passkey_status}" }
                }
                if !oidc_status().is_empty() {
                    div { class: "muted", "data-testid": "oidc-status", "{oidc_status}" }
                }
                if !dev_login_status().is_empty() {
                    div { class: "muted", "data-testid": "dev-login-status", "{dev_login_status}" }
                }
            }

            div { class: "event", "data-testid": "production-auth-bridge",
                div { class: "event-head", span { "Production auth bridge" } span { "coauth -> soland / chime" } }
                div { class: "muted",
                    "Production auth is a separate topology: coauth owns OIDC and account sessions, soland consumes short-lived grants, and chime registration needs the same grant context on push registration requests."
                }
                div { class: "workflow-form",
                    label { "Auth Server URL" }
                    input {
                        "data-testid": "auth-server-url",
                        "aria-label": "Auth Server URL",
                        value: "{auth_server_url}",
                        oninput: move |evt| auth_server_url.set(evt.value()),
                    }
                    label { "Coauth Username" }
                    input {
                        "data-testid": "coauth-username",
                        value: "{coauth_username}",
                        oninput: move |evt| coauth_username.set(evt.value()),
                    }
                    label { "Coauth Password" }
                    input {
                        r#type: "password",
                        "data-testid": "coauth-password",
                        value: "{coauth_password}",
                        oninput: move |evt| coauth_password.set(evt.value()),
                    }
                    label { "OIDC Authorization Code" }
                    input {
                        "data-testid": "coauth-authorization-code",
                        value: "{coauth_authorization_code}",
                        oninput: move |evt| coauth_authorization_code.set(evt.value()),
                    }
                    label { "OIDC Callback URL" }
                    input {
                        "data-testid": "coauth-callback-url",
                        value: "{coauth_callback_url}",
                        oninput: move |evt| coauth_callback_url.set(evt.value()),
                    }
                    label { "OIDC PKCE Code Verifier" }
                    input {
                        "data-testid": "coauth-code-verifier",
                        value: "{coauth_code_verifier}",
                        oninput: move |evt| coauth_code_verifier.set(evt.value()),
                    }
                    div { class: "actions",
                        button {
                            class: "secondary",
                            "data-testid": "capture-oidc-browser-callback-button",
                            onclick: {
                                move |_| {
                                    match capture_current_browser_callback_url() {
                                        Ok(callback_url) => {
                                            coauth_callback_url.set(callback_url.clone());
                                            let mut expected_state = coauth_expected_state();
                                            if expected_state.trim().is_empty()
                                                || coauth_code_verifier().trim().is_empty()
                                            {
                                                if let Ok(Some(scaffold)) = restore_oidc_scaffold()
                                                {
                                                    if auth_server_url() == base_url() {
                                                        auth_server_url
                                                            .set(scaffold.auth_server_url.clone());
                                                    }
                                                    if base_url().trim().is_empty() {
                                                        base_url.set(
                                                            scaffold.principal_server_url.clone(),
                                                        );
                                                    }
                                                    if account_did().trim().is_empty() {
                                                        account_did.set(
                                                            scaffold.principal_actor_did.clone(),
                                                        );
                                                    }
                                                    if device_id().trim().is_empty() {
                                                        device_id
                                                            .set(scaffold.device_id.clone());
                                                    }
                                                    if expected_state.trim().is_empty() {
                                                        expected_state =
                                                            scaffold.expected_state.clone();
                                                        coauth_expected_state
                                                            .set(expected_state.clone());
                                                    }
                                                    if coauth_code_verifier().trim().is_empty() {
                                                        coauth_code_verifier
                                                            .set(scaffold.code_verifier);
                                                    }
                                                }
                                            }
                                            match extract_error_from_callback(&callback_url) {
                                                Ok(Some(error_code)) => {
                                                    let error_description =
                                                        extract_error_description_from_callback(
                                                            &callback_url,
                                                        )
                                                        .ok()
                                                        .flatten()
                                                        .unwrap_or_else(|| "missing".to_owned());
                                                    let returned_state = extract_state_from_callback(
                                                        &callback_url,
                                                    )
                                                    .ok()
                                                    .flatten()
                                                    .unwrap_or_default();
                                                    coauth_authorization_code.set(String::new());
                                                    coauth_imported_state.set(returned_state.clone());
                                                    coauth_state_verified.set(false);
                                                    integration_plan_status.set(format!(
                                                        "Captured OIDC callback from current browser location.\nerror={error_code}\nerror_description={error_description}\nexpected_state={}\nreturned_state={}\n\nDo not continue the bridge flow until the browser callback succeeds.",
                                                        if expected_state.is_empty() { "missing" } else { expected_state.as_str() },
                                                        if returned_state.is_empty() { "missing" } else { returned_state.as_str() },
                                                    ));
                                                }
                                                Ok(None) => match extract_authorization_code_from_callback(
                                                    &callback_url,
                                                ) {
                                                    Ok(code) => {
                                                        let returned_state = extract_state_from_callback(
                                                            &callback_url,
                                                        )
                                                        .ok()
                                                        .flatten()
                                                        .unwrap_or_default();
                                                        let expected_state = coauth_expected_state();
                                                        if expected_state.is_empty() {
                                                            coauth_authorization_code.set(code);
                                                            coauth_imported_state
                                                                .set(returned_state.clone());
                                                            coauth_state_verified
                                                                .set(returned_state.is_empty());
                                                            integration_plan_status.set(format!(
                                                                "Captured authorization code from current browser location without a prepared expected state.\nreturned_state={}\n\nRun `Prepare OIDC Browser Flow` first if you want the client to verify callback state before `OIDC Code + Push Bridge`.",
                                                                if returned_state.is_empty() { "missing" } else { returned_state.as_str() },
                                                            ));
                                                        } else if returned_state.is_empty() {
                                                            coauth_authorization_code
                                                                .set(String::new());
                                                            coauth_imported_state
                                                                .set(String::new());
                                                            coauth_state_verified.set(false);
                                                            integration_plan_status.set(format!(
                                                                "Captured browser callback is missing state.\nexpected_state={expected_state}\n\nRefuse to continue until the callback returns the prepared state."
                                                            ));
                                                        } else if returned_state != expected_state {
                                                            coauth_authorization_code
                                                                .set(String::new());
                                                            coauth_imported_state
                                                                .set(returned_state.clone());
                                                            coauth_state_verified.set(false);
                                                            integration_plan_status.set(format!(
                                                                "Captured browser callback state mismatch.\nexpected_state={expected_state}\nreturned_state={returned_state}\n\nRefuse to continue until the returned callback matches the prepared browser flow."
                                                            ));
                                                        } else {
                                                            coauth_authorization_code.set(code);
                                                            coauth_imported_state
                                                                .set(returned_state.clone());
                                                            coauth_state_verified.set(true);
                                                            integration_plan_status.set(format!(
                                                                "Captured authorization code from current browser location.\nstate={returned_state}\nstate_verified=true\n\nRun `OIDC Code + Push Bridge` to continue the scaffold flow."
                                                            ));
                                                        }
                                                    }
                                                    Err(error) => integration_plan_status.set(format!(
                                                        "browser callback capture failed: {error}"
                                                    )),
                                                },
                                                Err(error) => integration_plan_status.set(format!(
                                                    "browser callback inspection failed: {error}"
                                                )),
                                            }
                                        }
                                        Err(error) => integration_plan_status.set(format!(
                                            "current browser callback capture failed: {error}"
                                        )),
                                    }
                                }
                            },
                            "Capture Current Callback"
                        }
                        button {
                            class: "secondary",
                            "data-testid": "import-oidc-callback-button",
                            onclick: {
                                move |_| {
                                    let callback_url = coauth_callback_url();
                                    let mut expected_state = coauth_expected_state();
                                    if expected_state.trim().is_empty()
                                        || coauth_code_verifier().trim().is_empty()
                                    {
                                        if let Ok(Some(scaffold)) = restore_oidc_scaffold() {
                                            if auth_server_url() == base_url() {
                                                auth_server_url
                                                    .set(scaffold.auth_server_url.clone());
                                            }
                                            if base_url().trim().is_empty() {
                                                base_url
                                                    .set(scaffold.principal_server_url.clone());
                                            }
                                            if account_did().trim().is_empty() {
                                                account_did
                                                    .set(scaffold.principal_actor_did.clone());
                                            }
                                            if device_id().trim().is_empty() {
                                                device_id.set(scaffold.device_id.clone());
                                            }
                                            if expected_state.trim().is_empty() {
                                                expected_state = scaffold.expected_state.clone();
                                                coauth_expected_state
                                                    .set(expected_state.clone());
                                            }
                                            if coauth_code_verifier().trim().is_empty() {
                                                coauth_code_verifier
                                                    .set(scaffold.code_verifier);
                                            }
                                        }
                                    }
                                    match extract_error_from_callback(&callback_url) {
                                        Ok(Some(error_code)) => {
                                            let error_description =
                                                extract_error_description_from_callback(
                                                    &callback_url,
                                                )
                                                .ok()
                                                .flatten()
                                                .unwrap_or_else(|| "missing".to_owned());
                                            let returned_state = extract_state_from_callback(
                                                &callback_url,
                                            )
                                            .ok()
                                            .flatten()
                                            .unwrap_or_default();
                                            coauth_authorization_code.set(String::new());
                                            coauth_imported_state.set(returned_state.clone());
                                            coauth_state_verified.set(false);
                                            integration_plan_status.set(format!(
                                                "OIDC callback returned an error.\nerror={error_code}\nerror_description={error_description}\nexpected_state={}\nreturned_state={}\n\nDo not continue the bridge flow until the browser callback succeeds.",
                                                if expected_state.is_empty() { "missing" } else { expected_state.as_str() },
                                                if returned_state.is_empty() { "missing" } else { returned_state.as_str() },
                                            ));
                                        }
                                        Ok(None) => match extract_authorization_code_from_callback(
                                            &callback_url,
                                        ) {
                                            Ok(code) => {
                                                let returned_state = extract_state_from_callback(
                                                    &callback_url,
                                                )
                                                .ok()
                                                .flatten()
                                                .unwrap_or_default();
                                                let expected_state = coauth_expected_state();
                                                if expected_state.is_empty() {
                                                    coauth_authorization_code.set(code);
                                                    coauth_imported_state
                                                        .set(returned_state.clone());
                                                    coauth_state_verified
                                                        .set(returned_state.is_empty());
                                                    integration_plan_status.set(format!(
                                                        "Imported authorization code from callback URL without a prepared expected state.\nreturned_state={}\n\nRun `Prepare OIDC Browser Flow` first if you want the client to verify callback state before `OIDC Code + Push Bridge`.",
                                                        if returned_state.is_empty() { "missing" } else { returned_state.as_str() },
                                                    ));
                                                } else if returned_state.is_empty() {
                                                    coauth_authorization_code
                                                        .set(String::new());
                                                    coauth_imported_state
                                                        .set(String::new());
                                                    coauth_state_verified
                                                        .set(false);
                                                    integration_plan_status.set(format!(
                                                        "Callback URL is missing state.\nexpected_state={expected_state}\n\nRefuse to continue until the callback returns the prepared state."
                                                    ));
                                                } else if returned_state != expected_state {
                                                    coauth_authorization_code
                                                        .set(String::new());
                                                    coauth_imported_state
                                                        .set(returned_state.clone());
                                                    coauth_state_verified
                                                        .set(false);
                                                    integration_plan_status.set(format!(
                                                        "Callback state mismatch.\nexpected_state={expected_state}\nreturned_state={returned_state}\n\nRefuse to continue until the returned callback matches the prepared browser flow."
                                                    ));
                                                } else {
                                                    coauth_authorization_code.set(code);
                                                    coauth_imported_state
                                                        .set(returned_state.clone());
                                                    coauth_state_verified
                                                        .set(true);
                                                    integration_plan_status.set(format!(
                                                        "Imported authorization code from callback URL.\nstate={returned_state}\nstate_verified=true\n\nRun `OIDC Code + Push Bridge` to continue the scaffold flow."
                                                    ));
                                                }
                                            }
                                            Err(error) => integration_plan_status.set(format!(
                                                "callback URL import failed: {error}"
                                            )),
                                        },
                                        Err(error) => integration_plan_status
                                            .set(format!("callback URL inspection failed: {error}")),
                                    }
                                }
                            },
                            "Import Callback URL"
                        }
                        button {
                            class: "secondary",
                            "data-testid": "inspect-coauth-button",
                            onclick: {
                                move |_| {
                                    let auth = auth_server_url();
                                    spawn(async move {
                                        match CoauthApi::new(&auth) {
                                            Ok(api) => match api.inspect_topology().await {
                                                Ok(topology) => {
                                                    let pkce = if topology.code_challenge_methods_supported.is_empty() {
                                                        "none advertised".to_owned()
                                                    } else {
                                                        topology.code_challenge_methods_supported.join(", ")
                                                    };
                                                    coauth_status.set(format!(
                                                        "issuer={} service_did={} service_type={} protocol={} identity_service_did={} authz={} token={} pkce={}",
                                                        topology.issuer,
                                                        topology.service_did.unwrap_or_else(|| "unknown".to_owned()),
                                                        topology.service_type.unwrap_or_else(|| "unknown".to_owned()),
                                                        topology.protocol_version.unwrap_or_else(|| "unknown".to_owned()),
                                                        topology.identity_service_did.unwrap_or_else(|| "unknown".to_owned()),
                                                        topology.authorization_endpoint,
                                                        topology.token_endpoint.unwrap_or_else(|| "missing".to_owned()),
                                                        pkce,
                                                    ));
                                                }
                                                Err(error) => coauth_status.set(format!("coauth inspect failed: {error}")),
                                            },
                                            Err(error) => coauth_status.set(format!("invalid auth server URL: {error}")),
                                        }
                                    });
                                }
                            },
                            "Inspect Coauth"
                        }
                        button {
                            class: "secondary",
                            "data-testid": "plan-production-auth-bridge-button",
                            onclick: {
                                move |_| {
                                    let auth = auth_server_url();
                                    let principal = base_url();
                                    let actor = account_did();
                                    let dev = device_id();
                                    spawn(async move {
                                        match CoauthApi::new(&auth) {
                                            Ok(api) => match api.inspect_topology().await {
                                                Ok(topology) => {
                                                    match (
                                                        build_soland_session_grant_plan(&topology, &principal, &actor, &dev),
                                                        build_chime_push_grant_plan(&principal, &dev),
                                                    ) {
                                                        (Ok(soland_plan), Ok(chime_plan)) => integration_plan_status.set(format!(
                                                            "OIDC authorize preview:\n{}\n\nSoland principal URL: {}\nSoland audience: {}\nActor DID: {}\nDevice ID: {}\nToken endpoint: {}\n{}\n\nChime register scaffold:\nprincipal={}\naudience={}\ndevice_id={}\n{}\n{}",
                                                            soland_plan.authorize_url_preview,
                                                            soland_plan.principal_server_url,
                                                            soland_plan.principal_audience,
                                                            soland_plan.actor_did,
                                                            soland_plan.device_id,
                                                            soland_plan.token_endpoint.unwrap_or_else(|| "missing".to_owned()),
                                                            soland_plan.todo,
                                                            chime_plan.principal_server_url,
                                                            chime_plan.principal_audience,
                                                            chime_plan.device_id,
                                                            chime_plan.register_request_preview,
                                                            chime_plan.todo,
                                                        )),
                                                        (Err(error), _) => integration_plan_status.set(format!("soland bridge plan failed: {error}")),
                                                        (_, Err(error)) => integration_plan_status.set(format!("chime bridge plan failed: {error}")),
                                                    }
                                                }
                                                Err(error) => integration_plan_status.set(format!("coauth inspect failed: {error}")),
                                            },
                                            Err(error) => integration_plan_status.set(format!("invalid auth server URL: {error}")),
                                        }
                                    });
                                }
                            },
                            "Plan Soland + Chime"
                        }
                        button {
                            class: "secondary",
                            "data-testid": "plan-coauth-oidc-exchange-button",
                            onclick: {
                                move |_| {
                                    let auth = auth_server_url();
                                    let principal = base_url();
                                    let actor = account_did();
                                    let dev = device_id();
                                    spawn(async move {
                                        match CoauthApi::new(&auth) {
                                            Ok(api) => match api.inspect_topology().await {
                                                Ok(topology) => match build_oidc_code_exchange_plan(&topology, &principal, &actor, &dev) {
                                                    Ok(plan) => integration_plan_status.set(format!(
                                                        "Authorize URL preview:\n{}\n\nToken endpoint: {}\nPrincipal URL: {}\nAudience: {}\nActor DID: {}\nDevice ID: {}\nExchange request preview:\n{}\n\n{}",
                                                        plan.authorize_url_preview,
                                                        plan.token_endpoint,
                                                        plan.principal_server_url,
                                                        plan.principal_audience,
                                                        plan.actor_did,
                                                        plan.device_id,
                                                        plan.exchange_request_preview,
                                                        plan.todo,
                                                    )),
                                                    Err(error) => integration_plan_status.set(format!("oidc code-exchange plan failed: {error}")),
                                                },
                                                Err(error) => integration_plan_status.set(format!("coauth inspect failed: {error}")),
                                            },
                                            Err(error) => integration_plan_status.set(format!("invalid auth server URL: {error}")),
                                        }
                                    });
                                }
                            },
                            "Plan OIDC Exchange"
                        }
                        button {
                            class: "secondary",
                            "data-testid": "prepare-oidc-browser-scaffold-button",
                            onclick: {
                                move |_| {
                                    let auth = auth_server_url();
                                    let principal = base_url();
                                    let actor = account_did();
                                    let dev = device_id();
                                    spawn(async move {
                                        match CoauthApi::new(&auth) {
                                            Ok(api) => match api.inspect_topology().await {
                                                Ok(topology) => match build_oidc_scaffold_bundle(&topology, &principal, &actor, &dev) {
                                                    Ok(bundle) => {
                                                        let persistence_status = match persist_oidc_scaffold(&bundle, auth.as_str(), principal.as_str(), actor.as_str(), dev.as_str()) {
                                                            Ok(()) => "browser scaffold persisted for callback recovery".to_owned(),
                                                            Err(error) => format!("browser scaffold persistence unavailable: {error}"),
                                                        };
                                                        coauth_authorization_code.set(String::new());
                                                        coauth_callback_url.set(String::new());
                                                        coauth_code_verifier.set(bundle.code_verifier.clone());
                                                        coauth_expected_state.set(bundle.state.clone());
                                                        coauth_imported_state.set(String::new());
                                                        coauth_state_verified.set(false);
                                                        integration_plan_status.set(format!(
                                                            "Open this authorize URL in the browser:\n{}\n\ncallback_uri={}\nprincipal_audience={}\nstate={}\nnonce={}\ncode_verifier={}\ncode_challenge={}\n{}\n\nImport the returned callback URL next. The client will verify the callback state before allowing `OIDC Code + Push Bridge`.\n\n{}",
                                                            bundle.authorize_url,
                                                            bundle.callback_uri,
                                                            bundle.principal_audience,
                                                            bundle.state,
                                                            bundle.nonce,
                                                            bundle.code_verifier,
                                                            bundle.code_challenge,
                                                            persistence_status,
                                                            bundle.todo,
                                                        ));
                                                    }
                                                    Err(error) => integration_plan_status.set(format!("oidc browser scaffold failed: {error}")),
                                                },
                                                Err(error) => integration_plan_status.set(format!("coauth inspect failed: {error}")),
                                            },
                                            Err(error) => integration_plan_status.set(format!("invalid auth server URL: {error}")),
                                        }
                                    });
                                }
                            },
                            "Prepare OIDC Browser Flow"
                        }
                        button {
                            class: "primary",
                            "data-testid": "bridge-oidc-code-push-button",
                            onclick: {
                                move |_| {
                                    let auth = auth_server_url();
                                    let principal = base_url();
                                    let actor = account_did();
                                    let dev = device_id();
                                    let authorization_code = coauth_authorization_code();
                                    let code_verifier = coauth_code_verifier();
                                    let redirect_uri = active_oidc_redirect_uri();
                                    let expected_state = coauth_expected_state();
                                    let imported_state = coauth_imported_state();
                                    let state_verified = coauth_state_verified();
                                    if authorization_code.trim().is_empty() {
                                        integration_plan_status.set(
                                            "missing authorization code: import a successful OIDC callback before continuing".to_owned(),
                                        );
                                        return;
                                    }
                                    if code_verifier.trim().is_empty() {
                                        integration_plan_status.set(
                                            "missing PKCE code verifier: run `Prepare OIDC Browser Flow` before continuing".to_owned(),
                                        );
                                        return;
                                    }
                                    if !expected_state.is_empty() && !state_verified {
                                        integration_plan_status.set(format!(
                                            "callback state has not been verified.\nexpected_state={expected_state}\nimported_state={}\n\nImport a successful callback URL whose state matches the prepared browser flow before running `OIDC Code + Push Bridge`.",
                                            if imported_state.is_empty() { "missing" } else { imported_state.as_str() },
                                        ));
                                        return;
                                    }
                                    spawn(async move {
                                        match CoauthApi::new(&auth) {
                                            Ok(coauth) => match coauth.inspect_topology().await {
                                                Ok(topology) => match build_oidc_code_exchange_plan(&topology, &principal, &actor, &dev) {
                                                    Ok(plan) => {
                                                        let issuer = topology.issuer.trim().to_owned();
                                                        if issuer.is_empty() {
                                                            integration_plan_status.set(
                                                                "coauth inspect returned an empty issuer; refuse to continue the OIDC bridge until discovery is coherent".to_owned(),
                                                            );
                                                            return;
                                                        }
                                                        let Some(token_endpoint) = topology
                                                            .token_endpoint
                                                            .clone()
                                                            .filter(|value| !value.trim().is_empty())
                                                        else {
                                                            integration_plan_status.set(
                                                                "coauth inspect did not expose a token_endpoint; refuse to continue the OIDC bridge until upstream discovery is complete".to_owned(),
                                                            );
                                                            return;
                                                        };
                                                        let Some(userinfo_endpoint) = topology
                                                            .userinfo_endpoint
                                                            .clone()
                                                            .filter(|value| !value.trim().is_empty())
                                                        else {
                                                            integration_plan_status.set(
                                                                "coauth inspect did not expose a userinfo_endpoint; refuse to continue the OIDC bridge until discovery is complete".to_owned(),
                                                            );
                                                            return;
                                                        };
                                                        let returned_state = (!imported_state.trim().is_empty())
                                                            .then_some(imported_state.as_str());
                                                        let expected_state_param = (!expected_state
                                                            .trim()
                                                            .is_empty())
                                                            .then_some(expected_state.as_str());
                                                        match coauth
                                                            .exchange_oidc_code(
                                                                &topology.oidc_exchange_path,
                                                                &authorization_code,
                                                                &code_verifier,
                                                                &redirect_uri,
                                                                &issuer,
                                                                &token_endpoint,
                                                                &userinfo_endpoint,
                                                                &plan.client_id,
                                                                &actor,
                                                                &dev,
                                                                Some(&plan.principal_audience),
                                                                returned_state,
                                                                expected_state_param,
                                                            )
                                                            .await
                                                        {
                                                        Ok(login) => {
                                                            if login.status != "success" {
                                                                integration_plan_status.set(format!(
                                                                    "coauth oidc exchange returned status={} error={}",
                                                                    login.status,
                                                                    login.error.unwrap_or_else(|| "unknown".to_owned()),
                                                                ));
                                                                return;
                                                            }
                                                            let Some(grant) = login.session_grant.as_ref() else {
                                                                integration_plan_status.set("coauth oidc exchange succeeded but returned no session grant".to_owned());
                                                                return;
                                                            };
                                                            let principal_target = grant
                                                                .principal_server
                                                                .as_ref()
                                                                .map(|server| server.endpoint.clone())
                                                                .unwrap_or_else(|| principal.clone());
                                                            match ContrixApi::new(&principal_target) {
                                                                Ok(api) => match api.auth_bridge_describe().await {
                                                                    Ok(bridge) => match api.exchange_session_grant_at(&bridge.auth.session_grant_exchange_path, &grant.grant_jwt, &actor, &dev).await {
                                                                    Ok(session) => {
                                                                        let register_request = match crate::push::build_register_request_for_actor(&dev, Some(&actor)) {
                                                                            Ok(request) => request,
                                                                            Err(error) => {
                                                                                integration_plan_status.set(format!("push register scaffold failed: {error}"));
                                                                                return;
                                                                            }
                                                                        };
                                                                        let register_request_preview = match serde_json::to_string_pretty(&register_request) {
                                                                            Ok(preview) => preview,
                                                                            Err(error) => {
                                                                                integration_plan_status.set(format!("push register preview failed: {error}"));
                                                                                return;
                                                                            }
                                                                        };
                                                                        let push_gateway_bridge_summary = match crate::push::describe_push_gateway_bridge(&register_request.push_gateway).await {
                                                                            Ok(bridge) => summarize_push_gateway_bridge(&bridge),
                                                                            Err(error) => format!("bridge_lookup_failed={error}"),
                                                                        };
                                                                        let api = api.with_bearer(session.access_token.clone());
                                                                        match api.register_push_device_with_request_at(&bridge.push.register_device_path, &register_request).await {
                                                                            Ok(response) => {
                                                                                let _ = clear_persisted_oidc_scaffold();
                                                                                token.set(session.access_token.clone());
                                                                                persist_config(
                                                                                    config_store,
                                                                                    principal_target.clone(),
                                                                                    actor.clone(),
                                                                                    dev.clone(),
                                                                                    session.access_token.clone(),
                                                                                );
                                                                                session_state.set(SessionState::Connected);
                                                                                session_info.set(format!(
                                                                                    "DID: {}, Device: {}",
                                                                                    session.actor, session.device_id
                                                                                ));
                                                                                token_expiry.set(session.expires_at.clone());
                                                                                status.set(format!(
                                                                                    "Online: oidc-code scaffold bridge as {}",
                                                                                    session.actor
                                                                                ));
                                                                                integration_plan_status.set(format!(
                                                                                    "{}\n\nauthorize_url_preview={}\ntoken_endpoint={}\nprincipal_target={}\npush_gateway_bridge={}\nsoland_bearer_session_expires={}\npush_registration_id={}",
                                                                                    summarize_password_login_bridge(
                                                                                        &login,
                                                                                        response.registration_id.as_deref(),
                                                                                        &register_request_preview,
                                                                                    ),
                                                                                    plan.authorize_url_preview,
                                                                                    plan.token_endpoint,
                                                                                    principal_target,
                                                                                    push_gateway_bridge_summary,
                                                                                    session.expires_at,
                                                                                    response.registration_id.as_deref().unwrap_or("missing"),
                                                                                ));
                                                                                on_login.call(());
                                                                            }
                                                                            Err(error) => integration_plan_status.set(format!(
                                                                                "push register after oidc-code exchange failed: {error}\nrequest_preview:\n{}",
                                                                                register_request_preview,
                                                                            )),
                                                                        }
                                                                    }
                                                                    Err(error) => integration_plan_status.set(format!(
                                                                        "soland session-grant exchange after oidc-code scaffold failed: {error}"
                                                                    )),
                                                                },
                                                                    Err(error) => integration_plan_status.set(format!(
                                                                        "principal auth bridge describe failed: {error}"
                                                                    )),
                                                                },
                                                                Err(error) => integration_plan_status.set(format!("invalid principal server URL: {error}")),
                                                            }
                                                        }
                                                        Err(error) => integration_plan_status.set(format!("coauth oidc exchange failed: {error}")),
                                                        }
                                                    }
                                                    Err(error) => integration_plan_status.set(format!("oidc code-exchange plan failed: {error}")),
                                                },
                                                Err(error) => integration_plan_status.set(format!("coauth inspect failed: {error}")),
                                            },
                                            Err(error) => integration_plan_status.set(format!("invalid auth server URL: {error}")),
                                        }
                                    });
                                }
                            },
                            "OIDC Code + Push Bridge"
                        }
                        button {
                            class: "primary",
                            "data-testid": "bridge-password-login-push-button",
                            onclick: {
                                move |_| {
                                    let auth = auth_server_url();
                                    let principal = base_url();
                                    let actor = account_did();
                                    let dev = device_id();
                                    let username = coauth_username();
                                    let password = coauth_password();
                                    spawn(async move {
                                        match CoauthApi::new(&auth) {
                                            Ok(coauth) => match coauth.password_login(&username, &password).await {
                                                Ok(login) => {
                                                    if login.status != "success" {
                                                        integration_plan_status.set(format!(
                                                            "coauth login returned status={} error={}",
                                                            login.status,
                                                            login.error.unwrap_or_else(|| "unknown".to_owned()),
                                                        ));
                                                        return;
                                                    }
                                                    let Some(grant) = login.session_grant.as_ref() else {
                                                        integration_plan_status.set("coauth login succeeded but returned no session grant".to_owned());
                                                        return;
                                                    };
                                                    let principal_target = grant
                                                        .principal_server
                                                        .as_ref()
                                                        .map(|server| server.endpoint.clone())
                                                        .unwrap_or_else(|| principal.clone());
                                                    match ContrixApi::new(&principal_target) {
                                                        Ok(api) => match api.auth_bridge_describe().await {
                                                            Ok(bridge) => match api.exchange_session_grant_at(&bridge.auth.session_grant_exchange_path, &grant.grant_jwt, &actor, &dev).await {
                                                            Ok(session) => {
                                                                let register_request = match crate::push::build_register_request_for_actor(&dev, Some(&actor)) {
                                                                    Ok(request) => request,
                                                                    Err(error) => {
                                                                        integration_plan_status.set(format!("push register scaffold failed: {error}"));
                                                                        return;
                                                                    }
                                                                };
                                                                let register_request_preview = match serde_json::to_string_pretty(&register_request) {
                                                                    Ok(preview) => preview,
                                                                    Err(error) => {
                                                                        integration_plan_status.set(format!("push register preview failed: {error}"));
                                                                        return;
                                                                    }
                                                                };
                                                                let push_gateway_bridge_summary = match crate::push::describe_push_gateway_bridge(&register_request.push_gateway).await {
                                                                    Ok(bridge) => summarize_push_gateway_bridge(&bridge),
                                                                    Err(error) => format!("bridge_lookup_failed={error}"),
                                                                };
                                                                let api = api.with_bearer(session.access_token.clone());
                                                                match api.register_push_device_with_request_at(&bridge.push.register_device_path, &register_request).await {
                                                                    Ok(response) => {
                                                                        token.set(session.access_token.clone());
                                                                        persist_config(
                                                                            config_store,
                                                                            principal_target.clone(),
                                                                            actor.clone(),
                                                                            dev.clone(),
                                                                            session.access_token.clone(),
                                                                        );
                                                                        session_state.set(SessionState::Connected);
                                                                        session_info.set(format!(
                                                                            "DID: {}, Device: {}",
                                                                            session.actor, session.device_id
                                                                        ));
                                                                        token_expiry.set(session.expires_at.clone());
                                                                        status.set(format!(
                                                                            "Online: session-grant bridge as {}",
                                                                            session.actor
                                                                        ));
                                                                        integration_plan_status.set(format!(
                                                                            "{}\n\nprincipal_target={}\npush_gateway_bridge={}\nsoland_bearer_session_expires={}\npush_registration_id={}",
                                                                            summarize_password_login_bridge(
                                                                                &login,
                                                                                response.registration_id.as_deref(),
                                                                                &register_request_preview,
                                                                            ),
                                                                            principal_target,
                                                                            push_gateway_bridge_summary,
                                                                            session.expires_at,
                                                                            response.registration_id.as_deref().unwrap_or("missing"),
                                                                        ));
                                                                        on_login.call(());
                                                                    }
                                                                    Err(error) => integration_plan_status.set(format!(
                                                                        "push register after session-grant exchange failed: {error}\nrequest_preview:\n{}",
                                                                        register_request_preview,
                                                                    )),
                                                                }
                                                            }
                                                            Err(error) => integration_plan_status.set(format!(
                                                                "soland session-grant exchange failed: {error}"
                                                            )),
                                                        },
                                                            Err(error) => integration_plan_status.set(format!(
                                                                "principal auth bridge describe failed: {error}"
                                                            )),
                                                        },
                                                        Err(error) => integration_plan_status.set(format!("invalid principal server URL: {error}")),
                                                    }
                                                }
                                                Err(error) => integration_plan_status.set(format!("coauth password login failed: {error}")),
                                            },
                                            Err(error) => integration_plan_status.set(format!("invalid auth server URL: {error}")),
                                        }
                                    });
                                }
                            },
                            "Password Login + Push Bridge"
                        }
                    }
                    if !coauth_status().is_empty() {
                        div { class: "muted", "data-testid": "coauth-status", "{coauth_status}" }
                    }
                    if !integration_plan_status().is_empty() {
                        pre { class: "muted", "data-testid": "production-auth-bridge-status", "{integration_plan_status}" }
                    }
                }
            }

            // Session state panel
            div { class: "event", "data-testid": "session-state",
                div { class: "event-head",
                    span { "Session" }
                    span { match session_state() {
                        SessionState::Disconnected => "disconnected",
                        SessionState::Connected => "connected",
                        SessionState::SoftLogout => "soft-logout",
                    }}
                }
                div { class: "muted",
                    "Session: access tokens are stored locally for this client. Re-authenticate after expiry or if the device state changes."
                }
                if !session_info().is_empty() {
                    div { class: "muted", "data-testid": "session-info", "{session_info}" }
                }
                if !token_expiry().is_empty() {
                    div { class: "muted", "data-testid": "token-expiry", "Expires: {token_expiry}" }
                }
                div { class: "muted",
                    if token().is_empty() { "No active token" } else { "Token active" }
                }
            }

            // Token refresh
            div { class: "event", "data-testid": "token-refresh",
                div { class: "event-head", span { "Token" } span { "refresh" } }
                div { class: "muted",
                    "Status: refresh keeps an authenticated session alive without changing the account DID or device binding."
                }
                div { class: "actions",
                    button {
                        class: "secondary",
                        "data-testid": "refresh-token-button",
                        onclick: {
                            move |_| {
                                let now = Utc::now().timestamp() as f64;
                                if let Err(cooldown) = rate_limiter.read().check("refresh", now) {
                                    refresh_status.set(format!("Rate limited. Try again in {cooldown:.0}s"));
                                    return;
                                }
                                let base = base_url();
                                let current_token = token();
                                spawn(async move {
                                    match ContrixApi::new(&base) {
                                        Ok(api) => match api.token_refresh(&current_token).await {
                                            Ok(resp) => {
                                                rate_limiter.write().clear("refresh");
                                                token.set(resp.access_token.clone());
                                                refresh_status.set(format!(
                                                    "Refreshed; expires={}",
                                                    resp.expires_at
                                                ));
                                                token_expiry.set(resp.expires_at);
                                            }
                                            Err(e) => {
                                                let now = Utc::now().timestamp() as f64;
                                                rate_limiter.write().record_failure("refresh", now);
                                                refresh_status.set(format!("Refresh failed: {e}"))
                                            }
                                        },
                                        Err(e) => refresh_status.set(format!("Invalid URL: {e}")),
                                    }
                                });
                            }
                        },
                        "Refresh Token"
                    }
                }
                if !refresh_status().is_empty() {
                    div { class: "muted", "data-testid": "refresh-status", "{refresh_status}" }
                }
            }

            // Soft-logout recovery
            if session_state() == SessionState::SoftLogout {
                div { class: "event", "data-testid": "soft-logout-recovery",
                    div { class: "event-head", span { "Recovery" } span { "soft-logout" } }
                    div { class: "muted", "Your session has expired. Log in again to continue." }
                    div { class: "actions",
                        button {
                            class: "primary",
                            "data-testid": "re-login-button",
                            onclick: move |_| session_state.set(SessionState::Disconnected),
                            "Re-Login"
                        }
                    }
                }
            }
        }
    }
}
