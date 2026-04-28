use dioxus::prelude::*;

use crate::{
    api::ContrixApi,
    config::LocalConfigStore,
    views::helpers::persist_config,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SessionState {
    Disconnected,
    Connected,
    SoftLogout,
    TokenExpired,
}

#[component]
pub fn LoginPanel(
    base_url: Signal<String>,
    account_did: Signal<String>,
    device_id: Signal<String>,
    token: Signal<String>,
    status: Signal<String>,
    config_store: Signal<LocalConfigStore>,
    on_login: EventHandler<()>,
) -> Element {
    let mut health_status = use_signal(|| String::new());
    let mut did_validation = use_signal(|| String::new());
    let mut session_state = use_signal(|| SessionState::Disconnected);
    let mut session_info = use_signal(|| String::new());
    let mut token_expiry = use_signal(|| String::new());
    let mut passkey_status = use_signal(|| String::new());
    let mut oidc_status = use_signal(|| String::new());
    let mut dev_login_status = use_signal(|| String::new());
    let mut refresh_status = use_signal(|| String::new());

    rsx! {
        div { class: "timeline", "data-testid": "login-panel",
            // Connection test
            div { class: "event", "data-testid": "connection-test",
                div { class: "event-head", span { "Server" } span { "connection test" } }
                div { class: "workflow-form",
                    label { "Server URL" }
                    input {
                        "data-testid": "login-server-url",
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
                div { class: "actions",
                    button {
                        class: "primary",
                        "data-testid": "passkey-login-button",
                        onclick: {
                            move |_| {
                                let base = base_url();
                                let did = account_did();
                                spawn(async move {
                                    match ContrixApi::new(&base) {
                                        Ok(api) => match api.passkey_challenge(&did).await {
                                            Ok(challenge) => passkey_status.set(format!(
                                                "Challenge received: rp={}, expires={}",
                                                challenge.rp_id, challenge.expires_at
                                            )),
                                            Err(e) => passkey_status.set(format!("Passkey challenge failed: {e}")),
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
                                let base = base_url();
                                spawn(async move {
                                    match ContrixApi::new(&base) {
                                        Ok(api) => match api.oidc_authorize("default", "http://localhost:3000/callback").await {
                                            Ok(resp) => oidc_status.set(format!(
                                                "Redirect: {} (state: {})",
                                                resp.redirect_url, resp.state
                                            )),
                                            Err(e) => oidc_status.set(format!("OIDC failed: {e}")),
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
                                                Err(e) => dev_login_status.set(format!("Dev login failed: {e}")),
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

            // Session state panel
            div { class: "event", "data-testid": "session-state",
                div { class: "event-head",
                    span { "Session" }
                    span { match session_state() {
                        SessionState::Disconnected => "disconnected",
                        SessionState::Connected => "connected",
                        SessionState::SoftLogout => "soft-logout",
                        SessionState::TokenExpired => "expired",
                    }}
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
                div { class: "actions",
                    button {
                        class: "secondary",
                        "data-testid": "refresh-token-button",
                        onclick: {
                            move |_| {
                                let base = base_url();
                                let current_token = token();
                                spawn(async move {
                                    match ContrixApi::new(&base) {
                                        Ok(api) => match api.token_refresh(&current_token).await {
                                            Ok(resp) => {
                                                token.set(resp.access_token.clone());
                                                refresh_status.set(format!(
                                                    "Refreshed; expires={}",
                                                    resp.expires_at
                                                ));
                                                token_expiry.set(resp.expires_at);
                                            }
                                            Err(e) => refresh_status.set(format!("Refresh failed: {e}")),
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
