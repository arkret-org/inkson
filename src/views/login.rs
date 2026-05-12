use dioxus::prelude::*;
use dioxus_router::Link;

use crate::{
    api::ContrixApi,
    coauth::{
        CoauthApi, build_oidc_code_exchange_plan, build_oidc_scaffold_bundle,
        capture_current_browser_callback_url, clear_persisted_oidc_scaffold,
        extract_authorization_code_from_callback, extract_error_description_from_callback,
        extract_error_from_callback, extract_state_from_callback, open_oidc_authorize_url,
        persist_oidc_scaffold, restore_oidc_scaffold,
    },
    config::LocalConfigStore,
    routes::Route,
    views::helpers::persist_config,
};

#[derive(Clone, Debug)]
struct CompletedLogin {
    principal_server_url: String,
    actor: String,
    device_id: String,
    access_token: String,
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
    let mut login_hint = use_signal(move || account_did());
    let mut auth_status = use_signal(|| {
        if auto_capture_callback {
            "Completing sign in...".to_owned()
        } else {
            String::new()
        }
    });
    let mut is_busy = use_signal(|| auto_capture_callback);
    let mut callback_started = use_signal(|| false);

    use_future(move || async move {
        if !auto_capture_callback || callback_started() {
            return;
        }
        callback_started.set(true);
        is_busy.set(true);

        let result = finish_oidc_callback(device_id()).await;
        match result {
            Ok(completed) => {
                base_url.set(completed.principal_server_url.clone());
                account_did.set(completed.actor.clone());
                device_id.set(completed.device_id.clone());
                token.set(completed.access_token.clone());
                persist_config(
                    config_store,
                    completed.principal_server_url,
                    completed.actor,
                    completed.device_id,
                    completed.access_token,
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
                        let value = event.value();
                        base_url.set(value.clone());
                        token.set(String::new());
                        persist_config(config_store, value, account_did(), device_id(), String::new());
                    },
                }

                label { "Account" }
                input {
                    "data-testid": "login-account-hint",
                    "aria-label": "Account",
                    placeholder: "Email or DID",
                    value: "{login_hint}",
                    disabled: is_busy(),
                    oninput: move |event| {
                        let value = event.value();
                        login_hint.set(value.clone());
                        account_did.set(value);
                    },
                }

                button {
                    class: "primary auth-primary",
                    "data-testid": "start-server-login-button",
                    disabled: is_busy(),
                    onclick: move |_| {
                        let principal = base_url();
                        let actor = login_hint();
                        let device = device_id();
                        is_busy.set(true);
                        auth_status.set("Opening server sign-in...".to_owned());
                        spawn(async move {
                            match start_oidc_flow(&principal, actor.trim(), device.trim(), false).await {
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

                Link {
                    class: "secondary auth-secondary",
                    "data-testid": "create-account-link",
                    to: Route::Register,
                    "Create account"
                }

                Link {
                    class: "secondary auth-secondary",
                    "data-testid": "forgot-account-link",
                    to: Route::Recovery,
                    "Lost password or account"
                }

                if !auth_status().is_empty() {
                    div { class: "auth-status", "data-testid": "auth-status", role: "status", "{auth_status}" }
                }
            }
        }
    }
}

pub(crate) async fn start_oidc_flow(
    principal_server_url: &str,
    login_hint: &str,
    device_id: &str,
    signup: bool,
) -> Result<(), String> {
    let coauth = CoauthApi::new(principal_server_url)
        .map_err(|error| format!("Invalid server URL: {error}"))?;
    let topology = coauth
        .inspect_topology()
        .await
        .map_err(|error| format!("Server sign-in metadata failed: {error}"))?;
    let mut bundle =
        build_oidc_scaffold_bundle(&topology, principal_server_url, login_hint, device_id)
            .map_err(|error| format!("Sign-in URL preparation failed: {error}"))?;

    if signup {
        bundle.authorize_url = signup_authorize_url(&bundle.authorize_url)
            .map_err(|error| format!("Registration URL preparation failed: {error}"))?;
    }

    persist_oidc_scaffold(
        &bundle,
        principal_server_url,
        principal_server_url,
        login_hint,
        device_id,
    )
    .map_err(|error| format!("Could not save sign-in state: {error}"))?;
    open_oidc_authorize_url(&bundle.authorize_url)
        .map_err(|error| format!("Could not open server sign-in: {error}"))
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

    let grant = login
        .session_grant
        .as_ref()
        .ok_or_else(|| "Server sign-in did not return a session grant.".to_owned())?;
    let actor = login
        .viewer
        .as_ref()
        .map(|viewer| viewer.did.clone())
        .filter(|value| !value.trim().is_empty())
        .or_else(|| {
            (!scaffold.principal_actor_did.trim().is_empty())
                .then(|| scaffold.principal_actor_did.clone())
        })
        .ok_or_else(|| "Server sign-in did not return a principal DID.".to_owned())?;
    let principal_target = grant
        .principal_server
        .as_ref()
        .map(|server| server.endpoint.clone())
        .filter(|value| !value.trim().is_empty())
        .unwrap_or(principal_server_url);
    let principal = ContrixApi::new(&principal_target)
        .map_err(|error| format!("Invalid principal server URL: {error}"))?;
    let bridge = principal
        .auth_bridge_describe()
        .await
        .map_err(|error| format!("Principal auth bridge describe failed: {error}"))?;
    let session = principal
        .exchange_session_grant_at(
            &bridge.auth.session_grant_exchange_path,
            &grant.grant_jwt,
            &actor,
            &device,
        )
        .await
        .map_err(|error| format!("Principal session exchange failed: {error}"))?;
    let _ = clear_persisted_oidc_scaffold();

    Ok(CompletedLogin {
        principal_server_url: principal_target,
        actor: session.actor,
        device_id: session.device_id,
        access_token: session.access_token,
    })
}

fn signup_authorize_url(authorize_url: &str) -> anyhow::Result<String> {
    let mut url = url::Url::parse(authorize_url)?;
    if !url.query_pairs().any(|(key, _)| key == "screen_hint") {
        url.query_pairs_mut().append_pair("screen_hint", "signup");
    }
    Ok(url.to_string())
}
