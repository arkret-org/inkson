use chrono::Utc;
use cokret_sdk::http_client::{Auth, ClientBuilder};
use dioxus::prelude::*;
use garth::{LoginKind, OidcLogin, SessionEngine, SessionGrantState};

use crate::account_auth::{
    AuthorityResolver, build_oidc_authorize_scaffold, build_persisted_oidc_scaffold,
    capture_current_browser_callback_url, clear_persisted_oidc_scaffold,
    extract_authorization_code_from_callback, extract_error_description_from_callback,
    extract_error_from_callback, extract_state_from_callback, fetch_oidc_discovery,
    oidc_request_canonical_digest, open_oidc_authorize_url, persist_oidc_scaffold,
    restore_oidc_scaffold,
};
use crate::api::CokretApi;
use crate::components::UiIcon;
use crate::config::{
    LocalConfigStore, normalize_device_id, normalize_server_url, principal_server_options_for,
    same_server_url,
};
use crate::local_state::{LocalStateStore, PersistedSessionGrant};
use crate::ui::button::{Button, ButtonVariant};
use crate::ui::card::Card;
use crate::ui::input::Input;
use crate::ui::label::Label;
use crate::views::helpers::{display_name_for_did, persist_config, short_protocol_id};

#[derive(Clone, Debug)]
struct CompletedLogin {
    principal_server_url: String,
    actor: String,
    personal_handle: Option<String>,
    device_id: String,
    dpop_device_key: crate::local_state::DpopDeviceKeyRecord,
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
    /// Connection-lifecycle label owned by the app shell; the only write
    /// here is the post-sign-in "Online" transition.
    connection_status: Signal<String>,
    config_store: Signal<LocalConfigStore>,
    state_store: Signal<LocalStateStore>,
    account_primary_handle: Signal<String>,
    personal_handles: Signal<Vec<String>>,
    personal_handles_status: Signal<String>,
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
    // Whether the styled Principal Server preset list is expanded. Inkson is a
    // neutral client: the field is a free-text URL input that the user can edit
    // to point at ANY server, with this custom-styled dropdown offering the
    // configured presets (and the current value) as one-click choices.
    let mut server_menu_open = use_signal(|| false);
    // Principal Server presets come from local config, with the current value
    // and the local development default merged in.
    let principal_server_options =
        principal_server_options_for(&base_url(), &config_store.read().load().principal_servers);

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
                let actor_changed = {
                    let previous = account_did();
                    !previous.trim().is_empty() && previous != completed.actor
                };
                let mut completed_dpop_error = None::<String>;
                {
                    let mut store = state_store_write.write();
                    // Adopt the signed-in actor as the active account. With
                    // per-account isolation this loads that account's own
                    // independent entry (its grant/cursor/projections/device
                    // key) — a previous identity's revoked grant or foreign
                    // cursor lives in a separate key and can never leak in.
                    // When a pre-DID `pending_login` is in flight this closes
                    // the root pending marker after the secure-store bootstrap
                    // device tuple has already been adopted for the resolved DID.
                    let switched = if store.pending_login().is_some() {
                        store.adopt_pending_login(&completed.actor)
                    } else {
                        store.adopt_account_scope(&completed.actor)
                    };
                    // Same actor but a different principal server: the cached
                    // projections/cursor are scoped to the old server and are
                    // meaningless here, so reset them too. The fresh grant for
                    // THIS server is persisted by `persist_completed_login_state`
                    // immediately below, so clearing here does not strand it.
                    if server_changed && !switched {
                        store.clear_account_scoped();
                        store.set_session_grant(None);
                    }
                    let secure_store = crate::secure_key_store::default_secure_key_store("inkson");
                    if let Err(error) = persist_completed_login_dpop_key(
                        &mut store,
                        secure_store.as_ref(),
                        &completed.actor,
                        &completed.device_id,
                        &completed.dpop_device_key,
                    ) {
                        tracing::warn!(%error, "persist completed-login DPoP key under account scope failed");
                        completed_dpop_error =
                            Some(format!("Could not persist the session DPoP key: {error}"));
                    }
                }
                if let Some(error) = completed_dpop_error {
                    auth_status.set(error);
                    is_busy.set(false);
                    return;
                }
                base_url.set(principal_server_url.clone());
                account_did.set(completed.actor.clone());
                let mut account_primary_handle = account_primary_handle;
                if server_changed || actor_changed {
                    account_primary_handle.set(String::new());
                    personal_handles.set(Vec::new());
                    personal_handles_status.set("Not published".to_owned());
                }
                if let Some(personal_handle) = completed.personal_handle.clone() {
                    account_primary_handle.set(personal_handle.clone());
                    let handles =
                        crate::app::merge_personal_handles(&personal_handles(), [personal_handle]);
                    personal_handles_status.set(crate::app::personal_handles_status_for(&handles));
                    personal_handles.set(handles);
                } else {
                    account_primary_handle.set(String::new());
                    if personal_handles().is_empty() {
                        personal_handles_status.set("Not published".to_owned());
                    }
                }
                device_id.set(completed.device_id.clone());
                token.set(completed.session_credential.clone());
                // Persist the resolved personal handle into THIS account's own
                // per-account entry (and register the account in the known-DID
                // selector index) so the re-login screen can label / list it by
                // handle, independent of which account is active later. Prefer
                // the freshly-resolved handle, fall back to the live signal.
                {
                    let resolved_handle = completed
                        .personal_handle
                        .clone()
                        .unwrap_or_else(|| account_primary_handle());
                    let mut store = state_store_write.write();
                    if !resolved_handle.trim().is_empty() {
                        store.set_primary_handle(&resolved_handle);
                    }
                    store.register_known_account(&completed.actor);
                }
                persist_config(
                    config_store,
                    principal_server_url,
                    completed.actor.clone(),
                    completed.device_id.clone(),
                    completed.session_credential.clone(),
                );
                persist_completed_login_state(state_store_write, completed.session_grant);
                connection_status.set("Online".to_owned());
                auth_status.set("Signed in".to_owned());
                on_login.call(());
            }
            Err(error) => auth_status.set(discard_failed_oidc_callback(error)),
        }
        is_busy.set(false);
    });

    // Account selection belongs to the Account Authority. Inkson chooses only
    // the Principal Server; it must not turn the locally persisted account DID
    // into a hidden account selection. Therefore an interactive OIDC sign-in
    // omits `principal_id`. When a signed-out account is locally known, reuse
    // its stable protocol device id so a hard re-login rotates only the
    // grant-binding key, not the E2EE device identity.
    let launch_sign_in = move || {
        let principal = base_url();
        let device = interactive_sign_in_device_id(&account_did(), &device_id());
        device_id.set(device.clone());
        let mut reset_state_store = state_store;
        is_busy.set(true);
        auth_status.set("Opening server sign-in...".to_owned());
        spawn(async move {
            #[cfg(target_arch = "wasm32")]
            if let Err(error) =
                crate::secure_key_store::ensure_wasm_secure_key_store_ready("inkson").await
            {
                tracing::warn!(%error, "secure store unavailable before sign-in");
                is_busy.set(false);
                auth_status.set(format!(
                    "Could not open browser secure storage for sign-in: {error}. Close other Inkson tabs and try again."
                ));
                return;
            }
            let secure_store = crate::secure_key_store::default_secure_key_store("inkson");
            if let Err(error) =
                crate::secure_key_store::reset_device_seed_scope_for_signin(secure_store.as_ref())
            {
                tracing::warn!(%error, "reset device seed scope for sign-in failed");
            }
            // Drop the cached DPoP record so the grant-binding key is rebuilt from
            // the freshly-rotated grant-binding seed.
            reset_state_store.write().set_dpop_device_key(None);
            // Pre-DID: record the sign-in device id as the pending login so the
            // bootstrap wrap_seed / secrets land under the
            // `pending.<device_id>` namespace until the principal DID resolves
            // and `adopt_pending_login` re-homes them.
            reset_state_store
                .write()
                .begin_pending_login(device.trim(), None);
            // Persist the pending device_id under the bootstrap scope. On a
            // returning account this should match the account-scoped device id;
            // on first sign-in it becomes the account-scoped protocol device.
            if let Err(error) = crate::secure_key_store::store_device_id_scoped(
                secure_store.as_ref(),
                None,
                device.trim(),
            ) {
                tracing::warn!(%error, "persist bootstrap device_id for sign-in failed");
            }
            match start_oidc_strand(&principal, device.trim(), "", "").await {
                Ok(()) => {}
                Err(error) => {
                    is_busy.set(false);
                    auth_status.set(error);
                }
            }
        });
    };

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
                // Inkson is a neutral client: this is a free-text Principal
                // Server URL the user can edit to point at ANY server. The
                // custom-styled dropdown below offers the configured presets
                // (and the current value) as one-click choices — a styled
                // replacement for the native `<datalist>` (whose popup is
                // unstyleable). Selecting a preset only fills the text field;
                // the user is free to keep typing a custom address.
                div { class: "auth-combobox", "data-testid": "login-server-combobox",
                    Input {
                        id: "login-server-url-input",
                        "data-testid": "login-server-url",
                        "aria-label": "Principal server URL",
                        autocomplete: "off",
                        value: "{base_url}",
                        disabled: is_busy(),
                        oninput: move |event: FormEvent| {
                            let value = normalize_server_url(&event.value());
                            base_url.set(value.clone());
                            token.set(String::new());
                            persist_config(config_store, value, account_did(), device_id(), String::new());
                        },
                    }
                    button {
                        r#type: "button",
                        class: "auth-combobox-toggle",
                        "data-testid": "login-server-options-toggle",
                        "aria-label": "Show preset servers",
                        "aria-expanded": if server_menu_open() { "true" } else { "false" },
                        disabled: is_busy(),
                        onclick: move |_| server_menu_open.toggle(),
                        if server_menu_open() {
                            UiIcon { name: "chevron-up" }
                        } else {
                            UiIcon { name: "chevron-down" }
                        }
                    }
                    if server_menu_open() {
                        div {
                            class: "auth-combobox-menu",
                            "data-testid": "login-server-options",
                            role: "listbox",
                            "aria-label": "Preset servers",
                            for option_url in principal_server_options.iter() {
                                button {
                                    key: "{option_url}",
                                    r#type: "button",
                                    class: if same_server_url(option_url, &base_url()) {
                                        "auth-combobox-option active"
                                    } else {
                                        "auth-combobox-option"
                                    },
                                    "data-testid": "login-server-option",
                                    role: "option",
                                    "aria-selected": if same_server_url(option_url, &base_url()) { "true" } else { "false" },
                                    onclick: {
                                        let option_url = option_url.clone();
                                        move |_| {
                                            let value = normalize_server_url(&option_url);
                                            base_url.set(value.clone());
                                            token.set(String::new());
                                            persist_config(
                                                config_store,
                                                value,
                                                account_did(),
                                                device_id(),
                                                String::new(),
                                            );
                                            server_menu_open.set(false);
                                        }
                                    },
                                    span { class: "auth-combobox-option-url mono", "{option_url}" }
                                    if same_server_url(option_url, &base_url()) {
                                        span { class: "auth-combobox-option-check", "✓" }
                                    }
                                }
                            }
                        }
                    }
                }

                // A single sign-in action. Account selection is delegated to the
                // Account Authority's OIDC screen — inkson only chooses the
                // Principal Server and does not assert a local account DID.
                Button {
                    variant: ButtonVariant::Primary,
                    class: "auth-primary",
                    "data-testid": "start-server-login-button",
                    disabled: is_busy(),
                    onclick: move |_| {
                        let mut go = launch_sign_in;
                        go();
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
                    let actor_label = display_name_for_did(&store_snapshot, &actor_value);
                    drop(store_snapshot);
                    let show_session_diagnostics =
                        session_status != "signed-out" || !jkt_display.is_empty();
                    let device_label = short_protocol_id(&device_value);
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

fn restore_oidc_callback_device_seed_scope(device_id: &str) {
    crate::secure_key_store::set_active_device_seed_scope(None);
    crate::secure_key_store::set_pending_login_device_id(Some(device_id));
}

fn interactive_sign_in_device_id(persisted_actor: &str, persisted_device: &str) -> String {
    let actor = persisted_actor.trim();
    let device = persisted_device.trim();
    if !actor.is_empty() && crate::config::is_valid_device_id(device) {
        device.to_owned()
    } else {
        crate::config::new_device_id()
    }
}

fn persist_completed_login_dpop_key(
    store: &mut LocalStateStore,
    secure_store: &dyn crate::secure_key_store::SecureKeyStore,
    actor: &str,
    device_id: &str,
    record: &crate::local_state::DpopDeviceKeyRecord,
) -> Result<(), String> {
    crate::secure_key_store::set_active_device_seed_scope(Some(actor));
    crate::secure_key_store::store_grant_binding_seed_b64url(secure_store, &record.seed_b64)
        .map_err(|error| format!("store grant-binding seed: {error}"))?;
    crate::secure_key_store::store_device_id_scoped(secure_store, Some(actor), device_id)
        .map_err(|error| format!("store account-scoped device id: {error}"))?;
    store
        .set_dpop_device_key_with_secure_store(Some(record.clone()), secure_store)
        .map_err(|error| format!("store account-scoped DPoP key: {error}"))?;
    let material = crate::secure_key_store::ensure_signing_seed_scoped(secure_store, Some(actor))
        .map_err(|error| format!("ensure account device signing seed: {error}"))?;
    crate::event_signer::activate_device_signer_from_seed_for_device(
        material.seed,
        Some(secure_store),
        Some(device_id),
    )
    .map_err(|error| format!("activate account device signer: {error}"))?;
    Ok(())
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

fn discard_failed_oidc_callback(error: String) -> String {
    if let Err(clear_error) = clear_persisted_oidc_scaffold() {
        tracing::warn!(%clear_error, "clear failed OIDC scaffold failed");
    }
    // Principal-binding mismatch gets specific guidance: the raw wire reason
    // ("proof_invalid; principal binding mismatch: …") tells the user nothing
    // actionable — the actual fix is signing in with the intended account.
    if error.contains("principal binding mismatch") {
        return "The account signed in at the Account Authority does not match this local device session. Start sign-in again with the intended account."
            .to_owned();
    }
    format!("{error} Start sign-in again.")
}

pub(crate) async fn start_oidc_strand(
    principal_server_url: &str,
    device_id: &str,
    login_hint: &str,
    principal_actor_id: &str,
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
    let discovery = fetch_oidc_discovery(&discovery_url)
        .await
        .map_err(|error| format!("OIDC discovery failed: {error}"))?;
    let redirect_uri = crate::account_auth::current_oidc_redirect_uri();
    let bundle = build_oidc_authorize_scaffold(
        &discovery,
        &method,
        &redirect_uri,
        login_hint,
        device_id,
        &resolver.principal_audience,
    )
    .map_err(|error| format!("Sign-in URL preparation failed: {error}"))?;

    let scaffold = build_persisted_oidc_scaffold(
        &bundle,
        &resolver.gate_account_base,
        principal_server_url,
        principal_actor_id,
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
    let sdk_base_url =
        crate::session_refresh::sdk_base_url_from_gate_account_base(&gate_account_base)
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
    restore_oidc_callback_device_seed_scope(&device);
    #[cfg(target_arch = "wasm32")]
    crate::secure_key_store::ensure_wasm_secure_key_store_ready("inkson")
        .await
        .map_err(|error| format!("DPoP key store not ready: {error}"))?;
    let dpop_handle = {
        let mut store = state_store.write();
        let handle = crate::account_auth::grant_dpop::ensure_device_key(&mut store)
            .map_err(|error| format!("DPoP key failed: {error}"))?;
        crate::event_signer::bind_active_signer_device_id(&device)
            .map_err(|error| format!("Event signer device binding failed: {error}"))?;
        handle
    };
    if scaffold.issuer.trim().is_empty() {
        return Err("Sign-in state is missing the OIDC issuer.".to_owned());
    }
    // `principal_id` is optional for Account Authority session-grants. Inkson's
    // neutral interactive login leaves the scaffold actor hint blank (sent as
    // `None`), so the Account Authority derives the principal DID from the OIDC
    // subject and returns it in `SessionGrantOutcome.principal_id`. A non-empty
    // scaffold value is an explicit binding request and coauth must reject it if
    // it does not match the authenticated user.
    let principal_id = if actor_hint.trim().is_empty() {
        None
    } else {
        Some(
            cokret_sdk::Did::new(actor_hint.clone())
                .map_err(|error| format!("invalid principal_id DID: {error}"))?,
        )
    };
    let device_id = cokret_sdk::DeviceId::new(device.clone())
        .map_err(|error| format!("invalid device_id: {error}"))?;
    let request_canonical_digest = oidc_request_canonical_digest(
        &scaffold.issuer,
        &scaffold.client_id,
        &authorization_code,
        &returned_state,
    )
    .map_err(|error| format!("OIDC session-grant digest failed: {error}"))?;
    let http = ClientBuilder::new(sdk_base_url)
        .allow_insecure_localhost()
        .auth(Auth::Dpop(dpop_handle.sdk_dpop_proof_only_auth()))
        .build()
        .map_err(|error| format!("Build Account Authority session client failed: {error}"))?;
    let session_engine = SessionEngine::new(http);
    session_engine
        .login(
            LoginKind::Oidc(OidcLogin {
                principal_id,
                device_id: Some(device_id),
                requested_scope: Vec::new(),
                challenge: String::new(),
                request_canonical_digest,
                audience: scaffold.principal_audience.clone(),
                issuer: scaffold.issuer.clone(),
                client_id: scaffold.client_id.clone(),
                redirect_uri: scaffold.callback_uri.clone(),
                state: returned_state.clone(),
                nonce: scaffold.expected_nonce.clone(),
                authorization_code: authorization_code.clone(),
                code_verifier: scaffold.code_verifier.clone(),
            }),
            Utc::now(),
        )
        .await
        .map_err(|error| format!("Account Authority session-grant issue failed: {error}"))?;
    let session_grant = session_engine
        .current_state()
        .ok_or_else(|| "Account Authority session-grant issue did not yield state.".to_owned())?;
    let session_private_key_pem = dpop_handle
        .session_signing_key_pkcs8_pem()
        .map_err(|error| format!("export device session key: {error}"))?
        .to_string();
    let dpop_device_key = crate::account_auth::grant_dpop::dpop_device_key_record_from_seed(
        dpop_handle.seed_b64().as_str(),
    )
    .map_err(|error| format!("DPoP device key record failed: {error}"))?;
    let principal_target = principal_server_url;
    let principal = CokretApi::new(&principal_target)
        .map_err(|error| format!("Invalid principal server URL: {error}"))?;
    let actor = session_grant.principal_id.as_str().to_owned();
    if actor.trim().is_empty() {
        return Err("Account Authority did not return an account DID.".to_owned());
    }
    // ②(A+②): the held credential is the `ck.session.grant` itself; every
    // `/_cokret/self/*` request presents it as `Authorization: Bearer <grant>` +
    // a per-request `DPoP` proof bound to the grant's `cnf.jkt`. Verify the
    // credential up front by reading the account viewer through a grant+DPoP
    // client (api-conventions.md §3.3).
    let authed_principal = principal
        .clone()
        .with_bearer(session_grant.grant_jwt.clone())
        .with_dpop_device(dpop_handle.clone());
    let account =
        async { crate::account_api::account_me(&authed_principal.sdk_http_client()?).await }
            .await
            .map_err(|error| {
                format!("Principal server did not accept the session grant + DPoP: {error}")
            })?;
    let canonical_actor = if account.did.trim().is_empty() {
        actor
    } else {
        account.did
    };
    // The resolved principal is now known: re-home the bootstrap device seed
    // (the one bound to the session grant just issued above) under this
    // account's scope and clear the bootstrap entry, so a later sign-in for a
    // *different* account on this browser cannot inherit this account's device
    // key. Sets the active seed scope to this account for the rest of the
    // session.
    {
        let secure_store = crate::secure_key_store::default_secure_key_store("inkson");
        if let Err(error) = crate::secure_key_store::adopt_device_seed_scope_on_login(
            secure_store.as_ref(),
            &canonical_actor,
        ) {
            tracing::warn!(%error, "adopt account device seed scope on login failed");
        }
        // The grant just issued is authoritative for this browser session's
        // protocol device id. `adopt_device_seed_scope_on_login` may have
        // carried over an older bootstrap/pending id for a first-time account;
        // overwrite it immediately so the next secure-store bootstrap does not
        // bind the durable signer to a device id different from the bearer
        // grant's `urn:cokret:client:device:*` scope.
        if let Err(error) = crate::secure_key_store::store_device_id_scoped(
            secure_store.as_ref(),
            Some(&canonical_actor),
            &device,
        ) {
            tracing::warn!(%error, "persist account device id from session grant failed");
        }
    }
    let personal_handle = crate::app::personal_handle_from_account_handle(&account.handle);
    let _ = clear_persisted_oidc_scaffold();

    let resolved_device = device;
    // Persist the principal session grant as the live credential. The refresh
    // path keeps it fresh by rotating it (grant-binding DPoP proof → fresh grant) when
    // near expiry.
    let persisted_session_grant = persisted_session_grant_from_state(
        &session_grant,
        &session_private_key_pem,
        &principal_target,
        &canonical_actor,
        &resolved_device,
    );

    Ok(CompletedLogin {
        principal_server_url: principal_target,
        actor: canonical_actor,
        personal_handle,
        device_id: resolved_device,
        dpop_device_key,
        // The grant JWT is now the live credential carried in the `token` signal.
        session_credential: session_grant.grant_jwt.clone(),
        session_grant: Some(persisted_session_grant),
    })
}

fn persisted_session_grant_from_state(
    grant: &SessionGrantState,
    session_private_key_pem: &str,
    principal_server_url: &str,
    actor: &str,
    device_id: &str,
) -> PersistedSessionGrant {
    PersistedSessionGrant {
        grant_jwt: grant.grant_jwt.clone(),
        session_private_key_pem: session_private_key_pem.to_owned(),
        grant_id: grant.grant_id.as_str().to_owned(),
        audience: grant.audience.clone(),
        principal_id: actor.to_owned(),
        device_id: device_id.to_owned(),
        principal_server_url: principal_server_url.to_owned(),
        grant_expires_at: Some(grant.expires_at),
        stored_at: Utc::now(),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Mutex, MutexGuard, OnceLock};

    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;

    use super::*;

    fn seed_scope_test_lock() -> MutexGuard<'static, ()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
            .lock()
            .expect("seed scope test lock")
    }

    struct SeedScopeReset;

    impl Drop for SeedScopeReset {
        fn drop(&mut self) {
            crate::secure_key_store::set_active_device_seed_scope(None);
            crate::secure_key_store::set_pending_login_device_id(None);
            let _ = crate::event_signer::replace_active_signer(None);
        }
    }

    fn dpop_record_for_seed(seed: [u8; 32]) -> crate::local_state::DpopDeviceKeyRecord {
        crate::account_auth::grant_dpop::dpop_device_key_record_from_seed(
            &URL_SAFE_NO_PAD.encode(seed),
        )
        .expect("dpop record")
    }

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
    fn failed_callback_prompts_fresh_sign_in() {
        assert_eq!(
            discard_failed_oidc_callback("Account Authority session-grant issue failed".to_owned()),
            "Account Authority session-grant issue failed Start sign-in again."
        );
    }

    #[test]
    fn principal_binding_mismatch_gets_specific_login_guidance() {
        assert_eq!(
            discard_failed_oidc_callback(
                "Account Authority session-grant issue failed: reason_code=proof_invalid; principal binding mismatch: the request principal_id does not match the authenticated user".to_owned()
            ),
            "The account signed in at the Account Authority does not match this local device session. Start sign-in again with the intended account."
        );
    }

    #[test]
    fn oidc_callback_restores_bootstrap_device_seed_scope() {
        let _lock = seed_scope_test_lock();
        let _reset = SeedScopeReset;
        crate::secure_key_store::set_active_device_seed_scope(Some("did:web:old.example"));

        restore_oidc_callback_device_seed_scope("ck:device:01964137-0000-7000-8000-000000000001");

        assert_eq!(crate::secure_key_store::active_device_seed_scope(), None);
        assert_eq!(
            crate::secure_key_store::pending_login_device_id().as_deref(),
            Some("ck:device:01964137-0000-7000-8000-000000000001")
        );
    }

    #[test]
    fn interactive_sign_in_reuses_known_account_device_id() {
        let existing = "ck:device:01964137-0000-7000-8000-000000000001";
        assert_eq!(
            interactive_sign_in_device_id("did:web:alice.example", existing),
            existing
        );
        assert_ne!(
            interactive_sign_in_device_id("", existing),
            existing,
            "first login mints a fresh protocol device id"
        );
        assert_ne!(
            interactive_sign_in_device_id("did:web:alice.example", "not-a-device"),
            "not-a-device",
            "invalid persisted ids are never reused"
        );
    }

    #[test]
    fn completed_login_dpop_key_preserves_returning_account_key_material() {
        let _lock = seed_scope_test_lock();
        let _reset = SeedScopeReset;
        let mut store = crate::local_state::isolated_store_for_tests("completed-login-dpop-key");
        let secure_store = crate::secure_key_store::MemorySecureKeyStore::default();
        let actor = "did:web:alice.example";
        let device = "ck:device:01964137-0000-7000-8000-000000000001";
        let old_seed = [3_u8; 32];
        let new_record = dpop_record_for_seed([7_u8; 32]);

        let _ = crate::event_signer::replace_active_signer(None);
        crate::secure_key_store::store_signing_seed_scoped(&secure_store, Some(actor), &old_seed)
            .expect("old account seed");

        persist_completed_login_dpop_key(&mut store, &secure_store, actor, device, &new_record)
            .expect("persist completed login dpop");

        let loaded_seed =
            crate::secure_key_store::load_signing_seed_scoped(&secure_store, Some(actor))
                .expect("load account seed")
                .expect("account seed");
        assert_eq!(loaded_seed.seed, old_seed);
        let grant_binding = crate::secure_key_store::load_grant_binding_seed(&secure_store)
            .expect("load grant-binding seed")
            .expect("grant-binding seed");
        assert_eq!(grant_binding.seed, [7_u8; 32]);
        let loaded_record = store
            .load_dpop_device_key_with_secure_store(&secure_store)
            .expect("load account dpop")
            .expect("account dpop");
        assert_eq!(loaded_record.jkt, new_record.jkt);
        let public_record = store.dpop_device_key().expect("public dpop");
        assert_eq!(public_record.jkt, new_record.jkt);
        assert!(public_record.seed_b64.is_empty());
    }

    #[test]
    fn persisted_session_grant_from_login_carries_refresh_material() {
        let device_id = "ck:device:01964137-0000-7000-8000-000000000001";
        let grant_id = "ck:grant:01964137-0000-7000-8000-000000000001";
        let grant = SessionGrantState {
            principal_id: cokret_sdk::Did::new("did:web:alice.example".to_owned()).unwrap(),
            device_id: Some(cokret_sdk::DeviceId::new(device_id.to_owned()).unwrap()),
            grant_id: cokret_sdk::GrantId::new(grant_id.to_owned()).unwrap(),
            grant_jwt: "grant.jwt".to_owned(),
            expires_at: "2026-05-29T12:00:00Z".parse().unwrap(),
            audience: "https://local.host/api".to_owned(),
            granted_scope: vec!["urn:cokret:principal-server:session.bind".to_owned()],
            session_public_key: "public-key".to_owned(),
            dpop_jkt: Some("dpop-jkt".to_owned()),
        };
        let persisted = persisted_session_grant_from_state(
            &grant,
            "private-key-pem",
            "https://local.host",
            "did:web:alice.example",
            device_id,
        );

        assert_eq!(persisted.grant_jwt, "grant.jwt");
        assert_eq!(persisted.session_private_key_pem, "private-key-pem");
        assert_eq!(persisted.grant_id, grant_id);
        assert_eq!(persisted.audience, "https://local.host/api");
        assert_eq!(persisted.principal_id, "did:web:alice.example");
        assert_eq!(persisted.device_id, device_id);
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
