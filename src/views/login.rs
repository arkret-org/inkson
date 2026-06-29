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
use crate::config::{
    LocalConfigStore, normalize_device_id, normalize_server_url, principal_server_options_for,
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
    // Principal Server presets come from local config, with the current value
    // and the local development default merged in for the datalist.
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
                {
                    let mut store = state_store_write.write();
                    // Adopt the signed-in actor as the active account. With
                    // per-account isolation this loads that account's own
                    // independent entry (its grant/cursor/projections/device
                    // key) — a previous identity's revoked grant or foreign
                    // cursor lives in a separate key and can never leak in.
                    // When a pre-DID `pending_login` is in flight this also
                    // discards-or-migrates the pending device material based on
                    // whether the resolved account is returning or new.
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
                    // Re-home the DPoP device-key record under the now-active
                    // account scope. A returning account may already have an
                    // older account-scoped DPoP record; ensure_device_key repairs
                    // that stale record from the just-adopted signing seed, whose
                    // jkt is the one bound into the newly-issued grant.
                    if let Err(error) = crate::auth_dpop::ensure_device_key(&mut store) {
                        tracing::warn!(%error, "re-home DPoP device key under account scope failed");
                    }
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
                status.set("Online".to_owned());
                auth_status.set("Signed in".to_owned());
                on_login.call(());
            }
            Err(error) => auth_status.set(discard_failed_oidc_callback(error)),
        }
        is_busy.set(false);
    });

    // Account selection belongs to the Account Authority. Yougen chooses the
    // Principal Server and either re-authenticates a returning account on its
    // OWN stable device (`reuse = true`) or starts a fresh pending login that
    // mints a brand-new device for a first/other account (`reuse = false`); the
    // callback adopts the DID returned by coauth as the authoritative account.
    //
    // Why the reuse branch exists: a `device_id` MUST be stable across
    // re-authentication (crypto-media/device-lifecycle.md §4 — "每个设备 MUST 有
    // 稳定 device_id"; §3.2 — a per-token/per-session device identity "会让该值在
    // 每次 token 轮换时漂移，静默破坏所有按 (principal, device) 绑定的不变量").
    // Minting a fresh device on every sign-in churns the protocol device_id, so
    // each re-login publishes a new MLS KeyPackage under a new device and strands
    // the to-device MLS Welcome addressed to the prior device — exactly the
    // "Waiting for a Welcome message" dead-end for an invited member who simply
    // signed in again.
    let launch_sign_in = move |reuse: bool| {
        let principal = base_url();
        // Reuse: keep this account's persisted stable device_id + device key.
        // Fresh: mint a brand-new device and forward no actor hint so the
        // callback adopts whatever account the OIDC flow resolves to.
        let (device, actor_hint) = if reuse {
            (device_id(), account_did())
        } else {
            (crate::config::new_device_id(), String::new())
        };
        device_id.set(device.clone());
        let mut reset_state_store = state_store;
        is_busy.set(true);
        auth_status.set("Opening server sign-in...".to_owned());
        spawn(async move {
            #[cfg(target_arch = "wasm32")]
            let _ = crate::secure_key_store::ensure_wasm_secure_key_store_ready("yougen").await;
            if reuse {
                // Pin the active device-seed scope to the returning account so
                // `ensure_device_key` (in `finish_oidc_callback`) loads that
                // account's existing device key — the same `cnf.jkt` it has
                // always used — instead of minting a bootstrap key. No
                // `begin_pending_login`: the device already belongs to this
                // account, so there is nothing to re-home, and
                // `adopt_device_seed_scope_on_login` finds no bootstrap seed to
                // overwrite the stable one with.
                let scope = actor_hint.trim();
                crate::secure_key_store::set_active_device_seed_scope(
                    (!scope.is_empty()).then_some(scope),
                );
            } else {
                let secure_store = crate::secure_key_store::default_secure_key_store("yougen");
                if let Err(error) = crate::secure_key_store::reset_device_seed_scope_for_signin(
                    secure_store.as_ref(),
                ) {
                    tracing::warn!(%error, "reset device seed scope for sign-in failed");
                }
                // Drop the cached DPoP record so the device key is rebuilt from
                // the freshly-scoped bootstrap seed.
                reset_state_store.write().set_dpop_device_key(None);
                // Pre-DID: record the freshly-minted device id as the pending
                // login so the bootstrap wrap_seed / secrets land under the
                // `pending.<device_id>` namespace until the principal DID
                // resolves and `adopt_pending_login` re-homes them.
                reset_state_store
                    .write()
                    .begin_pending_login(device.trim(), None);
                // Persist the freshly-minted device_id under the bootstrap scope,
                // paired with the bootstrap signing seed, so
                // `adopt_device_seed_scope_on_login` re-homes BOTH under the
                // account scope once the principal DID resolves. This is what
                // keeps the device_id stable across later reloads (it is then
                // recovered from the secure store, not re-minted from a phantom
                // config blob) and matches the MLS KeyPackage published this
                // sign-in.
                if let Err(error) = crate::secure_key_store::store_device_id_scoped(
                    secure_store.as_ref(),
                    None,
                    device.trim(),
                ) {
                    tracing::warn!(%error, "persist bootstrap device_id for sign-in failed");
                }
            }
            match start_oidc_strand(&principal, device.trim(), "", actor_hint.trim()).await {
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
                Input {
                    id: "login-server-url-input",
                    "data-testid": "login-server-url",
                    "aria-label": "Principal server URL",
                    "list": "login-principal-server-options",
                    autocomplete: "url",
                    value: "{base_url}",
                    disabled: is_busy(),
                    oninput: move |event: FormEvent| {
                        let value = normalize_server_url(&event.value());
                        base_url.set(value.clone());
                        token.set(String::new());
                        persist_config(config_store, value, account_did(), device_id(), String::new());
                    },
                }
                datalist {
                    id: "login-principal-server-options",
                    "data-testid": "login-principal-server-options",
                    for option_url in principal_server_options.iter() {
                        option {
                            key: "{option_url}",
                            value: "{option_url}",
                            "{option_url}"
                        }
                    }
                }

                {
                    // A returning account is one already persisted on this
                    // browser: its DID is known AND it carries a valid stable
                    // `device_id`. Its primary action re-authenticates on that
                    // SAME device (reuse = true) so the protocol device_id never
                    // drifts; an explicit secondary action signs a different /
                    // first account in on a fresh device (reuse = false).
                    let returning_actor = account_did();
                    let returning_device = device_id();
                    let has_returning_account = returning_account_can_reuse_device(
                        &returning_actor,
                        &returning_device,
                    );
                    let returning_label = if has_returning_account {
                        display_name_for_did(&state_store_write.read(), &returning_actor)
                    } else {
                        String::new()
                    };
                    rsx! {
                        if has_returning_account {
                            Button {
                                variant: ButtonVariant::Primary,
                                class: "auth-primary",
                                "data-testid": "start-server-login-button",
                                disabled: is_busy(),
                                onclick: move |_| { let mut go = launch_sign_in; go(true); },
                                if is_busy() {
                                    "Working..."
                                } else {
                                    "Continue as {returning_label}"
                                }
                            }
                            Button {
                                variant: ButtonVariant::Ghost,
                                class: "ghost",
                                "data-testid": "use-different-account-button",
                                disabled: is_busy(),
                                onclick: move |_| { let mut go = launch_sign_in; go(false); },
                                "Use a different account"
                            }
                        } else {
                            Button {
                                variant: ButtonVariant::Primary,
                                class: "auth-primary",
                                "data-testid": "start-server-login-button",
                                disabled: is_busy(),
                                onclick: move |_| { let mut go = launch_sign_in; go(false); },
                                if is_busy() { "Working..." } else { "Continue" }
                            }
                        }
                    }
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

/// Whether a sign-in for a known/returning account on this browser may
/// re-authenticate on that account's OWN persisted device, instead of minting a
/// fresh one. Both halves of the stable identity must be present: a non-empty
/// account DID AND a syntactically valid `device_id` (`ck:device:<uuid>`). When
/// either is missing the browser has no stable device to reuse, so the sign-in
/// MUST take the fresh path. Reusing keeps the protocol `device_id` stable
/// across re-authentication, which is what keeps to-device MLS Welcomes routable
/// (crypto-media/device-lifecycle.md §4).
fn returning_account_can_reuse_device(account_did: &str, device_id: &str) -> bool {
    !account_did.trim().is_empty() && crate::config::is_valid_device_id(device_id.trim())
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

fn discard_failed_oidc_callback(error: String) -> String {
    if let Err(clear_error) = clear_persisted_oidc_scaffold() {
        tracing::warn!(%clear_error, "clear failed OIDC scaffold failed");
    }
    if error.contains("principal binding mismatch") {
        return "The account signed in at the Account Authority does not match the selected account. Use a different account, or sign in to the selected account again.".to_owned();
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
    let discovery = CoauthApi::fetch_oidc_discovery(&discovery_url)
        .await
        .map_err(|error| format!("OIDC discovery failed: {error}"))?;
    let redirect_uri = crate::coauth::current_oidc_redirect_uri();
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
    #[cfg(target_arch = "wasm32")]
    crate::secure_key_store::ensure_wasm_secure_key_store_ready("yougen")
        .await
        .map_err(|error| format!("DPoP key store not ready: {error}"))?;
    let (issue_dpop, dpop_handle) = {
        let mut store = state_store.write();
        let handle = crate::auth_dpop::ensure_device_key(&mut store)
            .map_err(|error| format!("DPoP key failed: {error}"))?;
        crate::event_signer::bind_active_signer_device_id(&device)
            .map_err(|error| format!("Event signer device binding failed: {error}"))?;
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
    // ②(A+②): the held credential is the `ck.session.grant` itself; every
    // `/_cokret/self/*` request presents it as `Authorization: Bearer <grant>` +
    // a per-request `DPoP` proof bound to the grant's `cnf.jkt`. Verify the
    // credential up front by reading the account viewer through a grant+DPoP
    // client (api-conventions.md §3.3).
    let authed_principal = principal
        .clone()
        .with_bearer(session_grant.grant_jwt.clone())
        .with_dpop_device(dpop_handle.clone());
    let account = authed_principal.account_me().await.map_err(|error| {
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
        let secure_store = crate::secure_key_store::default_secure_key_store("yougen");
        if let Err(error) = crate::secure_key_store::adopt_device_seed_scope_on_login(
            secure_store.as_ref(),
            &canonical_actor,
        ) {
            tracing::warn!(%error, "adopt account device seed scope on login failed");
        }
    }
    let personal_handle = crate::app::personal_handle_from_account_handle(&account.handle);
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
        personal_handle,
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
/// are top-level outcome fields (mirroring `SessionGrantRefreshOutcome`);
/// `scope_details` is the agent-only overlay and MUST be absent for human grants.
fn session_grant_info_from_outcome(
    outcome: &cokret_sdk::SessionGrantOutcome,
    dpop_handle: &crate::auth_dpop::DpopHandle,
) -> Result<CoauthSessionGrantInfo, String> {
    let grant_id = outcome
        .grant_id
        .as_ref()
        .map(|value| value.as_str().to_owned());
    let session_public_key = outcome.session_public_key.clone().unwrap_or_default();
    let audience = outcome.audience.clone();
    let session_private_key_pem = dpop_handle
        .session_signing_key_pkcs8_pem()
        .map_err(|error| format!("export device session key: {error}"))?;
    Ok(CoauthSessionGrantInfo {
        kind: Some("session_grant".to_owned()),
        id: grant_id,
        grant_jwt: outcome.session_grant.clone(),
        session_public_key,
        session_private_key_pem: session_private_key_pem.to_string(),
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
    fn returning_account_reuses_device_only_with_did_and_valid_device_id() {
        let valid_device = "ck:device:01964137-0000-7000-8000-000000000001";
        // Both present → reuse the stable device.
        assert!(returning_account_can_reuse_device(
            "did:web:bob.example",
            valid_device
        ));
        // No persisted account → fresh sign-in (mint a device).
        assert!(!returning_account_can_reuse_device("", valid_device));
        assert!(!returning_account_can_reuse_device("   ", valid_device));
        // Account known but no valid stable device_id → fresh sign-in.
        assert!(!returning_account_can_reuse_device("did:web:bob.example", ""));
        assert!(!returning_account_can_reuse_device(
            "did:web:bob.example",
            "not-a-device-id"
        ));
        // Surrounding whitespace is trimmed before the validity check.
        assert!(returning_account_can_reuse_device(
            "  did:web:bob.example  ",
            &format!("  {valid_device}  ")
        ));
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
            "The account signed in at the Account Authority does not match the selected account. Use a different account, or sign in to the selected account again."
        );
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
