use arkret_sdk::http_client::{Auth, ClientBuilder};
use dioxus::prelude::*;
use dioxus_router::Link;
use garth::{AccountHandoffDisposition, OidcAccountHandoffInput};

use crate::components::UiIcon;
use crate::config::{
    LocalConfigStore, normalize_device_id, normalize_server_url, principal_server_options_for,
    same_server_url,
};
use crate::identity::account_auth::{
    AuthorityResolver, build_oidc_authorize_scaffold, build_persisted_oidc_scaffold,
    capture_current_browser_callback_url, clear_persisted_oidc_scaffold,
    extract_authorization_code_from_callback, extract_error_description_from_callback,
    extract_error_from_callback, extract_state_from_callback, fetch_oidc_discovery,
    open_oidc_authorize_url, persist_oidc_scaffold, restore_oidc_scaffold,
};
use crate::state::{LocalStateStore, PersistedSessionGrant};
use crate::transport::TransportClient;
use crate::ui::button::{Button, ButtonVariant};
use crate::ui::card::Card;
use crate::ui::input::Input;
use crate::ui::label::Label;
use crate::views::helpers::{actor_display_label, persist_config, short_protocol_id};

#[derive(Clone, Debug)]
struct CompletedLogin {
    principal_server_url: String,
    actor: String,
    personal_handle: Option<String>,
    device_id: String,
    dpop_device_key: crate::state::DpopDeviceKeyRecord,
    session_credential: String,
    /// Account-private preference returned by the authenticated, DPoP-bound
    /// account handoff. This is the value the user selected in coauth during
    /// the just-completed login/registration flow.
    preferred_locale: Option<crate::i18n::Locale>,
    /// Persisted principal session grant. This is the live credential for
    /// `/_arkret/self/*`; refresh rotates this grant before its own expiry.
    session_grant: Option<PersistedSessionGrant>,
}

enum OidcCallbackOutcome {
    Login(Box<CompletedLogin>),
    Onboarding {
        preferred_locale: Option<crate::i18n::Locale>,
    },
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
    account_did: Signal<String>,
    device_id: Signal<String>,
    token: Signal<String>,
    /// Connection-lifecycle label owned by the app shell; the only write
    /// here is the post-sign-in "Online" transition.
    connection_status: Signal<String>,
    config_store: Signal<LocalConfigStore>,
    account_primary_handle: Signal<String>,
    personal_handles: Signal<Vec<String>>,
    personal_handles_status: Signal<String>,
    mut locale: Signal<crate::i18n::Locale>,
    auto_capture_callback: bool,
    on_login: EventHandler<()>,
    on_onboarding: EventHandler<()>,
) -> Element {
    // A4 — base_url / state_store from session context instead of props.
    let mut base_url = crate::app::SessionContext::get().base_url;
    let state_store = crate::app::SessionContext::get().state_store;
    let i18n = use_context::<crate::i18n::I18nSignal>();
    let session = use_context::<crate::runtime::services::RuntimeServices>()
        .session
        .clone();
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
            Ok(OidcCallbackOutcome::Onboarding { preferred_locale }) => {
                apply_authenticated_account_locale(
                    preferred_locale,
                    state_store_write,
                    &mut locale,
                );
                auth_status.set(
                    "Account authenticated. Continue identity custody and binding.".to_owned(),
                );
                on_onboarding.call(());
            }
            Ok(OidcCallbackOutcome::Login(completed)) => {
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
                        store.switch_active_account(&completed.actor)
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
                        .unwrap_or_else(&*account_primary_handle);
                    let mut store = state_store_write.write();
                    if !resolved_handle.trim().is_empty() {
                        store.set_primary_handle(&resolved_handle);
                    }
                    store.register_known_account(&completed.actor);
                }
                apply_authenticated_account_locale(
                    completed.preferred_locale,
                    state_store_write,
                    &mut locale,
                );
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

    // Account selection belongs to the Account Authority. For a locally known
    // account, carry its principal DID as the explicit session-grant binding
    // assertion; coauth still authenticates the selected account and rejects a
    // mismatch. This is not a login hint or silent account selection. Reuse the
    // stable protocol device id so a hard re-login rotates only the
    // grant-binding key, not the E2EE device identity.
    let launch_sign_in = move || {
        let principal = base_url();
        let ui_locale = i18n.read().0.code().to_owned();
        let (principal_binding, device) = interactive_sign_in_context(&account_did(), &device_id());
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
            let resume_account_handoff = {
                let store = reset_state_store.read();
                store.can_resume_pending_login(&device)
            };
            if resume_account_handoff {
                // An unfinished identity-creation lease is fenced to this DPoP
                // holder. Rotating the key here makes the same browser look like
                // another device and leaves it stuck behind its own lease until
                // expiry. Re-authentication for this one resumable flow is a
                // soft continuation, so retain the holder key.
                crate::secure_key_store::set_active_device_seed_scope(None);
            } else {
                if let Err(error) = crate::secure_key_store::reset_device_seed_scope_for_signin(
                    secure_store.as_ref(),
                ) {
                    tracing::warn!(%error, "reset device seed scope for sign-in failed");
                }
                // Drop the cached DPoP record so the grant-binding key is rebuilt from
                // the freshly-rotated grant-binding seed.
                reset_state_store.write().set_dpop_device_key(None);
            }
            // Pre-DID: record the sign-in device id as the pending login so the
            // bootstrap wrap_seed / secrets land under the
            // `pending.<device_id>` namespace until the principal DID resolves
            // and `adopt_pending_login` re-homes them.
            if resume_account_handoff {
                let resumed = reset_state_store
                    .write()
                    .resume_pending_login(device.trim());
                debug_assert!(resumed, "validated handoff resume must remain valid");
            } else {
                reset_state_store
                    .write()
                    .begin_pending_login(device.trim(), None);
            }
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
            match start_oidc_strand(
                &principal,
                device.trim(),
                "",
                principal_binding.as_str(),
                &ui_locale,
            )
            .await
            {
                Ok(()) => {}
                Err(error) => {
                    is_busy.set(false);
                    auth_status.set(error);
                }
            }
        });
    };

    rsx! {
        Card { class: "auth-panel", "data-testid": "login-panel", role: "region", "aria-label": crate::i18n::tr("login.title"),
            div { class: "auth-brand",
                div { class: "auth-logo", "C" }
                div {
                    h1 {
                        if auto_capture_callback {
                            {crate::i18n::tr("login.completing")}
                        } else {
                            {crate::i18n::tr("login.title")}
                        }
                    }
                    p { "Arkret" }
                }
            }

            div { class: "auth-form",
                Label { html_for: "login-server-url-input", {crate::i18n::tr("login.principal_server")} }
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
                        "aria-label": crate::i18n::tr("login.principal_server_url"),
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
                        "aria-label": crate::i18n::tr("login.show_preset_servers"),
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
                            "aria-label": crate::i18n::tr("login.preset_servers"),
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
                    if is_busy() {
                        {crate::i18n::tr("login.working")}
                    } else {
                        {crate::i18n::tr("login.continue")}
                    }
                }

                if !auto_capture_callback {
                    div { class: "auth-footer",
                        Link {
                            to: crate::routes::Route::Register,
                            "New here? Create a recoverable identity"
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
                    let actor_label = actor_display_label(&store_snapshot, &actor_value);
                    drop(store_snapshot);
                    let show_session_diagnostics =
                        session_status != "signed-out" || !jkt_display.is_empty();
                    let device_label = short_protocol_id(&device_value);
                    let jkt_label = short_protocol_id(&jkt_display);
                    let session_status_label = crate::i18n::tr(match session_status {
                        "signed-in" => "login.status.signed_in",
                        "session-expired" => "login.status.session_expired",
                        _ => "login.status.signed_out",
                    });
                    rsx! {
                        if show_session_diagnostics {
                            div { class: "auth-session-state", "data-testid": "session-state-card",
                                div {
                                    "data-testid": "session-status",
                                    "data-status": session_status,
                                    "{session_status_label}"
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
                                    onclick: {
                                        let session = session.clone();
                                        move |_| {
                                        let session = session.clone();
                                        is_busy.set(true);
                                        auth_status.set("Refreshing session...".to_owned());
                                        spawn(async move {
                                            match session.refresh().await {
                                                crate::runtime::session::CurrentSessionRefresh::Credential(
                                                    session_credential,
                                                ) => {
                                                    token.set(session_credential);
                                                    auth_status.set("Session restored".to_owned());
                                                    on_login.call(());
                                                }
                                                crate::runtime::session::CurrentSessionRefresh::SignInRequired { reason } => {
                                                    auth_status.set(format!(
                                                        "Sign in required: {reason}"
                                                    ));
                                                }
                                                crate::runtime::session::CurrentSessionRefresh::LoginRequired { reason } => {
                                                    auth_status.set(format!(
                                                        "Session could not be restored: {reason}"
                                                    ));
                                                }
                                                crate::runtime::session::CurrentSessionRefresh::RetryLater { reason } => {
                                                    auth_status.set(format!(
                                                        "Session refresh pending: {reason}"
                                                    ));
                                                }
                                            }
                                            is_busy.set(false);
                                        });
                                        }
                                    },
                                    {crate::i18n::tr("login.refresh_now")}
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
    mut state_store: SyncSignal<LocalStateStore>,
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

fn interactive_sign_in_context(persisted_actor: &str, persisted_device: &str) -> (String, String) {
    (
        persisted_actor.trim().to_owned(),
        interactive_sign_in_device_id(persisted_actor, persisted_device),
    )
}

pub(crate) fn persist_completed_login_dpop_key(
    store: &mut LocalStateStore,
    secure_store: &dyn crate::secure_key_store::SecureKeyStore,
    actor: &str,
    device_id: &str,
    record: &crate::state::DpopDeviceKeyRecord,
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
    let principal_id = arkret_sdk::DidFullId::new(actor.to_owned())
        .map_err(|error| format!("bind account device signer principal: {error}"))?;
    crate::event_signer::bind_active_signer_principal_device_id(&principal_id, device_id)
        .map_err(|error| format!("bind account device signer principal: {error}"))?;
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
    if let Ok(callback_url) = capture_current_browser_callback_url()
        && let Ok(Some(state)) = extract_state_from_callback(&callback_url)
        && let Err(clear_error) = clear_persisted_oidc_scaffold(&state)
    {
        tracing::warn!(%clear_error, "clear failed OIDC scaffold failed");
    }
    // Principal-binding mismatch gets specific guidance: the raw wire reason
    // ("proof_invalid; principal binding mismatch: …") tells the user nothing
    // actionable — the actual fix is signing in with the intended account.
    if error.contains("principal binding mismatch") {
        return "The account signed in at the Account Authority does not match this local device session. Start sign-in again with the intended account."
            .to_owned();
    }
    if error.contains("principal_unknown") {
        return "The Account Authority reported that the verified principal binding is missing. No new identity was created; authenticate again and use account recovery or diagnostics if this device was already bound."
            .to_owned();
    }
    format!("{error} Start sign-in again.")
}

pub(crate) async fn start_oidc_strand(
    principal_server_url: &str,
    device_id: &str,
    login_hint: &str,
    principal_actor_id: &str,
    ui_locale: &str,
) -> Result<(), String> {
    // T1.Y1 — discover the Account Authority + auth methods from the Principal
    // Server's root `/_arkret/describe` (service-surface §2.5.1).
    let principal = TransportClient::unauthenticated(principal_server_url)
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
    // Standard OpenID Connect Discovery 1.0 — no Arkret-private OAuth family.
    let discovery = fetch_oidc_discovery(&discovery_url)
        .await
        .map_err(|error| format!("OIDC discovery failed: {error}"))?;
    let redirect_uri = crate::identity::account_auth::current_oidc_redirect_uri();
    let bundle = build_oidc_authorize_scaffold(
        &discovery,
        &method,
        &redirect_uri,
        login_hint,
        device_id,
        &resolver.principal_audience,
        ui_locale,
    )
    .map_err(|error| format!("Sign-in URL preparation failed: {error}"))?;

    let scaffold = build_persisted_oidc_scaffold(
        &bundle,
        &resolver.gate_account_base,
        principal_server_url,
        principal_actor_id,
        device_id,
        &discovery.issuer,
        &resolver.principal_trust_domain,
    );
    persist_oidc_scaffold(&scaffold)
        .map_err(|error| format!("Could not save sign-in state: {error}"))?;
    open_oidc_authorize_url(&bundle.authorize_url)
        .map_err(|error| format!("Could not open server sign-in: {error}"))
}

/// Standard OIDC discovery URL for an auth method: the explicit
/// `openid_configuration` when present, else `{issuer}/.well-known/openid-configuration`.
fn oidc_discovery_url(method: &arkret_sdk::AuthMethod) -> Option<String> {
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
    mut state_store: SyncSignal<LocalStateStore>,
) -> Result<OidcCallbackOutcome, String> {
    let callback_url = capture_current_browser_callback_url()
        .map_err(|error| format!("Could not read callback URL: {error}"))?;
    let returned_state = extract_state_from_callback(&callback_url)
        .map_err(|error| format!("Could not read callback state: {error}"))?
        .ok_or_else(|| "Callback did not include state.".to_owned())?;
    let scaffold = restore_oidc_scaffold(&returned_state)
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
        crate::identity::session_refresh::sdk_base_url_from_gate_account_base(&gate_account_base)
            .map_err(|error| format!("Invalid Account Authority base: {error}"))?;
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
        let handle = crate::identity::account_auth::grant_dpop::ensure_device_key(&mut store)
            .map_err(|error| format!("DPoP key failed: {error}"))?;
        crate::event_signer::bind_active_signer_device_id(&device)
            .map_err(|error| format!("Event signer device binding failed: {error}"))?;
        handle
    };
    if scaffold.issuer.trim().is_empty() {
        return Err("Sign-in state is missing the OIDC issuer.".to_owned());
    }
    let principal_audience =
        arkret_sdk::DidCoreId::new(scaffold.principal_audience.trim().to_owned())
            .map_err(|error| format!("invalid Principal Server audience core_id: {error}"))?;
    let http = ClientBuilder::new(sdk_base_url)
        .allow_insecure_localhost()
        .auth(Auth::Dpop(dpop_handle.sdk_dpop_proof_only_auth()))
        .build()
        .map_err(|error| format!("Build Account Authority handoff client failed: {error}"))?;
    let handoff_request = garth::oidc_account_handoff_request(
        OidcAccountHandoffInput {
            request_id: arkret_sdk::RequestId::new_v7_at(crate::clock::now_unix_ms()),
            audience: principal_audience.clone(),
            issuer: scaffold.issuer.clone(),
            client_id: scaffold.client_id.clone(),
            redirect_uri: scaffold.callback_uri.clone(),
            state: returned_state,
            nonce: scaffold.expected_nonce.clone(),
            authorization_code,
            code_verifier: scaffold.code_verifier.clone(),
        },
        |bytes| {
            dpop_handle
                .sign_protocol_bytes(bytes)
                .map_err(|error| garth::Error::Protocol(error.to_string()))
        },
    )
    .map_err(|error| format!("Account handoff request failed: {error}"))?;
    let handoff = http
        .auth_create_account_handoff(&handoff_request)
        .await
        .map_err(|error| format!("Account Authority handoff failed: {error}"))?;
    let disposition = garth::account_handoff_disposition(&handoff)
        .map_err(|error| format!("Account handoff outcome failed validation: {error}"))?;
    if let AccountHandoffDisposition::IdentityCreationActive(lease) = &disposition {
        let pending_handoff = crate::state::PendingAccountHandoff {
            principal_server_url,
            gate_account_base,
            request_id: handoff.request_id.to_string(),
            account_handle: handoff.account_handle.canonical().to_owned(),
            account_subject: Some(handoff.account_subject.clone()),
            holder_jkt: dpop_handle.jkt().to_owned(),
            audience: principal_audience.to_string(),
            expires_at: handoff.expires_at,
            lease_id: Some(lease.identity_creation_lease_id.clone()),
            lease_fence: Some(lease.fence),
            lease_expires_at: Some(lease.expires_at),
            reserved_identity: lease
                .reserved_identity
                .as_ref()
                .map(serde_json::to_value)
                .transpose()
                .map_err(|error| format!("Persist reserved identity checkpoint failed: {error}"))?,
            retry_after_ms: None,
            device_id: device,
            trust_domain: scaffold.principal_trust_domain.clone(),
            bound_principal_id: None,
        };
        crate::identity::account_auth::persist_account_handoff_grant(
            &pending_handoff,
            &handoff.account_handoff_grant,
        )
        .await
        .map_err(|error| format!("Persist account handoff credential failed: {error}"))?;
        {
            let mut store = state_store.write();
            persist_pending_account_handoff(&mut store, pending_handoff)
                .map_err(|error| format!("Persist public handoff checkpoint failed: {error}"))?;
        }
        let _ = clear_persisted_oidc_scaffold(&scaffold.expected_state);
        return Ok(OidcCallbackOutcome::Onboarding {
            preferred_locale: handoff.preferred_locale,
        });
    }
    if let AccountHandoffDisposition::IdentityCreationBusy {
        retry_after_ms,
        expires_at: busy_expires_at,
    } = disposition
    {
        let pending_handoff = crate::state::PendingAccountHandoff {
            principal_server_url,
            gate_account_base,
            request_id: handoff.request_id.to_string(),
            account_handle: handoff.account_handle.canonical().to_owned(),
            account_subject: Some(handoff.account_subject.clone()),
            holder_jkt: dpop_handle.jkt().to_owned(),
            audience: principal_audience.to_string(),
            expires_at: handoff.expires_at,
            lease_id: None,
            lease_fence: None,
            lease_expires_at: Some(busy_expires_at),
            reserved_identity: None,
            retry_after_ms: Some(retry_after_ms),
            device_id: device,
            trust_domain: scaffold.principal_trust_domain.clone(),
            bound_principal_id: None,
        };
        crate::identity::account_auth::persist_account_handoff_grant(
            &pending_handoff,
            &handoff.account_handoff_grant,
        )
        .await
        .map_err(|error| format!("Persist account handoff credential failed: {error}"))?;
        {
            let mut store = state_store.write();
            persist_pending_account_handoff(&mut store, pending_handoff)
                .map_err(|error| format!("Persist busy handoff checkpoint failed: {error}"))?;
        }
        let _ = clear_persisted_oidc_scaffold(&scaffold.expected_state);
        return Ok(OidcCallbackOutcome::Onboarding {
            preferred_locale: handoff.preferred_locale,
        });
    }
    let AccountHandoffDisposition::Bound { principal_id, .. } = disposition else {
        unreachable!("active and busy handoff outcomes returned above")
    };
    let pending_handoff = crate::state::PendingAccountHandoff {
        principal_server_url,
        gate_account_base,
        request_id: handoff.request_id.to_string(),
        account_handle: handoff.account_handle.canonical().to_owned(),
        account_subject: Some(handoff.account_subject.clone()),
        holder_jkt: dpop_handle.jkt().to_owned(),
        audience: principal_audience.to_string(),
        expires_at: handoff.expires_at,
        lease_id: None,
        lease_fence: None,
        lease_expires_at: None,
        reserved_identity: None,
        retry_after_ms: None,
        device_id: device,
        trust_domain: scaffold.principal_trust_domain.clone(),
        bound_principal_id: Some(principal_id.to_string()),
    };
    crate::identity::account_auth::persist_account_handoff_grant(
        &pending_handoff,
        &handoff.account_handoff_grant,
    )
    .await
    .map_err(|error| format!("Persist account recovery handoff credential failed: {error}"))?;
    {
        let mut store = state_store.write();
        persist_pending_account_handoff(&mut store, pending_handoff)
            .map_err(|error| format!("Persist account recovery checkpoint failed: {error}"))?;
    }
    let _ = clear_persisted_oidc_scaffold(&scaffold.expected_state);
    Ok(OidcCallbackOutcome::Onboarding {
        preferred_locale: handoff.preferred_locale,
    })
}

fn apply_authenticated_account_locale(
    preferred_locale: Option<crate::i18n::Locale>,
    mut state_store: SyncSignal<LocalStateStore>,
    locale: &mut Signal<crate::i18n::Locale>,
) {
    let Some(preferred_locale) = preferred_locale else {
        return;
    };
    state_store
        .write()
        .set_device_pref("locale", preferred_locale.code());
    if *locale.peek() != preferred_locale {
        locale.set(preferred_locale);
    }
}

fn persist_pending_account_handoff(
    store: &mut LocalStateStore,
    pending_handoff: crate::state::PendingAccountHandoff,
) -> anyhow::Result<()> {
    if store
        .pending_principal_registration()
        .is_some_and(|checkpoint| {
            !crate::identity::principal_registration::checkpoint_belongs_to_handoff(
                &checkpoint,
                &pending_handoff,
            )
        })
    {
        store.set_pending_principal_registration(None)?;
    }
    store.set_pending_account_handoff(Some(pending_handoff))
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

    struct SeedScopeReset {
        _signer: crate::event_signer::ActiveSignerTestGuard,
    }

    impl SeedScopeReset {
        fn new() -> Self {
            Self {
                _signer: crate::event_signer::ActiveSignerTestGuard::replace(None),
            }
        }
    }

    impl Drop for SeedScopeReset {
        fn drop(&mut self) {
            crate::secure_key_store::set_active_device_seed_scope(None);
            crate::secure_key_store::set_pending_login_device_id(None);
        }
    }

    fn dpop_record_for_seed(seed: [u8; 32]) -> crate::state::DpopDeviceKeyRecord {
        crate::identity::account_auth::grant_dpop::dpop_device_key_record_from_seed(
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
            audience: "did:web:principal.example".to_owned(),
            principal_id: "did:web:alice.example".to_owned(),
            device_id: "device-1".to_owned(),
            principal_server_url: "https://principal.example".to_owned(),
            grant_expires_at: Some(now + chrono::Duration::seconds(3600)),
            stored_at: now,
        }
    }

    fn pending_handoff_for_test(
        request_id: &str,
        account_handle: &str,
    ) -> crate::state::PendingAccountHandoff {
        crate::state::PendingAccountHandoff {
            principal_server_url: "https://principal.example".to_owned(),
            gate_account_base: "https://auth.example/_arkret/gate/account".to_owned(),
            request_id: request_id.to_owned(),
            account_handle: account_handle.to_owned(),
            account_subject: Some(
                arkret_sdk::Hash::new(format!("sha256:{}", "a".repeat(64))).unwrap(),
            ),
            holder_jkt: "holder-jkt".to_owned(),
            audience: "did:webvh:z6mkfixture:principal.example".to_owned(),
            expires_at: chrono::Utc::now() + chrono::Duration::minutes(10),
            lease_id: Some("lease-1".to_owned()),
            lease_fence: Some(1),
            lease_expires_at: Some(chrono::Utc::now() + chrono::Duration::minutes(15)),
            reserved_identity: None,
            retry_after_ms: None,
            device_id: "ak:device:019f0000-0000-7000-8000-000000000001".to_owned(),
            trust_domain: "ak:trust_domain:auth.example".to_owned(),
            bound_principal_id: None,
        }
    }

    #[test]
    fn callback_handoff_does_not_use_account_handle_as_identity_evidence() {
        let mut store = crate::state::isolated_store_for_tests("foreign-callback-checkpoint");
        let old_handoff = pending_handoff_for_test(
            "ak:request:019f0000-0000-7000-8000-000000000010",
            "alice:auth.example",
        );
        let recovery_key = crate::recovery_crypto::generate_recovery_key().unwrap();
        let checkpoint = crate::identity::principal_registration::prepare_registration_checkpoint(
            &old_handoff,
            &old_handoff.device_id,
            &recovery_key,
        )
        .unwrap();
        store
            .set_pending_principal_registration(Some(checkpoint))
            .unwrap();
        let new_handoff = pending_handoff_for_test(
            "ak:request:019f0000-0000-7000-8000-000000000010",
            "bob:auth.example",
        );

        persist_pending_account_handoff(&mut store, new_handoff.clone()).unwrap();

        assert!(store.pending_principal_registration().is_some());
        assert_eq!(store.pending_account_handoff(), Some(new_handoff));
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
    fn unknown_principal_fails_closed_without_minting_guidance() {
        assert_eq!(
            discard_failed_oidc_callback(
                "Account Authority session-grant issue failed: principal_unknown".to_owned()
            ),
            "The Account Authority reported that the verified principal binding is missing. No new identity was created; authenticate again and use account recovery or diagnostics if this device was already bound."
        );
    }

    #[test]
    fn oidc_callback_restores_bootstrap_device_seed_scope() {
        let _lock = seed_scope_test_lock();
        let _reset = SeedScopeReset::new();
        crate::secure_key_store::set_active_device_seed_scope(Some("did:web:old.example"));

        restore_oidc_callback_device_seed_scope("ak:device:01964137-0000-7000-8000-000000000001");

        assert_eq!(crate::secure_key_store::active_device_seed_scope(), None);
        assert_eq!(
            crate::secure_key_store::pending_login_device_id().as_deref(),
            Some("ak:device:01964137-0000-7000-8000-000000000001")
        );
    }

    #[test]
    fn interactive_sign_in_reuses_known_account_device_id() {
        let existing = "ak:device:01964137-0000-7000-8000-000000000001";
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
    fn interactive_sign_in_carries_known_principal_binding() {
        let actor = "did:webvh:z6mkfixture:alice.example";
        let device = "ak:device:01964137-0000-7000-8000-000000000001";

        let (binding, selected_device) =
            interactive_sign_in_context(&format!("  {actor}  "), device);

        assert_eq!(binding, actor);
        assert_eq!(selected_device, device);

        let (unbound, _) = interactive_sign_in_context("   ", device);
        assert!(
            unbound.is_empty(),
            "first registration must not infer a principal DID"
        );
    }

    #[test]
    fn completed_login_dpop_key_preserves_returning_account_key_material() {
        let _lock = seed_scope_test_lock();
        let _reset = SeedScopeReset::new();
        let mut store = crate::state::isolated_store_for_tests("completed-login-dpop-key");
        let secure_store = crate::secure_key_store::MemorySecureKeyStore::default();
        let actor = "did:web:alice.example";
        let device = "ak:device:01964137-0000-7000-8000-000000000001";
        let old_seed = [3_u8; 32];
        let new_record = dpop_record_for_seed([7_u8; 32]);

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
}
