use arkret_sdk::http_client::{Auth, ClientBuilder};
use chrono::Utc;
use dioxus::prelude::*;
use dioxus_router::Link;
use garth::{
    AccountHandoffDisposition, LoginKind, OidcAccountHandoffInput, OidcLogin, SessionEngine,
    SessionGrantState,
};

use crate::components::UiIcon;
use crate::config::{
    LocalConfigStore, normalize_device_id, normalize_server_url, principal_server_options_for,
    same_server_url,
};
use crate::identity::account_auth::{
    AuthorityResolver, OidcEntryPoint, build_oidc_authorize_scaffold,
    build_persisted_oidc_scaffold, capture_current_browser_callback_url,
    clear_persisted_oidc_scaffold, extract_authorization_code_from_callback,
    extract_error_description_from_callback, extract_error_from_callback,
    extract_state_from_callback, fetch_oidc_discovery, open_oidc_authorize_url,
    persist_oidc_scaffold, restore_oidc_scaffold,
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
    actor: arkret_sdk::DidFullId,
    personal_handle: Option<String>,
    device_id: String,
    dpop_device_key: crate::state::DpopDeviceKeyRecord,
    session_credential: String,
    session_grant: PersistedSessionGrant,
}

enum OidcCallbackOutcome {
    /// A known principal and its durable local device identity were retained,
    /// so Account Authority issued a fresh session grant for that same device.
    Login(Box<CompletedLogin>),
    /// No usable local device identity was available. The Account Authority's
    /// typed handoff decides between first creation and existing-account
    /// recovery; Inkson does not infer either state locally.
    Onboarding {
        preferred_locale: Option<crate::i18n::Locale>,
    },
}

fn recover_pending_handoff_for_sign_in(
    store: &mut LocalStateStore,
    secure_store: &dyn crate::secure_key_store::SecureKeyStore,
    device_id: &str,
) -> bool {
    let pending_holder = store
        .pending_account_handoff()
        .filter(|handoff| handoff.device_id == device_id)
        .map(|handoff| handoff.holder_jkt);
    if let Some(expected_holder) = pending_holder {
        let pending_device_id = match arkret_sdk::DeviceId::new(device_id.to_owned()) {
            Ok(device_id) => device_id,
            Err(error) => {
                tracing::warn!(%error, device_id, "starting fresh sign-in because the unfinished handoff device id is invalid");
                return false;
            }
        };
        let pending_store = crate::secure_key_store::PendingLocalStore::new(pending_device_id);
        let recovered = match crate::identity::account_auth::grant_dpop::load_or_recover_pending_device_key_with_secure_store(
            store,
            secure_store,
            &pending_store,
        ) {
            Ok(Some(recovered)) => recovered,
            Ok(None) => {
                tracing::warn!(
                    device_id,
                    "starting fresh sign-in because the unfinished handoff holder key is missing"
                );
                return false;
            }
            Err(error) => {
                tracing::warn!(
                    %error,
                    device_id,
                    "starting fresh sign-in because the unfinished handoff holder could not be recovered"
                );
                return false;
            }
        };
        if recovered.jkt() != expected_holder {
            tracing::warn!(
                device_id,
                "starting fresh sign-in because the unfinished handoff belongs to a different holder"
            );
            return false;
        }
    }
    store.can_resume_pending_login(device_id)
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
    config_store: Signal<LocalConfigStore>,
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
            Ok(OidcCallbackOutcome::Login(completed)) => {
                let principal_server_url = normalize_server_url(&completed.principal_server_url);
                let actor = completed.actor.to_string();
                let server_changed = {
                    let previous = normalize_server_url(&base_url());
                    !previous.trim().is_empty() && previous != principal_server_url
                };
                let mut persist_error = None::<String>;
                {
                    let mut store = state_store_write.write();
                    let new_account = store.adopt_pending_login(&completed.actor);
                    if server_changed && !new_account {
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
                        persist_error = Some(format!(
                            "Could not persist the returning-device session key: {error}"
                        ));
                    } else {
                        if let Some(handle) = completed.personal_handle.as_deref() {
                            store.set_primary_handle(handle);
                        }
                        store.register_known_account(&actor);
                        store.set_session_grant(Some(completed.session_grant.clone()));
                    }
                }
                if let Some(error) = persist_error {
                    auth_status.set(error);
                    is_busy.set(false);
                    return;
                }
                base_url.set(principal_server_url.clone());
                account_did.set(actor.clone());
                device_id.set(completed.device_id.clone());
                token.set(completed.session_credential.clone());
                persist_config(
                    config_store,
                    principal_server_url,
                    actor,
                    completed.device_id.clone(),
                    completed.session_credential.clone(),
                );
                auth_status.set("Signed in on this authorized device.".to_owned());
                on_login.call(());
            }
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
            Err(error) => auth_status.set(discard_failed_oidc_callback(error)),
        }
        is_busy.set(false);
    });

    // Coauth remains authoritative for which account the user authenticates.
    // For a locally retained principal, Inkson carries that principal only as
    // an assertion for the canonical session-grant exchange; coauth verifies
    // the assertion against the selected account and the server verifies the
    // durable device authorization. Account-first sign-in (no usable local
    // device identity) continues through an anonymous account handoff.
    let sign_in_session = session.clone();
    let mut launch_sign_in = move || {
        let principal = base_url();
        let ui_locale = i18n.read().0.code().to_owned();
        let loaded_config = config_store.read().load();
        let live_actor = account_did();
        let persisted_actor = if live_actor.trim().is_empty() {
            loaded_config.account_did
        } else {
            live_actor
        };
        let persisted_device = if crate::config::is_valid_device_id(&loaded_config.device_id) {
            loaded_config.device_id
        } else {
            device_id()
        };
        let returning_principal = {
            let store = state_store.read();
            match returning_sign_in_principal(&store, &persisted_actor) {
                Ok(principal) => principal,
                Err(error) => {
                    auth_status.set(error);
                    return;
                }
            }
        };
        let mut reset_state_store = state_store;
        let session = sign_in_session.clone();
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
            let returning_device = if let Some(expected) = returning_principal.as_ref() {
                match returning_device_id(secure_store.as_ref(), expected, &persisted_device) {
                    Ok(device) => device,
                    Err(error) => {
                        is_busy.set(false);
                        auth_status.set(error);
                        return;
                    }
                }
            } else {
                None
            };
            let (pending_handoff, has_pending_checkpoint, recovery_ready) = {
                let store = reset_state_store.read();
                let pending_handoff = store.pending_account_handoff();
                let has_pending_checkpoint = store.pending_principal_registration().is_some();
                let recovery_ready = returning_principal.as_ref().is_some_and(|principal| {
                    store.recovery_material_evidence().is_some_and(|evidence| {
                        evidence.principal_id == *principal
                            && pending_handoff.as_ref().is_none_or(|handoff| {
                                evidence.device_id.as_str() == handoff.device_id
                            })
                            && crate::views::recovery::local_recovery_public_key_result(
                                &store,
                                principal.as_str(),
                            )
                            .is_ok()
                    })
                });
                (pending_handoff, has_pending_checkpoint, recovery_ready)
            };
            let use_returning_device = returning_principal
                .as_ref()
                .zip(returning_device.as_ref())
                .is_some_and(|(principal, _)| {
                    returning_device_can_bypass_handoff(
                        pending_handoff.as_ref(),
                        principal,
                        has_pending_checkpoint,
                        recovery_ready,
                    )
                });
            let pending_device = pending_handoff
                .as_ref()
                .map(|handoff| handoff.device_id.clone())
                .filter(|device| crate::config::is_valid_device_id(device));
            let resume_account_handoff =
                if !use_returning_device && let Some(pending_device) = pending_device.as_deref() {
                    let mut store = reset_state_store.write();
                    recover_pending_handoff_for_sign_in(
                        &mut store,
                        secure_store.as_ref(),
                        pending_device,
                    )
                } else {
                    false
                };
            let (device, expected_principal) = if resume_account_handoff {
                (
                    pending_device.expect("resumable handoff has a device id"),
                    None,
                )
            } else if use_returning_device {
                (
                    returning_device.expect("selected returning device exists"),
                    returning_principal,
                )
            } else {
                (crate::config::new_device_id(), None)
            };
            // Stop every old-account poller before installing the anonymous
            // pending namespace. Otherwise a delayed refresh can reinstall the
            // previous account's signer while onboarding is preparing proofs.
            session.invalidate("starting an account sign-in transaction");
            token.set(String::new());
            device_id.set(device.clone());
            if expected_principal.is_none() {
                account_did.set(String::new());
                persist_config(
                    config_store,
                    principal.clone(),
                    String::new(),
                    device.clone(),
                    String::new(),
                );
            }
            if resume_account_handoff {
                // An unfinished identity-creation lease is fenced to this DPoP
                // holder. Rotating the key here makes the same browser look like
                // another device and leaves it stuck behind its own lease until
                // expiry. Re-authentication for this one resumable flow is a
                // soft continuation, so retain the holder key.
                crate::secure_key_store::set_active_device_seed_scope(None);
            } else {
                reset_state_store
                    .write()
                    .begin_pending_login(device.trim(), None);
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
            }
            let pending_store = match arkret_sdk::DeviceId::new(device.trim().to_owned()) {
                Ok(device_id) => crate::secure_key_store::PendingLocalStore::new(device_id),
                Err(error) => {
                    is_busy.set(false);
                    auth_status.set(format!("The generated device id is invalid: {error}"));
                    return;
                }
            };
            if !resume_account_handoff
                && let Err(error) = pending_store.delete(secure_store.as_ref())
            {
                is_busy.set(false);
                auth_status.set(format!("Could not rotate the pending sign-in key: {error}"));
                return;
            }
            pending_store.activate();
            if let Err(error) = pending_store.save_device_id(secure_store.as_ref()) {
                tracing::warn!(%error, "persist pending device_id for sign-in failed");
            }
            match start_oidc_strand(
                &principal,
                device.trim(),
                OidcEntryPoint::SignIn,
                expected_principal.as_ref(),
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
                // Account Authority's OIDC screen. A browser that still owns an
                // authorized device also binds the callback to that local principal;
                // otherwise the server returns an account handoff for onboarding.
                Button {
                    variant: ButtonVariant::Primary,
                    class: "auth-primary",
                    "data-testid": "start-server-login-button",
                    disabled: is_busy(),
                    onclick: move |_| launch_sign_in(),
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
                    let show_session_diagnostics = session_status != "signed-out";
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

fn restore_oidc_callback_device_seed_scope(
    device_id: &str,
) -> Result<crate::secure_key_store::PendingLocalStore, String> {
    let device_id = arkret_sdk::DeviceId::new(device_id.to_owned())
        .map_err(|error| format!("invalid pending login device id: {error}"))?;
    let pending_store = crate::secure_key_store::PendingLocalStore::new(device_id);
    pending_store.activate();
    Ok(pending_store)
}

fn returning_sign_in_principal(
    store: &LocalStateStore,
    persisted_actor: &str,
) -> Result<Option<arkret_sdk::DidFullId>, String> {
    let actor = persisted_actor.trim();
    if actor.is_empty() {
        return Ok(None);
    }
    if let Ok(full_id) = arkret_sdk::DidFullId::new(actor.to_owned()) {
        arkret_sdk::project_full_id_to_core_id(&full_id)
            .map_err(|error| format!("The saved account principal cannot be projected: {error}"))?;
        return Ok(Some(full_id));
    }

    let core_id = arkret_sdk::DidCoreId::new(actor.to_owned())
        .map_err(|error| format!("The saved account principal is invalid: {error}"))?;
    let Some(evidence) = store.recovery_material_evidence() else {
        // Older profiles may contain only a stable core id. Without retained
        // full-id evidence we cannot safely restore the event signer binding;
        // continue as account-first recovery rather than inventing a full DID.
        return Ok(None);
    };
    let evidence_core = arkret_sdk::project_full_id_to_core_id(&evidence.principal_id)
        .map_err(|error| format!("The retained principal evidence is invalid: {error}"))?;
    if evidence_core != core_id {
        return Err(
            "The saved account principal does not match this device's retained identity evidence. No local device state was used."
                .to_owned(),
        );
    }
    Ok(Some(evidence.principal_id))
}

fn principal_value_matches_full(value: &str, expected: &arkret_sdk::DidFullId) -> bool {
    let Ok(expected_core) = arkret_sdk::project_full_id_to_core_id(expected) else {
        return false;
    };
    arkret_sdk::DidCoreId::new(value.trim().to_owned()).is_ok_and(|core| core == expected_core)
        || arkret_sdk::DidFullId::new(value.trim().to_owned())
            .ok()
            .and_then(|full| arkret_sdk::project_full_id_to_core_id(&full).ok())
            .is_some_and(|core| core == expected_core)
}

fn returning_device_can_bypass_handoff(
    pending_handoff: Option<&crate::state::PendingAccountHandoff>,
    expected: &arkret_sdk::DidFullId,
    has_pending_checkpoint: bool,
    recovery_ready: bool,
) -> bool {
    if has_pending_checkpoint {
        return false;
    }
    pending_handoff.is_none_or(|handoff| {
        recovery_ready
            && handoff
                .bound_principal_id
                .as_deref()
                .is_some_and(|bound| principal_value_matches_full(bound, expected))
    })
}

fn returning_device_id(
    secure_store: &dyn crate::secure_key_store::SecureKeyStore,
    principal_id: &arkret_sdk::DidFullId,
    configured_device_id: &str,
) -> Result<Option<String>, String> {
    let principal_core_id = arkret_sdk::project_full_id_to_core_id(principal_id)
        .map_err(|error| format!("Project the returning account principal: {error}"))?;
    let user_store = crate::secure_key_store::UserLocalStore::new(principal_core_id);
    let Some(stored_device_id) = user_store
        .load_device_id(secure_store)
        .map_err(|error| format!("Load the returning account device id: {error}"))?
    else {
        return Ok(None);
    };
    if user_store
        .load_signing_seed(secure_store)
        .map_err(|error| format!("Load the returning account device identity: {error}"))?
        .is_none()
    {
        return Ok(None);
    }
    let configured_device_id = configured_device_id.trim();
    if !configured_device_id.is_empty() && configured_device_id != stored_device_id.as_str() {
        tracing::warn!(
            configured_device_id,
            stored_device_id = %stored_device_id,
            "using secure-store device id instead of stale public config during returning sign-in"
        );
    }
    Ok(Some(stored_device_id.to_string()))
}

pub(crate) fn persist_completed_login_dpop_key(
    store: &mut LocalStateStore,
    secure_store: &dyn crate::secure_key_store::SecureKeyStore,
    principal_id: &arkret_sdk::DidFullId,
    device_id: &str,
    record: &crate::state::DpopDeviceKeyRecord,
) -> Result<(), String> {
    let principal_core_id = arkret_sdk::project_full_id_to_core_id(principal_id)
        .map_err(|error| format!("project account principal to core id: {error}"))?;
    let device_id = arkret_sdk::DeviceId::new(device_id.to_owned())
        .map_err(|error| format!("validate account device id: {error}"))?;
    let user_store = crate::secure_key_store::UserLocalStore::new(principal_core_id);
    let pending_store = crate::secure_key_store::PendingLocalStore::new(device_id.clone());
    pending_store
        .promote_to(secure_store, &user_store)
        .map_err(|error| format!("promote pending local store: {error}"))?;
    user_store
        .save_grant_binding_seed_b64url(secure_store, &record.seed_b64)
        .map_err(|error| format!("store grant-binding seed: {error}"))?;
    user_store
        .save_device_id(secure_store, &device_id)
        .map_err(|error| format!("store account-scoped device id: {error}"))?;
    user_store.activate();
    store
        .set_dpop_device_key_with_secure_store(Some(record.clone()), secure_store)
        .map_err(|error| format!("store account-scoped DPoP key: {error}"))?;
    let material = user_store
        .ensure_signing_seed(secure_store)
        .map_err(|error| format!("ensure account device signing seed: {error}"))?;
    crate::event_signer::activate_device_signer_from_seed_for_device(
        material.seed,
        Some(secure_store),
        Some(device_id.as_str()),
    )
    .map_err(|error| format!("activate account device signer: {error}"))?;
    crate::event_signer::bind_active_signer_principal_device_id(principal_id, device_id.as_str())
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
    if error.contains("principal binding mismatch")
        || error.contains("different principal or device")
        || error.contains("does not match the returning principal")
    {
        return "The account authenticated at the Account Authority does not match this local device. No device state was changed; sign in again with the account already stored on this device."
            .to_owned();
    }
    if error.contains("principal_unknown") {
        return "The Account Authority no longer has a verified binding for this local principal. No new identity was created; use account recovery or diagnostics."
            .to_owned();
    }
    if error.contains("device_revoked") || error.contains("device_revocation_pending") {
        return "This locally retained device is no longer authorized by the principal. Use the new-device recovery flow; the old device identity was not reused."
            .to_owned();
    }
    format!("{error} Start sign-in again.")
}

pub(crate) async fn start_oidc_strand(
    principal_server_url: &str,
    device_id: &str,
    entry_point: OidcEntryPoint,
    expected_principal_full_id: Option<&arkret_sdk::DidFullId>,
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
        device_id,
        &resolver.principal_audience,
        &entry_point,
        ui_locale,
    )
    .map_err(|error| format!("Sign-in URL preparation failed: {error}"))?;

    let scaffold = build_persisted_oidc_scaffold(
        &bundle,
        &resolver.gate_account_base,
        principal_server_url,
        device_id,
        &discovery.issuer,
        &resolver.principal_trust_domain,
        expected_principal_full_id,
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
    let pending_store = restore_oidc_callback_device_seed_scope(&device)?;
    #[cfg(target_arch = "wasm32")]
    crate::secure_key_store::ensure_wasm_secure_key_store_ready("inkson")
        .await
        .map_err(|error| format!("DPoP key store not ready: {error}"))?;
    let dpop_handle = {
        let mut store = state_store.write();
        let secure_store = crate::secure_key_store::default_secure_key_store("inkson");
        let handle =
            crate::identity::account_auth::grant_dpop::ensure_pending_device_key_with_secure_store(
                &mut store,
                secure_store.as_ref(),
                &pending_store,
            )
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
        .map_err(|error| format!("Build Account Authority OIDC client failed: {error}"))?;
    if let Some(expected_full_id) = scaffold.expected_principal_full_id.clone() {
        let expected_principal_id = arkret_sdk::project_full_id_to_core_id(&expected_full_id)
            .map_err(|error| format!("invalid returning principal full_id: {error}"))?;
        let typed_device_id = arkret_sdk::DeviceId::new(device.clone())
            .map_err(|error| format!("invalid returning device_id: {error}"))?;
        let signed_login = returning_oidc_login(
            &scaffold,
            expected_principal_id.clone(),
            typed_device_id.clone(),
            principal_audience.clone(),
            &returned_state,
            &authorization_code,
        )?
        .sign(|bytes| {
            dpop_handle
                .sign_protocol_bytes(bytes)
                .map_err(|error| garth::Error::Protocol(error.to_string()))
        })
        .map_err(|error| format!("OIDC session-grant request failed: {error}"))?;
        let session_engine = SessionEngine::new(http);
        session_engine
            .login(LoginKind::Oidc(signed_login), Utc::now())
            .await
            .map_err(|error| format!("Account Authority session-grant issue failed: {error}"))?;
        let session_grant = session_engine.current_state().ok_or_else(|| {
            "Account Authority session-grant issue did not yield state.".to_owned()
        })?;
        if session_grant.principal_id != expected_principal_id
            || session_grant.device_id.as_ref() != Some(&typed_device_id)
        {
            return Err(
                "Account Authority returned a session for a different principal or device. No local account state was adopted."
                    .to_owned(),
            );
        }
        let principal = TransportClient::unauthenticated(&principal_server_url)
            .map_err(|error| format!("Invalid principal server URL: {error}"))?;
        let authed_principal = principal
            .with_bearer(session_grant.grant_jwt.clone())
            .map_err(|error| format!("Attach returning session grant: {error}"))?
            .with_dpop_device(dpop_handle.clone())
            .map_err(|error| format!("Attach returning DPoP key: {error}"))?;
        let account = async {
            crate::transport::account::account_me(&authed_principal.sdk_http_client()?).await
        }
        .await
        .map_err(|error| {
            format!("Principal server did not accept the session grant + DPoP: {error}")
        })?;
        let account_principal_id = arkret_sdk::DidCoreId::new(account.did.clone())
            .map_err(|error| format!("Principal server returned an invalid account id: {error}"))?;
        if account_principal_id != expected_principal_id {
            return Err(
                "Principal server account does not match the returning principal. No local account state was adopted."
                    .to_owned(),
            );
        }
        let session_private_key_pem = dpop_handle
            .session_signing_key_pkcs8_pem()
            .map_err(|error| format!("export device session key: {error}"))?
            .to_string();
        let dpop_device_key =
            crate::identity::account_auth::grant_dpop::dpop_device_key_record_from_seed(
                dpop_handle.seed_b64().as_str(),
            )
            .map_err(|error| format!("DPoP device key record failed: {error}"))?;
        let persisted_session_grant = persisted_session_grant_from_state(
            &session_grant,
            &session_private_key_pem,
            &principal_server_url,
            &device,
        );
        let _ = clear_persisted_oidc_scaffold(&scaffold.expected_state);
        return Ok(OidcCallbackOutcome::Login(Box::new(CompletedLogin {
            principal_server_url,
            actor: expected_full_id,
            personal_handle: crate::app::personal_handle_from_account_handle(&account.handle),
            device_id: device,
            dpop_device_key,
            session_credential: session_grant.grant_jwt.clone(),
            session_grant: persisted_session_grant,
        })));
    }
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
            identity_creation_state: Some(lease.state),
            reserved_identity: lease.reserved_identity.clone(),
            identity_abandonment: None,
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
            identity_creation_state: None,
            reserved_identity: None,
            identity_abandonment: None,
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
        identity_creation_state: None,
        reserved_identity: None,
        identity_abandonment: None,
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

fn returning_oidc_login(
    scaffold: &crate::identity::account_auth::PersistedOidcScaffold,
    principal_id: arkret_sdk::DidCoreId,
    device_id: arkret_sdk::DeviceId,
    audience: arkret_sdk::DidCoreId,
    returned_state: &str,
    authorization_code: &str,
) -> Result<OidcLogin, String> {
    if scaffold.expected_nonce.trim().is_empty() {
        return Err("Sign-in state is missing the OIDC nonce.".to_owned());
    }
    Ok(OidcLogin {
        principal_id,
        device_id: Some(device_id),
        requested_scope: Vec::new(),
        // The OIDC proof challenge is the authorization transaction nonce.
        // Reusing it binds the holder signature to the same transaction that
        // the Account Authority verifies during the code exchange.
        challenge: scaffold.expected_nonce.clone(),
        audience,
        issuer: scaffold.issuer.clone(),
        client_id: scaffold.client_id.clone(),
        redirect_uri: scaffold.callback_uri.clone(),
        state: returned_state.to_owned(),
        nonce: scaffold.expected_nonce.clone(),
        authorization_code: authorization_code.to_owned(),
        code_verifier: scaffold.code_verifier.clone(),
    })
}

fn persisted_session_grant_from_state(
    grant: &SessionGrantState,
    session_private_key_pem: &str,
    principal_server_url: &str,
    device_id: &str,
) -> PersistedSessionGrant {
    PersistedSessionGrant {
        grant_jwt: grant.grant_jwt.clone(),
        session_private_key_pem: session_private_key_pem.to_owned(),
        grant_id: grant.grant_id.as_str().to_owned(),
        audience: grant.audience.to_string(),
        principal_id: grant.principal_id.to_string(),
        device_id: device_id.to_owned(),
        principal_server_url: principal_server_url.to_owned(),
        grant_expires_at: Some(grant.expires_at),
        stored_at: Utc::now(),
    }
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
    crate::identity::account_auth::persist_reconciled_handoff(store, pending_handoff)
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
            identity_creation_state: Some(arkret_sdk::IdentityCreationLeaseState::Active),
            reserved_identity: None,
            identity_abandonment: None,
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
    fn sign_in_recovers_pending_handoff_holder_from_secure_grant_binding_seed() {
        let mut store = crate::state::isolated_store_for_tests("recover-pending-handoff-holder");
        let secure_store = crate::secure_key_store::MemorySecureKeyStore::default();
        let mut handoff = pending_handoff_for_test(
            "ak:request:019f0000-0000-7000-8000-000000000011",
            "alice:auth.example",
        );
        let pending_store = crate::secure_key_store::PendingLocalStore::new(
            arkret_sdk::DeviceId::new(handoff.device_id.clone()).unwrap(),
        );
        let seed = pending_store
            .ensure_grant_binding_seed(&secure_store)
            .expect("grant-binding seed")
            .seed;
        let expected = dpop_record_for_seed(seed);
        handoff.holder_jkt = expected.jkt.clone();
        let device_id = handoff.device_id.clone();
        store
            .set_pending_account_handoff(Some(handoff))
            .expect("pending handoff");

        assert!(!store.can_resume_pending_login(&device_id));
        assert!(recover_pending_handoff_for_sign_in(
            &mut store,
            &secure_store,
            &device_id
        ));
        assert_eq!(
            store.dpop_device_key().expect("public holder record").jkt,
            expected.jkt
        );
    }

    #[test]
    fn sign_in_starts_fresh_when_pending_handoff_holder_is_missing() {
        let mut store = crate::state::isolated_store_for_tests("missing-pending-handoff-holder");
        let secure_store = crate::secure_key_store::MemorySecureKeyStore::default();
        let handoff = pending_handoff_for_test(
            "ak:request:019f0000-0000-7000-8000-000000000012",
            "alice:auth.example",
        );
        let device_id = handoff.device_id.clone();
        store
            .set_pending_account_handoff(Some(handoff))
            .expect("pending handoff");

        assert!(!recover_pending_handoff_for_sign_in(
            &mut store,
            &secure_store,
            &device_id
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
            discard_failed_oidc_callback("Account Authority handoff failed".to_owned()),
            "Account Authority handoff failed Start sign-in again."
        );
    }

    #[test]
    fn returning_login_principal_mismatch_fails_closed_with_specific_guidance() {
        assert_eq!(
            discard_failed_oidc_callback(
                "Account Authority session-grant issue failed: principal binding mismatch"
                    .to_owned()
            ),
            "The account authenticated at the Account Authority does not match this local device. No device state was changed; sign in again with the account already stored on this device."
        );
    }

    #[test]
    fn revoked_returning_device_is_not_silently_recreated() {
        assert_eq!(
            discard_failed_oidc_callback(
                "Account Authority session-grant issue failed: device_revoked".to_owned()
            ),
            "This locally retained device is no longer authorized by the principal. Use the new-device recovery flow; the old device identity was not reused."
        );
    }

    #[test]
    fn oidc_callback_restores_bootstrap_device_seed_scope() {
        let _lock = seed_scope_test_lock();
        let _reset = SeedScopeReset::new();
        crate::secure_key_store::set_active_device_seed_scope(Some("did:web:old.example"));

        restore_oidc_callback_device_seed_scope("ak:device:01964137-0000-7000-8000-000000000001")
            .expect("pending local store");

        assert_eq!(crate::secure_key_store::active_device_seed_scope(), None);
        assert_eq!(
            crate::secure_key_store::pending_login_device_id().as_deref(),
            Some("ak:device:01964137-0000-7000-8000-000000000001")
        );
    }

    #[test]
    fn account_first_sign_in_has_no_returning_principal() {
        let store = crate::state::isolated_store_for_tests("account-first-fresh-device");
        assert_eq!(returning_sign_in_principal(&store, "").unwrap(), None);
    }

    #[test]
    fn returning_sign_in_keeps_the_resolvable_principal_assertion() {
        let store = crate::state::isolated_store_for_tests("returning-principal");
        let actor = "did:webvh:z6mkfixture:alice.example";

        assert_eq!(
            returning_sign_in_principal(&store, actor)
                .unwrap()
                .expect("returning principal")
                .as_str(),
            actor
        );
    }

    #[test]
    fn returning_device_bypasses_only_a_matching_bound_handoff() {
        let principal =
            arkret_sdk::DidFullId::new("did:webvh:z6mkfixture:alice.example".to_owned()).unwrap();
        let principal_core = arkret_sdk::project_full_id_to_core_id(&principal).unwrap();
        let mut handoff = pending_handoff_for_test(
            "ak:request:019f0000-0000-7000-8000-000000000013",
            "alice:auth.example",
        );

        assert!(returning_device_can_bypass_handoff(
            None, &principal, false, false
        ));
        assert!(
            !returning_device_can_bypass_handoff(Some(&handoff), &principal, false, false,),
            "an unfinished identity creation must keep its fenced handoff"
        );

        handoff.bound_principal_id = Some(principal_core.to_string());
        assert!(
            returning_device_can_bypass_handoff(Some(&handoff), &principal, false, true),
            "a matching bound handoff may be bypassed only after local recovery readiness is complete"
        );
        assert!(
            !returning_device_can_bypass_handoff(Some(&handoff), &principal, true, true),
            "a pending registration checkpoint must always resume before ordinary login"
        );

        handoff.bound_principal_id = Some("ak:did_core:web:bob.example".to_owned());
        assert!(
            !returning_device_can_bypass_handoff(Some(&handoff), &principal, false, true,),
            "a foreign bound handoff must never be discarded by local account state"
        );
    }

    #[test]
    fn returning_oidc_session_grant_binds_challenge_to_transaction_nonce() {
        let scaffold = crate::identity::account_auth::PersistedOidcScaffold {
            expected_state: "state".to_owned(),
            expected_nonce: "oidc-transaction-nonce".to_owned(),
            code_verifier: "pkce-verifier".to_owned(),
            client_id: "inkson".to_owned(),
            principal_server_url: "https://principal.example".to_owned(),
            device_id: "ak:device:019f0000-0000-7000-8000-000000000001".to_owned(),
            principal_audience: "ak:did_core:webvh:z6mkfixture:principal.example".to_owned(),
            callback_uri: "https://app.example/auth/callback".to_owned(),
            authorize_url: "https://auth.example/authorize".to_owned(),
            issuer: "https://auth.example".to_owned(),
            gate_account_base: "https://auth.example/_arkret/gate/account".to_owned(),
            principal_trust_domain: "ak:trust_domain:auth.example".to_owned(),
            expected_principal_full_id: None,
        };
        let login = returning_oidc_login(
            &scaffold,
            arkret_sdk::DidCoreId::new(
                "ak:did_core:webvh:z6mkfixture:principal.example".to_owned(),
            )
            .unwrap(),
            arkret_sdk::DeviceId::new("ak:device:019f0000-0000-7000-8000-000000000001".to_owned())
                .unwrap(),
            arkret_sdk::DidCoreId::new(
                "ak:did_core:webvh:z6mkfixture:principal.example".to_owned(),
            )
            .unwrap(),
            "state",
            "authorization-code",
        )
        .unwrap();

        let request = login.into_unsigned_session_grant_request().unwrap();
        assert_eq!(request.proof.challenge, scaffold.expected_nonce);
        assert_eq!(
            request.proof.nonce.as_deref(),
            Some("oidc-transaction-nonce")
        );
    }

    #[test]
    fn returning_oidc_session_grant_rejects_missing_transaction_nonce() {
        let mut scaffold = crate::identity::account_auth::PersistedOidcScaffold {
            expected_state: "state".to_owned(),
            expected_nonce: "nonce".to_owned(),
            code_verifier: "pkce-verifier".to_owned(),
            client_id: "inkson".to_owned(),
            principal_server_url: "https://principal.example".to_owned(),
            device_id: "ak:device:019f0000-0000-7000-8000-000000000001".to_owned(),
            principal_audience: "ak:did_core:webvh:z6mkfixture:principal.example".to_owned(),
            callback_uri: "https://app.example/auth/callback".to_owned(),
            authorize_url: "https://auth.example/authorize".to_owned(),
            issuer: "https://auth.example".to_owned(),
            gate_account_base: "https://auth.example/_arkret/gate/account".to_owned(),
            principal_trust_domain: "ak:trust_domain:auth.example".to_owned(),
            expected_principal_full_id: None,
        };
        scaffold.expected_nonce = "   ".to_owned();

        let error = returning_oidc_login(
            &scaffold,
            arkret_sdk::DidCoreId::new(
                "ak:did_core:webvh:z6mkfixture:principal.example".to_owned(),
            )
            .unwrap(),
            arkret_sdk::DeviceId::new("ak:device:019f0000-0000-7000-8000-000000000001".to_owned())
                .unwrap(),
            arkret_sdk::DidCoreId::new(
                "ak:did_core:webvh:z6mkfixture:principal.example".to_owned(),
            )
            .unwrap(),
            "state",
            "authorization-code",
        )
        .unwrap_err();

        assert_eq!(error, "Sign-in state is missing the OIDC nonce.");
    }

    #[test]
    fn returning_sign_in_requires_the_durable_device_identity_key() {
        let secure_store = crate::secure_key_store::MemorySecureKeyStore::default();
        let principal = arkret_sdk::DidFullId::new("did:web:alice.example".to_owned()).unwrap();
        let principal_core = arkret_sdk::project_full_id_to_core_id(&principal).unwrap();
        let user_store = crate::secure_key_store::UserLocalStore::new(principal_core);
        let device =
            arkret_sdk::DeviceId::new("ak:device:01964137-0000-7000-8000-000000000001".to_owned())
                .unwrap();
        user_store.save_device_id(&secure_store, &device).unwrap();

        assert_eq!(
            returning_device_id(&secure_store, &principal, device.as_str()).unwrap(),
            None,
            "a public device id without its long-term signing key is a new device"
        );

        user_store
            .save_signing_seed(&secure_store, &[41_u8; 32])
            .unwrap();
        assert_eq!(
            returning_device_id(
                &secure_store,
                &principal,
                "ak:device:01964137-0000-7000-8000-000000000099",
            )
            .unwrap()
            .as_deref(),
            Some(device.as_str()),
            "secure storage is authoritative over a stale public config"
        );
    }

    #[test]
    fn completed_login_dpop_key_preserves_returning_account_key_material() {
        let _lock = seed_scope_test_lock();
        let _reset = SeedScopeReset::new();
        let mut store = crate::state::isolated_store_for_tests("completed-login-dpop-key");
        let secure_store = crate::secure_key_store::MemorySecureKeyStore::default();
        let actor = "did:web:alice.example";
        let principal_id = arkret_sdk::DidFullId::new(actor.to_owned()).expect("full principal id");
        let device = "ak:device:01964137-0000-7000-8000-000000000001";
        let old_seed = [3_u8; 32];
        let new_record = dpop_record_for_seed([7_u8; 32]);

        crate::secure_key_store::store_signing_seed_scoped(&secure_store, Some(actor), &old_seed)
            .expect("old account seed");

        persist_completed_login_dpop_key(
            &mut store,
            &secure_store,
            &principal_id,
            device,
            &new_record,
        )
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
