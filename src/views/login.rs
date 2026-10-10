use arkret_sdk::http_client::{Auth, ClientBuilder};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::Utc;
use dioxus::prelude::*;
use dioxus_router::Link;
#[cfg(not(target_arch = "wasm32"))]
use dioxus_router::hooks::use_navigator;
use garth::{
    AccountHandoffDisposition, BoundSessionRoute, LocalEvidenceHydration,
    LocalEvidenceUnavailableReason, OidcAccountHandoffInput, ReturningDeviceCandidate,
    SessionEngine, SessionGrantState,
};

use crate::components::UiIcon;
use crate::config::{
    LocalConfigStore, normalize_device_id, normalize_server_url, same_server_url,
    station_options_for,
};
use crate::identity::account_auth::{
    AuthorityResolver, OidcEntryPoint, build_oidc_authorize_scaffold,
    build_persisted_oidc_scaffold, capture_current_browser_callback_url,
    clear_persisted_oidc_scaffold, extract_authorization_code_from_callback,
    extract_error_description_from_callback, extract_error_from_callback,
    extract_state_from_callback, fetch_oidc_discovery, open_oidc_authorize_url,
    persist_oidc_scaffold, restore_oidc_scaffold,
};
#[cfg(not(target_arch = "wasm32"))]
use crate::routes::Route;
use crate::state::{LocalStateStore, PersistedSessionGrant};
use crate::transport::TransportClient;
use crate::ui::button::{Button, ButtonVariant};
use crate::ui::card::Card;
use crate::ui::input::Input;
use crate::ui::label::Label;
use crate::views::helpers::{actor_display_label, persist_config, short_protocol_id};

mod controller;
mod model;
mod session;
#[cfg(test)]
mod tests;

use controller::*;
pub(crate) use model::*;
pub(crate) use session::*;

#[component]
pub fn LoginPanel(
    principal_id: Signal<Option<arkret_sdk::DidCoreId>>,
    device_id: Signal<String>,
    token: Signal<String>,
    config_store: Signal<LocalConfigStore>,
    mut locale: Signal<crate::i18n::UiLocale>,
    auto_capture_callback: bool,
    #[props(default)] session_error: Option<String>,
    on_login: EventHandler<()>,
) -> Element {
    // A4 — base_url / state_store from session context instead of props.
    let session_context = crate::app::SessionContext::get();
    let mut base_url = session_context.base_url;
    let mut active_account = session_context.active_account;
    let state_store = session_context.state_store;
    let session_generation = session_context.session_generation;
    let i18n = use_context::<crate::i18n::I18nSignal>();
    let session = use_context::<crate::runtime::services::RuntimeServices>()
        .session
        .clone();
    #[cfg(not(target_arch = "wasm32"))]
    let navigator = use_navigator();
    let pending_device_id = use_signal(|| {
        active_account
            .peek()
            .as_ref()
            .map(|account| account.device_id.to_string())
            .unwrap_or_else(crate::config::new_device_id)
    });
    let mut auth_status = use_signal(|| {
        if auto_capture_callback {
            "Completing sign in...".to_owned()
        } else {
            String::new()
        }
    });
    let mut is_busy = use_signal(|| auto_capture_callback);
    let controller = LoginController {
        is_busy,
        auth_status,
    };
    let mut callback_started = use_signal(|| false);
    let mut callback_retry_url = use_signal(|| Option::<String>::None);
    let mut connection_change =
        use_signal(|| Option::<crate::station_connection::ConnectionTrustChange>::None);
    let mut state_store_write = state_store;
    // Whether the styled Station preset list is expanded. Inkson is a
    // neutral client: the field is a free-text URL input that the user can edit
    // to point at ANY server, with this custom-styled dropdown offering the
    // configured presets (and the current value) as one-click choices.
    let mut server_menu_open = use_signal(|| false);
    // Station presets come from local config, with the current value
    // and the local development default merged in.
    let station_options = station_options_for(&base_url(), &config_store.read().load().stations);

    let callback_session = use_signal(|| session.clone());
    use_future(move || async move {
        if !auto_capture_callback || callback_started() {
            return;
        }
        let callback_url = match capture_current_browser_callback_url() {
            Ok(url) => url,
            Err(error) => {
                auth_status.set(format!("Could not read callback URL: {error}"));
                is_busy.set(false);
                return;
            }
        };
        let returned_state = match extract_state_from_callback(&callback_url) {
            Ok(Some(state)) => state,
            Ok(None) => {
                auth_status.set("Callback did not include state.".to_owned());
                is_busy.set(false);
                return;
            }
            Err(error) => {
                auth_status.set(format!("Could not read callback state: {error}"));
                is_busy.set(false);
                return;
            }
        };
        // Cross-instance claim: the same authorization transaction is exchanged
        // once, while a later transaction in a BFCache-restored wasm instance is
        // allowed to complete under its distinct state.
        if !claim_oidc_callback_completion(&returned_state) {
            return;
        }
        callback_started.set(true);
        is_busy.set(true);

        let callback_generation = *session_generation.peek();
        let callback_device = pending_device_id();
        let resume_url = returning_callback_resume_url(&callback_url, &returned_state).ok();
        let result = finish_oidc_callback(callback_url, callback_device, state_store_write).await;
        if *session_generation.peek() != callback_generation {
            return;
        }
        match result {
            Ok(OidcCallbackOutcome::Login(completed)) => {
                callback_retry_url.set(resume_url.clone());
                let _commit = crate::identity::session_refresh::session_credential_mutation_lock()
                    .lock()
                    .await;
                if *session_generation.peek() != callback_generation {
                    return;
                }
                let mut account = completed.account.clone();
                let mut profiles = config_store.read().load_profiles();
                let profile_id =
                    match profiles.upsert_and_activate(crate::config::AccountProfile::new(
                        account.clone(),
                        completed.session_credential.clone(),
                    )) {
                        Ok(profile_id) => profile_id,
                        Err(error) => {
                            auth_status.set(format!(
                                "Could not prepare the accepted account profile: {error}"
                            ));
                            is_busy.set(false);
                            return;
                        }
                    };
                account.profile_id = profile_id;
                let station_url = normalize_server_url(account.server_url.as_str());
                let secure_store = crate::secure_key_store::default_secure_key_store("inkson");
                let prepared_keys = match prepare_completed_login_dpop_key(
                    secure_store.as_ref(),
                    &account,
                    completed.pending_device_id.as_str(),
                    &completed.dpop_device_key,
                )
                .await
                {
                    Ok(prepared) => prepared,
                    Err(error) => {
                        auth_status.set(format!(
                            "Could not prepare the returning-device session key: {error}"
                        ));
                        is_busy.set(false);
                        return;
                    }
                };
                let account_store = match crate::secure_key_store::UserLocalStore::new(
                    account.authority.clone(),
                    account.device_id.clone(),
                ) {
                    Ok(store) => store,
                    Err(error) => {
                        auth_status.set(format!(
                            "Could not open the accepted account secure scope: {error}"
                        ));
                        is_busy.set(false);
                        return;
                    }
                };
                if let Err(error) = crate::state::store_session_grant_in_user_secure_store_durable(
                    &account_store,
                    secure_store.as_ref(),
                    &completed.session_grant,
                )
                .await
                {
                    auth_status.set(format!(
                        "Could not durably store the accepted account session: {error}"
                    ));
                    is_busy.set(false);
                    return;
                }
                {
                    let mut store = config_store.write();
                    store.save(crate::config::ClientConfig::authenticated(
                        account.clone(),
                        completed.session_credential.clone(),
                    ));
                    if let Some(error) = store.persist_error() {
                        auth_status.set(format!(
                            "Could not persist the accepted account configuration: {error}"
                        ));
                        is_busy.set(false);
                        return;
                    }
                    if let Err(error) = store.save_profiles(&profiles) {
                        auth_status.set(format!(
                            "Could not persist the accepted account profile: {error}"
                        ));
                        is_busy.set(false);
                        return;
                    }
                }
                if let Err(error) = promote_completed_login_state(
                    &mut state_store_write.write(),
                    secure_store.as_ref(),
                    &account,
                    &completed.dpop_device_key,
                    prepared_keys,
                    completed.personal_handle.as_deref(),
                    completed.session_grant.clone(),
                ) {
                    auth_status.set(format!("Could not commit the accepted account: {error}"));
                    is_busy.set(false);
                    return;
                }
                let account_barrier = state_store_write.write().begin_durable_flush();
                let committed = match account_barrier {
                    Ok(barrier) => barrier.wait().await,
                    Err(error) => Err(error),
                };
                if let Err(error) = committed {
                    auth_status.set(format!(
                        "Could not durably commit the accepted account: {error}"
                    ));
                    is_busy.set(false);
                    return;
                }
                if let Err(error) = consume_completed_login_pending_store(
                    secure_store.as_ref(),
                    &crate::secure_key_store::PendingLocalStore::new(
                        completed.pending_device_id.clone(),
                    ),
                ) {
                    auth_status.set(format!(
                        "Could not finish the accepted account commit: {error}"
                    ));
                    is_busy.set(false);
                    return;
                }
                if let Err(error) = crate::identity::account_auth::clear_account_handoff_grant(
                    &completed.consumed_handoff,
                ) {
                    tracing::warn!(
                        %error,
                        "clear consumed account handoff after accepted account commit failed"
                    );
                }
                if let Err(error) =
                    crate::identity::account_auth::clear_prepared_returning_session_request(
                        &completed.consumed_handoff,
                    )
                {
                    tracing::warn!(
                        %error,
                        "clear returning-session replay checkpoint after accepted account commit failed"
                    );
                }
                if *session_generation.peek() != callback_generation {
                    return;
                }
                if let Err(error) = clear_persisted_oidc_scaffold(&returned_state) {
                    tracing::warn!(%error, "clear committed callback scaffold failed");
                }
                active_account.set(Some(account.clone()));
                base_url.set(station_url.clone());
                principal_id.set(Some(account.principal_id().clone()));
                device_id.set(account.device_id.to_string());
                crate::app::accept_authenticated_session(
                    &callback_session.peek(),
                    session_generation,
                    token,
                    completed.session_credential.clone(),
                );
                auth_status.set("Signed in on this authorized device.".to_owned());
                on_login.call(());
            }
            Ok(OidcCallbackOutcome::Onboarding { preferred_locale }) => {
                // The pending handoff owns onboarding routing. Do not rewrite
                // last-known account/device configuration before a successful
                // authenticated commit; cancellation and reload must still be
                // able to recover the previous account-scoped secure store.
                token.set(String::new());
                apply_authenticated_account_locale(
                    preferred_locale,
                    state_store_write,
                    &mut locale,
                );
                auth_status.set(
                    "Account authenticated. Continue identity custody and binding.".to_owned(),
                );
                #[cfg(target_arch = "wasm32")]
                if let Some(window) = web_sys::window() {
                    if let Err(error) = window.location().replace("/onboarding") {
                        tracing::warn!(?error, "OIDC onboarding browser navigation failed");
                    }
                } else {
                    tracing::warn!("OIDC onboarding browser window unavailable");
                }
                #[cfg(not(target_arch = "wasm32"))]
                if let Some(failure) = navigator.replace(Route::Onboarding) {
                    tracing::warn!(?failure, "OIDC onboarding navigation failed");
                }
            }
            Ok(OidcCallbackOutcome::RetryableSessionExchange { message }) => {
                callback_retry_url.set(resume_url);
                auth_status.set(format!(
                    "{message} The signed request was preserved. Use Retry verification below to resume it."
                ));
            }
            Ok(OidcCallbackOutcome::ReturningDeviceBlocked { reason, message }) => {
                tracing::warn!(?reason, %message, "returning device session exchange was blocked");
                auth_status.set(returning_device_block_message(reason).to_owned());
            }
            Ok(OidcCallbackOutcome::LocalEvidenceDiagnostics { reason }) => {
                auth_status.set(local_evidence_diagnostics_message(&reason));
            }
            Err(error) => auth_status.set(discard_failed_oidc_callback(error)),
        }
        is_busy.set(false);
    });

    // Coauth remains authoritative for which account the user authenticates.
    // Every fresh OIDC callback first creates an account handoff. Local account
    // and device evidence is only a returning candidate checked after the
    // handoff reports the authenticated account as Bound.
    let mut launch_sign_in = move || {
        let principal = base_url();
        let ui_locale = i18n.read().0.code().to_owned();
        let loaded_config = config_store.read().load();
        // The returning-principal assertion is a resolvable DID, so it comes
        // from the account's accepted resolution. `principal_id()` is the
        // projected `ak:did_core:` core id, which is deliberately not
        // repairable into resolution material and would fail closed here.
        let live_actor = active_account()
            .map(|account| account.did().to_string())
            .unwrap_or_default();
        let persisted_actor = if live_actor.trim().is_empty() {
            loaded_config
                .active_account
                .as_ref()
                .map(|account| account.did().to_string())
                .unwrap_or_default()
        } else {
            live_actor
        };
        let persisted_account = loaded_config.active_account.clone();
        let returning_principal = {
            match returning_sign_in_principal(&persisted_actor) {
                Ok(principal) => principal,
                Err(error) => {
                    auth_status.set(error);
                    return;
                }
            }
        };
        let reset_state_store = state_store;
        is_busy.set(true);
        auth_status.set("Opening server sign-in...".to_owned());
        controller.launch_sign_in(
            principal,
            ui_locale,
            returning_principal,
            persisted_account,
            reset_state_store,
        );
    };

    rsx! {
        Card { class: "auth-panel", "data-testid": "login-panel", role: "region", "aria-label": crate::i18n::tr("login.title"),
            if let Some(error) = session_error {
                div { class: "auth-error", role: "alert", "data-testid": "login-session-error",
                    div { class: "auth-error-mark", "aria-hidden": "true", "!" }
                    div { class: "auth-error-content",
                        p { "{error}" }
                    }
                }
            }
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
                Label { html_for: "login-server-url-input", {crate::i18n::tr("login.station")} }
                // Inkson is a neutral client: this is a free-text Station URL the user can edit to point at ANY server. The
                // custom-styled dropdown below offers the configured presets
                // (and the current value) as one-click choices — a styled
                // replacement for the native `<datalist>` (whose popup is
                // unstyleable). Selecting a preset only fills the text field;
                // the user is free to keep typing a custom address.
                div { class: "auth-combobox", "data-testid": "login-server-combobox",
                    Input {
                        id: "login-server-url-input",
                        "data-testid": "login-server-url",
                        "aria-label": crate::i18n::tr("login.station_url"),
                        autocomplete: "off",
                        value: "{base_url}",
                        disabled: is_busy(),
                        oninput: move |event: FormEvent| {
                            let value = normalize_server_url(&event.value());
                            base_url.set(value.clone());
                            token.set(String::new());
                            persist_config(config_store, value, principal_id(), device_id(), String::new());
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
                            for option_url in station_options.iter() {
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
                                                principal_id(),
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
                            {crate::i18n::tr("login.create_identity")}
                        }
                    }
                }

                if !auth_status().is_empty()
                    && (connection_change().is_none() || !auth_status().contains("Station identity or authentication changed")) {
                    div { class: "auth-status", "data-testid": "auth-status", role: "status", "{auth_status}" }
                }
                if !auto_capture_callback && connection_change().is_none()
                    && auth_status().contains("Station identity or authentication changed") {
                    Button {
                        variant: ButtonVariant::Ghost,
                        disabled: is_busy(),
                        onclick: move |_| {
                            is_busy.set(true);
                            let selected = base_url();
                            spawn(async move {
                                match crate::station_connection::discover(&selected).await {
                                    Err(error) => {
                                        if let Some(change) = error.downcast_ref::<crate::station_connection::ConnectionTrustChange>() {
                                            connection_change.set(Some(change.clone()));
                                        } else { auth_status.set(error.to_string()); }
                                    }
                                    Ok(_) => auth_status.set("The server connection still matches the saved identity.".into()),
                                }
                                is_busy.set(false);
                            });
                        },
                        {crate::i18n::tr("login.connection.review")}
                    }
                }
                if let Some(change) = connection_change() {
                    div { class: "auth-status auth-connection-review", role: "alert",
                        "data-testid": "station-connection-review",
                        {connection_review_details(&change)}
                        div { class: "auth-connection-actions",
                        Button {
                            variant: ButtonVariant::Ghost,
                            disabled: is_busy(),
                            onclick: move |_| connection_change.set(None),
                            {crate::i18n::tr("login.connection.keep")}
                        }
                        Button {
                            variant: ButtonVariant::Primary,
                            disabled: is_busy() || !same_server_url(&base_url(), &change.candidate.base_url),
                            onclick: {
                                let session = session.clone();
                                move |_| {
                                    let change = change.clone();
                                    let session = session.clone();
                                    is_busy.set(true);
                                    spawn(async move {
                                        if let Err(error) = crate::station_connection::clear_pending_authentication(
                                            &mut state_store_write.write(), &change.previous.base_url,
                                        ) {
                                            auth_status.set(error.to_string());
                                            is_busy.set(false);
                                            return;
                                        }
                                        match crate::station_connection::confirm_change(&change).await {
                                            Ok(()) => {
                                                session.invalidate("Station connection changed; sign in again");
                                                callback_retry_url.set(None);
                                                connection_change.set(None);
                                                auth_status.set("New connection accepted. Start a new sign-in.".into());
                                            }
                                            Err(error) => auth_status.set(error.to_string()),
                                        }
                                        is_busy.set(false);
                                    });
                                }
                            },
                            {crate::i18n::tr("login.connection.trust")}
                        }
                        }
                    }
                }
                if let Some(resume_url) = callback_retry_url() {
                    a { href: "{resume_url}", "data-testid": "retry-session-verification", {crate::i18n::tr("login.retry_verification")} }
                }

                // G3.Y0 — session state surface for cotest's
                // `identity/account-device-auth.spec.ts`. These testids
                // expose the live session triple (status / device id /
                // actor DID) so a refresh assertion can see them rotate
                // without scraping log lines.
                {
                    let token_value = token();
                    let device_value = device_id();
                    let actor_value = crate::app::principal_id_owned(principal_id());
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
                                        controller.refresh_session(session, token, on_login);
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

// Translate only names emitted by the Station review model. Unknown future
// field names and every old/new value remain literal, including dotted keys.
fn connection_review_field_label(label: &str) -> String {
    label
        .split(" · ")
        .map(|field| {
            let key = match field {
                "Server identity" => Some("login.connection.field.identity"),
                "Trust domain" => Some("login.connection.field.trust_domain"),
                "Sign-in service" => Some("login.connection.field.sign_in_service"),
                "Origin" => Some("login.connection.field.origin"),
                "URL" => Some("login.connection.field.url"),
                "Sign-in method" => Some("login.connection.field.method"),
                "Type" => Some("login.connection.field.type"),
                "Issuer" => Some("login.connection.field.issuer"),
                "Provider" => Some("login.connection.field.provider"),
                "Provider discovery" => Some("login.connection.field.provider_discovery"),
                "Client" => Some("login.connection.field.client"),
                "Permissions" => Some("login.connection.field.permissions"),
                "Grant exchange" => Some("login.connection.field.grant_exchange"),
                "Identity binding methods" => {
                    Some("login.connection.field.identity_binding_methods")
                }
                _ => None,
            };
            if let Some(key) = key {
                return crate::i18n::tr(key);
            }
            if let Some(numbered) = field.strip_prefix("Sign-in method ")
                && let Some((index, method)) = numbered.split_once(" (")
                && !index.is_empty()
                && index.bytes().all(|byte| byte.is_ascii_digit())
                && index.parse::<usize>().is_ok_and(|index| index > 0)
                && let Some(method) = method.strip_suffix(')')
            {
                return crate::i18n::tr_args(
                    "login.connection.field.numbered_method",
                    &[("index", index.to_owned()), ("method", method.to_owned())],
                );
            }
            field.to_owned()
        })
        .collect::<Vec<_>>()
        .join(" · ")
}

fn connection_review_details(change: &crate::station_connection::ConnectionTrustChange) -> Element {
    rsx! {
        strong { {crate::i18n::tr("login.connection.changed")} }
        ul { class: "auth-connection-summary",
            if change.previous.service_id != change.candidate.service_id {
                li { {crate::i18n::tr("login.connection.identity_changed")} }
            }
            if change.previous.trust_domain != change.candidate.trust_domain {
                li { {crate::i18n::tr("login.connection.domain_changed")} }
            }
            if change.previous.auth_metadata != change.candidate.auth_metadata {
                li { {crate::i18n::tr("login.connection.provider_changed")} }
            }
        }
        p { {crate::i18n::tr("login.connection.warning")} }
        details { class: "auth-connection-details",
            summary { {crate::i18n::tr("login.connection.details")} }
            p { class: "auth-connection-server", {crate::i18n::tr_args("login.connection.server", &[("url", change.candidate.base_url.clone())])} }
            for detail in crate::station_connection::connection_changes(&change) {
                div { class: "auth-connection-field",
                    strong { {connection_review_field_label(&detail.label)} }
                    dl {
                        dt { {crate::i18n::tr("login.connection.previous")} }
                        dd { "{detail.previous}" }
                        dt { {crate::i18n::tr("login.connection.new")} }
                        dd { "{detail.candidate}" }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod connection_review_locale_tests {
    use std::cell::RefCell;
    use std::collections::BTreeMap;
    use std::rc::Rc;

    use super::*;
    use crate::i18n::{I18nSignal, UiLocale};

    type LocaleHandle = Rc<RefCell<Option<I18nSignal>>>;

    fn retained_review(
        (handle, change): (
            LocaleHandle,
            crate::station_connection::ConnectionTrustChange,
        ),
    ) -> Element {
        let locale = use_context_provider(|| crate::i18n::init_i18n_with_locale(UiLocale::En));
        *handle.borrow_mut() = Some(locale);
        let change = use_signal(move || change);
        rsx! {
            div {
                {connection_review_details(&change.read())}
                p { {connection_review_field_label("future_label.{url} / 原文")} }
                p { {connection_review_field_label("Sign-in method unknown (oidc)")} }
            }
        }
    }

    fn apply_text_edits(
        text: &mut BTreeMap<usize, String>,
        edits: dioxus::core::Mutations,
    ) -> usize {
        let mut changed = 0;
        for edit in edits.edits {
            match edit {
                dioxus::core::Mutation::CreateTextNode { id, value }
                | dioxus::core::Mutation::SetText { id, value } => {
                    text.insert(id.0, value);
                    changed += 1;
                }
                _ => {}
            }
        }
        changed
    }

    #[test]
    fn station_review_rerenders_retained_changes_without_translating_original_values() {
        let mut previous: arkret_sdk::StationConnectionBinding = serde_json::from_value(serde_json::json!({
            "base_url": "https://station.example/",
            "service_id": "ak:did_core:webvh:z6mkfixture",
            "trust_domain": "ak:trust_domain:station.example",
            "auth_metadata": {
                "account_authority": { "origin": "https://auth.example", "gate_account_base_url": "https://auth.example/_arkret/gate/account" },
                "methods": [{ "method": "oidc", "issuer_uri": "https://auth.example/", "client_id": "login.connection.new", "scopes": ["openid", "profile"], "grant_exchange": { "kind": "account_handoff" } }]
            }
        })).unwrap();
        let mut second = previous.auth_metadata.methods[0].clone();
        second.client_id = Some("unchanged-client".to_owned());
        previous.auth_metadata.methods.push(second);
        let mut candidate = previous.clone();
        candidate.service_id = arkret_sdk::DidCoreId::new("ak:did_core:webvh:z6mkchanged").unwrap();
        candidate.trust_domain =
            arkret_sdk::TrustDomainId::new("ak:trust_domain:new-station.example").unwrap();
        candidate.auth_metadata.methods[0].client_id = Some("{index} {method} / 原文".to_owned());
        let change = crate::station_connection::ConnectionTrustChange {
            previous,
            candidate,
        };
        let raw_values = crate::station_connection::connection_changes(&change)
            .into_iter()
            .flat_map(|detail| [detail.previous, detail.candidate])
            .collect::<Vec<_>>();
        let handle = Rc::new(RefCell::new(None));
        let mut dom = VirtualDom::new_with_props(retained_review, (handle.clone(), change));
        let mut text = BTreeMap::new();
        apply_text_edits(&mut text, dom.rebuild_to_vec());
        let english = text.clone();
        assert!(
            text.values()
                .any(|value| value == "Sign-in method 1 (oidc) · Client")
        );
        let mut locale = handle.borrow().expect("review provides locale");
        for language in [UiLocale::Zh, UiLocale::En] {
            dom.in_runtime(|| crate::i18n::set_locale(&mut locale, language));
            assert!(apply_text_edits(&mut text, dom.render_immediate_to_vec()) > 0);
            for raw in &raw_values {
                assert!(
                    text.values().any(|value| value == raw),
                    "original trust value disappeared: {raw}"
                );
            }
            for unknown in ["future_label.{url} / 原文", "Sign-in method unknown (oidc)"] {
                assert!(text.values().any(|value| value == unknown));
            }
            if language == UiLocale::Zh {
                for expected in [
                    "服务器连接已变更",
                    "服务器身份已变更",
                    "信任域已变更",
                    "登录提供方已变更",
                    "登录方式 1（oidc） · 客户端",
                    "原值",
                    "新值",
                    "服务器：https://station.example/",
                ] {
                    assert!(
                        text.values().any(|value| value == expected),
                        "review text missing: {expected}"
                    );
                }
            } else {
                assert_eq!(text, english);
            }
        }
    }
}
