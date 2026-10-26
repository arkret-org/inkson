use std::rc::Rc;

use arkret_sdk::http_client::{Auth, ClientBuilder};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::Utc;
use garth::{
    AccountHandoffDisposition, BoundSessionRoute, LocalEvidenceHydration,
    LocalEvidenceUnavailableReason, OidcAccountHandoffInput, ReturningDeviceCandidate,
    SessionEngine, SessionGrantState,
};
use glory::{Cage, Scope};

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
use crate::presentation::widgets::*;
use crate::presentation::{InksonContext, View};
use crate::routes::Route;
use crate::state::{LocalStateStore, PersistedSessionGrant};
use crate::transport::TransportClient;
use crate::views::helpers::{actor_display_label, short_protocol_id};

#[cfg(test)]
mod connection_review_tests;
mod controller;
mod model;
mod session;
#[cfg(test)]
mod tests;

use controller::*;
pub(crate) use model::*;
pub(crate) use session::*;

#[derive(Clone, Copy)]
struct LoginState {
    station: Cage<String>,
    pending_device: Cage<String>,
    status: Cage<String>,
    busy: Cage<bool>,
    callback_started: Cage<bool>,
    callback_retry_url: Cage<Option<String>>,
    connection_change: Cage<Option<crate::station_connection::ConnectionTrustChange>>,
    presets_open: Cage<bool>,
}

async fn complete_callback(context: Rc<InksonContext>, state: LoginState) {
    let auth_status = state.status;
    let is_busy = state.busy;
    let pending_device_id = state.pending_device;
    let callback_started = state.callback_started;
    let callback_retry_url = state.callback_retry_url;
    let session_generation = context.session_generation;
    let config_store = context.config_store;
    let state_store_write = context.state_store.clone();
    let active_account = context.active_account;
    let base_url = context.base_url;
    let principal_id = context.principal_id;
    let device_id = context.device_id;
    let token = context.token;
    let locale = context.locale;
    let callback_url = match capture_current_browser_callback_url() {
        Ok(url) => url,
        Err(error) => {
            auth_status
                .revise(|current| *current = format!("Could not read callback URL: {error}"));
            is_busy.revise(|current| *current = false);
            return;
        }
    };
    let returned_state = match extract_state_from_callback(&callback_url) {
        Ok(Some(state)) => state,
        Ok(None) => {
            auth_status.revise(|current| *current = "Callback did not include state.".to_owned());
            is_busy.revise(|current| *current = false);
            return;
        }
        Err(error) => {
            auth_status
                .revise(|current| *current = format!("Could not read callback state: {error}"));
            is_busy.revise(|current| *current = false);
            return;
        }
    };
    // Cross-instance claim: the same authorization transaction is exchanged
    // once, while a later transaction in a BFCache-restored wasm instance is
    // allowed to complete under its distinct state.
    if !claim_oidc_callback_completion(&returned_state) {
        return;
    }
    callback_started.revise(|current| *current = true);
    is_busy.revise(|current| *current = true);

    let callback_generation = session_generation.get_untracked();
    let callback_device = pending_device_id.get_untracked();
    let resume_url = returning_callback_resume_url(&callback_url, &returned_state).ok();
    let result =
        finish_oidc_callback(callback_url, callback_device, state_store_write.clone()).await;
    if session_generation.get_untracked() != callback_generation {
        return;
    }
    match result {
        Ok(OidcCallbackOutcome::Login(completed)) => {
            callback_retry_url.revise(|current| *current = resume_url.clone());
            let _commit = crate::identity::session_refresh::session_credential_mutation_lock()
                .lock()
                .await;
            if session_generation.get_untracked() != callback_generation {
                return;
            }
            let mut account = completed.account.clone();
            let mut profiles = config_store.with(|store| store.load_profiles());
            let mut profile = crate::config::AccountProfile::new(
                account.clone(),
                completed.session_credential.clone(),
            );
            profile.label = completed.personal_handle.clone().unwrap_or_default();
            let profile_id = match profiles.upsert_and_activate(profile) {
                Ok(profile_id) => profile_id,
                Err(error) => {
                    auth_status.revise(|current| {
                        *current =
                            format!("Could not prepare the accepted account profile: {error}")
                    });
                    is_busy.revise(|current| *current = false);
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
                    auth_status.revise(|current| {
                        *current =
                            format!("Could not prepare the returning-device session key: {error}")
                    });
                    is_busy.revise(|current| *current = false);
                    return;
                }
            };
            let account_store = match crate::secure_key_store::UserLocalStore::new(
                account.authority.clone(),
                account.device_id.clone(),
            ) {
                Ok(store) => store,
                Err(error) => {
                    auth_status.revise(|current| {
                        *current =
                            format!("Could not open the accepted account secure scope: {error}")
                    });
                    is_busy.revise(|current| *current = false);
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
                auth_status.revise(|current| {
                    *current =
                        format!("Could not durably store the accepted account session: {error}")
                });
                is_busy.revise(|current| *current = false);
                return;
            }
            let persisted = config_store.revise(|store| -> Result<(), String> {
                store.save(crate::config::ClientConfig::authenticated(
                    account.clone(),
                    completed.session_credential.clone(),
                ));
                if let Some(error) = store.persist_error() {
                    return Err(format!(
                        "Could not persist the accepted account configuration: {error}"
                    ));
                }
                if let Err(error) = store.save_profiles(&profiles) {
                    return Err(format!(
                        "Could not persist the accepted account profile: {error}"
                    ));
                }
                Ok(())
            });
            if let Err(error) = persisted {
                auth_status.revise(|current| *current = error);
                is_busy.revise(|current| *current = false);
                return;
            }
            if let Err(error) = state_store_write.write(|store| {
                promote_completed_login_state(
                    store,
                    secure_store.as_ref(),
                    &account,
                    &completed.dpop_device_key,
                    prepared_keys,
                    completed.personal_handle.as_deref(),
                    completed.session_grant.clone(),
                )
            }) {
                auth_status.revise(|current| {
                    *current = format!("Could not commit the accepted account: {error}")
                });
                is_busy.revise(|current| *current = false);
                return;
            }
            let account_barrier = state_store_write.write(|store| store.begin_durable_flush());
            let committed = match account_barrier {
                Ok(barrier) => barrier.wait().await,
                Err(error) => Err(error),
            };
            if let Err(error) = committed {
                auth_status.revise(|current| {
                    *current = format!("Could not durably commit the accepted account: {error}")
                });
                is_busy.revise(|current| *current = false);
                return;
            }
            if let Err(error) = consume_completed_login_pending_store(
                secure_store.as_ref(),
                &crate::secure_key_store::PendingLocalStore::new(
                    completed.pending_device_id.clone(),
                ),
            ) {
                auth_status.revise(|current| {
                    *current = format!("Could not finish the accepted account commit: {error}")
                });
                is_busy.revise(|current| *current = false);
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
            if session_generation.get_untracked() != callback_generation {
                return;
            }
            if let Err(error) = clear_persisted_oidc_scaffold(&returned_state) {
                tracing::warn!(%error, "clear committed callback scaffold failed");
            }
            active_account.revise(|current| *current = Some(account.clone()));
            base_url.revise(|current| *current = station_url.clone());
            principal_id.revise(|current| *current = Some(account.principal_id().clone()));
            device_id.revise(|current| *current = account.device_id.to_string());
            crate::app::accept_authenticated_session(
                &context.services.session,
                session_generation,
                token,
                completed.session_credential.clone(),
            );
            auth_status
                .revise(|current| *current = "Signed in on this authorized device.".to_owned());
            context.navigate(Route::Dashboard);
        }
        Ok(OidcCallbackOutcome::Onboarding { preferred_locale }) => {
            // The pending handoff owns onboarding routing. Do not rewrite
            // last-known account/device configuration before a successful
            // authenticated commit; cancellation and reload must still be
            // able to recover the previous account-scoped secure store.
            token.revise(|current| *current = String::new());
            apply_authenticated_account_locale(preferred_locale, state_store_write.clone(), locale);
            auth_status.revise(|current| {
                *current =
                    "Account authenticated. Continue identity custody and binding.".to_owned()
            });
            context.navigate(Route::Onboarding);
        }
        Ok(OidcCallbackOutcome::RetryableSessionExchange { message }) => {
            callback_retry_url.revise(|current| *current = resume_url);
            auth_status.revise(|current| *current = format!(
                    "{message} The signed request was preserved. Use Retry verification below to resume it."
                ));
        }
        Ok(OidcCallbackOutcome::ReturningDeviceBlocked { reason, message }) => {
            tracing::warn!(?reason, %message, "returning device session exchange was blocked");
            auth_status
                .revise(|current| *current = returning_device_block_message(reason).to_owned());
        }
        Ok(OidcCallbackOutcome::LocalEvidenceDiagnostics { reason }) => {
            auth_status.revise(|current| *current = local_evidence_diagnostics_message(&reason));
        }
        Err(error) => auth_status.revise(|current| *current = discard_failed_oidc_callback(error)),
    }
    is_busy.revise(|current| *current = false);
}

fn launch_sign_in(context: Rc<InksonContext>, state: LoginState, owner: glory::ui::WeakScope) {
    let selected = context
        .config_store
        .revise(|store| store.save_neutral_station_choice(&state.station.get_untracked()));
    let principal = match selected {
        Ok(selected) => selected,
        Err(error) => {
            state
                .status
                .revise(|value| *value = format!("Could not retain sign-in Station: {error}"));
            return;
        }
    };
    context.base_url.revise(|value| *value = principal.clone());
    state.station.revise(|value| *value = principal.clone());
    let config = context.config_store.with(LocalConfigStore::load);
    let live_account = context.active_account.get_untracked();
    let candidate = live_account.as_ref().or(config.active_account.as_ref());
    let actor = candidate
        .map(|account| account.did().to_string())
        .unwrap_or_default();
    let returning = match returning_sign_in_principal(&actor) {
        Ok(value) => value,
        Err(error) => {
            state.status.revise(|value| *value = error);
            return;
        }
    };
    state.busy.revise(|value| *value = true);
    state
        .status
        .revise(|value| *value = "Opening server sign-in...".into());
    LoginController {
        is_busy: state.busy,
        auth_status: state.status,
        owner,
    }
    .launch_sign_in(
        principal,
        context.locale.get_untracked().code().to_owned(),
        returning,
        config.active_account,
        context.state_store.clone(),
    );
}

pub fn page(scope: &Scope, context: Rc<InksonContext>, route: Route) -> View {
    use glory::ui::{text, view};
    let callback = route == Route::AuthCallback;
    let state = LoginState {
        station: scope.cage(context.base_url.get_untracked()),
        pending_device: scope.cage(
            context
                .active_account
                .get_untracked()
                .map(|account| account.device_id.to_string())
                .unwrap_or_else(crate::config::new_device_id),
        ),
        status: scope.cage(if callback {
            "Completing sign in...".into()
        } else {
            String::new()
        }),
        busy: scope.cage(callback),
        callback_started: scope.cage(false),
        callback_retry_url: scope.cage(None),
        connection_change: scope.cage(None),
        presets_open: scope.cage(false),
    };
    let active_base = context.base_url;
    scope.effect(move || {
        let base = active_base.get();
        state.station.revise(|station| *station = base);
    });
    if callback {
        let context = context.clone();
        if let Err(error) = scope.spawn(complete_callback(context, state)) {
            scope.report_error(error);
        }
    }
    let ready = scope.bond(move || !state.busy.get());
    let station_context = context.clone();
    let token = context.token;
    let station_name = context.translated(scope, "login.station_url");
    let station_control = move |field| {
        let context = station_context.clone();
        sapid::text_field()
            .unstyled()
            .field(field)
            .name(station_name)
            .value(state.station)
            .enabled(ready)
            .purpose(glory::render::Purpose::Url)
            .on_value_change(move |next| {
                state.station.revise(|value| *value = next);
                token.revise(String::clear);
            })
            .on(glory::ui::events::focus_changed, move |event| {
                if matches!(event, glory::render::Event::FocusChanged(false)) {
                    retain_station(&context, state, &state.station.get_untracked());
                }
            })
    };
    let presets_context = context.clone();
    let preset_menu = reactive(state.presets_open, move |scope, open| {
        if !open {
            return empty();
        }
        let context = presets_context.clone();
        let options = station_options_for(
            &context.base_url.get_untracked(),
            &context.config_store.with(LocalConfigStore::load).stations,
        );
        let mut children = Vec::new();
        for option in options {
            let click_context = context.clone();
            let selected = same_server_url(&option, &context.base_url.get_untracked());
            children.push(Box::new(
                sapid::button()
                    .unstyled()
                    .class(if selected {
                        "auth-combobox-option active"
                    } else {
                        "auth-combobox-option"
                    })
                    .name(option.clone())
                    .fill(
                        glory::ui::group().fill((
                            glory::ui::text()
                                .class("auth-combobox-option-url mono")
                                .content(option.clone()),
                            glory::ui::text()
                                .class("auth-combobox-option-check")
                                .content(if selected { "✓" } else { "" }),
                        )),
                    )
                    .on_press(move || {
                        retain_station(&click_context, state, &option);
                        click_context.token.revise(String::clear);
                        state.presets_open.revise(|value| *value = false);
                    }),
            ) as View);
        }
        Box::new(
            view()
                .class("auth-combobox-menu")
                .name(context.translated(scope, "login.preset_servers"))
                .fill(children),
        )
    });
    let preset_label = context.translated(scope, "login.show_preset_servers");
    let preset_toggle = glory::ui::button()
        .class("auth-combobox-toggle")
        .enabled(ready)
        .name(preset_label)
        .semantics(scope.bond(move || {
            Some(Box::new(glory::render::Semantics {
                expanded: Some(state.presets_open.get()),
                ..Default::default()
            }))
        }))
        .fill(
            glory::ui::when(state.presets_open, || {
                crate::components::ui_icon("chevron-up")
            })
            .otherwise(|| crate::components::ui_icon("chevron-down")),
        )
        .on(glory::render::EventKind::Activate, move |_| {
            state.presets_open.revise(|open| *open = !*open)
        });
    let mut preset_menu = Some(preset_menu);
    let mut preset_toggle = Some(Box::new(preset_toggle) as View);
    let station = sapid::field("login-station")
        .unstyled()
        .class("auth-station-field")
        .label(context.translated(scope, "login.station"))
        .control(move |field| {
            view().class("auth-combobox").fill((
                station_control(field),
                preset_toggle.take().unwrap_or_else(empty),
                preset_menu.take().unwrap_or_else(empty),
            ))
        });
    let button_context = context.clone();
    let owner = scope.downgrade();
    let busy_label_context = context.clone();
    let signin_label = scope.bond(move || {
        busy_label_context.tr(if state.busy.get() {
            "login.working"
        } else {
            "login.server_sign_in"
        })
    });
    let sign_in = sapid::button()
        .unstyled()
        .class("btn btn-primary auth-primary")
        .label(signin_label)
        .enabled(ready)
        .on_press(move || launch_sign_in(button_context.clone(), state, owner.clone()));
    let footer_context = context.clone();
    let return_previous = if callback {
        empty()
    } else {
        crate::app::account_switch::return_to_previous_account(scope, context.clone(), ready.into())
    };
    let footer = if callback {
        empty()
    } else {
        stack(
            "auth-footer",
            vec![Box::new(
                internal_link()
                    .class("auth-create-account")
                    .target(Route::Register.to_string())
                    .label(context.translated(scope, "login.create_identity"))
                    .on(glory::render::EventKind::Activate, move |_| {
                        footer_context.navigate(Route::Register)
                    }),
            )],
        )
    };
    let review_phase =
        scope.bond(move || (state.status.get(), state.connection_change.get().is_some()));
    let status = reactive(review_phase, move |_, (value, reviewing)| {
        if value.is_empty() || reviewing {
            empty()
        } else {
            Box::new(
                view()
                    .role(glory::render::Role::Status)
                    .class("auth-status")
                    .fill(text().content(value)),
            )
        }
    });
    let review_context = context.clone();
    let review_owner = scope.downgrade();
    let review = reactive(review_phase, move |scope, (status, reviewing)| {
        if callback || reviewing || !status.contains("Station identity or authentication changed") {
            return empty();
        }
        let context = review_context.clone();
        let owner = review_owner.clone();
        Box::new(sapid::button().unstyled().class("btn btn-ghost")
            .label(context.translated(scope, "login.connection.review")).enabled(ready)
            .on_press(move || {
                let Some(scope) = owner.upgrade() else { return };
                let selected = context.base_url.get_untracked();
                state.busy.revise(|value| *value = true);
                if let Err(error) = scope.spawn(async move {
                    match crate::station_connection::discover(&selected).await {
                        Err(error) => {
                            if let Some(change) = error.downcast_ref::<crate::station_connection::ConnectionTrustChange>() {
                                state.connection_change.revise(|value| *value = Some(change.clone()));
                            } else { state.status.revise(|value| *value = error.to_string()); }
                        }
                        Ok(_) => state.status.revise(|value| *value = "The server connection still matches the saved identity.".into()),
                    }
                    state.busy.revise(|value| *value = false);
                }) { scope.report_error(error); }
            }))
    });
    let trust_context = context.clone();
    let trust_owner = scope.downgrade();
    let trust = reactive(state.connection_change, move |scope, change| {
        let Some(change) = change else {
            return empty();
        };
        let context = trust_context.clone();
        let owner = trust_owner.clone();
        let may_trust = scope.bond({
            let context = context.clone();
            let url = change.candidate.base_url.clone();
            move || !state.busy.get() && same_server_url(&context.base_url.get(), &url)
        });
        let details = connection_review_details(scope, context.clone(), &change);
        stack("auth-status auth-connection-review station-connection-review", vec![details, line("auth-connection-actions", vec![
            Box::new(sapid::button().unstyled().class("btn btn-ghost").enabled(ready).label(context.translated(scope, "login.connection.keep"))
                .on_press(move || state.connection_change.revise(|value| *value = None))),
            Box::new(sapid::button().unstyled().class("btn btn-primary").enabled(may_trust).label(context.translated(scope, "login.connection.trust"))
                .on_press(move || {
                    let Some(scope) = owner.upgrade() else { return };
                    let change = change.clone(); let context = context.clone();
                    state.busy.revise(|value| *value = true);
                    if let Err(error) = scope.spawn(async move {
                        let cleared = context.state_store.write(|store| crate::station_connection::clear_pending_authentication(store, &change.previous.base_url));
                        if let Err(error) = cleared {
                            state.status.revise(|value| *value = error.to_string());
                            state.busy.revise(|value| *value = false); return;
                        }
                        match crate::station_connection::confirm_change(&change).await {
                            Ok(()) => {
                                context.services.session.invalidate("Station connection changed; sign in again");
                                state.callback_retry_url.revise(|value| *value = None);
                                state.connection_change.revise(|value| *value = None);
                                state.status.revise(|value| *value = "New connection accepted. Start a new sign-in.".into());
                            }
                            Err(error) => state.status.revise(|value| *value = error.to_string()),
                        }
                        state.busy.revise(|value| *value = false);
                    }) { scope.report_error(error); }
                })),
        ])])
    });
    let retry_context = context.clone();
    let retry = reactive(state.callback_retry_url, move |scope, url| match url {
        Some(url) => Box::new(
            glory::ui::link()
                .target(url)
                .label(retry_context.translated(scope, "login.retry_verification")),
        ) as View,
        None => empty(),
    });
    let diagnostics_context = context.clone();
    let diagnostics_owner = scope.downgrade();
    let diagnostics_source = scope.bond({
        let context = context.clone();
        move || (context.token.get(), context.state_revision.get())
    });
    let diagnostics = reactive(diagnostics_source, move |scope, (credential, _)| {
        let context = diagnostics_context.clone();
        let (session_status, key_id, actor_label) = context.state_store.read(|store| {
            (
                compute_session_status(&credential, store.session_grant().as_ref()),
                store
                    .dpop_device_key()
                    .map(|record| record.jkt)
                    .unwrap_or_default(),
                actor_display_label(
                    store,
                    &crate::app::principal_id_owned(context.principal_id.get_untracked()),
                ),
            )
        });
        if session_status == "signed-out" {
            return empty();
        }
        let owner = diagnostics_owner.clone();
        let refresh_context = context.clone();
        stack(
            "auth-session-state",
            vec![
                Box::new(
                    glory::ui::text()
                        .class("session-diagnostic session-status")
                        .content(context.translated(
                            scope,
                            if session_status == "signed-in" {
                                "login.status.signed_in"
                            } else {
                                "login.status.session_expired"
                            },
                        )),
                ),
                Box::new(
                    glory::ui::text()
                        .class("session-diagnostic session-device-id")
                        .content(short_protocol_id(context.device_id.get_untracked())),
                ),
                Box::new(
                    glory::ui::text()
                        .class("session-diagnostic session-actor-did")
                        .content(actor_label),
                ),
                Box::new(
                    glory::ui::text()
                        .class("session-diagnostic session-dpop-jkt")
                        .content(short_protocol_id(&key_id)),
                ),
                Box::new(
                    sapid::button()
                        .unstyled()
                        .class("btn btn-ghost")
                        .enabled(ready)
                        .label(context.translated(scope, "login.refresh_now"))
                        .on_press(move || {
                            state.busy.revise(|value| *value = true);
                            state
                                .status
                                .revise(|value| *value = "Refreshing session...".into());
                            let completed_context = refresh_context.clone();
                            LoginController {
                                is_busy: state.busy,
                                auth_status: state.status,
                                owner: owner.clone(),
                            }
                            .refresh_session(
                                refresh_context.services.session.clone(),
                                refresh_context.token,
                                Rc::new(move || completed_context.navigate(Route::Dashboard)),
                            );
                        }),
                ),
            ],
        )
    });
    let error = reactive(context.last_error, move |_, value| match value {
        Some(error) => Box::new(
            view()
                .role(glory::render::Role::Alert)
                .class("auth-error")
                .fill((
                    view().class("auth-error-mark").fill(text().content("!")),
                    view()
                        .class("auth-error-content")
                        .fill(paragraph("", error)),
                )),
        ) as View,
        None => empty(),
    });
    Box::new(view().class("auth-panel").fill((
        error,
        view().class("auth-brand").fill((
            view().class("auth-logo").fill(text().content("C")),
            view().fill((
                heading(
                    1,
                    "",
                    context.translated(
                        scope,
                        if callback {
                            "login.completing"
                        } else {
                            "login.title"
                        },
                    ),
                ),
                paragraph("", "Arkret"),
            )),
        )),
        view().class("auth-form").fill((
            station,
            sign_in,
            return_previous,
            footer,
            status,
            review,
            trust,
            retry,
            diagnostics,
        )),
    )))
}

fn retain_station(context: &InksonContext, state: LoginState, url: &str) {
    match context
        .config_store
        .revise(|store| store.save_neutral_station_choice(url))
    {
        Ok(selected) => {
            context.base_url.revise(|value| *value = selected.clone());
            state.station.revise(|value| *value = selected);
        }
        Err(error) => state
            .status
            .revise(|value| *value = format!("Could not retain sign-in Station: {error}")),
    }
}

fn connection_review_details(
    scope: &Scope,
    context: Rc<InksonContext>,
    change: &crate::station_connection::ConnectionTrustChange,
) -> View {
    let mut summaries = Vec::new();
    for (changed, key) in [
        (
            change.previous.service_id != change.candidate.service_id,
            "login.connection.identity_changed",
        ),
        (
            change.previous.trust_domain != change.candidate.trust_domain,
            "login.connection.domain_changed",
        ),
        (
            change.previous.authentication_metadata != change.candidate.authentication_metadata,
            "login.connection.provider_changed",
        ),
    ] {
        if changed {
            summaries.push(Box::new(
                glory::ui::view()
                    .class("auth-connection-summary-item")
                    .role(glory::render::Role::ListItem)
                    .fill(glory::ui::text().content(context.translated(scope, key))),
            ) as View);
        }
    }
    let mut fields = vec![paragraph(
        "auth-connection-server",
        context.translated_args(scope, "login.connection.server", {
            let url = change.candidate.base_url.clone();
            move || vec![("url", url.clone())]
        }),
    )];
    for detail in crate::station_connection::connection_changes(change) {
        let label_context = context.clone();
        let title =
            scope.bond(move || connection_review_field_label(&label_context, &detail.label));
        fields.push(stack(
            "auth-connection-field",
            vec![
                Box::new(
                    glory::ui::text()
                        .class("auth-connection-label")
                        .content(title),
                ),
                stack(
                    "auth-connection-values",
                    vec![
                        paragraph(
                            "auth-connection-term",
                            context.translated(scope, "login.connection.previous"),
                        ),
                        paragraph("auth-connection-value", detail.previous),
                        paragraph(
                            "auth-connection-term",
                            context.translated(scope, "login.connection.new"),
                        ),
                        paragraph("auth-connection-value", detail.candidate),
                    ],
                ),
            ],
        ));
    }
    let mut fields = Some(fields);
    let details_label = context.translated(scope, "login.connection.details");
    let details = Box::new(
        sapid::collapsible("station-connection-details")
            .unstyled()
            .class("auth-connection-details")
            .default_open(false)
            .label(details_label)
            .trigger_content(move || glory::ui::text().content(details_label))
            .content_policy(sapid::ContentPolicy::KeepMounted)
            .content(move || {
                Box::new(glory::ui::group().fill(fields.take().unwrap_or_default())) as View
            }),
    ) as View;
    Box::new(glory::ui::group().fill(vec![
            Box::new(
                glory::ui::text()
                    .class("auth-connection-label")
                    .content(context.translated(scope, "login.connection.changed")),
            ) as View,
            Box::new(
                glory::ui::view()
                    .class("auth-connection-summary")
                    .role(glory::render::Role::List)
                    .fill(summaries),
            ),
            paragraph("", context.translated(scope, "login.connection.warning")),
            details,
        ]))
}

fn connection_review_field_label(context: &InksonContext, label: &str) -> String {
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
                return context.tr(key);
            }
            if let Some(numbered) = field.strip_prefix("Sign-in method ")
                && let Some((index, method)) = numbered.split_once(" (")
                && index.parse::<usize>().is_ok_and(|index| index > 0)
                && let Some(method) = method.strip_suffix(')')
            {
                return crate::i18n::substitute_args(
                    context.tr("login.connection.field.numbered_method"),
                    &[("index", index.to_owned()), ("method", method.to_owned())],
                );
            }
            field.to_owned()
        })
        .collect::<Vec<_>>()
        .join(" · ")
}
