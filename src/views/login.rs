use arkret_sdk::http_client::{Auth, ClientBuilder};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::Utc;
use dioxus::prelude::*;
use dioxus_router::Link;
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
use crate::state::{LocalStateStore, PersistedSessionGrant};
use crate::transport::TransportClient;
use crate::ui::button::{Button, ButtonVariant};
use crate::ui::card::Card;
use crate::ui::input::Input;
use crate::ui::label::Label;
use crate::views::helpers::{actor_display_label, persist_config, short_protocol_id};

#[derive(Clone, Debug)]
pub(crate) struct CompletedLogin {
    pub(crate) account: crate::config::ActiveAccountContext,
    pub(crate) personal_handle: Option<String>,
    pub(crate) pending_device_id: arkret_sdk::DeviceId,
    pub(crate) dpop_device_key: crate::state::DpopDeviceKeyRecord,
    pub(crate) session_credential: String,
    pub(crate) session_grant: PersistedSessionGrant,
    pub(crate) consumed_handoff: crate::state::PendingAccountHandoff,
}

enum OidcCallbackOutcome {
    /// A known principal and its durable local device identity were retained,
    /// so Account Authority issued a fresh session grant for that same device.
    Login(Box<CompletedLogin>),
    /// No usable local device identity was available. The Account Authority's
    /// typed handoff decides between first creation and existing-account
    /// recovery; Inkson does not infer either state locally.
    Onboarding {
        preferred_locale: Option<crate::i18n::UiLocale>,
    },
    /// The authenticated handoff and exact signed session request remain
    /// durable. Reloading this same callback resumes that request without
    /// redeeming the OIDC code or selecting an account again.
    RetryableSessionExchange { message: String },
    /// The retained device is known but cannot safely continue. In particular,
    /// a revoked/fenced device must not be silently reinterpreted as a fresh
    /// pairing or Recovery-Key flow.
    ReturningDeviceBlocked {
        reason: ReturningDeviceBlockReason,
        message: String,
    },
    LocalEvidenceDiagnostics {
        reason: LocalEvidenceUnavailableReason,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ReturningDeviceBlockReason {
    RevocationPending,
    Revoked,
    GenerationFenced,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ReturningSessionExchangeError {
    DeviceSetupRequired(String),
    Blocked(ReturningDeviceBlockReason, String),
    Retryable(String),
    Fatal(String),
}

impl std::fmt::Display for ReturningSessionExchangeError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DeviceSetupRequired(message)
            | Self::Blocked(_, message)
            | Self::Retryable(message)
            | Self::Fatal(message) => formatter.write_str(message),
        }
    }
}

impl From<String> for ReturningSessionExchangeError {
    fn from(message: String) -> Self {
        Self::Fatal(message)
    }
}

fn classify_returning_session_exchange_error(error: garth::Error) -> ReturningSessionExchangeError {
    let message = format!("Account Authority handoff session issue failed: {error}");
    match &error {
        garth::Error::Http(_) => ReturningSessionExchangeError::Retryable(message),
        garth::Error::Api { status, error }
            if *status >= 500
                || error.error.error_code()
                    == Some(
                        arkret_sdk::error_codes::ErrorCode::SessionGrantReplayIndeterminate,
                    ) =>
        {
            ReturningSessionExchangeError::Retryable(message)
        }
        garth::Error::Api { error, .. }
            if error.error.error_code()
                == Some(arkret_sdk::error_codes::ErrorCode::DeviceUnauthorized) =>
        {
            ReturningSessionExchangeError::DeviceSetupRequired(message)
        }
        garth::Error::Api { error, .. } => match error.error.error_code() {
            Some(arkret_sdk::error_codes::ErrorCode::PrincipalUnknown) => {
                ReturningSessionExchangeError::Fatal(format!(
                    "{message}. No new identity was created. Use recovery or diagnostics to inspect this bound account."
                ))
            }
            Some(arkret_sdk::error_codes::ErrorCode::DeviceRevocationPending) => {
                ReturningSessionExchangeError::Blocked(
                    ReturningDeviceBlockReason::RevocationPending,
                    message,
                )
            }
            Some(arkret_sdk::error_codes::ErrorCode::DeviceRevoked) => {
                ReturningSessionExchangeError::Blocked(ReturningDeviceBlockReason::Revoked, message)
            }
            Some(arkret_sdk::error_codes::ErrorCode::DeviceGenerationFenced) => {
                ReturningSessionExchangeError::Blocked(
                    ReturningDeviceBlockReason::GenerationFenced,
                    message,
                )
            }
            _ => ReturningSessionExchangeError::Fatal(message),
        },
        _ => ReturningSessionExchangeError::Fatal(message),
    }
}

fn returning_device_block_message(reason: ReturningDeviceBlockReason) -> &'static str {
    match reason {
        ReturningDeviceBlockReason::RevocationPending => {
            "This device has a pending revocation. No session was issued. Finish or inspect that security transaction before trying another device flow."
        }
        ReturningDeviceBlockReason::Revoked => {
            "This device has been revoked. No session was issued, and Inkson did not start pairing or Recovery-Key recovery automatically."
        }
        ReturningDeviceBlockReason::GenerationFenced => {
            "This device belongs to an older fenced generation. No session was issued. Inspect the accepted recovery/re-anchor state before choosing a new device flow."
        }
    }
}

/// Record how the persisted identity-creation checkpoint participates in the
/// sign-in transaction that is starting.
fn record_registration_checkpoint_disposition(
    pending_handoff: Option<&crate::state::PendingAccountHandoff>,
    disposition: Option<garth::RegistrationCheckpointDisposition>,
) {
    use garth::RegistrationCheckpointDisposition as Disposition;

    use crate::identity::account_auth::transition::{
        LoginCorrelation, LoginStage, record_login_transition,
    };

    let reason = match disposition {
        None => "no_registration_checkpoint",
        Some(Disposition::ContinuesIdentityCreation) => "checkpoint_continues_identity_creation",
        Some(Disposition::DiscardStale) => "stale_checkpoint_pruned",
        Some(Disposition::Quarantine) => "foreign_checkpoint_quarantined",
    };
    let correlation = pending_handoff.map_or_else(LoginCorrelation::default, |handoff| {
        LoginCorrelation::for_handoff(handoff)
    });
    record_login_transition(
        LoginStage::SignInStart,
        "registration_checkpoint_classification",
        LoginStage::OidcCallback,
        reason,
        None,
        &correlation,
    );
}

/// Counter values an operator can read straight off a stuck diagnostics
/// screen. They separate an authorized login from device setup, a typed block,
/// an exact retry, a contradiction and a recovery surface.
fn login_transition_counter_summary() -> String {
    let counters = crate::identity::account_auth::transition::login_transition_counters()
        .into_iter()
        .map(|(name, value)| format!("{name}={value}"))
        .collect::<Vec<_>>()
        .join(" ");
    format!("Login transitions: {counters}.")
}

fn local_evidence_diagnostics_message(reason: &LocalEvidenceUnavailableReason) -> String {
    let detail = local_evidence_diagnostics_detail(reason);
    format!("{detail} {}", login_transition_counter_summary())
}

fn local_evidence_diagnostics_detail(reason: &LocalEvidenceUnavailableReason) -> String {
    match reason {
        LocalEvidenceUnavailableReason::HydrationInProgress => {
            "Local device security data is still loading. No session or device setup was started; retry after loading completes."
                .to_owned()
        }
        LocalEvidenceUnavailableReason::StorageFailure { reason } => format!(
            "Local device security data could not be read ({reason}). No session or device setup was started."
        ),
        LocalEvidenceUnavailableReason::InvalidSignerReference => {
            "The retained device signer reference is invalid. No session or device setup was started."
                .to_owned()
        }
        LocalEvidenceUnavailableReason::AmbiguousReturningDevices => {
            "More than one retained device signer matched this account. No signer was guessed and no device setup was started."
                .to_owned()
        }
    }
}

fn recover_pending_handoff_for_sign_in(
    store: &mut LocalStateStore,
    secure_store: &dyn crate::secure_key_store::SecureKeyStore,
    device_id: &str,
) -> bool {
    let pending_device_id = match arkret_sdk::DeviceId::new(device_id.to_owned()) {
        Ok(device_id) => device_id,
        Err(error) => {
            tracing::warn!(%error, device_id, "starting fresh sign-in because the unfinished handoff device id is invalid");
            return false;
        }
    };
    let pending_holder = store
        .pending_account_handoff()
        .filter(|handoff| handoff.device_id == device_id)
        .map(|handoff| handoff.holder_jkt);
    if let Some(expected_holder) = pending_holder {
        let pending_store =
            crate::secure_key_store::PendingLocalStore::new(pending_device_id.clone());
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
    store.can_resume_pending_login(&pending_device_id)
}

// Process-global OIDC-callback completion claims. `callback_started` below is a
// per-component signal, so a Dioxus double-mount (the 0.7.9 reactivity quirk
// that occasionally renders the panel twice) gives each instance its own `false`
// flag and BOTH run `finish_oidc_callback` — double-submitting the handoff and
// burning the single-use authorization_code (second POST → `invalid grant`).
//
// The claim must be keyed by the OAuth transaction state, not by the lifetime of
// the wasm instance. Browsers may restore Inkson from BFCache after the external
// authorization page, so a process-wide bool would incorrectly suppress every
// later sign-in without reloading wasm. The callback receiver still validates
// the returned state against its persisted scaffold before exchanging the code.
#[derive(Default)]
struct OidcCallbackCompletionClaims {
    claimed_state: Option<String>,
}

impl OidcCallbackCompletionClaims {
    fn claim(&mut self, returned_state: &str) -> bool {
        if self.claimed_state.as_deref() == Some(returned_state) {
            return false;
        }
        self.claimed_state = Some(returned_state.to_owned());
        true
    }
}

thread_local! {
    static OIDC_CALLBACK_COMPLETION_CLAIMS: std::cell::RefCell<OidcCallbackCompletionClaims> =
        std::cell::RefCell::new(OidcCallbackCompletionClaims::default());
}

fn claim_oidc_callback_completion(returned_state: &str) -> bool {
    OIDC_CALLBACK_COMPLETION_CLAIMS.with(|claims| claims.borrow_mut().claim(returned_state))
}

#[component]
pub fn LoginPanel(
    principal_id: Signal<Option<arkret_sdk::DidCoreId>>,
    device_id: Signal<String>,
    token: Signal<String>,
    config_store: Signal<LocalConfigStore>,
    mut locale: Signal<crate::i18n::UiLocale>,
    auto_capture_callback: bool,
    on_login: EventHandler<()>,
    on_onboarding: EventHandler<()>,
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
    let mut callback_started = use_signal(|| false);
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

        let callback_device = pending_device_id();
        let result = finish_oidc_callback(callback_url, callback_device, state_store_write).await;
        match result {
            Ok(OidcCallbackOutcome::Login(completed)) => {
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
                on_onboarding.call(());
            }
            Ok(OidcCallbackOutcome::RetryableSessionExchange { message }) => {
                auth_status.set(format!(
                    "{message} The signed request was preserved; reload this page to retry safely."
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
    let sign_in_session = session.clone();
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
            let returning_device = if let Some(expected) = persisted_account.as_ref() {
                match returning_device_id(secure_store.as_ref(), expected) {
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
            let (pending_handoff, pending_checkpoint) = {
                let store = reset_state_store.read();
                (
                    store.pending_account_handoff(),
                    store.pending_principal_registration(),
                )
            };
            let checkpoint_disposition = pending_checkpoint.as_ref().map(|checkpoint| {
                crate::identity::account_auth::registration_checkpoint_disposition(
                    checkpoint,
                    pending_handoff.as_ref(),
                    Utc::now(),
                )
            });
            if checkpoint_disposition
                == Some(garth::RegistrationCheckpointDisposition::DiscardStale)
                && let Some(checkpoint) = pending_checkpoint.as_ref()
            {
                if let Err(error) =
                    crate::identity::account_auth::clear_prepared_identity_creation_request_for_checkpoint(
                        checkpoint,
                    )
                {
                    tracing::warn!(%error, "clear stale identity-creation request artifact failed");
                }
                if let Err(error) = reset_state_store
                    .write()
                    .set_pending_principal_registration(None)
                {
                    tracing::warn!(%error, "prune stale identity-creation checkpoint failed");
                }
            }
            record_registration_checkpoint_disposition(
                pending_handoff.as_ref(),
                checkpoint_disposition,
            );
            let pending_device = pending_handoff
                .as_ref()
                .map(|handoff| handoff.device_id.clone())
                .filter(|device| crate::config::is_valid_device_id(device));
            let resume_account_handoff = if let Some(pending_device) = pending_device.as_deref() {
                let mut store = reset_state_store.write();
                recover_pending_handoff_for_sign_in(
                    &mut store,
                    secure_store.as_ref(),
                    pending_device,
                )
            } else {
                false
            };
            #[allow(clippy::expect_used)]
            let device = if resume_account_handoff {
                pending_device.expect("resumable handoff has a device id")
            } else {
                crate::config::new_device_id()
            };
            let pending_device_id = match arkret_sdk::DeviceId::new(device.clone()) {
                Ok(device_id) => device_id,
                Err(error) => {
                    is_busy.set(false);
                    auth_status.set(format!("The generated device id is invalid: {error}"));
                    return;
                }
            };
            // Only a checkpoint this exact transaction can still finish owns
            // the authentication. A stale, terminal, fenced-out or foreign
            // draft never suppresses the returning candidate: the old
            // account/device is carried as a candidate and compared against
            // the Bound handoff returned by the Account Authority.
            #[allow(clippy::expect_used)]
            let (expected_principal, expected_device) = if checkpoint_disposition
                == Some(garth::RegistrationCheckpointDisposition::ContinuesIdentityCreation)
            {
                (None, None)
            } else {
                (
                    returning_principal,
                    returning_device.map(|device| {
                        arkret_sdk::DeviceId::new(device)
                            .expect("secure-store device id was validated when loaded")
                    }),
                )
            };
            let pending_store =
                crate::secure_key_store::PendingLocalStore::new(pending_device_id.clone());
            if !resume_account_handoff
                && let Err(error) = pending_store.delete(secure_store.as_ref())
            {
                is_busy.set(false);
                auth_status.set(format!("Could not rotate the pending sign-in key: {error}"));
                return;
            }
            if let Err(error) = pending_store
                .save_device_id_durable(secure_store.as_ref())
                .await
            {
                is_busy.set(false);
                auth_status.set(format!(
                    "Could not durably prepare the pending sign-in device: {error}"
                ));
                return;
            }
            let prepared_authorization = match prepare_oidc_authorization(
                &principal,
                device.trim(),
                OidcEntryPoint::SignIn,
                expected_principal.as_ref(),
                expected_device.as_ref(),
                &ui_locale,
            )
            .await
            {
                Ok(prepared) => prepared,
                Err(error) => {
                    is_busy.set(false);
                    auth_status.set(error);
                    return;
                }
            };

            // Invalidation synchronously unmounts this route and pushes Login.
            // Complete the pending-scope transition in one no-await JS turn;
            // an URL-only detached task performs external navigation after it.
            if resume_account_handoff {
                // An unfinished identity-creation lease is fenced to this DPoP
                // holder. Rotating the key here makes the same browser look like
                // another device and leaves it stuck behind its own lease until
                // expiry. Re-authentication for this one resumable flow is a
                // soft continuation, so retain the holder key.
                crate::secure_key_store::set_active_device_seed_scope(None);
                let resumed = reset_state_store
                    .write()
                    .resume_pending_login(&pending_device_id);
                debug_assert!(resumed, "validated handoff resume must remain valid");
            } else {
                // Pre-DID: keep all bootstrap material in the transaction's
                // `pending.<device_id>` namespace until accepted-context
                // promotion re-homes it under the resolved principal.
                reset_state_store
                    .write()
                    .begin_pending_login(&pending_device_id, None);
                if let Err(error) = crate::secure_key_store::reset_device_seed_scope_for_signin(
                    secure_store.as_ref(),
                    &pending_device_id,
                ) {
                    tracing::warn!(%error, "reset device seed scope for sign-in failed");
                }
                reset_state_store.write().set_dpop_device_key(None);
            }
            pending_store.activate();
            prepared_authorization.launch_detached();
            session.invalidate("starting an account sign-in transaction");
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

fn returning_sign_in_principal(persisted_actor: &str) -> Result<Option<arkret_sdk::Did>, String> {
    let actor = persisted_actor.trim();
    if actor.is_empty() {
        return Ok(None);
    }
    let did = arkret_sdk::Did::new(actor.to_owned())
        .map_err(|error| format!("The saved current principal resolution is invalid: {error}"))?;
    arkret_sdk::project_did_to_core_id(&did)
        .map_err(|error| format!("The saved account principal cannot be projected: {error}"))?;
    Ok(Some(did))
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum AuthenticatedAccountRoute {
    IdentityCreation,
    IdentityCreationBusy,
    ReturningSession(arkret_sdk::DeviceId),
    DeviceSetupRequired,
    Diagnostics(LocalEvidenceUnavailableReason),
}

#[allow(clippy::expect_used)]
fn authenticated_account_route(
    disposition: &AccountHandoffDisposition,
    candidate_principal: Option<&arkret_sdk::Did>,
    candidate_device: Option<&arkret_sdk::DeviceId>,
) -> AuthenticatedAccountRoute {
    match disposition {
        AccountHandoffDisposition::IdentityCreationActive(_) => {
            AuthenticatedAccountRoute::IdentityCreation
        }
        AccountHandoffDisposition::IdentityCreationBusy { .. } => {
            AuthenticatedAccountRoute::IdentityCreationBusy
        }
        AccountHandoffDisposition::Bound {
            principal_id: authenticated_principal_id,
            ..
        } => {
            let candidates =
                candidate_principal
                    .zip(candidate_device)
                    .and_then(|(principal_did, device_id)| {
                        arkret_sdk::project_did_to_core_id(principal_did)
                            .ok()
                            .map(|principal_id| ReturningDeviceCandidate {
                                principal_id,
                                device_id: device_id.clone(),
                                signer_ref: format!("inkson-secure-store:{device_id}"),
                            })
                    });
            let normalized = garth::normalize_local_evidence(
                authenticated_principal_id,
                LocalEvidenceHydration::Ready,
                candidates,
            );
            match garth::route_bound_session(disposition, normalized)
                .expect("a bound handoff always has a bound-session route")
            {
                BoundSessionRoute::IssueOrReplay(candidate) => {
                    AuthenticatedAccountRoute::ReturningSession(candidate.device_id)
                }
                BoundSessionRoute::DeviceSetupRequired => {
                    AuthenticatedAccountRoute::DeviceSetupRequired
                }
                BoundSessionRoute::Diagnostics(reason) => {
                    AuthenticatedAccountRoute::Diagnostics(reason)
                }
            }
        }
    }
}

fn local_evidence_unavailable_code(reason: &LocalEvidenceUnavailableReason) -> &'static str {
    match reason {
        LocalEvidenceUnavailableReason::HydrationInProgress => "hydration_in_progress",
        LocalEvidenceUnavailableReason::StorageFailure { .. } => "storage_failure",
        LocalEvidenceUnavailableReason::InvalidSignerReference => "invalid_signer_reference",
        LocalEvidenceUnavailableReason::AmbiguousReturningDevices => "ambiguous_returning_devices",
    }
}

/// Record the one authoritative routing decision taken after the Account
/// Authority answered, so a later surface can always be traced back to the
/// disposition and the normalization outcome that selected it.
fn record_authenticated_account_route(
    pending_handoff: &crate::state::PendingAccountHandoff,
    disposition: &AccountHandoffDisposition,
    route: &AuthenticatedAccountRoute,
) {
    use crate::identity::account_auth::transition::{
        LoginStage, LoginTransitionOutcome, note_bound_admission_outcome, record_login_transition,
    };

    let authoritative_input = match disposition {
        AccountHandoffDisposition::IdentityCreationActive(_) => "identity_creation_active",
        AccountHandoffDisposition::IdentityCreationBusy { .. } => "identity_creation_busy",
        AccountHandoffDisposition::Bound { .. } => "bound_account_handoff",
    };
    let mut correlation =
        crate::identity::account_auth::transition::LoginCorrelation::for_handoff(pending_handoff);
    let bound = matches!(disposition, AccountHandoffDisposition::Bound { .. });
    if bound {
        // The bound disposition is the input local normalization consumed.
        record_login_transition(
            LoginStage::AccountHandoff,
            authoritative_input,
            LoginStage::LocalNormalization,
            "hydrated_local_evidence_normalized",
            None,
            &correlation,
        );
    }
    let (next_state, reason, outcome) = match route {
        AuthenticatedAccountRoute::IdentityCreation => (
            LoginStage::IdentityCreation,
            "identity_creation_owns_this_authentication",
            None,
        ),
        AuthenticatedAccountRoute::IdentityCreationBusy => (
            LoginStage::IdentityCreation,
            "identity_creation_lease_held_by_another_holder",
            None,
        ),
        AuthenticatedAccountRoute::ReturningSession(device_id) => {
            correlation = correlation.with_device_id(device_id.as_str());
            (
                LoginStage::SessionIssuance,
                "returning_device_normalized",
                None,
            )
        }
        AuthenticatedAccountRoute::DeviceSetupRequired => (
            LoginStage::DeviceSetup,
            "no_returning_device",
            Some(LoginTransitionOutcome::DeviceSetupRequired),
        ),
        AuthenticatedAccountRoute::Diagnostics(reason) => (
            LoginStage::LoginDiagnostics,
            local_evidence_unavailable_code(reason),
            Some(LoginTransitionOutcome::Contradiction),
        ),
    };
    if outcome.is_some() {
        note_bound_admission_outcome(&pending_handoff.request_id);
    }
    record_login_transition(
        if bound {
            LoginStage::LocalNormalization
        } else {
            LoginStage::AccountHandoff
        },
        if bound {
            "local_evidence_normalization"
        } else {
            authoritative_input
        },
        next_state,
        reason,
        outcome,
        &correlation,
    );
}

fn can_resume_returning_handoff_for_callback(
    handoff: &crate::state::PendingAccountHandoff,
    oidc_state: &str,
    pending_device_id: &str,
    holder_jkt: &str,
    gate_account_base_url: &str,
) -> bool {
    handoff.oidc_state.as_deref() == Some(oidc_state)
        && handoff.device_id == pending_device_id
        && handoff.holder_jkt == holder_jkt
        && same_server_url(&handoff.gate_account_base_url, gate_account_base_url)
        && handoff.bound_principal_id.is_some()
}

fn pending_handoff_from_authority(
    station_url: &str,
    gate_account_base_url: &str,
    audience: &arkret_sdk::DidCoreId,
    device_id: &str,
    trust_domain: &str,
    holder_jkt: &str,
    oidc_state: &str,
    outcome: &arkret_sdk::AccountHandoffOutcome,
    disposition: &AccountHandoffDisposition,
) -> crate::state::PendingAccountHandoff {
    let (
        lease_id,
        lease_fence,
        lease_expires_at,
        identity_creation_state,
        reserved_identity,
        retry_after_ms,
        bound_principal_id,
        bound_principal_did,
    ) = match disposition {
        AccountHandoffDisposition::IdentityCreationActive(lease) => (
            Some(lease.identity_creation_lease_id.clone()),
            Some(lease.fence),
            Some(lease.expires_at),
            Some(lease.state),
            lease.reserved_identity.clone(),
            None,
            None,
            None,
        ),
        AccountHandoffDisposition::IdentityCreationBusy {
            retry_after_ms,
            expires_at,
        } => (
            None,
            None,
            Some(*expires_at),
            None,
            None,
            Some(*retry_after_ms),
            None,
            None,
        ),
        AccountHandoffDisposition::Bound { principal_id, did } => (
            None,
            None,
            None,
            None,
            None,
            None,
            Some(principal_id.clone()),
            Some(did.clone()),
        ),
    };
    crate::state::PendingAccountHandoff {
        station_url: station_url.to_owned(),
        gate_account_base_url: gate_account_base_url.to_owned(),
        request_id: outcome.request_id.to_string(),
        oidc_state: Some(oidc_state.to_owned()),
        account_handle: outcome.account_handle.canonical().to_owned(),
        account_subject: Some(outcome.account_subject.clone()),
        holder_jkt: holder_jkt.to_owned(),
        audience_id: audience.clone(),
        expires_at: outcome.expires_at,
        lease_id,
        lease_fence,
        lease_expires_at,
        identity_creation_state,
        reserved_identity,
        identity_abandonment: None,
        retry_after_ms,
        device_id: device_id.to_owned(),
        trust_domain: trust_domain.to_owned(),
        bound_principal_id,
        bound_principal_did,
    }
}

fn returning_device_id(
    secure_store: &dyn crate::secure_key_store::SecureKeyStore,
    account: &crate::config::ActiveAccountContext,
) -> Result<Option<String>, String> {
    let user_store = crate::secure_key_store::UserLocalStore::new(
        account.authority.clone(),
        account.device_id.clone(),
    )
    .map_err(|error| format!("Open returning account secure scope: {error}"))?;
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
    if stored_device_id != account.device_id {
        return Err("Returning account secure-store device does not match its profile.".to_owned());
    }
    Ok(Some(stored_device_id.to_string()))
}

pub(crate) struct PreparedCompletedLoginKeys {
    user_store: crate::secure_key_store::UserLocalStore,
    pending_store: crate::secure_key_store::PendingLocalStore,
    device_id: arkret_sdk::DeviceId,
    signing_seed: [u8; 32],
}

pub(crate) async fn prepare_completed_login_dpop_key(
    secure_store: &dyn crate::secure_key_store::SecureKeyStore,
    account: &crate::config::ActiveAccountContext,
    pending_device_id: &str,
    record: &crate::state::DpopDeviceKeyRecord,
) -> Result<PreparedCompletedLoginKeys, String> {
    let device_id = account.device_id.clone();
    let pending_device_id = arkret_sdk::DeviceId::new(pending_device_id.to_owned())
        .map_err(|error| format!("validate pending login device id: {error}"))?;
    let user_store = crate::secure_key_store::UserLocalStore::new(
        account.authority.clone(),
        account.device_id.clone(),
    )
    .map_err(|error| format!("Open completed login secure scope: {error}"))?;
    let pending_store = crate::secure_key_store::PendingLocalStore::new(pending_device_id);
    pending_store
        .copy_to_durable(secure_store, &user_store)
        .await
        .map_err(|error| format!("prepare pending local store promotion: {error}"))?;
    user_store
        .save_grant_binding_seed_b64url_durable(secure_store, &record.seed_b64)
        .await
        .map_err(|error| format!("store grant-binding seed: {error}"))?;
    let encoded_record = serde_json::to_string(record)
        .map_err(|error| format!("serialize account-scoped DPoP key: {error}"))?;
    user_store
        .save_secret_durable(
            secure_store,
            LocalStateStore::SECURE_DPOP_DEVICE_KEY,
            &encoded_record,
        )
        .await
        .map_err(|error| format!("store account-scoped DPoP key: {error}"))?;
    user_store
        .save_device_id_durable(secure_store, &device_id)
        .await
        .map_err(|error| format!("store account-scoped device id: {error}"))?;
    // `copy_to_durable` above is the only promotion step. If neither the
    // pending transaction nor the accepted account held a signer, minting one
    // here would create a key the server never authorized and make possession
    // proof failures look like an ordinary device block.
    let material = user_store
        .load_signing_seed(secure_store)
        .map_err(|error| format!("load account device signing seed: {error}"))?
        .ok_or_else(|| "Accepted account device signing seed is unavailable.".to_owned())?;
    Ok(PreparedCompletedLoginKeys {
        user_store,
        pending_store,
        device_id,
        signing_seed: material.seed,
    })
}

pub(crate) fn commit_completed_login_dpop_key(
    store: &mut LocalStateStore,
    secure_store: &dyn crate::secure_key_store::SecureKeyStore,
    account: &crate::config::ActiveAccountContext,
    record: &crate::state::DpopDeviceKeyRecord,
    prepared: PreparedCompletedLoginKeys,
) -> Result<(), String> {
    prepared.user_store.activate();
    let mut public_record = record.clone();
    public_record.seed_b64.clear();
    store.set_dpop_device_key(Some(public_record));
    crate::event_signer::activate_device_signer_from_seed_for_device(
        prepared.signing_seed,
        Some(secure_store),
        Some(prepared.device_id.as_str()),
    )
    .map_err(|error| format!("activate account device signer: {error}"))?;
    crate::event_signer::bind_active_signer_principal_device_id(
        account.did(),
        prepared.device_id.as_str(),
    )
    .map_err(|error| format!("bind account device signer principal: {error}"))?;
    prepared
        .pending_store
        .delete(secure_store)
        .map_err(|error| format!("consume pending local store: {error}"))?;
    Ok(())
}

fn promote_completed_login_state(
    store: &mut LocalStateStore,
    secure_store: &dyn crate::secure_key_store::SecureKeyStore,
    account: &crate::config::ActiveAccountContext,
    record: &crate::state::DpopDeviceKeyRecord,
    prepared: PreparedCompletedLoginKeys,
    personal_handle: Option<&str>,
    session_grant: PersistedSessionGrant,
) -> Result<(), String> {
    commit_completed_login_dpop_key(store, secure_store, account, record, prepared)
        .map_err(|error| format!("persist returning-device session key: {error}"))?;
    if let Some(handle) = personal_handle {
        store.set_primary_handle(handle);
    }
    store.set_session_grant(Some(session_grant));
    store
        .set_pending_account_handoff(None)
        .map_err(|error| format!("clear completed account handoff checkpoint: {error}"))?;
    store
        .switch_active_account(account)
        .map_err(|error| format!("activate accepted account namespace: {error}"))?;
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
    format!("{error} Start sign-in again.")
}

/// A fully discovered and durably scaffolded OIDC transaction that is ready
/// for the browser navigation boundary. Keeping the authorize URL private
/// prevents callers from confusing an unprepared external URL with a launch
/// that already owns PKCE/state/nonce persistence.
#[must_use = "a prepared OIDC authorization must be launched or explicitly discarded"]
pub(crate) struct PreparedOidcAuthorization {
    authorize_url: String,
}

impl PreparedOidcAuthorization {
    fn launch(self) -> Result<(), String> {
        open_oidc_authorize_url(&self.authorize_url)
            .map_err(|error| format!("Could not open server sign-in: {error}"))
    }

    /// Schedule browser navigation outside the route-owned task that is about
    /// to synchronously invalidate and unmount itself. The detached task owns
    /// only an already-validated URL; it captures no component Signals.
    pub(crate) fn launch_detached(self) {
        dioxus::core::spawn_forever(async move {
            if let Err(error) = self.launch() {
                tracing::error!(%error, "launch prepared OIDC authorization failed");
            }
        });
    }
}

pub(crate) async fn prepare_oidc_authorization(
    station_url: &str,
    device_id: &str,
    entry_point: OidcEntryPoint,
    expected_principal_did: Option<&arkret_sdk::Did>,
    expected_device_id: Option<&arkret_sdk::DeviceId>,
    ui_locale: &str,
) -> Result<PreparedOidcAuthorization, String> {
    // T1.Y1 — discover the Account Authority + auth methods from the Station's root
    // `/_arkret/describe` (service-surface §2.5.1).
    let principal = TransportClient::unauthenticated(station_url)
        .map_err(|error| format!("Invalid Station URL: {error}"))?;
    let description = principal
        .describe()
        .await
        .map_err(|error| format_sign_in_discovery_error(station_url, &error))?;
    let resolver = AuthorityResolver::from_description(station_url, &description)
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
        &resolver.principal_audience,
        &entry_point,
        ui_locale,
    )
    .map_err(|error| format!("Sign-in URL preparation failed: {error}"))?;

    let scaffold = build_persisted_oidc_scaffold(
        &bundle,
        &resolver.gate_account_base_url,
        station_url,
        device_id,
        &discovery.issuer,
        &resolver.principal_trust_domain,
        expected_principal_did,
        expected_device_id,
    );
    persist_oidc_scaffold(&scaffold)
        .map_err(|error| format!("Could not save sign-in state: {error}"))?;
    Ok(PreparedOidcAuthorization {
        authorize_url: bundle.authorize_url,
    })
}

/// Standard OIDC discovery URL for an auth method: the explicit
/// `openid_configuration` when present, else `{issuer}/.well-known/openid-configuration`.
fn oidc_discovery_url(method: &arkret_sdk::AuthMethod) -> Option<String> {
    if let Some(config) = method
        .openid_configuration_url
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        return Some(config.to_owned());
    }
    method
        .issuer_uri
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

fn format_sign_in_discovery_error(station_url: &str, error: &anyhow::Error) -> String {
    let normalized = normalize_server_url(station_url);
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
            "Could not reach {normalized} for server sign-in discovery. Start the local Station on local.host:443 and make sure its HTTPS certificate is trusted. Details: {error}"
        )
    } else {
        format!("Could not reach {normalized} for server sign-in discovery: {error}")
    }
}

async fn finish_oidc_callback(
    callback_url: String,
    device_fallback: String,
    mut state_store: SyncSignal<LocalStateStore>,
) -> Result<OidcCallbackOutcome, String> {
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
    // `gate_account_base_url` persisted in the scaffold (service-surface §2.5.1).
    let gate_account_base_url = scaffold.gate_account_base_url.clone();
    if gate_account_base_url.trim().is_empty() {
        return Err("Sign-in state is missing the Account Authority base.".to_owned());
    }
    let station_url = if scaffold.station_url.trim().is_empty() {
        gate_account_base_url.clone()
    } else {
        scaffold.station_url.clone()
    };
    let sdk_base_url = crate::identity::session_refresh::sdk_base_url_from_gate_account_base_url(
        &gate_account_base_url,
    )
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
    let secure_store = crate::secure_key_store::default_secure_key_store("inkson");
    let (dpop_handle, dpop_record) = crate::identity::account_auth::grant_dpop::prepare_pending_device_key_with_secure_store_durable(
        secure_store.as_ref(),
        &pending_store,
    )
    .await
    .map_err(|error| format!("DPoP key failed: {error}"))?;
    {
        state_store
            .write()
            .set_pending_dpop_device_key_with_secure_store(
                Some(dpop_record),
                secure_store.as_ref(),
                &pending_store,
            )
            .map_err(|error| format!("DPoP key metadata failed: {error}"))?;
        crate::event_signer::bind_active_signer_device_id(&device)
            .map_err(|error| format!("Event signer device binding failed: {error}"))?;
    }
    let resumable_handoff = state_store
        .read()
        .pending_account_handoff()
        .filter(|handoff| {
            can_resume_returning_handoff_for_callback(
                handoff,
                &returned_state,
                &device,
                dpop_handle.jkt(),
                &gate_account_base_url,
            )
        });
    if let (Some(pending_handoff), Some(expected_principal), Some(returning_device)) = (
        resumable_handoff,
        scaffold.expected_principal_did.as_ref(),
        scaffold.expected_device_id.as_ref(),
    ) && pending_handoff
        .bound_principal_did
        .as_ref()
        .is_some_and(|bound| bound == expected_principal)
    {
        let handoff_grant =
            crate::identity::account_auth::load_account_handoff_grant(&pending_handoff)
                .map_err(|error| format!("Load resumable account handoff failed: {error}"))?
                .ok_or_else(|| "Resumable account handoff credential is unavailable.".to_owned())?;
        let principal_id = arkret_sdk::project_did_to_core_id(expected_principal)
            .map_err(|error| format!("Project resumable account principal: {error}"))?;
        match exchange_bound_handoff_session(
            &station_url,
            &sdk_base_url,
            &pending_handoff,
            &handoff_grant,
            principal_id,
            expected_principal.clone(),
            returning_device.clone(),
            &dpop_handle,
        )
        .await
        {
            Ok(completed) => {
                let _ = clear_persisted_oidc_scaffold(&scaffold.expected_state);
                return Ok(OidcCallbackOutcome::Login(Box::new(completed)));
            }
            Err(ReturningSessionExchangeError::DeviceSetupRequired(error)) => {
                tracing::warn!(%error, "resumed returning-device exchange requires device setup");
                let _ = clear_persisted_oidc_scaffold(&scaffold.expected_state);
                return Ok(OidcCallbackOutcome::Onboarding {
                    preferred_locale: None,
                });
            }
            Err(ReturningSessionExchangeError::Blocked(reason, message)) => {
                let _ = clear_persisted_oidc_scaffold(&scaffold.expected_state);
                return Ok(OidcCallbackOutcome::ReturningDeviceBlocked { reason, message });
            }
            Err(ReturningSessionExchangeError::Retryable(message)) => {
                return Ok(OidcCallbackOutcome::RetryableSessionExchange { message });
            }
            Err(ReturningSessionExchangeError::Fatal(error)) => return Err(error),
        }
    }
    if scaffold.issuer.trim().is_empty() {
        return Err("Sign-in state is missing the OIDC issuer.".to_owned());
    }
    let principal_audience =
        arkret_sdk::DidCoreId::new(scaffold.principal_audience.trim().to_owned())
            .map_err(|error| format!("invalid Station audience core_id: {error}"))?;
    let http = ClientBuilder::new(sdk_base_url.clone())
        .allow_insecure_localhost()
        .auth(Auth::Dpop(dpop_handle.sdk_dpop_proof_only_auth()))
        .build()
        .map_err(|error| format!("Build Account Authority OIDC client failed: {error}"))?;
    let handoff_request = garth::oidc_account_handoff_request(
        OidcAccountHandoffInput {
            request_id: arkret_sdk::RequestId::new_v7_at(crate::clock::now_unix_ms()),
            audience_id: principal_audience.clone(),
            issuer_uri: scaffold.issuer.clone(),
            client_id: scaffold.client_id.clone(),
            redirect_uri: scaffold.callback_uri.clone(),
            state: returned_state.clone(),
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
    let account_route = authenticated_account_route(
        &disposition,
        scaffold.expected_principal_did.as_ref(),
        scaffold.expected_device_id.as_ref(),
    );
    let pending_handoff = pending_handoff_from_authority(
        &station_url,
        &gate_account_base_url,
        &principal_audience,
        &device,
        &scaffold.principal_trust_domain,
        dpop_handle.jkt(),
        &returned_state,
        &handoff,
        &disposition,
    );
    crate::identity::account_auth::persist_account_handoff_grant(
        &pending_handoff,
        &handoff.account_handoff_grant,
    )
    .await
    .map_err(|error| format!("Persist account handoff credential failed: {error}"))?;
    {
        let mut store = state_store.write();
        persist_pending_account_handoff(&mut store, pending_handoff.clone())
            .map_err(|error| format!("Persist account handoff checkpoint failed: {error}"))?;
    }
    record_authenticated_account_route(&pending_handoff, &disposition, &account_route);
    if let (
        AuthenticatedAccountRoute::ReturningSession(returning_device),
        AccountHandoffDisposition::Bound { principal_id, did },
    ) = (&account_route, &disposition)
    {
        match exchange_bound_handoff_session(
            &station_url,
            &sdk_base_url,
            &pending_handoff,
            &handoff.account_handoff_grant,
            principal_id.clone(),
            did.clone(),
            returning_device.clone(),
            &dpop_handle,
        )
        .await
        {
            Ok(completed) => {
                let _ = clear_persisted_oidc_scaffold(&scaffold.expected_state);
                return Ok(OidcCallbackOutcome::Login(Box::new(completed)));
            }
            Err(ReturningSessionExchangeError::DeviceSetupRequired(error)) => {
                tracing::warn!(
                    %error,
                    principal_id = %pending_handoff.bound_principal_id.as_ref().map(arkret_sdk::DidCoreId::as_str).unwrap_or_default(),
                    device_id = %returning_device,
                    "returning-device authority rejected the durable device; entering device setup"
                );
            }
            Err(ReturningSessionExchangeError::Blocked(reason, message)) => {
                let _ = clear_persisted_oidc_scaffold(&scaffold.expected_state);
                return Ok(OidcCallbackOutcome::ReturningDeviceBlocked { reason, message });
            }
            Err(ReturningSessionExchangeError::Retryable(message)) => {
                return Ok(OidcCallbackOutcome::RetryableSessionExchange { message });
            }
            Err(ReturningSessionExchangeError::Fatal(error)) => return Err(error),
        }
    }
    if let AuthenticatedAccountRoute::Diagnostics(reason) = account_route {
        let _ = clear_persisted_oidc_scaffold(&scaffold.expected_state);
        return Ok(OidcCallbackOutcome::LocalEvidenceDiagnostics { reason });
    }
    let _ = clear_persisted_oidc_scaffold(&scaffold.expected_state);
    Ok(OidcCallbackOutcome::Onboarding {
        preferred_locale: handoff.preferred_locale,
    })
}

/// Issue or exactly replay one bound-account session grant and emit the single
/// structured record that ties this transaction's handoff, issuance operation
/// and device gate outcome together.
#[allow(clippy::too_many_arguments)]
async fn exchange_bound_handoff_session(
    station_url: &str,
    sdk_base_url: &url::Url,
    pending_handoff: &crate::state::PendingAccountHandoff,
    handoff_grant: &str,
    principal_id: arkret_sdk::DidCoreId,
    did: arkret_sdk::Did,
    device_id: arkret_sdk::DeviceId,
    dpop_handle: &crate::identity::account_auth::grant_dpop::DpopHandle,
) -> Result<CompletedLogin, ReturningSessionExchangeError> {
    use crate::identity::account_auth::transition::{
        LoginStage, LoginTransitionOutcome, note_bound_admission_outcome, record_login_transition,
    };

    let mut correlation =
        crate::identity::account_auth::transition::LoginCorrelation::for_handoff(pending_handoff)
            .with_principal_id(principal_id.clone())
            .with_device_id(device_id.as_str());
    let outcome = issue_bound_handoff_session(
        station_url,
        sdk_base_url,
        pending_handoff,
        handoff_grant,
        principal_id,
        did,
        device_id,
        dpop_handle,
        &mut correlation,
    )
    .await;
    let (next_state, reason, metric) = match &outcome {
        Ok(_) => (
            LoginStage::Authenticated,
            "accepted_device_session_issued",
            LoginTransitionOutcome::AuthorizedLogin,
        ),
        Err(ReturningSessionExchangeError::DeviceSetupRequired(_)) => (
            LoginStage::DeviceSetup,
            "device_unauthorized",
            LoginTransitionOutcome::DeviceSetupRequired,
        ),
        Err(ReturningSessionExchangeError::Blocked(reason, _)) => (
            LoginStage::LoginDiagnostics,
            returning_device_block_code(*reason),
            LoginTransitionOutcome::TypedBlock,
        ),
        Err(ReturningSessionExchangeError::Retryable(_)) => (
            LoginStage::SessionIssuance,
            "retryable_issuance_outcome",
            LoginTransitionOutcome::RetryExactIssue,
        ),
        Err(ReturningSessionExchangeError::Fatal(_)) => (
            LoginStage::LoginDiagnostics,
            "session_issuance_contradiction",
            LoginTransitionOutcome::Contradiction,
        ),
    };
    if !matches!(outcome, Err(ReturningSessionExchangeError::Fatal(_))) {
        note_bound_admission_outcome(&pending_handoff.request_id);
    }
    record_login_transition(
        LoginStage::SessionIssuance,
        "session_grant_admission",
        next_state,
        reason,
        Some(metric),
        &correlation,
    );
    outcome
}

fn returning_device_block_code(reason: ReturningDeviceBlockReason) -> &'static str {
    match reason {
        ReturningDeviceBlockReason::RevocationPending => "device_revocation_pending",
        ReturningDeviceBlockReason::Revoked => "device_revoked",
        ReturningDeviceBlockReason::GenerationFenced => "device_generation_fenced",
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn issue_bound_handoff_session(
    station_url: &str,
    sdk_base_url: &url::Url,
    pending_handoff: &crate::state::PendingAccountHandoff,
    handoff_grant: &str,
    principal_id: arkret_sdk::DidCoreId,
    did: arkret_sdk::Did,
    device_id: arkret_sdk::DeviceId,
    dpop_handle: &crate::identity::account_auth::grant_dpop::DpopHandle,
    correlation: &mut crate::identity::account_auth::transition::LoginCorrelation,
) -> Result<CompletedLogin, ReturningSessionExchangeError> {
    let now = Utc::now();
    let station_id = pending_handoff.audience_id.clone();
    let authority = arkret_sdk::AccountId::new(principal_id.clone(), station_id);
    let proof_expires_at = std::cmp::min(
        now + chrono::Duration::minutes(5),
        pending_handoff.expires_at,
    );
    if proof_expires_at <= now {
        return Err(ReturningSessionExchangeError::Fatal(
            "Account handoff expired before returning-device session exchange.".to_owned(),
        ));
    }
    let request = match crate::identity::account_auth::load_prepared_returning_session_request(
        pending_handoff,
    )
    .map_err(|error| format!("Load prepared returning-session request: {error}"))?
    {
        Some(request) => request,
        None => {
            // Normalize the retained account-scoped key into the one expected
            // returning-device state before authoring the protocol request.
            // The pending-login DPoP key proves the fresh AccountHandoff; it
            // must never be mistaken for the durable accepted-device signer.
            let secure_store = crate::secure_key_store::default_secure_key_store("inkson");
            let user_store =
                crate::secure_key_store::UserLocalStore::new(authority.clone(), device_id.clone())
                    .map_err(|error| format!("Open returning-device secure scope: {error}"))?;
            let signing_seed = user_store
                .load_signing_seed(secure_store.as_ref())
                .map_err(|error| format!("Load returning-device signer: {error}"))?
                .ok_or_else(|| "Returning-device signer is unavailable.".to_owned())?;
            crate::event_signer::activate_device_signer_from_seed_for_device(
                signing_seed.seed,
                Some(secure_store.as_ref()),
                Some(device_id.as_str()),
            )
            .map_err(|error| format!("Activate returning-device signer: {error}"))?;
            crate::event_signer::bind_active_signer_principal_device_id(&did, device_id.as_str())
                .map_err(|error| format!("Bind returning-device signer: {error}"))?;
            let signer = crate::event_signer::active_signer()
                .ok_or_else(|| "Returning-device signer is not active.".to_owned())?;

            let request_id = arkret_sdk::RequestId::new_v7_at(crate::clock::now_unix_ms());
            let audience = pending_handoff.audience_id.clone();
            let session_intent_digest = arkret_sdk::human_session_grant_intent_digest(
                &request_id,
                &principal_id,
                &device_id,
                &audience,
                &pending_handoff.holder_jkt,
            )
            .map_err(|error| format!("Build returning-session intent: {error}"))?;
            let account_subject = pending_handoff.account_subject.clone().ok_or_else(|| {
                "Account handoff omitted its authenticated account subject.".to_owned()
            })?;
            let account_handoff_grant_digest = arkret_sdk::Hash::new(
                crate::identity::account_auth::session_grant_jwt_digest(handoff_grant),
            )
            .map_err(|error| format!("Hash AccountHandoff credential: {error}"))?;
            let verification_method = arkret_sdk::DidUrl::new(format!("{did}#{device_id}"))
                .map_err(|error| format!("Build accepted-device method: {error}"))?;
            let unsigned_proof = arkret_wire::UnsignedAcceptedDeviceIssuePossessionProof {
                context: arkret_wire::AcceptedDevicePossessionProofContext::V1,
                purpose: arkret_wire::AcceptedDeviceIssuePossessionPurpose::SessionGrantIssue,
                request_id: request_id.clone(),
                account_subject,
                account_handoff_grant_digest,
                principal_id: principal_id.clone(),
                device_id: device_id.clone(),
                audience_id: audience.clone(),
                holder_jkt: pending_handoff.holder_jkt.clone(),
                session_intent_digest,
                issued_at: now,
                expires_at: proof_expires_at,
                verification_method,
            };
            let signing_bytes = unsigned_proof
                .canonical_signing_bytes()
                .map_err(|error| format!("Build accepted-device transcript: {error}"))?;
            let signature = arkret_sdk::Base64UrlString::new(
                URL_SAFE_NO_PAD.encode(
                    signer
                        .sign_raw(&signing_bytes)
                        .map_err(|error| format!("Sign accepted-device transcript: {error}"))?,
                ),
            )
            .map_err(|error| format!("Encode accepted-device signature: {error}"))?;
            let accepted_device_possession_proof = unsigned_proof
                .attach_signature(signature)
                .map_err(|error| format!("Finalize accepted-device proof: {error}"))?;
            let request = arkret_sdk::auth::session_grant::human_session_grant_request(
                request_id,
                principal_id.clone(),
                device_id.clone(),
                audience,
                accepted_device_possession_proof,
            )
            .map_err(|error| format!("Build returning-device session request: {error}"))?;
            crate::identity::account_auth::persist_prepared_returning_session_request(
                pending_handoff,
                &request,
            )
            .await
            .map_err(|error| format!("Persist returning-session replay request: {error}"))?;
            request
        }
    };
    if let arkret_sdk::SessionGrantRequestBody::Human(human) = &request {
        correlation.session_grant_request_id = Some(human.request_id.to_string());
        correlation.session_intent_digest = Some(
            human
                .accepted_device_possession_proof
                .session_intent_digest
                .to_string(),
        );
    }
    let http = ClientBuilder::new(sdk_base_url.clone())
        .allow_insecure_localhost()
        .auth(Auth::Dpop(
            dpop_handle.sdk_account_handoff_auth(handoff_grant.to_owned()),
        ))
        .build()
        .map_err(|error| format!("Build Account Authority handoff client: {error}"))?;
    let session_engine = SessionEngine::new(http);
    if let Err(first_error) = session_engine.login_request(request.clone(), now).await {
        let first_error = classify_returning_session_exchange_error(first_error);
        if !matches!(first_error, ReturningSessionExchangeError::Retryable(_)) {
            return Err(first_error);
        }
        tracing::warn!(
            error = %first_error,
            "returning-session response was retryable; replaying the exact signed request once"
        );
        session_engine
            .login_request(request, now)
            .await
            .map_err(classify_returning_session_exchange_error)?;
    }
    let session_grant = session_engine
        .current_state()
        .ok_or_else(|| "Account Authority handoff session issue did not yield state.".to_owned())?;
    correlation.session_grant_id = Some(session_grant.grant_id.as_str().to_owned());
    if session_grant.account_id.principal_id != principal_id
        || session_grant.device_id.as_ref() != Some(&device_id)
    {
        return Err(ReturningSessionExchangeError::Fatal(
            "Account Authority returned a session for a different principal or device.".to_owned(),
        ));
    }
    let principal = TransportClient::unauthenticated(station_url)
        .map_err(|error| format!("Invalid Station URL: {error}"))?;
    let authed_principal = principal
        .with_session_grant_dpop(session_grant.grant_jwt.clone(), dpop_handle.clone())
        .map_err(|error| format!("Attach returning SessionGrant + DPoP: {error}"))?;
    let principal_http = authed_principal
        .sdk_http_client()
        .map_err(|error| format!("Build authenticated Station client: {error}"))?;
    let account = crate::transport::account::account_me(&principal_http)
        .await
        .map_err(|error| format!("Station rejected the returning session: {error}"))?;
    if account.principal_id != principal_id {
        return Err(ReturningSessionExchangeError::Fatal(
            "Station account does not match the authenticated handoff.".to_owned(),
        ));
    }
    let session_private_key_pem = dpop_handle
        .session_signing_key_pkcs8_pem()
        .map_err(|error| format!("export session key: {error}"))?
        .to_string();
    let dpop_device_key =
        crate::identity::account_auth::grant_dpop::dpop_device_key_record_from_seed(
            dpop_handle.seed_b64().as_str(),
        )
        .map_err(|error| format!("DPoP device key record failed: {error}"))?;
    let station_route = url::Url::parse(&normalize_server_url(station_url))
        .map_err(|error| format!("Invalid Station route: {error}"))?;
    let active_account = crate::transport::account::resolve_active_account_context(
        &principal_http,
        format!("ak:profile:{}", crate::operation::uuid_v7()),
        authority.clone(),
        device_id.clone(),
        station_route.clone(),
    )
    .await
    .map_err(|error| {
        ReturningSessionExchangeError::Fatal(format!("Verify active principal resolution: {error}"))
    })?;
    let persisted_session_grant = persisted_session_grant_from_state(
        &session_grant,
        &session_private_key_pem,
        url::Url::parse(station_url).map_err(|error| {
            ReturningSessionExchangeError::Fatal(format!("invalid Station route: {error}"))
        })?,
        device_id.clone(),
    );
    Ok(CompletedLogin {
        account: active_account,
        personal_handle: crate::app::personal_handle_from_account_handle(&account.handle),
        pending_device_id: arkret_sdk::DeviceId::new(pending_handoff.device_id.clone()).map_err(
            |error| {
                ReturningSessionExchangeError::Fatal(format!(
                    "Pending login device id is invalid: {error}"
                ))
            },
        )?,
        dpop_device_key,
        session_credential: session_grant.grant_jwt.clone(),
        session_grant: persisted_session_grant,
        consumed_handoff: pending_handoff.clone(),
    })
}

fn persisted_session_grant_from_state(
    grant: &SessionGrantState,
    session_private_key_pem: &str,
    station_url: url::Url,
    device_id: arkret_sdk::DeviceId,
) -> PersistedSessionGrant {
    PersistedSessionGrant {
        grant_jwt: grant.grant_jwt.clone(),
        session_private_key_pem: session_private_key_pem.to_owned(),
        grant_id: grant.grant_id.as_str().to_owned(),
        audience_id: grant.audience_id.clone(),
        account_id: grant.account_id.clone(),
        device_id,
        station_url,
        grant_expires_at: Some(grant.expires_at),
        stored_at: Utc::now(),
    }
}

fn apply_authenticated_account_locale(
    preferred_locale: Option<crate::i18n::UiLocale>,
    mut state_store: SyncSignal<LocalStateStore>,
    locale: &mut Signal<crate::i18n::UiLocale>,
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
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;

    use super::*;

    #[test]
    fn oidc_callback_completion_claims_are_scoped_to_the_transaction_state() {
        let mut claims = OidcCallbackCompletionClaims::default();

        assert!(claims.claim("state-a"));
        assert!(
            !claims.claim("state-a"),
            "a duplicate Dioxus mount must not exchange one authorization code twice"
        );
        assert!(
            claims.claim("state-b"),
            "a BFCache-restored wasm instance must accept a later authorization transaction"
        );
        assert!(!claims.claim("state-b"));
    }

    fn dpop_record_for_seed(seed: [u8; 32]) -> crate::state::DpopDeviceKeyRecord {
        crate::identity::account_auth::grant_dpop::dpop_device_key_record_from_seed(
            &URL_SAFE_NO_PAD.encode(seed),
        )
        .expect("dpop record")
    }

    fn test_active_account(did: &str, device_id: &str) -> crate::config::ActiveAccountContext {
        let did = arkret_sdk::Did::new(did.to_owned()).unwrap();
        let authority = arkret_sdk::AccountId::new(
            arkret_sdk::project_did_to_core_id(&did).unwrap(),
            arkret_sdk::DidCoreId::new("ak:did_core:web:principal.example".to_owned()).unwrap(),
        );
        crate::config::ActiveAccountContext::new(
            "ak:profile:test".to_owned(),
            authority,
            arkret_sdk::PrincipalResolutionProjection {
                did,
                method_history_head: "head-test".to_owned(),
                version_id: "version-test".to_owned(),
                resolution_event_ref: "event-test".to_owned(),
                updated_at: "2026-08-22T00:00:00Z".parse().unwrap(),
            },
            arkret_sdk::DeviceId::new(device_id.to_owned()).unwrap(),
            url::Url::parse("https://principal.example").unwrap(),
        )
        .unwrap()
    }

    fn dummy_grant() -> PersistedSessionGrant {
        let now = chrono::Utc::now();
        PersistedSessionGrant {
            grant_jwt: "test.grant.jwt".to_owned(),
            session_private_key_pem: "PEM".to_owned(),
            grant_id: "grant-1".to_owned(),
            audience_id: arkret_sdk::DidCoreId::new("ak:did_core:web:principal.example").unwrap(),
            account_id: arkret_sdk::AccountId::new(
                crate::mls_api_helpers::principal_core_id("did:web:alice.example").unwrap(),
                arkret_sdk::DidCoreId::new("ak:did_core:web:principal.example").unwrap(),
            ),
            device_id: arkret_sdk::DeviceId::new(
                "ak:device:01904100-0000-7000-8000-000000000001".to_owned(),
            )
            .unwrap(),
            station_url: url::Url::parse("https://principal.example").unwrap(),
            grant_expires_at: Some(now + chrono::Duration::seconds(3600)),
            stored_at: now,
        }
    }

    fn pending_handoff_for_test(
        request_id: &str,
        account_handle: &str,
    ) -> crate::state::PendingAccountHandoff {
        crate::state::PendingAccountHandoff {
            station_url: "https://principal.example".to_owned(),
            gate_account_base_url: "https://auth.example/_arkret/gate/account".to_owned(),
            request_id: request_id.to_owned(),
            oidc_state: None,
            account_handle: account_handle.to_owned(),
            account_subject: Some(
                arkret_sdk::Hash::new(format!("sha256:{}", "a".repeat(64))).unwrap(),
            ),
            holder_jkt: "holder-jkt".to_owned(),
            audience_id: arkret_sdk::DidCoreId::new(
                "ak:did_core:webvh:z6mkfixture:principal.example",
            )
            .unwrap(),
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
            bound_principal_did: None,
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
        let typed_device_id = arkret_sdk::DeviceId::new(device_id.clone()).unwrap();
        store
            .set_pending_account_handoff(Some(handoff))
            .expect("pending handoff");

        assert!(!store.can_resume_pending_login(&typed_device_id));
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

    fn api_exchange_error(status: u16, code: &str) -> garth::Error {
        garth::Error::Api {
            status,
            error: Box::new(arkret_sdk::ErrorEnvelope::new(code, "fixture")),
        }
    }

    #[test]
    fn returning_session_errors_preserve_retry_setup_and_security_boundaries() {
        assert!(matches!(
            classify_returning_session_exchange_error(garth::Error::Http("offline".to_owned())),
            ReturningSessionExchangeError::Retryable(_)
        ));
        assert!(matches!(
            classify_returning_session_exchange_error(api_exchange_error(
                503,
                arkret_sdk::error_codes::ErrorCode::SESSION_GRANT_REPLAY_INDETERMINATE,
            )),
            ReturningSessionExchangeError::Retryable(_)
        ));
        assert!(matches!(
            classify_returning_session_exchange_error(api_exchange_error(
                403,
                arkret_sdk::error_codes::ErrorCode::DEVICE_UNAUTHORIZED,
            )),
            ReturningSessionExchangeError::DeviceSetupRequired(_)
        ));
        assert!(matches!(
            classify_returning_session_exchange_error(api_exchange_error(
                409,
                arkret_sdk::error_codes::ErrorCode::DEVICE_REVOCATION_PENDING,
            )),
            ReturningSessionExchangeError::Blocked(
                ReturningDeviceBlockReason::RevocationPending,
                _
            )
        ));
        assert!(matches!(
            classify_returning_session_exchange_error(api_exchange_error(
                403,
                arkret_sdk::error_codes::ErrorCode::DEVICE_REVOKED,
            )),
            ReturningSessionExchangeError::Blocked(ReturningDeviceBlockReason::Revoked, _)
        ));
        assert!(matches!(
            classify_returning_session_exchange_error(api_exchange_error(
                403,
                arkret_sdk::error_codes::ErrorCode::DEVICE_GENERATION_FENCED,
            )),
            ReturningSessionExchangeError::Blocked(ReturningDeviceBlockReason::GenerationFenced, _)
        ));
        assert!(matches!(
            classify_returning_session_exchange_error(api_exchange_error(
                404,
                arkret_sdk::error_codes::ErrorCode::PRINCIPAL_UNKNOWN,
            )),
            ReturningSessionExchangeError::Fatal(message)
                if message.contains("No new identity was created")
                    && message.contains("recovery or diagnostics")
        ));
        assert!(matches!(
            classify_returning_session_exchange_error(api_exchange_error(
                401,
                arkret_sdk::error_codes::ErrorCode::SIGNATURE_INVALID,
            )),
            ReturningSessionExchangeError::Fatal(_)
        ));
    }

    #[test]
    fn oidc_callback_restores_bootstrap_device_seed_scope() {
        let authority = arkret_sdk::AccountId::new(
            crate::mls_api_helpers::principal_core_id("did:web:old.example").unwrap(),
            arkret_sdk::DidCoreId::new("ak:did_core:web:principal.example".to_owned()).unwrap(),
        );
        let device_id =
            arkret_sdk::DeviceId::new("ak:device:01964137-0000-7000-8000-000000000000".to_owned())
                .unwrap();
        let _scope = crate::secure_key_store::DeviceSeedScopeTestGuard::replace(Some((
            &authority, &device_id,
        )));
        let _signer = crate::event_signer::ActiveSignerTestGuard::replace(None);

        restore_oidc_callback_device_seed_scope("ak:device:01964137-0000-7000-8000-000000000001")
            .expect("pending local store");

        assert_eq!(crate::secure_key_store::active_device_seed_scope(), None);
        assert_eq!(
            crate::secure_key_store::pending_login_device_id()
                .as_ref()
                .map(arkret_sdk::DeviceId::as_str),
            Some("ak:device:01964137-0000-7000-8000-000000000001")
        );
    }

    #[test]
    fn account_first_sign_in_has_no_returning_principal() {
        assert_eq!(returning_sign_in_principal("").unwrap(), None);
    }

    #[test]
    fn returning_sign_in_keeps_the_resolvable_principal_assertion() {
        let actor = "did:webvh:z6mkfixture:alice.example";

        assert_eq!(
            returning_sign_in_principal(actor)
                .unwrap()
                .expect("returning principal")
                .as_str(),
            actor
        );
    }

    #[test]
    fn core_only_profile_is_not_repaired_into_resolution_material() {
        let principal =
            arkret_sdk::Did::new("did:webvh:z6mkfixture:alice.example".to_owned()).unwrap();
        let principal_core = arkret_sdk::project_did_to_core_id(&principal).unwrap();
        assert!(returning_sign_in_principal(principal_core.as_str()).is_err());
    }

    #[test]
    fn returning_handoff_resume_is_bound_to_the_exact_coauth_callback() {
        let mut handoff = pending_handoff_for_test(
            "ak:request:019f0000-0000-7000-8000-000000000013",
            "alice:auth.example",
        );
        handoff.oidc_state = Some("state-a".to_owned());
        handoff.bound_principal_id =
            Some(arkret_sdk::DidCoreId::new("ak:did_core:web:alice.example".to_owned()).unwrap());
        handoff.bound_principal_did =
            Some(arkret_sdk::Did::new("did:web:alice.example".to_owned()).unwrap());

        assert!(can_resume_returning_handoff_for_callback(
            &handoff,
            "state-a",
            &handoff.device_id,
            &handoff.holder_jkt,
            &handoff.gate_account_base_url,
        ));
        assert!(
            !can_resume_returning_handoff_for_callback(
                &handoff,
                "state-b",
                &handoff.device_id,
                &handoff.holder_jkt,
                &handoff.gate_account_base_url,
            ),
            "a new Coauth callback must observe its newly selected account"
        );
    }

    #[test]
    fn bound_handoff_uses_returning_device_only_for_the_same_account() {
        let alice = arkret_sdk::Did::new("did:web:alice.example".to_owned()).unwrap();
        let bob = arkret_sdk::Did::new("did:web:bob.example".to_owned()).unwrap();
        let device =
            arkret_sdk::DeviceId::new("ak:device:01964137-0000-7000-8000-000000000001".to_owned())
                .unwrap();
        let disposition = AccountHandoffDisposition::Bound {
            principal_id: arkret_sdk::project_did_to_core_id(&alice).unwrap(),
            did: alice.clone(),
        };

        assert_eq!(
            authenticated_account_route(&disposition, Some(&alice), Some(&device)),
            AuthenticatedAccountRoute::ReturningSession(device.clone()),
        );
        assert_eq!(
            authenticated_account_route(&disposition, Some(&bob), Some(&device)),
            AuthenticatedAccountRoute::DeviceSetupRequired,
            "a different Coauth account must enter device setup",
        );
        assert_eq!(
            authenticated_account_route(&disposition, Some(&alice), None),
            AuthenticatedAccountRoute::DeviceSetupRequired,
            "a matching account without durable device material is a new device",
        );
    }

    #[test]
    fn server_identity_creation_states_ignore_local_returning_candidates() {
        let principal =
            arkret_sdk::Did::new("did:webvh:z6mkfixture:alice.example".to_owned()).unwrap();
        let device =
            arkret_sdk::DeviceId::new("ak:device:01964137-0000-7000-8000-000000000001".to_owned())
                .unwrap();
        let active =
            AccountHandoffDisposition::IdentityCreationActive(arkret_sdk::IdentityCreationLease {
                identity_creation_lease_id: "lease-fixture".to_owned(),
                fence: 1,
                state: arkret_sdk::IdentityCreationLeaseState::Active,
                expires_at: Utc::now() + chrono::Duration::minutes(15),
                reserved_identity: None,
            });
        let busy = AccountHandoffDisposition::IdentityCreationBusy {
            retry_after_ms: 1_000,
            expires_at: Utc::now() + chrono::Duration::minutes(15),
        };

        assert_eq!(
            authenticated_account_route(&active, Some(&principal), Some(&device)),
            AuthenticatedAccountRoute::IdentityCreation,
        );
        assert_eq!(
            authenticated_account_route(&busy, Some(&principal), Some(&device)),
            AuthenticatedAccountRoute::IdentityCreationBusy,
        );
    }

    #[test]
    fn returning_sign_in_requires_the_durable_device_identity_key() {
        let secure_store = crate::secure_key_store::MemorySecureKeyStore::default();
        let account = test_active_account(
            "did:web:alice.example",
            "ak:device:01964137-0000-7000-8000-000000000001",
        );
        let user_store = crate::secure_key_store::UserLocalStore::new(
            account.authority.clone(),
            account.device_id.clone(),
        )
        .unwrap();
        user_store
            .save_device_id(&secure_store, &account.device_id)
            .unwrap();

        assert_eq!(
            returning_device_id(&secure_store, &account).unwrap(),
            None,
            "a public device id without its long-term signing key is a new device"
        );

        user_store
            .save_signing_seed(&secure_store, &[41_u8; 32])
            .unwrap();
        assert_eq!(
            returning_device_id(&secure_store, &account)
                .unwrap()
                .as_deref(),
            Some(account.device_id.as_str()),
            "the typed profile and secure scope select the same device"
        );
    }

    #[tokio::test]
    async fn completed_login_promotes_verified_authority_and_preserves_device_key() {
        let _scope = crate::secure_key_store::DeviceSeedScopeTestGuard::replace(None);
        let _signer = crate::event_signer::ActiveSignerTestGuard::replace(None);
        let mut store = crate::state::isolated_store_for_tests("completed-login-dpop-key");
        let secure_store = crate::secure_key_store::MemorySecureKeyStore::default();
        let device = "ak:device:01964137-0000-7000-8000-000000000001";
        let account = test_active_account("did:web:alice.example", device);
        let pending_device = "ak:device:01964137-0000-7000-8000-000000000002";
        let pending_device_id = arkret_sdk::DeviceId::new(pending_device.to_owned()).unwrap();
        let old_seed = [3_u8; 32];
        let new_record = dpop_record_for_seed([7_u8; 32]);

        let user_store = crate::secure_key_store::UserLocalStore::new(
            account.authority.clone(),
            account.device_id.clone(),
        )
        .unwrap();
        user_store
            .save_signing_seed(&secure_store, &old_seed)
            .expect("old account seed");
        store.begin_pending_login(&pending_device_id, Some(&new_record.jkt));

        let prepared =
            prepare_completed_login_dpop_key(&secure_store, &account, pending_device, &new_record)
                .await
                .expect("prepare completed login dpop");
        assert!(
            store.active_principal_id().is_none(),
            "fallible secure preparation must not switch the public account"
        );
        let mut grant = dummy_grant();
        grant.account_id = account.authority.clone();
        grant.device_id = account.device_id.clone();
        promote_completed_login_state(
            &mut store,
            &secure_store,
            &account,
            &new_record,
            prepared,
            Some("alice"),
            grant.clone(),
        )
        .expect("promote completed login");

        assert_eq!(store.active_authority(), Some(account.authority.clone()));
        assert_eq!(
            store.known_profile_id_for_authority(&account.authority),
            Some(account.profile_id.clone())
        );
        assert_eq!(store.load().primary_handle, "alice");
        assert_eq!(store.session_grant(), Some(grant));
        assert!(store.pending_login().is_none());

        let loaded_seed = user_store
            .load_signing_seed(&secure_store)
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
