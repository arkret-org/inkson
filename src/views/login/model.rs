//! Pure classification behind the sign-in panel.
//!
//! Which failure a returning-session exchange actually is, what to tell the
//! user about a blocked device, and the one-shot claim that keeps a replayed
//! OIDC callback from being completed twice.

use super::*;

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

pub(super) enum OidcCallbackOutcome {
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

pub(super) fn classify_returning_session_exchange_error(
    error: garth::Error,
) -> ReturningSessionExchangeError {
    let message = format!("Account Authority handoff session issue failed: {error}");
    match &error {
        garth::Error::Http(_) => ReturningSessionExchangeError::Retryable(message),
        garth::Error::Api { error, .. }
            if matches!(
                error.error_code(),
                Some(
                    arkret_sdk::error_codes::ErrorCode::SessionGrantReplayIndeterminate
                        | arkret_sdk::error_codes::ErrorCode::SessionGrantReplayExpired
                        | arkret_sdk::error_codes::ErrorCode::SessionGrantReplayTerminal
                )
            ) =>
        {
            ReturningSessionExchangeError::Fatal(format!(
                "{message}. This issuance attempt cannot be replayed; authenticate again with a fresh request."
            ))
        }
        garth::Error::Api { status, .. } if *status == 429 || *status >= 500 => {
            ReturningSessionExchangeError::Retryable(message)
        }
        garth::Error::Api { error, .. }
            if error.error_code()
                == Some(arkret_sdk::error_codes::ErrorCode::DeviceUnauthorized) =>
        {
            ReturningSessionExchangeError::DeviceSetupRequired(message)
        }
        garth::Error::Api { error, .. } => match error.error_code() {
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

pub(super) fn returning_callback_resume_url(
    callback: &str,
    state: &str,
) -> Result<String, url::ParseError> {
    let mut url = url::Url::parse(callback)?;
    url.set_query(None);
    url.set_fragment(None);
    url.query_pairs_mut().append_pair("state", state);
    Ok(url.into())
}

/// Keep typed transport failures retryable without weakening evidence checks.
pub(super) fn classify_returning_verification_error(
    stage: &str,
    error: anyhow::Error,
) -> ReturningSessionExchangeError {
    use arkret_sdk::http_client::Error;
    let retryable = match error.downcast_ref::<Error>() {
        Some(Error::Http(_)) => true,
        Some(Error::Api { status, .. }) => *status >= 500 || *status == 429,
        _ => false,
    };
    let message = format!("{stage}: {error:#}");
    if retryable {
        ReturningSessionExchangeError::Retryable(message)
    } else {
        ReturningSessionExchangeError::Fatal(message)
    }
}

pub(super) fn returning_device_block_message(reason: ReturningDeviceBlockReason) -> &'static str {
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
pub(super) fn record_registration_checkpoint_disposition(
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
pub(super) fn login_transition_counter_summary() -> String {
    let counters = crate::identity::account_auth::transition::login_transition_counters()
        .into_iter()
        .map(|(name, value)| format!("{name}={value}"))
        .collect::<Vec<_>>()
        .join(" ");
    format!("Login transitions: {counters}.")
}

pub(super) fn local_evidence_diagnostics_message(
    reason: &LocalEvidenceUnavailableReason,
) -> String {
    let detail = local_evidence_diagnostics_detail(reason);
    format!("{detail} {}", login_transition_counter_summary())
}

pub(super) fn local_evidence_diagnostics_detail(reason: &LocalEvidenceUnavailableReason) -> String {
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

pub(super) struct RetainedAccountSignIn {
    pub(super) principal_did: arkret_sdk::Did,
    pub(super) device_id: arkret_sdk::DeviceId,
    pub(super) onboarding: Option<(
        crate::state::PendingAccountHandoff,
        crate::state::PendingPrincipalRegistration,
        crate::state::DpopDeviceKeyRecord,
    )>,
}

/// Recover a candidate from the accepted account namespace, including a first
/// registration whose profile was never published because readiness failed.
/// The next authenticated handoff still decides the account and device gate.
pub(super) async fn prepare_retained_account_sign_in(
    secure_store: &dyn crate::secure_key_store::SecureKeyStore,
    retained: Option<(arkret_sdk::AccountId, crate::state::ClientLocalState)>,
    current_checkpoint: Option<&crate::state::PendingPrincipalRegistration>,
) -> Result<Option<RetainedAccountSignIn>, String> {
    let Some((authority, state)) = retained else {
        return Ok(None);
    };
    let accepted = state
        .pending_principal_registration
        .as_ref()
        .filter(|checkpoint| {
            matches!(
                checkpoint.stage,
                crate::state::PendingPrincipalRegistrationStage::Accepted
                    | crate::state::PendingPrincipalRegistrationStage::RecoveryMaterialComplete
            ) && arkret_sdk::project_did_to_core_id(&checkpoint.did)
                .ok()
                .as_ref()
                == Some(&authority.principal_id)
        });
    // An explicit creation transaction for another identity owns its own
    // material. The last account must never replace that transaction.
    if current_checkpoint.is_some_and(|current| {
        accepted.is_none_or(|accepted| {
            current.did != accepted.did || current.device_id != accepted.device_id
        })
    }) {
        return Ok(None);
    }
    let candidate = accepted
        .map(|checkpoint| (checkpoint.did.clone(), checkpoint.device_id.clone()))
        .or_else(|| {
            state
                .recovery_material_evidence
                .as_ref()
                .filter(|evidence| {
                    evidence.account_id == authority
                        && arkret_sdk::project_did_to_core_id(&evidence.principal_did)
                            .ok()
                            .as_ref()
                            == Some(&authority.principal_id)
                })
                .map(|evidence| {
                    (
                        evidence.principal_did.clone(),
                        evidence.device_id.to_string(),
                    )
                })
        });
    let Some((principal_did, device)) = candidate else {
        return Ok(None);
    };
    let device_id = arkret_sdk::DeviceId::new(device).map_err(|error| error.to_string())?;
    let user_store = crate::secure_key_store::UserLocalStore::new(authority, device_id.clone())
        .map_err(|error| error.to_string())?;
    if user_store
        .load_device_id(secure_store)
        .map_err(|error| error.to_string())?
        .as_ref()
        != Some(&device_id)
        || user_store
            .load_signing_seed(secure_store)
            .map_err(|error| error.to_string())?
            .is_none()
    {
        if accepted.is_none() {
            return Ok(None);
        }
        return Err("The retained accepted device key is unavailable. Its setup was preserved; restore browser storage or use account recovery.".to_owned());
    }
    let onboarding = if let Some(checkpoint) = accepted {
        let handoff = state
            .pending_account_handoff
            .as_ref()
            .filter(|handoff| {
                handoff.audience_id == user_store.authority().station_id
                    && handoff.device_id == checkpoint.device_id
                    && (crate::identity::principal_registration::checkpoint_belongs_to_handoff(
                        checkpoint, handoff,
                    ) || crate::identity::account_auth::checkpoint_continues_bound_creation(
                        checkpoint, handoff,
                    ))
            })
            .ok_or_else(|| {
                "The retained accepted setup contradicts its account handoff.".to_owned()
            })?;
        let holder =
            crate::identity::account_auth::grant_dpop::load_user_device_key_with_secure_store(
                &user_store,
                secure_store,
            )
            .map_err(|error| error.to_string())?
            .ok_or_else(|| "The retained accepted setup has no grant-binding key.".to_owned())?;
        if holder.jkt() != handoff.holder_jkt {
            return Err(
                "The retained accepted setup belongs to a different authentication key.".to_owned(),
            );
        }
        let pending = crate::secure_key_store::PendingLocalStore::new(device_id.clone());
        pending
            .restore_from_user_durable(secure_store, &user_store)
            .await
            .map_err(|error| error.to_string())?;
        let record = crate::identity::account_auth::grant_dpop::dpop_device_key_record_from_seed(
            holder.seed_b64().as_str(),
        )
        .map_err(|error| error.to_string())?;
        Some((handoff.clone(), checkpoint.clone(), record))
    } else {
        None
    };
    Ok(Some(RetainedAccountSignIn {
        principal_did,
        device_id,
        onboarding,
    }))
}

pub(super) fn recover_pending_handoff_for_sign_in(
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
    // A lost handoff response can leave a server-side lease before the client
    // has a handoff checkpoint. The durable pending transaction still owns
    // its holder key; fresh authentication must not strand that lease by
    // replacing the key. This conveys no account authority on its own.
    let pending_login = store.pending_login();
    if pending_holder.is_some()
        || pending_login
            .as_ref()
            .is_some_and(|pending| pending.device_id == pending_device_id)
    {
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
        let expected_holder = pending_holder.as_deref().or_else(|| {
            pending_login
                .as_ref()
                .and_then(|pending| pending.dpop_jkt.as_deref())
        });
        if expected_holder.is_some_and(|expected| recovered.jkt() != expected) {
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
// per-component signal, so a Dioxus development double-mount (the reactivity quirk
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
pub(super) struct OidcCallbackCompletionClaims {
    pub(super) claimed_state: Option<String>,
}

impl OidcCallbackCompletionClaims {
    pub(super) fn claim(&mut self, returned_state: &str) -> bool {
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

pub(super) fn claim_oidc_callback_completion(returned_state: &str) -> bool {
    OIDC_CALLBACK_COMPLETION_CLAIMS.with(|claims| claims.borrow_mut().claim(returned_state))
}
