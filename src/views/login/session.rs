//! Everything behind the sign-in button.
//!
//! Routing an authenticated account, resuming a bound handoff, finishing the
//! OIDC callback and exchanging the session it returns. These are durable
//! protocol stages the panel narrates but does not own; none of them touches
//! `rsx!`.

use super::*;

pub(super) fn restore_oidc_callback_device_seed_scope(
    device_id: &str,
) -> Result<crate::secure_key_store::PendingLocalStore, String> {
    let device_id = arkret_sdk::DeviceId::new(device_id.to_owned())
        .map_err(|error| format!("invalid pending login device id: {error}"))?;
    let pending_store = crate::secure_key_store::PendingLocalStore::new(device_id);
    pending_store.activate();
    Ok(pending_store)
}

pub(super) fn returning_sign_in_principal(
    persisted_actor: &str,
) -> Result<Option<arkret_sdk::Did>, String> {
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
pub(super) enum AuthenticatedAccountRoute {
    IdentityCreation,
    IdentityCreationBusy,
    ReturningSession(arkret_sdk::DeviceId),
    DeviceSetupRequired,
    Diagnostics(LocalEvidenceUnavailableReason),
}

#[allow(clippy::expect_used)]
pub(super) fn authenticated_account_route(
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

pub(super) fn local_evidence_unavailable_code(
    reason: &LocalEvidenceUnavailableReason,
) -> &'static str {
    match reason {
        LocalEvidenceUnavailableReason::HydrationInProgress => "hydration_in_progress",
        LocalEvidenceUnavailableReason::StorageFailure { .. } => "storage_failure",
        LocalEvidenceUnavailableReason::InvalidSignerReference => "invalid_signer_reference",
        LocalEvidenceUnavailableReason::AmbiguousReturningDevices => "ambiguous_returning_devices",
    }
}

pub(super) fn bound_device_entry_state_for_route(
    route: &AuthenticatedAccountRoute,
) -> Option<crate::state::BoundDeviceEntryState> {
    match route {
        AuthenticatedAccountRoute::ReturningSession(device_id) => {
            Some(crate::state::BoundDeviceEntryState::ReturningDevice {
                device_id: device_id.to_string(),
            })
        }
        AuthenticatedAccountRoute::DeviceSetupRequired => {
            Some(crate::state::BoundDeviceEntryState::NoReturningDevice)
        }
        AuthenticatedAccountRoute::Diagnostics(reason) => Some(
            crate::state::BoundDeviceEntryState::LocalEvidenceUnavailable {
                reason: local_evidence_unavailable_code(reason).to_owned(),
            },
        ),
        AuthenticatedAccountRoute::IdentityCreation
        | AuthenticatedAccountRoute::IdentityCreationBusy => None,
    }
}

/// Record the one authoritative routing decision taken after the Account
/// Authority answered, so a later surface can always be traced back to the
/// disposition and the normalization outcome that selected it.
pub(super) fn record_authenticated_account_route(
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

pub(super) fn can_resume_returning_handoff_for_callback(
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

pub(super) fn pending_handoff_from_authority(
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
        bound_device_entry_state: None,
    }
}

pub(super) fn returning_device_id(
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

pub(super) fn pending_pairing_for_handoff(
    secure_store: &dyn crate::secure_key_store::SecureKeyStore,
    handoff: &crate::state::PendingAccountHandoff,
) -> Result<Option<crate::identity::device_pairing::PendingDevicePairingVerification>, String> {
    let device_id = arkret_sdk::DeviceId::new(handoff.device_id.clone())
        .map_err(|error| format!("Validate pending pairing device id: {error}"))?;
    let pending = crate::secure_key_store::PendingLocalStore::new(device_id);
    let verification = crate::identity::device_pairing::load_pending_device_pairing_verification(
        &pending,
        secure_store,
    )
    .map_err(|error| format!("Load pending device pairing: {error}"))?;
    if let Some(verification) = verification.as_ref() {
        verification
            .validate_for_handoff(handoff)
            .map_err(|error| format!("Validate pending device pairing: {error}"))?;
    }
    Ok(verification)
}

pub(crate) struct PreparedCompletedLoginKeys {
    pub(super) user_store: crate::secure_key_store::UserLocalStore,
    pub(super) device_id: arkret_sdk::DeviceId,
    pub(super) signing_seed: [u8; 32],
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
    // Account acceptance precedes the onboarding readiness gate. Retain the
    // pending keys until its caller has durably committed the whole flow.
    Ok(())
}

pub(crate) fn consume_completed_login_pending_store(
    secure_store: &dyn crate::secure_key_store::SecureKeyStore,
    pending_store: &crate::secure_key_store::PendingLocalStore,
) -> Result<(), String> {
    crate::identity::device_pairing::clear_pending_device_pairing_verification(
        pending_store,
        secure_store,
    )
    .map_err(|error| format!("consume pending device-pairing verification: {error}"))?;
    pending_store
        .delete(secure_store)
        .map_err(|error| format!("consume pending local store: {error}"))?;
    Ok(())
}

pub(super) fn promote_completed_login_state(
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
pub(super) fn compute_session_status(
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

pub(super) fn discard_failed_oidc_callback(error: String) -> String {
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
    pub(super) authorize_url: String,
}

impl PreparedOidcAuthorization {
    pub(crate) fn launch(self) -> Result<(), String> {
        open_oidc_authorize_url(&self.authorize_url)
            .map_err(|error| format!("Could not open server sign-in: {error}"))
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

    let station_binding = arkret_sdk::StationConnectionBinding::from_description(
        principal.base_url(),
        &description,
        true,
    )
    .map_err(|error| error.to_string())?;
    let scaffold = build_persisted_oidc_scaffold(
        &station_binding,
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
pub(super) fn oidc_discovery_url(method: &arkret_sdk::AuthMethod) -> Option<String> {
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

pub(super) fn format_sign_in_discovery_error(station_url: &str, error: &anyhow::Error) -> String {
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

pub(super) async fn finish_oidc_callback(
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

    // A restored callback is bound to the original Station and auth configuration.
    // Re-enrollment never forwards an old authorization code to a new provider.
    let description = crate::station_connection::discover(&scaffold.station_url)
        .await
        .map_err(|error| error.to_string())?;
    let base = crate::config::validate_server_url(&scaffold.station_url)
        .map_err(|error| error.to_string())?;
    let binding = arkret_sdk::StationConnectionBinding::from_description(&base, &description, true)
        .map_err(|error| error.to_string())?;
    scaffold
        .station_binding
        .require_same(&binding)
        .map_err(|error| error.to_string())?;

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
    if let (Some(mut pending_handoff), Some(expected_principal), Some(returning_device)) = (
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
                return Ok(OidcCallbackOutcome::Login(Box::new(completed)));
            }
            Err(ReturningSessionExchangeError::DeviceSetupRequired(error)) => {
                tracing::warn!(%error, "resumed returning-device exchange requires device setup");
                pending_handoff.bound_device_entry_state =
                    Some(crate::state::BoundDeviceEntryState::NoReturningDevice);
                persist_pending_account_handoff_durably(&mut state_store, &pending_handoff).await?;
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
    // An exact durable handoff resumes above without replaying the OIDC code.
    // A state-only link cannot start a new handoff when that evidence is absent.
    let authorization_code = extract_authorization_code_from_callback(&callback_url)
        .map_err(|error| format!("Callback did not include an authorization code: {error}"))?;
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
    let mut pending_handoff = pending_handoff_from_authority(
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
    pending_handoff.bound_device_entry_state = bound_device_entry_state_for_route(&account_route);
    crate::identity::account_auth::persist_account_handoff_grant(
        &pending_handoff,
        &handoff.account_handoff_grant,
    )
    .await
    .map_err(|error| format!("Persist account handoff credential failed: {error}"))?;
    persist_pending_account_handoff_durably(&mut state_store, &pending_handoff).await?;
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
                return Ok(OidcCallbackOutcome::Login(Box::new(completed)));
            }
            Err(ReturningSessionExchangeError::DeviceSetupRequired(error)) => {
                tracing::warn!(
                    %error,
                    principal_id = %pending_handoff.bound_principal_id.as_ref().map(arkret_sdk::DidCoreId::as_str).unwrap_or_default(),
                    device_id = %returning_device,
                    "returning-device authority rejected the durable device; entering device setup"
                );
                pending_handoff.bound_device_entry_state =
                    Some(crate::state::BoundDeviceEntryState::NoReturningDevice);
                persist_pending_account_handoff_durably(&mut state_store, &pending_handoff).await?;
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
pub(super) async fn exchange_bound_handoff_session(
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

pub(super) fn returning_device_block_code(reason: ReturningDeviceBlockReason) -> &'static str {
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
    let secure_store = crate::secure_key_store::default_secure_key_store("inkson");
    let user_store =
        crate::secure_key_store::UserLocalStore::new(authority.clone(), device_id.clone())
            .map_err(|error| format!("Open returning-device secure scope: {error}"))?;
    let durable_signing_seed = user_store
        .load_signing_seed(secure_store.as_ref())
        .map_err(|error| format!("Load returning-device signer: {error}"))?;
    let pending_pairing = if durable_signing_seed.is_none() {
        pending_pairing_for_handoff(secure_store.as_ref(), pending_handoff)?
    } else {
        None
    };
    let signing_seed = match durable_signing_seed.as_ref() {
        Some(material) => material.seed,
        None => {
            let pairing = pending_pairing.as_ref().ok_or_else(|| {
                "Returning-device signer is unavailable and no exact pending pairing exists."
                    .to_owned()
            })?;
            let pending =
                crate::secure_key_store::PendingLocalStore::new(pairing.device_id.clone());
            pending
                .load_signing_seed(secure_store.as_ref())
                .map_err(|error| format!("Load pending paired-device signer: {error}"))?
                .ok_or_else(|| "Pending paired-device signer is unavailable.".to_owned())?
                .seed
        }
    };
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
            crate::event_signer::activate_device_signer_from_seed_for_device(
                signing_seed,
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
                arkret_sdk::canonical::sha256_digest(handoff_grant.as_bytes()),
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
                account_id: arkret_wire::AccountId::new(principal_id.clone(), audience.clone()),
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
    if let Some(pairing) = pending_pairing.as_ref() {
        let status_http = TransportClient::unauthenticated(station_url)
            .map_err(|error| format!("Build pairing status client: {error}"))?
            .sdk_http_client()
            .map_err(|error| format!("Build pairing status HTTP client: {error}"))?;
        let status = status_http
            .device_pairing_status(&arkret_sdk::DevicePairingStatusRequestBody {
                device_pairing_request_id: pairing.request_id.clone(),
                pairing_code: pairing.pairing_code.clone(),
            })
            .await
            .map_err(|error| {
                classify_returning_verification_error(
                    "Read accepted device-pairing status",
                    error.into(),
                )
            })?;
        if status.state != arkret_sdk::DevicePairingState::Authorized {
            return Err(ReturningSessionExchangeError::Fatal(
                "The paired-device session was issued before its staged request reported authorized."
                    .to_owned(),
            ));
        }
        crate::identity::device_pairing::verify_authorized_pairing_event_for_authority(
            &principal_http,
            &pairing.principal_did,
            &pairing.account_id,
            &status,
            &pairing.target_proof,
        )
        .await
        .map_err(|error| {
            classify_returning_verification_error(
                "Verify accepted paired-device authorization Event",
                error,
            )
        })?;
    }
    let account = crate::transport::account::account_me(&principal_http)
        .await
        .map_err(|error| {
            classify_returning_verification_error("Station rejected the returning session", error)
        })?;
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
        classify_returning_verification_error("Verify active principal resolution", error)
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

pub(super) fn persisted_session_grant_from_state(
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
        granted_scope: grant.granted_scope.clone(),
        account_id: grant.account_id.clone(),
        device_id,
        station_url,
        grant_expires_at: Some(grant.expires_at),
        stored_at: Utc::now(),
    }
}

pub(super) fn apply_authenticated_account_locale(
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

pub(super) fn persist_pending_account_handoff(
    store: &mut LocalStateStore,
    pending_handoff: crate::state::PendingAccountHandoff,
) -> anyhow::Result<()> {
    crate::identity::account_auth::persist_reconciled_handoff(store, pending_handoff)
}

pub(super) async fn persist_pending_account_handoff_durably(
    state_store: &mut SyncSignal<LocalStateStore>,
    pending_handoff: &crate::state::PendingAccountHandoff,
) -> Result<(), String> {
    let barrier = {
        let mut store = state_store.write();
        persist_pending_account_handoff(&mut store, pending_handoff.clone())
            .map_err(|error| format!("Persist account handoff checkpoint failed: {error}"))?;
        store.begin_durable_flush().map_err(|error| {
            format!("Prepare account handoff durability barrier failed: {error}")
        })?
    };
    barrier
        .wait()
        .await
        .map_err(|error| format!("Durably persist account handoff checkpoint failed: {error}"))
}
