use super::*;

pub(super) fn session_grant_boot_usable(
    grant: &PersistedSessionGrant,
    active_account: &crate::config::ActiveAccountContext,
    now_unix: i64,
) -> bool {
    if grant.grant_jwt.trim().is_empty()
        || !crate::identity::session_refresh::grant_matches_station(
            grant,
            active_account.server_url.as_str(),
        )
        || !crate::identity::session_refresh::grant_matches_principal_id(
            grant,
            active_account.principal_id(),
        )
        || grant.device_id != active_account.device_id
        || grant.audience_id != active_account.authority.station_id
    {
        return false;
    }
    if grant
        .grant_expires_at
        .is_some_and(|expires_at| expires_at.timestamp() <= now_unix)
    {
        return false;
    }
    true
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum SessionBootState {
    Checking,
    Restoring,
    Authenticated,
    Unauthenticated,
}

impl SessionBootState {
    pub(super) fn from_boot_material(credential: &str, can_restore_session: bool) -> Self {
        if !credential.trim().is_empty() {
            Self::Checking
        } else if can_restore_session {
            Self::Restoring
        } else {
            Self::Unauthenticated
        }
    }
}

pub(super) fn transition_session_boot_state(
    mut state: Signal<SessionBootState>,
    next: SessionBootState,
    reason: &'static str,
) {
    let previous = *state.peek();
    if previous == next {
        return;
    }
    // Debug wasm promotes this audit trail to WARN because its console layer
    // intentionally filters normal INFO traffic; release builds keep INFO.
    #[cfg(all(target_arch = "wasm32", debug_assertions))]
    tracing::warn!(
        target: "session_state",
        from = ?previous,
        to = ?next,
        reason,
        "session boot state transition"
    );
    #[cfg(not(all(target_arch = "wasm32", debug_assertions)))]
    tracing::info!(
        target: "session_state",
        from = ?previous,
        to = ?next,
        reason,
        "session boot state transition"
    );
    state.set(next);
}

/// Publish a newly accepted session as one generation change.
///
/// Durable account, grant, and key writes must complete before this boundary.
/// Incrementing both fences before exposing the token prevents an older
/// background refresh from clearing the replacement session after login.
pub(crate) fn accept_authenticated_session(
    session: &crate::runtime::session::SessionCoordinator,
    mut session_generation: Signal<u64>,
    mut token: Signal<String>,
    credential: String,
) {
    debug_assert!(!credential.trim().is_empty());
    let next_generation = (*session_generation.peek()).wrapping_add(1);
    session_generation.set(next_generation);
    session.replace(credential.clone());
    token.set(credential);
}

pub(super) fn should_wait_for_secure_store_session_restore(
    credential: &str,
    can_restore_session: bool,
    _principal_id: &str,
    secure_store_ready: bool,
) -> bool {
    // On wasm the accepted account context and session grant both live in the
    // encrypted IndexedDB tier.  The synchronous bootstrap intentionally
    // cannot see either of them, so an empty principal here does not prove
    // that this is a signed-out browser.  Keep the auth surface in Restoring
    // until IndexedDB has settled; the ready-state pass below will classify a
    // genuinely fresh browser as Unauthenticated immediately afterwards.
    credential.trim().is_empty() && !can_restore_session && !secure_store_ready
}

pub(super) fn session_boot_state_from_bootstrap_material(
    credential: &str,
    can_restore_session: bool,
    principal_id: &str,
    secure_store_ready: bool,
) -> SessionBootState {
    if should_wait_for_secure_store_session_restore(
        credential,
        can_restore_session,
        principal_id,
        secure_store_ready,
    ) {
        SessionBootState::Restoring
    } else {
        SessionBootState::from_boot_material(credential, can_restore_session)
    }
}

pub(super) fn rehydrated_session_credential_for_active_config(
    config: &ClientConfig,
    desired_account: Option<&crate::config::ActiveAccountContext>,
) -> Option<String> {
    let (Some(account), Some(desired_account)) = (config.active_account.as_ref(), desired_account)
    else {
        return None;
    };
    let cred_empty = config.session_credential.trim().is_empty();
    let authority_mismatch = account.authority != desired_account.authority;
    let device_mismatch = account.device_id != desired_account.device_id;
    if cred_empty || authority_mismatch || device_mismatch {
        tracing::debug!(
            target: "secure_store",
            cred_empty,
            authority_mismatch,
            device_mismatch,
            stored_authority = ?account.authority,
            desired_authority = ?desired_account.authority,
            stored_device = %account.device_id,
            desired_device = %desired_account.device_id,
            "rehydrate session credential: returning None (credential does not match active config)"
        );
        None
    } else {
        Some(config.session_credential.clone())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum AuthSurface {
    AppShell,
    Login,
    Register,
    Callback,
    Restoring,
}

pub(super) fn auth_surface_for_route(
    route: &Route,
    has_session: bool,
    boot_state: SessionBootState,
    secure_store_ready: bool,
) -> AuthSurface {
    // Browser secure storage is a one-shot startup barrier, not a recurring
    // session status. Every auth flow depends on the account-scoped grant and
    // signing keys hydrated behind this barrier, including OIDC callback
    // completion. Mounting the callback before it settles lets a late hydrate
    // overwrite or discard the newly accepted session.
    if !secure_store_ready {
        AuthSurface::Restoring
    } else if matches!(route, Route::Onboarding) {
        // Account-first onboarding intentionally runs before a session grant
        // exists; the short-lived handoff credential is held separately. This
        // check must precede the generic Restoring guard because onboarding
        // deliberately pauses ConnectionEffects and therefore does not rely on
        // that effect to reclassify the session boot state.
        AuthSurface::AppShell
    } else if !has_session && boot_state == SessionBootState::Restoring {
        AuthSurface::Restoring
    } else if has_session {
        AuthSurface::AppShell
    } else if matches!(route, Route::AuthCallback) {
        AuthSurface::Callback
    } else if matches!(route, Route::Register) {
        AuthSurface::Register
    } else {
        AuthSurface::Login
    }
}

/// Account projections may be rendered only when the in-memory snapshot owner
/// still matches the current account. Pre-session onboarding is deliberately
/// excluded: it runs in the anonymous pre-DID scope and must never paint the
/// previous account's cached Realm tree.
pub(super) fn account_projections_visible(
    route: &Route,
    has_session: bool,
    current_principal_id: &str,
    projection_owner_did: &str,
) -> bool {
    let current = current_principal_id.trim();
    !current.is_empty()
        && current == projection_owner_did.trim()
        && (has_session || !matches!(route, Route::Onboarding))
}

pub(super) fn should_redirect_to_dashboard_after_login(route: &Route) -> bool {
    matches!(route, Route::Login | Route::Register | Route::AuthCallback)
}

pub(super) fn authenticated_content_route(route: &Route, has_session: bool) -> Route {
    if has_session && should_redirect_to_dashboard_after_login(route) {
        Route::Dashboard
    } else {
        route.clone()
    }
}

pub(super) fn initial_session_credential_from_state(
    local_state: &ClientLocalState,
    config: &ClientConfig,
    now_unix: i64,
) -> String {
    if let Some(grant) = local_state.session_grant.as_ref() {
        return if config
            .active_account
            .as_ref()
            .is_some_and(|account| session_grant_boot_usable(grant, account, now_unix))
        {
            grant.grant_jwt.clone()
        } else {
            String::new()
        };
    }
    String::new()
}

#[cfg(test)]
mod account_projection_tests {
    use super::*;

    fn principal(value: &str) -> arkret_sdk::DidCoreId {
        arkret_sdk::DidCoreId::new(value.to_owned()).expect("valid principal id")
    }

    #[test]
    fn pre_session_onboarding_never_exposes_previous_account_projections() {
        assert!(!account_projections_visible(
            &Route::Onboarding,
            false,
            principal("ak:did_core:webvh:znew:principal.example").as_str(),
            principal("ak:did_core:webvh:zold:principal.example").as_str(),
        ));
        assert!(!account_projections_visible(
            &Route::Onboarding,
            false,
            principal("ak:did_core:webvh:zold:principal.example").as_str(),
            principal("ak:did_core:webvh:zold:principal.example").as_str(),
        ));
    }

    #[test]
    fn account_projection_owner_must_match_even_with_a_live_session() {
        assert!(!account_projections_visible(
            &Route::Dashboard,
            true,
            principal("ak:did_core:webvh:znew:principal.example").as_str(),
            principal("ak:did_core:webvh:zold:principal.example").as_str(),
        ));
        assert!(account_projections_visible(
            &Route::Dashboard,
            true,
            principal("ak:did_core:webvh:znew:principal.example").as_str(),
            principal("ak:did_core:webvh:znew:principal.example").as_str(),
        ));
    }
}

/// localStorage key the cotest joint-e2e harness uses to hand inkson a real
/// `ak.session.grant` + the DPoP device seed it is bound to. Read ONCE at boot,
/// only in wasm builds compiled with `wasm-localstorage-secrets-test`.
#[cfg(all(target_arch = "wasm32", feature = "wasm-localstorage-secrets-test"))]
pub(super) const TEST_SESSION_INJECTION_KEY: &str = "inkson.test.session_injection.v1";

#[cfg(all(target_arch = "wasm32", feature = "wasm-localstorage-secrets-test"))]
pub(super) const TEST_SESSION_CREDENTIAL_INJECTION_KEY: &str =
    "inkson.test.session_credential_injection.v1";

#[cfg(any(
    test,
    all(target_arch = "wasm32", feature = "wasm-localstorage-secrets-test")
))]
fn parse_test_account_id(
    fixture: &Value,
) -> Result<arkret_sdk::AccountId, &'static str> {
    let value = fixture
        .get("account_id")
        .ok_or("account_id is missing")?
        .clone();
    let account_id: arkret_sdk::AccountId =
        serde_json::from_value(value).map_err(|_| "account_id is invalid")?;
    account_id.validate().map_err(|_| "account_id is invalid")?;
    Ok(account_id)
}

/// Dev-only bearer injection for cotest scenarios that intentionally exercise
/// soland's development login rather than a DPoP-bound account grant. This is
/// compiled only into the explicit localStorage-secrets test build.
#[cfg(all(target_arch = "wasm32", feature = "wasm-localstorage-secrets-test"))]
pub(super) fn inject_test_session_credential(
    config_store: Signal<LocalConfigStore>,
    server_url: &str,
    principal_id: Option<arkret_sdk::DidCoreId>,
    device_id: &str,
) -> Option<String> {
    let credential = web_sys::window()
        .and_then(|window| window.local_storage().ok().flatten())
        .and_then(|storage| {
            storage
                .get_item(TEST_SESSION_CREDENTIAL_INJECTION_KEY)
                .ok()
                .flatten()
        })?;
    if credential.trim().is_empty() {
        return None;
    }
    persist_config(
        config_store,
        server_url.to_owned(),
        principal_id,
        device_id.to_owned(),
        credential.clone(),
    );
    Some(credential)
}

/// Dev-only boot injection of a real grant + DPoP key (cotest joint e2e,
/// ②(A+②) model). Returns the injected grant JWT so the caller can seed the
/// in-memory `token` signal before the bootstrap `connect()` reads it.
///
/// Timing: this MUST run after the IndexedDB/SubtleCrypto store is installed,
/// but before `secure_store_bootstrap_ready` lets the bootstrap `connect()`
/// block read `token` and `state_store`. Session and DPoP material must never
/// be downgraded into the synchronous localStorage fallback, even in tests.
///
/// On success it (1) writes the DPoP device key to the initialized IndexedDB
/// secure store, with a thumbprint that equals the grant's `cnf.jkt` because
/// both derive from the same seed, and (2) persists a `PersistedSessionGrant`
/// whose
/// `station_url` is the active server so the bootstrap does not treat
/// it as stale, and (3) creates the account MLS root that a completed first-device
/// enrollment would already have established.
#[cfg(all(target_arch = "wasm32", feature = "wasm-localstorage-secrets-test"))]
pub(super) async fn inject_test_session_grant(
    state_store: &mut SyncSignal<LocalStateStore>,
    config_store: Signal<LocalConfigStore>,
    server_url: &str,
    account: Option<crate::config::ActiveAccountContext>,
    device_id: &str,
    secure_store: &dyn crate::secure_key_store::SecureKeyStore,
) -> Option<String> {
    let raw = match web_sys::window()
        .and_then(|window| window.local_storage().ok().flatten())
        .and_then(|storage| storage.get_item(TEST_SESSION_INJECTION_KEY).ok().flatten())
    {
        Some(raw) => raw,
        None => {
            tracing::warn!(
                target: "mls_admission",
                "test session injection skipped: no {TEST_SESSION_INJECTION_KEY} in localStorage"
            );
            return None;
        }
    };
    let parsed: Value = match serde_json::from_str(&raw) {
        Ok(parsed) => parsed,
        Err(error) => {
            tracing::warn!(
                ?error,
                fixture_len = raw.len(),
                "test session injection skipped: invalid JSON fixture"
            );
            return None;
        }
    };
    let fixture_account_id = match parse_test_account_id(&parsed) {
        Ok(account_id) => account_id,
        Err(error) => {
            tracing::warn!(
                error,
                "test session injection skipped: invalid account_id fixture"
            );
            return None;
        }
    };
    let Some(expected_account) = account else {
        tracing::warn!("test session injection skipped: active account context is unavailable");
        return None;
    };
    let principal_did = expected_account.did().clone();
    let account_key = expected_account.principal_id().clone();
    if fixture_account_id != expected_account.authority {
        tracing::warn!("test session injection skipped: account_id does not match active account");
        return None;
    }
    // The browser fixture starts with the account DID already present in the
    // config signals, but a fresh LocalStateStore can still be scoped to the
    // anonymous namespace. Defensively select the fixture account before
    // persisting so connect() observes the grant and resumable registration in
    // the same account scope. SecureStoreEffects also selects this scope before
    // hydration so the durable snapshot is loaded from the correct namespace.
    let configured_account = config_store
        .read()
        .load_with_secure_store(secure_store)
        .active_account;
    let Some(configured_account) = configured_account.filter(|account| {
        account.principal_id() == &account_key
            && account.did() == &principal_did
            && account.device_id.as_str() == device_id
            && account.server_url.as_str() == server_url
    }) else {
        tracing::warn!(
            principal_did = %principal_did,
            device_id,
            server_url,
            "test session injection skipped: active account config does not match fixture"
        );
        return None;
    };
    if let Err(error) = state_store
        .write()
        .switch_active_account(&configured_account)
    {
        tracing::warn!(
            ?error,
            "test session injection: account scope activation failed"
        );
        return None;
    }
    if parsed
        .get("recovery_gate_verified")
        .and_then(Value::as_bool)
        == Some(true)
    {
        crate::event_submit::remember_verified_recovery_gate(principal_did.as_str(), device_id);
    }
    for (fixture_field, private_data_key) in [
        ("local_recovery_state", "recovery.state.v1"),
        ("mls_recovery_backup_state", "mls.recovery_backup.v1"),
    ] {
        if let Some(value) = parsed.get(fixture_field) {
            let payload = match serde_json::to_string(value) {
                Ok(payload) => payload,
                Err(error) => {
                    tracing::warn!(
                        ?error,
                        fixture_field,
                        "test session injection: invalid local metadata fixture"
                    );
                    return None;
                }
            };
            state_store
                .write()
                .save_private_data(account_key.as_str(), private_data_key, payload);
        }
    }
    if let Some(value) = parsed.get("pending_principal_registration").cloned() {
        match serde_json::from_value::<crate::state::PendingPrincipalRegistration>(value) {
            Ok(registration) if registration.did == principal_did => {
                if let Err(error) = state_store
                    .write()
                    .set_pending_principal_registration(Some(registration))
                {
                    tracing::warn!(
                        ?error,
                        "test session injection: pending principal registration persist failed"
                    );
                    return None;
                }
            }
            Ok(_) => {
                tracing::warn!(
                    "test session injection: pending principal registration DID mismatch"
                );
                return None;
            }
            Err(error) => {
                tracing::warn!(
                    ?error,
                    "test session injection: invalid pending principal registration"
                );
                return None;
            }
        }
    }
    if let Some(value) = parsed.get("recovery_material_evidence").cloned() {
        match serde_json::from_value::<crate::state::RecoveryMaterialEvidence>(value) {
            Ok(evidence) => {
                if let Err(error) = state_store
                    .write()
                    .set_recovery_material_evidence(Some(evidence))
                {
                    tracing::warn!(
                        ?error,
                        "test session injection: recovery material evidence persist failed"
                    );
                    return None;
                }
            }
            Err(error) => {
                tracing::warn!(
                    ?error,
                    "test session injection: invalid recovery material evidence"
                );
                return None;
            }
        }
    }
    let Some(grant_jwt) = parsed
        .get("grant_jwt")
        .and_then(Value::as_str)
        .map(str::to_owned)
    else {
        tracing::warn!("test session injection skipped: grant_jwt is missing or not a string");
        return None;
    };
    let Some(dpop_seed_b64url) = parsed
        .get("dpop_seed_b64url")
        .and_then(Value::as_str)
        .map(str::to_owned)
    else {
        tracing::warn!(
            "test session injection skipped: dpop_seed_b64url is missing or not a string"
        );
        return None;
    };
    if grant_jwt.trim().is_empty() || dpop_seed_b64url.trim().is_empty() {
        tracing::warn!(
            target: "mls_admission",
            "test session injection skipped: empty grant_jwt or dpop_seed"
        );
        return None;
    }
    let grant_id = parsed
        .get("grant_id")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    let audience = parsed
        .get("audience")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();

    let record = match crate::identity::account_auth::grant_dpop::dpop_device_key_record_from_seed(
        &dpop_seed_b64url,
    ) {
        Ok(record) => record,
        Err(error) => {
            tracing::warn!(?error, "test session injection: invalid DPoP seed");
            return None;
        }
    };
    if let Err(error) = state_store
        .write()
        .set_dpop_device_key_with_secure_store(Some(record), secure_store)
    {
        tracing::warn!(?error, "test session injection: DPoP key persist failed");
        return None;
    }
    // 0004 §4.2/§4.3: the injected `dpop_seed_b64url` is the key the issued grant's
    // `cnf.jkt` binds to — it is the GRANT-BINDING (DPoP) key, NOT the device
    // identity key. Persist it as the grant-binding seed so `ensure_device_key`
    // (which now sources the grant-binding store) mints DPoP proofs whose
    // thumbprint matches `cnf.jkt`. The event signer (device identity key that
    // signs events / KeyPackages / MLS) is activated SEPARATELY from the account
    // signing seed and bound to the injected device id, so the two lifecycles
    // stay decoupled just as they do in production.
    if let Err(error) =
        crate::secure_key_store::store_grant_binding_seed_b64url(secure_store, &dpop_seed_b64url)
    {
        tracing::warn!(
            ?error,
            "test session injection: grant-binding key persist failed"
        );
        return None;
    }
    let event_signer_result = parsed
        .get("event_signing_seed_b64url")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|seed| !seed.is_empty())
        .map_or_else(
            || crate::event_signer::bootstrap_default_signer_for_device("inkson", device_id),
            |seed| {
                crate::event_signer::activate_device_signer_from_seed_b64url_for_device(
                    seed,
                    Some(secure_store),
                    Some(device_id),
                )
            },
        );
    if let Err(error) = event_signer_result {
        tracing::warn!(
            ?error,
            "test session injection: device identity signer install failed"
        );
        return None;
    }
    if let Err(error) =
        crate::event_signer::bind_active_signer_principal_device_id(&principal_did, device_id)
    {
        tracing::warn!(
            ?error,
            "test session injection: principal signer binding failed"
        );
        return None;
    }

    let now = chrono::Utc::now();
    let grant = PersistedSessionGrant {
        grant_jwt: grant_jwt.clone(),
        // ②(A+②): the grant rotation proof is signed by the grant-binding DPoP
        // key, not a separate session key, so no PEM is needed; e2e never
        // refreshes the injected grant.
        session_private_key_pem: String::new(),
        grant_id,
        audience_id: arkret_sdk::DidCoreId::new(audience.clone()).ok()?,
        account_id: fixture_account_id,
        device_id: arkret_sdk::DeviceId::new(device_id.to_owned()).ok()?,
        // MUST match the active server so the bootstrap does not discard the
        // grant as stale (see `grant_matches_station`).
        station_url: url::Url::parse(server_url).ok()?,
        grant_expires_at: Some(now + chrono::Duration::hours(8)),
        stored_at: now,
    };
    let user_store = match crate::secure_key_store::UserLocalStore::new(
        grant.account_id.clone(),
        grant.device_id.clone(),
    ) {
        Ok(user_store) => user_store,
        Err(error) => {
            tracing::warn!(
                ?error,
                "test session injection: account secure scope construction failed"
            );
            return None;
        }
    };
    // The injected account becomes the live authenticated account in the same
    // bootstrap transaction. Activate its typed secure scope before any
    // account-data/event submitter can observe the installed grant.
    user_store.activate();
    if let Err(error) =
        crate::mls::runtime::ensure_account_mls_secret_durable(secure_store, user_store.authority())
            .await
    {
        tracing::warn!(
            ?error,
            "test session injection: account MLS root persist failed"
        );
        return None;
    }
    if let Err(error) = crate::state::store_session_grant_in_user_secure_store_durable(
        &user_store,
        secure_store,
        &grant,
    )
    .await
    {
        tracing::warn!(
            ?error,
            "test session injection: session grant durable persist failed"
        );
        return None;
    }
    tracing::warn!(
        target: "mls_admission",
        device = %device_id,
        "test session injection: session grant installed"
    );
    state_store.write().set_session_grant(Some(grant));
    // Mirror the grant into the persisted config credential slot so a re-render /
    // reload rehydrates the same session instead of bouncing to /login.
    persist_config(
        config_store,
        server_url.to_owned(),
        Some(account_key),
        device_id.to_owned(),
        grant_jwt.clone(),
    );
    // The handoff is single-use. The live session coordinator may rotate this
    // grant immediately after boot; retaining the original fixture in
    // localStorage would overwrite that newer durable grant on a hard reload
    // and make an otherwise valid authenticated deep link fall back to login.
    if let Some(storage) =
        web_sys::window().and_then(|window| window.local_storage().ok().flatten())
    {
        let _ = storage.remove_item(TEST_SESSION_INJECTION_KEY);
    }
    Some(grant_jwt)
}

#[cfg(test)]
mod test_session_injection_tests {
    use super::*;

    #[test]
    fn account_id_is_required_and_typed() {
        let parsed = serde_json::json!({
            "account_id": {
                "principal_id": "ak:did_core:web:alice.example",
                "station_id": "ak:did_core:web:station.example"
            }
        });
        let account_id = parse_test_account_id(&parsed).expect("valid account id");
        assert_eq!(account_id.principal_id.as_str(), "ak:did_core:web:alice.example");

        assert_eq!(
            parse_test_account_id(&serde_json::json!({})),
            Err("account_id is missing")
        );
        assert_eq!(
            parse_test_account_id(&serde_json::json!({ "account_id": 42 })),
            Err("account_id is invalid")
        );
    }
}
