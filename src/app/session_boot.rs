use super::*;

pub(super) fn session_grant_boot_usable(
    grant: &PersistedSessionGrant,
    principal_server_url: &str,
    now_unix: i64,
) -> bool {
    if grant.grant_jwt.trim().is_empty()
        || !crate::identity::session_refresh::grant_matches_principal_server(
            grant,
            principal_server_url,
        )
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

    fn is_pending(self) -> bool {
        matches!(self, Self::Checking | Self::Restoring)
    }
}

pub(super) fn should_wait_for_secure_store_session_restore(
    credential: &str,
    can_restore_session: bool,
    account_did: &str,
    secure_store_ready: bool,
) -> bool {
    credential.trim().is_empty()
        && !can_restore_session
        && !account_did.trim().is_empty()
        && !secure_store_ready
}

pub(super) fn session_boot_state_from_bootstrap_material(
    credential: &str,
    can_restore_session: bool,
    account_did: &str,
    secure_store_ready: bool,
) -> SessionBootState {
    if should_wait_for_secure_store_session_restore(
        credential,
        can_restore_session,
        account_did,
        secure_store_ready,
    ) {
        SessionBootState::Restoring
    } else {
        SessionBootState::from_boot_material(credential, can_restore_session)
    }
}

pub(super) fn rehydrated_session_credential_for_active_config(
    config: &ClientConfig,
    base_url: &str,
    account_did: &str,
    device_id: &str,
) -> Option<String> {
    let cred_empty = config.session_credential.trim().is_empty();
    let server_mismatch =
        normalize_server_url(&config.server_url) != normalize_server_url(base_url);
    let account_mismatch = config.account_did.trim() != account_did.trim();
    let device_mismatch = config.device_id.trim() != device_id.trim();
    if cred_empty || server_mismatch || account_mismatch || device_mismatch {
        tracing::warn!(
            target: "secure_store",
            cred_empty,
            server_mismatch,
            account_mismatch,
            device_mismatch,
            stored_server = %config.server_url,
            want_server = %base_url,
            stored_account = %config.account_did,
            want_account = %account_did,
            stored_device = %config.device_id,
            want_device = %device_id,
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
    Callback,
    Restoring,
}

pub(super) fn auth_surface_for_route(
    route: &Route,
    has_session: bool,
    boot_state: SessionBootState,
) -> AuthSurface {
    if matches!(route, Route::AuthCallback) {
        AuthSurface::Callback
    } else if has_session {
        AuthSurface::AppShell
    } else if boot_state.is_pending() {
        AuthSurface::Restoring
    } else {
        AuthSurface::Login
    }
}

pub(super) fn should_redirect_to_dashboard_after_login(route: &Route) -> bool {
    matches!(route, Route::Login | Route::AuthCallback)
}

pub(super) fn initial_session_credential_from_state(
    local_state: &ClientLocalState,
    config: &ClientConfig,
    now_unix: i64,
) -> String {
    if let Some(grant) = local_state.session_grant.as_ref() {
        return if session_grant_boot_usable(grant, &config.server_url, now_unix) {
            grant.grant_jwt.clone()
        } else {
            String::new()
        };
    }
    String::new()
}

/// localStorage key the cotest joint-e2e harness uses to hand inkson a real
/// `ak.session.grant` + the DPoP device seed it is bound to. Read ONCE at boot,
/// only in wasm builds compiled with `wasm-localstorage-secrets-test`.
#[cfg(all(target_arch = "wasm32", feature = "wasm-localstorage-secrets-test"))]
pub(super) const TEST_SESSION_INJECTION_KEY: &str = "inkson.test.session_injection.v1";

#[cfg(all(target_arch = "wasm32", feature = "wasm-localstorage-secrets-test"))]
pub(super) const TEST_SESSION_CREDENTIAL_INJECTION_KEY: &str =
    "inkson.test.session_credential_injection.v1";

/// Dev-only bearer injection for cotest scenarios that intentionally exercise
/// soland's development login rather than a DPoP-bound account grant. This is
/// compiled only into the explicit localStorage-secrets test build.
#[cfg(all(target_arch = "wasm32", feature = "wasm-localstorage-secrets-test"))]
pub(super) fn inject_test_session_credential(
    config_store: Signal<LocalConfigStore>,
    server_url: &str,
    account_did: &str,
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
        account_did.to_owned(),
        device_id.to_owned(),
        credential.clone(),
    );
    Some(credential)
}

/// Dev-only boot injection of a real grant + DPoP key (cotest joint e2e,
/// ②(A+②) model). Returns the injected grant JWT so the caller can seed the
/// in-memory `token` signal before the bootstrap `connect()` reads it.
///
/// Timing: this MUST run before the bootstrap `connect()` block reads `token`
/// and `state_store` (the DPoP key + persisted grant) so the very first
/// `/_arkret/self/*` request carries a valid grant + DPoP proof. It is
/// driven from a `use_hook` placed ahead of that block so it executes once,
/// synchronously, on first render.
///
/// On success it (1) writes the DPoP device key to the secure store through the
/// compile-time test localStorage tier, with a thumbprint that equals the
/// grant's `cnf.jkt` because both derive from the same seed, and (2) persists a
/// `PersistedSessionGrant` whose
/// `principal_server_url` is the active server so the bootstrap does not treat
/// it as stale.
#[cfg(all(target_arch = "wasm32", feature = "wasm-localstorage-secrets-test"))]
pub(super) fn inject_test_session_grant(
    state_store: &mut SyncSignal<LocalStateStore>,
    config_store: Signal<LocalConfigStore>,
    server_url: &str,
    account_did: &str,
    device_id: &str,
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
    let parsed: Value = serde_json::from_str(&raw).ok()?;
    let grant_jwt = parsed.get("grant_jwt")?.as_str()?.to_owned();
    let dpop_seed_b64url = parsed.get("dpop_seed_b64url")?.as_str()?.to_owned();
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
    let secure_store = crate::secure_key_store::default_secure_key_store("inkson");
    if let Err(error) = state_store
        .write()
        .set_dpop_device_key_with_secure_store(Some(record), secure_store.as_ref())
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
    if let Err(error) = crate::secure_key_store::store_grant_binding_seed_b64url(
        secure_store.as_ref(),
        &dpop_seed_b64url,
    ) {
        tracing::warn!(
            ?error,
            "test session injection: grant-binding key persist failed"
        );
        return None;
    }
    if let Err(error) =
        crate::event_signer::bootstrap_default_signer_for_device("inkson", device_id)
    {
        tracing::warn!(
            ?error,
            "test session injection: device identity signer install failed"
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
        audience,
        principal_id: account_did.to_owned(),
        device_id: device_id.to_owned(),
        // MUST match the active server so the bootstrap does not discard the
        // grant as stale (see `grant_matches_principal_server`).
        principal_server_url: server_url.to_owned(),
        grant_expires_at: Some(now + chrono::Duration::hours(8)),
        stored_at: now,
    };
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
        account_did.to_owned(),
        device_id.to_owned(),
        grant_jwt.clone(),
    );
    Some(grant_jwt)
}
