use super::*;

pub(super) fn oidc_access_token_boot_usable(bundle: &OidcTokenBundle, now_unix: i64) -> bool {
    if bundle.access_token.trim().is_empty() {
        return false;
    }
    match bundle.expires_at_unix {
        Some(expires_at) => now_unix + BOOT_ACCESS_TOKEN_SKEW_SECS < expires_at,
        None => true,
    }
}

pub(super) fn session_grant_access_token_boot_usable(
    grant: &PersistedSessionGrant,
    access_token: &str,
    now_unix: i64,
) -> bool {
    if access_token.trim().is_empty() {
        return false;
    }
    if grant
        .grant_expires_at
        .is_some_and(|expires_at| expires_at.timestamp() <= now_unix)
    {
        return false;
    }
    grant
        .session_expires_at
        .is_some_and(|expires_at| now_unix + BOOT_ACCESS_TOKEN_SKEW_SECS < expires_at.timestamp())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum SessionBootState {
    Checking,
    Restoring,
    Authenticated,
    Unauthenticated,
}

impl SessionBootState {
    pub(super) fn from_boot_material(session_token: &str, can_restore_session: bool) -> Self {
        if !session_token.trim().is_empty() {
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
    session_token: &str,
    can_restore_session: bool,
    account_did: &str,
    secure_store_ready: bool,
) -> bool {
    session_token.trim().is_empty()
        && !can_restore_session
        && !account_did.trim().is_empty()
        && !secure_store_ready
}

pub(super) fn session_boot_state_from_bootstrap_material(
    session_token: &str,
    can_restore_session: bool,
    can_reissue_development_session: bool,
    account_did: &str,
    secure_store_ready: bool,
) -> SessionBootState {
    let can_restore_now = can_restore_session || can_reissue_development_session;
    if should_wait_for_secure_store_session_restore(
        session_token,
        can_restore_now,
        account_did,
        secure_store_ready,
    ) {
        SessionBootState::Restoring
    } else {
        SessionBootState::from_boot_material(session_token, can_restore_now)
    }
}

pub(super) fn rehydrated_session_token_for_active_config(
    config: &ClientConfig,
    base_url: &str,
    account_did: &str,
    device_id: &str,
) -> Option<String> {
    if config.session_token.trim().is_empty()
        || normalize_server_url(&config.server_url) != normalize_server_url(base_url)
        || config.account_did.trim() != account_did.trim()
        || config.device_id.trim() != device_id.trim()
    {
        None
    } else {
        Some(config.session_token.clone())
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
    } else if boot_state.is_pending() {
        AuthSurface::Restoring
    } else if has_session {
        AuthSurface::AppShell
    } else {
        AuthSurface::Login
    }
}

pub(super) fn initial_session_token_from_state(
    local_state: &ClientLocalState,
    config: &ClientConfig,
    now_unix: i64,
) -> String {
    if let Some(bundle) = local_state.oidc_tokens.as_ref() {
        // Access tokens are short-lived cache material. On a hard page
        // reload, let the refresh-token/session-grant poller mint a fresh
        // bearer instead of racing boot API calls with an expired one.
        if oidc_access_token_boot_usable(bundle, now_unix) {
            return bundle.access_token.clone();
        }
    }
    if let Some(grant) = local_state.session_grant.as_ref() {
        return if session_grant_access_token_boot_usable(grant, &config.session_token, now_unix) {
            config.session_token.clone()
        } else {
            String::new()
        };
    }
    String::new()
}

/// localStorage key the cotest joint-e2e harness uses to hand yougen a real
/// `ck.session.grant` + the DPoP device seed it is bound to. Read ONCE at boot,
/// only on wasm and only when `wasm_allow_localstorage_secrets()` is set — the
/// same dev-only opt-in the harness already toggles. Production never sets
/// either key, so this path is fully inert there.
#[cfg(target_arch = "wasm32")]
pub(super) const TEST_SESSION_INJECTION_KEY: &str = "yougen.test.session_injection.v1";

/// Dev-only boot injection of a real grant + DPoP key (cotest joint e2e,
/// ②(A+②) model). Returns the injected grant JWT so the caller can seed the
/// in-memory `token` signal before the bootstrap `connect()` reads it.
///
/// Timing: this MUST run before the bootstrap `connect()` block reads `token`
/// and `state_store` (the DPoP key + persisted grant) so the very first
/// `/_cokret/self/*` request carries a valid grant + DPoP + holder proof. It is
/// driven from a `use_hook` placed ahead of that block so it executes once,
/// synchronously, on first render.
///
/// On success it (1) writes the DPoP device key to the secure store via the
/// localStorage tier (the harness sets `allow_localstorage_secrets`), with a
/// thumbprint that equals the grant's `cnf.jkt` because both derive from the
/// same seed, and (2) persists a `PersistedSessionGrant` whose
/// `principal_server_url` is the active server so the bootstrap does not treat
/// it as stale.
#[cfg(target_arch = "wasm32")]
pub(super) fn inject_test_session_grant(
    state_store: &mut Signal<LocalStateStore>,
    config_store: Signal<LocalConfigStore>,
    server_url: &str,
    account_did: &str,
    device_id: &str,
) -> Option<String> {
    if !crate::secure_key_store::wasm_allow_localstorage_secrets() {
        return None;
    }
    let raw = web_sys::window()
        .and_then(|window| window.local_storage().ok().flatten())
        .and_then(|storage| storage.get_item(TEST_SESSION_INJECTION_KEY).ok().flatten())?;
    let parsed: Value = serde_json::from_str(&raw).ok()?;
    let grant_jwt = parsed.get("grant_jwt")?.as_str()?.to_owned();
    let dpop_seed_b64url = parsed.get("dpop_seed_b64url")?.as_str()?.to_owned();
    if grant_jwt.trim().is_empty() || dpop_seed_b64url.trim().is_empty() {
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

    let record = match crate::auth_dpop::dpop_device_key_record_from_seed(&dpop_seed_b64url) {
        Ok(record) => record,
        Err(error) => {
            tracing::warn!(?error, "test session injection: invalid DPoP seed");
            return None;
        }
    };
    let secure_store = crate::secure_key_store::default_secure_key_store("yougen");
    if let Err(error) = state_store
        .write()
        .set_dpop_device_key_with_secure_store(Some(record), secure_store.as_ref())
    {
        tracing::warn!(?error, "test session injection: DPoP key persist failed");
        return None;
    }

    let now = chrono::Utc::now();
    let grant = PersistedSessionGrant {
        grant_jwt: grant_jwt.clone(),
        // ②(A+②): the grant rotation/holder proof is signed by the device DPoP
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
        session_grant_exchange_path: "_cokret/gate/account/session-grants".to_owned(),
        grant_expires_at: Some(now + chrono::Duration::hours(8)),
        session_expires_at: Some(now + chrono::Duration::hours(8)),
        stored_at: now,
    };
    state_store.write().set_session_grant(Some(grant));
    // Mirror the grant into the persisted config bearer slot so a re-render /
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
