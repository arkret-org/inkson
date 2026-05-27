//! Principal-session refresh, driven by the persisted coauth
//! `session_grant`.
//!
//! `views/login.rs` runs the OIDC handshake against coauth, the coauth
//! `oidc_exchange_path` returns a `session_grant` (long-lived JWT plus
//! an ephemeral signing key), and the client trades that grant at the
//! principal server's `session_grant_exchange_path` for a short-lived
//! bearer `access_token`. The bearer expires on the order of minutes.
//!
//! Without a refresh path the user gets bounced back to the login page
//! every time the bearer dies. We don't have a refresh token (the
//! `DevLoginResponse` body doesn't carry one) — but we still have the
//! grant. Persisting it lets us silently mint a new bearer by repeating
//! the principal-side exchange.
//!
//! This module is the policy layer for that:
//!
//! 1. [`refresh_decision`] inspects the persisted [`PersistedSessionGrant`]
//!    and decides whether to do nothing, re-exchange now, or surface a
//!    "must re-login" event.
//! 2. [`run_refresh`] performs the actual exchange against the principal
//!    server, persisting the fresh `session_expires_at` and returning
//!    the new access token.
//!
//! The split keeps the policy pure (testable without spinning up
//! reqwest) and the IO thin.

use chrono::{DateTime, Utc};

use crate::{
    api::{ContrixApi, SessionGrantIntrospectionProof},
    coauth::{build_session_grant_introspection_proof_bundle, session_grant_signing_key_from_pem},
    config::normalize_server_url,
    local_state::{LocalStateStore, PersistedSessionGrant},
    models::DevLoginResponse,
};

/// Window before the current `session_expires_at` at which the
/// background poller proactively re-exchanges the grant.
pub const REFRESH_SKEW_SECS: i64 = 60;

/// Recommended polling interval for the dioxus `use_future` poll loop.
/// 30s is chosen so that any token expiring within `REFRESH_SKEW_SECS`
/// gets at least one refresh attempt before it dies mid-request.
pub const POLL_INTERVAL_SECS: u64 = 30;

/// Decision the polling tick / 401 retry path reaches after looking at
/// the persisted grant.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RefreshDecision {
    /// No grant on disk — either the user hasn't logged in, or a
    /// previous failure wiped it. Caller must route to the login view.
    NoGrant,
    /// Grant is on disk and the current minted session has plenty of
    /// runway — caller does nothing.
    Fresh,
    /// Session token is within `REFRESH_SKEW_SECS` of expiry (or has no
    /// recorded expiry, which we treat as "always refresh on demand").
    /// Caller should run [`run_refresh`].
    Due,
    /// The grant itself has expired. Re-exchange will fail; caller
    /// should clear local state and bounce to login.
    GrantExpired,
}

/// Outcome the refresh harness returns to the caller.
#[derive(Clone, Debug)]
pub enum RefreshOutcome {
    /// No persisted grant — caller routes to login.
    NoGrant,
    /// Nothing to do; the current session token is still fresh.
    Fresh,
    /// A new principal `access_token` was minted; caller swaps it into
    /// the in-memory token signal and the persisted config.
    Refreshed {
        access_token: String,
        session_expires_at: Option<DateTime<Utc>>,
    },
    /// The grant is dead (expired, revoked, or any non-transient
    /// failure). The persisted grant has been cleared; caller must
    /// route to the login view.
    LoginRequired { reason: String },
    /// Refresh attempt failed without proving the active bearer is dead
    /// (network down, 5xx, or a consumed legacy grant). Caller should
    /// leave the current bearer alone.
    Transient { reason: String },
}

/// True when the persisted bearer is within `REFRESH_SKEW_SECS` of
/// expiry. `None` for `session_expires_at` is treated as "due" — the
/// safe choice since we don't know how much runway the token has.
pub fn session_due_for_refresh(grant: &PersistedSessionGrant) -> bool {
    match grant.session_expires_at {
        Some(expires_at) => expires_at.timestamp() - Utc::now().timestamp() <= REFRESH_SKEW_SECS,
        None => true,
    }
}

/// True when the grant itself has gone past its `grant_expires_at`.
pub fn grant_is_dead(grant: &PersistedSessionGrant) -> bool {
    matches!(grant.grant_expires_at, Some(expires_at) if expires_at <= Utc::now())
}

/// Inspect the persisted grant and decide what the caller should do.
pub fn refresh_decision(store: &LocalStateStore) -> RefreshDecision {
    let Some(grant) = store.session_grant() else {
        return RefreshDecision::NoGrant;
    };
    if grant_is_dead(&grant) {
        return RefreshDecision::GrantExpired;
    }
    if session_due_for_refresh(&grant) {
        return RefreshDecision::Due;
    }
    RefreshDecision::Fresh
}

fn normalized_server_key(server_url: &str) -> String {
    normalize_server_url(server_url)
        .trim()
        .trim_end_matches('/')
        .to_ascii_lowercase()
}

/// True when a persisted grant is scoped to the active Principal Server.
///
/// The client currently keeps one foreground server session. A grant minted
/// for another server must not be refreshed in the background or persisted as
/// the active server's bearer; otherwise an inactive server can indirectly
/// bounce the visible session back to login.
pub fn grant_matches_principal_server(
    grant: &PersistedSessionGrant,
    principal_server_url: &str,
) -> bool {
    let grant_server = normalized_server_key(&grant.principal_server_url);
    let active_server = normalized_server_key(principal_server_url);
    !grant_server.is_empty() && grant_server == active_server
}

/// Outcome of the synchronous prep step. Either the refresh is already
/// resolved (no grant, fresh enough, grant dead) or the caller has the
/// materials it needs to run the async exchange.
///
/// The split exists so the caller can drop its `LocalStateStore` borrow
/// before awaiting the network round-trip. Holding the borrow across
/// the await crashes any concurrent signal mutation with
/// `AlreadyBorrowedMut` — typical victims are UI handlers that persist
/// user preferences (e.g. the sidebar scope toggle).
#[allow(clippy::large_enum_variant)] // session grant + proof bundle dominates the union; happy path.
pub enum RefreshPrepared {
    /// Refresh is already resolved — caller turns this directly into
    /// the outcome and skips the network call.
    Done(RefreshOutcome),
    /// Caller should run [`exchange_refresh`] with these materials and
    /// then feed the result into [`commit_refresh`].
    Ready {
        grant: PersistedSessionGrant,
        proof: SessionGrantIntrospectionProof,
    },
}

/// Synchronous prep: read the persisted grant, decide whether to
/// refresh, and (when due) build the introspection proof. Writes
/// happen only inside this function or [`commit_refresh`], so the
/// caller can release its `LocalStateStore` borrow before awaiting the
/// network exchange.
pub fn prepare_refresh(store: &mut LocalStateStore) -> RefreshPrepared {
    match refresh_decision(store) {
        RefreshDecision::NoGrant => return RefreshPrepared::Done(RefreshOutcome::NoGrant),
        RefreshDecision::Fresh => return RefreshPrepared::Done(RefreshOutcome::Fresh),
        RefreshDecision::GrantExpired => {
            store.set_session_grant(None);
            return RefreshPrepared::Done(RefreshOutcome::LoginRequired {
                reason: "session grant has expired".to_owned(),
            });
        }
        RefreshDecision::Due => {}
    }

    let Some(grant) = store.session_grant() else {
        return RefreshPrepared::Done(RefreshOutcome::NoGrant);
    };

    let signing_key = match session_grant_signing_key_from_pem(&grant.session_private_key_pem) {
        Ok(key) => key,
        Err(error) => {
            store.set_session_grant(None);
            return RefreshPrepared::Done(RefreshOutcome::LoginRequired {
                reason: format!("session grant signing key invalid: {error}"),
            });
        }
    };

    let proof = match build_session_grant_introspection_proof_bundle(
        &grant.grant_id,
        &grant.grant_jwt,
        &grant.audience,
        &signing_key,
    ) {
        Ok(value) => value,
        Err(error) => {
            return RefreshPrepared::Done(RefreshOutcome::Transient {
                reason: format!("could not build introspection proof: {error}"),
            });
        }
    };

    RefreshPrepared::Ready { grant, proof }
}

/// Like [`prepare_refresh`], but refuses to use a grant minted for any server
/// other than the currently selected Principal Server.
pub fn prepare_refresh_for_server(
    store: &mut LocalStateStore,
    principal_server_url: &str,
) -> RefreshPrepared {
    if let Some(grant) = store.session_grant()
        && !grant_matches_principal_server(&grant, principal_server_url)
    {
        return RefreshPrepared::Done(RefreshOutcome::NoGrant);
    }

    prepare_refresh(store)
}

/// Pure async exchange. Holds no `LocalStateStore` borrow.
pub async fn exchange_refresh(
    grant: &PersistedSessionGrant,
    proof: &SessionGrantIntrospectionProof,
) -> anyhow::Result<DevLoginResponse> {
    let api = ContrixApi::new(&grant.principal_server_url)?;
    api.exchange_session_grant_at_with_proof(
        &grant.session_grant_exchange_path,
        &grant.grant_jwt,
        &grant.principal_did,
        &grant.device_id,
        Some(proof),
    )
    .await
}

/// Synchronous commit: persist the outcome (fresh expiry on success,
/// cleared grant on definitive failure) and translate into a
/// `RefreshOutcome` the caller can act on.
pub fn commit_refresh(
    store: &mut LocalStateStore,
    result: anyhow::Result<DevLoginResponse>,
) -> RefreshOutcome {
    match result {
        Ok(session) => {
            let session_expires_at = parse_rfc3339(&session.expires_at);
            store.update_session_expires_at(session_expires_at);
            RefreshOutcome::Refreshed {
                access_token: session.access_token,
                session_expires_at,
            }
        }
        Err(error) => {
            if is_grant_dead_error(&error) {
                store.set_session_grant(None);
                RefreshOutcome::Transient {
                    reason: format!(
                        "session grant cannot refresh principal bearer and was cleared: {error}"
                    ),
                }
            } else {
                RefreshOutcome::Transient {
                    reason: format!("session-grant re-exchange failed: {error}"),
                }
            }
        }
    }
}

/// Convenience wrapper that drives the full prep → exchange → commit
/// flow against a single `&mut LocalStateStore`. Holds the borrow
/// across the network await, so callers backed by a Dioxus
/// `Signal<LocalStateStore>` must orchestrate the three phases by hand
/// (see the session-refresh `use_future` in `app.rs`). Test code that
/// owns the store directly can keep using this entrypoint.
#[cfg(test)]
pub async fn run_refresh(store: &mut LocalStateStore) -> RefreshOutcome {
    let prepared = prepare_refresh(store);
    let (grant, proof) = match prepared {
        RefreshPrepared::Done(outcome) => return outcome,
        RefreshPrepared::Ready { grant, proof } => (grant, proof),
    };
    let result = exchange_refresh(&grant, &proof).await;
    commit_refresh(store, result)
}

fn parse_rfc3339(value: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(value.trim())
        .ok()
        .map(|dt| dt.with_timezone(&Utc))
}

/// G3.Y0 + G3.C1 — exchange the persisted session grant for a fresh
/// one against coauth's `POST /api/v1/session-grants/refresh` endpoint.
///
/// The endpoint requires:
///
/// * A `DPoP:` header proving possession of the same key that's bound
///   to the grant's `cnf.jkt` claim (issuance side: G3.S1 / G3.C1).
/// * The prior grant JWT in the body (single-use: the old grant is
///   revoked on success).
///
/// On success the caller persists the rotated grant + access-token
/// materials and bumps the in-memory token signal. On a 401 / 403 /
/// `refresh_token_already_consumed`-style error the caller must fall
/// through to the soft-logout path (clear access token + bounce to
/// `/login`) but keep the device DPoP key in place per the G3.Y0
/// soft/hard split.
///
/// Returns the [`crate::coauth::RefreshSessionGrantResponse`] body so
/// the caller can persist the new grant id + `cnf.jkt` for the next
/// rotation. The `htu` argument is the absolute URL of coauth's
/// refresh endpoint — the cotest harness pins it; production callers
/// derive it from the persisted grant's audience.
pub async fn refresh_via_dpop(
    auth_server_url: &str,
    grant_jwt: &str,
    audience: Option<&str>,
    dpop_proof: &str,
) -> anyhow::Result<crate::coauth::RefreshSessionGrantResponse> {
    let coauth = crate::coauth::CoauthApi::new(auth_server_url)?;
    coauth
        .refresh_session_grant(grant_jwt, audience, dpop_proof)
        .await
}

fn is_grant_dead_error(error: &anyhow::Error) -> bool {
    // We don't have a structured error code for "grant revoked" — fall
    // back to the same heuristic as session-expired handling. A bare 401
    // might be transient (proxy hiccup, clock skew), but if the error
    // chain mentions `auth_expired` / `invalid_grant` we treat it as
    // terminal.
    if crate::api::is_auth_expired_error(error) {
        return true;
    }
    if let Some(api_error) = error.downcast_ref::<crate::api::ContrixApiError>() {
        let code = api_error.error.code();
        let message = api_error.error.message().to_ascii_lowercase();
        if matches!(
            code,
            "invalid_grant" | "grant_expired" | "grant_revoked" | "session_grant_revoked"
        ) {
            return true;
        }
        if code == "capability_denied" && terminal_session_grant_message(&message) {
            return true;
        }
    }
    let chain = format!("{error}").to_ascii_lowercase();
    chain.contains("invalid_grant")
        || chain.contains("grant_expired")
        || chain.contains("grant_revoked")
        || terminal_session_grant_message(&chain)
}

fn terminal_session_grant_message(message: &str) -> bool {
    message.contains("session grant")
        && (message.contains("revoked")
            || message.contains("not active")
            || message.contains("expired")
            || message.contains("locked")
            || message.contains("suspended"))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(not(target_arch = "wasm32"))]
    use std::path::PathBuf;
    #[cfg(not(target_arch = "wasm32"))]
    use std::time::{SystemTime, UNIX_EPOCH};

    #[cfg(not(target_arch = "wasm32"))]
    fn isolated_store(tag: &str) -> LocalStateStore {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        let path: PathBuf =
            std::env::temp_dir().join(format!("yougen-session-refresh-{tag}-{stamp}.json"));
        LocalStateStore::with_path(path)
    }

    #[cfg(target_arch = "wasm32")]
    fn isolated_store(_tag: &str) -> LocalStateStore {
        LocalStateStore::default()
    }

    fn grant_with_session_expiry(session_secs: i64, grant_secs: i64) -> PersistedSessionGrant {
        let now = Utc::now();
        PersistedSessionGrant {
            grant_jwt: "test.grant.jwt".to_owned(),
            session_private_key_pem: "-----BEGIN PRIVATE KEY-----\nMOCK\n-----END PRIVATE KEY-----"
                .to_owned(),
            grant_id: "grant-1".to_owned(),
            audience: "https://principal.example/api".to_owned(),
            principal_did: "did:web:alice.example".to_owned(),
            device_id: "device-1".to_owned(),
            principal_server_url: "https://principal.example".to_owned(),
            session_grant_exchange_path: "api/v1/auth/session-grant/exchange".to_owned(),
            grant_expires_at: Some(now + chrono::Duration::seconds(grant_secs)),
            session_expires_at: Some(now + chrono::Duration::seconds(session_secs)),
            stored_at: now,
        }
    }

    #[test]
    fn decision_no_grant_when_unset() {
        let store = isolated_store("no-grant");
        assert_eq!(refresh_decision(&store), RefreshDecision::NoGrant);
    }

    #[test]
    fn decision_fresh_when_runway_long() {
        let mut store = isolated_store("fresh");
        store.set_session_grant(Some(grant_with_session_expiry(3600, 86400)));
        assert_eq!(refresh_decision(&store), RefreshDecision::Fresh);
    }

    #[test]
    fn decision_due_when_session_within_skew() {
        let mut store = isolated_store("due");
        store.set_session_grant(Some(grant_with_session_expiry(30, 86400)));
        assert_eq!(refresh_decision(&store), RefreshDecision::Due);
    }

    #[test]
    fn decision_due_when_session_expiry_unknown() {
        let mut store = isolated_store("due-unknown");
        let mut grant = grant_with_session_expiry(3600, 86400);
        grant.session_expires_at = None;
        store.set_session_grant(Some(grant));
        assert_eq!(refresh_decision(&store), RefreshDecision::Due);
    }

    #[test]
    fn decision_grant_expired_when_past_grant_window() {
        let mut store = isolated_store("grant-expired");
        store.set_session_grant(Some(grant_with_session_expiry(3600, -60)));
        assert_eq!(refresh_decision(&store), RefreshDecision::GrantExpired);
    }

    #[test]
    fn grant_match_normalizes_current_server_url() {
        let grant = grant_with_session_expiry(3600, 86400);
        assert!(grant_matches_principal_server(
            &grant,
            "https://principal.example/"
        ));
        assert!(!grant_matches_principal_server(
            &grant,
            "https://other-principal.example"
        ));
    }

    #[test]
    fn prepare_refresh_ignores_grant_for_inactive_server() {
        let mut store = isolated_store("inactive-server-grant");
        store.set_session_grant(Some(grant_with_session_expiry(30, 86400)));

        let outcome = prepare_refresh_for_server(&mut store, "https://other-principal.example");

        assert!(matches!(
            outcome,
            RefreshPrepared::Done(RefreshOutcome::NoGrant)
        ));
        assert!(store.session_grant().is_some());
    }

    #[test]
    fn commit_clears_grant_without_forcing_login_when_principal_reports_revoked_session_grant() {
        let mut store = isolated_store("revoked-grant");
        store.set_session_grant(Some(grant_with_session_expiry(30, 86400)));
        let error: anyhow::Error = crate::api::ContrixApiError {
            status: reqwest::StatusCode::FORBIDDEN,
            error: crate::api::decode_contrix_error(
                reqwest::StatusCode::FORBIDDEN,
                br#"{"ok":false,"error":{"code":"capability_denied","message":"session grant is not active: revoked"},"request_id":"cx:request:01964137-0000-7000-8000-000000000012"}"#,
            ),
        }
        .into();

        let outcome = commit_refresh(&mut store, Err(error));

        assert!(matches!(outcome, RefreshOutcome::Transient { .. }));
        assert!(store.session_grant().is_none());
    }

    #[test]
    fn commit_keeps_grant_for_unrelated_capability_denial() {
        let mut store = isolated_store("unrelated-capability-denied");
        store.set_session_grant(Some(grant_with_session_expiry(30, 86400)));
        let error: anyhow::Error = crate::api::ContrixApiError {
            status: reqwest::StatusCode::FORBIDDEN,
            error: crate::api::decode_contrix_error(
                reqwest::StatusCode::FORBIDDEN,
                br#"{"ok":false,"error":{"code":"capability_denied","message":"actor is not a member of the event Space"},"request_id":"cx:request:01964137-0000-7000-8000-000000000012"}"#,
            ),
        }
        .into();

        let outcome = commit_refresh(&mut store, Err(error));

        assert!(matches!(outcome, RefreshOutcome::Transient { .. }));
        assert!(store.session_grant().is_some());
    }

    #[test]
    fn poll_constants_are_sane() {
        const { assert!(POLL_INTERVAL_SECS > 0) };
        const { assert!(POLL_INTERVAL_SECS <= 60) };
        const { assert!(REFRESH_SKEW_SECS > POLL_INTERVAL_SECS as i64) };
    }
}
