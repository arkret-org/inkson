//! Session keep-alive, driven by the persisted `ck.session.grant`.
//!
//! ②(A+②) model (api-conventions.md §3.3): there is **no** second client-visible
//! local session credential minted by soland. After login, the client
//! holds the `ck.session.grant` (issued by the Account Authority) plus the
//! device DPoP holder key whose thumbprint is the grant's `cnf.jkt`. The grant
//! itself is the live credential for `/_cokret/self/*`: every request presents
//! `Authorization: Bearer <grant>` + a per-request `DPoP` proof.
//!
//! This module's only job is therefore to keep that grant fresh:
//!
//! 1. [`refresh_decision`] inspects the persisted [`PersistedSessionGrant`] and decides whether to
//!    do nothing, rotate the grant now, or surface a "must re-login" event.
//! 2. [`exchange_refresh`] rotates a near-expiry grant onto a fresh one via the existing DPoP
//!    refresh (`refresh_session_grant`); when the grant still has runway it is returned unchanged.
//! 3. [`commit_refresh`] persists the (possibly rotated) grant and hands the caller back the live
//!    grant JWT — which the UI swaps into the `token` signal (the "current credential").
//!
//! The split keeps the policy pure (testable without spinning up
//! reqwest) and the IO thin.

use chrono::Utc;

use crate::auth_dpop::DpopHandle;
use crate::config::normalize_server_url;
use crate::local_state::{LocalStateStore, PersistedSessionGrant};

/// Window before the current grant expiry at which the background poller
/// proactively rotates the grant.
pub const REFRESH_SKEW_SECS: i64 = 60;

/// Recommended polling interval for the dioxus `use_future` poll loop.
/// 30s is chosen so that any token expiring within `REFRESH_SKEW_SECS`
/// gets at least one refresh attempt before it dies mid-request.
pub const POLL_INTERVAL_SECS: u64 = 30;

/// Decision the polling tick / 401 retry path reaches after looking at
/// the persisted grant.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RefreshDecision {
    /// No grant on disk. Caller may ask the user to sign in, but this is not
    /// a refresh-endpoint terminal error and must not clear a live credential.
    NoGrant,
    /// Grant is on disk and still has plenty of runway — caller does nothing.
    Fresh,
    /// The grant is within `GRANT_ROTATION_SKEW_SECS` of its own expiry and
    /// should be rotated onto a fresh grant. Caller should run [`run_refresh`].
    Due,
    /// The grant itself appears expired locally. The refresh path still
    /// attempts rotation so only the refresh endpoint's terminal error code
    /// decides whether local session material is cleared.
    GrantExpired,
}

/// Outcome the refresh harness returns to the caller.
#[derive(Clone, Debug)]
pub enum RefreshOutcome {
    /// No persisted grant. Caller may ask the user to sign in, but must not
    /// clear a live credential because no refresh-endpoint terminal code was
    /// observed.
    NoGrant,
    /// Nothing to do; the current grant is still fresh.
    Fresh,
    /// The grant was rotated. `session_credential` carries the live
    /// `ck.session.grant` JWT; caller swaps it into the in-memory credential
    /// signal and the persisted config.
    Refreshed { session_credential: String },
    /// The refresh endpoint reported a terminal grant error. The persisted
    /// grant has been cleared; caller should route to the login view through
    /// the app-wide invalidator.
    LoginRequired { reason: String },
    /// Rotation attempt failed without proving the grant is dead
    /// (network down, 5xx, missing endpoint, or generic auth denial). Caller
    /// should leave the current grant alone.
    Transient { reason: String },
}

/// Rotate the session grant when it has less than this much runway left.
/// The grant is the (minutes-to-hours) refresh credential; rotating it before
/// it dies — onto a fresh grant via the DPoP holder proof — is what slides the
/// device session into multi-day territory without re-login. 30 min gives many
/// poll ticks to land a rotation before the grant expires.
pub const GRANT_ROTATION_SKEW_SECS: i64 = 30 * 60;

/// True when the persisted grant is within `GRANT_ROTATION_SKEW_SECS` of its own
/// expiry and should be rotated (DPoP holder proof → fresh grant). `None` grant
/// expiry is treated as "not due" — the 401 path handles unknown-expiry
/// grants, and we must not rotate blindly without a deadline.
pub fn grant_due_for_rotation(grant: &PersistedSessionGrant) -> bool {
    match grant.grant_expires_at {
        Some(expires_at) => {
            expires_at.timestamp() - Utc::now().timestamp() <= GRANT_ROTATION_SKEW_SECS
        }
        None => false,
    }
}

/// True when the grant itself has gone past its `grant_expires_at`.
pub fn grant_is_dead(grant: &PersistedSessionGrant) -> bool {
    matches!(grant.grant_expires_at, Some(expires_at) if expires_at <= Utc::now())
}

/// Inspect the persisted grant and decide what the caller should do.
///
/// ②(A+②): "Due" now means the grant itself is near its own expiry and should
/// be rotated (DPoP holder proof → fresh grant). There is no separate
/// minted local session expiry to chase any more — the grant *is* the credential.
pub fn refresh_decision(store: &LocalStateStore) -> RefreshDecision {
    let Some(grant) = store.session_grant() else {
        return RefreshDecision::NoGrant;
    };
    if grant_is_dead(&grant) {
        return RefreshDecision::GrantExpired;
    }
    if grant_due_for_rotation(&grant) {
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
/// the active server's credential.
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
#[allow(clippy::large_enum_variant)] // the persisted grant dominates the union; happy path.
pub enum RefreshPrepared {
    /// Refresh is already resolved — caller turns this directly into
    /// the outcome and skips the network call.
    Done(RefreshOutcome),
    /// Caller should run [`exchange_refresh`] with these materials and
    /// then feed the result into [`commit_refresh`]. `device_handle` is the
    /// DPoP holder key bound into the grant's `cnf.jkt`; it signs the rotation
    /// proof.
    Ready {
        grant: PersistedSessionGrant,
        device_handle: DpopHandle,
    },
}

/// Synchronous prep: read the persisted grant, decide whether to rotate, and
/// (when due) load the device DPoP key. Writes happen only inside this function
/// or [`commit_refresh`], so the caller can release its `LocalStateStore` borrow
/// before awaiting the network rotation.
pub fn prepare_refresh(store: &mut LocalStateStore) -> RefreshPrepared {
    match refresh_decision(store) {
        RefreshDecision::NoGrant => return RefreshPrepared::Done(RefreshOutcome::NoGrant),
        RefreshDecision::Fresh => return RefreshPrepared::Done(RefreshOutcome::Fresh),
        RefreshDecision::GrantExpired | RefreshDecision::Due => {}
    }

    let Some(grant) = store.session_grant() else {
        return RefreshPrepared::Done(RefreshOutcome::NoGrant);
    };

    prepare_refresh_grant(store, grant)
}

fn prepare_refresh_grant(
    store: &mut LocalStateStore,
    grant: PersistedSessionGrant,
) -> RefreshPrepared {
    // The rotation proof is signed by the durable device DPoP key (the same key
    // bound into the grant's `cnf.jkt`), not the grant's own session key.
    let device_handle = match crate::auth_dpop::ensure_device_key(store) {
        Ok(handle) => handle,
        Err(error) => {
            return RefreshPrepared::Done(RefreshOutcome::Transient {
                reason: format!("could not load device DPoP key for grant rotation: {error}"),
            });
        }
    };

    RefreshPrepared::Ready {
        grant,
        device_handle,
    }
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

/// Like [`prepare_refresh_for_server`], but forces a rotation attempt after the
/// server has already returned a definitive 401 for the current grant. Local
/// expiry metadata can be stale when the Account Authority rotated or revoked
/// the grant early.
pub fn prepare_refresh_for_server_after_unauthorized(
    store: &mut LocalStateStore,
    principal_server_url: &str,
) -> RefreshPrepared {
    let Some(grant) = store.session_grant() else {
        return RefreshPrepared::Done(RefreshOutcome::NoGrant);
    };
    if !grant_matches_principal_server(&grant, principal_server_url) {
        return RefreshPrepared::Done(RefreshOutcome::NoGrant);
    }
    // Even when local expiry metadata says the grant is already dead, attempt
    // the refresh exchange and let the Account Authority's structured terminal
    // error code decide whether the grant is cleared.
    prepare_refresh_grant(store, grant)
}

/// Pure async rotation. Holds no `LocalStateStore` borrow.
///
/// ②(A+②): there is no local session credential minted from the grant. This rotates the near-expiry
/// grant onto a fresh one via the DPoP refresh (`refresh_session_grant`) and
/// returns the rotated [`PersistedSessionGrant`]. The grant itself remains the
/// live credential; the caller swaps its JWT into the `token` signal.
pub async fn exchange_refresh(
    grant: &PersistedSessionGrant,
    device_handle: &DpopHandle,
) -> anyhow::Result<PersistedSessionGrant> {
    rotate_session_grant(grant, device_handle).await
}

/// Rotate a session grant onto a fresh one via the Account Authority's DPoP
/// refresh endpoint. The DPoP proof is `htm=POST`, `htu`=absolute refresh URL,
/// `ath`=hash(prior grant), signed by the device key bound into `cnf.jkt`.
async fn rotate_session_grant(
    grant: &PersistedSessionGrant,
    device_handle: &DpopHandle,
) -> anyhow::Result<PersistedSessionGrant> {
    let gate_account_base =
        crate::coauth::resolve_principal_gate_account_base(&grant.principal_server_url)
            .await
            .map_err(|error| anyhow::anyhow!("resolve Account Authority: {error}"))?;
    let coauth = crate::coauth::CoauthApi::new(&gate_account_base)?;
    let htu = coauth.endpoint_url("session-grants/refresh")?;
    let dpop_proof = device_handle
        .mint_proof("POST", &htu, Some(&grant.grant_jwt))
        .map_err(|error| anyhow::anyhow!("mint rotation DPoP proof: {error}"))?;
    let outcome = refresh_session_grant(
        &gate_account_base,
        &grant.grant_jwt,
        Some(&grant.audience),
        &dpop_proof,
    )
    .await?;
    // The rotated grant binds to the same device key (`cnf.jkt` constant), so
    // the introspection signing key persisted with the grant is this device key.
    let session_private_key_pem = device_handle
        .session_signing_key_pkcs8_pem()
        .map_err(|error| anyhow::anyhow!("export device session key: {error}"))?;
    Ok(PersistedSessionGrant {
        grant_jwt: outcome.grant_jwt,
        session_private_key_pem,
        grant_id: outcome.grant_id,
        audience: outcome.audience,
        principal_id: grant.principal_id.clone(),
        device_id: grant.device_id.clone(),
        principal_server_url: grant.principal_server_url.clone(),
        grant_expires_at: Some(outcome.expires_at),
        stored_at: Utc::now(),
    })
}

/// Synchronous commit: persist the rotated grant (or clear it on a definitive
/// failure) and translate into a `RefreshOutcome` whose `session_credential` carries
/// the live grant JWT (the current credential).
pub fn commit_refresh(
    store: &mut LocalStateStore,
    result: anyhow::Result<PersistedSessionGrant>,
) -> RefreshOutcome {
    match result {
        Ok(rotated) => {
            let grant_jwt = rotated.grant_jwt.clone();
            store.set_session_grant(Some(rotated));
            RefreshOutcome::Refreshed {
                session_credential: grant_jwt,
            }
        }
        Err(error) => {
            if is_grant_dead_error(&error) {
                store.set_session_grant(None);
                RefreshOutcome::LoginRequired {
                    reason: format!("session grant could not be rotated: {error}"),
                }
            } else {
                RefreshOutcome::Transient {
                    reason: format!("session-grant rotation failed: {error}"),
                }
            }
        }
    }
}

/// Convenience wrapper that drives the full prep → exchange → commit
/// strand against a single `&mut LocalStateStore`. Holds the borrow
/// across the network await, so callers backed by a Dioxus
/// `Signal<LocalStateStore>` must orchestrate the three phases by hand
/// (see the session-refresh `use_future` in `app.rs`). Test code that
/// owns the store directly can keep using this entrypoint.
#[cfg(test)]
pub async fn run_refresh(store: &mut LocalStateStore) -> RefreshOutcome {
    let prepared = prepare_refresh(store);
    let (grant, device_handle) = match prepared {
        RefreshPrepared::Done(outcome) => return outcome,
        RefreshPrepared::Ready {
            grant,
            device_handle,
        } => (grant, device_handle),
    };
    let result = exchange_refresh(&grant, &device_handle).await;
    commit_refresh(store, result)
}

/// Rotate the persisted session grant onto a fresh one against the Account
/// Authority's DPoP refresh endpoint (kept from the existing refresh path).
///
/// The endpoint requires:
///
/// * A `DPoP:` header proving possession of the same key that's bound to the grant's `cnf.jkt`
///   claim (issuance side: G3.S1 / G3.C1).
/// * The prior grant JWT in the body (single-use: the old grant is revoked on success).
///
/// Returns the SDK [`cokret_sdk::SessionGrantRefreshOutcome`] body so the caller
/// can persist the new grant id + expiry for the next rotation. The DPoP proof
/// MUST already be minted against `htm=POST`, `htu`=absolute refresh URL,
/// `ath`=hash(prior grant).
pub async fn refresh_session_grant(
    gate_account_base: &str,
    grant_jwt: &str,
    audience: Option<&str>,
    dpop_proof: &str,
) -> anyhow::Result<cokret_sdk::SessionGrantRefreshOutcome> {
    let coauth = crate::coauth::CoauthApi::new(gate_account_base)?;
    coauth
        .refresh_session_grant(grant_jwt, audience, dpop_proof)
        .await
}

fn is_grant_dead_error(error: &anyhow::Error) -> bool {
    // Only refresh-specific terminal grant errors clear the persisted grant.
    // A generic `auth_expired` / 401 on the refresh call can be a stale
    // deployment, proxy route miss, clock skew, or temporary Account Authority
    // outage; treating it as logout causes the UI to throw away recoverable
    // session material.
    if crate::api::is_terminal_session_grant_error(error) {
        return true;
    }
    if let Some(api_error) = error.downcast_ref::<crate::api::CokretApiError>() {
        let code = api_error.error.code();
        let message = api_error.error.message().to_ascii_lowercase();
        if matches!(
            code,
            "invalid_grant"
                | "grant_expired"
                | "grant_revoked"
                | "session_grant_revoked"
                | "grant_already_consumed"
                | "session_grant_not_found"
                | "session_logged_out"
                | "invalid_signature"
                | "did_proof_required"
        ) {
            return true;
        }
        if code == "capability_denied" && terminal_session_grant_message(&message) {
            return true;
        }
    }
    false
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
    // YOU-05-010: shared hermetic state-store fixture from `local_state`.
    use crate::local_state::isolated_store_for_tests as isolated_store;

    fn grant_with_expiry(grant_secs: i64) -> PersistedSessionGrant {
        let now = Utc::now();
        PersistedSessionGrant {
            grant_jwt: "test.grant.jwt".to_owned(),
            session_private_key_pem: "-----BEGIN PRIVATE KEY-----\nMOCK\n-----END PRIVATE KEY-----"
                .to_owned(),
            grant_id: "grant-1".to_owned(),
            audience: "https://principal.example/api".to_owned(),
            principal_id: "did:web:alice.example".to_owned(),
            device_id: "device-1".to_owned(),
            principal_server_url: "https://principal.example".to_owned(),
            grant_expires_at: Some(now + chrono::Duration::seconds(grant_secs)),
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
        store.set_session_grant(Some(grant_with_expiry(86400)));
        assert_eq!(refresh_decision(&store), RefreshDecision::Fresh);
    }

    #[test]
    fn decision_due_when_grant_within_rotation_skew() {
        // ②(A+②): "Due" is driven by the grant's own expiry (rotation), not a
        // separate session-token expiry. Grant within the 30-min skew → rotate.
        let mut store = isolated_store("due");
        store.set_session_grant(Some(grant_with_expiry(600)));
        assert_eq!(refresh_decision(&store), RefreshDecision::Due);
    }

    #[test]
    fn decision_fresh_when_grant_expiry_unknown() {
        // Unknown grant expiry is never blindly rotated by the poller; the 401
        // path forces a rotation attempt instead.
        let mut store = isolated_store("fresh-unknown");
        let mut grant = grant_with_expiry(86400);
        grant.grant_expires_at = None;
        store.set_session_grant(Some(grant));
        assert_eq!(refresh_decision(&store), RefreshDecision::Fresh);
    }

    #[test]
    fn decision_grant_expired_when_past_grant_window() {
        let mut store = isolated_store("grant-expired");
        store.set_session_grant(Some(grant_with_expiry(-60)));
        assert_eq!(refresh_decision(&store), RefreshDecision::GrantExpired);
    }

    #[test]
    fn grant_match_normalizes_current_server_url() {
        let grant = grant_with_expiry(86400);
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
        store.set_session_grant(Some(grant_with_expiry(86400)));

        let outcome = prepare_refresh_for_server(&mut store, "https://other-principal.example");

        assert!(matches!(
            outcome,
            RefreshPrepared::Done(RefreshOutcome::NoGrant)
        ));
        assert!(store.session_grant().is_some());
    }

    #[test]
    fn commit_clears_grant_and_requires_login_when_principal_reports_revoked_session_grant() {
        let mut store = isolated_store("revoked-grant");
        store.set_session_grant(Some(grant_with_expiry(86400)));
        let error: anyhow::Error = crate::api::CokretApiError {
            status: reqwest::StatusCode::FORBIDDEN,
            error: crate::api::decode_cokret_error(
                reqwest::StatusCode::FORBIDDEN,
                br#"{"ok":false,"error":{"code":"capability_denied","message":"session grant is not active: revoked"},"request_id":"ck:request:01964137-0000-7000-8000-000000000012"}"#,
            ),
        }
        .into();

        let outcome = commit_refresh(&mut store, Err(error));

        assert!(matches!(outcome, RefreshOutcome::LoginRequired { .. }));
        assert!(store.session_grant().is_none());
    }

    #[test]
    fn commit_clears_grant_when_refresh_reports_already_consumed() {
        let mut store = isolated_store("consumed-grant");
        store.set_session_grant(Some(grant_with_expiry(86400)));
        let error: anyhow::Error = crate::api::CokretApiError {
            status: reqwest::StatusCode::BAD_REQUEST,
            error: crate::api::decode_cokret_error(
                reqwest::StatusCode::BAD_REQUEST,
                br#"{"ok":false,"error":{"code":"grant_already_consumed","message":"session grant already consumed; its rotation chain cannot continue"}}"#,
            ),
        }
        .into();

        let outcome = commit_refresh(&mut store, Err(error));

        assert!(matches!(outcome, RefreshOutcome::LoginRequired { .. }));
        assert!(store.session_grant().is_none());
    }

    #[test]
    fn commit_clears_grant_when_refresh_rejects_holder_proof() {
        let mut store = isolated_store("invalid-proof-grant");
        store.set_session_grant(Some(grant_with_expiry(86400)));
        let error: anyhow::Error = crate::api::CokretApiError {
            status: reqwest::StatusCode::UNAUTHORIZED,
            error: crate::api::decode_cokret_error(
                reqwest::StatusCode::UNAUTHORIZED,
                br#"{"ok":false,"error":{"code":"invalid_signature","message":"DPoP proof key does not match grant cnf.jkt"}}"#,
            ),
        }
        .into();

        let outcome = commit_refresh(&mut store, Err(error));

        assert!(matches!(outcome, RefreshOutcome::LoginRequired { .. }));
        assert!(store.session_grant().is_none());
    }

    #[test]
    fn commit_keeps_grant_for_unrelated_capability_denial() {
        let mut store = isolated_store("unrelated-capability-denied");
        store.set_session_grant(Some(grant_with_expiry(86400)));
        let error: anyhow::Error = crate::api::CokretApiError {
            status: reqwest::StatusCode::FORBIDDEN,
            error: crate::api::decode_cokret_error(
                reqwest::StatusCode::FORBIDDEN,
                br#"{"ok":false,"error":{"code":"capability_denied","message":"actor is not a member of the event Space"},"request_id":"ck:request:01964137-0000-7000-8000-000000000012"}"#,
            ),
        }
        .into();

        let outcome = commit_refresh(&mut store, Err(error));

        assert!(matches!(outcome, RefreshOutcome::Transient { .. }));
        assert!(store.session_grant().is_some());
    }

    #[test]
    fn commit_keeps_grant_for_generic_auth_expired_refresh_failure() {
        let mut store = isolated_store("generic-auth-expired-refresh");
        store.set_session_grant(Some(grant_with_expiry(86400)));
        let error: anyhow::Error = crate::api::CokretApiError {
            status: reqwest::StatusCode::UNAUTHORIZED,
            error: crate::api::decode_cokret_error(
                reqwest::StatusCode::UNAUTHORIZED,
                br#"{"ok":false,"error":{"code":"auth_expired","message":"temporary auth gateway denial"}}"#,
            ),
        }
        .into();

        let outcome = commit_refresh(&mut store, Err(error));

        assert!(matches!(outcome, RefreshOutcome::Transient { .. }));
        assert!(store.session_grant().is_some());
    }

    #[test]
    fn commit_keeps_grant_for_unstructured_terminal_looking_text() {
        let mut store = isolated_store("unstructured-terminal-looking-text");
        store.set_session_grant(Some(grant_with_expiry(86400)));
        let error = anyhow::anyhow!("upstream said grant_revoked without an error envelope");

        let outcome = commit_refresh(&mut store, Err(error));

        assert!(matches!(outcome, RefreshOutcome::Transient { .. }));
        assert!(store.session_grant().is_some());
    }

    #[test]
    fn grant_due_for_rotation_fires_only_inside_skew() {
        // Plenty of grant runway (2h) → not yet due to rotate.
        let fresh = grant_with_expiry(7200);
        assert!(!grant_due_for_rotation(&fresh));

        // Grant within the rotation skew (10 min left) → rotate now, before it
        // dies, so the session slides into multi-day territory.
        let near = grant_with_expiry(600);
        assert!(grant_due_for_rotation(&near));

        // Unknown grant expiry → never blindly rotate (re-exchange handles it).
        let mut unknown = grant_with_expiry(7200);
        unknown.grant_expires_at = None;
        assert!(!grant_due_for_rotation(&unknown));
    }

    #[test]
    fn poll_constants_are_sane() {
        const { assert!(POLL_INTERVAL_SECS > 0) };
        const { assert!(POLL_INTERVAL_SECS <= 60) };
        const { assert!(REFRESH_SKEW_SECS > POLL_INTERVAL_SECS as i64) };
    }
}
