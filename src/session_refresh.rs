//! Session keep-alive, driven by the persisted `ak.session.grant`.
//!
//! ②(A+②) model (api-conventions.md §3.3): there is **no** second client-visible
//! local session credential minted by soland. After login, the client
//! holds the `ak.session.grant` (issued by the Account Authority) plus the
//! grant-binding (DPoP) key whose thumbprint is the grant's `cnf.jkt`. The grant
//! itself is the live credential for `/_arkret/self/*`: every request presents
//! `Authorization: Bearer <grant>` + a per-request `DPoP` proof.
//!
//! This module's only job is therefore to keep that grant fresh:
//!
//! 1. [`refresh_decision`] inspects the persisted [`PersistedSessionGrant`] and decides whether to
//!    do nothing, rotate the grant now, or surface a "must re-login" event.
//! 2. [`exchange_refresh`] rotates a near-expiry grant onto a fresh one via garth's session refresh
//!    engine; when the grant still has runway it is returned unchanged.
//! 3. [`commit_refresh`] persists the (possibly rotated) grant and hands the caller back the live
//!    grant JWT — which the UI swaps into the `token` signal (the "current credential").
//!
//! The split keeps the policy pure (testable without spinning up
//! reqwest) and the IO thin.

use anyhow::Context as _;
use arkret_sdk::http_client::{Auth, ClientBuilder};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::Utc;
use garth::{SessionEngine, SessionGrantState, SessionRefreshOptions};
use serde::Serialize;
use url::Url;

use crate::account_auth::grant_dpop::DpopHandle;
use crate::config::normalize_server_url;
use crate::local_state::{LocalStateStore, PersistedSessionGrant};

const SOFT_LOGOUT_RESTORE_OPERATION: &str = "resume_soft_logged_out_session";

// The refresh decision layer (constants, `RefreshDecision`, the due/dead
// predicates) is garth's — inkson only maps its persisted grant into
// `garth::SessionGrantRefreshState` and supplies the wall clock. Semantics
// notes that used to live on a local copy: `NoGrant` must not clear a live
// credential; `GrantExpired` still attempts rotation so only the refresh
// endpoint's terminal error decides whether session material is cleared.
pub use garth::{POLL_INTERVAL_SECS, REFRESH_SKEW_SECS, RefreshDecision};

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
    /// `ak.session.grant` JWT; caller swaps it into the in-memory credential
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

fn grant_refresh_state(grant: &PersistedSessionGrant) -> garth::SessionGrantRefreshState {
    garth::SessionGrantRefreshState {
        grant_expires_at: grant.grant_expires_at,
    }
}

/// True when the persisted grant is within `garth::GRANT_ROTATION_SKEW_SECS` of
/// its own expiry and should be rotated (grant-binding DPoP proof → fresh
/// grant). `None` grant expiry is "not due" — the 401 path handles
/// unknown-expiry grants, and we must not rotate blindly without a deadline.
pub fn grant_due_for_rotation(grant: &PersistedSessionGrant) -> bool {
    garth::grant_due_for_rotation(&grant_refresh_state(grant), Utc::now())
}

/// True when the grant itself has gone past its `grant_expires_at`.
pub fn grant_is_dead(grant: &PersistedSessionGrant) -> bool {
    garth::grant_is_dead(&grant_refresh_state(grant), Utc::now())
}

/// Inspect the persisted grant and decide what the caller should do.
///
/// ②(A+②): "Due" means the grant itself is near its own expiry and should be
/// rotated (grant-binding DPoP proof → fresh grant). There is no separate
/// minted local session expiry to chase — the grant *is* the credential.
pub fn refresh_decision(store: &LocalStateStore) -> RefreshDecision {
    let state = store
        .session_grant()
        .map(|grant| grant_refresh_state(&grant));
    garth::refresh_decision(state.as_ref(), Utc::now())
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
    /// grant-binding (DPoP) key bound into the grant's `cnf.jkt`; the active event
    /// signer supplies the separate device-identity DID proof.
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
    // The DPoP header is signed by the grant-binding key (`cnf.jkt`). The body
    // proof is a separate DID proof signed by the authorized device identity
    // signer, so bind the active signer to the grant's protocol device id here.
    let device_handle = match crate::account_auth::grant_dpop::load_or_recover_device_key(store) {
        Ok(Some(handle)) => handle,
        Ok(None) => {
            return RefreshPrepared::Done(RefreshOutcome::Transient {
                reason: "could not load device DPoP key for grant rotation".to_owned(),
            });
        }
        Err(error) => {
            return RefreshPrepared::Done(RefreshOutcome::Transient {
                reason: format!("could not load device DPoP key for grant rotation: {error}"),
            });
        }
    };
    match crate::event_signer::bind_active_signer_device_id(&grant.device_id) {
        Ok(Some(_)) => {}
        Ok(None) => {
            return RefreshPrepared::Done(RefreshOutcome::Transient {
                reason: "could not load device identity signer for grant rotation".to_owned(),
            });
        }
        Err(error) => {
            return RefreshPrepared::Done(RefreshOutcome::Transient {
                reason: format!("could not bind event signer to grant device: {error}"),
            });
        }
    }

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
/// grant onto a fresh one via garth's DPoP refresh engine and
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
/// `ath`=hash(prior grant), signed by the grant-binding key bound into
/// `cnf.jkt`. The body proof is signed by the authorized device identity key.
async fn rotate_session_grant(
    grant: &PersistedSessionGrant,
    device_handle: &DpopHandle,
) -> anyhow::Result<PersistedSessionGrant> {
    let gate_account_base =
        crate::account_auth::resolve_principal_gate_account_base(&grant.principal_server_url)
            .await
            .map_err(|error| anyhow::anyhow!("resolve Account Authority: {error}"))?;
    let sdk_base_url = sdk_base_url_from_gate_account_base(&gate_account_base)?;
    let http = ClientBuilder::new(sdk_base_url)
        .allow_insecure_localhost()
        .auth(Auth::Dpop(
            device_handle.sdk_dpop_auth_for_access_token(grant.grant_jwt.clone()),
        ))
        .build()
        .map_err(|error| anyhow::anyhow!("build session refresh HTTP client: {error}"))?;
    let refresh_proof = mint_session_grant_refresh_proof(grant)
        .map_err(|error| anyhow::anyhow!("mint rotation DID proof: {error}"))?;
    let device_id = arkret_sdk::DeviceId::new(grant.device_id.trim().to_owned())
        .map_err(|error| anyhow::anyhow!("invalid refresh device_id: {error}"))?;
    let engine = SessionEngine::with_state(
        http,
        session_grant_state_from_persisted(grant, device_handle, Utc::now())?,
    );
    let handle = engine
        .refresh_once(
            SessionRefreshOptions {
                audience: Some(grant.audience.clone()),
                device_id: Some(device_id),
                proof: Some(refresh_proof),
                expected_dpop_jkt: Some(device_handle.jkt().to_owned()),
            },
            Utc::now(),
        )
        .await
        .map_err(|error| anyhow::anyhow!("session grant refresh: {error}"))?;
    let state = engine
        .current_state()
        .context("session grant refresh did not yield state")?;
    // The rotated grant binds to the same device key (`cnf.jkt` constant), so
    // the introspection signing key persisted with the grant is this device key.
    let session_private_key_pem = device_handle
        .session_signing_key_pkcs8_pem()
        .map_err(|error| anyhow::anyhow!("export device session key: {error}"))?;
    Ok(PersistedSessionGrant {
        grant_jwt: handle.access_token,
        session_private_key_pem: session_private_key_pem.to_string(),
        grant_id: state.grant_id.as_str().to_owned(),
        audience: state.audience,
        principal_id: grant.principal_id.clone(),
        device_id: grant.device_id.clone(),
        principal_server_url: grant.principal_server_url.clone(),
        grant_expires_at: Some(state.expires_at),
        stored_at: Utc::now(),
    })
}

fn session_grant_state_from_persisted(
    grant: &PersistedSessionGrant,
    device_handle: &DpopHandle,
    now: chrono::DateTime<Utc>,
) -> anyhow::Result<SessionGrantState> {
    let expires_at = grant
        .grant_expires_at
        .filter(|expires_at| *expires_at > now)
        .unwrap_or_else(|| now + chrono::Duration::seconds(REFRESH_SKEW_SECS));
    Ok(SessionGrantState {
        principal_id: arkret_sdk::Did::new(grant.principal_id.trim().to_owned())
            .map_err(|error| anyhow::anyhow!("invalid refresh principal_id: {error}"))?,
        device_id: Some(
            arkret_sdk::DeviceId::new(grant.device_id.trim().to_owned())
                .map_err(|error| anyhow::anyhow!("invalid refresh device_id: {error}"))?,
        ),
        grant_id: arkret_sdk::GrantId::new(grant.grant_id.trim().to_owned())
            .map_err(|error| anyhow::anyhow!("invalid refresh grant_id: {error}"))?,
        grant_jwt: grant.grant_jwt.clone(),
        expires_at,
        audience: grant.audience.clone(),
        granted_scope: Vec::new(),
        // Reconstructed-from-persistence state: the client persistence layer does
        // not retain the session public key, and garth's refresh flow never reads
        // it (only the wire refresh outcome supplies the rotated key). Pass `None`
        // rather than a placeholder string.
        session_public_key: None,
        dpop_jkt: Some(device_handle.jkt().to_owned()),
    })
}

pub(crate) fn sdk_base_url_from_gate_account_base(gate_account_base: &str) -> anyhow::Result<Url> {
    let mut url = Url::parse(gate_account_base.trim())
        .with_context(|| format!("invalid Account Authority URL: {gate_account_base}"))?;
    url.set_query(None);
    url.set_fragment(None);

    let path = url.path().trim_end_matches('/');
    if let Some(prefix) = path.strip_suffix("/_arkret/gate/account") {
        let root_path = if prefix.is_empty() {
            "/".to_owned()
        } else {
            format!("{}/", prefix.trim_end_matches('/'))
        };
        url.set_path(&root_path);
    } else if !url.path().ends_with('/') {
        let with_slash = format!("{}/", url.path());
        url.set_path(&with_slash);
    }
    Ok(url)
}

#[derive(Debug, Serialize)]
struct SoftLogoutDidProofClaims<'a> {
    pub principal_id: &'a str,
    pub device_id: &'a str,
    pub audience: &'a str,
    pub challenge: &'a str,
    pub request_canonical_digest: &'a str,
    pub issued_at: chrono::DateTime<Utc>,
    pub expires_at: chrono::DateTime<Utc>,
}

#[derive(Debug, Serialize)]
struct SoftLogoutRestoreRequestDigest<'a> {
    pub operation: &'static str,
    pub grant_jwt_hash: String,
    pub principal_id: &'a str,
    pub device_id: &'a str,
    pub audience: &'a str,
    pub grant_binding_key_id: &'a str,
}

fn mint_session_grant_refresh_proof(
    grant: &PersistedSessionGrant,
) -> anyhow::Result<arkret_sdk::SessionGrantRefreshProof> {
    let principal_id = required_trimmed(&grant.principal_id, "principal_id")?;
    let device_id = required_trimmed(&grant.device_id, "device_id")?;
    let audience = required_trimmed(&grant.audience, "audience")?;
    let verification_method = format!("{principal_id}#{device_id}");
    let request_canonical_digest = soft_logout_restore_request_canonical_digest(
        &grant.grant_jwt,
        principal_id,
        device_id,
        audience,
        &verification_method,
    )?;
    let request_canonical_digest_hash = arkret_sdk::Hash::new(request_canonical_digest.clone())
        .map_err(|error| anyhow::anyhow!("soft logout restore request digest: {error}"))?;
    let challenge = soft_logout_refresh_challenge()?;
    let issued_at = Utc::now();
    let expires_at = issued_at + chrono::Duration::seconds(60);
    let claims = SoftLogoutDidProofClaims {
        principal_id,
        device_id,
        audience,
        challenge: &challenge,
        request_canonical_digest: &request_canonical_digest,
        issued_at,
        expires_at,
    };
    let payload = crate::canonical::canonical_json_bytes(&claims)
        .map_err(|error| anyhow::anyhow!("soft logout restore proof payload: {error}"))?;
    let signer = crate::event_signer::active_signer()
        .ok_or_else(|| anyhow::anyhow!("active device identity signer is not installed"))?;
    let signature = signer
        .detached_jws_over_payload_with_kid(&verification_method, &payload)
        .map_err(|error| anyhow::anyhow!("sign soft logout restore proof: {error}"))?;
    Ok(arkret_sdk::SessionGrantRefreshProof {
        proof_kind: Some(arkret_sdk::SessionGrantProofKind::DidBoundSignature),
        challenge: Some(challenge),
        request_canonical_digest: Some(request_canonical_digest_hash),
        audience: Some(audience.to_owned()),
        issued_at: Some(issued_at),
        expires_at: Some(expires_at),
        signature: Some(signature),
        verification_method: Some(verification_method),
    })
}

fn required_trimmed<'a>(value: &'a str, field: &str) -> anyhow::Result<&'a str> {
    let value = value.trim();
    if value.is_empty() {
        anyhow::bail!("{field} is required");
    }
    Ok(value)
}

fn soft_logout_restore_request_canonical_digest(
    grant_jwt: &str,
    principal_id: &str,
    device_id: &str,
    audience: &str,
    grant_binding_key_id: &str,
) -> anyhow::Result<String> {
    crate::canonical::canonical_sha256(&SoftLogoutRestoreRequestDigest {
        operation: SOFT_LOGOUT_RESTORE_OPERATION,
        grant_jwt_hash: crate::account_auth::session_grant_jwt_hash(grant_jwt),
        principal_id,
        device_id,
        audience,
        grant_binding_key_id,
    })
    .map_err(|error| anyhow::anyhow!("soft logout restore request canonicalization: {error}"))
}

/// Build the soft-logout refresh challenge from a pure 128-bit random nonce +
/// millisecond timestamp. The DPoP jkt is intentionally not mixed in: the
/// grant-binding key id is carried by the signed proof payload and request
/// digest.
fn soft_logout_refresh_challenge() -> anyhow::Result<String> {
    let mut nonce = [0u8; 16];
    getrandom::fill(&mut nonce).map_err(|err| anyhow::anyhow!("refresh challenge RNG: {err}"))?;
    Ok(format!(
        "sg-refresh-{}-{}",
        Utc::now().timestamp_millis(),
        URL_SAFE_NO_PAD.encode(nonce)
    ))
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
            if crate::api_error::is_terminal_session_grant_refresh_error(&error) {
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
    fn prepare_refresh_does_not_generate_new_dpop_key_for_existing_grant() {
        let mut store = isolated_store("missing-grant-dpop-key");
        store.set_session_grant(Some(grant_with_expiry(600)));

        let outcome =
            prepare_refresh_for_server_after_unauthorized(&mut store, "https://principal.example");

        assert!(matches!(
            outcome,
            RefreshPrepared::Done(RefreshOutcome::Transient { .. })
        ));
        assert!(store.dpop_device_key().is_none());
        assert!(store.session_grant().is_some());
    }

    #[test]
    fn commit_clears_grant_and_requires_login_when_principal_reports_revoked_session_grant() {
        let mut store = isolated_store("revoked-grant");
        store.set_session_grant(Some(grant_with_expiry(86400)));
        let error: anyhow::Error = crate::api_error::CokretApiError {
            status: reqwest::StatusCode::FORBIDDEN,
            error: crate::api_error::decode_arkret_error(
                reqwest::StatusCode::FORBIDDEN,
                br#"{"ok":false,"error":{"code":"capability_denied","message":"session grant is not active: revoked"},"request_id":"ak:request:01964137-0000-7000-8000-000000000012"}"#,
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
        let error: anyhow::Error = crate::api_error::CokretApiError {
            status: reqwest::StatusCode::BAD_REQUEST,
            error: crate::api_error::decode_arkret_error(
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
    fn commit_clears_grant_when_refresh_rejects_grant_binding_proof() {
        let mut store = isolated_store("invalid-proof-grant");
        store.set_session_grant(Some(grant_with_expiry(86400)));
        let error: anyhow::Error = crate::api_error::CokretApiError {
            status: reqwest::StatusCode::UNAUTHORIZED,
            error: crate::api_error::decode_arkret_error(
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
        let error: anyhow::Error = crate::api_error::CokretApiError {
            status: reqwest::StatusCode::FORBIDDEN,
            error: crate::api_error::decode_arkret_error(
                reqwest::StatusCode::FORBIDDEN,
                br#"{"ok":false,"error":{"code":"capability_denied","message":"actor is not a member of the event Space"},"request_id":"ak:request:01964137-0000-7000-8000-000000000012"}"#,
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
        let error: anyhow::Error = crate::api_error::CokretApiError {
            status: reqwest::StatusCode::UNAUTHORIZED,
            error: crate::api_error::decode_arkret_error(
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

    // The pure decision predicates (due-for-rotation skew, poll constants) are
    // garth's and covered by garth's own tests; the tests above exercise
    // inkson's store-backed mapping on top of them.
}
