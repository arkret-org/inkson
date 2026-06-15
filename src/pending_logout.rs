//! F7 — durable hard-logout retry.
//!
//! A hard logout ("Log out" button) must do more than wipe local
//! credentials: per `account-lifecycle §4.1` it has to terminate the
//! server-side authentication context so the rotation chain can never be
//! resumed —
//!
//! 1. **coauth**: revoke the session grant + finish its browser session
//!    (presenting the device holder proof bound into the grant's
//!    `cnf.jkt`). This is the *durable, security-critical* step: while the
//!    grant lives, a holder of the device key could mint fresh access
//!    bearers for up to the grant's 8h TTL.
//! 2. **soland**: revoke the short principal bearer / device session. The
//!    bearer self-expires within ≤15min, so this is a courtesy
//!    fast-path, not a durability requirement.
//!
//! The old implementation fired both calls from a detached `spawn` after
//! the local wipe. If the tab closed mid-flight, or coauth was briefly
//! unreachable, the grant could outlive the "logout" — a real hole: the
//! UI says signed-out while the rotation chain is still alive server-side.
//!
//! This module closes that hole by journalling the logout intent to
//! `localStorage` **before** the local wipe, retrying it in the
//! background, and on the next app boot. The record is cleared only once
//! the coauth revoke has definitively succeeded (or the grant is already
//! gone). A wall-clock TTL bounds the record so a permanently-unreachable
//! coauth can't leave a poison entry forever — and crucially the grant's
//! own 8h TTL means the chain self-heals well before the 24h record TTL.

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

/// localStorage key for the journalled logout intent. Referenced only by
/// the wasm persistence helpers; the host build's stubs don't touch it.
#[cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]
const PENDING_LOGOUT_STORAGE_KEY: &str = "cokret.pending_logout.v1";

/// How long a pending-logout record stays actionable. Past this we drop it
/// without further retries: the session grant's own TTL (8h, see
/// `coauth` `SESSION_GRANT_TTL_MICROS`) is far shorter, so by 24h the
/// rotation chain is already dead from natural expiry and there is nothing
/// left to revoke.
const RECORD_TTL_HOURS: i64 = 24;

/// The journalled intent to terminate a server-side session, persisted so
/// it survives a tab close or a transient coauth outage.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingLogout {
    /// The grant JWT to revoke at coauth. `None` when the logging-out
    /// session had no persisted grant (legacy / dev sessions); then only
    /// the soland courtesy logout runs.
    #[serde(default)]
    pub grant_jwt: Option<String>,
    /// Base64url seed of the device DPoP key whose thumbprint is bound
    /// into the grant's `cnf.jkt`. Stashed because the hard logout wipes
    /// the live device key (to rotate `cnf.jkt` on next sign-in); this
    /// copy exists solely to mint the holder proof for the revoke.
    #[serde(default)]
    pub device_seed_b64: Option<String>,
    /// Thumbprint that must re-derive from `device_seed_b64`.
    #[serde(default)]
    pub device_jkt: Option<String>,
    /// Principal-server URL the grant was issued against; used to resolve
    /// the grant's Auth Server for the revoke call.
    #[serde(default)]
    pub principal_server_url: Option<String>,
    /// Principal-server base URL for the soland courtesy logout.
    pub base_url: String,
    /// Short principal bearer for the soland courtesy logout. May already
    /// be expired by retry time — that's fine, soland treats an expired
    /// bearer as already-terminated.
    #[serde(default)]
    pub bearer: String,
    /// Account DID, for diagnostics only.
    #[serde(default)]
    pub account_did: String,
    /// When the record was journalled. Drives the [`RECORD_TTL_HOURS`] bound.
    pub created_at: DateTime<Utc>,
}

impl PendingLogout {
    /// True once the record is past its actionable window — the grant has
    /// long since expired by natural TTL and there is nothing left to
    /// revoke, so a stale entry should be dropped rather than retried.
    pub fn is_expired(&self, now: DateTime<Utc>) -> bool {
        now - self.created_at >= Duration::hours(RECORD_TTL_HOURS)
    }

    /// True when there is a coauth grant revoke to perform. A record with
    /// no grant (or missing holder material) only carries the soland
    /// courtesy logout.
    pub fn has_coauth_revoke(&self) -> bool {
        self.grant_jwt.is_some()
            && self.device_seed_b64.is_some()
            && self.device_jkt.is_some()
            && self.principal_server_url.is_some()
    }
}

/// Classify a coauth revoke error as *terminal-benign*: the grant is
/// already gone, so the security goal (no resumable rotation chain) is
/// met and the record can be cleared rather than retried forever.
///
/// coauth's revoke is documented as idempotent; a second call against an
/// already-revoked/expired grant surfaces one of these markers.
fn coauth_revoke_already_terminated(error: &anyhow::Error) -> bool {
    let message = error.to_string().to_ascii_lowercase();
    message.contains("already")
        || message.contains("revoked")
        || message.contains("invalid_grant")
        || message.contains("not active")
        || message.contains("expired")
        || message.contains("not found")
        || message.contains("returned 404")
        || message.contains("returned 400")
}

/// Outcome of running a pending-logout record once.
#[derive(Debug, PartialEq, Eq)]
pub enum LogoutRunOutcome {
    /// The server-side context is terminated (or was already gone). The
    /// record has been cleared; nothing further to do.
    Completed,
    /// coauth could not be reached / failed transiently. The record is
    /// retained for the next retry or boot.
    Retain,
}

/// Run one pending-logout record to completion:
///
/// 1. Revoke the grant at coauth (the durable, critical step). Success —
///    or a "grant already gone" error — clears the record.
/// 2. Best-effort soland courtesy logout (never blocks clearing).
///
/// Returns whether the record was cleared. A still-live coauth failure
/// keeps the record so a later boot retries it; the [`RECORD_TTL_HOURS`]
/// bound (checked by [`run_pending_logout_if_any`]) prevents an immortal
/// poison entry.
pub async fn execute_pending_logout(record: &PendingLogout) -> LogoutRunOutcome {
    let coauth_done = if record.has_coauth_revoke() {
        match revoke_grant_at_coauth(record).await {
            Ok(()) => true,
            Err(error) if coauth_revoke_already_terminated(&error) => {
                tracing::info!(?error, "pending logout: coauth grant already terminated");
                true
            }
            Err(error) => {
                tracing::warn!(?error, "pending logout: coauth revoke failed, will retry");
                false
            }
        }
    } else {
        // No grant to revoke — the soland courtesy logout is the whole job.
        true
    };

    if !coauth_done {
        return LogoutRunOutcome::Retain;
    }

    // Courtesy soland logout — revokes the short bearer / device session
    // immediately instead of waiting out its ≤15min TTL. Never gates
    // clearing: with the grant dead, no fresh bearer can be minted, so the
    // existing one expires harmlessly on its own.
    soland_courtesy_logout(record).await;

    let _ = clear_pending_logout();
    LogoutRunOutcome::Completed
}

/// coauth grant revoke with a holder proof minted from the stashed device
/// seed. Mirrors `app::revoke_session_grant_at_coauth`, but rebuilds the
/// handle from the journalled seed (the live key is already wiped) and —
/// critically — mints the DPoP proof against the **actual** revoke URL.
async fn revoke_grant_at_coauth(record: &PendingLogout) -> anyhow::Result<()> {
    let grant_jwt = record
        .grant_jwt
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("pending logout missing grant_jwt"))?;
    let seed = record
        .device_seed_b64
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("pending logout missing device seed"))?;
    let jkt = record
        .device_jkt
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("pending logout missing device jkt"))?;
    let principal_server_url = record
        .principal_server_url
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("pending logout missing principal_server_url"))?;

    let handle = crate::auth_dpop::device_handle_from_seed(seed, jkt)
        .map_err(|error| anyhow::anyhow!("rebuild device handle: {error}"))?;
    let auth_server_url = crate::coauth::resolve_principal_auth_server_url(principal_server_url)
        .await
        .map_err(|error| anyhow::anyhow!("resolve auth server: {error}"))?;
    let coauth = crate::coauth::CoauthApi::new(&auth_server_url)?;
    // The DPoP `htu` MUST equal the URL the request is actually sent to,
    // which `CoauthApi::revoke_session_grant` posts to
    // `_cokret/gate/account/session-grants/logout`.
    let htu = coauth.endpoint_url("_cokret/gate/account/session-grants/logout")?;
    let dpop_proof = handle
        .mint_proof("POST", &htu, Some(grant_jwt))
        .map_err(|error| anyhow::anyhow!("mint logout DPoP proof: {error}"))?;
    coauth.revoke_session_grant(grant_jwt, &dpop_proof).await
}

/// Best-effort soland logout. Swallows all errors: an expired bearer (the
/// common case by retry time) or a transient failure is harmless because
/// the grant is already dead.
async fn soland_courtesy_logout(record: &PendingLogout) {
    if record.base_url.trim().is_empty() {
        return;
    }
    let api = match crate::api::CokretApi::new(&record.base_url) {
        Ok(api) => api.with_bearer(record.bearer.clone()),
        Err(error) => {
            tracing::warn!(?error, "pending logout: invalid soland base url");
            return;
        }
    };
    if let Err(error) = api.logout().await {
        tracing::info!(?error, "pending logout: soland courtesy logout failed (ignored)");
    }
}

/// Journal a logout intent to `localStorage`. Call this **before** wiping
/// local credentials so the retry can still mint a holder proof.
#[cfg(target_arch = "wasm32")]
pub fn persist_pending_logout(record: &PendingLogout) -> anyhow::Result<()> {
    let storage = local_storage()?;
    storage
        .set_item(
            PENDING_LOGOUT_STORAGE_KEY,
            &serde_json::to_string(record)?,
        )
        .map_err(|error| anyhow::anyhow!("failed to persist pending logout: {error:?}"))?;
    Ok(())
}

#[cfg(not(target_arch = "wasm32"))]
pub fn persist_pending_logout(_record: &PendingLogout) -> anyhow::Result<()> {
    Ok(())
}

/// Read the journalled logout intent, if any.
#[cfg(target_arch = "wasm32")]
pub fn restore_pending_logout() -> anyhow::Result<Option<PendingLogout>> {
    let storage = local_storage()?;
    let Some(payload) = storage
        .get_item(PENDING_LOGOUT_STORAGE_KEY)
        .map_err(|error| anyhow::anyhow!("failed to load pending logout: {error:?}"))?
    else {
        return Ok(None);
    };
    Ok(Some(serde_json::from_str(&payload)?))
}

#[cfg(not(target_arch = "wasm32"))]
pub fn restore_pending_logout() -> anyhow::Result<Option<PendingLogout>> {
    Ok(None)
}

/// Drop the journalled logout intent.
#[cfg(target_arch = "wasm32")]
pub fn clear_pending_logout() -> anyhow::Result<()> {
    let storage = local_storage()?;
    storage
        .remove_item(PENDING_LOGOUT_STORAGE_KEY)
        .map_err(|error| anyhow::anyhow!("failed to clear pending logout: {error:?}"))?;
    Ok(())
}

#[cfg(not(target_arch = "wasm32"))]
pub fn clear_pending_logout() -> anyhow::Result<()> {
    Ok(())
}

#[cfg(target_arch = "wasm32")]
fn local_storage() -> anyhow::Result<web_sys::Storage> {
    web_sys::window()
        .ok_or_else(|| anyhow::anyhow!("browser window is not available"))?
        .local_storage()
        .map_err(|error| anyhow::anyhow!("failed to access localStorage: {error:?}"))?
        .ok_or_else(|| anyhow::anyhow!("localStorage is not available"))
}

/// Boot / background entry point: if a logout intent is journalled, run it.
///
/// Expired records are dropped without a network call (the grant is dead
/// by its own TTL). Live records are executed; the record is cleared on
/// success and retained on transient failure for the next attempt.
pub async fn run_pending_logout_if_any(now: DateTime<Utc>) {
    let record = match restore_pending_logout() {
        Ok(Some(record)) => record,
        Ok(None) => return,
        Err(error) => {
            tracing::warn!(?error, "pending logout: failed to read journal");
            return;
        }
    };
    if record.is_expired(now) {
        tracing::info!("pending logout: record past TTL, dropping (grant self-expired)");
        let _ = clear_pending_logout();
        return;
    }
    let _ = execute_pending_logout(&record).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_record(created_at: DateTime<Utc>) -> PendingLogout {
        PendingLogout {
            grant_jwt: Some("eyJ.grant.jwt".to_owned()),
            device_seed_b64: Some("seed".to_owned()),
            device_jkt: Some("jkt".to_owned()),
            principal_server_url: Some("https://soland.example".to_owned()),
            base_url: "https://soland.example".to_owned(),
            bearer: "bearer".to_owned(),
            account_did: "did:web:soland.example:users:01".to_owned(),
            created_at,
        }
    }

    #[test]
    fn record_round_trips_through_json() {
        let record = base_record(Utc::now());
        let json = serde_json::to_string(&record).unwrap();
        let parsed: PendingLogout = serde_json::from_str(&json).unwrap();
        assert_eq!(record, parsed);
    }

    #[test]
    fn record_expires_after_ttl() {
        let now = Utc::now();
        let fresh = base_record(now);
        assert!(!fresh.is_expired(now));
        assert!(!fresh.is_expired(now + Duration::hours(RECORD_TTL_HOURS - 1)));
        assert!(fresh.is_expired(now + Duration::hours(RECORD_TTL_HOURS)));
        assert!(fresh.is_expired(now + Duration::hours(RECORD_TTL_HOURS + 1)));
    }

    #[test]
    fn has_coauth_revoke_requires_all_holder_material() {
        let now = Utc::now();
        assert!(base_record(now).has_coauth_revoke());

        let mut no_grant = base_record(now);
        no_grant.grant_jwt = None;
        assert!(!no_grant.has_coauth_revoke());

        let mut no_seed = base_record(now);
        no_seed.device_seed_b64 = None;
        assert!(!no_seed.has_coauth_revoke());

        let mut no_jkt = base_record(now);
        no_jkt.device_jkt = None;
        assert!(!no_jkt.has_coauth_revoke());

        let mut no_principal = base_record(now);
        no_principal.principal_server_url = None;
        assert!(!no_principal.has_coauth_revoke());
    }

    #[test]
    fn already_terminated_errors_are_classified_benign() {
        for marker in [
            "grant already consumed",
            "session grant is not active: revoked",
            "invalid_grant",
            "refresh endpoint returned 400: expired",
            "endpoint returned 404",
            "grant not found",
        ] {
            assert!(
                coauth_revoke_already_terminated(&anyhow::anyhow!("{marker}")),
                "expected '{marker}' to be terminal-benign"
            );
        }
    }

    #[test]
    fn transient_errors_are_not_benign() {
        for marker in [
            "connection refused",
            "dns failure",
            "timed out",
            "503 service unavailable",
        ] {
            assert!(
                !coauth_revoke_already_terminated(&anyhow::anyhow!("{marker}")),
                "expected '{marker}' to be retryable"
            );
        }
    }

    #[tokio::test]
    async fn execute_returns_completed_when_no_coauth_revoke_needed() {
        // A record with no grant material and an empty base URL has nothing
        // to do over the network — it should clear immediately.
        let mut record = base_record(Utc::now());
        record.grant_jwt = None;
        record.base_url = String::new();
        let outcome = execute_pending_logout(&record).await;
        assert_eq!(outcome, LogoutRunOutcome::Completed);
    }
}
