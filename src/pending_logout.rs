//! F7 — durable hard-logout retry.
//!
//! A hard logout ("Log out" button) must do more than wipe local
//! credentials: per `account-lifecycle §4.1` it has to terminate the
//! server-side authentication context so the rotation chain can never be
//! resumed.
//!
//! T1.Y3 — this is now a SINGLE client-visible call to the Account Authority
//! `POST {gate_account_base}/logout` (service-surface §2.5.1) carrying
//! `Authorization: Bearer <ck.session.grant>` + a grant-binding `DPoP` proof bound to
//! that grant. The Account Authority internally terminates BOTH the Auth-side
//! grant rotation chain + `browser_session` AND the Principal-side
//! account/device session + to-device drop. The client MUST NOT fan out to two
//! origins or call Auth-side sub-operations directly.
//!
//! The old implementation fired two calls from a detached `spawn` after
//! the local wipe. If the tab closed mid-flight, or the server was briefly
//! unreachable, the grant could outlive the "logout" — a real hole: the
//! UI says signed-out while the rotation chain is still alive server-side.
//!
//! This module closes that hole by journalling the logout intent to the
//! [`SecureKeyStore`](crate::secure_key_store) **before** the local wipe,
//! retrying it in the background, and on the next app boot. The record
//! embeds the grant-binding seed, so it is classified seed-grade
//! (`PENDING_LOGOUT_SECRET_KEY`): IndexedDB-only on wasm with no localStorage
//! unload-race mirror, OS keyring on native. The record is cleared only once
//! the coauth revoke has definitively succeeded (or the grant is already
//! gone). A wall-clock TTL bounds the record so a permanently-unreachable
//! coauth can't leave a poison entry forever — and crucially the grant's
//! own 8h TTL means the chain self-heals well before the 24h record TTL.

use chrono::{DateTime, Duration, Utc};
use arkret_sdk::http_client::{Auth, ClientBuilder};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize as _;

/// Secure-key-store key for the journalled logout intent. Defined in
/// `secure_key_store` so its seed-grade (IndexedDB-only, no localStorage
/// mirror) classification stays in lockstep with the key string.
use crate::secure_key_store::PENDING_LOGOUT_SECRET_KEY as PENDING_LOGOUT_STORAGE_KEY;

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
    /// copy exists solely to mint the grant-binding DPoP proof for the revoke.
    #[serde(default)]
    pub device_seed_b64: Option<String>,
    /// Thumbprint that must re-derive from `device_seed_b64`.
    #[serde(default)]
    pub device_jkt: Option<String>,
    /// Principal-server URL the grant was issued against; used to re-resolve
    /// the Account Authority `gate_account_base` if it was not journalled.
    #[serde(default)]
    pub principal_server_url: Option<String>,
    /// T1.Y4 — resolved Account Authority `gate_account_base`; the single
    /// `/logout` origin. Preferred over re-resolving from
    /// `principal_server_url` at retry time.
    #[serde(default)]
    pub gate_account_base: Option<String>,
    /// Principal-server base URL for diagnostics.
    pub base_url: String,
    /// Last in-memory session credential captured for diagnostics. The single
    /// hard logout authenticates with the grant + DPoP, not this value.
    #[serde(default)]
    pub session_credential: String,
    /// Account DID, for diagnostics only.
    #[serde(default)]
    pub account_did: String,
    /// When the record was journalled. Drives the [`RECORD_TTL_HOURS`] bound.
    pub created_at: DateTime<Utc>,
}

impl Drop for PendingLogout {
    /// Defence-in-depth: wipe the stashed device seed (the grant-binding secret bound
    /// into the grant's `cnf.jkt`) when the journal record drops, so the
    /// plaintext key material does not linger in freed heap. `zeroize`'s
    /// `serde` feature is not enabled in this workspace, so the field stays a
    /// plain `String` for (de)serialisation and is wiped here instead of via a
    /// `Zeroizing<String>` field type.
    fn drop(&mut self) {
        if let Some(seed) = self.device_seed_b64.as_mut() {
            seed.zeroize();
        }
    }
}

impl PendingLogout {
    /// True once the record is past its actionable window — the grant has
    /// long since expired by natural TTL and there is nothing left to
    /// revoke, so a stale entry should be dropped rather than retried.
    pub fn is_expired(&self, now: DateTime<Utc>) -> bool {
        now - self.created_at >= Duration::hours(RECORD_TTL_HOURS)
    }

    /// True when there is a server-side grant chain to terminate. Requires the
    /// grant JWT + grant-binding material + a routable Account Authority base (either
    /// the journalled `gate_account_base` or a `principal_server_url` to
    /// re-resolve it from).
    pub fn has_coauth_revoke(&self) -> bool {
        let has_route = self
            .gate_account_base
            .as_deref()
            .is_some_and(|base| !base.trim().is_empty())
            || self.principal_server_url.is_some();
        self.grant_jwt.is_some()
            && self.device_seed_b64.is_some()
            && self.device_jkt.is_some()
            && has_route
    }
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AccountLogoutRunOutcome {
    Terminated,
}

/// Run one pending-logout record to completion via the SINGLE Account
/// Authority hard logout (T1.Y3). Success — or a "grant already gone" error —
/// clears the record. A still-live failure keeps the record so a later boot
/// retries it; the [`RECORD_TTL_HOURS`] bound (checked by
/// [`run_pending_logout_if_any`]) prevents an immortal poison entry.
pub async fn execute_pending_logout(
    record: &PendingLogout,
    store: &dyn crate::secure_key_store::SecureKeyStore,
) -> LogoutRunOutcome {
    if !record.has_coauth_revoke() {
        // No grant / grant-binding material to terminate server-side — nothing to do.
        let _ = clear_pending_logout(store);
        return LogoutRunOutcome::Completed;
    }
    match hard_logout_at_authority(record).await {
        // The SDK logout wrapper below classifies the HTTP result: a terminal
        // outcome (revoked / already-gone) → `Ok`, any real failure → `Err`.
        Ok(AccountLogoutRunOutcome::Terminated) => {
            let _ = clear_pending_logout(store);
            LogoutRunOutcome::Completed
        }
        Err(error) => {
            tracing::warn!(
                ?error,
                "pending logout: authority logout failed, will retry"
            );
            LogoutRunOutcome::Retain
        }
    }
}

/// T1.Y3 — single hard logout to `{gate_account_base}/logout` with the grant
/// plus a grant-binding DPoP proof minted from the stashed device seed (the live
/// key is already wiped). The DPoP `htu` MUST equal the `/logout` URL and `ath`
/// MUST bind the grant.
async fn hard_logout_at_authority(
    record: &PendingLogout,
) -> anyhow::Result<AccountLogoutRunOutcome> {
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

    let handle = crate::account_auth::grant_dpop::device_handle_from_seed(seed, jkt)
        .map_err(|error| anyhow::anyhow!("rebuild device handle: {error}"))?;
    // Prefer the journalled gate_account_base; re-resolve from the principal
    // server only if it was not captured.
    let gate_account_base = match record.gate_account_base.as_deref() {
        Some(base) if !base.trim().is_empty() => base.to_owned(),
        _ => {
            let principal_server_url = record.principal_server_url.as_deref().ok_or_else(|| {
                anyhow::anyhow!("pending logout missing gate_account_base and principal_server_url")
            })?;
            crate::account_auth::resolve_principal_gate_account_base(principal_server_url)
                .await
                .map_err(|error| anyhow::anyhow!("resolve account authority: {error}"))?
        }
    };
    let sdk_base_url =
        crate::session_refresh::sdk_base_url_from_gate_account_base(&gate_account_base)?;
    let client = ClientBuilder::new(sdk_base_url)
        .allow_insecure_localhost()
        .auth(Auth::Dpop(
            handle.sdk_dpop_auth_for_access_token(grant_jwt.to_owned()),
        ))
        .build()
        .map_err(|error| anyhow::anyhow!("build account logout HTTP client: {error}"))?;
    match client.auth_account_logout().await {
        Ok(_) => Ok(AccountLogoutRunOutcome::Terminated),
        Err(error) if account_logout_error_is_terminal(&error) => {
            Ok(AccountLogoutRunOutcome::Terminated)
        }
        Err(error) => Err(anyhow::anyhow!("account authority logout failed: {error}")),
    }
}

fn account_logout_error_is_terminal(error: &arkret_sdk::Error) -> bool {
    match error {
        arkret_sdk::Error::Api { status: 404, .. } => true,
        arkret_sdk::Error::Api { error, .. } => matches!(
            error.code(),
            "grant_already_consumed"
                | "session_logged_out"
                | "session_grant_not_found"
                | "authorized_grant_revoked"
        ),
        _ => false,
    }
}

/// Journal a logout intent to the secure key store. Call this **before**
/// wiping local credentials so the retry can still mint a grant-binding DPoP proof.
///
/// The journal holds the grant-binding seed, so it goes through the
/// [`SecureKeyStore`](crate::secure_key_store::SecureKeyStore) (OS keyring on
/// native) rather than a plaintext file. Its key is classified seed-grade, so
/// on wasm it is IndexedDB-only with NO localStorage unload-race mirror — the
/// grant-binding seed never touches the weak localStorage tier.
pub fn persist_pending_logout(
    record: &PendingLogout,
    store: &dyn crate::secure_key_store::SecureKeyStore,
) -> anyhow::Result<()> {
    let json = serde_json::to_string(record)?;
    store
        .store_secret(PENDING_LOGOUT_STORAGE_KEY, &json)
        .map_err(|error| anyhow::anyhow!("failed to persist pending logout: {error}"))?;
    Ok(())
}

/// Read the journalled logout intent, if any.
pub fn restore_pending_logout(
    store: &dyn crate::secure_key_store::SecureKeyStore,
) -> anyhow::Result<Option<PendingLogout>> {
    let Some(json) = store
        .get_secret(PENDING_LOGOUT_STORAGE_KEY)
        .map_err(|error| anyhow::anyhow!("failed to load pending logout: {error}"))?
    else {
        return Ok(None);
    };
    Ok(Some(serde_json::from_str(&json)?))
}

/// Drop the journalled logout intent.
pub fn clear_pending_logout(
    store: &dyn crate::secure_key_store::SecureKeyStore,
) -> anyhow::Result<()> {
    store
        .delete_secret(PENDING_LOGOUT_STORAGE_KEY)
        .map_err(|error| anyhow::anyhow!("failed to clear pending logout: {error}"))?;
    Ok(())
}

/// Boot / background entry point: if a logout intent is journalled, run it.
///
/// Expired records are dropped without a network call (the grant is dead
/// by its own TTL). Live records are executed; the record is cleared on
/// success and retained on transient failure for the next attempt.
pub async fn run_pending_logout_if_any(now: DateTime<Utc>) {
    let store = crate::secure_key_store::default_secure_key_store("inkson");
    run_pending_logout_with_store(now, store.as_ref()).await;
}

/// Store-injectable core of [`run_pending_logout_if_any`].
pub async fn run_pending_logout_with_store(
    now: DateTime<Utc>,
    store: &dyn crate::secure_key_store::SecureKeyStore,
) {
    let record = match restore_pending_logout(store) {
        Ok(Some(record)) => record,
        Ok(None) => return,
        Err(error) => {
            tracing::warn!(?error, "pending logout: failed to read journal");
            return;
        }
    };
    if record.is_expired(now) {
        tracing::info!("pending logout: record past TTL, dropping (grant self-expired)");
        let _ = clear_pending_logout(store);
        return;
    }
    let _ = execute_pending_logout(&record, store).await;
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
            gate_account_base: Some("https://soland.example/_arkret/gate/account".to_owned()),
            base_url: "https://soland.example".to_owned(),
            session_credential: "session-credential".to_owned(),
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
    fn record_round_trips_through_secure_store() {
        use crate::secure_key_store::MemorySecureKeyStore;
        let store = MemorySecureKeyStore::default();
        let record = base_record(Utc::now());
        assert!(restore_pending_logout(&store).unwrap().is_none());
        persist_pending_logout(&record, &store).unwrap();
        assert_eq!(restore_pending_logout(&store).unwrap(), Some(record));
        clear_pending_logout(&store).unwrap();
        assert!(restore_pending_logout(&store).unwrap().is_none());
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

        // No route at all (neither gate_account_base nor principal_server_url).
        let mut no_route = base_record(now);
        no_route.principal_server_url = None;
        no_route.gate_account_base = None;
        assert!(!no_route.has_coauth_revoke());

        // gate_account_base alone is a sufficient route.
        let mut base_only = base_record(now);
        base_only.principal_server_url = None;
        assert!(base_only.has_coauth_revoke());
    }

    #[tokio::test]
    async fn execute_returns_completed_when_no_coauth_revoke_needed() {
        use crate::secure_key_store::MemorySecureKeyStore;
        // A record with no grant material and an empty base URL has nothing
        // to do over the network — it should clear immediately, including
        // removing any journalled copy from the store.
        let store = MemorySecureKeyStore::default();
        let mut record = base_record(Utc::now());
        record.grant_jwt = None;
        record.base_url = String::new();
        persist_pending_logout(&record, &store).unwrap();
        let outcome = execute_pending_logout(&record, &store).await;
        assert_eq!(outcome, LogoutRunOutcome::Completed);
        assert!(restore_pending_logout(&store).unwrap().is_none());
    }

    #[test]
    fn account_logout_terminal_errors_complete_pending_logout() {
        for (status, code) in [
            (404, "not_found"),
            (400, "grant_already_consumed"),
            (401, "session_logged_out"),
            (404, "session_grant_not_found"),
            (403, "authorized_grant_revoked"),
        ] {
            let error = arkret_sdk::Error::Api {
                status,
                error: Box::new(arkret_sdk::ErrorEnvelope::new(code, "terminal")),
            };
            assert!(
                account_logout_error_is_terminal(&error),
                "{status} {code} should be terminal"
            );
        }
    }

    #[test]
    fn account_logout_non_terminal_errors_retain_pending_logout() {
        for (status, code) in [
            (500, "internal"),
            (401, "auth_expired"),
            (403, "capability_denied"),
        ] {
            let error = arkret_sdk::Error::Api {
                status,
                error: Box::new(arkret_sdk::ErrorEnvelope::new(code, "retryable")),
            };
            assert!(
                !account_logout_error_is_terminal(&error),
                "{status} {code} should be retryable"
            );
        }
        assert!(!account_logout_error_is_terminal(
            &arkret_sdk::Error::Protocol("network boundary".to_owned())
        ));
    }
}
