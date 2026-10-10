//! F7 — durable hard-logout retry.
//!
//! A hard logout ("Log out" button) must do more than wipe local
//! credentials: per `account-lifecycle §4.1` it has to terminate the
//! server-side authentication context so the rotation chain can never be
//! resumed.
//!
//! T1.Y3 — this is now a SINGLE client-visible call to the Account Authority
//! `POST {gate_account_base_url}/logout` (service-surface §2.5.1) carrying
//! `Authorization: DPoP <ak.session.grant>` + a grant-binding `DPoP` proof bound to
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
//! (`PENDING_LOGOUT_SECRET_KEY_PREFIX`): IndexedDB-only on wasm with no localStorage
//! unload-race mirror, OS keyring on native. The record is cleared only once
//! Account Authority logout termination is confirmed. Holder refusal or an old
//! captured grant stops automatic presentation without deleting the journal:
//! expiry/rotation of that one grant does not prove its browser chain is dead.

use arkret_sdk::http_client::{Auth, ClientBuilder};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize as _;

mod retry;

/// Secure-key-store key for the journalled logout intent. Defined in
/// `secure_key_store` so its seed-grade (IndexedDB-only, no localStorage
/// mirror) classification stays in lockstep with the key string.
use crate::secure_key_store::PENDING_LOGOUT_SECRET_KEY_PREFIX as PENDING_LOGOUT_STORAGE_PREFIX;

/// Maximum age for automatic presentation of the original captured holder.
/// Passing this boundary does not authorize deletion or prove chain termination.
const AUTOMATIC_RETRY_MAX_AGE_HOURS: i64 = 24;

/// The journalled intent to terminate a server-side session, persisted so
/// it survives a tab close or a transient coauth outage.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingLogout {
    /// Exact account authority whose logout record owns this secure-store slot.
    pub authority: arkret_sdk::AccountId,
    /// Exact account device whose grant-binding material is journalled.
    pub device_id: arkret_sdk::DeviceId,
    /// The grant JWT to revoke at coauth. `None` when the store held no
    /// session grant at the moment "Log out" was pressed. Missing captured
    /// holder material cannot authorize a network call or prove termination.
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
    /// Station URL the grant was issued against; used to re-resolve
    /// the Account Authority `gate_account_base_url` if it was not journalled.
    #[serde(default)]
    pub station_url: Option<url::Url>,
    /// T1.Y4 — resolved Account Authority `gate_account_base_url`; the single
    /// `/logout` origin. Preferred over re-resolving from
    /// `station_url` at retry time.
    #[serde(default)]
    pub gate_account_base_url: Option<url::Url>,
    /// Station base URL for diagnostics.
    pub base_url: url::Url,
    /// Last in-memory session credential captured for diagnostics. The single
    /// hard logout authenticates with the grant + DPoP, not this value.
    #[serde(default)]
    pub session_credential: String,
    /// Stable account identity, for diagnostics only.
    pub principal_id: arkret_sdk::DidCoreId,
    /// When the intent was journalled. Bounds automatic holder presentation.
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
    fn storage_key(&self) -> anyhow::Result<String> {
        Ok(format!(
            "{PENDING_LOGOUT_STORAGE_PREFIX}{}.{}",
            crate::secure_key_store::account_id_storage_digest(&self.authority)
                .map_err(|error| anyhow::anyhow!(error.to_string()))?,
            crate::secure_key_store::device_storage_digest(&self.device_id)
        ))
    }

    /// True when automatic presentation must stop. The original journal is
    /// retained because an old grant's age says nothing about its successor chain.
    pub fn automatic_retry_expired(&self, now: DateTime<Utc>) -> bool {
        now - self.created_at >= Duration::hours(AUTOMATIC_RETRY_MAX_AGE_HOURS)
    }

    /// True when there is a server-side grant chain to terminate. Requires the
    /// grant JWT + grant-binding material + a routable Account Authority base (either
    /// the journalled `gate_account_base_url` or a `station_url` to
    /// re-resolve it from).
    pub fn has_coauth_revoke(&self) -> bool {
        let has_route = self.gate_account_base_url.as_ref().is_some() || self.station_url.is_some();
        self.grant_jwt.is_some()
            && self.device_seed_b64.is_some()
            && self.device_jkt.is_some()
            && has_route
    }
}

/// Outcome of running a pending-logout record once.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogoutRunOutcome {
    /// The server-side context is terminated (or was already gone). The
    /// record has been cleared; nothing further to do.
    Completed,
    /// coauth could not be reached / failed transiently. The record is
    /// retained for the next retry or boot.
    Retain,
    /// The captured holder cannot authorize this request. Keep the journal,
    /// but do not repeatedly present the same rejected credential this runtime.
    Blocked,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AccountLogoutRunOutcome {
    Terminated,
}

/// Run one pending-logout record to completion via the SINGLE Account
/// Authority hard logout (T1.Y3). Confirmed termination clears the record.
/// Holder refusal keeps the record without repeated automatic presentation;
/// transient failure is subject to the SDK cadence and shared retry budget.
pub async fn execute_pending_logout(
    record: &PendingLogout,
    store: &dyn crate::secure_key_store::SecureKeyStore,
) -> LogoutRunOutcome {
    execute_pending_logout_with(record, store, Utc::now(), || {
        hard_logout_at_authority(record)
    })
    .await
}

async fn execute_pending_logout_with<
    F: std::future::Future<Output = anyhow::Result<AccountLogoutRunOutcome>>,
>(
    record: &PendingLogout,
    store: &dyn crate::secure_key_store::SecureKeyStore,
    now: DateTime<Utc>,
    perform: impl FnOnce() -> F,
) -> LogoutRunOutcome {
    if record.automatic_retry_expired(now) {
        return LogoutRunOutcome::Blocked;
    }
    let mut attempt = match retry::claim(record, now) {
        Ok(retry::Admission::Attempt(attempt)) => attempt,
        Ok(retry::Admission::Deferred) => return LogoutRunOutcome::Retain,
        Ok(retry::Admission::Blocked) => return LogoutRunOutcome::Blocked,
        Ok(retry::Admission::Terminated) => return clear_completed_logout(record, store).await,
        Err(error) => {
            tracing::warn!(?error, "pending logout: retry admission failed");
            return LogoutRunOutcome::Retain;
        }
    };
    if !record.has_coauth_revoke() {
        attempt.finish(LogoutRunOutcome::Blocked, now, None);
        tracing::warn!(
            "pending logout: captured holder material is incomplete; journal retained without automatic retry"
        );
        return LogoutRunOutcome::Blocked;
    }
    match perform().await {
        // Only a logout receipt or SessionLoggedOut proves termination.
        Ok(AccountLogoutRunOutcome::Terminated) => {
            attempt.finish(LogoutRunOutcome::Completed, now, None);
            clear_completed_logout(record, store).await
        }
        Err(error) => {
            let sdk_error = error.downcast_ref::<arkret_sdk::http_client::Error>();
            let invalid_holder = error
                .downcast_ref::<crate::identity::account_auth::grant_dpop::AuthDpopError>()
                .is_some_and(|error| {
                    matches!(
                        error,
                        crate::identity::account_auth::grant_dpop::AuthDpopError::PersistedSeed(_)
                    )
                });
            let outcome =
                if invalid_holder || sdk_error.is_some_and(account_logout_error_requires_repair) {
                    LogoutRunOutcome::Blocked
                } else {
                    LogoutRunOutcome::Retain
                };
            let retry_after = sdk_error.and_then(|error| match error {
                arkret_sdk::http_client::Error::Api { error, .. } => {
                    error.retry_after_ms().map(std::time::Duration::from_millis)
                }
                _ => None,
            });
            attempt.finish(outcome, now.max(Utc::now()), retry_after);
            tracing::warn!(
                code = ?sdk_error.and_then(arkret_sdk::http_client::Error::error_code),
                ?outcome,
                "pending logout: authority did not confirm termination; journal retained"
            );
            outcome
        }
    }
}

async fn clear_completed_logout(
    record: &PendingLogout,
    store: &dyn crate::secure_key_store::SecureKeyStore,
) -> LogoutRunOutcome {
    match pending_logout_slot_matches(record, store) {
        // Completion of an older captured intent must never clear a newer
        // logout journal written for the same account/device secure-store slot.
        Ok(false) => return LogoutRunOutcome::Completed,
        Ok(true) => {}
        Err(error) => {
            tracing::warn!(
                ?error,
                "pending logout: confirmed termination journal identity check failed"
            );
            return LogoutRunOutcome::Retain;
        }
    }
    let result = match record.storage_key() {
        Ok(key) => store
            .delete_secret_durable(&key)
            .await
            .map_err(anyhow::Error::from),
        Err(error) => Err(error),
    };
    match result {
        Ok(()) => LogoutRunOutcome::Completed,
        Err(error) => {
            tracing::warn!(
                ?error,
                "pending logout: confirmed termination journal cleanup failed"
            );
            LogoutRunOutcome::Retain
        }
    }
}

fn pending_logout_slot_matches(
    record: &PendingLogout,
    store: &dyn crate::secure_key_store::SecureKeyStore,
) -> anyhow::Result<bool> {
    let Some(mut encoded) = store.get_secret(&record.storage_key()?)? else {
        return Ok(false);
    };
    let decoded = serde_json::from_str::<PendingLogout>(&encoded);
    encoded.zeroize();
    Ok(decoded? == *record)
}

/// T1.Y3 — single hard logout to `{gate_account_base_url}/logout` with the grant
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

    let handle = crate::identity::account_auth::grant_dpop::device_handle_from_seed(seed, jkt)
        .map_err(|error| anyhow::Error::new(error).context("rebuild captured logout holder"))?;
    // Prefer the journalled gate_account_base_url; re-resolve from the principal
    // server only if it was not captured.
    let gate_account_base_url = match record.gate_account_base_url.as_ref() {
        Some(base) => base.clone(),
        _ => {
            let station_url = record.station_url.as_ref().ok_or_else(|| {
                anyhow::anyhow!("pending logout missing gate_account_base_url and station_url")
            })?;
            let resolved = crate::identity::account_auth::resolve_principal_gate_account_base_url(
                station_url.as_str(),
            )
            .await
            .map_err(|error| anyhow::anyhow!("resolve account authority: {error}"))?;
            url::Url::parse(&resolved)?
        }
    };
    let sdk_base_url = crate::identity::session_refresh::sdk_base_url_from_gate_account_base_url(
        gate_account_base_url.as_str(),
    )?;
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
        Err(error) => Err(anyhow::Error::new(error).context("account authority logout failed")),
    }
}

fn account_logout_error_is_terminal(error: &arkret_sdk::http_client::Error) -> bool {
    error.error_code() == Some(arkret_sdk::ErrorCode::SessionLoggedOut)
}

fn account_logout_error_requires_repair(error: &arkret_sdk::http_client::Error) -> bool {
    match error {
        arkret_sdk::http_client::Error::Api { status, error } => {
            matches!(
                error.error_code(),
                Some(
                    arkret_sdk::ErrorCode::Unauthenticated
                        | arkret_sdk::ErrorCode::AuthExpired
                        | arkret_sdk::ErrorCode::GrantAlreadyConsumed
                        | arkret_sdk::ErrorCode::SessionGrantNotFound
                )
            ) || matches!(*status, 400 | 401 | 403 | 404 | 422)
        }
        arkret_sdk::http_client::Error::InsecureUrl(_)
        | arkret_sdk::http_client::Error::Url(_)
        | arkret_sdk::http_client::Error::Identifier(_)
        | arkret_sdk::http_client::Error::Signature(_) => true,
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
        .store_secret(&record.storage_key()?, &json)
        .map_err(|error| anyhow::anyhow!("failed to persist pending logout: {error}"))?;
    Ok(())
}

/// Read the journalled logout intent, if any.
pub fn restore_pending_logouts(
    store: &dyn crate::secure_key_store::SecureKeyStore,
) -> anyhow::Result<Vec<PendingLogout>> {
    let keys = store
        .list_secret_keys(Some(PENDING_LOGOUT_STORAGE_PREFIX))
        .map_err(|error| anyhow::anyhow!("failed to enumerate pending logouts: {error}"))?;
    keys.into_iter()
        .filter_map(|key| match store.get_secret(&key) {
            Ok(Some(json)) => Some(serde_json::from_str(&json).map_err(anyhow::Error::from)),
            Ok(None) => None,
            Err(error) => Some(Err(anyhow::anyhow!(
                "failed to load pending logout {key}: {error}"
            ))),
        })
        .collect()
}

/// Drop the journalled logout intent.
pub fn clear_pending_logout(
    record: &PendingLogout,
    store: &dyn crate::secure_key_store::SecureKeyStore,
) -> anyhow::Result<()> {
    if !pending_logout_slot_matches(record, store)? {
        return Ok(());
    }
    store
        .delete_secret(&record.storage_key()?)
        .map_err(|error| anyhow::anyhow!("failed to clear pending logout: {error}"))?;
    Ok(())
}

/// Store-injectable core of the pending-logout retry.
pub async fn run_pending_logout_with_store(
    now: DateTime<Utc>,
    store: &dyn crate::secure_key_store::SecureKeyStore,
) {
    let records = match restore_pending_logouts(store) {
        Ok(records) => records,
        Err(error) => {
            tracing::warn!(?error, "pending logout: failed to read journal");
            return;
        }
    };
    for record in records {
        if record.automatic_retry_expired(now) {
            continue;
        }
        let _ = execute_pending_logout(&record, store).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(super) fn base_record(created_at: DateTime<Utc>) -> PendingLogout {
        PendingLogout {
            authority: arkret_sdk::AccountId::new(
                arkret_sdk::DidCoreId::new("ak:did_core:web:alice.example").unwrap(),
                arkret_sdk::DidCoreId::new("ak:did_core:web:soland.example").unwrap(),
            ),
            device_id: arkret_sdk::DeviceId::new("ak:device:01904100-0000-7000-8000-000000000042")
                .unwrap(),
            grant_jwt: Some("eyJ.grant.jwt".to_owned()),
            device_seed_b64: Some("seed".to_owned()),
            device_jkt: Some("jkt".to_owned()),
            station_url: Some(url::Url::parse("https://soland.example").unwrap()),
            gate_account_base_url: Some(
                url::Url::parse("https://soland.example/_arkret/gate/account").unwrap(),
            ),
            base_url: url::Url::parse("https://soland.example").unwrap(),
            session_credential: "session-credential".to_owned(),
            principal_id: arkret_sdk::DidCoreId::new(
                "ak:did_core:web:soland.example:users:01".to_owned(),
            )
            .unwrap(),
            created_at,
        }
    }

    fn isolated_record(now: DateTime<Utc>, case: &str) -> PendingLogout {
        let mut record = base_record(now);
        record.authority = arkret_sdk::AccountId::new(
            arkret_sdk::DidCoreId::new(format!("ak:did_core:web:logout-{case}.example")).unwrap(),
            record.authority.station_id.clone(),
        );
        record
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
        assert!(restore_pending_logouts(&store).unwrap().is_empty());
        persist_pending_logout(&record, &store).unwrap();
        assert_eq!(
            restore_pending_logouts(&store).unwrap(),
            vec![record.clone()]
        );
        clear_pending_logout(&record, &store).unwrap();
        assert!(restore_pending_logouts(&store).unwrap().is_empty());
    }

    #[test]
    fn automatic_retry_age_does_not_prove_chain_termination() {
        let now = Utc::now();
        let fresh = base_record(now);
        assert!(!fresh.automatic_retry_expired(now));
        assert!(
            !fresh
                .automatic_retry_expired(now + Duration::hours(AUTOMATIC_RETRY_MAX_AGE_HOURS - 1))
        );
        assert!(
            fresh.automatic_retry_expired(now + Duration::hours(AUTOMATIC_RETRY_MAX_AGE_HOURS))
        );
        assert!(
            fresh.automatic_retry_expired(now + Duration::hours(AUTOMATIC_RETRY_MAX_AGE_HOURS + 1))
        );
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

        // No route at all (neither gate_account_base_url nor station_url).
        let mut no_route = base_record(now);
        no_route.station_url = None;
        no_route.gate_account_base_url = None;
        assert!(!no_route.has_coauth_revoke());

        // gate_account_base_url alone is a sufficient route.
        let mut base_only = base_record(now);
        base_only.station_url = None;
        assert!(base_only.has_coauth_revoke());
    }

    #[tokio::test]
    async fn missing_grant_is_not_treated_as_confirmed_logout() {
        use crate::secure_key_store::MemorySecureKeyStore;
        // Missing captured material must neither initiate a request nor claim
        // the server-side chain was terminated.
        let store = MemorySecureKeyStore::default();
        let mut record = base_record(Utc::now());
        record.grant_jwt = None;
        record.base_url = url::Url::parse("https://unused.example").unwrap();
        persist_pending_logout(&record, &store).unwrap();
        let outcome = execute_pending_logout(&record, &store).await;
        assert_eq!(outcome, LogoutRunOutcome::Blocked);
        assert_eq!(restore_pending_logouts(&store).unwrap(), vec![record]);
    }

    #[test]
    fn account_logout_terminal_errors_complete_pending_logout() {
        {
            let (status, code) = (401, "session_logged_out");
            let error = arkret_sdk::http_client::Error::Api {
                status,
                error: Box::new(arkret_sdk::Problem::from_code(code, "terminal")),
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
            (404, "unrecognized_endpoint"),
            (500, "internal"),
            (401, "auth_expired"),
            (403, "capability_denied"),
        ] {
            let error = arkret_sdk::http_client::Error::Api {
                status,
                error: Box::new(arkret_sdk::Problem::from_code(code, "retryable")),
            };
            assert!(
                !account_logout_error_is_terminal(&error),
                "{status} {code} does not prove logout completion"
            );
        }
        assert!(!account_logout_error_is_terminal(
            &arkret_sdk::http_client::Error::Protocol("network boundary".to_owned())
        ));
    }

    #[tokio::test]
    async fn missing_holder_refusal_is_retained_once_without_touching_current_credentials() {
        use std::cell::Cell;

        use crate::secure_key_store::{MemorySecureKeyStore, SecureKeyStore};
        let now = Utc::now();
        let record = isolated_record(now, "holder-refusal");
        let store = MemorySecureKeyStore::default();
        store
            .store_secret("auth.session_grant.v1", "current authenticated grant")
            .unwrap();
        persist_pending_logout(&record, &store).unwrap();
        let calls = Cell::new(0);
        for later in [now, now + Duration::seconds(1), now + Duration::minutes(10)] {
            let result = execute_pending_logout_with(&record, &store, later, || async {
                calls.set(calls.get() + 1);
                Err(anyhow::Error::new(arkret_sdk::http_client::Error::Api {
                    status: 401,
                    error: Box::new(arkret_sdk::Problem::from_code(
                        arkret_sdk::ErrorCode::Unauthenticated.as_str(),
                        "session grant logout has no verifiable holder metadata",
                    )),
                }))
            })
            .await;
            assert_eq!(result, LogoutRunOutcome::Blocked);
        }
        assert_eq!(
            calls.get(),
            1,
            "remounts cannot re-present the same refused holder"
        );
        assert_eq!(restore_pending_logouts(&store).unwrap(), vec![record]);
        assert_eq!(
            store
                .get_secret("auth.session_grant.v1")
                .unwrap()
                .as_deref(),
            Some("current authenticated grant")
        );
    }

    #[tokio::test]
    async fn transient_logout_failure_obeys_server_hint_and_does_not_fake_completion() {
        use std::cell::Cell;

        use crate::secure_key_store::MemorySecureKeyStore;
        let now = Utc::now();
        let record = isolated_record(now, "transient");
        let store = MemorySecureKeyStore::default();
        persist_pending_logout(&record, &store).unwrap();
        let calls = Cell::new(0);
        let first = execute_pending_logout_with(&record, &store, now, || async {
            calls.set(calls.get() + 1);
            Err(anyhow::Error::new(arkret_sdk::http_client::Error::Api {
                status: 503,
                error: Box::new(
                    arkret_sdk::Problem::from_code("temporarily_unavailable", "dependency offline")
                        .with_retry_after_ms(Some(120_000)),
                ),
            }))
        })
        .await;
        assert_eq!(first, LogoutRunOutcome::Retain);
        let early =
            execute_pending_logout_with(&record, &store, now + Duration::seconds(119), || async {
                panic!("must not retry before the server hint")
            })
            .await;
        assert_eq!(early, LogoutRunOutcome::Retain);
        assert_eq!(
            restore_pending_logouts(&store).unwrap(),
            vec![record.clone()]
        );
        let done =
            execute_pending_logout_with(&record, &store, now + Duration::seconds(121), || async {
                calls.set(calls.get() + 1);
                Ok(AccountLogoutRunOutcome::Terminated)
            })
            .await;
        assert_eq!(done, LogoutRunOutcome::Completed);
        assert_eq!(calls.get(), 2);
        assert!(restore_pending_logouts(&store).unwrap().is_empty());
    }

    #[tokio::test]
    async fn missing_captured_key_is_not_treated_as_confirmed_logout() {
        use crate::secure_key_store::MemorySecureKeyStore;
        let now = Utc::now();
        let mut record = isolated_record(now, "missing-key");
        record.device_seed_b64 = None;
        let store = MemorySecureKeyStore::default();
        persist_pending_logout(&record, &store).unwrap();
        let result = execute_pending_logout_with(&record, &store, now, || async {
            panic!("incomplete holder must not produce an HTTP request")
        })
        .await;
        assert_eq!(result, LogoutRunOutcome::Blocked);
        assert_eq!(restore_pending_logouts(&store).unwrap(), vec![record]);
    }

    #[tokio::test]
    async fn expired_capture_retains_journal_without_presenting_holder_or_current_credentials() {
        use crate::secure_key_store::{MemorySecureKeyStore, SecureKeyStore};
        let now = Utc::now();
        let record = isolated_record(
            now - Duration::hours(AUTOMATIC_RETRY_MAX_AGE_HOURS),
            "expired",
        );
        let store = MemorySecureKeyStore::default();
        store
            .store_secret("auth.session_grant.v1", "current authenticated grant")
            .unwrap();
        persist_pending_logout(&record, &store).unwrap();
        let result = execute_pending_logout_with(&record, &store, now, || async {
            panic!("expired captured holder must not produce an HTTP request")
        })
        .await;
        assert_eq!(result, LogoutRunOutcome::Blocked);
        assert_eq!(
            execute_pending_logout(&record, &store).await,
            LogoutRunOutcome::Blocked
        );
        run_pending_logout_with_store(now, &store).await;
        assert_eq!(restore_pending_logouts(&store).unwrap(), vec![record]);
        assert_eq!(
            store
                .get_secret("auth.session_grant.v1")
                .unwrap()
                .as_deref(),
            Some("current authenticated grant")
        );
    }

    #[tokio::test]
    async fn cancelled_logout_releases_single_flight_without_losing_the_journal() {
        use std::future::Future;

        use crate::secure_key_store::MemorySecureKeyStore;
        let now = Utc::now();
        let record = isolated_record(now, "cancelled");
        let store = MemorySecureKeyStore::default();
        persist_pending_logout(&record, &store).unwrap();
        let mut running = Box::pin(execute_pending_logout_with(
            &record,
            &store,
            now,
            || async {
                std::future::pending::<()>().await;
                Ok(AccountLogoutRunOutcome::Terminated)
            },
        ));
        let mut context = std::task::Context::from_waker(std::task::Waker::noop());
        assert!(running.as_mut().poll(&mut context).is_pending());
        let concurrent = execute_pending_logout_with(&record, &store, now, || async {
            panic!("another logout presentation is already running")
        })
        .await;
        assert_eq!(concurrent, LogoutRunOutcome::Retain);
        drop(running);
        assert_eq!(
            restore_pending_logouts(&store).unwrap(),
            vec![record.clone()]
        );
        let complete = execute_pending_logout_with(
            &record,
            &store,
            Utc::now() + Duration::seconds(2),
            || async { Ok(AccountLogoutRunOutcome::Terminated) },
        )
        .await;
        assert_eq!(complete, LogoutRunOutcome::Completed);
        assert!(restore_pending_logouts(&store).unwrap().is_empty());
    }

    #[tokio::test]
    async fn invalid_captured_seed_blocks_before_any_authority_request() {
        use crate::secure_key_store::MemorySecureKeyStore;
        let record = isolated_record(Utc::now(), "invalid-seed");
        let store = MemorySecureKeyStore::default();
        persist_pending_logout(&record, &store).unwrap();
        assert_eq!(
            execute_pending_logout(&record, &store).await,
            LogoutRunOutcome::Blocked
        );
        assert_eq!(
            execute_pending_logout(&record, &store).await,
            LogoutRunOutcome::Blocked
        );
        assert_eq!(restore_pending_logouts(&store).unwrap(), vec![record]);
    }

    #[tokio::test]
    async fn completion_of_an_old_logout_does_not_clear_a_new_captured_holder() {
        use crate::secure_key_store::{MemorySecureKeyStore, SecureKeyStore};
        let now = Utc::now();
        let old = isolated_record(now, "replacement");
        let mut newer = old.clone();
        newer.grant_jwt = Some("new captured grant".into());
        newer.created_at = now + Duration::seconds(1);
        let store = MemorySecureKeyStore::default();
        store
            .store_secret("auth.session_grant.v1", "current authenticated grant")
            .unwrap();
        persist_pending_logout(&old, &store).unwrap();
        let result = execute_pending_logout_with(&old, &store, now, || async {
            persist_pending_logout(&newer, &store).unwrap();
            Ok(AccountLogoutRunOutcome::Terminated)
        })
        .await;
        assert_eq!(result, LogoutRunOutcome::Completed);
        assert_eq!(restore_pending_logouts(&store).unwrap(), vec![newer]);
        assert_eq!(
            store
                .get_secret("auth.session_grant.v1")
                .unwrap()
                .as_deref(),
            Some("current authenticated grant")
        );
    }

    #[test]
    fn consumed_or_missing_grant_does_not_prove_browser_chain_termination() {
        for (status, code) in [
            (400, "grant_already_consumed"),
            (404, "session_grant_not_found"),
            (401, "auth_expired"),
            (403, "capability_denied"),
        ] {
            let error = arkret_sdk::http_client::Error::Api {
                status,
                error: Box::new(arkret_sdk::Problem::from_code(
                    code,
                    "not a completion receipt",
                )),
            };
            assert!(!account_logout_error_is_terminal(&error));
            assert!(account_logout_error_requires_repair(&error));
        }
    }
}
