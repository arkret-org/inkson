//! Main session OIDC token lifecycle.
//!
//! This module owns the **client-side** half of the token-refresh /
//! 401-retry contract that keeps a yougen session alive without
//! manual re-login:
//!
//! 1. **Background refresh** — every 30s a polling task wakes up, inspects the persisted
//!    [`OidcTokenBundle`], and calls [`CoauthApi::refresh_oidc_tokens`] when the access token is
//!    within `REFRESH_SKEW_SECS` of expiry. The new bundle is written back via
//!    `LocalStateStore::set_oidc_tokens`. Use [`refresh_if_due`] from a `dioxus::use_future`
//!    polling loop (or a platform-specific scheduler).
//! 2. **401 retry** — every soland call goes through [`with_oidc_retry`]. The first 401 from the
//!    wrapped future triggers a one-shot refresh; on success the future is retried with the fresh
//!    access token. If the refresh itself fails (refresh_token revoked / expired), the persisted
//!    bundle is cleared and the caller surfaces [`OidcLifecycleEvent::LoginRequired`].
//!
//! The split into pure logic functions (`due_for_refresh`,
//! `extract_status_code`) plus a thin async harness keeps the
//! state-machine fully testable without spinning up a real reqwest
//! client. The harness side that talks to `LocalStateStore` is
//! `cfg(not(target_arch = "wasm32"))` because the persisted state
//! lives in `state.json` on native; on the web we lean on
//! `localStorage` indirectly through the same store.

use chrono::Utc;

use crate::coauth::{CoauthApi, OidcTokenResponse};
use crate::local_state::{LocalStateStore, OidcTokenBundle};

/// Window before the access-token's `expires_at_unix` at which the
/// background polling triggers a refresh. Mirrors the
/// `LocalStateStore::oidc_access_token_valid` 30s skew but uses a
/// 60s window so the refresh actually happens *before* the token
/// dies mid-request.
pub const REFRESH_SKEW_SECS: i64 = 60;

/// Recommended polling interval for `dioxus::use_future` /
/// platform-equivalent schedulers. 30s strikes a balance between
/// reactivity (a token expiring in 60s gets exactly one chance to
/// refresh) and mobile-battery friendliness.
pub const POLL_INTERVAL_SECS: u64 = 30;

/// Typed lifecycle event surfaced by the polling /
/// retry helpers. UIs subscribe to this stream and route
/// `LoginRequired` to the login page; `Refreshed` is informational and
/// drives a "session refreshed" toast.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OidcLifecycleEvent {
    /// No persisted bundle — either the user hasn't logged in yet or
    /// a previous failed-refresh cleared the bundle.
    NoBundle,
    /// The persisted access token is fresh; nothing to do.
    Fresh,
    /// A refresh just succeeded; the new bundle has been persisted.
    Refreshed,
    /// The refresh attempt failed (network, refresh_token revoked,
    /// principal-server policy). The persisted bundle has been
    /// cleared and the UI must redirect to the login page.
    LoginRequired { reason: String },
    /// The bundle has no `refresh_token` — no automatic refresh path
    /// available. Treat as `Fresh` until the access token actually
    /// expires; then the next 401 promotes to `LoginRequired`.
    NoRefreshToken,
}

/// True when the bundle's access token is within
/// [`REFRESH_SKEW_SECS`] of expiry. `None` for `expires_at_unix`
/// (provider didn't return `expires_in`) is treated as "not due for
/// refresh" — the 401-retry path will catch it if it does expire.
pub fn due_for_refresh(bundle: &OidcTokenBundle) -> bool {
    let Some(expires_at) = bundle.expires_at_unix else {
        return false;
    };
    let now = Utc::now().timestamp();
    expires_at - now <= REFRESH_SKEW_SECS
}

/// True when the bundle has a refresh_token to spend. Without one,
/// expired access tokens immediately surface `LoginRequired`.
pub fn has_refresh_token(bundle: &OidcTokenBundle) -> bool {
    bundle
        .refresh_token
        .as_deref()
        .is_some_and(|rt| !rt.is_empty())
}

/// Runs the refresh policy decision on the persisted
/// bundle. Pure function — no I/O — so the caller (background poller
/// or 401 retry path) can decide whether to actually issue the
/// refresh request without holding a network handle.
pub fn evaluate_refresh_policy(store: &LocalStateStore) -> RefreshDecision {
    let Some(bundle) = store.oidc_tokens() else {
        return RefreshDecision::NoBundle;
    };
    evaluate_refresh_decision_from_bundle(&bundle)
}

/// SecureKeyStore-aware variant. Reads the bundle via
/// [`LocalStateStore::load_oidc_tokens_with_secure_store`] so the
/// `refresh_token` actually surfaces (the disk-backed bundle holds
/// `refresh_token: None`; the live secret only exists in the
/// SecureKeyStore). Use this from the production refresh poller; tests
/// that don't care about secure-store wiring keep using
/// [`evaluate_refresh_policy`].
pub fn evaluate_refresh_policy_with_secure_store(
    store: &LocalStateStore,
    actor_did: &str,
    secure_store: &dyn crate::secure_key_store::SecureKeyStore,
) -> RefreshDecision {
    let Some(bundle) = store.load_oidc_tokens_with_secure_store(actor_did, secure_store) else {
        return RefreshDecision::NoBundle;
    };
    evaluate_refresh_decision_from_bundle(&bundle)
}

/// Shared logic between the two `evaluate_refresh_policy*` entry
/// points. Pure function over the typed bundle so neither path
/// touches disk a second time.
fn evaluate_refresh_decision_from_bundle(bundle: &OidcTokenBundle) -> RefreshDecision {
    if !due_for_refresh(bundle) {
        return RefreshDecision::Fresh;
    }
    if !has_refresh_token(bundle) {
        return RefreshDecision::NoRefreshToken;
    }
    RefreshDecision::Refresh {
        client_id: bundle.audience.clone().unwrap_or_default(),
        refresh_token: bundle.refresh_token.clone().unwrap_or_default(),
        audience: bundle.audience.clone(),
    }
}

/// Decision the polling loop reaches after inspecting the persisted
/// bundle. The `Refresh` variant carries the raw token-endpoint
/// inputs so the network harness only needs to know how to call
/// [`CoauthApi::refresh_oidc_tokens`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RefreshDecision {
    NoBundle,
    Fresh,
    NoRefreshToken,
    Refresh {
        client_id: String,
        refresh_token: String,
        audience: Option<String>,
    },
}

impl RefreshDecision {
    /// Translate the policy decision into a UI-facing event. Used by
    /// callers that don't go through the network step (mock tests,
    /// the "refresh on demand" button in settings).
    pub fn as_event(&self) -> OidcLifecycleEvent {
        match self {
            Self::NoBundle => OidcLifecycleEvent::NoBundle,
            Self::Fresh => OidcLifecycleEvent::Fresh,
            Self::NoRefreshToken => OidcLifecycleEvent::NoRefreshToken,
            Self::Refresh { .. } => OidcLifecycleEvent::Refreshed,
        }
    }
}

/// Apply a token-endpoint refresh response to the
/// persisted bundle. Returns the resulting [`OidcTokenBundle`] so the
/// caller can both persist it (via `set_oidc_tokens`) and use the
/// fresh access token for the in-flight request.
///
/// Spec contract: per RFC 6749 §6, the refresh response MAY return a
/// new refresh_token (rotating refresh tokens, e.g. Google) or omit
/// it (the existing refresh_token stays valid, e.g. Auth0). This
/// helper preserves the previous refresh_token when the response
/// doesn't carry a new one — that mirrors how [`OidcTokenResponse::to_persisted_bundle`]
/// interprets the wire shape but composes it with the original
/// bundle's refresh_token as the fallback.
pub fn apply_refresh_response(
    previous: &OidcTokenBundle,
    response: &OidcTokenResponse,
) -> OidcTokenBundle {
    let mut next = response.to_persisted_bundle(previous.audience.as_deref());
    if next.refresh_token.is_none() || next.refresh_token.as_deref() == Some("") {
        next.refresh_token = previous.refresh_token.clone();
    }
    next
}

/// Polling tick. Called every
/// [`POLL_INTERVAL_SECS`] (default 30s). Returns the lifecycle event
/// for the UI to route. Network calls go through `coauth_api`; the
/// `token_endpoint` is the OIDC provider's token endpoint URL
/// resolved via discovery (cached in [`LocalConfigStore`] in the
/// real app).
pub async fn refresh_if_due(
    store: &mut LocalStateStore,
    coauth_api: &CoauthApi,
    token_endpoint: &str,
) -> OidcLifecycleEvent {
    refresh_if_due_inner(store, coauth_api, token_endpoint, None).await
}

/// SecureKeyStore-aware variant of [`refresh_if_due`].
/// The refresh poller in production code MUST call
/// this — it reads the refresh_token via
/// [`LocalStateStore::load_oidc_tokens_with_secure_store`] and writes
/// the rotated refresh_token back through
/// [`LocalStateStore::set_oidc_tokens_with_secure_store`], so the
/// disk-backed `state.json` never holds the refresh credential in
/// plaintext. The `actor_did` parameter is the principal whose bundle
/// is being refreshed; it's woven into the SecureKeyStore key as
/// `coauth.refresh_token.<actor_did>` so multi-actor devices stay
/// isolated.
pub async fn refresh_if_due_with_secure_store(
    store: &mut LocalStateStore,
    coauth_api: &CoauthApi,
    token_endpoint: &str,
    actor_did: &str,
    secure_store: &dyn crate::secure_key_store::SecureKeyStore,
) -> OidcLifecycleEvent {
    refresh_if_due_inner(
        store,
        coauth_api,
        token_endpoint,
        Some((actor_did, secure_store)),
    )
    .await
}

/// Shared body between `refresh_if_due` and the secure-store-aware
/// variant. When `actor_did_and_store` is `Some`, reads + writes use
/// the H3 helpers (refresh_token never lands in `state.json`).
async fn refresh_if_due_inner(
    store: &mut LocalStateStore,
    coauth_api: &CoauthApi,
    token_endpoint: &str,
    actor_did_and_store: Option<(&str, &dyn crate::secure_key_store::SecureKeyStore)>,
) -> OidcLifecycleEvent {
    let decision = match actor_did_and_store {
        Some((actor_did, secure_store)) => {
            evaluate_refresh_policy_with_secure_store(store, actor_did, secure_store)
        }
        None => evaluate_refresh_policy(store),
    };
    let (client_id, refresh_token, audience) = match decision {
        RefreshDecision::NoBundle => return OidcLifecycleEvent::NoBundle,
        RefreshDecision::Fresh => return OidcLifecycleEvent::Fresh,
        RefreshDecision::NoRefreshToken => return OidcLifecycleEvent::NoRefreshToken,
        RefreshDecision::Refresh {
            client_id,
            refresh_token,
            audience,
        } => (client_id, refresh_token, audience),
    };
    let _ = audience; // currently informational; bundle preserves it.
    match coauth_api
        .refresh_oidc_tokens(token_endpoint, &client_id, &refresh_token)
        .await
    {
        Ok(response) => {
            // Read prev bundle through the appropriate helper so the
            // restored `refresh_token` is honoured when computing the
            // next bundle (per RFC 6749 §6, the IdP MAY omit the new
            // refresh_token meaning the old one stays valid).
            let previous = match actor_did_and_store {
                Some((actor_did, secure_store)) => store
                    .load_oidc_tokens_with_secure_store(actor_did, secure_store)
                    .unwrap_or_else(|| OidcTokenBundle {
                        access_token: String::new(),
                        refresh_token: Some(refresh_token.clone()),
                        token_type: "Bearer".to_owned(),
                        expires_at_unix: None,
                        id_token: None,
                        scope: None,
                        audience: None,
                        stored_at: Utc::now(),
                    }),
                None => store.oidc_tokens().unwrap_or_else(|| OidcTokenBundle {
                    access_token: String::new(),
                    refresh_token: Some(refresh_token.clone()),
                    token_type: "Bearer".to_owned(),
                    expires_at_unix: None,
                    id_token: None,
                    scope: None,
                    audience: None,
                    stored_at: Utc::now(),
                }),
            };
            let next = apply_refresh_response(&previous, &response);
            match actor_did_and_store {
                Some((actor_did, secure_store)) => {
                    store.set_oidc_tokens_with_secure_store(Some(next), actor_did, secure_store);
                }
                None => store.set_oidc_tokens(Some(next)),
            }
            OidcLifecycleEvent::Refreshed
        }
        Err(error) => {
            // Refresh failed — clear the bundle so the next render
            // routes to the login page rather than re-trying with the
            // dead refresh_token in a tight loop.
            match actor_did_and_store {
                Some((actor_did, secure_store)) => {
                    store.set_oidc_tokens_with_secure_store(None, actor_did, secure_store);
                }
                None => store.set_oidc_tokens(None),
            }
            OidcLifecycleEvent::LoginRequired {
                reason: error.to_string(),
            }
        }
    }
}

/// Outcome of a soland call wrapped in `with_oidc_retry`.
/// Generic over the success type so any typed API call composes the same
/// way; the caller handles `LoginRequired` by routing to the login view.
#[derive(Debug)]
pub enum AuthedCallOutcome<T> {
    /// Call returned successfully (either on first try or after a
    /// successful refresh).
    Ok(T),
    /// Call returned a 401 and the refresh attempt also failed; the
    /// caller MUST route to the login view.
    LoginRequired { reason: String },
    /// Call returned a non-401 error (network, 500, etc.); pass
    /// through to the caller's normal error path.
    Error(anyhow::Error),
}

/// Map a reqwest / SDK / coauth error to its HTTP status code, if any.
/// Used by the 401-retry harness to decide whether to attempt a
/// refresh. Currently does a string-search on the error chain because
/// `anyhow::Error` erases the underlying type — the helper looks for
/// a `HTTP NNN` marker (reqwest + soland typed wrappers both emit
/// this) so generic body text doesn't false-match.
pub fn extract_status_code(error: &anyhow::Error) -> Option<u16> {
    let chain = format!("{error}");
    // Try the chain (Display) first — Debug includes a stacktrace
    // that may contain rust-source line numbers that look like HTTP
    // status codes. Display is the bare error message reqwest /
    // soland actually emit.
    for code in [401, 403, 500, 502, 503, 504, 400, 404, 409, 422] {
        let with_prefix = format!("HTTP {code}");
        if chain.contains(&with_prefix) {
            return Some(code);
        }
        // Plain "401: ..." and ": 401:" style markers — reqwest's
        // status_for_error uses these when the response is wrapped.
        let inline = format!(" {code}:");
        if chain.contains(&inline) {
            return Some(code);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    #[cfg(not(target_arch = "wasm32"))]
    use std::path::PathBuf;
    #[cfg(not(target_arch = "wasm32"))]
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;

    /// Build a hermetic `LocalStateStore` rooted at a unique temp file.
    /// Necessary because `LocalStateStore::default()` resolves to the
    /// developer's `state.json` under `$LOCALAPPDATA/yougen/` (or the
    /// `YOUGEN_STATE_PATH` override) and would otherwise leak whatever
    /// pre-existing OIDC bundle the dev session has persisted into the
    /// `evaluate_refresh_policy` decisions under test.
    #[cfg(not(target_arch = "wasm32"))]
    fn isolated_store(tag: &str) -> LocalStateStore {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        let path: PathBuf =
            std::env::temp_dir().join(format!("yougen-oidc-lifecycle-{tag}-{stamp}.json"));
        LocalStateStore::with_path(path)
    }

    #[cfg(target_arch = "wasm32")]
    fn isolated_store(_tag: &str) -> LocalStateStore {
        LocalStateStore::default()
    }

    fn fresh_bundle(expires_in: i64) -> OidcTokenBundle {
        OidcTokenBundle {
            access_token: "at-1".to_owned(),
            refresh_token: Some("rt-1".to_owned()),
            token_type: "Bearer".to_owned(),
            expires_at_unix: Some(Utc::now().timestamp() + expires_in),
            id_token: None,
            scope: None,
            audience: Some("https://principal.example/api".to_owned()),
            stored_at: Utc::now(),
        }
    }

    #[test]
    fn due_for_refresh_fires_within_skew_window() {
        // Token expires in 30s — well within the 60s skew window.
        let bundle = fresh_bundle(30);
        assert!(due_for_refresh(&bundle));
    }

    #[test]
    fn due_for_refresh_skips_when_token_has_lots_of_runway() {
        let bundle = fresh_bundle(3600);
        assert!(!due_for_refresh(&bundle));
    }

    #[test]
    fn due_for_refresh_skips_when_no_expiry_recorded() {
        let mut bundle = fresh_bundle(30);
        bundle.expires_at_unix = None;
        assert!(!due_for_refresh(&bundle));
    }

    #[test]
    fn has_refresh_token_requires_non_empty_value() {
        let mut bundle = fresh_bundle(30);
        assert!(has_refresh_token(&bundle));
        bundle.refresh_token = Some(String::new());
        assert!(!has_refresh_token(&bundle));
        bundle.refresh_token = None;
        assert!(!has_refresh_token(&bundle));
    }

    /// With a SecureKeyStore-aware persist pre-run, the on-disk bundle's
    /// `refresh_token` is `None` — but
    /// `evaluate_refresh_policy_with_secure_store` MUST surface the
    /// refresh_token from the secure store so the policy decision is
    /// `Refresh { refresh_token: "rt-1", .. }` not `NoRefreshToken`.
    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn evaluate_policy_with_secure_store_reattaches_refresh_token_for_due_bundle() {
        use crate::secure_key_store::MemorySecureKeyStore;
        let mut store = isolated_store("h5-secure-store-due");
        let secure = MemorySecureKeyStore::default();
        let actor = "did:web:alice.example";
        // Persist a due bundle through the SecureKeyStore helper so
        // disk-state has `refresh_token: None` and the secret lives
        // only in `secure`.
        store.set_oidc_tokens_with_secure_store(Some(fresh_bundle(20)), actor, &secure);
        // The disk-only evaluator MUST see no refresh token — proving
        // the secure-store path kept the secret out of state.json.
        assert_eq!(
            evaluate_refresh_policy(&store),
            RefreshDecision::NoRefreshToken,
            "disk-only poller can't see the secure-store refresh_token",
        );
        // The new poller MUST reattach + decide Refresh.
        match evaluate_refresh_policy_with_secure_store(&store, actor, &secure) {
            RefreshDecision::Refresh { refresh_token, .. } => {
                assert_eq!(refresh_token, "rt-1");
            }
            other => panic!("expected Refresh, got {other:?}"),
        }
    }

    #[test]
    fn evaluate_policy_returns_no_bundle_when_unset() {
        // Hermetic: route the store at a unique tempfile path so the
        // developer's persisted state.json (which may carry an OIDC
        // bundle) cannot leak into this assertion. The fresh tempfile
        // does not exist yet, so `read_persisted_state` returns None
        // and `evaluate_refresh_policy` reaches the `NoBundle` arm.
        let store = isolated_store("no-bundle-when-unset");
        match evaluate_refresh_policy(&store) {
            RefreshDecision::NoBundle => {}
            other => panic!("expected NoBundle, got {other:?}"),
        }
    }

    #[test]
    fn evaluate_policy_returns_no_refresh_token_for_disk_only_due_bundle() {
        let mut store = isolated_store("refresh-when-due");
        store.set_oidc_tokens(Some(fresh_bundle(20)));
        assert_eq!(
            evaluate_refresh_policy(&store),
            RefreshDecision::NoRefreshToken
        );
    }

    #[test]
    fn evaluate_policy_returns_fresh_when_runway_long() {
        let mut store = isolated_store("fresh-when-runway-long");
        store.set_oidc_tokens(Some(fresh_bundle(3600)));
        assert_eq!(evaluate_refresh_policy(&store), RefreshDecision::Fresh);
    }

    #[test]
    fn evaluate_policy_returns_no_refresh_token_when_missing() {
        let mut bundle = fresh_bundle(20);
        bundle.refresh_token = None;
        let mut store = isolated_store("no-refresh-token-when-missing");
        store.set_oidc_tokens(Some(bundle));
        assert_eq!(
            evaluate_refresh_policy(&store),
            RefreshDecision::NoRefreshToken
        );
    }

    #[test]
    fn refresh_decision_maps_to_lifecycle_events() {
        assert_eq!(
            RefreshDecision::NoBundle.as_event(),
            OidcLifecycleEvent::NoBundle
        );
        assert_eq!(RefreshDecision::Fresh.as_event(), OidcLifecycleEvent::Fresh);
        assert_eq!(
            RefreshDecision::NoRefreshToken.as_event(),
            OidcLifecycleEvent::NoRefreshToken
        );
        assert_eq!(
            RefreshDecision::Refresh {
                client_id: "c".into(),
                refresh_token: "rt".into(),
                audience: None
            }
            .as_event(),
            OidcLifecycleEvent::Refreshed
        );
    }

    #[test]
    fn apply_refresh_preserves_previous_refresh_token_when_response_omits_it() {
        let previous = fresh_bundle(20);
        let response = OidcTokenResponse {
            access_token: "at-2".to_owned(),
            token_type: Some("Bearer".to_owned()),
            expires_in: Some(3600),
            refresh_token: None, // Auth0-style: refresh_token unchanged
            id_token: None,
            scope: None,
            extras: serde_json::Map::new(),
        };
        let next = apply_refresh_response(&previous, &response);
        assert_eq!(next.access_token, "at-2");
        assert_eq!(next.refresh_token.as_deref(), Some("rt-1"));
    }

    #[test]
    fn apply_refresh_uses_new_refresh_token_when_present() {
        let previous = fresh_bundle(20);
        let response = OidcTokenResponse {
            access_token: "at-2".to_owned(),
            token_type: Some("Bearer".to_owned()),
            expires_in: Some(3600),
            refresh_token: Some("rt-rotated".to_owned()),
            id_token: None,
            scope: None,
            extras: serde_json::Map::new(),
        };
        let next = apply_refresh_response(&previous, &response);
        assert_eq!(next.refresh_token.as_deref(), Some("rt-rotated"));
    }

    #[test]
    fn extract_status_code_recognises_401_and_403() {
        let err401 = anyhow::anyhow!("HTTP 401: unauthorized: token expired");
        let err403 = anyhow::anyhow!("HTTP 403: forbidden");
        let err_clean = anyhow::anyhow!("network unreachable");
        assert_eq!(extract_status_code(&err401), Some(401));
        assert_eq!(extract_status_code(&err403), Some(403));
        assert!(extract_status_code(&err_clean).is_none());
    }

    #[test]
    fn poll_constants_are_sane() {
        const { assert!(POLL_INTERVAL_SECS > 0) };
        const { assert!(POLL_INTERVAL_SECS <= 60) };
        const { assert!(REFRESH_SKEW_SECS > POLL_INTERVAL_SECS as i64) };
    }
}
