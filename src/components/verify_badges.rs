//! Visual indicators for identity-cache state.
//!
//! The badge is intentionally pure — it takes a single typed prop
//! and renders an `<span>` with a stable `data-testid` for the e2e
//! harness.

use arkret_sdk::identity::{CachedResolution, DidResolutionCache, Freshness};
use chrono::{DateTime, Utc};
use dioxus::prelude::*;

// TRUST-CACHE: `TrustCacheBadge` is a cache-allowed surface per AKP
// B-E §1 / identity-handles §6. It renders the locally-cached binding
// state but MUST downgrade to the degraded tint on a cache miss or
// any §6.1.2 trigger.
// Authority surfaces (wallet disclosure / accept invite / audit-trail
// review) MUST go through `crate::identity::did_resolver::build_default_resolver`
// and verify the DID Document inline before granting trust — they
// MUST NOT consult these cached badges as a source of truth.

/// Y3 - TRUST-CACHE display degradation state.
///
/// This is pure UX state: it only reflects whether the local DID resolution
/// cache has a usable actor record, and never replaces authority validation
/// (the authority path uses
/// `crate::identity::did_resolver::resolve_with_cache` / `verify_principal`).
/// The three render states map to three badges:
/// - `Cached`: fresh cache hit; display `cached`, meaning the cached identity is usable.
/// - `Stale`: cache hit past policy TTL; display `stale`, meaning identity may have changed and
///   authority re-resolution is in progress.
/// - `Degraded`: cache miss; display `degraded`, meaning there is no local cache evidence and trust
///   decisions must go through authority validation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TrustCacheState {
    Cached,
    Stale,
    Degraded,
}

impl TrustCacheState {
    /// `data-trust-cache` attribute value and CSS modifier suffix for this state.
    pub fn token(self) -> &'static str {
        match self {
            Self::Cached => "cached",
            Self::Stale => "stale",
            Self::Degraded => "degraded",
        }
    }
}

/// Y3 core mapping, kept pure for unit tests: derive [`TrustCacheState`] from a
/// cache entry's state at `now`.
/// - `None` (cache miss) -> `Degraded`.
/// - `Some` with [`Freshness::Fresh`] -> `Cached`.
/// - `Some` with [`Freshness::Stale`] -> `Stale`.
pub fn trust_cache_state(entry: Option<&CachedResolution>, now: DateTime<Utc>) -> TrustCacheState {
    match entry {
        None => TrustCacheState::Degraded,
        Some(entry) => match entry.freshness_at(now) {
            Freshness::Fresh => TrustCacheState::Cached,
            Freshness::Stale { .. } => TrustCacheState::Stale,
            Freshness::Missing => TrustCacheState::Degraded,
        },
    }
}

/// DID-P2-B: map a durable accepted-binding status onto the same three display
/// states. `Deactivated` / `Quarantined` are terminal and deliberately render
/// as `Degraded` — the client holds evidence, but evidence that says "do not
/// trust", which for a display badge is the same instruction as "no evidence".
pub fn trust_cache_state_from_binding(
    status: Option<arkret_sdk::identity::DidBindingStatus>,
) -> TrustCacheState {
    use arkret_sdk::identity::DidBindingStatus;
    match status {
        Some(DidBindingStatus::Active) => TrustCacheState::Cached,
        Some(DidBindingStatus::Stale) => TrustCacheState::Stale,
        Some(DidBindingStatus::Deactivated | DidBindingStatus::Quarantined) | None => {
            TrustCacheState::Degraded
        }
    }
}

/// Y3 display component: render a `cached` / `stale` / `degraded` badge based
/// on the `peer` DID's state in the session-scoped DID resolution cache.
///
/// Reads the cache through `use_context::<Signal<DidResolutionCache>>()`
/// provided by `app.rs`, then probes with read-only `peek` so expired entries
/// are not evicted. If `peer` is not valid DID syntax, render `Degraded`.
///
/// TRUST-CACHE: this badge is a UX hint only and is not trust evidence.
#[component]
pub fn TrustCacheBadge(peer: String) -> Element {
    let cache = use_context::<Signal<DidResolutionCache>>();
    let state_store = crate::app::SessionContext::get().state_store;
    let now = Utc::now();
    let state = match arkret_sdk::DidFullId::new(peer.clone()) {
        Ok(did) => {
            let session_state = {
                let guard = cache.read();
                let entry = guard.peek(&did);
                trust_cache_state(entry.as_ref(), now)
            };
            // DID-P2-B step 3: on a session-cache miss, fall back to the
            // **durable** accepted binding before degrading. A restart empties
            // the session cache but not the binding store, and the badge must
            // not claim "no local evidence" while the client is in fact still
            // verifying signatures against a pinned document. Both reads are
            // local and read-only (`peek` does not evict, the binding probe
            // does not clone documents); neither can reach a resolver.
            if session_state == TrustCacheState::Degraded {
                trust_cache_state_from_binding(
                    state_store.read().accepted_did_binding_status(&did, now),
                )
            } else {
                session_state
            }
        }
        Err(_) => TrustCacheState::Degraded,
    };
    let (label, title) = match state {
        TrustCacheState::Cached => (
            "✓ cached",
            "Identity served from a fresh local cache. Authority surfaces still re-verify the DID inline.",
        ),
        TrustCacheState::Stale => (
            "… stale",
            "Cached identity is past its TTL; a fresh resolution is pending. Treat as unverified for trust decisions.",
        ),
        TrustCacheState::Degraded => (
            "⚠ degraded",
            "No cached identity evidence. Trust decisions must go through inline DID resolution.",
        ),
    };
    rsx! {
        span {
            class: "badge trust-cache-badge {state.token()}",
            "data-testid": "trust-cache-badge",
            "data-trust-cache": state.token(),
            title,
            "{label}"
        }
    }
}

#[cfg(test)]
mod tests {
    use arkret_sdk::{DidDocument, DidFullId};
    use chrono::Duration;

    use super::*;

    // ── Y3 TRUST-CACHE display degradation ───────────────────────────

    fn sample_entry(ttl_secs: i64, now: DateTime<Utc>) -> CachedResolution {
        let did = DidFullId::new("did:web:alice.example".to_owned()).expect("valid did");
        CachedResolution::new(
            DidDocument::new(did, "key-1", "z6Mksample"),
            now,
            now + Duration::seconds(ttl_secs),
        )
        .unwrap()
    }

    #[test]
    fn trust_cache_state_miss_is_degraded() {
        let now = Utc::now();
        assert_eq!(trust_cache_state(None, now), TrustCacheState::Degraded);
    }

    #[test]
    fn trust_cache_state_fresh_entry_is_cached() {
        let now = Utc::now();
        let entry = sample_entry(60, now);
        assert_eq!(
            trust_cache_state(Some(&entry), now + Duration::seconds(30)),
            TrustCacheState::Cached
        );
    }

    #[test]
    fn trust_cache_state_expired_entry_is_stale() {
        let now = Utc::now();
        let entry = sample_entry(60, now);
        assert_eq!(
            trust_cache_state(Some(&entry), now + Duration::seconds(61)),
            TrustCacheState::Stale
        );
    }

    #[test]
    fn trust_cache_state_tokens_are_stable() {
        assert_eq!(TrustCacheState::Cached.token(), "cached");
        assert_eq!(TrustCacheState::Stale.token(), "stale");
        assert_eq!(TrustCacheState::Degraded.token(), "degraded");
    }
}
