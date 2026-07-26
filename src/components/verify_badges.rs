//! Visual indicators for crypto and identity-cache state.
//!
//! Two small surfaces:
//!
//! - [`NeedsVerificationBadge`] — rendered next to a message when its crypto state is
//!   `NeedsVerification`. Red dot + tooltip warning the reader the sender's device hasn't been
//!   cross-signed yet.
//!
//! The badges are intentionally pure — they take a single typed prop
//! and render an `<span>` with a stable `data-testid` for the e2e
//! harness.

use arkret_sdk::identity::{CachedResolution, DidResolutionCache, Freshness};
use chrono::{DateTime, Utc};
use dioxus::prelude::*;

// TRUST-CACHE: `NeedsVerificationBadge` is a
// cache-allowed surfaces per AKP B-E §1 / identity-handles §6. They
// render the locally-cached binding state but MUST downgrade to the
// "needs verification" tint on a cache miss or any §6.1.2 trigger.
// Authority surfaces (wallet disclosure / accept invite / audit-trail
// review) MUST go through `crate::identity::did_resolver::build_default_resolver`
// and verify the DID Document inline before granting trust — they
// MUST NOT consult these cached badges as a source of truth.

/// Renders a small "Needs verification" badge. Hidden when `active` is
/// `false` so call sites can unconditionally include the badge in
/// message-card rsx without an `if` branch.
#[component]
pub fn NeedsVerificationBadge(active: bool) -> Element {
    if !active {
        return rsx! {};
    }
    rsx! {
        span {
            class: "badge needs-verification-badge red",
            "data-testid": "needs-verification-badge",
            title: "Sender device hasn't been verified. Cross-sign or scan a QR before trusting this message.",
            "⚠ Needs verification"
        }
    }
}

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
    let now = Utc::now();
    let state = match arkret_sdk::Did::new(peer.clone()) {
        Ok(did) => {
            let guard = cache.read();
            let entry = guard.peek(&did);
            trust_cache_state(entry.as_ref(), now)
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
    use arkret_sdk::{Did, DidDocument};
    use chrono::Duration;

    use super::*;

    // ── Y3 TRUST-CACHE display degradation ───────────────────────────

    fn sample_entry(ttl_secs: i64, now: DateTime<Utc>) -> CachedResolution {
        let did = Did::new("did:web:alice.example".to_owned()).expect("valid did");
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
