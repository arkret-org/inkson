//! Visual indicators for crypto state and Realm class (P3B.6).
//!
//! Two small surfaces:
//!
//! - [`NeedsVerificationBadge`] — rendered next to a message when its crypto state is
//!   `NeedsVerification`. Red dot + tooltip warning the reader the sender's device hasn't been
//!   cross-signed yet.
//! - [`RealmClassBadge`] — rendered next to a Realm name in the switcher / sidebar / breadcrumb so
//!   the user can instantly tell a Principal Realm (federation identity) apart from a Collaboration
//!   Realm (shared workspace inside someone else's Principal Realm).
//!
//! The badges are intentionally pure — they take a single typed prop
//! and render an `<span>` with a stable `data-testid` for the e2e
//! harness.

use chrono::{DateTime, Utc};
use dioxus::prelude::*;

use crate::did_resolver::{CachedDidEntry, Freshness};

// TRUST-CACHE: `NeedsVerificationBadge` and `RealmClassBadge` are
// cache-allowed surfaces per CKP B-E §1 / identity-handles §6. They
// render the locally-cached binding state but MUST downgrade to the
// "needs verification" tint on a cache miss or any §6.1.2 trigger.
// Authority surfaces (wallet disclosure / accept invite / audit-trail
// review) MUST go through `crate::did_resolver::build_default_resolver`
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

/// Realm classification used by [`RealmClassBadge`]. Sourced from the
/// Realm's `security_class` field (`principal` | `collaboration`)
/// surfaced by `ck.realm.create`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RealmClass {
    /// The user's home Realm — carries the federation identity, the
    /// device set, the recovery vault. Loss of this Realm is a hard
    /// account-recovery event.
    Principal,
    /// A workspace inside someone else's Principal Realm. The user has
    /// no federation identity here — they're a guest member.
    Collaboration,
    /// Unknown / not yet hydrated. Renders nothing (so the badge
    /// doesn't flash on initial load).
    Unknown,
}

impl RealmClass {
    pub fn from_wire(value: &str) -> Self {
        match value {
            "principal" => Self::Principal,
            "collaboration" => Self::Collaboration,
            _ => Self::Unknown,
        }
    }
}

#[component]
pub fn RealmClassBadge(class: RealmClass) -> Element {
    match class {
        RealmClass::Principal => rsx! {
            span {
                class: "badge realm-class-badge principal",
                "data-testid": "realm-class-badge",
                "data-class": "principal",
                title: "Principal Realm — your home federation identity lives here.",
                "★ Principal"
            }
        },
        RealmClass::Collaboration => rsx! {
            span {
                class: "badge realm-class-badge collaboration",
                "data-testid": "realm-class-badge",
                "data-class": "collaboration",
                title: "Collaboration Realm — guest workspace inside another Principal Realm.",
                "↔ Collaboration"
            }
        },
        RealmClass::Unknown => rsx! {},
    }
}

/// Y3 —— TRUST-CACHE 展示降级状态。
///
/// 这是**纯 UX 面**:它只反映本地 DID 解析缓存里那条 actor 记录的
/// 可用性,绝不替代 authority 校验(authority 面走
/// `crate::did_resolver::resolve_with_cache` / `verify_principal`)。
/// 渲染时三态对应三个标记:
/// - `Cached`:缓存命中且新鲜 —— 展示 `cached`(可放心用缓存身份)。
/// - `Stale`:缓存命中但已过期(超过 policy TTL)—— 展示 `stale` (身份可能已变,authority 重解析在途)。
/// - `Degraded`:缓存未命中 —— 展示 `degraded`(本地无任何缓存证据, 降级到 "未验证" 语义,trust
///   决策必须走 authority)。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TrustCacheState {
    Cached,
    Stale,
    Degraded,
}

impl TrustCacheState {
    /// 该状态对应的 `data-trust-cache` 属性值 / CSS 修饰类后缀。
    pub fn token(self) -> &'static str {
        match self {
            Self::Cached => "cached",
            Self::Stale => "stale",
            Self::Degraded => "degraded",
        }
    }
}

/// Y3 核心映射(纯函数,便于单测):根据缓存条目在 `now` 时刻的状态,
/// 推导 [`TrustCacheState`]。
/// - `None`(cache miss)→ `Degraded`。
/// - `Some` 且 [`Freshness::Fresh`] → `Cached`。
/// - `Some` 且 [`Freshness::Stale`] → `Stale`。
pub fn trust_cache_state(entry: Option<&CachedDidEntry>, now: DateTime<Utc>) -> TrustCacheState {
    match entry {
        None => TrustCacheState::Degraded,
        Some(entry) => match entry.freshness(now) {
            Freshness::Fresh => TrustCacheState::Cached,
            Freshness::Stale => TrustCacheState::Stale,
        },
    }
}

/// Y3 展示组件:根据 `peer` DID 在会话级 DID 解析缓存里的状态,渲染一个
/// `cached` / `stale` / `degraded` 小标记。
///
/// 经 `use_context::<Signal<DidResolutionCache>>()` 读取缓存(由 `app.rs`
/// 提供),用只读 `peek` 探查(不触发过期淘汰)。`peer` 不是合法 DID 语法
/// 时按 `Degraded` 渲染。
///
/// TRUST-CACHE:此标记仅供 UX 提示,**不构成 trust 依据**。
#[component]
pub fn TrustCacheBadge(peer: String) -> Element {
    let cache = use_context::<Signal<crate::did_resolver::DidResolutionCache>>();
    let now = Utc::now();
    let state = match cokret_sdk::Did::new(peer.clone()) {
        Ok(did) => {
            let guard = cache.read();
            trust_cache_state(guard.peek(&did), now)
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
    use chrono::Duration;
    use cokret_sdk::{Did, DidDocument};

    use super::*;

    #[test]
    fn realm_class_from_wire_maps_known_values() {
        assert_eq!(RealmClass::from_wire("principal"), RealmClass::Principal);
        assert_eq!(
            RealmClass::from_wire("collaboration"),
            RealmClass::Collaboration
        );
        assert_eq!(RealmClass::from_wire("hybrid"), RealmClass::Unknown);
        assert_eq!(RealmClass::from_wire(""), RealmClass::Unknown);
    }

    // ── Y3 TRUST-CACHE 展示降级 ──────────────────────────────────────

    fn sample_entry(ttl_secs: i64, now: DateTime<Utc>) -> CachedDidEntry {
        let did = Did::new("did:web:alice.example".to_owned()).expect("valid did");
        CachedDidEntry {
            document: DidDocument::new(did, "key-1", "z6Mksample"),
            cached_at: now,
            expires_at: now + Duration::seconds(ttl_secs),
        }
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
