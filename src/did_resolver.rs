//! Default DID resolver chain for yougen.
//!
//! Wraps `cokret_sdk::identity::*` resolvers with a yougen-specific
//! `ResolverPolicy` so login / coauth / Move-signing call sites can validate
//! principal DIDs before relying on a server-asserted identity.
//!
//! Spec sources:
//! - `identity/identity-did.md` (§3 default DID methods, §4 resolver policy)
//! - `identity/identity-handles.md` (§5 fail-closed rules, §6 verifier authority/cache split)
//!
//! TRUST-AUTHORITY: this module is the single authority-grade DID
//! resolution path. Trust-decision surfaces — wallet disclosure,
//! accept-invite, join-official-Realm, cross-org federation, audit
//! trail review — MUST go through here (CXP B-E §1 /
//! identity-handles §6.1). They MUST NOT accept the server-attested
//! `binding_state=verified` projection as authoritative; that field
//! is a cache hint only. Cache-allowed surfaces (verified badge,
//! mention autocomplete, contact card) live in `components::verify_badges`
//! and `views::contacts` — those are tagged `TRUST-CACHE`.

use std::collections::HashMap;

use chrono::{DateTime, Duration, Utc};
use cokret_sdk::identity::{
    CompositeDidResolver, DidKeyResolver, DidResolver as _, DidWebResolver, DidWebvhResolver,
    ResolverFailMode, ResolverPolicy,
};
use cokret_sdk::{Did, DidDocument};

/// Deployment profile drives which DID methods are accepted as principal.
///
/// Mirrors `spec/v1/zh/identity/identity-did.md` §3.3 / §3.4:
/// - `PersonalNode`: `did:web` allowed as principal fallback.
/// - `SmallTeam` / `Organization` / higher: principal MUST be `did:webvh`.
/// - `Sovereign`: principal limited to a deployment-specific method list.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeploymentProfile {
    PersonalNode,
    SmallTeam,
    Organization,
    HighSecurity,
    Sovereign,
}

impl DeploymentProfile {
    fn allowed_principal_methods(self) -> Vec<String> {
        match self {
            // did:key remains valid for device / bootstrap on every tier.
            Self::PersonalNode => vec!["did:webvh:".into(), "did:web:".into(), "did:key:".into()],
            Self::SmallTeam | Self::Organization | Self::HighSecurity => {
                vec!["did:webvh:".into(), "did:key:".into()]
            }
            // Sovereign deployments configure their own method list; default to
            // webvh + key and let callers extend via `policy_for()`.
            Self::Sovereign => vec!["did:webvh:".into(), "did:key:".into()],
        }
    }

    fn default_principal_method(self) -> &'static str {
        match self {
            Self::PersonalNode => "did:webvh:",
            _ => "did:webvh:",
        }
    }
}

/// Build the default policy for `profile`. Fails closed on resolver errors,
/// 15-minute TTL on cached resolutions.
pub fn policy_for(profile: DeploymentProfile) -> ResolverPolicy {
    ResolverPolicy {
        allowed_methods: profile.allowed_principal_methods(),
        default_principal_method: Some(profile.default_principal_method().to_owned()),
        trust_roots: Vec::new(),
        ttl: Some(chrono::Duration::minutes(15)),
        fail_mode: ResolverFailMode::FailClosed,
    }
}

/// Build a composite resolver chain with `did:web` + `did:webvh` + `did:key`
/// adapters and the given policy. Documents must be ingested via the SDK
/// resolver APIs (`insert_from_https_response`, `ingest_log`, etc.) before
/// `resolve()` will succeed for that DID.
pub fn build_default_resolver(profile: DeploymentProfile) -> CompositeDidResolver {
    let mut composite = CompositeDidResolver::new().with_policy(policy_for(profile));
    composite.push(DidKeyResolver::new());
    composite.push(DidWebResolver::new());
    composite.push(DidWebvhResolver::new());
    composite
}

/// High-level verification surface for login / coauth.
///
/// Errors:
/// - `Disallowed` — DID method is not in `allowed_methods` for the active profile.
/// - `Unresolved` — no resolver could resolve the DID (likely missing document evidence).
/// - `MethodMismatch` — returned document `id` does not equal the requested DID.
#[derive(Debug, thiserror::Error)]
pub enum VerifyError {
    #[error("DID method not allowed: {0}")]
    Disallowed(String),
    #[error("DID resolution failed: {0}")]
    Unresolved(String),
    #[error("DID document id does not match requested DID")]
    MethodMismatch,
}

/// Verify `principal` against the resolver chain. Returns the resolved
/// `DidDocument` on success.
///
/// The resolver must already have document / log evidence registered for
/// `principal` (e.g. the caller fetched `did.json` and ingested it via
/// `DidWebResolver::insert_from_https_response`).
pub fn verify_principal(
    resolver: &CompositeDidResolver,
    principal: &Did,
) -> Result<DidDocument, VerifyError> {
    resolver
        .policy()
        .validate(principal)
        .map_err(|e| VerifyError::Disallowed(format!("{e:?}")))?;
    let doc = resolver
        .resolve_did(principal)
        .map_err(|e| VerifyError::Unresolved(format!("{e:?}")))?;
    if &doc.id != principal {
        return Err(VerifyError::MethodMismatch);
    }
    Ok(doc)
}

/// F-DID-CACHE-1: in-memory LRU + TTL cache for resolved DID documents.
///
/// Spec `identity/did-resolution.md §4` says clients SHOULD cache
/// resolved DIDs + key logs to avoid repeated network calls. The SDK
/// `CompositeDidResolver` carries a `ttl` field on its policy but does
/// not actually cache: every `resolve_did(...)` call walks the resolver
/// chain again. This struct fills that gap on the yougen side.
///
/// Invariants:
/// - `max_entries == 0` disables caching entirely (every `get` misses).
/// - Eviction is LRU by `cached_at` (the entry with the oldest `cached_at` is dropped first) —
///   sufficient because each `insert` bumps `cached_at` to "now".
/// - `get(now)` returns `None` for entries whose `expires_at <= now` and also lazily removes them
///   so size bookkeeping stays honest.
/// - `invalidate(did)` is for revocation pushes — the spec requires clients to drop cached evidence
///   when a `ck.cross_signing.reset` or `ck.device.revoke` event arrives for the actor.
///
/// Persistence to IndexedDB / local state is a follow-up; this revision
/// is in-memory only so the cache survives a single login session.
#[derive(Clone, Debug)]
pub struct DidResolutionCache {
    entries: HashMap<String, CachedDidEntry>,
    max_entries: usize,
}

#[derive(Clone, Debug)]
pub struct CachedDidEntry {
    pub document: DidDocument,
    pub cached_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

impl DidResolutionCache {
    pub fn new(max_entries: usize) -> Self {
        Self {
            entries: HashMap::new(),
            max_entries,
        }
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Look up `did` and return a clone of the cached document if a
    /// valid entry exists. Expired entries are evicted as a side
    /// effect so `len()` reflects the post-cleanup state.
    pub fn get(&mut self, did: &Did, now: DateTime<Utc>) -> Option<DidDocument> {
        let key = did.as_str().to_owned();
        match self.entries.get(&key) {
            Some(entry) if entry.expires_at > now => Some(entry.document.clone()),
            Some(_) => {
                self.entries.remove(&key);
                None
            }
            None => None,
        }
    }

    /// Insert `document` for `did`, applying TTL relative to `now`.
    /// Evicts the least-recently-cached entry when the cache exceeds
    /// `max_entries` (a no-op when `max_entries == 0` since we never
    /// admit the new entry either — the lookup will always miss).
    pub fn insert(&mut self, did: Did, document: DidDocument, now: DateTime<Utc>, ttl: Duration) {
        if self.max_entries == 0 {
            return;
        }
        let key = did.as_str().to_owned();
        let entry = CachedDidEntry {
            document,
            cached_at: now,
            expires_at: now + ttl,
        };
        if !self.entries.contains_key(&key) && self.entries.len() >= self.max_entries {
            // Pick the oldest cached_at for eviction — straightforward
            // O(n) scan; cache sizes here are small (10s, not 100k).
            if let Some(victim_key) = self
                .entries
                .iter()
                .min_by_key(|(_, e)| e.cached_at)
                .map(|(k, _)| k.clone())
            {
                self.entries.remove(&victim_key);
            }
        }
        self.entries.insert(key, entry);
    }

    /// Drop the cached entry (if any) for `did`. Called by
    /// `ck.cross_signing.reset` / `ck.device.revoke` handlers so a
    /// rotated key set isn't masked by stale cache.
    pub fn invalidate(&mut self, did: &Did) {
        self.entries.remove(did.as_str());
    }

    /// Clear every entry (e.g. on logout or trust-bundle reset).
    pub fn clear(&mut self) {
        self.entries.clear();
    }
}

impl Default for DidResolutionCache {
    /// Default cache:
    /// - 128 entries — a comfortable upper bound on the number of distinct actors a single yougen
    ///   session interacts with.
    fn default() -> Self {
        Self::new(128)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(did: &str) -> Did {
        Did::new(did.to_owned()).expect("valid did")
    }

    #[test]
    fn personal_node_allows_did_web() {
        let policy = policy_for(DeploymentProfile::PersonalNode);
        assert!(policy.permits(&parse("did:web:alice.example")));
        assert!(policy.permits(&parse(
            "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
        )));
    }

    #[test]
    fn organization_rejects_plain_did_web_principal() {
        let policy = policy_for(DeploymentProfile::Organization);
        assert!(!policy.permits(&parse("did:web:alice.example")));
        assert!(policy.permits(&parse("did:webvh:QmExampleScidValue123456:alice.example")));
    }

    #[test]
    fn default_resolver_rejects_unknown_method() {
        let resolver = build_default_resolver(DeploymentProfile::PersonalNode);
        let bogus = parse("did:bogus:1234");
        let err = verify_principal(&resolver, &bogus).expect_err("must be disallowed");
        match err {
            VerifyError::Disallowed(_) => {}
            other => panic!("expected Disallowed, got {other:?}"),
        }
    }

    #[test]
    fn unresolved_did_web_fails_closed() {
        // Allowed method, but no document evidence ingested -> fail-closed.
        let resolver = build_default_resolver(DeploymentProfile::PersonalNode);
        let did = parse("did:web:alice.example");
        match verify_principal(&resolver, &did) {
            Err(VerifyError::Unresolved(_)) => {}
            other => panic!("expected Unresolved, got {other:?}"),
        }
    }

    // ── F-DID-CACHE-1 ────────────────────────────────────────────────

    fn sample_document(did_str: &str) -> (Did, DidDocument) {
        let did = parse(did_str);
        let doc = DidDocument::new(did.clone(), "key-1", "z6Mksample");
        (did, doc)
    }

    #[test]
    fn cache_hit_returns_cloned_document_within_ttl() {
        let mut cache = DidResolutionCache::new(8);
        let (did, doc) = sample_document("did:web:alice.example");
        let t0 = Utc::now();
        cache.insert(did.clone(), doc.clone(), t0, Duration::seconds(60));
        let hit = cache.get(&did, t0 + Duration::seconds(30));
        assert_eq!(hit.as_ref().map(|d| d.id.as_str()), Some(did.as_str()));
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn cache_evicts_expired_entries_lazily_on_get() {
        let mut cache = DidResolutionCache::new(8);
        let (did, doc) = sample_document("did:web:alice.example");
        let t0 = Utc::now();
        cache.insert(did.clone(), doc, t0, Duration::seconds(60));
        // 61s later — past expires_at.
        let miss = cache.get(&did, t0 + Duration::seconds(61));
        assert!(miss.is_none());
        assert_eq!(cache.len(), 0, "expired entry should be removed on get");
    }

    #[test]
    fn cache_invalidate_drops_entry_for_revocation_pushes() {
        let mut cache = DidResolutionCache::new(8);
        let (did, doc) = sample_document("did:web:alice.example");
        let t0 = Utc::now();
        cache.insert(did.clone(), doc, t0, Duration::seconds(60));
        cache.invalidate(&did);
        assert_eq!(cache.len(), 0);
        assert!(cache.get(&did, t0).is_none());
    }

    #[test]
    fn cache_evicts_least_recently_cached_when_full() {
        let mut cache = DidResolutionCache::new(2);
        let (did_a, doc_a) = sample_document("did:web:alice.example");
        let (did_b, doc_b) = sample_document("did:web:bob.example");
        let (did_c, doc_c) = sample_document("did:web:carol.example");

        let t0 = Utc::now();
        cache.insert(did_a.clone(), doc_a, t0, Duration::seconds(600));
        cache.insert(
            did_b.clone(),
            doc_b,
            t0 + Duration::seconds(1),
            Duration::seconds(600),
        );
        // At capacity. Inserting C should evict the oldest by cached_at — A.
        cache.insert(
            did_c.clone(),
            doc_c,
            t0 + Duration::seconds(2),
            Duration::seconds(600),
        );

        assert_eq!(cache.len(), 2);
        assert!(cache.get(&did_a, t0 + Duration::seconds(3)).is_none());
        assert!(cache.get(&did_b, t0 + Duration::seconds(3)).is_some());
        assert!(cache.get(&did_c, t0 + Duration::seconds(3)).is_some());
    }

    #[test]
    fn cache_with_zero_capacity_disables_inserts() {
        let mut cache = DidResolutionCache::new(0);
        let (did, doc) = sample_document("did:web:alice.example");
        let t0 = Utc::now();
        cache.insert(did.clone(), doc, t0, Duration::seconds(60));
        assert_eq!(cache.len(), 0);
        assert!(cache.get(&did, t0).is_none());
    }

    #[test]
    fn cache_clear_empties_everything() {
        let mut cache = DidResolutionCache::default();
        let (did_a, doc_a) = sample_document("did:web:alice.example");
        let (did_b, doc_b) = sample_document("did:web:bob.example");
        let t0 = Utc::now();
        cache.insert(did_a, doc_a, t0, Duration::seconds(60));
        cache.insert(did_b, doc_b, t0, Duration::seconds(60));
        assert_eq!(cache.len(), 2);
        cache.clear();
        assert_eq!(cache.len(), 0);
    }
}
