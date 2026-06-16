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
//! trail review — MUST go through here (CKP B-E §1 /
//! identity-handles §6.1). They MUST NOT accept the server-attested
//! `binding_state=verified` projection as authoritative; that field
//! is a cache hint only. Cache-allowed surfaces (verified badge,
//! mention autocomplete, contact card) live in `components::verify_badges`
//! and `views::contacts` — those are tagged `TRUST-CACHE`.

use std::collections::HashMap;

use chrono::{DateTime, Duration, Utc};
use cokret_sdk::identity::{
    CompositeDidResolver, DID_WEB_MAX_DOCUMENT_BYTES, DidKeyResolver, DidResolver as _,
    DidWebDocumentOutcome, DidWebResolver, DidWebvhDocumentOutcome, DidWebvhLogOutcome,
    DidWebvhResolver, ResolverFailMode, ResolverPolicy, host_is_safe_for_outbound,
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

/// Resolver-backed [`crate::device_directory::DidAnchor`] for the Tier-2
/// device-key cross-signing chain (`device-lifecycle.md` §8.3 step 1).
///
/// Holds the deployment `profile` (which drives the [`ResolverPolicy`]) plus a
/// pair of *mutable* offline `did:web` / `did:webvh` resolvers and a
/// [`DidResolutionCache`]. The device directory's DID-anchoring step reuses the
/// *same* authority-grade resolution path as login / coauth (policy-gated,
/// cache-first via [`resolve_with_cache`], fail-closed on policy / unresolved).
///
/// ## P3.2b: async fetch + ingest of sender DID documents
///
/// `did:web` / `did:webvh` actors carry their key material off-host, so the
/// cross-signing chain can only anchor once their `did.json` (and, for webvh,
/// `did.jsonl`) is ingested. [`ResolverDidAnchor::ensure_actor_document`] is the
/// async entry the receive path calls *before* the synchronous trait method: it
/// fetches the actor's DID document over the caller's existing
/// [`reqwest::Client`] (cross-platform — native + the wasm browser-fetch
/// backend) and ingests it into the mutable resolvers via the SDK's offline
/// helpers, fail-closed on any fetch / size / content-type / chain failure.
/// `did:key` actors self-resolve and need no fetch.
///
/// The mutable resolvers + cache live behind [`RefCell`] so the `&self`
/// [`crate::device_directory::DidAnchor`] trait can still back-fill resolved
/// documents; callers reclaim the (possibly grown) cache via
/// [`ResolverDidAnchor::into_cache`] to persist it back into their signal.
pub struct ResolverDidAnchor {
    profile: DeploymentProfile,
    web: std::cell::RefCell<DidWebResolver>,
    webvh: std::cell::RefCell<DidWebvhResolver>,
    cache: std::cell::RefCell<DidResolutionCache>,
}

impl ResolverDidAnchor {
    /// Build an anchor for `profile` with fresh (empty) offline `did:web` /
    /// `did:webvh` resolvers and a snapshot of `cache`. Document / key-log
    /// evidence is ingested lazily via [`Self::ensure_actor_document`]; absent
    /// evidence, resolution fails closed and the device key is rejected.
    pub fn from_profile(profile: DeploymentProfile, cache: DidResolutionCache) -> Self {
        Self {
            profile,
            web: std::cell::RefCell::new(DidWebResolver::new()),
            webvh: std::cell::RefCell::new(DidWebvhResolver::new()),
            cache: std::cell::RefCell::new(cache),
        }
    }

    /// Reclaim the (possibly back-filled) cache so the caller can write it
    /// back into its `Signal<DidResolutionCache>`.
    pub fn into_cache(self) -> DidResolutionCache {
        self.cache.into_inner()
    }

    /// Rebuild the composite resolver chain from the policy for this profile
    /// plus a snapshot of the currently-ingested offline resolvers. `did:key`
    /// always self-resolves; `did:web` / `did:webvh` resolve only for actors
    /// whose evidence [`Self::ensure_actor_document`] has already ingested.
    fn current_resolver(&self) -> CompositeDidResolver {
        let mut composite = CompositeDidResolver::new().with_policy(policy_for(self.profile));
        composite.push(DidKeyResolver::new());
        composite.push(self.web.borrow().clone());
        composite.push(self.webvh.borrow().clone());
        composite
    }

    /// Test-only: ingest a `did:web` document straight through the SDK offline
    /// helper, bypassing the network fetch so the `ensure → resolve` contract
    /// can be exercised with synthetic responses. Returns whether ingest
    /// succeeded (the same fail-closed verdict the live fetch path applies).
    #[cfg(test)]
    fn ingest_web_for_test(&self, actor: &Did, outcome: DidWebDocumentOutcome) -> bool {
        self.web
            .borrow_mut()
            .insert_from_https_response(actor, outcome)
            .is_ok()
    }

    /// Inner async body for [`crate::device_directory::DidAnchor::ensure_actor_document`].
    /// Fetches + ingests `actor`'s DID document via the SDK offline helpers,
    /// fail-closed on any failure. `did:key` self-resolves (no fetch). A method
    /// not allowed by the active policy is a no-op `false` — the synchronous
    /// trait method then fails the policy gate too.
    async fn ingest_actor_document(&self, http: &reqwest::Client, actor: &Did) -> bool {
        if !policy_for(self.profile).permits(actor) {
            return false;
        }
        match actor.method() {
            // did:key self-resolves via DidKeyResolver; no document to fetch.
            "key" => true,
            "web" => {
                // P3.2c peek: if this actor's did.json is already ingested (a
                // prior ensure already fetched it, or the cache was seeded),
                // skip the network round-trip entirely. `resolve_did` on the
                // offline resolver succeeds only when evidence is present.
                if self.web.borrow().resolve_did(actor).is_ok() {
                    return true;
                }
                let outcome = match fetch_did_web_document(http, actor).await {
                    Some(outcome) => outcome,
                    None => return false,
                };
                self.web
                    .borrow_mut()
                    .insert_from_https_response(actor, outcome)
                    .is_ok()
            }
            "webvh" => {
                // P3.2c peek: skip the fetch when the webvh document + log are
                // already ingested for this actor.
                if self.webvh.borrow().resolve_did(actor).is_ok() {
                    return true;
                }
                let Some((doc, log)) = fetch_did_webvh_document(http, actor).await else {
                    return false;
                };
                let mut webvh = self.webvh.borrow_mut();
                if webvh.insert_from_https_response(actor, doc).is_err() {
                    return false;
                }
                // SCID + chain validation happens inside `ingest_log`; a bad log
                // rejects the actor (fail-closed).
                webvh.ingest_log(actor, log).is_ok()
            }
            // Any other method is unsupported by the offline resolvers; the
            // composite chain will fail-closed when the trait method runs.
            _ => false,
        }
    }
}

impl crate::device_directory::DidAnchor for ResolverDidAnchor {
    fn resolve_did_document(&self, actor: &Did) -> Option<DidDocument> {
        let resolver = self.current_resolver();
        let mut cache = self.cache.borrow_mut();
        resolve_with_cache(&resolver, &mut cache, actor, Utc::now()).ok()
    }

    fn ensure_actor_document<'a>(
        &'a self,
        http: &'a reqwest::Client,
        actor: &'a Did,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = bool> + 'a>> {
        Box::pin(self.ingest_actor_document(http, actor))
    }
}

/// Maximum bytes accepted for a fetched `did.jsonl` log. Mirrors the SDK's
/// native `HttpDidResolver` template (`http_did_resolver.rs`): the document is
/// capped at [`DID_WEB_MAX_DOCUMENT_BYTES`]; the append-only log is deliberately
/// wider (×32, matching `DidWebvhResolver::ingest_log`'s own ceiling).
const DID_WEBVH_MAX_LOG_BYTES: usize = DID_WEB_MAX_DOCUMENT_BYTES * 32;

/// P3.2c: SSRF host guard for an about-to-be-fetched `did:web` / `did:webvh`
/// URL. Returns `false` (caller fails closed, does **not** fetch) when the
/// URL's host is unsafe to reach from a client:
///
/// - a **literal IP** in non-public space: IPv4 loopback `127.0.0.0/8`,
///   unspecified `0.0.0.0`, private `10/8` + `172.16/12` + `192.168/16`,
///   link-local `169.254/16` (incl. the `169.254.169.254` cloud-metadata
///   endpoint), CGNAT `100.64/10`; IPv6 `::1`, unique-local `fc00::/7`,
///   link-local `fe80::/10`, and any IPv4-mapped form of the above. The IP
///   classification is delegated to the SDK's [`host_is_safe_for_outbound`]
///   (the shared STA-05-001 egress blocklist) so yougen and the SDK never
///   drift on which ranges count as private.
/// - bare `localhost` / `*.localhost` (handled by the SDK helper) and any
///   host ending in `.local` (mDNS — added here on top of the SDK helper).
///
/// Only `https` is accepted; the SDK URL builders only ever emit `https://`,
/// so a non-https scheme here means a malformed/forged URL and is rejected.
///
/// ## Boundary: registered domain names are NOT DNS-resolved.
///
/// This is a *static* host check. A registered domain (e.g. `evil.example`
/// whose A record points at `127.0.0.1`) passes this guard — the client has no
/// DNS in the wasm browser-fetch backend, and resolving here would both be
/// platform-specific and open a DNS-rebinding gap (the name could resolve to a
/// public IP at check time and a private one at fetch time). Blocking literal
/// IPs + `localhost`/`.local` covers the dominant client-side SSRF surface
/// (an attacker putting a raw private IP / metadata address straight into the
/// actor DID). `std::net` parsing used by the SDK helper is pure (no syscalls)
/// and therefore works on `wasm32-unknown-unknown` as well.
fn url_host_is_safe(url: &str) -> bool {
    let Ok(parsed) = url::Url::parse(url) else {
        return false;
    };
    if parsed.scheme() != "https" {
        return false;
    }
    let Some(host) = parsed.host_str() else {
        return false;
    };
    // mDNS `.local` is not covered by the SDK's localhost-only name check.
    if host.to_ascii_lowercase().ends_with(".local") {
        return false;
    }
    host_is_safe_for_outbound(host)
}

/// Fetch `url` over `http` with an enforced response-size ceiling and a JSON
/// content-type check. Cross-platform: `bytes()` works on both the native and
/// the wasm browser-fetch reqwest backends (the wasm backend does not expose
/// incremental `chunk()` streaming, so we read once and bound by length).
///
/// DID resolution is triggered by untrusted input (verifying a stranger's
/// signature), so a hostile host must not force an unbounded allocation: the
/// declared `Content-Length` (when present) is rejected above the ceiling
/// before the body is read, and the materialized body is re-checked. Returns
/// `(content_type, body)` or `None` (fail-closed) on any transport / status /
/// size / content-type failure.
async fn fetch_did_bytes(
    http: &reqwest::Client,
    url: &str,
    max_bytes: usize,
) -> Option<(String, Vec<u8>)> {
    // P3.2c SSRF egress guard — fail-closed *before* any outbound request.
    // The `did:web` host is taken verbatim from an untrusted actor DID, so a
    // hostile `did:web:127.0.0.1` / `did:web:169.254.169.254` (cloud metadata)
    // / `did:web:localhost` must never let the client reach into loopback,
    // private, link-local or carrier-NAT address space. We re-derive the host
    // from the constructed URL and reject it here, independently of the SDK
    // `document_url` helper (defence in depth — even though that helper already
    // applies the same check, this module must not rely on that internal
    // behaviour for its own security property).
    if !url_host_is_safe(url) {
        return None;
    }
    let response = http.get(url).send().await.ok()?;
    if !response.status().is_success() {
        return None;
    }
    let content_type = response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("application/json")
        .to_owned();
    // Best-effort pre-check: the wasm browser-fetch backend often omits
    // Content-Length, so this is an early-out, not the sole guard.
    if response
        .content_length()
        .is_some_and(|len| len > max_bytes as u64)
    {
        return None;
    }
    let body = response.bytes().await.ok()?;
    if body.len() > max_bytes {
        return None;
    }
    Some((content_type, body.to_vec()))
}

/// Build the `did:web` document URL (HTTPS, via the SDK helper) and fetch it.
/// The URL helper only ever yields `https://…/did.json`, so plaintext hosts are
/// rejected by construction; the SDK `insert_from_https_response` re-validates
/// the URL, content-type and document `id`.
async fn fetch_did_web_document(http: &reqwest::Client, did: &Did) -> Option<DidWebDocumentOutcome> {
    let url = DidWebResolver::document_url(did).ok()?;
    let (content_type, body) = fetch_did_bytes(http, &url, DID_WEB_MAX_DOCUMENT_BYTES).await?;
    Some(DidWebDocumentOutcome {
        url,
        content_type,
        body,
    })
}

/// Build the `did:webvh` document + log URLs (HTTPS, via the SDK helpers) and
/// fetch both. The log is bounded by the wider [`DID_WEBVH_MAX_LOG_BYTES`]
/// ceiling. SCID + hash-chain + proof validation runs inside the SDK
/// `ingest_log`, not here.
async fn fetch_did_webvh_document(
    http: &reqwest::Client,
    did: &Did,
) -> Option<(DidWebvhDocumentOutcome, DidWebvhLogOutcome)> {
    let doc_url = DidWebvhResolver::document_url(did).ok()?;
    let log_url = DidWebvhResolver::log_url(did).ok()?;
    let (doc_ct, doc_body) = fetch_did_bytes(http, &doc_url, DID_WEB_MAX_DOCUMENT_BYTES).await?;
    let (log_ct, log_body) = fetch_did_bytes(http, &log_url, DID_WEBVH_MAX_LOG_BYTES).await?;
    Some((
        DidWebvhDocumentOutcome {
            url: doc_url,
            content_type: doc_ct,
            body: doc_body,
        },
        DidWebvhLogOutcome {
            url: log_url,
            content_type: log_ct,
            body: log_body,
        },
    ))
}

/// Y1:以缓存为先的 authority 解析辅助。
///
/// 这是 authority 调用点(`verify_principal` 之前)应当走的入口:
/// 1. 先查 `cache`:命中且 [`Freshness::Fresh`] —— 直接返回缓存文档, 跳过 resolver
///    链(省掉重复网络/链上解析)。
/// 2. miss 或 `Stale` —— 调 [`verify_principal`] 走完整 resolver 链 (内含 policy 校验 + 文档 id
///    比对),成功后按 policy 的 `ttl` 回填 `cache` 再返回。
///
/// 注意边界:
/// - 缓存命中**不重做** policy 校验。这是有意为之 —— 能进缓存的条目 必然是此前 `verify_principal`
///   成功(policy 已通过 + id 已比对) 的产物;`invalidate` / `clear`(Y2 失效钩子)负责在密钥轮换 /
///   撤销时把陈旧条目清掉,使下一次解析重新走链。
/// - policy 未配置 `ttl` 时退化为一个保守的 15 分钟默认,与 `policy_for`
///   的取值一致,避免把无限期文档塞进缓存。
///
/// TRUST-AUTHORITY:本函数仍是 authority 面 —— 缓存只是省去重复解析,
/// 不改变 "server 断言的 binding_state 仅作提示" 这一原则。展示面的
/// `cached` / `stale` 降级在 `components::verify_badges` /
/// `views::contacts`(TRUST-CACHE)单独处理,不复用此路径。
pub fn resolve_with_cache(
    resolver: &CompositeDidResolver,
    cache: &mut DidResolutionCache,
    principal: &Did,
    now: DateTime<Utc>,
) -> Result<DidDocument, VerifyError> {
    // 1) 缓存命中且未过期 —— 直接复用。`get` 会顺带惰性淘汰过期项。
    if let Some(doc) = cache.get(principal, now) {
        return Ok(doc);
    }
    // 2) miss / 过期 —— 走完整 resolver 链(policy 校验 + id 比对)。
    let doc = verify_principal(resolver, principal)?;
    // 3) 回填缓存,TTL 取 policy 配置,缺省回落到 15 分钟。
    let ttl = resolver
        .policy()
        .ttl
        .unwrap_or_else(|| Duration::minutes(15));
    cache.insert(principal.clone(), doc.clone(), now, ttl);
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

/// Y1:缓存条目相对某个 `now` 的新鲜度。
///
/// 本仓库内自定义,**刻意不引入任何 SDK 新符号**(SDK 正被并发修改)。
/// 仅区分两态:
/// - `Fresh`:`now < expires_at`,缓存命中可直接复用。
/// - `Stale`:`now >= expires_at`,已过期 —— 展示层据此降级到 `stale` 标记,authority
///   解析路径据此放弃缓存改走 resolver 链。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Freshness {
    Fresh,
    Stale,
}

impl CachedDidEntry {
    /// 返回该条目在 `now` 时刻的新鲜度。过期点(`expires_at`)本身视为已过期,
    /// 与 [`DidResolutionCache::get`] 的 `expires_at > now` 判定保持一致。
    pub fn freshness(&self, now: DateTime<Utc>) -> Freshness {
        if self.expires_at > now {
            Freshness::Fresh
        } else {
            Freshness::Stale
        }
    }
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

    /// Y3:只读探查缓存条目,**不触发任何过期淘汰**。展示层(verify_badges /
    /// contacts)用它来读取 `binding_state` 与 [`Freshness`],从而渲染
    /// `cached` / `stale` / `degraded` 标记。与 `get` 不同:`get` 是
    /// authority 解析路径用的、会惰性淘汰过期项的可变借用;`peek` 是
    /// 纯 UX 面、对过期项也照常返回(返回值里带 `Freshness::Stale`),
    /// 这样 UI 才能区分 "miss" 与 "stale"。
    pub fn peek<'a>(&'a self, did: &Did) -> Option<&'a CachedDidEntry> {
        self.entries.get(did.as_str())
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

    // ── Y1 freshness / resolve_with_cache ────────────────────────────

    #[test]
    fn freshness_reports_fresh_before_expiry_and_stale_after() {
        let (_did, doc) = sample_document("did:web:alice.example");
        let t0 = Utc::now();
        let entry = CachedDidEntry {
            document: doc,
            cached_at: t0,
            expires_at: t0 + Duration::seconds(60),
        };
        assert_eq!(
            entry.freshness(t0 + Duration::seconds(30)),
            Freshness::Fresh
        );
        // 过期点本身即视为 Stale,与 get 的 `expires_at > now` 判定一致。
        assert_eq!(
            entry.freshness(t0 + Duration::seconds(60)),
            Freshness::Stale
        );
        assert_eq!(
            entry.freshness(t0 + Duration::seconds(61)),
            Freshness::Stale
        );
    }

    #[test]
    fn resolve_with_cache_returns_fresh_cached_document_without_resolver() {
        // 预填一条新鲜缓存:resolve_with_cache 应直接命中,不去碰 resolver
        // (resolver 没有任何证据,若真去解析必然 Unresolved)。
        let resolver = build_default_resolver(DeploymentProfile::PersonalNode);
        let mut cache = DidResolutionCache::new(8);
        let (did, doc) = sample_document("did:web:alice.example");
        let t0 = Utc::now();
        cache.insert(did.clone(), doc, t0, Duration::seconds(600));

        let out = resolve_with_cache(&resolver, &mut cache, &did, t0 + Duration::seconds(1))
            .expect("fresh cache hit must succeed without touching resolver");
        assert_eq!(out.id.as_str(), did.as_str());
    }

    #[test]
    fn resolve_with_cache_miss_falls_through_to_resolver_and_fails_closed() {
        // 缓存为空 + resolver 无证据 -> 走链解析 -> Unresolved(fail-closed)。
        let resolver = build_default_resolver(DeploymentProfile::PersonalNode);
        let mut cache = DidResolutionCache::new(8);
        let did = parse("did:web:alice.example");
        let t0 = Utc::now();
        match resolve_with_cache(&resolver, &mut cache, &did, t0) {
            Err(VerifyError::Unresolved(_)) => {}
            other => panic!("expected Unresolved on cache miss, got {other:?}"),
        }
        // 解析失败不应回填缓存。
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn resolve_with_cache_treats_expired_entry_as_miss() {
        // 过期条目应被当作 miss:get 惰性淘汰后走 resolver(无证据 -> Unresolved)。
        let resolver = build_default_resolver(DeploymentProfile::PersonalNode);
        let mut cache = DidResolutionCache::new(8);
        let (did, doc) = sample_document("did:web:alice.example");
        let t0 = Utc::now();
        cache.insert(did.clone(), doc, t0, Duration::seconds(60));
        match resolve_with_cache(&resolver, &mut cache, &did, t0 + Duration::seconds(61)) {
            Err(VerifyError::Unresolved(_)) => {}
            other => panic!("expected Unresolved after expiry, got {other:?}"),
        }
        assert_eq!(cache.len(), 0, "expired entry should be evicted on miss");
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

    // ── P3.2b: anchor fetch + ingest of did:web documents ────────────────────

    use crate::device_directory::DidAnchor as _;
    use cokret_sdk::identity::DidWebDocumentOutcome;

    /// Serialize a `DidDocument` into the exact `did.json` body shape the SDK
    /// `insert_from_https_response` validates (the round-trip the helper's own
    /// tests use).
    fn web_outcome(did: &Did, document: &DidDocument, content_type: &str) -> DidWebDocumentOutcome {
        DidWebDocumentOutcome {
            url: DidWebResolver::document_url(did).unwrap(),
            content_type: content_type.to_owned(),
            body: serde_json::to_vec(document).unwrap(),
        }
    }

    #[test]
    fn anchor_resolves_did_web_after_ingest() {
        // Before ingest the anchor has no evidence → fail-closed (None). After a
        // well-formed did.json is ingested (the offline half of the live
        // fetch+ingest path) the SAME anchor resolves the document — proving
        // Tier-2 anchoring is now reachable for did:web actors.
        let anchor = ResolverDidAnchor::from_profile(
            DeploymentProfile::PersonalNode,
            DidResolutionCache::new(8),
        );
        let did = parse("did:web:tier2-anchor.example");
        assert!(anchor.resolve_did_document(&did).is_none());

        let document = DidDocument::new(did.clone(), "owner", "z6Mkanchorkey");
        assert!(anchor.ingest_web_for_test(&did, web_outcome(&did, &document, "application/did+json")));

        let resolved = anchor
            .resolve_did_document(&did)
            .expect("ingested did:web document must resolve");
        assert_eq!(resolved.id.as_str(), did.as_str());
        assert_eq!(resolved.verification_methods["owner"], "z6Mkanchorkey");
    }

    #[test]
    fn anchor_rejects_bad_content_type_fail_closed() {
        // A non-JSON content type is rejected by the SDK helper → ingest fails →
        // the actor stays unresolvable (fail-closed), exactly as a hostile host
        // serving the wrong media type would land.
        let anchor = ResolverDidAnchor::from_profile(
            DeploymentProfile::PersonalNode,
            DidResolutionCache::new(8),
        );
        let did = parse("did:web:hostile.example");
        let document = DidDocument::new(did.clone(), "owner", "z6Mkhostilekey");
        assert!(!anchor.ingest_web_for_test(&did, web_outcome(&did, &document, "text/html")));
        assert!(anchor.resolve_did_document(&did).is_none());
    }

    #[test]
    fn anchor_rejects_id_mismatch_fail_closed() {
        // A document whose `id` is a DIFFERENT did:web than requested is
        // rejected by the SDK helper (id mismatch) → fail-closed.
        let anchor = ResolverDidAnchor::from_profile(
            DeploymentProfile::PersonalNode,
            DidResolutionCache::new(8),
        );
        let requested = parse("did:web:victim.example");
        let other = parse("did:web:attacker.example");
        let spoofed = DidDocument::new(other, "owner", "z6Mkspoofkey");
        assert!(!anchor.ingest_web_for_test(
            &requested,
            web_outcome(&requested, &spoofed, "application/json")
        ));
        assert!(anchor.resolve_did_document(&requested).is_none());
    }

    #[tokio::test]
    async fn ensure_actor_document_skips_fetch_for_did_key() {
        // did:key self-resolves; ensure returns true without any network. We
        // pass a default client that is never actually used for did:key.
        let anchor = ResolverDidAnchor::from_profile(
            DeploymentProfile::PersonalNode,
            DidResolutionCache::new(8),
        );
        let did = parse("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK");
        let http = reqwest::Client::new();
        assert!(anchor.ensure_actor_document(&http, &did).await);
        // And the did:key document resolves through the composite chain.
        assert!(anchor.resolve_did_document(&did).is_some());
    }

    #[tokio::test]
    async fn ensure_actor_document_rejects_disallowed_method() {
        // An Organization profile forbids plain did:web as principal; ensure is
        // a no-op false and the actor never anchors.
        let anchor = ResolverDidAnchor::from_profile(
            DeploymentProfile::Organization,
            DidResolutionCache::new(8),
        );
        let did = parse("did:web:not-allowed.example");
        let http = reqwest::Client::new();
        assert!(!anchor.ensure_actor_document(&http, &did).await);
    }

    // ── P3.2c: SSRF host guard ───────────────────────────────────────────────

    #[test]
    fn url_host_guard_rejects_literal_private_and_metadata_ips() {
        // Every range an SSRF egress guard must block. Built as the exact
        // https URL shape the did:web / did:webvh fetch path constructs.
        let blocked = [
            // IPv4 loopback / unspecified.
            "https://127.0.0.1/.well-known/did.json",
            "https://127.13.37.42/.well-known/did.json",
            "https://0.0.0.0/.well-known/did.json",
            // RFC1918 private.
            "https://10.0.0.5/.well-known/did.json",
            "https://172.16.9.9/.well-known/did.json",
            "https://192.168.1.1/.well-known/did.json",
            // Link-local incl. cloud metadata.
            "https://169.254.1.1/.well-known/did.json",
            "https://169.254.169.254/.well-known/did.json",
            // CGNAT 100.64/10.
            "https://100.64.0.1/.well-known/did.json",
            "https://100.127.255.254/.well-known/did.json",
            // IPv6 loopback / ULA / link-local (bracketed authority).
            "https://[::1]/.well-known/did.json",
            "https://[fc00::1]/.well-known/did.json",
            "https://[fd12:3456::1]/.well-known/did.json",
            "https://[fe80::1]/.well-known/did.json",
            // IPv4-mapped IPv6 of a private address.
            "https://[::ffff:10.0.0.1]/.well-known/did.json",
            "https://[::ffff:169.254.169.254]/.well-known/did.json",
        ];
        for url in blocked {
            assert!(!url_host_is_safe(url), "must reject {url}");
        }
    }

    #[test]
    fn url_host_guard_rejects_localhost_and_dot_local() {
        assert!(!url_host_is_safe("https://localhost/.well-known/did.json"));
        assert!(!url_host_is_safe(
            "https://api.localhost/.well-known/did.json"
        ));
        // mDNS .local (added on top of the SDK's localhost-only name check).
        assert!(!url_host_is_safe("https://printer.local/.well-known/did.json"));
        assert!(!url_host_is_safe("https://HOST.LOCAL/.well-known/did.json"));
    }

    #[test]
    fn url_host_guard_rejects_non_https_scheme() {
        // The SDK URL builders only ever emit https; a non-https URL is forged.
        assert!(!url_host_is_safe("http://alice.example/.well-known/did.json"));
        assert!(!url_host_is_safe(
            "file:///etc/passwd/.well-known/did.json"
        ));
    }

    #[test]
    fn url_host_guard_allows_public_registered_domains() {
        // A normal public host passes — the guard only blocks literal private
        // IPs + localhost/.local (DNS resolution of domains is out of scope).
        assert!(url_host_is_safe(
            "https://alice.example/.well-known/did.json"
        ));
        assert!(url_host_is_safe(
            "https://did.acroidea.com/path/did.json"
        ));
    }

    #[tokio::test]
    async fn ensure_actor_document_fail_closed_for_metadata_ip() {
        // did:web:169.254.169.254 (cloud-metadata) parses as a valid DID and is
        // allowed by the PersonalNode policy, but the SSRF guard must keep the
        // fetch from ever reaching that address → ensure returns false and the
        // actor never anchors. The host carries a dot so it survives the SDK's
        // bare-IP-without-dot rejection and genuinely exercises the IP guard.
        let anchor = ResolverDidAnchor::from_profile(
            DeploymentProfile::PersonalNode,
            DidResolutionCache::new(8),
        );
        let did = parse("did:web:169.254.169.254");
        let http = reqwest::Client::new();
        assert!(!anchor.ensure_actor_document(&http, &did).await);
        assert!(anchor.resolve_did_document(&did).is_none());
    }

    #[tokio::test]
    async fn ensure_actor_document_peeks_and_skips_fetch_when_already_ingested() {
        // Seed the offline did:web resolver with a valid document (the offline
        // half of a prior fetch). A second ensure must short-circuit on the
        // peek and return true WITHOUT any network — proven by handing it a
        // client pointed at a guaranteed-dead address that would error if used.
        let anchor = ResolverDidAnchor::from_profile(
            DeploymentProfile::PersonalNode,
            DidResolutionCache::new(8),
        );
        let did = parse("did:web:already-ingested.example");
        let document = DidDocument::new(did.clone(), "owner", "z6Mkpeekkey");
        assert!(anchor.ingest_web_for_test(
            &did,
            web_outcome(&did, &document, "application/did+json")
        ));

        // A client whose only proxy is an unroutable address: if ensure tried
        // to fetch, the request would fail and ensure would return false.
        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_millis(1))
            .build()
            .unwrap();
        assert!(
            anchor.ensure_actor_document(&http, &did).await,
            "already-ingested actor must skip the fetch via peek"
        );
        assert!(anchor.resolve_did_document(&did).is_some());
    }
}
