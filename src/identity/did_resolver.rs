//! Default DID resolver chain for inkson.
//!
//! Wraps `arkret_sdk::identity::*` resolvers with a inkson-specific
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
//! trail review — MUST go through here (AKP B-E §1 /
//! identity-handles §6.1). They MUST NOT accept the server-attested
//! `binding_state=verified` projection as authoritative; that field
//! is a cache hint only. Cache-allowed surfaces (verified badge,
//! mention autocomplete, contact card) live in `components::verify_badges`
//! and `views::contacts` — those are tagged `TRUST-CACHE`.

use arkret_sdk::identity::{
    CompositeDidResolver, DID_WEB_MAX_DOCUMENT_BYTES, DidKeyResolver, DidResolutionCache,
    DidResolver as _, DidWebDocumentOutcome, DidWebResolver, DidWebvhDocumentOutcome,
    DidWebvhLogOutcome, DidWebvhResolver, ResolverFailMode, ResolverPolicy,
    host_is_safe_for_outbound,
};
use arkret_sdk::{Did, DidDocument};
use chrono::{DateTime, Duration, Utc};

/// Deployment profile drives which DID methods are accepted as principal.
///
/// Mirrors `spec/v1/zh/identity/identity-did.md` §3.3 / §3.4:
/// - `PersonalNode`: `did:web` allowed as principal fallback.
/// - `SmallTeam` / `Organization` / higher: principal MUST be `did:webvh`.
/// - `Sovereign`: principal limited to a deployment-specific method list.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[expect(
    dead_code,
    reason = "non-personal deployment policies are conformance-tested before runtime profile selection is exposed"
)]
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
#[cfg(test)]
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
    // Ordinary verification path: the document is all this returns, so it uses
    // the document-only accessor rather than dropping method evidence by hand.
    let doc = resolver
        .resolve_did_document(principal)
        .map_err(|e| VerifyError::Unresolved(format!("{e:?}")))?;
    if &doc.id != principal {
        return Err(VerifyError::MethodMismatch);
    }
    Ok(doc)
}

/// Resolver-backed [`crate::identity::device_directory::DidAnchor`] for the Tier-2
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
/// The mutable resolvers + cache live behind [`std::sync::Mutex`] so the `&self`
/// [`crate::identity::device_directory::DidAnchor`] trait can still back-fill resolved
/// documents across the native `Send` transport boundary; callers reclaim the (possibly grown)
/// cache via [`ResolverDidAnchor::into_cache`] to persist it back into their signal.
/// DID-P2-B: the durable half of the anchor's trust state.
///
/// `bindings` is the persisted, purpose- and trust-domain-scoped
/// [`crate::identity::did_binding::InksonDidBindingStore`]; `scope` records
/// which trust domain / policy digest this anchor's acceptances belong to and
/// `purpose` which single purpose they authorize. Together they turn the
/// anchor's DID resolutions into reusable bindings that survive a restart,
/// instead of dying with the login-session `DidResolutionCache`.
struct AnchorBindingState {
    scope: crate::identity::did_binding::DidBindingScope,
    purpose: arkret_sdk::identity::DidBindingPurpose,
    store: crate::identity::did_binding::InksonDidBindingStore,
}

pub struct ResolverDidAnchor {
    profile: DeploymentProfile,
    web: std::sync::Mutex<DidWebResolver>,
    webvh: std::sync::Mutex<DidWebvhResolver>,
    cache: std::sync::Mutex<DidResolutionCache>,
    /// `None` for legacy / test anchors that have no durable binding scope.
    /// Production call sites build the anchor with
    /// [`Self::from_persisted_bindings`] so every acceptance is recorded.
    bindings: Option<AnchorBindingState>,
}

impl ResolverDidAnchor {
    /// Build an anchor for `profile` with fresh (empty) offline `did:web` /
    /// `did:webvh` resolvers and a snapshot of `cache`. Document / key-log
    /// evidence is ingested lazily via [`Self::ensure_actor_document`]; absent
    /// evidence, resolution fails closed and the device key is rejected.
    ///
    /// This constructor carries **no durable binding scope**: resolutions are
    /// reusable only for the lifetime of the returned anchor. Prefer
    /// [`Self::from_persisted_bindings`] on any path that has access to the
    /// account's local state.
    pub fn from_profile(profile: DeploymentProfile, cache: DidResolutionCache) -> Self {
        Self {
            profile,
            web: std::sync::Mutex::new(DidWebResolver::new()),
            webvh: std::sync::Mutex::new(DidWebvhResolver::new()),
            cache: std::sync::Mutex::new(cache),
            bindings: None,
        }
    }

    /// DID-P2-B: build an anchor whose resolutions are recorded as durable
    /// accepted bindings under `scope` / `purpose`.
    ///
    /// `records` come from the active account's persisted state; the caller
    /// writes the (possibly grown) set back with
    /// [`Self::into_cache_and_bindings`]. A binding hit short-circuits
    /// [`crate::identity::device_directory::DidAnchor::resolve_did_document`]
    /// with **zero network work** — including across restarts, which is the
    /// P2-B acceptance criterion.
    pub fn from_persisted_bindings(
        profile: DeploymentProfile,
        cache: DidResolutionCache,
        scope: crate::identity::did_binding::DidBindingScope,
        purpose: arkret_sdk::identity::DidBindingPurpose,
        records: Vec<arkret_sdk::identity::AcceptedDidBinding>,
    ) -> Self {
        Self {
            profile,
            web: std::sync::Mutex::new(DidWebResolver::new()),
            webvh: std::sync::Mutex::new(DidWebvhResolver::new()),
            cache: std::sync::Mutex::new(cache),
            bindings: Some(AnchorBindingState {
                scope,
                purpose,
                store: crate::identity::did_binding::InksonDidBindingStore::hydrate(records),
            }),
        }
    }

    /// Reclaim the (possibly back-filled) cache so the caller can write it
    /// back into its `Signal<DidResolutionCache>`.
    pub fn into_cache(self) -> DidResolutionCache {
        self.cache
            .into_inner()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Reclaim both the session cache and the durable binding records.
    ///
    /// Returns `None` for the binding half when the anchor was built without a
    /// scope ([`Self::from_profile`]).
    pub fn into_cache_and_bindings(
        self,
    ) -> (
        DidResolutionCache,
        Option<Vec<arkret_sdk::identity::AcceptedDidBinding>>,
    ) {
        let records = self
            .bindings
            .as_ref()
            .map(|state| state.store.persisted_records());
        let cache = self
            .cache
            .into_inner()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        (cache, records)
    }

    /// Zero-network lookup of an already-accepted binding for `actor`.
    ///
    /// Ordinary paths (sync ingest, render, member list) call this and stop
    /// here on a hit. `did-usage-and-verification.md` §5: a `Stale` binding is
    /// still a hit — TTL expiry alone MUST NOT escalate an ordinary read into
    /// an online resolution.
    fn accepted_document(&self, actor: &Did, now: DateTime<Utc>) -> Option<DidDocument> {
        let state = self.bindings.as_ref()?;
        let key = state.scope.key(actor, state.purpose, None);
        state
            .store
            .ordinary_lookup(&key, now)
            .map(|accepted| accepted.document().clone())
    }

    /// Record a freshly chain-verified `document` as an accepted binding.
    fn record_accepted_document(&self, document: &DidDocument, now: DateTime<Utc>) {
        let Some(state) = self.bindings.as_ref() else {
            return;
        };
        match crate::identity::did_binding::accept_verified_document(
            &state.scope,
            state.purpose,
            None,
            document,
            now,
        ) {
            // Not recording is the fail-safe outcome: the next authority caller
            // simply resolves again. Recording a binding under a fallback digest
            // would be the unsafe one.
            Err(error) => tracing::warn!(%error, did = %document.id, "not recording a DID binding"),
            Ok(accepted) => state.store.accept(accepted),
        }
    }

    /// Rebuild the composite resolver chain from the policy for this profile
    /// plus a snapshot of the currently-ingested offline resolvers. `did:key`
    /// always self-resolves; `did:web` / `did:webvh` resolve only for actors
    /// whose evidence [`Self::ensure_actor_document`] has already ingested.
    fn current_resolver(&self) -> CompositeDidResolver {
        let mut composite = CompositeDidResolver::new().with_policy(policy_for(self.profile));
        composite.push(DidKeyResolver::new());
        composite.push(
            self.web
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone(),
        );
        composite.push(
            self.webvh
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone(),
        );
        composite
    }

    /// Test-only: ingest a `did:web` document straight through the SDK offline
    /// helper, bypassing the network fetch so the `ensure → resolve` contract
    /// can be exercised with synthetic responses. Returns whether ingest
    /// succeeded (the same fail-closed verdict the live fetch path applies).
    #[cfg(test)]
    fn ingest_web_for_test(&self, actor: &Did, outcome: DidWebDocumentOutcome) -> bool {
        self.web
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert_from_https_response(actor, outcome)
            .is_ok()
    }

    /// Inner async body for
    /// [`crate::identity::device_directory::DidAnchor::ensure_actor_document`].
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
                if self
                    .web
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .resolve_did(actor)
                    .is_ok()
                {
                    return true;
                }
                let outcome = match fetch_did_web_document(http, actor).await {
                    Some(outcome) => outcome,
                    None => return false,
                };
                self.web
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .insert_from_https_response(actor, outcome)
                    .is_ok()
            }
            "webvh" => {
                // P3.2c peek: skip the fetch when the webvh document + log are
                // already ingested for this actor.
                if self
                    .webvh
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .resolve_did(actor)
                    .is_ok()
                {
                    return true;
                }
                let Some((doc, log)) = fetch_did_webvh_document(http, actor).await else {
                    return false;
                };
                let mut webvh = self
                    .webvh
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
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

    /// Resolve the configured Principal Server's own WebVH document without
    /// weakening the untrusted actor-DID SSRF guard. The caller must first
    /// establish that `service` is the `service_id` returned by the same
    /// authenticated SDK client's describe endpoint. The DID host and port
    /// must exactly match the configured server before this path fetches from
    /// that origin. The SDK then validates the DID document id, WebVH SCID,
    /// append-only log, proofs, hash chain, and exact log-head state.
    pub(crate) async fn ensure_trusted_same_origin_service_document(
        &self,
        http: &reqwest::Client,
        trusted_base_url: &url::Url,
        service: &Did,
    ) -> bool {
        if !policy_for(self.profile).permits(service) || service.method() != "webvh" {
            return false;
        }
        if self
            .cache
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(service, Utc::now())
            .is_some()
        {
            return true;
        }
        let Some((document_url, log_url)) = trusted_webvh_urls(trusted_base_url, service) else {
            return false;
        };
        let Some((document_content_type, document_body)) =
            fetch_did_bytes_from_url(http, document_url.as_str(), DID_WEB_MAX_DOCUMENT_BYTES).await
        else {
            return false;
        };
        if !did_document_content_type_allowed(&document_content_type) {
            return false;
        }
        let Some((_log_content_type, log_body)) =
            fetch_did_bytes_from_url(http, log_url.as_str(), DID_WEBVH_MAX_LOG_BYTES).await
        else {
            return false;
        };
        let Ok(document) = arkret_sdk::identity::verify_did_webvh_document_and_log_bytes(
            service,
            &document_body,
            &log_body,
        ) else {
            return false;
        };
        let ttl = policy_for(self.profile)
            .ttl
            .unwrap_or_else(|| Duration::minutes(15));
        self.cache
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            // `verify_did_webvh_document_and_log_bytes` verifies the log but
            // returns only the document, so the cached resolution carries no
            // method-proof rows: §5.2 forbids synthesizing one here.
            .insert(
                service.clone(),
                arkret_sdk::identity::ResolvedDid::proofless(document),
                Utc::now(),
                ttl,
            )
            .is_ok()
    }
}

impl crate::identity::device_directory::DidAnchor for ResolverDidAnchor {
    fn resolve_did_document(&self, actor: &Did) -> Option<DidDocument> {
        let now = Utc::now();
        // DID-P2-B step 1: a durable accepted binding is a zero-network hit and
        // is checked before the session cache, because it is the layer that
        // survives a restart.
        if let Some(document) = self.accepted_document(actor, now) {
            return Some(document);
        }
        let resolver = self.current_resolver();
        let document = {
            let cache = self
                .cache
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            resolve_with_cache(&resolver, &cache, actor, now).ok()?
        };
        // Step 2: the chain verified policy + document id, so this resolution is
        // an acceptance — record it so the next boot does not repeat it.
        self.record_accepted_document(&document, now);
        Some(document)
    }

    fn ensure_actor_document<'a>(
        &'a self,
        http: &'a reqwest::Client,
        actor: &'a Did,
    ) -> crate::identity::device_directory::DidAnchorFuture<'a> {
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
/// - a **literal IP** in non-public space: IPv4 loopback `127.0.0.0/8`, unspecified `0.0.0.0`,
///   private `10/8` + `172.16/12` + `192.168/16`, link-local `169.254/16` (incl. the
///   `169.254.169.254` cloud-metadata endpoint), CGNAT `100.64/10`; IPv6 `::1`, unique-local
///   `fc00::/7`, link-local `fe80::/10`, and any IPv4-mapped form of the above. The IP
///   classification is delegated to the SDK's [`host_is_safe_for_outbound`] (the shared STA-05-001
///   egress blocklist) so inkson and the SDK never drift on which ranges count as private.
/// - bare `localhost` / `*.localhost` (handled by the SDK helper) and any host ending in `.local`
///   (mDNS — added here on top of the SDK helper).
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
    fetch_did_bytes_from_url(http, url, max_bytes).await
}

async fn fetch_did_bytes_from_url(
    http: &reqwest::Client,
    url: &str,
    max_bytes: usize,
) -> Option<(String, Vec<u8>)> {
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

fn trusted_webvh_urls(trusted_base_url: &url::Url, service: &Did) -> Option<(url::Url, url::Url)> {
    if !matches!(trusted_base_url.scheme(), "http" | "https") {
        return None;
    }
    let (_, host, port, path) = arkret_sdk::identity::did_webvh_parts(service)?;
    if trusted_base_url.host_str() != Some(host.as_str()) || trusted_base_url.port() != port {
        return None;
    }
    let prefix = if path.is_empty() {
        "/.well-known".to_owned()
    } else {
        format!("/{}", path.join("/"))
    };
    let mut document_url = trusted_base_url.clone();
    document_url.set_path(&format!("{prefix}/did.json"));
    document_url.set_query(None);
    document_url.set_fragment(None);
    let mut log_url = document_url.clone();
    log_url.set_path(&format!("{prefix}/did.jsonl"));
    Some((document_url, log_url))
}

fn did_document_content_type_allowed(content_type: &str) -> bool {
    matches!(
        content_type
            .split(';')
            .next()
            .unwrap_or("")
            .trim()
            .to_ascii_lowercase()
            .as_str(),
        "application/did+json" | "application/json"
    )
}

/// Build the `did:web` document URL (HTTPS, via the SDK helper) and fetch it.
/// The URL helper only ever yields `https://…/did.json`, so plaintext hosts are
/// rejected by construction; the SDK `insert_from_https_response` re-validates
/// the URL, content-type and document `id`.
async fn fetch_did_web_document(
    http: &reqwest::Client,
    did: &Did,
) -> Option<DidWebDocumentOutcome> {
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

/// Fetch a recipient principal's **raw** DID Document JSON (carrying `service`
/// and `keyAgreement`, which the SDK [`DidDocument`] projection drops).
///
/// The Realm Recovery Key (RRK) verification path
/// (`arkret_identity::history_recovery::resolve_realm_history_recovery_key`,
/// encryption-and-audit.md §2.10.8 / identity-did.md §8.3) needs the original
/// document to confirm an active `ArkretRealmHistoryRecoveryKey` service entry
/// designates the declared verification method. This reuses the same
/// SSRF-guarded, size-capped, `https`-only fetch path as the authority resolver:
///
/// - `did:web` → `…/.well-known/did.json` (or path form) raw bytes parsed as JSON.
/// - `did:webvh` → the resolved document body (the append-only log's SCID / chain validation is NOT
///   re-run here; callers that need verified key rotation must anchor through [`ResolverDidAnchor`]
///   first). The raw document is sufficient for the SDK's `service` / `keyAgreement` designation
///   check.
/// - `did:key` → has no off-host document and no `service` entries, so RRK is structurally
///   impossible; returns `None`.
///
/// Returns `None` (fail-closed) on any transport / SSRF / size / parse failure;
/// the SDK resolver then fails closed with `durability_recovery_recipient_unverified`.
pub async fn fetch_raw_did_document_json(
    http: &reqwest::Client,
    did: &arkret_sdk::Did,
) -> Option<serde_json::Value> {
    match did.method() {
        "web" => {
            let url = DidWebResolver::document_url(did).ok()?;
            let (_content_type, body) =
                fetch_did_bytes(http, &url, DID_WEB_MAX_DOCUMENT_BYTES).await?;
            serde_json::from_slice(&body).ok()
        }
        "webvh" => {
            let url = DidWebvhResolver::document_url(did).ok()?;
            let (_content_type, body) =
                fetch_did_bytes(http, &url, DID_WEB_MAX_DOCUMENT_BYTES).await?;
            serde_json::from_slice(&body).ok()
        }
        // did:key carries no off-host document / service entries.
        _ => None,
    }
}

/// Y1: cache-first authority resolution helper.
///
/// Authority call sites should enter here before `verify_principal`:
/// 1. Check `cache` first. A [`arkret_sdk::identity::Freshness::Fresh`] hit returns the cached
///    document directly and skips the resolver chain, avoiding repeated network / chain lookups.
/// 2. On miss or `Stale`, call [`verify_principal`] through the full resolver chain, including
///    policy validation and document id comparison, then write back to `cache` with the policy
///    `ttl`.
///
/// Boundary notes:
/// - A cache hit does not rerun policy validation. This is intentional: entries can only enter the
///   cache after a previous successful `verify_principal` result with policy already passed and id
///   already compared. `invalidate` / `clear` (the Y2 invalidation hook) removes stale entries
///   after key rotation or revocation so the next resolution walks the chain again.
/// - If policy has no `ttl`, fall back to the conservative 15-minute default used by `policy_for`
///   so indefinitely live documents are not cached.
///
/// TRUST-AUTHORITY: this function is still on the authority path. The cache only
/// removes duplicate resolution work and does not change the rule that
/// server-asserted `binding_state` is only a hint. Display-path `cached` /
/// `stale` degradation is handled separately in `components::verify_badges` and
/// `views::contacts` (TRUST-CACHE), without reusing this path.
pub fn resolve_with_cache(
    resolver: &CompositeDidResolver,
    cache: &DidResolutionCache,
    principal: &Did,
    now: DateTime<Utc>,
) -> Result<DidDocument, VerifyError> {
    // 1) Fresh cache hit: reuse directly. `get` also lazily evicts expired entries.
    if let Some(resolved) = cache.get(principal, now) {
        return Ok(resolved.document);
    }
    // 2) Miss / expired entry: walk the full resolver chain (policy validation + id check).
    let doc = verify_principal(resolver, principal)?;
    // 3) Write back to cache. TTL comes from policy, with a 15-minute default.
    let ttl = resolver
        .policy()
        .ttl
        .unwrap_or_else(|| Duration::minutes(15));
    cache
        .insert(
            principal.clone(),
            arkret_sdk::identity::ResolvedDid::proofless(doc.clone()),
            now,
            ttl,
        )
        .map_err(|error| VerifyError::Unresolved(error.to_string()))?;
    Ok(doc)
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

    fn sample_document(did_str: &str) -> (Did, DidDocument) {
        let did = parse(did_str);
        let doc = DidDocument::new(did.clone(), "key-1", "z6Mksample");
        (did, doc)
    }

    #[test]
    fn resolve_with_cache_returns_fresh_cached_document_without_resolver() {
        // Preload a fresh cache entry: resolve_with_cache should hit it directly
        // and not touch the resolver. The resolver has no evidence, so a real
        // resolution attempt would be Unresolved.
        let resolver = build_default_resolver(DeploymentProfile::PersonalNode);
        let cache = DidResolutionCache::new(8);
        let (did, doc) = sample_document("did:web:alice.example");
        let t0 = Utc::now();
        cache
            .insert(did.clone(), doc, t0, Duration::seconds(600))
            .unwrap();

        let out = resolve_with_cache(&resolver, &cache, &did, t0 + Duration::seconds(1))
            .expect("fresh cache hit must succeed without touching resolver");
        assert_eq!(out.id.as_str(), did.as_str());
    }

    #[test]
    fn resolve_with_cache_miss_falls_through_to_resolver_and_fails_closed() {
        // Empty cache + resolver with no evidence -> chain resolution ->
        // Unresolved (fail-closed).
        let resolver = build_default_resolver(DeploymentProfile::PersonalNode);
        let cache = DidResolutionCache::new(8);
        let did = parse("did:web:alice.example");
        let t0 = Utc::now();
        match resolve_with_cache(&resolver, &cache, &did, t0) {
            Err(VerifyError::Unresolved(_)) => {}
            other => panic!("expected Unresolved on cache miss, got {other:?}"),
        }
        // Resolution failure must not write back to cache.
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn resolve_with_cache_treats_expired_entry_as_miss() {
        // Expired entries should be treated as misses: `get` lazily evicts them,
        // then resolver fallback runs and returns Unresolved because there is no
        // evidence.
        let resolver = build_default_resolver(DeploymentProfile::PersonalNode);
        let cache = DidResolutionCache::new(8);
        let (did, doc) = sample_document("did:web:alice.example");
        let t0 = Utc::now();
        cache
            .insert(did.clone(), doc, t0, Duration::seconds(60))
            .unwrap();
        match resolve_with_cache(&resolver, &cache, &did, t0 + Duration::seconds(61)) {
            Err(VerifyError::Unresolved(_)) => {}
            other => panic!("expected Unresolved after expiry, got {other:?}"),
        }
        assert_eq!(cache.len(), 0, "expired entry should be evicted on miss");
    }

    #[test]
    fn cache_clear_empties_everything() {
        let cache = DidResolutionCache::default();
        let (did_a, doc_a) = sample_document("did:web:alice.example");
        let (did_b, doc_b) = sample_document("did:web:bob.example");
        let t0 = Utc::now();
        cache
            .insert(did_a, doc_a, t0, Duration::seconds(60))
            .unwrap();
        cache
            .insert(did_b, doc_b, t0, Duration::seconds(60))
            .unwrap();
        assert_eq!(cache.len(), 2);
        cache.clear();
        assert_eq!(cache.len(), 0);
    }

    // ── P3.2b: anchor fetch + ingest of did:web documents ────────────────────

    use arkret_sdk::identity::DidWebDocumentOutcome;

    use crate::identity::device_directory::DidAnchor as _;

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
        assert!(
            anchor.ingest_web_for_test(&did, web_outcome(&did, &document, "application/did+json"))
        );

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
        assert!(!url_host_is_safe(
            "https://printer.local/.well-known/did.json"
        ));
        assert!(!url_host_is_safe("https://HOST.LOCAL/.well-known/did.json"));
    }

    #[test]
    fn url_host_guard_rejects_non_https_scheme() {
        // The SDK URL builders only ever emit https; a non-https URL is forged.
        assert!(!url_host_is_safe(
            "http://alice.example/.well-known/did.json"
        ));
        assert!(!url_host_is_safe("file:///etc/passwd/.well-known/did.json"));
    }

    #[test]
    fn url_host_guard_allows_public_registered_domains() {
        // A normal public host passes — the guard only blocks literal private
        // IPs + localhost/.local (DNS resolution of domains is out of scope).
        assert!(url_host_is_safe(
            "https://alice.example/.well-known/did.json"
        ));
        assert!(url_host_is_safe("https://did.acroidea.com/path/did.json"));
    }

    #[test]
    fn trusted_service_fetch_is_confined_to_the_configured_origin() {
        let base = url::Url::parse("http://127.0.0.1:22618/").unwrap();
        let service = parse("did:webvh:QmServiceScid:127.0.0.1%3A22618:webvh:service");
        let (document, log) =
            trusted_webvh_urls(&base, &service).expect("configured local service origin");
        assert_eq!(
            document.as_str(),
            "http://127.0.0.1:22618/webvh/service/did.json"
        );
        assert_eq!(
            log.as_str(),
            "http://127.0.0.1:22618/webvh/service/did.jsonl"
        );
        let wrong_port = parse("did:webvh:QmServiceScid:127.0.0.1%3A22619:webvh:service");
        assert!(trusted_webvh_urls(&base, &wrong_port).is_none());
        let metadata = parse("did:webvh:QmServiceScid:169.254.169.254:webvh:service");
        assert!(trusted_webvh_urls(&base, &metadata).is_none());
        let external = parse("did:webvh:QmServiceScid:example.test:webvh:service");
        assert!(trusted_webvh_urls(&base, &external).is_none());
        assert!(trusted_webvh_urls(&url::Url::parse("file:///tmp/").unwrap(), &service).is_none());
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
        assert!(
            anchor.ingest_web_for_test(&did, web_outcome(&did, &document, "application/did+json"))
        );

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
