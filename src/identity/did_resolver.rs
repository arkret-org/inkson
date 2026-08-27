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
use arkret_sdk::{DidDocument, DidFullId};
use chrono::{DateTime, Duration, Utc};

/// Deployment profile drives resolver policy for long-lived principals.
///
/// Every deployment profile accepts only `did:webvh` for a durable principal.
/// `did:web` is service-only, while an ephemeral pairwise `did:key` actor is
/// verified against the exact accepted MLS LeafNode and never enters this
/// principal resolver.
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
        let _ = self;
        vec!["did:webvh:".into()]
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

/// Build a composite resolver chain with all method adapters and the strict
/// long-lived-principal policy. Documents must be ingested via the SDK
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
    principal: &DidFullId,
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

/// Resolver-backed [`crate::identity::device_directory::DidAnchor`] for the
/// Tier-2 device authorization chain (`device-lifecycle.md` §8.3): a client
/// MUST NOT treat a server-asserted `device_signing_key` as trust, it has to
/// replay the chain from the identity-root anchored PCR genesis. Anchoring the
/// actor's DID is the first step of that replay.
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
/// device authorization chain can only anchor once their `did.json` (and, for webvh,
/// `did.jsonl`) is ingested. [`ResolverDidAnchor::ensure_actor_document`] is the
/// async entry the receive path calls *before* the synchronous trait method: it
/// fetches the actor's DID document over the caller's existing
/// [`reqwest::Client`] (cross-platform — native + the wasm browser-fetch
/// backend) and ingests it into the mutable resolvers via the SDK's offline
/// helpers, fail-closed on any fetch / size / content-type / chain failure.
/// Ephemeral pairwise `did:key` actors never enter this resolver: their only
/// valid trust anchor is the exact accepted Realm MLS LeafNode.
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
    /// `None` for test anchors that have no durable binding scope.
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
    fn accepted_document(&self, actor: &DidFullId, now: DateTime<Utc>) -> Option<DidDocument> {
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
    fn ingest_web_for_test(&self, actor: &DidFullId, outcome: DidWebDocumentOutcome) -> bool {
        self.web
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert_from_https_response(actor, outcome)
            .is_ok()
    }

    /// Inner async body for
    /// [`crate::identity::device_directory::DidAnchor::ensure_actor_document`].
    /// Fetches + ingests `actor`'s DID document via the SDK offline helpers,
    /// fail-closed on any failure. A method not allowed by the active policy
    /// (including `did:key`) is a no-op `false` — the synchronous
    /// trait method then fails the policy gate too.
    async fn ingest_actor_document(&self, http: &reqwest::Client, actor: &DidFullId) -> bool {
        if !policy_for(self.profile).permits(actor) {
            return false;
        }
        match actor.method() {
            // Pairwise did:key is admitted only by exact accepted MLS leaf
            // verification, never as a long-lived principal.
            "key" => false,
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
        service: &DidFullId,
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
        let Some((document_content_type, document_body)) = fetch_did_bytes_from_url(
            http,
            document_url.as_str(),
            DID_WEB_MAX_DOCUMENT_BYTES,
            None,
        )
        .await
        else {
            return false;
        };
        if !did_document_content_type_allowed(&document_content_type) {
            return false;
        }
        let Some((_log_content_type, log_body)) =
            fetch_did_bytes_from_url(http, log_url.as_str(), DID_WEBVH_MAX_LOG_BYTES, None).await
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
    fn resolve_did_document(&self, actor: &DidFullId) -> Option<DidDocument> {
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
        actor: &'a DidFullId,
    ) -> crate::identity::device_directory::DidAnchorFuture<'a> {
        Box::pin(self.ingest_actor_document(http, actor))
    }
}

/// Maximum bytes accepted for a fetched `did.jsonl` log. Mirrors the SDK's
/// native `HttpDidResolver` template (`http_did_resolver.rs`): the document is
/// capped at [`DID_WEB_MAX_DOCUMENT_BYTES`]; the append-only log is deliberately
/// wider (×32, matching `DidWebvhResolver::ingest_log`'s own ceiling).
const DID_WEBVH_MAX_LOG_BYTES: usize = DID_WEB_MAX_DOCUMENT_BYTES * 32;

/// P3.2c: wasm half of the SSRF host guard for an about-to-be-fetched
/// `did:web` / `did:webvh` URL. Returns `false` (caller fails closed, does
/// **not** fetch) when the URL's host is unsafe to reach from a client:
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
/// ## Why wasm keeps a *static* guard while native pins DNS answers.
///
/// On `wasm32-unknown-unknown` the browser owns both DNS resolution and the
/// socket: there is no address to validate and nothing to pin into a client,
/// so this static judgment (scheme + host classification via the shared
/// blocklist) is the entire guard the platform allows. The native half is
/// stronger — see `locked_did_fetch_client`, which resolves the host, judges
/// every DNS answer and pins the validated set into the request client,
/// closing the DNS-rebinding window this static check cannot see (a registered
/// name whose A record points at `127.0.0.1` passes here and is rejected
/// there). `std::net` parsing used by the SDK helper is pure (no syscalls)
/// and therefore works on `wasm32-unknown-unknown` as well.
#[cfg_attr(
    not(target_arch = "wasm32"),
    allow(
        dead_code,
        reason = "the static judgment is the wasm request-layer guard; native uses locked_did_fetch_client instead, and host tests exercise this classifier directly"
    )
)]
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
/// P3.2c: native half of the DID-fetch SSRF guard. Judges the derived URL,
/// resolves the host, judges **every** DNS answer, and returns a client with
/// the validated addresses pinned into its connector, so a second lookup
/// between validation and connect cannot rebind the host (the gap the wasm
/// static check in [`url_host_is_safe`] structurally cannot close). Any
/// failure is fail-closed (`None`) before a socket is opened.
#[cfg(not(target_arch = "wasm32"))]
async fn locked_did_fetch_client(url: &str) -> Option<reqwest::Client> {
    let locked = arkret_egress_reqwest::EgressGuard::public_https()
        .lock_str_async(url, "did fetch")
        .await
        .ok()?;
    locked
        .apply_to_client_builder(
            reqwest::Client::builder().redirect(reqwest::redirect::Policy::none()),
        )
        .build()
        .ok()
}

pub(crate) async fn fetch_did_bytes(
    http: &reqwest::Client,
    url: &str,
    max_bytes: usize,
) -> Option<(String, Vec<u8>)> {
    fetch_guarded_bytes(http, url, max_bytes, None).await
}

pub(crate) async fn fetch_arkret_bytes(
    http: &reqwest::Client,
    url: &str,
    max_bytes: usize,
    operation: &str,
) -> Option<(String, Vec<u8>)> {
    fetch_guarded_bytes(http, url, max_bytes, Some(operation)).await
}

async fn fetch_guarded_bytes(
    http: &reqwest::Client,
    url: &str,
    max_bytes: usize,
    operation: Option<&str>,
) -> Option<(String, Vec<u8>)> {
    // P3.2c SSRF egress guard — fail-closed *before* any outbound request.
    // The `did:web` / `did:webvh` host is taken verbatim from an untrusted
    // actor DID, so a hostile `did:web:127.0.0.1` /
    // `did:web:169.254.169.254` (cloud metadata) / `did:web:localhost` must
    // never let the client reach into loopback, private, link-local or
    // carrier-NAT address space. The guard lives here, at the request layer:
    // the SDK URL helpers are pure syntax-to-URL derivations and no longer
    // carry this judgment.
    #[cfg(not(target_arch = "wasm32"))]
    {
        // Native: lock the target through the shared guard and dispatch on a
        // client pinned to the validated address set. The caller's client is
        // not reused because DNS pinning is a per-target client property.
        let _ = http;
        let client = locked_did_fetch_client(url).await?;
        fetch_did_bytes_from_url(&client, url, max_bytes, operation).await
    }
    #[cfg(target_arch = "wasm32")]
    {
        // wasm: the browser owns DNS and the socket, so the static shared
        // classification is the entire guard the platform allows.
        if !url_host_is_safe(url) {
            return None;
        }
        fetch_did_bytes_from_url(http, url, max_bytes, operation).await
    }
}

async fn fetch_did_bytes_from_url(
    http: &reqwest::Client,
    url: &str,
    max_bytes: usize,
    operation: Option<&str>,
) -> Option<(String, Vec<u8>)> {
    let mut request = http.get(url);
    if let Some(operation) = operation {
        request = request.header("Arkret-Operation", operation);
    }
    let response = request.send().await.ok()?;
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

fn trusted_webvh_urls(
    trusted_base_url: &url::Url,
    service: &DidFullId,
) -> Option<(url::Url, url::Url)> {
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
pub(crate) async fn fetch_did_web_document(
    http: &reqwest::Client,
    did: &DidFullId,
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
    did: &DidFullId,
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
    principal: &DidFullId,
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

    fn parse(did: &str) -> DidFullId {
        DidFullId::new(did.to_owned()).expect("valid did")
    }

    #[test]
    fn personal_node_rejects_plain_did_web_principals() {
        let policy = policy_for(DeploymentProfile::PersonalNode);
        assert!(!policy.permits(&parse("did:web:alice.example")));
        assert!(policy.permits(&parse("did:webvh:QmExampleScidValue123456:alice.example")));
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
    fn plain_did_web_is_disallowed_before_resolution() {
        let resolver = build_default_resolver(DeploymentProfile::PersonalNode);
        let did = parse("did:web:alice.example");
        match verify_principal(&resolver, &did) {
            Err(VerifyError::Disallowed(_)) => {}
            other => panic!("expected Disallowed, got {other:?}"),
        }
    }

    fn sample_document(did_str: &str) -> (DidFullId, DidDocument) {
        let did = parse(did_str);
        let doc = DidDocument::new(did.clone(), "key-1", "z6Mksample");
        (did, doc)
    }

    /// A cached resolution for a method that publishes nothing to prove — which
    /// is what every fixture here is. Synthesizing evidence instead would let a
    /// test assert a trust level `did:web` cannot give.
    fn proofless(document: DidDocument) -> arkret_sdk::identity::ResolvedDid {
        arkret_sdk::identity::ResolvedDid::proofless(document)
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
            .insert(did.clone(), proofless(doc), t0, Duration::seconds(600))
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
        let did = parse("did:webvh:QmExampleScidValue123456:alice.example");
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
        let (did, doc) = sample_document("did:webvh:QmExampleScidValue123456:alice.example");
        let t0 = Utc::now();
        cache
            .insert(did.clone(), proofless(doc), t0, Duration::seconds(60))
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
            .insert(did_a, proofless(doc_a), t0, Duration::seconds(60))
            .unwrap();
        cache
            .insert(did_b, proofless(doc_b), t0, Duration::seconds(60))
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
    fn web_outcome(
        did: &DidFullId,
        document: &DidDocument,
        content_type: &str,
    ) -> DidWebDocumentOutcome {
        DidWebDocumentOutcome {
            url: DidWebResolver::document_url(did).unwrap(),
            content_type: content_type.to_owned(),
            body: serde_json::to_vec(document).unwrap(),
        }
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
    async fn ensure_actor_document_rejects_pairwise_did_key() {
        // Pairwise did:key is Realm/leaf-scoped and may not be promoted into
        // the durable principal directory.
        let anchor = ResolverDidAnchor::from_profile(
            DeploymentProfile::PersonalNode,
            DidResolutionCache::new(8),
        );
        let did = parse("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK");
        let http = reqwest::Client::new();
        assert!(!anchor.ensure_actor_document(&http, &did).await);
        assert!(anchor.resolve_did_document(&did).is_none());
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

    // Caller-closure gate: no production path may fetch a derived DID URL
    // without the request-layer egress guard. The raw fetch helper has
    // exactly four call sites — the two `fetch_did_bytes` platform halves
    // (native locks and pins through the shared `EgressGuard`; wasm applies
    // the static shared classification, which is all a browser client can
    // do) and the two same-origin trusted-service fetches, whose target
    // comes from the operator-configured server origin rather than a
    // DID-carried host — and `.send()` appears only inside the raw fetch
    // helper itself. A future "derive a URL, then reqwest it directly" path
    // fails here instead of silently skipping the guard.
    #[test]
    fn every_did_fetch_passes_through_the_egress_guard() {
        let path =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/identity/did_resolver.rs");
        let text = std::fs::read_to_string(path).expect("did_resolver.rs source");
        // Cut at the test *module*, not the first `#[cfg(test)]`: the file
        // carries earlier test-only helpers (`build_default_resolver`,
        // `ingest_web_for_test`) whose attributes would otherwise truncate
        // "production" to the first 78 lines.
        let production = text
            .split("\n#[cfg(test)]\nmod tests")
            .next()
            .unwrap_or(&text);
        let raw_fetch_calls = production
            .lines()
            .filter(|line| {
                !line.trim_start().starts_with("//")
                    && line.contains("fetch_did_bytes_from_url(")
                    && !line.contains("async fn fetch_did_bytes_from_url")
            })
            .count();
        assert_eq!(
            raw_fetch_calls, 4,
            "raw DID fetches must stay confined to the guarded fetch_did_bytes halves and the configured same-origin service path"
        );
        let sends = production
            .lines()
            .filter(|line| !line.trim_start().starts_with("//") && line.contains(".send()"))
            .count();
        assert_eq!(
            sends, 1,
            "fetch_did_bytes_from_url must remain the only dispatch point"
        );
    }
}
