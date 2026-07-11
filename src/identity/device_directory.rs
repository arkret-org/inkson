//! Device signing-key directory: resolve `(actor, device)` to its authoritative
//! Ed25519 verify key for fail-closed proof verification of call signaling
//! (`webrtc-signaling.md` §5.1) and persistent chat messages
//! (`device-lifecycle.md` §8.2).
//!
//! ## Why a cache exists
//!
//! The authoritative key lives behind soland's async `keys/query` endpoint, but
//! the call-signal receive routing (`views::call_signals::route_realm_call_signals`)
//! runs on the *synchronous* sync-apply path with no `.await` seam. This module
//! bridges that gap with a process-wide cache:
//!
//! - [`resolve_device_signing_key`] is the async path: it calls `keys/query`, decodes the `did:key`
//!   multibase into [`PublicKeyMaterial`], and writes the result (positive *or* negative) into the
//!   cache with a TTL.
//! - [`cached_device_signing_key`] is the sync lookup the receive path uses. It never blocks; it
//!   returns [`CacheLookup::Hit`] / [`CacheLookup::NegativeHit`] / [`CacheLookup::Miss`].
//! - [`prefetch_device_keys`] primes the cache for a set of `(actor, device)` pairs (called when a
//!   realm's members load / sync), so a normal inbound invite hits the cache and can be verified
//!   inline.
//!
//! ## Negative caching + status semantics
//!
//! Per spec §8.2, "omitted `device_signing_key`" and "`device_status != active`"
//! both mean the device is unusable for verification. Either condition resolves
//! to a *negative* cache entry → [`cached_device_signing_key`] returns
//! `NegativeHit`, and the receive path fail-closed drops the signal. A genuine
//! query error (network / decode) is NOT cached so a transient failure can be
//! retried by the next prefetch.
//!
//! ## Accepted trust regimes
//!
//! Bare Tier-1 trusts soland's assertion that `device_signing_key` is the
//! device's authoritative verify key. This module does not accept that for
//! E2EE proof verification. A positive cache entry requires one of the two
//! normative trust regimes:
//!
//! - **Cross-signing** ([`verify_tier2_chain`]): before a key is cached / used for proof
//!   verification the client independently verifies the full cross-signing chain per
//!   `device-lifecycle.md` §5.2.1 / §8.3:
//!
//!   1. **DID anchoring** (done here, not by the SDK): resolve the actor's DID document through
//!      inkson's existing resolver chain ([`crate::identity::did_resolver`]) and confirm
//!      `cross_signing[principal] .principal_signing_key` (`kid` + `public_key`) equals the
//!      DID-resolved verification method key byte-for-byte. Mismatch / unresolvable → fail.
//!   2. **PSK→SSK→device chain**: hand the DID-anchored PSK plus the publish payload, the device's
//!      `cross_signing_binding`, and the directory key to the SDK primitive
//!      [`arkret_sdk::verify_device_cross_signing_chain`].
//!   3. **Accept only on `CrossSigned`**. Missing `cross_signing` / missing `cross_signing_binding`
//!      / `Unverified` / `NeedsReverification` all map to a negative cache entry for this regime.
//! - **Service-attested enrollment** (`device-lifecycle.md` §5.4): managed-DID principals have no
//!   SSK publish. For those records, `keys/query` must return the accepted
//!   `enrollment_authority_binding` plus `device_authorize_event_id`; the current device-set
//!   projection is the hot-path trust anchor. Missing or malformed anchors fail closed.
//!
//! If neither regime accepts the record, the directory key is never cached.

use std::collections::HashMap;
use std::sync::{LazyLock, RwLock};

use arkret_sdk::signatures::PublicKeyMaterial;
use arkret_sdk::{
    CrossSigningPublishContent, DeviceId, DeviceTrustBinding, DeviceTrustState, Did, DidDocument,
    QueryDeviceCrossSigningBinding, resolve_verification_method_key_from_document,
};

use crate::transport::TransportClient;

/// Resolve the DID document for an `actor` so the Tier-2 anchoring step can
/// confirm the published PSK against the actor's current DID control set.
///
/// Implementations wrap inkson's authority-grade DID resolver
/// ([`crate::identity::did_resolver::build_default_resolver`] + `resolve_with_cache`),
/// so the same fail-closed policy that governs login / trust UI also governs
/// device-key trust. Returning `None` (unresolvable / disallowed method / no
/// evidence) makes [`verify_tier2_chain`] fail-closed — exactly the §8.2 rule
/// "missing → MUST treat as unverified".
pub trait DidAnchor {
    fn resolve_did_document(&self, actor: &Did) -> Option<DidDocument>;

    /// P3.2b: asynchronously fetch + ingest `actor`'s DID document so a
    /// subsequent [`Self::resolve_did_document`] can anchor the cross-signing
    /// chain for `did:web` / `did:webvh` actors (whose key material lives
    /// off-host). `http` is the caller's existing cross-platform
    /// [`reqwest::Client`]. Returns `true` when the document is available
    /// (fetched + ingested, or `did:key` which self-resolves and needs no
    /// fetch), `false` fail-closed on any fetch / validation failure.
    ///
    /// The default is a no-op `true`: in-memory anchors (e.g. test fixtures)
    /// pre-seed their evidence, so they need no network step. The live
    /// [`crate::identity::did_resolver::ResolverDidAnchor`] overrides this to perform the
    /// real fetch + ingest.
    fn ensure_actor_document<'a>(
        &'a self,
        http: &'a reqwest::Client,
        actor: &'a Did,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = bool> + 'a>> {
        let _ = (http, actor);
        Box::pin(async { true })
    }
}

/// Positive-entry TTL: a resolved key is trusted for this long before a fresh
/// `keys/query` is required. Bounded so a revoke that lands after the key was
/// cached is picked up promptly on the next prefetch.
const POSITIVE_TTL_MS: u64 = 5 * 60 * 1000;

/// Negative-entry TTL: a "no key / revoked / absent" verdict is cached for a
/// shorter window so a freshly-authorized device becomes resolvable quickly.
const NEGATIVE_TTL_MS: u64 = 30 * 1000;

/// Hard cap for the process-wide device-key cache. The receive path is
/// synchronous, so eviction stays O(n) here rather than introducing an async
/// cache dependency into the hot path.
const MAX_CACHE_ENTRIES: usize = 4096;

#[derive(Clone)]
struct CacheEntry {
    /// `Some` = authoritative verify key; `None` = negative (revoked / absent /
    /// no key returned).
    key: Option<PublicKeyMaterial>,
    /// `now_unix_ms` at which this entry stops being valid.
    expires_at_ms: u64,
    /// Last successful sync lookup or insertion time, used for bounded-cache
    /// eviction.
    last_accessed_ms: u64,
}

type CacheKey = (String, String);

static CACHE: LazyLock<RwLock<HashMap<CacheKey, CacheEntry>>> =
    LazyLock::new(|| RwLock::new(HashMap::new()));

/// Result of a synchronous cache lookup for a `(actor, device)` pair.
#[derive(Clone)]
pub enum CacheLookup {
    /// A fresh authoritative verify key is cached.
    Hit(PublicKeyMaterial),
    /// A fresh negative verdict is cached: the device is revoked, absent from
    /// the directory, or returned no `device_signing_key`. Receivers MUST
    /// fail-closed.
    NegativeHit,
    /// No fresh entry — caller should trigger an async resolve (and, for
    /// non-invite signals, fail-closed in the meantime).
    Miss,
}

fn cache_key(actor: &str, device: &str) -> CacheKey {
    (actor.to_owned(), device.to_owned())
}

/// Synchronous, non-blocking cache lookup used by the receive routing path.
pub fn cached_device_signing_key(actor: &str, device: &str) -> CacheLookup {
    let now = crate::clock::now_unix_ms();
    let mut guard = match CACHE.write() {
        Ok(g) => g,
        Err(poison) => poison.into_inner(),
    };
    let key = cache_key(actor, device);
    match guard.get_mut(&key) {
        Some(entry) if entry.expires_at_ms > now => {
            entry.last_accessed_ms = now;
            match &entry.key {
                Some(key) => CacheLookup::Hit(key.clone()),
                None => CacheLookup::NegativeHit,
            }
        }
        Some(_) => {
            guard.remove(&key);
            CacheLookup::Miss
        }
        None => CacheLookup::Miss,
    }
}

fn store_entry(actor: &str, device: &str, key: Option<PublicKeyMaterial>) {
    let now = crate::clock::now_unix_ms();
    let ttl = if key.is_some() {
        POSITIVE_TTL_MS
    } else {
        NEGATIVE_TTL_MS
    };
    let entry = CacheEntry {
        key,
        expires_at_ms: now.saturating_add(ttl),
        last_accessed_ms: now,
    };
    let mut guard = match CACHE.write() {
        Ok(g) => g,
        Err(poison) => poison.into_inner(),
    };
    guard.retain(|_, entry| entry.expires_at_ms > now);
    let inserted_key = cache_key(actor, device);
    guard.insert(inserted_key.clone(), entry);
    while guard.len() > MAX_CACHE_ENTRIES {
        let victim = guard
            .iter()
            .filter(|(candidate, _)| *candidate != &inserted_key)
            .min_by_key(|(_, entry)| (entry.last_accessed_ms, entry.expires_at_ms))
            .map(|(key, _)| key.clone())
            .or_else(|| guard.keys().next().cloned());
        let Some(victim) = victim else {
            break;
        };
        guard.remove(&victim);
    }
}

/// Decode a directory `device_signing_key` (`did:key` Ed25519 multibase, with
/// or without the `did:key:` prefix) into wire-form [`PublicKeyMaterial`].
/// Returns `None` for an unparseable / wrong-curve value so the caller treats
/// it as "no usable key" (fail-closed).
pub fn public_key_from_directory_value(value: &str) -> Option<PublicKeyMaterial> {
    let multibase = value
        .trim()
        .strip_prefix("did:key:")
        .unwrap_or(value.trim());
    if !multibase.starts_with('z') {
        return None;
    }
    let material = PublicKeyMaterial::Ed25519Multibase {
        value: multibase.to_owned(),
    };
    // Validate it actually decodes to 32 Ed25519 bytes now, so a malformed
    // directory entry becomes a negative verdict rather than a later verify
    // error on the hot path.
    material.ed25519_bytes().ok()?;
    Some(material)
}

/// Extract the directory verdict for one `(actor, device)` out of a
/// `keys/query` outcome: `Some(Some(key))` = active with key,
/// `Some(None)` = present-but-unusable (revoked / no key),
/// `None` = the device was absent from the response.
fn directory_verdict(
    outcome: &arkret_sdk::models::KeysQueryOutcome,
    actor: &str,
    device: &str,
) -> Option<Option<PublicKeyMaterial>> {
    let record = directory_record(outcome, actor, device)?;

    // Spec §8.2: a non-active status, or an omitted key, both mean unusable.
    let active = matches!(
        record.device_status,
        None | Some(arkret_sdk::models::DeviceStatus::Active)
    );
    if !active {
        return Some(None);
    }
    let key = record
        .device_signing_key
        .as_deref()
        .and_then(public_key_from_directory_value);
    Some(key)
}

fn directory_record<'a>(
    outcome: &'a arkret_sdk::models::KeysQueryOutcome,
    actor: &str,
    device: &str,
) -> Option<&'a arkret_sdk::models::QueryDeviceRecord> {
    outcome
        .device_keys
        .iter()
        .find(|(did, _)| did.as_str() == actor)
        .and_then(|(_, devices)| devices.iter().find(|(dev, _)| dev.as_str() == device))
        .map(|(_, record)| record)
}

// ── Tier-2: client-side cross-signing chain verification (§8.3) ────────────

/// Convert the directory `cross_signing[principal]` publish payload (the
/// `cross-signing-publish.schema.json` counterpart [`arkret_sdk::CrossSigningPublish`])
/// into the SDK chain-verifier input type [`CrossSigningPublishContent`]. The
/// two are field-for-field 1:1 (soland produces one from the other by the same
/// round-trip), so a JSON round-trip is lossless; a shape mismatch fails closed.
fn publish_content_from_directory(
    publish: &arkret_sdk::CrossSigningPublish,
) -> Option<CrossSigningPublishContent> {
    let value = serde_json::to_value(publish).ok()?;
    serde_json::from_value(value).ok()
}

/// Convert the per-device directory `cross_signing_binding`
/// ([`QueryDeviceCrossSigningBinding`], `alg` optional) into the SDK chain
/// input [`DeviceTrustBinding`] (`alg` required). `alg` defaults to `EdDSA`
/// (the v1 core signature algorithm) when the directory omits it.
fn trust_binding_from_directory(binding: &QueryDeviceCrossSigningBinding) -> DeviceTrustBinding {
    DeviceTrustBinding {
        verification_method: binding.verification_method.clone(),
        alg: binding.alg.clone().unwrap_or_else(|| "EdDSA".to_owned()),
        ssk_generation: binding.ssk_generation,
        signature: binding.signature.clone(),
    }
}

/// DID-anchor the published PSK: confirm `publish.principal_signing_key`
/// (`kid` + `public_key`) equals the verification-method key in the actor's
/// resolved DID document, byte-for-byte (§8.3 step 1). Returns the anchored PSK
/// key material on success, `None` on any mismatch / lookup failure.
fn anchor_psk_against_did(
    did_document: &DidDocument,
    publish: &CrossSigningPublishContent,
) -> Option<PublicKeyMaterial> {
    let resolved = resolve_verification_method_key_from_document(
        did_document,
        &publish.principal_signing_key.kid,
    )
    .ok()?;
    // The published PSK public_key is a bare multibase Ed25519 key; decode both
    // sides to raw bytes and require exact equality. This is the byte-for-byte
    // anchoring §8.3 step 1 mandates — we do NOT trust the publish's own
    // assertion of the PSK key; only the DID control set decides.
    let published = PublicKeyMaterial::Ed25519Multibase {
        value: publish.principal_signing_key.public_key.clone(),
    };
    if resolved.public_key.ed25519_bytes().ok()? != published.ed25519_bytes().ok()? {
        return None;
    }
    Some(resolved.public_key)
}

/// Tier-2 chain verdict for one `(actor, device)` (§5.2.1 / §8.3), end to end:
/// DID-anchor the PSK, then run the SDK PSK→SSK→device chain verifier. Returns
/// [`DeviceTrustState::CrossSigned`] only when the whole chain holds; any
/// failure (DID anchoring, signature, generation) maps to a non-`CrossSigned`
/// state and the caller fail-closes.
///
/// `device_signing_key_multibase` is the bare multibase Ed25519 key the
/// directory exposed (the inner key of the `did:key` `device_signing_key`). It
/// is the *same* key fed to the device-binding canonical input, closing §8.3
/// step 5 "directory key ⇔ cross-signed key".
pub fn verify_tier2_chain(
    did_document: &DidDocument,
    publish: &arkret_sdk::CrossSigningPublish,
    binding: &QueryDeviceCrossSigningBinding,
    actor: &Did,
    device: &DeviceId,
    device_signing_key_multibase: &str,
    hpke_key: &str,
    trust_algorithms: &[String],
) -> DeviceTrustState {
    let Some(publish_content) = publish_content_from_directory(publish) else {
        return DeviceTrustState::Unverified;
    };
    // §8.3 step 1: the publish's principal_id MUST be the actor we're anchoring.
    if publish_content.principal_id.as_str() != actor.as_str() {
        return DeviceTrustState::Unverified;
    }
    let Some(anchored_psk) = anchor_psk_against_did(did_document, &publish_content) else {
        return DeviceTrustState::Unverified;
    };
    let trust_binding = trust_binding_from_directory(binding);
    arkret_sdk::verify_device_cross_signing_chain(arkret_sdk::DeviceCrossSigningChainVerification {
        publish: &publish_content,
        binding: &trust_binding,
        principal_id: actor,
        device_id: device,
        device_public_key: device_signing_key_multibase,
        hpke_key,
        algorithms: trust_algorithms,
        anchored_psk: &anchored_psk,
    })
}

/// Apply the full Tier-2 acceptance gate to a `keys/query` outcome for one
/// `(actor, device)`: read the per-device `cross_signing_binding` + the
/// per-principal `cross_signing` publish, DID-anchor + chain-verify, and accept
/// the directory key **only** when the chain is `CrossSigned`.
///
/// Returns the key to cache: `Some(key)` (positive) only on a clean
/// `CrossSigned`; `None` (negative) for every other case — missing publish,
/// missing binding (incl. inception bootstrap), DID anchoring failure,
/// `Unverified` / `NeedsReverification`, or an undecodable directory key. There
/// is no Tier-1 fallback: a present-but-unverifiable key is rejected.
fn tier2_accepted_key(
    outcome: &arkret_sdk::models::KeysQueryOutcome,
    did_document: &DidDocument,
    actor: &Did,
    device: &DeviceId,
) -> Option<PublicKeyMaterial> {
    // Tier-1 facet first: a revoked / absent / no-key device is already a
    // negative verdict regardless of Tier-2 material.
    let directory_key = directory_verdict(outcome, actor.as_str(), device.as_str())??;

    // §8.2: missing per-principal `cross_signing` OR missing per-device
    // `cross_signing_binding` → MUST treat as unverified, fail-closed. Inception
    // bootstrap devices (no binding) fall here on purpose (§8.3 step 3 / §5.0.1
    // exception is deferred to a later line — do NOT relax to pass).
    let publish = outcome
        .cross_signing
        .iter()
        .find_map(|(did, publish)| (did.as_str() == actor.as_str()).then_some(publish))?;
    let record = directory_record(outcome, actor.as_str(), device.as_str())?;
    let binding = record.cross_signing_binding.as_ref()?;

    // §8.3 step 5: verify the chain over the SAME bare multibase key the
    // directory exposed (and which we will use for proof verification).
    let multibase = directory_signing_key_multibase(record.device_signing_key.as_deref()?)?;
    // §5.2/§8.2: the trust binding transcript also covers the device HPKE
    // sealing key and the canonical algorithms array — a directory record
    // missing either cannot be chain-verified (fail closed).
    let hpke_key = record.hpke_key.as_deref()?;
    let trust_algorithms = record.trust_algorithms.as_deref()?;
    match verify_tier2_chain(
        did_document,
        publish,
        binding,
        actor,
        device,
        &multibase,
        hpke_key,
        trust_algorithms,
    ) {
        DeviceTrustState::CrossSigned => Some(directory_key),
        _ => None,
    }
}

/// Accept a managed-DID service-attested device record (§5.4) only when the
/// active directory key is accompanied by the current device-set projection
/// anchors: the accepted `ak.device.authorize` id and the enrollment authority
/// binding that caused the projection.
fn service_attested_accepted_key(
    outcome: &arkret_sdk::models::KeysQueryOutcome,
    actor: &Did,
    device: &DeviceId,
) -> Option<PublicKeyMaterial> {
    let directory_key = directory_verdict(outcome, actor.as_str(), device.as_str())??;
    let record = directory_record(outcome, actor.as_str(), device.as_str())?;
    if record.cross_signing_binding.is_some() {
        return None;
    }
    let binding = record.enrollment_authority_binding.as_ref()?;
    if binding.kind != arkret_sdk::DeviceEnrollmentAuthorityBinding::KIND_SERVICE_ATTESTED {
        return None;
    }
    if binding.authorization_ref.trim().is_empty() {
        return None;
    }
    record.device_authorize_event_id.as_ref()?;
    Some(directory_key)
}

/// Strip the optional `did:key:` prefix from a directory `device_signing_key`,
/// returning the bare multibase (`z…`) form that the device-binding canonical
/// input was signed over. Returns `None` for a non-multibase value.
fn directory_signing_key_multibase(value: &str) -> Option<String> {
    let multibase = value
        .trim()
        .strip_prefix("did:key:")
        .unwrap_or(value.trim());
    multibase.starts_with('z').then(|| multibase.to_owned())
}

/// Async resolve: query soland for the `(actor, device)` directory record, run
/// the accepted device trust regime (cross-signing §8.3, or service-attested
/// device-set projection §5.4), update the cache (positive or negative), and
/// return the resolved key.
///
/// Returns `Ok(Some(key))` only for an active device accepted by one of those
/// regimes; `Ok(None)` for revoked / absent / no-key / missing trust material /
/// verification failure (a negative cache entry is written, fail-closed);
/// `Err` for a transport / decode failure (not cached, so a later prefetch retries).
pub async fn resolve_device_signing_key(
    api: &TransportClient,
    anchor: &dyn DidAnchor,
    actor: &str,
    device: &str,
) -> anyhow::Result<Option<PublicKeyMaterial>> {
    let actor_did = match Did::new(actor.to_owned()) {
        Ok(did) => did,
        // Malformed actor DID → fail-closed negative cache.
        Err(_) => {
            store_entry(actor, device, None);
            return Ok(None);
        }
    };
    let device_id = match DeviceId::new(device.to_owned()) {
        Ok(id) => id,
        Err(_) => {
            store_entry(actor, device, None);
            return Ok(None);
        }
    };

    let outcome =
        crate::transport::keys::query_keys(&api.sdk_http_client()?, actor, device).await?;

    // P3.2b: DID anchoring (§8.3 step 1) needs the actor's DID document. For
    // `did:web` / `did:webvh` actors that document lives off-host, so fetch +
    // ingest it into the anchor's resolver first (best-effort: a failure leaves
    // the anchor without evidence, and the synchronous resolve below then
    // fail-closes). `did:key` actors self-resolve and skip the fetch.
    let _ = anchor.ensure_actor_document(&api.http, &actor_did).await;

    let cross_signed_key = match anchor.resolve_did_document(&actor_did) {
        Some(did_document) => tier2_accepted_key(&outcome, &did_document, &actor_did, &device_id),
        None => None,
    };
    let key = cross_signed_key
        .or_else(|| service_attested_accepted_key(&outcome, &actor_did, &device_id));
    store_entry(actor, device, key.clone());
    Ok(key)
}

/// Prime the cache for a batch of `(actor, device)` pairs (e.g. a realm's
/// members on load / sync). Pairs already covered by a fresh cache entry are
/// skipped. Best-effort: a per-pair query error is swallowed (left uncached for
/// retry) so one unreachable device never blocks the rest.
pub async fn prefetch_device_keys(
    api: &TransportClient,
    anchor: &dyn DidAnchor,
    pairs: &[(String, String)],
) {
    for (actor, device) in pairs {
        if !matches!(cached_device_signing_key(actor, device), CacheLookup::Miss) {
            continue;
        }
        let _ = resolve_device_signing_key(api, anchor, actor, device).await;
    }
}

// ── Receiver-side proof verification ───────────────────────────────────────

/// Strip the fragment / query from a `{actor}#device` verification-method DID
/// URL, yielding the controller DID. `did:web:alice#device` → `did:web:alice`.
fn verification_method_controller(verification_method: &str) -> &str {
    let no_query = verification_method
        .split_once('?')
        .map(|(head, _)| head)
        .unwrap_or(verification_method);
    no_query
        .split_once('#')
        .map(|(head, _)| head)
        .unwrap_or(no_query)
}

/// Verify a single detached-JWS `proof` object against the canonical bytes of
/// the surrounding envelope.
///
/// `envelope_without_proof` is the envelope `Value` with its proof field(s)
/// already removed; this function canonicalizes it with RFC 8785 JCS (the same
/// encoder the sender hashed, `EventProofBuilder::canonical_bytes`) to recover
/// the `canonical_bytes` the SDK verifier expects. `actor_id` is the envelope's
/// `actor_id` (folded into the proof binding object per `webrtc-signaling.md`
/// §5.1).
///
/// Checks, in order, fail-closed on any miss:
///   1. `proof.verification_method` controller DID == `actor_id` (byte-equal);
///   2. SDK [`verify_eddsa_detached_jws_proof`] — recomputes the canonical envelope digest,
///      compares it to `proof.event_digest`, rebuilds the binding object `{event_digest, actor_id,
///      verification_method, created_at, domain?, audience?}`, and verifies the detached JWS over
///      it with `public_key`.
pub fn verify_proof_value(
    envelope_without_proof: &serde_json::Value,
    proof_value: &serde_json::Value,
    actor_id: &str,
    public_key: &PublicKeyMaterial,
) -> bool {
    let proof: arkret_sdk::Proof = match serde_json::from_value(proof_value.clone()) {
        Ok(proof) => proof,
        Err(_) => return false,
    };
    // §5.1: the verification_method controller DID MUST equal envelope actor_id.
    if verification_method_controller(&proof.verification_method) != actor_id {
        return false;
    }
    let did = match arkret_sdk::Did::new(actor_id.to_owned()) {
        Ok(did) => did,
        Err(_) => return false,
    };
    let canonical_bytes = match crate::canonical::canonical_json_bytes(envelope_without_proof) {
        Ok(bytes) => bytes,
        Err(_) => return false,
    };
    arkret_sdk::signatures::verify_eddsa_detached_jws_proof(
        &proof,
        &canonical_bytes,
        &did,
        public_key,
    )
    .is_ok()
}

/// Maximum accepted age of an ephemeral (call-signal) proof's `created_at`
/// relative to now. Ephemeral signaling frames are transient, so bounding the
/// `created_at` window caps how long a captured, already-signed frame can be
/// replayed onto the routing path. The window is intentionally generous (an
/// hour) so legitimately delayed or clock-skewed signaling is never dropped —
/// persistent Events are NOT subject to this gate (they may be legitimately old
/// during backfill/sync), which is why the check lives here and not in the
/// shared [`verify_proof_value`].
const EPHEMERAL_PROOF_MAX_AGE_SECS: i64 = 3600;
/// Maximum accepted forward clock skew for an ephemeral proof's `created_at`.
const EPHEMERAL_PROOF_MAX_FUTURE_SKEW_SECS: i64 = 300;

/// Fail-closed freshness check for an ephemeral proof's `created_at`: it MUST be
/// present, RFC 3339, and within [`EPHEMERAL_PROOF_MAX_AGE_SECS`] in the past /
/// [`EPHEMERAL_PROOF_MAX_FUTURE_SKEW_SECS`] in the future of `now`.
fn ephemeral_proof_created_at_fresh(
    proof_value: &serde_json::Value,
    now: chrono::DateTime<chrono::Utc>,
) -> bool {
    let Some(created_at) = proof_value.get("created_at").and_then(|v| v.as_str()) else {
        return false;
    };
    let Ok(parsed) = chrono::DateTime::parse_from_rfc3339(created_at) else {
        return false;
    };
    let age = now
        .signed_duration_since(parsed.with_timezone(&chrono::Utc))
        .num_seconds();
    age <= EPHEMERAL_PROOF_MAX_AGE_SECS && age >= -EPHEMERAL_PROOF_MAX_FUTURE_SKEW_SECS
}

/// Verify an ephemeral call-signal envelope's `proof` (single object).
///
/// Strips the top-level `proof` field, then delegates to [`verify_proof_value`].
/// Returns `false` (fail-closed) when the envelope carries no `actor_id` or no
/// `proof`, or when the proof's `created_at` is stale/absent (replay window).
pub fn verify_ephemeral_envelope_proof(
    envelope: &serde_json::Value,
    public_key: &PublicKeyMaterial,
) -> bool {
    verify_ephemeral_envelope_proof_at(envelope, public_key, chrono::Utc::now())
}

/// [`verify_ephemeral_envelope_proof`] with an injectable clock for tests.
pub fn verify_ephemeral_envelope_proof_at(
    envelope: &serde_json::Value,
    public_key: &PublicKeyMaterial,
    now: chrono::DateTime<chrono::Utc>,
) -> bool {
    let actor_id = match envelope.get("actor_id").and_then(|v| v.as_str()) {
        Some(actor) => actor.to_owned(),
        None => return false,
    };
    let proof_value = match envelope.get("proof") {
        Some(proof) => proof.clone(),
        None => return false,
    };
    // Bound the replay window before signature work.
    if !ephemeral_proof_created_at_fresh(&proof_value, now) {
        return false;
    }
    let mut without_proof = envelope.clone();
    if let Some(object) = without_proof.as_object_mut() {
        object.remove("proof");
    }
    verify_proof_value(&without_proof, &proof_value, &actor_id, public_key)
}

/// Verify a persistent Event envelope's `proofs` (array). The envelope passes
/// if at least one proof entry verifies under `public_key` after the whole
/// `proofs` (and `unsigned`) field is stripped for canonicalization — matching
/// the sender's `sign_envelope` which strips `proofs` + `unsigned` before
/// hashing.
///
/// Returns `false` (fail-closed) when the envelope carries no `actor_id` or an
/// empty / absent `proofs` array.
pub fn verify_persistent_envelope_proofs(
    envelope: &serde_json::Value,
    public_key: &PublicKeyMaterial,
) -> bool {
    let actor_id = match envelope.get("actor_id").and_then(|v| v.as_str()) {
        Some(actor) => actor.to_owned(),
        None => return false,
    };
    let proofs = match envelope.get("proofs").and_then(|v| v.as_array()) {
        Some(proofs) if !proofs.is_empty() => proofs.clone(),
        _ => return false,
    };
    let mut without_proofs = envelope.clone();
    if let Some(object) = without_proofs.as_object_mut() {
        object.remove("proofs");
        object.remove("unsigned");
    }
    proofs
        .iter()
        .any(|proof| verify_proof_value(&without_proofs, proof, &actor_id, public_key))
}

/// Drop the cached entry for one `(actor, device)` (e.g. after observing a
/// `ak.device.revoke` locally) so the next lookup re-queries.
pub fn invalidate(actor: &str, device: &str) {
    let mut guard = match CACHE.write() {
        Ok(g) => g,
        Err(poison) => poison.into_inner(),
    };
    guard.remove(&cache_key(actor, device));
}

/// Test-only: seed a positive cache entry so synchronous receiver paths
/// (call-signal routing, chat render) can be exercised without a live
/// `keys/query`. Mirrors what [`resolve_device_signing_key`] writes on success.
#[cfg(test)]
pub(crate) fn seed_positive_for_test(actor: &str, device: &str, key: PublicKeyMaterial) {
    store_entry(actor, device, Some(key));
}

/// Test-only: seed a negative cache entry (revoked / absent device).
#[cfg(test)]
pub(crate) fn seed_negative_for_test(actor: &str, device: &str) {
    store_entry(actor, device, None);
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::SigningKey;

    use super::*;

    fn test_did_key(seed: u8) -> String {
        let sk = SigningKey::from_bytes(&[seed; 32]);
        crate::identity::did_key::did_key_from_verifying_key(&sk.verifying_key())
    }

    #[test]
    fn decodes_did_key_with_and_without_prefix() {
        let did = test_did_key(11);
        let multibase = did.strip_prefix("did:key:").unwrap();
        let a = public_key_from_directory_value(&did).expect("did:key form");
        let b = public_key_from_directory_value(multibase).expect("bare multibase form");
        assert_eq!(a.ed25519_bytes().unwrap(), b.ed25519_bytes().unwrap());
    }

    #[test]
    fn rejects_non_multibase_directory_value() {
        assert!(public_key_from_directory_value("not-a-key").is_none());
        assert!(public_key_from_directory_value("").is_none());
    }

    #[test]
    fn cache_hit_then_miss_after_invalidate() {
        let actor = "did:web:cache-test-alice";
        let device = "ak:device:cache-1";
        let key = public_key_from_directory_value(&test_did_key(22)).unwrap();
        store_entry(actor, device, Some(key.clone()));
        match cached_device_signing_key(actor, device) {
            CacheLookup::Hit(got) => {
                assert_eq!(got.ed25519_bytes().unwrap(), key.ed25519_bytes().unwrap())
            }
            _ => panic!("expected Hit"),
        }
        invalidate(actor, device);
        assert!(matches!(
            cached_device_signing_key(actor, device),
            CacheLookup::Miss
        ));
    }

    #[test]
    fn negative_entry_resolves_to_negative_hit() {
        let actor = "did:web:cache-test-bob";
        let device = "ak:device:cache-neg";
        store_entry(actor, device, None);
        assert!(matches!(
            cached_device_signing_key(actor, device),
            CacheLookup::NegativeHit
        ));
        invalidate(actor, device);
    }

    const TEST_DEVICE_ID: &str = "ak:device:01904100-0000-7000-8000-000000000001";

    #[test]
    fn directory_verdict_revoked_is_negative_even_with_key() {
        let did = test_did_key(33);
        let outcome: arkret_sdk::models::KeysQueryOutcome =
            serde_json::from_value(serde_json::json!({
                "device_keys": {
                    "did:web:carol": {
                        TEST_DEVICE_ID: {
                            "algorithms": {},
                            "device_signing_key": did,
                            "device_status": "revoked"
                        }
                    }
                }
            }))
            .unwrap();
        let verdict = directory_verdict(&outcome, "did:web:carol", TEST_DEVICE_ID);
        // Present-but-revoked → Some(None): a usable key MUST NOT be derived.
        assert!(matches!(verdict, Some(None)));
    }

    #[test]
    fn directory_verdict_active_with_key_resolves() {
        let did = test_did_key(44);
        let outcome: arkret_sdk::models::KeysQueryOutcome =
            serde_json::from_value(serde_json::json!({
                "device_keys": {
                    "did:web:dave": {
                        TEST_DEVICE_ID: {
                            "algorithms": {},
                            "device_signing_key": did.clone(),
                            "device_status": "active"
                        }
                    }
                }
            }))
            .unwrap();
        let verdict = directory_verdict(&outcome, "did:web:dave", TEST_DEVICE_ID);
        match verdict {
            Some(Some(key)) => assert_eq!(
                key.ed25519_bytes().unwrap(),
                public_key_from_directory_value(&did)
                    .unwrap()
                    .ed25519_bytes()
                    .unwrap()
            ),
            _ => panic!("expected active key verdict"),
        }
    }

    #[test]
    fn directory_verdict_absent_device_is_none() {
        let outcome: arkret_sdk::models::KeysQueryOutcome =
            serde_json::from_value(serde_json::json!({
                "device_keys": {}
            }))
            .unwrap();
        assert!(directory_verdict(&outcome, "did:web:nobody", TEST_DEVICE_ID).is_none());
    }

    #[test]
    fn service_attested_accepts_projected_device_anchor() {
        let did = test_did_key(55);
        let actor = Did::new("did:web:managed-alice.example".to_owned()).unwrap();
        let device = DeviceId::new(TEST_DEVICE_ID.to_owned()).unwrap();
        let outcome: arkret_sdk::models::KeysQueryOutcome =
            serde_json::from_value(serde_json::json!({
                "device_keys": {
                    actor.as_str(): {
                        device.as_str(): {
                            "algorithms": {},
                            "device_signing_key": did.clone(),
                            "device_status": "active",
                            "enrollment_authority_binding": {
                                "kind": "service_attested",
                                "authority_did": "did:web:auth.example",
                                "authorization_ref": "did:web:managed-alice.example#device-enrollment"
                            },
                            "device_authorize_event_id": "ak:event:01904100-0000-7000-8000-000000000011"
                        }
                    }
                }
            }))
            .unwrap();
        let key = service_attested_accepted_key(&outcome, &actor, &device)
            .expect("service-attested projection anchors accept the device key");
        assert_eq!(
            key.ed25519_bytes().unwrap(),
            public_key_from_directory_value(&did)
                .unwrap()
                .ed25519_bytes()
                .unwrap()
        );
    }

    #[test]
    fn service_attested_missing_authorize_event_id_fails_closed() {
        let actor = Did::new("did:web:managed-bob.example".to_owned()).unwrap();
        let device = DeviceId::new(TEST_DEVICE_ID.to_owned()).unwrap();
        let outcome: arkret_sdk::models::KeysQueryOutcome =
            serde_json::from_value(serde_json::json!({
                "device_keys": {
                    actor.as_str(): {
                        device.as_str(): {
                            "algorithms": {},
                            "device_signing_key": test_did_key(56),
                            "device_status": "active",
                            "enrollment_authority_binding": {
                                "kind": "service_attested",
                                "authority_did": "did:web:auth.example",
                                "authorization_ref": "did:web:managed-bob.example#device-enrollment"
                            }
                        }
                    }
                }
            }))
            .unwrap();
        assert!(service_attested_accepted_key(&outcome, &actor, &device).is_none());
    }

    // ── Tier-2 client cross-signing chain (§8.3) ───────────────────────────
    //
    // These exercise the real DID-anchoring + real SDK chain verifier over
    // genuine Ed25519 signatures, following the SDK's own
    // `signed_chain_fixture` construction (sdk devices/tests.rs §550+).

    use arkret_sdk::{
        CrossSigningBinding, CrossSigningKeyRecord,
        CrossSigningPublishContent as SdkPublishContent, SignedCrossSigningKey, TypedTrustDomainId,
        base64url_encode,
    };
    use ed25519_dalek::Signer;

    const TIER2_TRUST_DOMAIN: &str = "ak:trust_domain:example.net";

    /// In-memory [`DidAnchor`] backed by a fixed actor→document map.
    struct TestAnchor {
        documents: HashMap<String, DidDocument>,
    }

    impl DidAnchor for TestAnchor {
        fn resolve_did_document(&self, actor: &Did) -> Option<DidDocument> {
            self.documents.get(actor.as_str()).cloned()
        }
    }

    /// A fully-signed Tier-2 fixture: the actor DID document (anchoring the
    /// published PSK), the directory `cross_signing` publish payload, the
    /// per-device `cross_signing_binding`, and the directory `device_signing_key`
    /// (did:key). `publish_gen` is the accepted publish generation;
    /// `binding_gen` is the `ssk_generation` baked into the device binding —
    /// differ them to drive the generation-comparison branches.
    struct Tier2Fixture {
        actor: Did,
        device: DeviceId,
        document: DidDocument,
        publish: arkret_sdk::CrossSigningPublish,
        binding: QueryDeviceCrossSigningBinding,
        device_signing_key: String,
    }

    fn build_tier2_fixture(
        actor_str: &str,
        device_str: &str,
        psk_seed: u8,
        ssk_seed: u8,
        device_seed: u8,
        publish_gen: u64,
        binding_gen: u64,
    ) -> Tier2Fixture {
        let actor = Did::new(actor_str.to_owned()).unwrap();
        let device = DeviceId::new(device_str.to_owned()).unwrap();

        let psk = SigningKey::from_bytes(&[psk_seed; 32]);
        let ssk = SigningKey::from_bytes(&[ssk_seed; 32]);
        let device_key = SigningKey::from_bytes(&[device_seed; 32]);

        let psk_multibase =
            crate::identity::did_key::encode_ed25519_did_key_multibase(&psk.verifying_key());
        let ssk_multibase =
            crate::identity::did_key::encode_ed25519_did_key_multibase(&ssk.verifying_key());
        let device_multibase =
            crate::identity::did_key::encode_ed25519_did_key_multibase(&device_key.verifying_key());
        let device_signing_key = format!("did:key:{device_multibase}");

        let psk_kid = format!("{actor_str}#ak_principal_signing_v1");
        let ssk_kid = format!("{actor_str}#ak_self_signing_v1");
        let usk_kid = format!("{actor_str}#ak_user_signing_v1");

        // DID document anchoring the PSK kid → PSK public key (multibase).
        let document = DidDocument::new(actor.clone(), psk_kid.clone(), psk_multibase.clone());

        // Build the SDK publish content so we compute the PSK→SSK binding
        // signature with the exact canonical input the verifier reconstructs.
        let mut content = SdkPublishContent {
            principal_id: actor.clone(),
            trust_domain: TypedTrustDomainId::new(TIER2_TRUST_DOMAIN).unwrap(),
            principal_signing_key: CrossSigningKeyRecord {
                kid: psk_kid.clone(),
                alg: "EdDSA".to_owned(),
                public_key: psk_multibase.clone(),
                key_format: "multibase".to_owned(),
            },
            self_signing_key: SignedCrossSigningKey {
                key: CrossSigningKeyRecord {
                    kid: ssk_kid.clone(),
                    alg: "EdDSA".to_owned(),
                    public_key: ssk_multibase.clone(),
                    key_format: "multibase".to_owned(),
                },
                binding: CrossSigningBinding {
                    verification_method: psk_kid.clone(),
                    alg: "EdDSA".to_owned(),
                    signature: String::new(),
                },
            },
            user_signing_key: SignedCrossSigningKey {
                key: CrossSigningKeyRecord {
                    kid: usk_kid,
                    alg: "EdDSA".to_owned(),
                    // Distinct from SSK (publish validation requires it).
                    public_key: format!("{ssk_multibase}USK"),
                    key_format: "multibase".to_owned(),
                },
                binding: CrossSigningBinding {
                    verification_method: psk_kid.clone(),
                    alg: "EdDSA".to_owned(),
                    signature: "unused".to_owned(),
                },
            },
            expected_previous_generation: publish_gen.saturating_sub(1),
            generation: publish_gen,
            issued_at: chrono::Utc::now(),
        };
        let ssk_input = content.self_signing_binding_input().unwrap();
        content.self_signing_key.binding.signature =
            base64url_encode(psk.sign(&ssk_input).to_bytes());

        // Serialize the SDK content into the artifact `CrossSigningPublish` the
        // directory carries (1:1 field shape).
        let publish: arkret_sdk::CrossSigningPublish =
            serde_json::from_value(serde_json::to_value(&content).unwrap()).unwrap();

        // SSK signs the device binding over the bare multibase device key
        // (§8.3 step 5: the same key the directory exposes).
        let device_input = DeviceTrustBinding::canonical_input(
            &actor,
            &device,
            &device_multibase,
            TIER2_HPKE_KEY,
            &tier2_algorithms(),
            binding_gen,
        )
        .unwrap();
        let binding = QueryDeviceCrossSigningBinding {
            verification_method: ssk_kid,
            alg: Some("EdDSA".to_owned()),
            ssk_generation: binding_gen,
            signature: base64url_encode(ssk.sign(&device_input).to_bytes()),
        };

        Tier2Fixture {
            actor,
            device,
            document,
            publish,
            binding,
            device_signing_key,
        }
    }

    impl Tier2Fixture {
        fn device_multibase(&self) -> String {
            directory_signing_key_multibase(&self.device_signing_key).unwrap()
        }

        /// Build a `keys/query` outcome carrying this fixture's directory facet
        /// + Tier-2 material for the `(actor, device)`.
        fn outcome(&self) -> arkret_sdk::models::KeysQueryOutcome {
            serde_json::from_value(serde_json::json!({
                "device_keys": {
                    self.actor.as_str(): {
                        self.device.as_str(): {
                            "algorithms": {},
                            "device_signing_key": self.device_signing_key,
                            "hpke_key": TIER2_HPKE_KEY,
                            "trust_algorithms": tier2_algorithms(),
                            "device_status": "active",
                            "cross_signing_binding": serde_json::to_value(&self.binding).unwrap(),
                        }
                    }
                },
                "cross_signing": {
                    self.actor.as_str(): serde_json::to_value(&self.publish).unwrap(),
                }
            }))
            .unwrap()
        }
    }

    const TIER2_HPKE_KEY: &str = "z6LSTier2TestHpkeKey";

    fn tier2_algorithms() -> Vec<String> {
        vec![
            "ak.hpke_x25519_aead_chacha20poly1305.v1".to_owned(),
            "ak.mls.v1".to_owned(),
        ]
    }

    const TIER2_ACTOR: &str = "did:web:tier2-alice.example";
    const TIER2_DEVICE: &str = "ak:device:01904100-0000-7000-8000-0000000000a1";

    #[test]
    fn tier2_well_formed_chain_is_cross_signed() {
        let fx = build_tier2_fixture(TIER2_ACTOR, TIER2_DEVICE, 11, 22, 33, 1, 1);
        let state = verify_tier2_chain(
            &fx.document,
            &fx.publish,
            &fx.binding,
            &fx.actor,
            &fx.device,
            &fx.device_multibase(),
            TIER2_HPKE_KEY,
            &tier2_algorithms(),
        );
        assert_eq!(state, DeviceTrustState::CrossSigned);
    }

    #[test]
    fn tier2_accepts_key_only_on_cross_signed() {
        let fx = build_tier2_fixture(TIER2_ACTOR, TIER2_DEVICE, 11, 22, 33, 1, 1);
        let key = tier2_accepted_key(&fx.outcome(), &fx.document, &fx.actor, &fx.device)
            .expect("a CrossSigned chain accepts the directory key");
        assert_eq!(
            key.ed25519_bytes().unwrap(),
            public_key_from_directory_value(&fx.device_signing_key)
                .unwrap()
                .ed25519_bytes()
                .unwrap()
        );
    }

    #[test]
    fn tier2_tampered_device_binding_rejected() {
        let mut fx = build_tier2_fixture(TIER2_ACTOR, TIER2_DEVICE, 11, 22, 33, 1, 1);
        let mut raw = arkret_sdk::base64url_decode(&fx.binding.signature).unwrap();
        raw[0] ^= 0xff;
        fx.binding.signature = base64url_encode(&raw);
        assert_eq!(
            verify_tier2_chain(
                &fx.document,
                &fx.publish,
                &fx.binding,
                &fx.actor,
                &fx.device,
                &fx.device_multibase(),
                TIER2_HPKE_KEY,
                &tier2_algorithms(),
            ),
            DeviceTrustState::Unverified
        );
        // And the acceptance gate yields no key (fail-closed).
        assert!(tier2_accepted_key(&fx.outcome(), &fx.document, &fx.actor, &fx.device).is_none());
    }

    #[test]
    fn tier2_psk_not_matching_did_rejected() {
        // The DID document anchors a DIFFERENT PSK than the publish carries:
        // anchoring fails byte-comparison → Unverified, key rejected.
        let fx = build_tier2_fixture(TIER2_ACTOR, TIER2_DEVICE, 11, 22, 33, 1, 1);
        let wrong_psk = SigningKey::from_bytes(&[99u8; 32]);
        let wrong_doc = DidDocument::new(
            fx.actor.clone(),
            format!("{TIER2_ACTOR}#ak_principal_signing_v1"),
            crate::identity::did_key::encode_ed25519_did_key_multibase(&wrong_psk.verifying_key()),
        );
        assert_eq!(
            verify_tier2_chain(
                &wrong_doc,
                &fx.publish,
                &fx.binding,
                &fx.actor,
                &fx.device,
                &fx.device_multibase(),
                TIER2_HPKE_KEY,
                &tier2_algorithms(),
            ),
            DeviceTrustState::Unverified
        );
        let outcome = fx.outcome();
        assert!(tier2_accepted_key(&outcome, &wrong_doc, &fx.actor, &fx.device).is_none());
    }

    #[test]
    fn tier2_did_anchoring_absent_document_fails_closed() {
        // No DID document for the actor → resolver returns None → no key.
        let fx = build_tier2_fixture(TIER2_ACTOR, TIER2_DEVICE, 11, 22, 33, 1, 1);
        let anchor = TestAnchor {
            documents: HashMap::new(),
        };
        assert!(anchor.resolve_did_document(&fx.actor).is_none());
    }

    #[test]
    fn tier2_stale_generation_needs_reverification() {
        // Accepted publish generation 2, device binding signed under gen 1 →
        // cross-signing reset since → NeedsReverification (not accepted).
        let fx = build_tier2_fixture(TIER2_ACTOR, TIER2_DEVICE, 11, 22, 33, 2, 1);
        assert_eq!(
            verify_tier2_chain(
                &fx.document,
                &fx.publish,
                &fx.binding,
                &fx.actor,
                &fx.device,
                &fx.device_multibase(),
                TIER2_HPKE_KEY,
                &tier2_algorithms(),
            ),
            DeviceTrustState::NeedsReverification
        );
        assert!(tier2_accepted_key(&fx.outcome(), &fx.document, &fx.actor, &fx.device).is_none());
    }

    #[test]
    fn tier2_missing_cross_signing_publish_fails_closed() {
        let fx = build_tier2_fixture(TIER2_ACTOR, TIER2_DEVICE, 11, 22, 33, 1, 1);
        // Strip the per-principal `cross_signing` publish from the outcome.
        let mut outcome = fx.outcome();
        outcome.cross_signing.clear();
        assert!(tier2_accepted_key(&outcome, &fx.document, &fx.actor, &fx.device).is_none());
    }

    #[test]
    fn tier2_missing_device_binding_fails_closed() {
        // Inception bootstrap shape: directory key present, no
        // `cross_signing_binding`. Tier-2 treats missing binding as Unverified
        // (do NOT relax for bootstrap on this line).
        let fx = build_tier2_fixture(TIER2_ACTOR, TIER2_DEVICE, 11, 22, 33, 1, 1);
        let outcome: arkret_sdk::models::KeysQueryOutcome =
            serde_json::from_value(serde_json::json!({
                "device_keys": {
                    fx.actor.as_str(): {
                        fx.device.as_str(): {
                            "algorithms": {},
                            "device_signing_key": fx.device_signing_key,
                            "device_status": "active"
                            // no cross_signing_binding
                        }
                    }
                },
                "cross_signing": {
                    fx.actor.as_str(): serde_json::to_value(&fx.publish).unwrap(),
                }
            }))
            .unwrap();
        assert!(tier2_accepted_key(&outcome, &fx.document, &fx.actor, &fx.device).is_none());
    }

    #[test]
    fn tier2_revoked_device_never_anchors() {
        // Revoked status → Tier-1 facet already negative; Tier-2 never even
        // reaches the chain. No key regardless of valid Tier-2 material.
        let fx = build_tier2_fixture(TIER2_ACTOR, TIER2_DEVICE, 11, 22, 33, 1, 1);
        let outcome: arkret_sdk::models::KeysQueryOutcome =
            serde_json::from_value(serde_json::json!({
                "device_keys": {
                    fx.actor.as_str(): {
                        fx.device.as_str(): {
                            "algorithms": {},
                            "device_status": "revoked",
                            "cross_signing_binding": serde_json::to_value(&fx.binding).unwrap(),
                        }
                    }
                },
                "cross_signing": {
                    fx.actor.as_str(): serde_json::to_value(&fx.publish).unwrap(),
                }
            }))
            .unwrap();
        assert!(tier2_accepted_key(&outcome, &fx.document, &fx.actor, &fx.device).is_none());
    }

    #[test]
    fn tier2_anchor_drives_resolve_to_positive_or_negative() {
        // End-to-end through the TestAnchor: a present, well-formed document
        // → key accepted; the SAME outcome with no document → fail-closed.
        let fx = build_tier2_fixture(TIER2_ACTOR, TIER2_DEVICE, 11, 22, 33, 1, 1);
        let with_doc = TestAnchor {
            documents: HashMap::from([(fx.actor.as_str().to_owned(), fx.document.clone())]),
        };
        let resolved = with_doc.resolve_did_document(&fx.actor).unwrap();
        assert!(tier2_accepted_key(&fx.outcome(), &resolved, &fx.actor, &fx.device).is_some());

        let without = TestAnchor {
            documents: HashMap::new(),
        };
        assert!(without.resolve_did_document(&fx.actor).is_none());
    }
}
