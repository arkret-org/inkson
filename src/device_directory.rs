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
//! - [`resolve_device_signing_key`] is the async path: it calls `keys/query`,
//!   decodes the `did:key` multibase into [`PublicKeyMaterial`], and writes the
//!   result (positive *or* negative) into the cache with a TTL.
//! - [`cached_device_signing_key`] is the sync lookup the receive path uses. It
//!   never blocks; it returns [`CacheLookup::Hit`] / [`CacheLookup::NegativeHit`]
//!   / [`CacheLookup::Miss`].
//! - [`prefetch_device_keys`] primes the cache for a set of `(actor, device)`
//!   pairs (called when a realm's members load / sync), so a normal inbound
//!   invite hits the cache and can be verified inline.
//!
//! ## Negative caching + status semantics
//!
//! Per spec §8.2, "omitted `device_signing_key`" and "`device_status != active`"
//! both mean the device is unusable for verification. Either condition resolves
//! to a *negative* cache entry → [`cached_device_signing_key`] returns
//! `NegativeHit`, and the receive path fail-closed drops the signal. A genuine
//! query error (network / decode) is NOT cached so a transient failure can be
//! retried by the next prefetch.

use std::collections::HashMap;
use std::sync::{LazyLock, RwLock};

use cokret_sdk::signatures::PublicKeyMaterial;

use crate::api::CokretApi;

/// Positive-entry TTL: a resolved key is trusted for this long before a fresh
/// `keys/query` is required. Bounded so a revoke that lands after the key was
/// cached is picked up promptly on the next prefetch.
const POSITIVE_TTL_MS: u64 = 5 * 60 * 1000;

/// Negative-entry TTL: a "no key / revoked / absent" verdict is cached for a
/// shorter window so a freshly-authorized device becomes resolvable quickly.
const NEGATIVE_TTL_MS: u64 = 30 * 1000;

#[derive(Clone)]
struct CacheEntry {
    /// `Some` = authoritative verify key; `None` = negative (revoked / absent /
    /// no key returned).
    key: Option<PublicKeyMaterial>,
    /// `now_unix_ms` at which this entry stops being valid.
    expires_at_ms: u64,
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
    let guard = match CACHE.read() {
        Ok(g) => g,
        Err(poison) => poison.into_inner(),
    };
    match guard.get(&cache_key(actor, device)) {
        Some(entry) if entry.expires_at_ms > now => match &entry.key {
            Some(key) => CacheLookup::Hit(key.clone()),
            None => CacheLookup::NegativeHit,
        },
        _ => CacheLookup::Miss,
    }
}

fn store_entry(actor: &str, device: &str, key: Option<PublicKeyMaterial>) {
    let ttl = if key.is_some() {
        POSITIVE_TTL_MS
    } else {
        NEGATIVE_TTL_MS
    };
    let entry = CacheEntry {
        key,
        expires_at_ms: crate::clock::now_unix_ms().saturating_add(ttl),
    };
    let mut guard = match CACHE.write() {
        Ok(g) => g,
        Err(poison) => poison.into_inner(),
    };
    guard.insert(cache_key(actor, device), entry);
}

/// Decode a directory `device_signing_key` (`did:key` Ed25519 multibase, with
/// or without the `did:key:` prefix) into wire-form [`PublicKeyMaterial`].
/// Returns `None` for an unparseable / wrong-curve value so the caller treats
/// it as "no usable key" (fail-closed).
pub fn public_key_from_directory_value(value: &str) -> Option<PublicKeyMaterial> {
    let multibase = value.trim().strip_prefix("did:key:").unwrap_or(value.trim());
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
    outcome: &cokret_sdk::models::KeysQueryOutcome,
    actor: &str,
    device: &str,
) -> Option<Option<PublicKeyMaterial>> {
    let record = outcome
        .device_keys
        .iter()
        .find(|(did, _)| did.as_str() == actor)
        .and_then(|(_, devices)| {
            devices.iter().find(|(dev, _)| dev.as_str() == device)
        })
        .map(|(_, record)| record)?;

    // Spec §8.2: a non-active status, or an omitted key, both mean unusable.
    let active = matches!(
        record.device_status,
        None | Some(cokret_sdk::models::DeviceStatus::Active)
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

/// Async resolve: query soland for the `(actor, device)` directory record,
/// update the cache (positive or negative), and return the resolved key.
///
/// Returns `Ok(Some(key))` only for an active device with a decodable key;
/// `Ok(None)` for revoked / absent / no-key (a negative cache entry is
/// written); `Err` for a transport / decode failure (NOT cached, so a later
/// prefetch retries).
pub async fn resolve_device_signing_key(
    api: &CokretApi,
    actor: &str,
    device: &str,
) -> anyhow::Result<Option<PublicKeyMaterial>> {
    let outcome = api.query_keys(actor, device).await?;
    // `None` (device absent) and `Some(None)` (revoked / no key) are both
    // negative verdicts for the cache.
    let key = directory_verdict(&outcome, actor, device).unwrap_or(None);
    store_entry(actor, device, key.clone());
    Ok(key)
}

/// Prime the cache for a batch of `(actor, device)` pairs (e.g. a realm's
/// members on load / sync). Pairs already covered by a fresh cache entry are
/// skipped. Best-effort: a per-pair query error is swallowed (left uncached for
/// retry) so one unreachable device never blocks the rest.
pub async fn prefetch_device_keys(api: &CokretApi, pairs: &[(String, String)]) {
    for (actor, device) in pairs {
        if !matches!(cached_device_signing_key(actor, device), CacheLookup::Miss) {
            continue;
        }
        let _ = resolve_device_signing_key(api, actor, device).await;
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
///   2. SDK [`verify_eddsa_detached_jws_proof`] — recomputes the canonical
///      envelope digest, compares it to `proof.event_digest`, rebuilds the
///      binding object `{event_digest, actor_id, verification_method,
///      created_at, domain?, audience?}`, and verifies the detached JWS over it
///      with `public_key`.
pub fn verify_proof_value(
    envelope_without_proof: &serde_json::Value,
    proof_value: &serde_json::Value,
    actor_id: &str,
    public_key: &PublicKeyMaterial,
) -> bool {
    let proof: cokret_sdk::Proof = match serde_json::from_value(proof_value.clone()) {
        Ok(proof) => proof,
        Err(_) => return false,
    };
    // §5.1: the verification_method controller DID MUST equal envelope actor_id.
    if verification_method_controller(&proof.verification_method) != actor_id {
        return false;
    }
    let did = match cokret_sdk::Did::new(actor_id.to_owned()) {
        Ok(did) => did,
        Err(_) => return false,
    };
    let canonical_bytes = match crate::canonical::canonical_json_bytes(envelope_without_proof) {
        Ok(bytes) => bytes,
        Err(_) => return false,
    };
    cokret_sdk::signatures::verify_eddsa_detached_jws_proof(
        &proof,
        &canonical_bytes,
        &did,
        public_key,
    )
    .is_ok()
}

/// Verify an ephemeral call-signal envelope's `proof` (single object).
///
/// Strips the top-level `proof` field, then delegates to [`verify_proof_value`].
/// Returns `false` (fail-closed) when the envelope carries no `actor_id` or no
/// `proof`.
pub fn verify_ephemeral_envelope_proof(
    envelope: &serde_json::Value,
    public_key: &PublicKeyMaterial,
) -> bool {
    let actor_id = match envelope.get("actor_id").and_then(|v| v.as_str()) {
        Some(actor) => actor.to_owned(),
        None => return false,
    };
    let proof_value = match envelope.get("proof") {
        Some(proof) => proof.clone(),
        None => return false,
    };
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
/// `ck.device.revoke` locally) so the next lookup re-queries.
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
    use super::*;
    use ed25519_dalek::SigningKey;

    fn test_did_key(seed: u8) -> String {
        let sk = SigningKey::from_bytes(&[seed; 32]);
        crate::did_key::did_key_from_verifying_key(&sk.verifying_key())
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
        let device = "ck:device:cache-1";
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
        let device = "ck:device:cache-neg";
        store_entry(actor, device, None);
        assert!(matches!(
            cached_device_signing_key(actor, device),
            CacheLookup::NegativeHit
        ));
        invalidate(actor, device);
    }

    const TEST_DEVICE_ID: &str = "ck:device:01904100-0000-7000-8000-000000000001";

    #[test]
    fn directory_verdict_revoked_is_negative_even_with_key() {
        let did = test_did_key(33);
        let outcome: cokret_sdk::models::KeysQueryOutcome = serde_json::from_value(serde_json::json!({
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
        let outcome: cokret_sdk::models::KeysQueryOutcome = serde_json::from_value(serde_json::json!({
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
                public_key_from_directory_value(&did).unwrap().ed25519_bytes().unwrap()
            ),
            _ => panic!("expected active key verdict"),
        }
    }

    #[test]
    fn directory_verdict_absent_device_is_none() {
        let outcome: cokret_sdk::models::KeysQueryOutcome = serde_json::from_value(serde_json::json!({
            "device_keys": {}
        }))
        .unwrap();
        assert!(directory_verdict(&outcome, "did:web:nobody", TEST_DEVICE_ID).is_none());
    }
}
