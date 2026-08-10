//! Fail-closed cache for PCR-authorized device signing keys.

use std::collections::HashMap;
use std::sync::{LazyLock, RwLock};

use arkret_sdk::signatures::PublicKeyMaterial;
use arkret_sdk::{DidDocument, DidFullId};

use crate::transport::TransportClient;

#[cfg(not(target_arch = "wasm32"))]
pub type DidAnchorFuture<'a> =
    std::pin::Pin<Box<dyn std::future::Future<Output = bool> + Send + 'a>>;
#[cfg(target_arch = "wasm32")]
pub type DidAnchorFuture<'a> = std::pin::Pin<Box<dyn std::future::Future<Output = bool> + 'a>>;

/// Retained for DID-resolution callers. Device authorization no longer reads
/// business authority from the DID document.
pub trait DidAnchor: Send + Sync {
    fn resolve_did_document(&self, actor: &DidFullId) -> Option<DidDocument>;

    fn ensure_actor_document<'a>(
        &'a self,
        http: &'a reqwest::Client,
        actor: &'a DidFullId,
    ) -> DidAnchorFuture<'a> {
        let _ = (http, actor);
        Box::pin(async { true })
    }
}

const POSITIVE_TTL_MS: u64 = 5 * 60 * 1000;
const NEGATIVE_TTL_MS: u64 = 30 * 1000;
const MAX_CACHE_ENTRIES: usize = 4096;

#[derive(Clone)]
struct CacheEntry {
    key: Option<PublicKeyMaterial>,
    authorize_event_id: Option<arkret_sdk::EventId>,
    expires_at_ms: u64,
    last_accessed_ms: u64,
}

type CacheKey = (String, String);
static CACHE: LazyLock<RwLock<HashMap<CacheKey, CacheEntry>>> =
    LazyLock::new(|| RwLock::new(HashMap::new()));

#[derive(Clone)]
pub enum CacheLookup {
    Hit(PublicKeyMaterial),
    NegativeHit,
    Miss,
}

fn cache_key(actor: &str, device: &str) -> CacheKey {
    (actor.to_owned(), device.to_owned())
}

pub fn cached_device_signing_key(actor: &str, device: &str) -> CacheLookup {
    let now = crate::clock::now_unix_ms();
    let mut guard = CACHE.write().unwrap_or_else(|poison| poison.into_inner());
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

pub fn cached_device_authorize_event_id(actor: &str, device: &str) -> Option<arkret_sdk::EventId> {
    let now = crate::clock::now_unix_ms();
    let guard = CACHE.read().unwrap_or_else(|poison| poison.into_inner());
    guard
        .get(&cache_key(actor, device))
        .filter(|entry| entry.expires_at_ms > now && entry.key.is_some())
        .and_then(|entry| entry.authorize_event_id.clone())
}

fn store_entry(
    actor: &str,
    device: &str,
    key: Option<PublicKeyMaterial>,
    authorize_event_id: Option<arkret_sdk::EventId>,
) {
    let now = crate::clock::now_unix_ms();
    let ttl = if key.is_some() {
        POSITIVE_TTL_MS
    } else {
        NEGATIVE_TTL_MS
    };
    let mut guard = CACHE.write().unwrap_or_else(|poison| poison.into_inner());
    guard.retain(|_, entry| entry.expires_at_ms > now);
    let inserted = cache_key(actor, device);
    guard.insert(
        inserted.clone(),
        CacheEntry {
            key,
            authorize_event_id,
            expires_at_ms: now.saturating_add(ttl),
            last_accessed_ms: now,
        },
    );
    while guard.len() > MAX_CACHE_ENTRIES {
        let victim = guard
            .iter()
            .filter(|(candidate, _)| *candidate != &inserted)
            .min_by_key(|(_, entry)| (entry.last_accessed_ms, entry.expires_at_ms))
            .map(|(key, _)| key.clone())
            .or_else(|| guard.keys().next().cloned());
        let Some(victim) = victim else { break };
        guard.remove(&victim);
    }
}

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
    material.ed25519_bytes().ok()?;
    Some(material)
}

fn accepted_device_key(
    outcome: &arkret_models_crypto::KeysQueryOutcome,
    actor: &str,
    device: &str,
) -> Option<(PublicKeyMaterial, arkret_sdk::EventId)> {
    let actor = crate::mls_api_helpers::principal_core_id(actor).ok()?;
    let device = arkret_sdk::DeviceId::new(device.to_owned()).ok()?;
    let record = outcome.device_keys.get(&actor)?.get(&device)?;
    let generation = outcome.device_generations.get(&actor)?;
    if !record.is_usable_in_generation(Some(generation)) {
        return None;
    }
    let key = record
        .device_signing_key
        .as_deref()
        .and_then(public_key_from_directory_value)?;
    Some((key, record.device_authorize_event_id.clone()?))
}

pub async fn resolve_device_signing_key(
    api: &TransportClient,
    anchor: &dyn DidAnchor,
    actor: &str,
    device: &str,
) -> anyhow::Result<Option<PublicKeyMaterial>> {
    resolve_device_signing_key_with_http(&api.sdk_http_client()?, anchor, actor, device).await
}

pub async fn resolve_device_signing_key_with_http(
    sdk_http: &arkret_sdk::http_client::Client,
    _anchor: &dyn DidAnchor,
    actor: &str,
    device: &str,
) -> anyhow::Result<Option<PublicKeyMaterial>> {
    let outcome = crate::transport::keys::query_keys(sdk_http, actor, device).await?;
    let resolved = accepted_device_key(&outcome, actor, device);
    let key = resolved.as_ref().map(|(key, _)| key.clone());
    let authorize_event_id = resolved.map(|(_, event_id)| event_id);
    store_entry(actor, device, key.clone(), authorize_event_id);
    Ok(key)
}

pub async fn refresh_device_keys(
    api: &TransportClient,
    anchor: &dyn DidAnchor,
    pairs: &[(String, String)],
) {
    for (actor, device) in pairs {
        let _ = resolve_device_signing_key(api, anchor, actor, device).await;
    }
}

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

pub fn verify_proof_value(
    envelope_without_proof: &serde_json::Value,
    proof_value: &serde_json::Value,
    actor_id: &str,
    public_key: &PublicKeyMaterial,
) -> bool {
    verify_proof_value_for_signer(
        envelope_without_proof,
        proof_value,
        actor_id,
        actor_id,
        public_key,
    )
}

pub fn verify_proof_value_for_signer(
    envelope_without_proof: &serde_json::Value,
    proof_value: &serde_json::Value,
    signer_id: &str,
    binding_actor_id: &str,
    public_key: &PublicKeyMaterial,
) -> bool {
    verify_proof_value_for_signer_result(
        envelope_without_proof,
        proof_value,
        signer_id,
        binding_actor_id,
        public_key,
    )
    .is_ok()
}

pub fn verify_proof_value_for_signer_result(
    envelope_without_proof: &serde_json::Value,
    proof_value: &serde_json::Value,
    signer_id: &str,
    binding_actor_id: &str,
    public_key: &PublicKeyMaterial,
) -> Result<(), String> {
    verify_proof_value_for_signer_result_with_digest_suite(
        envelope_without_proof,
        proof_value,
        signer_id,
        binding_actor_id,
        public_key,
        arkret_sdk::canonical::DigestSuite::Sha256,
    )
}

pub fn verify_proof_value_for_signer_result_with_digest_suite(
    envelope_without_proof: &serde_json::Value,
    proof_value: &serde_json::Value,
    signer_id: &str,
    binding_actor_id: &str,
    public_key: &PublicKeyMaterial,
    digest_suite: arkret_sdk::canonical::DigestSuite,
) -> Result<(), String> {
    let proof: arkret_sdk::Proof = serde_json::from_value(proof_value.clone())
        .map_err(|error| format!("decode Event proof: {error}"))?;
    let controller = verification_method_controller(&proof.verification_method);
    let controller_matches_signer = arkret_sdk::DidFullId::new(controller.to_owned())
        .ok()
        .and_then(|full_id| arkret_sdk::project_full_id_to_core_id(&full_id).ok())
        .is_some_and(|core_id| core_id.as_str() == signer_id);
    if !controller_matches_signer {
        return Err("Event proof verification-method controller differs from signer".to_owned());
    }
    let actor_id = arkret_sdk::DidCoreId::new(binding_actor_id.to_owned())
        .map_err(|error| format!("invalid Event binding actor core_id: {error}"))?;
    let canonical_bytes = crate::canonical::canonical_json_bytes(envelope_without_proof)
        .map_err(|error| format!("canonicalize Event proof envelope: {error}"))?;
    arkret_sdk::signatures::verify_ed25519_detached_jws_proof_with_digest_suite(
        &proof,
        &canonical_bytes,
        &actor_id,
        public_key,
        digest_suite,
    )
    .map_err(|error| error.to_string())
}

pub fn verify_signal_envelope_proof(
    envelope: &arkret_wire::SignalEnvelope,
    public_key: &PublicKeyMaterial,
) -> bool {
    verify_signal_envelope_proof_at(envelope, public_key, chrono::Utc::now())
}

pub fn verify_signal_envelope_proof_at(
    envelope: &arkret_wire::SignalEnvelope,
    public_key: &PublicKeyMaterial,
    now: chrono::DateTime<chrono::Utc>,
) -> bool {
    let controller = verification_method_controller(&envelope.proof.verification_method);
    let controller_matches_sender = arkret_sdk::DidFullId::new(controller.to_owned())
        .ok()
        .and_then(|full_id| arkret_sdk::project_full_id_to_core_id(&full_id).ok())
        .is_some_and(|core_id| core_id == envelope.sender_actor_id);
    if envelope.validate_structural().is_err()
        || !controller_matches_sender
        || envelope.expires_at <= now
    {
        return false;
    }
    let Ok(expected_digest) = envelope.envelope_digest() else {
        return false;
    };
    if envelope.proof.envelope_digest != expected_digest {
        return false;
    }
    let Ok(binding_bytes) = envelope.proof_binding_bytes() else {
        return false;
    };
    arkret_sdk::signatures::proof::Ed25519DetachedJwsVerifier::new()
        .verify_detached_jws(&envelope.proof.jws, &binding_bytes, public_key)
        .is_ok()
}

pub fn verify_persistent_envelope_proofs(
    envelope: &serde_json::Value,
    public_key: &PublicKeyMaterial,
) -> bool {
    let Some(actor_id) = envelope.get("actor_id").and_then(|value| value.as_str()) else {
        return false;
    };
    let Some(proofs) = envelope.get("proofs").and_then(|value| value.as_array()) else {
        return false;
    };
    if proofs.is_empty() {
        return false;
    }
    let Ok(preimage) = arkret_sdk::event_digest_preimage(envelope) else {
        return false;
    };
    proofs
        .iter()
        .any(|proof| verify_proof_value(&preimage, proof, actor_id, public_key))
}

pub fn is_device_frontier_event_kind(kind: &str) -> bool {
    matches!(
        kind,
        "ak.device.authorize" | "ak.device.revoke" | "ak.device.reanchor" | "ak.device.list_update"
    )
}

pub fn invalidate_actor(actor: &str) -> usize {
    let actor = actor.trim();
    if actor.is_empty() {
        return 0;
    }
    let mut guard = CACHE.write().unwrap_or_else(|poison| poison.into_inner());
    let before = guard.len();
    guard.retain(|(cached_actor, _), _| cached_actor != actor);
    before - guard.len()
}

#[cfg(test)]
pub(crate) fn seed_positive_for_test(actor: &str, device: &str, key: PublicKeyMaterial) {
    store_entry(actor, device, Some(key), None);
}

#[cfg(test)]
pub(crate) fn seed_negative_for_test(actor: &str, device: &str) {
    store_entry(actor, device, None, None);
}
