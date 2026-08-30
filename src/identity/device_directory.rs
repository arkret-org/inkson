//! Fail-closed cache for PCR-authorized device signing keys.

use std::collections::HashMap;
use std::sync::{LazyLock, RwLock};

use arkret_sdk::signatures::PublicKeyMaterial;
use arkret_sdk::{Did, DidDocument};
use arkret_wire::event_kind_str;

use crate::transport::TransportClient;

#[cfg(not(target_arch = "wasm32"))]
pub type DidAnchorFuture<'a> =
    std::pin::Pin<Box<dyn std::future::Future<Output = bool> + Send + 'a>>;
#[cfg(target_arch = "wasm32")]
pub type DidAnchorFuture<'a> = std::pin::Pin<Box<dyn std::future::Future<Output = bool> + 'a>>;

/// Retained for DID-resolution callers. Device authorization no longer reads
/// business authority from the DID document.
pub trait DidAnchor: Send + Sync {
    fn resolve_did_document(&self, actor: &Did) -> Option<DidDocument>;

    fn ensure_actor_document<'a>(
        &'a self,
        http: &'a reqwest::Client,
        actor: &'a Did,
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
    authority: Option<arkret_sdk::AccountId>,
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
    let actor = crate::mls_api_helpers::principal_core_id(actor)
        .map(|actor| actor.to_string())
        .unwrap_or_else(|_| actor.trim().to_owned());
    (actor, device.trim().to_owned())
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

/// Return the exact public authority tuple required to admit a Signal sender.
///
/// A plain cached key is insufficient: the Signal proof also has to be bound
/// to the origin Station whose signed device projection established
/// that key. Entries created without a verified projection attestation are
/// therefore deliberately invisible through this accessor.
pub fn cached_signal_sender_evidence(
    actor: &str,
    device: &str,
) -> Option<(PublicKeyMaterial, arkret_sdk::AccountId)> {
    let now = crate::clock::now_unix_ms();
    let mut guard = CACHE.write().unwrap_or_else(|poison| poison.into_inner());
    let cache_key = cache_key(actor, device);
    match guard.get_mut(&cache_key) {
        Some(entry) if entry.expires_at_ms > now => {
            entry.last_accessed_ms = now;
            Some((entry.key.clone()?, entry.authority.clone()?))
        }
        Some(_) => {
            guard.remove(&cache_key);
            None
        }
        None => None,
    }
}

fn store_entry(
    actor: &str,
    device: &str,
    key: Option<PublicKeyMaterial>,
    authorize_event_id: Option<arkret_sdk::EventId>,
    authority: Option<arkret_sdk::AccountId>,
    attestation_expires_at_ms: Option<u64>,
) {
    let now = crate::clock::now_unix_ms();
    let ttl = if key.is_some() {
        POSITIVE_TTL_MS
    } else {
        NEGATIVE_TTL_MS
    };
    let expires_at_ms = now
        .saturating_add(ttl)
        .min(attestation_expires_at_ms.unwrap_or(u64::MAX));
    let mut guard = CACHE.write().unwrap_or_else(|poison| poison.into_inner());
    guard.retain(|_, entry| entry.expires_at_ms > now);
    let inserted = cache_key(actor, device);
    guard.insert(
        inserted.clone(),
        CacheEntry {
            key,
            authorize_event_id,
            authority,
            expires_at_ms,
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

async fn accepted_device_evidence(
    outcome: &arkret_models_crypto::KeysQueryOutcome,
    anchor: &dyn DidAnchor,
    actor: &str,
    device: &str,
) -> Option<(
    PublicKeyMaterial,
    arkret_sdk::EventId,
    arkret_sdk::AccountId,
    u64,
)> {
    let actor = crate::mls_api_helpers::principal_core_id(actor).ok()?;
    let device = arkret_sdk::DeviceId::new(device.to_owned()).ok()?;
    let record = outcome.device_keys.get(&actor)?.get(&device)?;
    let generation = outcome.device_generations.get(&actor)?;
    if !record.is_usable_in_generation(Some(generation)) {
        return None;
    }
    record.validate_attestation_binding(&actor, &device).ok()?;
    let attestation = &record.device_projection_attestation;
    let method_did =
        arkret_sdk::verification_method_did(attestation.proof.verification_method.as_str()).ok()?;
    let document = match anchor.resolve_did_document(&method_did) {
        Some(document) => document,
        None => {
            let http = reqwest::Client::new();
            if !anchor.ensure_actor_document(&http, &method_did).await {
                return None;
            }
            anchor.resolve_did_document(&method_did)?
        }
    };
    let method = arkret_sdk::resolve_verification_method_key_from_document(
        &document,
        attestation.proof.verification_method.as_str(),
    )
    .ok()?;
    let verifying_key =
        ed25519_dalek::VerifyingKey::from_bytes(&method.public_key.ed25519_bytes().ok()?).ok()?;
    arkret_sdk::signatures::device_projection::verify_device_projection_attestation(
        attestation,
        &verifying_key,
        chrono::Utc::now(),
    )
    .ok()?;
    let key =
        public_key_from_directory_value(attestation.attestation.device_signing_key_did.as_str())?;
    let authority = arkret_sdk::AccountId::new(actor, attestation.attestation.station_id.clone());
    authority.validate().ok()?;
    let expires_at_ms =
        u64::try_from(attestation.attestation.expires_at.timestamp_millis()).ok()?;
    Some((
        key,
        attestation.attestation.device_authorize_event_id.clone(),
        authority,
        expires_at_ms,
    ))
}

pub(crate) async fn cache_accepted_device_evidence_from_outcome(
    outcome: &arkret_models_crypto::KeysQueryOutcome,
    anchor: &dyn DidAnchor,
    actor: &str,
    device: &str,
) -> Option<PublicKeyMaterial> {
    let resolved = accepted_device_evidence(outcome, anchor, actor, device).await;
    let key = resolved.as_ref().map(|(key, ..)| key.clone());
    let authorize_event_id = resolved.as_ref().map(|(_, event_id, ..)| event_id.clone());
    let authority = resolved
        .as_ref()
        .map(|(_, _, authority, _)| authority.clone());
    let attestation_expires_at_ms = resolved.map(|(_, _, _, expires_at_ms)| expires_at_ms);
    store_entry(
        actor,
        device,
        key.clone(),
        authorize_event_id,
        authority,
        attestation_expires_at_ms,
    );
    key
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
    anchor: &dyn DidAnchor,
    actor: &str,
    device: &str,
) -> anyhow::Result<Option<PublicKeyMaterial>> {
    let outcome = crate::transport::keys::query_keys(sdk_http, actor, device).await?;
    Ok(cache_accepted_device_evidence_from_outcome(&outcome, anchor, actor, device).await)
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

fn verification_method_controller_matches_signer(
    verification_method: &str,
    signer_id: &str,
) -> bool {
    let controller = verification_method_controller(verification_method);
    let Ok(controller_core_id) = crate::mls_api_helpers::principal_core_id(controller) else {
        return false;
    };
    let Ok(signer_core_id) = crate::mls_api_helpers::principal_core_id(signer_id) else {
        return false;
    };
    controller_core_id == signer_core_id
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
    let proof: arkret_sdk::ProducerEventProof = serde_json::from_value(proof_value.clone())
        .map_err(|error| format!("decode Event proof: {error}"))?;
    if !verification_method_controller_matches_signer(&proof.verification_method, signer_id) {
        return Err("Event proof verification-method controller differs from signer".to_owned());
    }
    let actor_id = serde_json::from_value::<arkret_sdk::ActorId>(
        envelope_without_proof
            .get("actor_id")
            .cloned()
            .ok_or_else(|| "Event binding omits actor_id".to_owned())?,
    )
    .map_err(|error| format!("invalid Event binding actor_id: {error}"))?;
    if actor_id.signing_principal_id().as_str() != binding_actor_id {
        return Err("Event binding actor differs from requested actor".to_owned());
    }
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
    let controller_matches_sender = arkret_sdk::Did::new(controller.to_owned())
        .ok()
        .and_then(|did| arkret_sdk::project_did_to_core_id(&did).ok())
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
    let Some(actor_id) = envelope
        .get("actor_id")
        .and_then(|value| serde_json::from_value::<arkret_sdk::ActorId>(value.clone()).ok())
    else {
        return false;
    };
    let actor_principal = actor_id.signing_principal_id().as_str();
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
        .any(|proof| verify_proof_value(&preimage, proof, actor_principal, public_key))
}

pub fn is_device_frontier_event_kind(kind: &str) -> bool {
    matches!(
        kind,
        event_kind_str::DEVICE_AUTHORIZE
            | event_kind_str::DEVICE_REVOKE
            | event_kind_str::DEVICE_REANCHOR
            | event_kind_str::DEVICE_LIST_UPDATE
    )
}

pub fn invalidate_actor(actor: &str) -> usize {
    let actor = actor.trim();
    if actor.is_empty() {
        return 0;
    }
    let canonical_actor = cache_key(actor, "").0;
    let mut guard = CACHE.write().unwrap_or_else(|poison| poison.into_inner());
    let before = guard.len();
    guard.retain(|(cached_actor, _), _| cached_actor != &canonical_actor);
    before - guard.len()
}

#[cfg(test)]
pub(crate) fn seed_positive_for_test(actor: &str, device: &str, key: PublicKeyMaterial) {
    store_entry(actor, device, Some(key), None, None, None);
}

#[cfg(test)]
pub(crate) fn seed_device_authorization_for_test(
    actor: &str,
    device: &str,
    key: PublicKeyMaterial,
    authorize_event_id: arkret_sdk::EventId,
) {
    store_entry(
        actor,
        device,
        Some(key),
        Some(authorize_event_id),
        None,
        None,
    );
}

#[cfg(test)]
pub(crate) fn seed_signal_sender_for_test(
    actor: &str,
    device: &str,
    key: PublicKeyMaterial,
    authority: arkret_sdk::AccountId,
) {
    store_entry(actor, device, Some(key), None, Some(authority), None);
}

#[cfg(test)]
pub(crate) fn seed_negative_for_test(actor: &str, device: &str) {
    store_entry(actor, device, None, None, None, None);
}

#[cfg(test)]
mod verification_method_controller_tests {
    use super::{
        cached_device_authorize_event_id, seed_device_authorization_for_test,
        verification_method_controller_matches_signer,
    };

    #[test]
    fn accepts_the_same_principal_in_full_and_core_forms() {
        let full = "did:webvh:zfixture:alice.example";
        let core = crate::mls_api_helpers::principal_core_id(full).expect("core id");
        let method = format!("{full}#ak:device:01904100-0000-7000-8000-0000000000a1");

        assert!(verification_method_controller_matches_signer(&method, full));
        assert!(verification_method_controller_matches_signer(
            &method,
            core.as_str()
        ));
    }

    #[test]
    fn device_authorization_cache_uses_the_projected_principal_identity() {
        let full = "did:webvh:zfixture:alice.example";
        let core = crate::mls_api_helpers::principal_core_id(full).expect("core id");
        let device = "ak:device:01904100-0000-7000-8000-0000000000a1";
        let event_id = arkret_sdk::EventId::new(
            "ak:event:AYvJpYtKqkEnnh-tjkBxu6DGwtce4dQAf8RyXfTIRLIj".to_owned(),
        )
        .expect("event id");
        let key = super::public_key_from_directory_value(
            "did:key:z6MkhHrTbtosB4xyyJM217fS4ry35F7JhZ5oA9uVHErBJDL5",
        )
        .expect("key");

        seed_device_authorization_for_test(full, device, key, event_id.clone());

        assert_eq!(
            cached_device_authorize_event_id(core.as_str(), device),
            Some(event_id)
        );
    }

    #[test]
    fn rejects_a_different_principal() {
        assert!(!verification_method_controller_matches_signer(
            "did:webvh:zfixture:alice.example#ak:device:01904100-0000-7000-8000-0000000000a1",
            "did:webvh:zmallory:mallory.example",
        ));
    }
}
