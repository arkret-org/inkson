//! Fail-closed cache for PCR-authorized device signing keys.

use std::collections::HashMap;
use std::sync::{LazyLock, RwLock};

use arkret_sdk::signatures::PublicKeyMaterial;

use super::verification_method_controller;
use crate::transport::TransportClient;

const POSITIVE_TTL_MS: u64 = 5 * 60 * 1000;
const NEGATIVE_TTL_MS: u64 = 30 * 1000;
const MAX_CACHE_ENTRIES: usize = 4096;

#[derive(Clone)]
struct VerifiedProjectionVersion {
    generation_ref: u64,
    attested_at: chrono::DateTime<chrono::Utc>,
    projection_digest: String,
}

impl VerifiedProjectionVersion {
    fn position(&self) -> (u64, chrono::DateTime<chrono::Utc>) {
        (self.generation_ref, self.attested_at)
    }
}

#[derive(Clone)]
struct CacheEntry {
    key: Option<PublicKeyMaterial>,
    authorize_event_id: Option<arkret_sdk::EventId>,
    verified_projection: Option<VerifiedProjectionVersion>,
    expires_at_ms: u64,
    last_accessed_ms: u64,
}

type CacheKey = (arkret_sdk::AccountId, String);
#[derive(Default)]
struct DeviceKeyCache {
    epoch: u64,
    entries: HashMap<CacheKey, CacheEntry>,
}

impl std::ops::Deref for DeviceKeyCache {
    type Target = HashMap<CacheKey, CacheEntry>;

    fn deref(&self) -> &Self::Target {
        &self.entries
    }
}

impl std::ops::DerefMut for DeviceKeyCache {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.entries
    }
}

static CACHE: LazyLock<RwLock<DeviceKeyCache>> =
    LazyLock::new(|| RwLock::new(DeviceKeyCache::default()));

pub(crate) fn cache_epoch() -> u64 {
    CACHE
        .read()
        .unwrap_or_else(|poison| poison.into_inner())
        .epoch
}

pub(crate) fn reset_session_cache() {
    let mut cache = CACHE.write().unwrap_or_else(|poison| poison.into_inner());
    cache.epoch = cache.epoch.wrapping_add(1);
    cache.entries.clear();
}

#[derive(Clone)]
pub enum CacheLookup {
    Hit(PublicKeyMaterial),
    NegativeHit,
    Miss,
}

pub(crate) fn account_from_selector(actor: &str) -> Option<arkret_sdk::AccountId> {
    crate::mls_api_helpers::account_id_from_selector(actor)
}

fn cache_key(actor: &str, device: &str) -> Option<CacheKey> {
    Some((account_from_selector(actor)?, device.trim().to_owned()))
}

pub fn cached_device_signing_key(actor: &str, device: &str) -> CacheLookup {
    let now = crate::clock::now_unix_ms();
    let mut guard = CACHE.write().unwrap_or_else(|poison| poison.into_inner());
    let Some(key) = cache_key(actor, device) else {
        return CacheLookup::Miss;
    };
    match guard.get_mut(&key) {
        Some(entry) if entry.expires_at_ms > now => {
            entry.last_accessed_ms = now;
            match &entry.key {
                Some(key) => CacheLookup::Hit(key.clone()),
                None => CacheLookup::NegativeHit,
            }
        }
        Some(_) => CacheLookup::Miss,
        None => CacheLookup::Miss,
    }
}

/// A retained authenticated negative projection remains a local revocation fence
/// after its ordinary lookup TTL; Signal delivery cannot resurrect it.
pub(crate) fn known_device_revoked(actor: &str, device: &str) -> bool {
    let Some(key) = cache_key(actor, device) else {
        return true;
    };
    CACHE
        .read()
        .unwrap_or_else(|poison| poison.into_inner())
        .get(&key)
        .is_some_and(|entry| entry.key.is_none() && entry.verified_projection.is_some())
}

pub fn cached_device_authorize_event_id(actor: &str, device: &str) -> Option<arkret_sdk::EventId> {
    let now = crate::clock::now_unix_ms();
    let guard = CACHE.read().unwrap_or_else(|poison| poison.into_inner());
    guard
        .get(&cache_key(actor, device)?)
        .filter(|entry| entry.expires_at_ms > now && entry.key.is_some())
        .and_then(|entry| entry.authorize_event_id.clone())
}

fn store_entry_at_epoch(
    expected_epoch: u64,
    actor: &str,
    device: &str,
    key: Option<PublicKeyMaterial>,
    authorize_event_id: Option<arkret_sdk::EventId>,
    attestation_expires_at_ms: Option<u64>,
    verified_projection: Option<VerifiedProjectionVersion>,
) -> bool {
    let Some(inserted) = cache_key(actor, device) else {
        return false;
    };
    let now = crate::clock::now_unix_ms();
    let ttl = if key.is_some() {
        POSITIVE_TTL_MS
    } else {
        NEGATIVE_TTL_MS
    };
    let expires_at_ms = now
        .saturating_add(ttl)
        .min(attestation_expires_at_ms.unwrap_or(u64::MAX));
    if key.is_some() && expires_at_ms <= now {
        return false;
    }
    let mut guard = CACHE.write().unwrap_or_else(|poison| poison.into_inner());
    if guard.epoch != expected_epoch {
        return false;
    }
    // Retain bounded in-memory watermarks after TTL or invalidation so an
    // out-of-order response cannot revive an already superseded projection.
    guard.retain(|_, entry| entry.expires_at_ms > now || entry.verified_projection.is_some());
    if let Some(incoming) = &verified_projection {
        if guard.iter().any(|((account, _), entry)| {
            account == &inserted.0
                && entry
                    .verified_projection
                    .as_ref()
                    .is_some_and(|retained| retained.generation_ref > incoming.generation_ref)
        }) {
            return false;
        }
        for ((account, _), entry) in guard.iter_mut() {
            if account == &inserted.0
                && entry
                    .verified_projection
                    .as_ref()
                    .is_some_and(|retained| retained.generation_ref < incoming.generation_ref)
            {
                entry.key = None;
                entry.authorize_event_id = None;
                entry.expires_at_ms = now;
            }
        }
    }
    if let Some(previous) = guard.get_mut(&inserted)
        && let (Some(incoming), Some(retained)) =
            (&verified_projection, &previous.verified_projection)
    {
        if incoming.position() < retained.position() {
            return false;
        }
        if incoming.position() == retained.position() {
            if incoming.projection_digest != retained.projection_digest {
                previous.key = None;
                previous.authorize_event_id = None;
                previous.expires_at_ms = now.saturating_add(NEGATIVE_TTL_MS);
                return false;
            }
            if previous.key.is_none() {
                return false;
            }
        }
    }
    let verified_projection = verified_projection.or_else(|| {
        guard
            .get(&inserted)
            .and_then(|previous| previous.verified_projection.clone())
    });
    guard.insert(
        inserted.clone(),
        CacheEntry {
            key,
            authorize_event_id,
            verified_projection,
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
    true
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

fn accepted_device_evidence(
    outcome: &arkret_models_crypto::KeysQueryOutcome,
    account_id: &arkret_sdk::AccountId,
    device: &str,
) -> Option<(
    PublicKeyMaterial,
    arkret_sdk::EventId,
    arkret_sdk::AccountId,
    u64,
    VerifiedProjectionVersion,
)> {
    let device = arkret_sdk::DeviceId::new(device.to_owned()).ok()?;
    let record = outcome.devices_for(account_id)?.get(&device)?;
    let generation = outcome.generation_for(account_id)?;
    if !record.is_usable_in_generation(Some(generation)) {
        return None;
    }
    record
        .validate_attestation_binding(account_id, &device)
        .ok()?;
    let attestation = &record.device_projection_attestation;
    let now = chrono::Utc::now();
    if attestation.attestation.attested_at > now || now >= attestation.attestation.expires_at {
        return None;
    }
    let key =
        public_key_from_directory_value(attestation.attestation.device_signing_key_did.as_str())?;
    let authority = attestation.attestation.account_id.clone();
    authority.validate().ok()?;
    let expires_at_ms =
        u64::try_from(attestation.attestation.expires_at.timestamp_millis()).ok()?;
    let version = VerifiedProjectionVersion {
        generation_ref: attestation.attestation.authorized_generation_ref,
        attested_at: attestation.attestation.attested_at,
        projection_digest: arkret_sdk::canonical::canonical_sha256(&attestation.attestation)
            .ok()?,
    };
    Some((
        key,
        attestation.attestation.device_authorize_event_id.clone(),
        authority,
        expires_at_ms,
        version,
    ))
}

pub(crate) fn cache_accepted_device_evidence_from_outcome(
    expected_epoch: u64,
    outcome: &arkret_models_crypto::KeysQueryOutcome,
    account_id: &arkret_sdk::AccountId,
    device: &str,
) -> Option<PublicKeyMaterial> {
    let resolved = accepted_device_evidence(outcome, account_id, device);
    let key = resolved.as_ref().map(|(key, ..)| key.clone());
    let authorize_event_id = resolved.as_ref().map(|(_, event_id, ..)| event_id.clone());
    let attestation_expires_at_ms = resolved
        .as_ref()
        .map(|(_, _, _, expires_at_ms, _)| *expires_at_ms);
    let version = resolved.map(|(_, _, _, _, version)| version);
    let stored = store_entry_at_epoch(
        expected_epoch,
        &account_id.to_string(),
        device,
        key.clone(),
        authorize_event_id,
        attestation_expires_at_ms,
        version,
    );
    stored.then_some(key).flatten()
}

pub async fn resolve_device_signing_key(
    api: &TransportClient,
    actor: &str,
    device: &str,
) -> anyhow::Result<Option<PublicKeyMaterial>> {
    resolve_device_signing_key_with_http(&api.sdk_http_client()?, actor, device).await
}

pub async fn resolve_device_signing_key_with_http(
    sdk_http: &arkret_sdk::http_client::Client,
    actor: &str,
    device: &str,
) -> anyhow::Result<Option<PublicKeyMaterial>> {
    let account_id = account_from_selector(actor).ok_or_else(|| {
        anyhow::anyhow!(
            "device query requires an exact AccountId; a bare DID has no Station binding"
        )
    })?;
    let expected_epoch = cache_epoch();
    let outcome = crate::transport::keys::query_keys(sdk_http, &account_id, device).await?;
    Ok(cache_accepted_device_evidence_from_outcome(
        expected_epoch,
        &outcome,
        &account_id,
        device,
    ))
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

pub fn invalidate_actor(actor: &str) -> usize {
    let actor = actor.trim();
    if actor.is_empty() {
        return 0;
    }
    let mut guard = CACHE.write().unwrap_or_else(|poison| poison.into_inner());
    guard.epoch = guard.epoch.wrapping_add(1);
    let account = account_from_selector(actor);
    let principal = crate::mls_api_helpers::principal_core_id(actor).ok();
    let mut invalidated = 0;
    for ((cached_account, _), entry) in guard.iter_mut() {
        if account
            .as_ref()
            .is_some_and(|account| cached_account == account)
            || principal
                .as_ref()
                .is_some_and(|principal| &cached_account.principal_id == principal)
        {
            entry.key = None;
            entry.authorize_event_id = None;
            entry.expires_at_ms = crate::clock::now_unix_ms();
            invalidated += 1;
        }
    }
    invalidated
}

#[cfg(test)]
fn store_entry(
    actor: &str,
    device: &str,
    key: Option<PublicKeyMaterial>,
    authorize_event_id: Option<arkret_sdk::EventId>,
    expires_at: Option<u64>,
    version: Option<VerifiedProjectionVersion>,
) -> bool {
    store_entry_at_epoch(
        cache_epoch(),
        actor,
        device,
        key,
        authorize_event_id,
        expires_at,
        version,
    )
}

#[cfg(test)]
fn test_account_selector(actor: &str) -> String {
    account_from_selector(actor)
        .map(|account| account.to_string())
        .unwrap_or_else(|| {
            crate::mls_api_helpers::local_account_actor_id(actor)
                .expect("test fixture requires an account actor")
                .to_string()
        })
}

#[cfg(test)]
pub(crate) fn seed_positive_for_test(actor: &str, device: &str, key: PublicKeyMaterial) {
    store_entry(
        &test_account_selector(actor),
        device,
        Some(key),
        None,
        None,
        None,
    );
}

#[cfg(test)]
pub(crate) fn seed_device_authorization_for_test(
    actor: &str,
    device: &str,
    key: PublicKeyMaterial,
    authorize_event_id: arkret_sdk::EventId,
) {
    store_entry(
        &test_account_selector(actor),
        device,
        Some(key),
        Some(authorize_event_id),
        None,
        None,
    );
}

#[cfg(test)]
pub(crate) fn seed_negative_for_test(actor: &str, device: &str) {
    store_entry(
        &test_account_selector(actor),
        device,
        None,
        None,
        None,
        None,
    );
}

#[cfg(test)]
mod verification_method_controller_tests {
    use super::{
        cached_device_authorize_event_id, seed_device_authorization_for_test,
        verification_method_controller_matches_signer,
    };

    #[test]
    fn trusted_device_result_requires_exact_binding_and_current_generation() {
        let station_did = arkret_sdk::Did::new("did:web:projection-station.example").unwrap();
        let method = arkret_sdk::DidUrl::new(format!("{station_did}#assertion")).unwrap();
        let account = arkret_sdk::AccountId::new(
            arkret_sdk::DidCoreId::new("ak:did_core:web:projection-principal.example").unwrap(),
            arkret_sdk::project_did_to_core_id(&station_did).unwrap(),
        );
        let device =
            arkret_sdk::DeviceId::new("ak:device:0196419b-0000-7000-8000-000000000001").unwrap();
        let now = arkret_sdk::canonical::normalize_timestamp_canonical(chrono::Utc::now());
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[43u8; 32]);
        let public_key =
            arkret_sdk::ed25519_pubkey_to_did_key_multibase(signing_key.verifying_key().as_bytes());
        let attestation =
            arkret_sdk::signatures::device_projection::sign_device_projection_attestation(
                arkret_models_crypto::DeviceProjectionAttestationCore {
                    account_id: account.clone(),
                    device_id: device.clone(),
                    device_signing_key_did: arkret_sdk::DidKey::new(format!(
                        "did:key:{public_key}"
                    ))
                    .unwrap(),
                    hpke_key: arkret_sdk::NonEmptyString::new("hpke-test").unwrap(),
                    device_authorize_event_id: arkret_sdk::EventId::new(
                        "ak:event:AfAnsJqSlM9bHVI7P1QBMOEW3p5P1PNQu7BBMpiSnD_e",
                    )
                    .unwrap(),
                    authorized_generation_ref: 7,
                    device_status: arkret_models_crypto::DeviceStatus::Active,
                    attested_at: now,
                    expires_at: now + chrono::Duration::minutes(5),
                },
                method.clone(),
                &signing_key,
            )
            .unwrap();
        let mut outcome: arkret_models_crypto::KeysQueryOutcome =
            serde_json::from_value(serde_json::json!({
                "device_keys": [{"account_id": account, "device_keys": {
                    device.as_str(): {
                        "signer_evidence_ref": "ak:signer_evidence:sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                        "algorithms": {}, "trust_algorithms": [],
                        "device_projection_attestation": attestation
                    }
                }}],
                "failures": [],
                "device_generations": [{"account_id": account, "generation_state": {
                    "current_device_generation_ref": 7,
                    "device_generation_status": "active"
                }}]
            }))
            .unwrap();
        assert!(super::accepted_device_evidence(&outcome, &account, device.as_str()).is_some());
        let other_device = "ak:device:0196419b-0000-7000-8000-000000000002";
        assert!(super::accepted_device_evidence(&outcome, &account, other_device).is_none());
        outcome.device_generations[0]
            .generation_state
            .current_device_generation_ref = 8;
        assert!(super::accepted_device_evidence(&outcome, &account, device.as_str()).is_none());
        outcome.device_generations[0]
            .generation_state
            .current_device_generation_ref = 7;
        outcome.device_keys[0]
            .device_keys
            .get_mut(&device)
            .unwrap()
            .device_projection_attestation
            .attestation
            .expires_at = now;
        assert!(super::accepted_device_evidence(&outcome, &account, device.as_str()).is_none());
    }

    #[test]
    fn verified_projection_cache_rejects_rollback_conflict_and_revoked_replay() {
        let account = arkret_sdk::AccountId::new(
            arkret_sdk::DidCoreId::new("ak:did_core:web:cache-watermark.example").unwrap(),
            arkret_sdk::DidCoreId::new("ak:did_core:web:station-watermark.example").unwrap(),
        )
        .to_string();
        let key = super::public_key_from_directory_value(
            "did:key:z6MkhHrTbtosB4xyyJM217fS4ry35F7JhZ5oA9uVHErBJDL5",
        )
        .unwrap();
        let at = chrono::DateTime::<chrono::Utc>::from_timestamp(1_800_000_000, 0).unwrap();
        let insert = |device: &str, generation_ref, offset, digest: &str| {
            super::store_entry(
                &account,
                device,
                Some(key.clone()),
                None,
                None,
                Some(super::VerifiedProjectionVersion {
                    generation_ref,
                    attested_at: at + chrono::Duration::seconds(offset),
                    projection_digest: digest.to_owned(),
                }),
            )
        };
        assert!(insert("first", 7, 0, "first-7"));
        assert!(insert("second", 8, 1, "second-8"));
        assert!(!matches!(
            super::cached_device_signing_key(&account, "first"),
            super::CacheLookup::Hit(_)
        ));
        assert!(!insert("first", 7, 2, "late-generation-7"));
        assert!(!insert("second", 8, 0, "late-time"));
        assert!(!insert("second", 8, 1, "conflicting-projection"));
        assert!(!insert("second", 8, 1, "second-8"));
        assert!(insert("second", 8, 2, "fresh-projection"));
        super::invalidate_actor(&account);
        assert!(!insert("second", 8, 2, "fresh-projection"));
        assert!(insert("second", 8, 3, "after-invalidation"));
        assert!(!super::store_entry(
            &account,
            "expired",
            Some(key),
            None,
            Some(crate::clock::now_unix_ms().saturating_sub(1)),
            None
        ));
        super::invalidate_actor(&account);
    }

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
    fn device_authorization_cache_binds_the_exact_account() {
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
        let account = arkret_sdk::AccountId::new(
            core.clone(),
            crate::operation::authoring_station_id().unwrap(),
        );
        let other = arkret_sdk::AccountId::new(
            core.clone(),
            arkret_sdk::DidCoreId::new("ak:did_core:web:other.example").unwrap(),
        );

        assert_eq!(
            cached_device_authorize_event_id(&account.to_string(), device),
            Some(event_id)
        );
        assert_eq!(
            cached_device_authorize_event_id(&other.to_string(), device),
            None
        );
        assert_eq!(
            cached_device_authorize_event_id(core.as_str(), device),
            None
        );
        assert_eq!(cached_device_authorize_event_id(full, device), None);
    }

    #[test]
    fn rejects_a_different_principal() {
        assert!(!verification_method_controller_matches_signer(
            "did:webvh:zfixture:alice.example#ak:device:01904100-0000-7000-8000-0000000000a1",
            "did:webvh:zmallory:mallory.example",
        ));
    }
}
