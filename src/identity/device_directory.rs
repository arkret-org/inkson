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
    signer_evidence_ref: Option<arkret_sdk::SignerEvidenceRef>,
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

/// Read previously verified producer evidence for ordinary Event authoring.
/// Query-cache freshness is not an authorization deadline. A known revocation,
/// generation replacement, or invalidation removes the retained key and proof.
pub(crate) fn retained_device_authoring_evidence(
    actor: &str,
    device: &str,
) -> Option<(PublicKeyMaterial, arkret_sdk::SignerEvidenceRef)> {
    let guard = CACHE.read().unwrap_or_else(|poison| poison.into_inner());
    let entry = guard.get(&cache_key(actor, device)?)?;
    entry.verified_projection.as_ref()?;
    let evidence_ref = entry.signer_evidence_ref.clone()?;
    Some((entry.key.clone()?, evidence_ref))
}

/// Validate a self device row read at exact `(account_id, device_id)` selectors.
///
/// A self row carries no origin proof shell. The requester's own Station
/// verified the origin attestation, the complete AccountId, the generation and
/// the validity before projecting, and the projection itself carries no
/// account/device identity: the row's identity is the outer entry `account_id`
/// plus the `device_keys` map key. Every caller therefore MUST reach the row
/// through `devices_for(account_id)?.get(device_id)` and never by scanning the
/// map. What remains the client's own check happens here: a resolvable
/// `signer_evidence_ref`, an `active` status, and a positive observation window.
pub(crate) fn validate_self_device_row(
    record: &arkret_models_crypto::QueryDeviceRecord,
) -> anyhow::Result<&arkret_models_crypto::VerifiedDeviceProjection> {
    record.signer_evidence_ref.content_digest()?;
    let projection = &record.device_projection;
    if projection.device_status != arkret_models_crypto::DeviceStatus::Active {
        anyhow::bail!("device projection does not describe a usable device");
    }
    if projection.attested_at >= projection.expires_at {
        anyhow::bail!("device projection is not a positive observation window");
    }
    Ok(projection)
}

/// Whether the Station's observation of this projection is still fresh.
///
/// This is a query-cache freshness bound, not an authorization deadline: a
/// previously accepted authority survives it for offline authoring, and only a
/// verified revocation or generation replacement fences it.
pub(crate) fn projection_observation_is_fresh(
    projection: &arkret_models_crypto::VerifiedDeviceProjection,
    now: chrono::DateTime<chrono::Utc>,
) -> bool {
    projection.attested_at <= now && now < projection.expires_at
}

/// Whether the device's own authorization window has opened and not closed.
///
/// Unlike the observation window this is a real authorization deadline, so it
/// gates the cold-start restore as well as live consumption.
pub(crate) fn projection_authorization_window_contains(
    projection: &arkret_models_crypto::VerifiedDeviceProjection,
    now: chrono::DateTime<chrono::Utc>,
) -> bool {
    let window = &projection.authorization_window;
    now >= window.not_before && window.expires_at.is_none_or(|expires_at| now < expires_at)
}

/// Version watermark of one projection, bound to the selectors it was read at.
///
/// The projection no longer repeats `account_id` / `device_id`, so the digest
/// covers the selectors explicitly; a row observed under different selectors
/// can never satisfy a retained watermark.
fn projection_version(
    account_id: &arkret_sdk::AccountId,
    device_id: &arkret_sdk::DeviceId,
    projection: &arkret_models_crypto::VerifiedDeviceProjection,
) -> Option<VerifiedProjectionVersion> {
    Some(VerifiedProjectionVersion {
        generation_ref: projection.authorized_generation_ref,
        attested_at: projection.attested_at,
        projection_digest: arkret_sdk::canonical::canonical_sha256(&serde_json::json!({
            "account_id": account_id,
            "device_id": device_id,
            "device_projection": projection,
        }))
        .ok()?,
    })
}

/// Restore the active device's last verified authoring authority after a cold
/// start. The persisted projection remains evidence of the last accepted
/// authorization after its online observation window; only a subsequently
/// verified revocation, a closed authorization window, or a generation
/// replacement fences it.
pub(crate) fn restore_persisted_device_authoring_authority(
    expected_epoch: u64,
    expected_account: &arkret_sdk::AccountId,
    expected_device: &arkret_sdk::DeviceId,
    persisted: &crate::state::PersistedDeviceAuthoringAuthority,
) -> bool {
    if &persisted.account_id != expected_account || &persisted.device_id != expected_device {
        return false;
    }
    let projection = &persisted.device_projection;
    if projection.device_status != arkret_models_crypto::DeviceStatus::Active
        || projection.attested_at >= projection.expires_at
        || !projection_authorization_window_contains(projection, chrono::Utc::now())
        || projection.authorized_generation_ref.to_string()
            != persisted.authoring_generation.generation_ref
        || persisted.authoring_generation.authority_model
            != crate::identity::authoring_generation::AuthoringAuthorityModel::AcceptedDevice
        || persisted.authoring_generation.authority_principal_id != expected_account.principal_id
        || persisted.signer_evidence_ref.content_digest().is_err()
    {
        return false;
    }
    let Some(key) = public_key_from_directory_value(projection.device_signing_key_did.as_str())
    else {
        return false;
    };
    let Some(version) = projection_version(expected_account, expected_device, projection) else {
        return false;
    };
    store_entry_at_epoch(
        expected_epoch,
        &expected_account.to_string(),
        expected_device.as_str(),
        Some(key),
        Some(projection.device_authorize_event_id.clone()),
        Some(persisted.signer_evidence_ref.clone()),
        None,
        Some(version),
    )
}

pub(crate) fn persisted_device_authoring_authority_from_outcome(
    outcome: &arkret_models_crypto::KeysQueryOutcome,
    viewer: &arkret_sdk::AccountView,
    account_id: &arkret_sdk::AccountId,
    device_id: &arkret_sdk::DeviceId,
    authoring_generation: crate::identity::authoring_generation::AuthoringGeneration,
) -> Option<crate::state::PersistedDeviceAuthoringAuthority> {
    let record = outcome.devices_for(account_id)?.get(device_id)?;
    let projection = validate_self_device_row(record).ok()?;
    let now = chrono::Utc::now();
    if !projection_observation_is_fresh(projection, now)
        || !projection_authorization_window_contains(projection, now)
        || projection.authorized_generation_ref.to_string() != authoring_generation.generation_ref
    {
        return None;
    }
    let signer_evidence_ref = record.signer_evidence_ref.clone();
    Some(crate::state::PersistedDeviceAuthoringAuthority {
        account_id: account_id.clone(),
        device_id: device_id.clone(),
        device_projection: projection.clone(),
        signer_evidence_ref,
        authoring_generation,
    })
}

fn local_signer_matches_device_projection(
    signer: &crate::event_signer::InksonEventSigner,
    account_id: &arkret_sdk::AccountId,
    device_id: &arkret_sdk::DeviceId,
    projection: &arkret_models_crypto::VerifiedDeviceProjection,
) -> bool {
    if signer.device_id() != Some(device_id.as_str()) {
        return false;
    }
    let Ok(signer_did) = arkret_sdk::Did::new(signer.signer_did().to_owned()) else {
        return false;
    };
    if arkret_sdk::project_did_to_core_id(&signer_did)
        .ok()
        .as_ref()
        != Some(&account_id.principal_id)
    {
        return false;
    }
    signer
        .public_key_multibase()
        .map(|public_key| format!("did:key:{public_key}"))
        .as_deref()
        == Some(projection.device_signing_key_did.as_str())
}

/// Resolve the exact Data and Control authoring roots for the active local
/// signer from one authenticated account viewer plus the authoritative
/// keys/query projection. Neither evidence plane may substitute for the other.
pub(crate) async fn authenticated_device_authoring_authority(
    http: &arkret_sdk::http_client::Client,
    viewer: &arkret_sdk::AccountView,
    account_id: &arkret_sdk::AccountId,
    device_id: &arkret_sdk::DeviceId,
    signer: &crate::event_signer::InksonEventSigner,
) -> anyhow::Result<Option<crate::state::PersistedDeviceAuthoringAuthority>> {
    let outcome = crate::transport::keys::query_keys(http, account_id, device_id.as_str()).await?;
    let Some(record) = outcome
        .devices_for(account_id)
        .and_then(|devices| devices.get(device_id))
    else {
        return Ok(None);
    };
    if !local_signer_matches_device_projection(
        signer,
        account_id,
        device_id,
        &record.device_projection,
    ) {
        return Ok(None);
    }
    if !crate::identity::authoring_generation::cache_principal_authoring_generation_from_keys(
        &outcome,
        account_id,
        device_id.as_str(),
    )? {
        return Ok(None);
    }
    let Some(generation) =
        crate::identity::authoring_generation::cached_principal_authoring_generation(
            account_id,
            device_id.as_str(),
        )
    else {
        return Ok(None);
    };
    Ok(persisted_device_authoring_authority_from_outcome(
        &outcome, viewer, account_id, device_id, generation,
    ))
}

pub(crate) fn cached_signer_evidence_ref_for_principal_device_and_key(
    principal_id: &arkret_sdk::DidCoreId,
    device: &str,
    expected_key: &PublicKeyMaterial,
) -> Option<arkret_sdk::SignerEvidenceRef> {
    let now = crate::clock::now_unix_ms();
    let guard = CACHE.read().unwrap_or_else(|poison| poison.into_inner());
    let mut matches = guard
        .iter()
        .filter_map(|((account, cached_device), entry)| {
            (account.principal_id == *principal_id
                && cached_device == device
                && entry.expires_at_ms > now
                && entry.key.as_ref() == Some(expected_key))
            .then(|| entry.signer_evidence_ref.clone())
            .flatten()
        });
    let evidence = matches.next()?;
    matches
        .all(|candidate| candidate == evidence)
        .then_some(evidence)
}

fn store_entry_at_epoch(
    expected_epoch: u64,
    actor: &str,
    device: &str,
    key: Option<PublicKeyMaterial>,
    authorize_event_id: Option<arkret_sdk::EventId>,
    signer_evidence_ref: Option<arkret_sdk::SignerEvidenceRef>,
    projection_expires_at_ms: Option<u64>,
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
    let expires_at_ms = if key.is_some() && projection_expires_at_ms.is_none() {
        // A persisted, previously verified authority remains usable while its
        // revocation is unknown. A later accepted projection invalidates it.
        u64::MAX
    } else {
        now.saturating_add(ttl)
            .min(projection_expires_at_ms.unwrap_or(u64::MAX))
    };
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
                entry.signer_evidence_ref = None;
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
                previous.signer_evidence_ref = None;
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
            signer_evidence_ref,
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

struct AcceptedDeviceEvidence {
    key: PublicKeyMaterial,
    authorize_event_id: arkret_sdk::EventId,
    signer_evidence_ref: arkret_sdk::SignerEvidenceRef,
    projection_expires_at_ms: u64,
    version: VerifiedProjectionVersion,
}

fn accepted_device_evidence(
    outcome: &arkret_models_crypto::KeysQueryOutcome,
    account_id: &arkret_sdk::AccountId,
    device: &str,
) -> Option<AcceptedDeviceEvidence> {
    account_id.validate().ok()?;
    let device = arkret_sdk::DeviceId::new(device.to_owned()).ok()?;
    let record = outcome.devices_for(account_id)?.get(&device)?;
    let generation = outcome.generation_for(account_id)?;
    if !record.is_usable_in_generation(Some(generation)) {
        return None;
    }
    let projection = validate_self_device_row(record).ok()?;
    let now = chrono::Utc::now();
    if !projection_observation_is_fresh(projection, now)
        || !projection_authorization_window_contains(projection, now)
    {
        return None;
    }
    Some(AcceptedDeviceEvidence {
        key: public_key_from_directory_value(projection.device_signing_key_did.as_str())?,
        authorize_event_id: projection.device_authorize_event_id.clone(),
        // The reference points at the original immutable evidence object and is
        // passed through byte-exactly; it is never recomputed from the values
        // the client kept.
        signer_evidence_ref: record.signer_evidence_ref.clone(),
        projection_expires_at_ms: u64::try_from(projection.expires_at.timestamp_millis()).ok()?,
        version: projection_version(account_id, &device, projection)?,
    })
}

pub(crate) fn cache_accepted_device_evidence_from_outcome(
    expected_epoch: u64,
    outcome: &arkret_models_crypto::KeysQueryOutcome,
    account_id: &arkret_sdk::AccountId,
    device: &str,
) -> Option<PublicKeyMaterial> {
    let resolved = accepted_device_evidence(outcome, account_id, device);
    let key = resolved.as_ref().map(|resolved| resolved.key.clone());
    let stored = store_entry_at_epoch(
        expected_epoch,
        &account_id.to_string(),
        device,
        key.clone(),
        resolved
            .as_ref()
            .map(|resolved| resolved.authorize_event_id.clone()),
        resolved
            .as_ref()
            .map(|resolved| resolved.signer_evidence_ref.clone()),
        None,
        resolved
            .as_ref()
            .map(|resolved| resolved.projection_expires_at_ms),
        resolved.map(|resolved| resolved.version),
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

pub fn verify_persistent_envelope_proof(
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
    let Some(proof) = envelope
        .get("producer_proof")
        .and_then(|value| value.as_object())
    else {
        return false;
    };
    let Ok(preimage) = arkret_sdk::event_digest_preimage(envelope) else {
        return false;
    };
    verify_proof_value(
        &preimage,
        &serde_json::Value::Object(proof.clone()),
        actor_principal,
        public_key,
    )
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
            entry.signer_evidence_ref = None;
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
        None,
        None,
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

    fn self_projection_fixture(
        now: chrono::DateTime<chrono::Utc>,
        device_signing_key_did: &str,
    ) -> arkret_models_crypto::VerifiedDeviceProjection {
        arkret_models_crypto::VerifiedDeviceProjection {
            device_signing_key_did: arkret_sdk::DidKey::new(device_signing_key_did.to_owned())
                .unwrap(),
            hpke_key: arkret_sdk::NonEmptyString::new("hpke-test").unwrap(),
            device_authorize_event_id: arkret_sdk::EventId::new(
                "ak:event:AfAnsJqSlM9bHVI7P1QBMOEW3p5P1PNQu7BBMpiSnD_e",
            )
            .unwrap(),
            authorized_generation_ref: 7,
            device_status: arkret_models_crypto::DeviceStatus::Active,
            authorization_window: arkret_models_crypto::DeviceAuthorizationWindow {
                not_before: now,
                expires_at: None,
            },
            attested_at: now,
            expires_at: now + chrono::Duration::minutes(5),
        }
    }

    const FIXTURE_DATA_SIGNER_EVIDENCE_REF: &str = "ak:signer_evidence:sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const FIXTURE_CONTROL_SIGNER_EVIDENCE_REF: &str = "ak:signer_evidence:sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    fn self_outcome_fixture(
        account: &arkret_sdk::AccountId,
        device: &arkret_sdk::DeviceId,
        projection: &arkret_models_crypto::VerifiedDeviceProjection,
    ) -> arkret_models_crypto::KeysQueryOutcome {
        serde_json::from_value(serde_json::json!({
            "device_keys": [{"account_id": account, "device_keys": {
                device.as_str(): {
                    "signer_evidence_ref": FIXTURE_DATA_SIGNER_EVIDENCE_REF,
                    "algorithms": {}, "trust_algorithms": [],
                    "device_projection": projection
                }
            }}],
            "failures": [],
            "device_generations": [{"account_id": account, "generation_state": {
                "current_device_generation_ref": 7,
                "device_generation_status": "active"
            }}]
        }))
        .unwrap()
    }

    fn account_viewer_fixture(
        account: &arkret_sdk::AccountId,
        device: &arkret_sdk::DeviceId,
        authorization_event_id: &arkret_sdk::EventId,
    ) -> arkret_sdk::AccountView {
        serde_json::from_value(serde_json::json!({
            "principal_id": account.principal_id,
            "state": "active",
            "devices": [{
                "device_id": device,
                "status": "active",
                "verification_state": "verified",
                "authorized_event_ref": authorization_event_id,
                "signer_resolution_evidence_ref": FIXTURE_CONTROL_SIGNER_EVIDENCE_REF
            }]
        }))
        .unwrap()
    }

    fn projection_fixture_account() -> (arkret_sdk::AccountId, arkret_sdk::DeviceId) {
        (
            arkret_sdk::AccountId::new(
                arkret_sdk::DidCoreId::new("ak:did_core:web:projection-principal.example").unwrap(),
                arkret_sdk::DidCoreId::new("ak:did_core:web:projection-station.example").unwrap(),
            ),
            arkret_sdk::DeviceId::new("ak:device:0196419b-0000-7000-8000-000000000001").unwrap(),
        )
    }

    #[test]
    fn local_signer_requires_exact_account_device_and_projection_key() {
        let (account, device) = projection_fixture_account();
        let signer = crate::event_signer::build_ed25519_device_signer(
            [43u8; 32],
            "did:web:projection-principal.example",
            device.as_str(),
        );
        let public_key = signer.public_key_multibase().unwrap();
        let projection = self_projection_fixture(
            arkret_sdk::canonical::normalize_timestamp_canonical(chrono::Utc::now()),
            &format!("did:key:{public_key}"),
        );
        assert!(super::local_signer_matches_device_projection(
            &signer,
            &account,
            &device,
            &projection,
        ));

        let other_device =
            arkret_sdk::DeviceId::new("ak:device:0196419b-0000-7000-8000-000000000002").unwrap();
        assert!(!super::local_signer_matches_device_projection(
            &signer,
            &account,
            &other_device,
            &projection,
        ));

        let other_account = arkret_sdk::AccountId::new(
            arkret_sdk::DidCoreId::new("ak:did_core:web:other-principal.example").unwrap(),
            account.station_id.clone(),
        );
        assert!(!super::local_signer_matches_device_projection(
            &signer,
            &other_account,
            &device,
            &projection,
        ));

        let wrong_key_projection = self_projection_fixture(
            arkret_sdk::canonical::normalize_timestamp_canonical(chrono::Utc::now()),
            "did:key:z6MkhHrTbtosB4xyyJM217fS4ry35F7JhZ5oA9uVHErBJDL5",
        );
        assert!(!super::local_signer_matches_device_projection(
            &signer,
            &account,
            &device,
            &wrong_key_projection,
        ));
    }

    #[test]
    fn trusted_device_result_requires_exact_binding_and_current_generation() {
        let (account, device) = projection_fixture_account();
        let now = arkret_sdk::canonical::normalize_timestamp_canonical(chrono::Utc::now());
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[43u8; 32]);
        let public_key =
            arkret_sdk::ed25519_pubkey_to_did_key_multibase(signing_key.verifying_key().as_bytes());
        let projection = self_projection_fixture(now, &format!("did:key:{public_key}"));
        let mut outcome = self_outcome_fixture(&account, &device, &projection);
        let viewer =
            account_viewer_fixture(&account, &device, &projection.device_authorize_event_id);
        assert!(super::accepted_device_evidence(&outcome, &account, device.as_str()).is_some());
        super::reset_session_cache();
        let directory_epoch = super::cache_epoch();
        assert!(
            super::cache_accepted_device_evidence_from_outcome(
                directory_epoch,
                &outcome,
                &account,
                device.as_str(),
            )
            .is_some()
        );
        assert!(
            super::retained_device_authoring_evidence(
                &account.to_string(),
                device.as_str(),
                arkret_sdk::CbsEffectPlane::Data,
            )
            .is_some()
        );
        assert!(
            super::retained_device_authoring_evidence(
                &account.to_string(),
                device.as_str(),
                arkret_sdk::CbsEffectPlane::Control,
            )
            .is_none(),
            "keys/query Data evidence must not be reused as Control evidence"
        );
        let generation = crate::identity::authoring_generation::AuthoringGeneration {
            authority_model:
                crate::identity::authoring_generation::AuthoringAuthorityModel::AcceptedDevice,
            authority_principal_id: account.principal_id.clone(),
            generation_ref: "7".to_owned(),
        };
        let persisted = super::persisted_device_authoring_authority_from_outcome(
            &outcome,
            &viewer,
            &account,
            &device,
            generation.clone(),
        )
        .expect("accepted projection forms durable authoring evidence");
        // The reference is the original immutable evidence object, carried
        // through byte-exactly rather than recomputed from the projection.
        assert_eq!(
            persisted.signer_evidence_ref,
            arkret_sdk::SignerEvidenceRef::new(FIXTURE_DATA_SIGNER_EVIDENCE_REF).unwrap()
        );
        assert_eq!(
            persisted.control_signer_evidence_ref,
            arkret_sdk::SignerEvidenceRef::new(FIXTURE_CONTROL_SIGNER_EVIDENCE_REF).unwrap()
        );
        assert_eq!(persisted.device_projection, projection);
        super::reset_session_cache();
        let epoch = super::cache_epoch();
        assert!(super::restore_persisted_device_authoring_authority(
            epoch, &account, &device, &persisted,
        ));
        crate::identity::authoring_generation::cache_verified_principal_generation(
            &account,
            device.as_str(),
            &generation,
        );
        assert_eq!(
            crate::identity::authoring_generation::cached_principal_authoring_generation(
                &account,
                device.as_str()
            ),
            Some(generation)
        );
        assert_eq!(
            super::retained_device_authoring_evidence(
                &account.to_string(),
                device.as_str(),
                arkret_sdk::CbsEffectPlane::Data,
            )
            .map(|(_, evidence)| evidence),
            Some(persisted.signer_evidence_ref.clone())
        );
        assert_eq!(
            super::retained_device_authoring_evidence(
                &account.to_string(),
                device.as_str(),
                arkret_sdk::CbsEffectPlane::Control,
            )
            .map(|(_, evidence)| evidence),
            Some(persisted.control_signer_evidence_ref.clone())
        );
        // A restore is bound to the account and device it was persisted under.
        let other_account = arkret_sdk::AccountId::new(
            account.principal_id.clone(),
            arkret_sdk::DidCoreId::new("ak:did_core:web:other-station.example").unwrap(),
        );
        assert!(!super::restore_persisted_device_authoring_authority(
            epoch,
            &other_account,
            &device,
            &persisted,
        ));
        let other_device =
            arkret_sdk::DeviceId::new("ak:device:0196419b-0000-7000-8000-000000000002").unwrap();
        assert!(!super::restore_persisted_device_authoring_authority(
            epoch,
            &account,
            &other_device,
            &persisted,
        ));
        assert!(
            super::accepted_device_evidence(&outcome, &account, other_device.as_str()).is_none()
        );
        outcome.device_generations[0]
            .generation_state
            .current_device_generation_ref = 8;
        assert!(super::accepted_device_evidence(&outcome, &account, device.as_str()).is_none());
        outcome.device_generations[0]
            .generation_state
            .current_device_generation_ref = 7;
        // A closed authorization window fences the device even while the
        // Station's observation of the projection is still fresh.
        let closed_window = arkret_models_crypto::VerifiedDeviceProjection {
            authorization_window: arkret_models_crypto::DeviceAuthorizationWindow {
                not_before: now - chrono::Duration::minutes(10),
                expires_at: Some(now - chrono::Duration::minutes(1)),
            },
            ..projection.clone()
        };
        let closed = self_outcome_fixture(&account, &device, &closed_window);
        assert!(super::accepted_device_evidence(&closed, &account, device.as_str()).is_none());
        assert!(
            super::persisted_device_authoring_authority_from_outcome(
                &closed,
                &viewer,
                &account,
                &device,
                crate::identity::authoring_generation::AuthoringGeneration {
                    authority_model: crate::identity::authoring_generation::AuthoringAuthorityModel::AcceptedDevice,
                    authority_principal_id: account.principal_id.clone(),
                    generation_ref: "7".to_owned(),
                },
            )
            .is_none()
        );
        outcome.device_keys[0]
            .device_keys
            .get_mut(&device)
            .unwrap()
            .device_projection
            .expires_at = now;
        assert!(super::accepted_device_evidence(&outcome, &account, device.as_str()).is_none());
        super::reset_session_cache();
        crate::identity::authoring_generation::reset_verified_authoring_generations();
    }

    #[test]
    fn control_authoring_root_requires_the_exact_verified_viewer_device() {
        let (account, device) = projection_fixture_account();
        let now = arkret_sdk::canonical::normalize_timestamp_canonical(chrono::Utc::now());
        let projection = self_projection_fixture(
            now,
            "did:key:z6MkhHrTbtosB4xyyJM217fS4ry35F7JhZ5oA9uVHErBJDL5",
        );
        let outcome = self_outcome_fixture(&account, &device, &projection);
        let generation = crate::identity::authoring_generation::AuthoringGeneration {
            authority_model:
                crate::identity::authoring_generation::AuthoringAuthorityModel::AcceptedDevice,
            authority_principal_id: account.principal_id.clone(),
            generation_ref: "7".to_owned(),
        };
        let viewer =
            account_viewer_fixture(&account, &device, &projection.device_authorize_event_id);

        let mut missing_control = viewer.clone();
        missing_control.devices[0].signer_resolution_evidence_ref = None;
        assert!(
            super::persisted_device_authoring_authority_from_outcome(
                &outcome,
                &missing_control,
                &account,
                &device,
                generation.clone(),
            )
            .is_none()
        );

        let mut wrong_authorization = viewer.clone();
        wrong_authorization.devices[0].authorized_event_ref = Some(
            arkret_sdk::EventId::from_digest(arkret_sdk::DigestSuite::Sha256, [99; 32]),
        );
        assert!(
            super::persisted_device_authoring_authority_from_outcome(
                &outcome,
                &wrong_authorization,
                &account,
                &device,
                generation.clone(),
            )
            .is_none()
        );

        let mut duplicate = viewer.clone();
        duplicate.devices.push(duplicate.devices[0].clone());
        assert!(
            super::persisted_device_authoring_authority_from_outcome(
                &outcome,
                &duplicate,
                &account,
                &device,
                generation.clone(),
            )
            .is_none()
        );

        let mut wrong_principal = viewer;
        wrong_principal.principal_id =
            arkret_sdk::DidCoreId::new("ak:did_core:web:other-principal.example").unwrap();
        assert!(
            super::persisted_device_authoring_authority_from_outcome(
                &outcome,
                &wrong_principal,
                &account,
                &device,
                generation,
            )
            .is_none()
        );

        let mut reused_data_root =
            account_viewer_fixture(&account, &device, &projection.device_authorize_event_id);
        reused_data_root.devices[0].signer_resolution_evidence_ref =
            Some(arkret_sdk::SignerEvidenceRef::new(FIXTURE_DATA_SIGNER_EVIDENCE_REF).unwrap());
        assert!(
            super::persisted_device_authoring_authority_from_outcome(
                &outcome,
                &reused_data_root,
                &account,
                &device,
                crate::identity::authoring_generation::AuthoringGeneration {
                    authority_model: crate::identity::authoring_generation::AuthoringAuthorityModel::AcceptedDevice,
                    authority_principal_id: account.principal_id.clone(),
                    generation_ref: "7".to_owned(),
                },
            )
            .is_none(),
            "the Data root cannot be reused as the Control root"
        );
    }

    /// The persisted self authority is a Station-verified projection, not
    /// portable evidence: the client never received the origin proof, so it
    /// MUST NOT be presentable where a complete signed evidence object is
    /// declared - `CurrentSignerEvidence::AccountDevice` in particular.
    #[test]
    fn an_unsigned_self_projection_cannot_pose_as_complete_signed_evidence() {
        use arkret_models_collaboration::current_signer_evidence::CurrentSignerEvidence;

        let (account, device) = projection_fixture_account();
        let now = arkret_sdk::canonical::normalize_timestamp_canonical(chrono::Utc::now());
        let projection = self_projection_fixture(
            now,
            "did:key:z6MkhHrTbtosB4xyyJM217fS4ry35F7JhZ5oA9uVHErBJDL5",
        );
        let outcome = self_outcome_fixture(&account, &device, &projection);
        let viewer =
            account_viewer_fixture(&account, &device, &projection.device_authorize_event_id);
        let persisted = super::persisted_device_authoring_authority_from_outcome(
            &outcome,
            &viewer,
            &account,
            &device,
            crate::identity::authoring_generation::AuthoringGeneration {
                authority_model:
                    crate::identity::authoring_generation::AuthoringAuthorityModel::AcceptedDevice,
                authority_principal_id: account.principal_id.clone(),
                generation_ref: "7".to_owned(),
            },
        )
        .expect("accepted projection forms durable authoring evidence");

        let serialized = serde_json::to_string(&persisted).unwrap();
        assert!(!serialized.contains("device_projection_attestation"));
        assert!(!serialized.contains("\"proof\""));
        assert!(!serialized.contains("\"jws\""));

        // Feeding the projection into the signed slot is rejected by the type
        // itself: `device_projection_attestation` demands an attested core plus
        // its detached proof, and neither exists on this device.
        assert!(
            serde_json::from_value::<CurrentSignerEvidence>(serde_json::json!({
                "sender_kind": "account_device",
                "account_id": persisted.account_id,
                "device_id": persisted.device_id,
                "device_projection_attestation": persisted.device_projection,
                "signer_evidence_ref": persisted.signer_evidence_ref,
            }))
            .is_err()
        );
        assert!(
            serde_json::from_value::<CurrentSignerEvidence>(serde_json::json!({
                "sender_kind": "account_device",
                "account_id": persisted.account_id,
                "device_id": persisted.device_id,
                "device_projection_attestation": {"attestation": persisted.device_projection},
                "signer_evidence_ref": persisted.signer_evidence_ref,
            }))
            .is_err()
        );
    }

    #[test]
    fn ordinary_authoring_retains_verified_evidence_past_lookup_ttl_until_revocation() {
        let account = arkret_sdk::AccountId::new(
            "ak:did_core:web:retained-author.example".parse().unwrap(),
            "ak:did_core:web:retained-station.example".parse().unwrap(),
        )
        .to_string();
        let device = "ak:device:0196419b-0000-7000-8000-000000000081";
        let key = super::public_key_from_directory_value(
            "did:key:z6MkhHrTbtosB4xyyJM217fS4ry35F7JhZ5oA9uVHErBJDL5",
        )
        .unwrap();
        let data_evidence = arkret_sdk::SignerEvidenceRef::new(
            "ak:signer_evidence:sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ).unwrap();
        let control_evidence = arkret_sdk::SignerEvidenceRef::new(
            "ak:signer_evidence:sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        ).unwrap();
        let now = chrono::Utc::now();
        let version = super::VerifiedProjectionVersion {
            generation_ref: 1,
            attested_at: now,
            projection_digest: "active".to_owned(),
        };
        assert!(super::store_entry_at_epoch(
            super::cache_epoch(),
            &account,
            device,
            Some(key.clone()),
            Some(arkret_sdk::EventId::from_digest(
                arkret_sdk::DigestSuite::Sha256,
                [81; 32]
            )),
            Some(data_evidence.clone()),
            Some(control_evidence.clone()),
            Some(crate::clock::now_unix_ms() + 60_000),
            Some(version.clone()),
        ));
        {
            let mut cache = super::CACHE.write().unwrap();
            cache
                .get_mut(&super::cache_key(&account, device).unwrap())
                .unwrap()
                .expires_at_ms = 0;
        }
        assert!(matches!(
            super::cached_device_signing_key(&account, device),
            super::CacheLookup::Miss
        ));
        assert_eq!(
            super::retained_device_authoring_evidence(
                &account,
                device,
                arkret_sdk::CbsEffectPlane::Data,
            ),
            Some((key.clone(), data_evidence))
        );
        assert_eq!(
            super::retained_device_authoring_evidence(
                &account,
                device,
                arkret_sdk::CbsEffectPlane::Control,
            ),
            Some((key, control_evidence))
        );
        let revoked = super::VerifiedProjectionVersion {
            attested_at: now + chrono::Duration::seconds(1),
            projection_digest: "revoked".to_owned(),
            ..version
        };
        assert!(super::store_entry_at_epoch(
            super::cache_epoch(),
            &account,
            device,
            None,
            None,
            None,
            None,
            None,
            Some(revoked),
        ));
        assert!(super::known_device_revoked(&account, device));
        assert!(
            super::retained_device_authoring_evidence(
                &account,
                device,
                arkret_sdk::CbsEffectPlane::Data,
            )
            .is_none()
        );
        assert!(
            super::retained_device_authoring_evidence(
                &account,
                device,
                arkret_sdk::CbsEffectPlane::Control,
            )
            .is_none()
        );
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
