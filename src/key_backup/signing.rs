use std::cell::RefCell;
use std::fmt;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde_json::{Value, json};

use super::{
    DEFAULT_SSK_GENERATION, KEY_BACKUP_RAW_SIGNATURE_ALGORITHM, KEY_BACKUP_SIGNED_FIELDS,
    KEY_BACKUP_SIGNED_FIELDS_MANDATORY, KEY_BACKUP_UNLOCK_PROOF_SCHEMA, required_str_anyhow,
};

const UNLOCKED_KEY_BACKUP_CACHE_MAX_ENTRIES: usize = 64;
const KEY_BACKUP_UNLOCK_BACKOFF_MAX_ENTRIES: usize = 32;

thread_local! {
    static UNLOCKED_KEY_BACKUP_CACHE: RefCell<Vec<(String, Value)>> =
        const { RefCell::new(Vec::new()) };
    static KEY_BACKUP_UNLOCK_BACKOFFS: RefCell<crate::keyed_cooldown::KeyedCooldown> = const {
        RefCell::new(crate::keyed_cooldown::KeyedCooldown::new(
            KEY_BACKUP_UNLOCK_BACKOFF_MAX_ENTRIES,
        ))
    };
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KeyBackupUnlockBackoff {
    retry_after_ms: u64,
}

impl KeyBackupUnlockBackoff {
    pub fn retry_after_ms(&self) -> u64 {
        self.retry_after_ms
    }
}

impl fmt::Display for KeyBackupUnlockBackoff {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "key backup download quota is cooling down; retry after {} ms",
            self.retry_after_ms
        )
    }
}

impl std::error::Error for KeyBackupUnlockBackoff {}

#[derive(Clone, Debug)]
pub enum KeyBackupDeviceTrustAnchor {
    SskGeneration(u64),
    DeviceAuthorizeEventId(String),
}

/// Phase 2 (key-management.md §7.4.1, AKP-0013): sign a key-backup envelope with
/// the device Ed25519 key. The signature covers
/// `canonical_json(envelope without auth_data.signature)` — i.e. the rest of
/// `auth_data` is bound too, so it cannot be tampered. The trust anchor seals
/// the envelope to either the published cross-signing generation or the
/// accepted service-attested device authorization event.
pub fn sign_key_backup_auth_data(
    body: &mut Value,
    signing_key: &SigningKey,
    device_id: &str,
    verification_method: &str,
    trust_anchor: Option<KeyBackupDeviceTrustAnchor>,
) -> anyhow::Result<()> {
    if let Some(object) = body.as_object_mut() {
        object.remove("auth_data");
    }
    let signed_fields = key_backup_signed_fields_for_body(body);
    let mut auth = json!({
        "device_id": device_id,
        "verification_method": verification_method,
        "signature_algorithm": KEY_BACKUP_RAW_SIGNATURE_ALGORITHM,
        "signed_fields": signed_fields,
    });
    apply_key_backup_trust_anchor(&mut auth, trust_anchor)?;
    body["auth_data"] = auth;
    // Sign over the envelope WITH auth_data present but WITHOUT the signature.
    let payload = crate::canonical::canonical_json_bytes(body)?;
    let signature = signing_key.sign(&payload);
    body["auth_data"]["signature"] = Value::String(B64.encode(signature.to_bytes()));
    Ok(())
}

/// Sign `body`'s `auth_data` with the active device signer. This requires a
/// signer that can produce raw Ed25519 signatures over canonical JSON bytes.
///
/// Returns `Ok(true)` when signed, `Ok(false)` when NO signer is installed (the
/// legitimate unsigned case — e.g. tests, or pre-bootstrap), and `Err` when a
/// signer IS present but signing failed. Crucially this no longer silently
/// downgrades a present-but-unsuitable signer to unsigned: a present signer
/// always signs or errors, so callers never ship an unsigned backup by accident.
pub fn sign_key_backup_with_active_device(
    body: &mut Value,
    device_id: &str,
) -> anyhow::Result<bool> {
    sign_key_backup_with_active_device_and_trust_anchor(
        body,
        device_id,
        Some(KeyBackupDeviceTrustAnchor::SskGeneration(
            DEFAULT_SSK_GENERATION,
        )),
    )
}

pub fn sign_key_backup_with_active_device_and_trust_anchor(
    body: &mut Value,
    device_id: &str,
    trust_anchor: Option<KeyBackupDeviceTrustAnchor>,
) -> anyhow::Result<bool> {
    let Some(signer) = crate::event_signer::active_signer() else {
        return Ok(false);
    };
    // Build auth_data WITHOUT the signature, then sign canonical(body) over it.
    if let Some(object) = body.as_object_mut() {
        object.remove("auth_data");
    }
    let signed_fields = key_backup_signed_fields_for_body(body);
    let verification_method = body
        .get("actor_id")
        .and_then(Value::as_str)
        .map(|actor_id| arkret_sdk::Did::new(actor_id.to_owned()))
        .transpose()?
        .map(|principal| signer.verification_method_for_principal(&principal))
        .transpose()
        .map_err(|error| anyhow::anyhow!("key backup principal binding: {error}"))?
        .unwrap_or_else(|| signer.verification_method().to_owned());
    let mut auth = json!({
        "device_id": device_id,
        "verification_method": verification_method,
        "signature_algorithm": KEY_BACKUP_RAW_SIGNATURE_ALGORITHM,
        "signed_fields": signed_fields,
    });
    apply_key_backup_trust_anchor(&mut auth, trust_anchor)?;
    body["auth_data"] = auth;
    let payload = crate::canonical::canonical_json_bytes(body)?;
    let signature = signer
        .sign_raw(&payload)
        .map_err(|err| anyhow::anyhow!("key backup auth_data sign: {err:?}"))?;
    body["auth_data"]["signature"] = Value::String(B64.encode(signature));
    Ok(true)
}

/// Phase 2 verify: check a key-backup envelope's `auth_data.signature` against
/// `verifying_key`, recomputing `canonical_json(envelope without
/// auth_data.signature)`, and confirm `signed_fields` covers the mandatory set.
/// Returns `Err` (caller maps to `untrusted_backup_signature`) on any mismatch.
pub fn verify_key_backup_auth_data(
    body: &Value,
    verifying_key: &VerifyingKey,
) -> Result<(), String> {
    let auth = body
        .get("auth_data")
        .and_then(Value::as_object)
        .ok_or_else(|| "auth_data is required".to_owned())?;
    if auth.get("signature_algorithm").and_then(Value::as_str)
        != Some(KEY_BACKUP_RAW_SIGNATURE_ALGORITHM)
    {
        return Err("auth_data.signature_algorithm must be Ed25519".to_owned());
    }
    let ssk_generation = auth.get("ssk_generation").and_then(Value::as_u64);
    if auth.get("ssk_generation").is_some()
        && ssk_generation.is_none_or(|generation| generation < 1)
    {
        return Err("auth_data.ssk_generation must be >= 1".to_owned());
    }
    let device_authorize_event_id = auth
        .get("device_authorize_event_id")
        .and_then(Value::as_str)
        .filter(|event_id| !event_id.trim().is_empty());
    if auth.get("device_authorize_event_id").is_some() && device_authorize_event_id.is_none() {
        return Err("auth_data.device_authorize_event_id must be a non-empty string".to_owned());
    }
    match (ssk_generation, device_authorize_event_id) {
        (Some(_), None) | (None, Some(_)) => {}
        (None, None) => {
            return Err("auth_data must include exactly one device trust anchor".to_owned());
        }
        (Some(_), Some(_)) => {
            return Err(
                "auth_data.ssk_generation and auth_data.device_authorize_event_id are mutually exclusive"
                    .to_owned(),
            );
        }
    }
    let sig_b64 = auth
        .get("signature")
        .and_then(Value::as_str)
        .ok_or_else(|| "auth_data.signature is required".to_owned())?;
    let sig_bytes: [u8; 64] = B64
        .decode(sig_b64)
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(|| "auth_data.signature must be 64-byte base64url".to_owned())?;
    let signature = Signature::from_bytes(&sig_bytes);

    let signed_fields: Vec<&str> = auth
        .get("signed_fields")
        .and_then(Value::as_array)
        .map(|items| items.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    for field in KEY_BACKUP_SIGNED_FIELDS_MANDATORY {
        if !signed_fields.contains(field) {
            return Err(format!("auth_data.signed_fields must cover `{field}`"));
        }
    }

    let mut unsigned = body.clone();
    if let Some(object) = unsigned.get_mut("auth_data").and_then(Value::as_object_mut) {
        object.remove("signature");
    }
    let payload =
        crate::canonical::canonical_json_bytes(&unsigned).map_err(|err| err.to_string())?;
    verifying_key
        .verify(&payload, &signature)
        .map_err(|_| "untrusted_backup_signature: signature does not verify".to_owned())
}

fn key_backup_signed_fields_for_body(body: &Value) -> Vec<Value> {
    KEY_BACKUP_SIGNED_FIELDS
        .iter()
        .filter(|field| body.get(**field).is_some())
        .map(|field| Value::String((*field).to_owned()))
        .collect()
}

fn apply_key_backup_trust_anchor(
    auth: &mut Value,
    trust_anchor: Option<KeyBackupDeviceTrustAnchor>,
) -> anyhow::Result<()> {
    match trust_anchor {
        Some(KeyBackupDeviceTrustAnchor::SskGeneration(generation)) if generation >= 1 => {
            auth["ssk_generation"] = Value::Number(serde_json::Number::from(generation));
        }
        Some(KeyBackupDeviceTrustAnchor::SskGeneration(_)) => {
            anyhow::bail!("auth_data.ssk_generation must be >= 1");
        }
        Some(KeyBackupDeviceTrustAnchor::DeviceAuthorizeEventId(event_id)) => {
            if event_id.trim().is_empty() {
                anyhow::bail!("auth_data.device_authorize_event_id must be a non-empty string");
            }
            auth["device_authorize_event_id"] = Value::String(event_id);
        }
        None => {}
    }
    Ok(())
}

pub fn build_key_backup_unlock_proof_active(
    backup: &Value,
    principal_id: &str,
    requesting_device_id: &str,
    recovery_session: Option<&Value>,
    recovery_key: Option<(&[u8; 32], &str)>,
) -> anyhow::Result<Value> {
    let active_signer = if recovery_key.is_none() {
        Some(crate::event_signer::active_signer().ok_or_else(|| {
            anyhow::anyhow!("active signer is required for key backup unlock proof")
        })?)
    } else {
        None
    };
    let backup_id = required_str_anyhow(backup, "backup_id")?;
    let backup_kind = required_str_anyhow(backup, "backup_kind")?;
    let series_id = required_str_anyhow(backup, "series_id")?;
    let ciphertext_digest = required_str_anyhow(backup, "ciphertext_digest")?;
    let issued_at = arkret_sdk::canonical::format_timestamp_canonical(chrono::Utc::now());
    let (recovery_session_id, proof_kind, proof_digest) = if let Some(session) = recovery_session {
        let session_id = required_str_anyhow(session, "recovery_session_id")?.to_owned();
        let summary = session
            .get("proof_summary")
            .ok_or_else(|| anyhow::anyhow!("verified recovery session missing proof_summary"))?;
        let kind = required_str_anyhow(summary, "kind")?.to_owned();
        let digest = required_str_anyhow(summary, "proof_digest")?.to_owned();
        (session_id, kind, digest)
    } else {
        // Ordinary already-authorized-device restores use the only proof kind
        // that does not require a durable recovery session.
        let session_id = format!("ak:recovery_session:{}", crate::operation::uuid_v7());
        let local_digest = crate::canonical::canonical_sha256(&json!({
            "type": "ak.key_backup.local_unlock_proof.v1",
            "principal_id": principal_id,
            "requesting_device_id": requesting_device_id,
            "backup_id": backup_id,
            "backup_kind": backup_kind,
            "series_id": series_id,
            "ciphertext_digest": ciphertext_digest,
            "issued_at": issued_at,
        }))?;
        (session_id, "principal_signing".to_owned(), local_digest)
    };
    let signed_fields = vec![
        "schema",
        "recovery_session_id",
        "principal_id",
        "requesting_device_id",
        "backup_id",
        "backup_kind",
        "series_id",
        "ciphertext_digest",
        "proof_kind",
        "proof_digest",
        "issued_at",
    ];
    let verification_method = recovery_key
        .map(|(_, method)| method.to_owned())
        .unwrap_or_else(|| {
            active_signer
                .as_ref()
                .expect("checked above")
                .verification_method()
                .to_owned()
        });
    let mut proof = json!({
        "schema": KEY_BACKUP_UNLOCK_PROOF_SCHEMA,
        "recovery_session_id": recovery_session_id,
        "principal_id": principal_id,
        "requesting_device_id": requesting_device_id,
        "backup_id": backup_id,
        "backup_kind": backup_kind,
        "series_id": series_id,
        "ciphertext_digest": ciphertext_digest,
        "proof_kind": proof_kind,
        "proof_digest": proof_digest,
        "issued_at": issued_at,
        "auth_data": {
            "verification_method": verification_method,
            "signature_algorithm": KEY_BACKUP_RAW_SIGNATURE_ALGORITHM,
            "signed_fields": signed_fields,
        }
    });
    let payload = crate::canonical::canonical_json_bytes(&proof)?;
    let signature = if let Some((seed, _)) = recovery_key {
        SigningKey::from_bytes(seed)
            .sign(&payload)
            .to_bytes()
            .to_vec()
    } else {
        active_signer
            .expect("checked above")
            .sign_raw(&payload)
            .map_err(|err| anyhow::anyhow!("key backup unlock proof sign: {err:?}"))?
    };
    proof["auth_data"]["signature"] = Value::String(B64.encode(signature));
    Ok(proof)
}

pub async fn fetch_key_backup_with_active_unlock_proof(
    api: &crate::transport::TransportClient,
    backup_metadata: &Value,
    principal_id: &str,
    requesting_device_id: &str,
) -> anyhow::Result<Value> {
    fetch_key_backup_with_unlock_proof(
        api,
        backup_metadata,
        principal_id,
        requesting_device_id,
        None,
        None,
    )
    .await
}

pub async fn fetch_key_backup_with_recovery_session_unlock_proof(
    api: &crate::transport::TransportClient,
    backup_metadata: &Value,
    principal_id: &str,
    requesting_device_id: &str,
    recovery_session: &arkret_sdk::RecoverySessionState,
    recovery_key_material: &arkret_sdk::identity_root::IdentityRecoveryKeyMaterial,
) -> anyhow::Result<Value> {
    recovery_session.validate()?;
    if recovery_session.principal_id.as_str() != principal_id
        || recovery_session.requesting_device_id.as_str() != requesting_device_id
        || !matches!(
            recovery_session.state,
            arkret_sdk::SessionState::Verified | arkret_sdk::SessionState::Completed
        )
    {
        anyhow::bail!("key backup unlock recovery session binding mismatch");
    }
    let session = serde_json::to_value(recovery_session)?;
    fetch_key_backup_with_unlock_proof(
        api,
        backup_metadata,
        principal_id,
        requesting_device_id,
        Some(&session),
        Some((
            &recovery_key_material.recovery_proof_seed,
            recovery_session
                .proof_summary
                .as_ref()
                .and_then(|summary| summary.verification_method.as_ref())
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "verified recovery session omitted recovery verification method"
                    )
                })?
                .as_str(),
        )),
    )
    .await
}

async fn fetch_key_backup_with_unlock_proof(
    api: &crate::transport::TransportClient,
    backup_metadata: &Value,
    principal_id: &str,
    requesting_device_id: &str,
    recovery_session: Option<&Value>,
    recovery_key: Option<(&[u8; 32], &str)>,
) -> anyhow::Result<Value> {
    let backoff_scope = key_backup_unlock_backoff_scope(api, principal_id)?;
    if let Some(retry_after_ms) = key_backup_unlock_backoff_remaining_ms(&backoff_scope) {
        return Err(KeyBackupUnlockBackoff { retry_after_ms }.into());
    }
    let cache_key = unlocked_key_backup_cache_key(
        api,
        backup_metadata,
        principal_id,
        requesting_device_id,
        recovery_session
            .and_then(|session| session.get("recovery_session_id"))
            .and_then(Value::as_str),
    )?;
    if let Some(cached) = unlocked_key_backup_cache_get(&cache_key) {
        return Ok(cached);
    }
    let backup_id = required_str_anyhow(backup_metadata, "backup_id")?.to_owned();
    let proof = build_key_backup_unlock_proof_active(
        backup_metadata,
        principal_id,
        requesting_device_id,
        recovery_session,
        recovery_key,
    )?;
    let backup = match api
        .get_key_backup_with_unlock_proof(&backup_id, &proof)
        .await
    {
        Ok(backup) => backup,
        Err(error) => {
            if let Some(retry_after_ms) = crate::api_error::rate_limited_retry_after(&error) {
                note_key_backup_unlock_backoff(&backoff_scope, retry_after_ms);
            }
            return Err(error);
        }
    };
    // Callers fold the full backup envelope through lenient `Value` accessors;
    // serialize the typed `KeyBackup` back to its wire JSON.
    let backup = serde_json::to_value(&backup)?;
    unlocked_key_backup_cache_put(cache_key, &backup);
    Ok(backup)
}

pub async fn fetch_key_backup_for_verified_recovery_session(
    api: &crate::transport::TransportClient,
    backup_metadata: &Value,
    session: &arkret_models_crypto::RecoverySessionState,
) -> anyhow::Result<Value> {
    session.validate()?;
    if session.state != arkret_models_crypto::SessionState::Verified {
        anyhow::bail!("key backup recovery requires a verified recovery session");
    }
    let session_value = serde_json::to_value(session)?;
    let backup_id = required_str_anyhow(backup_metadata, "backup_id")?.to_owned();
    let proof = build_key_backup_unlock_proof_active(
        backup_metadata,
        session.principal_id.as_str(),
        session.requesting_device_id.as_str(),
        Some(&session_value),
        None,
    )?;
    let backup = api
        .get_key_backup_with_unlock_proof(&backup_id, &proof)
        .await?;
    serde_json::to_value(backup).map_err(anyhow::Error::from)
}

fn key_backup_unlock_backoff_scope(
    api: &crate::transport::TransportClient,
    principal_id: &str,
) -> anyhow::Result<String> {
    let endpoint = api.endpoint("_arkret/self/keys/backups")?;
    Ok(format!(
        "{}|principal={}",
        endpoint.as_str(),
        principal_id.trim()
    ))
}

fn key_backup_unlock_backoff_remaining_ms(scope: &str) -> Option<u64> {
    let now_ms = crate::clock::now_unix_ms();
    KEY_BACKUP_UNLOCK_BACKOFFS.with(|backoffs| backoffs.borrow_mut().remaining_ms(scope, now_ms))
}

fn note_key_backup_unlock_backoff(scope: &str, retry_after_ms: u64) {
    let until_ms = crate::clock::now_unix_ms().saturating_add(retry_after_ms.max(1_000));
    KEY_BACKUP_UNLOCK_BACKOFFS.with(|backoffs| backoffs.borrow_mut().note_until(scope, until_ms));
}

fn unlocked_key_backup_cache_key(
    api: &crate::transport::TransportClient,
    backup_metadata: &Value,
    principal_id: &str,
    requesting_device_id: &str,
    recovery_session_id: Option<&str>,
) -> anyhow::Result<String> {
    let endpoint = api.endpoint("_arkret/self/keys/backups")?;
    let backup_id = required_str_anyhow(backup_metadata, "backup_id")?;
    let backup_kind = required_str_anyhow(backup_metadata, "backup_kind")?;
    let series_id = required_str_anyhow(backup_metadata, "series_id")?;
    let ciphertext_digest = required_str_anyhow(backup_metadata, "ciphertext_digest")?;
    Ok(format!(
        "{}|principal={}|device={}|recovery_session={}|backup={backup_id}|class={backup_kind}|series={series_id}|digest={ciphertext_digest}",
        endpoint.as_str(),
        principal_id.trim(),
        requesting_device_id.trim(),
        recovery_session_id.unwrap_or("none")
    ))
}

fn unlocked_key_backup_cache_get(cache_key: &str) -> Option<Value> {
    UNLOCKED_KEY_BACKUP_CACHE.with(|cache| {
        let mut entries = cache.borrow_mut();
        let index = entries
            .iter()
            .position(|(entry_key, _)| entry_key == cache_key)?;
        let (entry_key, value) = entries.remove(index);
        let result = value.clone();
        entries.push((entry_key, value));
        Some(result)
    })
}

fn unlocked_key_backup_cache_put(cache_key: String, backup: &Value) {
    if backup.get("ciphertext").and_then(Value::as_str).is_none() {
        return;
    }
    UNLOCKED_KEY_BACKUP_CACHE.with(|cache| {
        let mut entries = cache.borrow_mut();
        if let Some(index) = entries
            .iter()
            .position(|(entry_key, _)| entry_key == cache_key.as_str())
        {
            entries.remove(index);
        }
        entries.push((cache_key, backup.clone()));
        while entries.len() > UNLOCKED_KEY_BACKUP_CACHE_MAX_ENTRIES {
            entries.remove(0);
        }
    });
}

#[cfg(test)]
fn clear_key_backup_unlock_memory() {
    UNLOCKED_KEY_BACKUP_CACHE.with(|cache| cache.borrow_mut().clear());
    KEY_BACKUP_UNLOCK_BACKOFFS.with(|backoffs| backoffs.borrow_mut().clear());
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::event_signer::{ActiveSignerTestGuard, build_ed25519_signer, replace_active_signer};

    fn reset_signer() -> impl Drop {
        ActiveSignerTestGuard::replace(None)
    }

    #[test]
    fn unlock_proof_auth_data_matches_sdk_schema() {
        let _guard = reset_signer();
        let signer = Arc::new(build_ed25519_signer([11u8; 32], "did:web:alice.example"));
        let _ = replace_active_signer(Some(signer));
        let backup = json!({
            "backup_id": "ak:backup:0196419b-0000-7000-8000-000000000001",
            "backup_kind": "mls_history",
            "series_id": "ak:backup_series:0196419b-0000-7000-8000-000000000002",
            "ciphertext_digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        });

        let proof = build_key_backup_unlock_proof_active(
            &backup,
            "did:web:alice.example",
            "ak:device:0196419b-0000-7000-8000-000000000003",
            None,
            None,
        )
        .expect("unlock proof builds");

        assert!(proof["auth_data"].get("device_id").is_none());
        // The device-signed path (no recovery session) MUST declare
        // `principal_signing`: it is the only proof_kind the server exempts from
        // requiring a durable recovery-session record. Declaring a recovery-
        // ceremony kind (e.g. `recovery_unlock`) makes the server fail closed with
        // `recovery_evidence_unbound` and permanently locks shared-history cards.
        assert_eq!(proof["proof_kind"], "principal_signing");
        serde_json::from_value::<arkret_sdk::KeyBackupUnlockProof>(proof)
            .expect("unlock proof matches SDK schema");
    }

    #[test]
    fn unlocked_key_backup_cache_reuses_digest_and_evicts_oldest() {
        clear_key_backup_unlock_memory();
        let key = "server|principal=alice|device=dev|backup=one|digest=sha256:a";
        let backup = json!({
            "backup_id": "ak:backup:one",
            "ciphertext": "ciphertext-a"
        });

        unlocked_key_backup_cache_put(key.to_owned(), &backup);
        assert_eq!(
            unlocked_key_backup_cache_get(key).and_then(|value| {
                value
                    .get("ciphertext")
                    .and_then(Value::as_str)
                    .map(str::to_owned)
            }),
            Some("ciphertext-a".to_owned())
        );

        for index in 0..(UNLOCKED_KEY_BACKUP_CACHE_MAX_ENTRIES + 1) {
            unlocked_key_backup_cache_put(
                format!("server|principal=alice|device=dev|backup={index}|digest=sha256:{index}"),
                &json!({
                    "backup_id": format!("ak:backup:{index}"),
                    "ciphertext": format!("ciphertext-{index}")
                }),
            );
        }

        assert!(
            unlocked_key_backup_cache_get(key).is_none(),
            "oldest full-backup cache entry must be evicted"
        );
    }

    #[test]
    fn unlock_backoff_reports_remaining_retry_window() {
        clear_key_backup_unlock_memory();
        let scope = "server|principal=alice";

        assert!(key_backup_unlock_backoff_remaining_ms(scope).is_none());
        note_key_backup_unlock_backoff(scope, 30_000);
        let remaining = key_backup_unlock_backoff_remaining_ms(scope)
            .expect("backoff must be visible after rate limit");
        assert!(remaining > 0 && remaining <= 30_000);
    }
}
