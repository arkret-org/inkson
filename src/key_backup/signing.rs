use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use chrono::SecondsFormat;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde_json::{Value, json};

use super::{
    DEFAULT_SSK_GENERATION, KEY_BACKUP_RAW_SIGNATURE_ALGORITHM, KEY_BACKUP_SIGNED_FIELDS,
    KEY_BACKUP_SIGNED_FIELDS_MANDATORY, KEY_BACKUP_UNLOCK_PROOF_SCHEMA, required_str_anyhow,
};

#[derive(Clone, Debug)]
pub enum KeyBackupDeviceTrustAnchor {
    SskGeneration(u64),
    DeviceAuthorizeEventId(String),
}

/// Phase 2 (key-management.md §7.4.1, CKP-0013): sign a key-backup envelope with
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
    let mut auth = json!({
        "device_id": device_id,
        "verification_method": signer.verification_method(),
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
) -> anyhow::Result<Value> {
    let signer = crate::event_signer::active_signer()
        .ok_or_else(|| anyhow::anyhow!("active signer is required for key backup unlock proof"))?;
    let backup_id = required_str_anyhow(backup, "backup_id")?;
    let backup_class = required_str_anyhow(backup, "backup_class")?;
    let series_id = required_str_anyhow(backup, "series_id")?;
    let ciphertext_digest = required_str_anyhow(backup, "ciphertext_digest")?;
    let issued_at = chrono::Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true);
    let (recovery_session_id, proof_kind, proof_digest) = if let Some(session) = recovery_session {
        let session_id = required_str_anyhow(session, "recovery_session_id")?.to_owned();
        let summary = session
            .get("proof_summary")
            .ok_or_else(|| anyhow::anyhow!("verified recovery session missing proof_summary"))?;
        let kind = required_str_anyhow(summary, "kind")?.to_owned();
        let digest = required_str_anyhow(summary, "proof_digest")?.to_owned();
        (session_id, kind, digest)
    } else {
        let session_id = format!("ck:recovery_session:{}", crate::operation::uuid_v7());
        let local_digest = crate::canonical::canonical_sha256(&json!({
            "type": "ck.key_backup.local_unlock_proof.v1",
            "principal_id": principal_id,
            "requesting_device_id": requesting_device_id,
            "backup_id": backup_id,
            "backup_class": backup_class,
            "series_id": series_id,
            "ciphertext_digest": ciphertext_digest,
            "issued_at": issued_at,
        }))?;
        (session_id, "recovery_unlock".to_owned(), local_digest)
    };
    let signed_fields = vec![
        "schema",
        "recovery_session_id",
        "principal_id",
        "requesting_device_id",
        "backup_id",
        "backup_class",
        "series_id",
        "ciphertext_digest",
        "proof_kind",
        "proof_digest",
        "issued_at",
    ];
    let mut proof = json!({
        "schema": KEY_BACKUP_UNLOCK_PROOF_SCHEMA,
        "recovery_session_id": recovery_session_id,
        "principal_id": principal_id,
        "requesting_device_id": requesting_device_id,
        "backup_id": backup_id,
        "backup_class": backup_class,
        "series_id": series_id,
        "ciphertext_digest": ciphertext_digest,
        "proof_kind": proof_kind,
        "proof_digest": proof_digest,
        "issued_at": issued_at,
        "auth_data": {
            "verification_method": signer.verification_method(),
            "signature_algorithm": KEY_BACKUP_RAW_SIGNATURE_ALGORITHM,
            "signed_fields": signed_fields,
        }
    });
    let payload = crate::canonical::canonical_json_bytes(&proof)?;
    let signature = signer
        .sign_raw(&payload)
        .map_err(|err| anyhow::anyhow!("key backup unlock proof sign: {err:?}"))?;
    proof["auth_data"]["signature"] = Value::String(B64.encode(signature));
    Ok(proof)
}

pub async fn fetch_key_backup_with_active_unlock_proof(
    api: &crate::api::CokretApi,
    backup_metadata: &Value,
    principal_id: &str,
    requesting_device_id: &str,
) -> anyhow::Result<Value> {
    let backup_id = required_str_anyhow(backup_metadata, "backup_id")?.to_owned();
    let proof = build_key_backup_unlock_proof_active(
        backup_metadata,
        principal_id,
        requesting_device_id,
        None,
    )?;
    let backup = api
        .get_key_backup_with_unlock_proof(&backup_id, &proof)
        .await?;
    // Callers fold the full backup envelope through lenient `Value` accessors;
    // serialize the typed `KeyBackup` back to its wire JSON.
    Ok(serde_json::to_value(&backup)?)
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use super::*;
    use crate::event_signer::{build_ed25519_signer, replace_active_signer};

    static TEST_MUTEX: Mutex<()> = Mutex::new(());

    fn reset_signer() -> impl Drop {
        let guard = TEST_MUTEX.lock().unwrap_or_else(|error| error.into_inner());
        let _ = replace_active_signer(None);
        struct Reset(#[allow(dead_code)] std::sync::MutexGuard<'static, ()>);
        impl Drop for Reset {
            fn drop(&mut self) {
                let _ = replace_active_signer(None);
            }
        }
        Reset(guard)
    }

    #[test]
    fn unlock_proof_auth_data_matches_sdk_schema() {
        let _guard = reset_signer();
        let signer = Arc::new(build_ed25519_signer([11u8; 32], "did:web:alice.example"));
        let _ = replace_active_signer(Some(signer));
        let backup = json!({
            "backup_id": "ck:backup:0196419b-0000-7000-8000-000000000001",
            "backup_class": "mls_history",
            "series_id": "ck:backup_series:0196419b-0000-7000-8000-000000000002",
            "ciphertext_digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        });

        let proof = build_key_backup_unlock_proof_active(
            &backup,
            "did:web:alice.example",
            "ck:device:0196419b-0000-7000-8000-000000000003",
            None,
        )
        .expect("unlock proof builds");

        assert!(proof["auth_data"].get("device_id").is_none());
        serde_json::from_value::<cokret_sdk::KeyBackupUnlockProof>(proof)
            .expect("unlock proof matches SDK schema");
    }
}
