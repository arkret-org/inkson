use std::cell::RefCell;
use std::fmt;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde_json::Value;
#[cfg(test)]
use serde_json::json;

use super::required_str_anyhow;

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

/// Phase 2 verify: check a key-backup envelope's `auth_data.signature` against
/// `verifying_key`, recomputing `canonical_json(envelope without
/// auth_data.signature)`. SDK validation first enforces the exact canonical
/// `signed_fields` set and all envelope cross-field invariants.
/// Returns `Err` (caller maps to `untrusted_backup_signature`) on any mismatch.
pub fn verify_key_backup_auth_data(
    backup: &arkret_sdk::KeyBackup,
    verifying_key: &VerifyingKey,
) -> Result<(), String> {
    backup.validate().map_err(|error| error.to_string())?;
    let auth = backup
        .auth_data
        .as_ref()
        .ok_or_else(|| "auth_data is required".to_owned())?;
    if auth.signature_algorithm != arkret_sdk::KeyBackupSignatureAlgorithm::Ed25519 {
        return Err("auth_data.signature_algorithm must be Ed25519".to_owned());
    }
    let sig_bytes: [u8; 64] = B64
        .decode(auth.signature.as_str())
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(|| "auth_data.signature must be 64-byte base64url".to_owned())?;
    let signature = Signature::from_bytes(&sig_bytes);
    let payload = backup
        .signing_payload_bytes()
        .map_err(|error| error.to_string())?;
    verifying_key
        .verify(&payload, &signature)
        .map_err(|_| "untrusted_backup_signature: signature does not verify".to_owned())
}

// Invariant assertions: each `expect` message names the check that
// establishes it a few lines earlier. Rewriting them as `?` would add
// error paths no caller can reach.
#[allow(clippy::expect_used)]
pub fn build_key_backup_unlock_proof(
    backup: &arkret_sdk::KeyBackupSummary,
    principal_id: &str,
    requesting_device_id: &str,
    recovery_session: Option<&arkret_sdk::RecoverySessionState>,
    recovery_key: Option<(&[u8; 32], &str)>,
    signer: Option<&std::sync::Arc<crate::event_signer::InksonEventSigner>>,
) -> anyhow::Result<arkret_sdk::KeyBackupUnlockProof> {
    let active_signer = if recovery_key.is_none() {
        Some(signer.ok_or_else(|| {
            anyhow::anyhow!("device signer is required for key backup unlock proof")
        })?)
    } else {
        None
    };
    let issued_at = chrono::Utc::now();
    let (recovery_session_id, proof_kind, proof_digest) = if let Some(session) = recovery_session {
        let summary = session
            .proof_summary
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("verified recovery session missing proof_summary"))?;
        let kind = match summary.kind {
            arkret_sdk::RecoveryProofKind::PrincipalSigning => {
                arkret_sdk::ProofKind::PrincipalSigning
            }
            arkret_sdk::RecoveryProofKind::RecoveryUnlock => arkret_sdk::ProofKind::RecoveryUnlock,
            arkret_sdk::RecoveryProofKind::DeviceQuorum => arkret_sdk::ProofKind::DeviceQuorum,
            arkret_sdk::RecoveryProofKind::TrustedRecoveryService => {
                arkret_sdk::ProofKind::TrustedRecoveryService
            }
            arkret_sdk::RecoveryProofKind::ThresholdRecovery => {
                arkret_sdk::ProofKind::ThresholdRecovery
            }
        };
        (
            session.recovery_session_id.clone(),
            kind,
            summary.proof_digest.clone(),
        )
    } else {
        // Ordinary already-authorized-device restores use the only proof kind
        // that does not require a durable recovery session.
        let session_id = arkret_sdk::RecoverySessionId::new(format!(
            "ak:recovery_session:{}",
            crate::operation::uuid_v7()
        ))?;
        #[derive(serde::Serialize)]
        struct LocalUnlockProofDigest<'a> {
            #[serde(rename = "type")]
            record_type: &'static str,
            principal_id: &'a str,
            requesting_device_id: &'a str,
            backup_id: &'a arkret_sdk::BackupId,
            backup_kind: arkret_sdk::BackupKind,
            series_id: &'a arkret_sdk::BackupSeriesId,
            ciphertext_digest: &'a str,
            issued_at: String,
        }

        let local_digest = crate::canonical::canonical_sha256(&LocalUnlockProofDigest {
            record_type: "org.arkret.inkson.key_backup.local_unlock_proof.v1",
            principal_id,
            requesting_device_id,
            backup_id: &backup.backup_id,
            backup_kind: backup.backup_kind,
            series_id: &backup.series_id,
            ciphertext_digest: backup.ciphertext_digest.as_str(),
            issued_at: arkret_sdk::canonical::format_timestamp_canonical(issued_at),
        })?;
        (
            session_id,
            arkret_sdk::ProofKind::PrincipalSigning,
            arkret_sdk::Hash::new(local_digest)?,
        )
    };
    let verification_method = recovery_key
        .map(|(_, method)| method.to_owned())
        .unwrap_or_else(|| {
            active_signer
                .as_ref()
                .expect("checked above")
                .verification_method()
                .to_owned()
        });
    let auth = arkret_sdk::UnsignedKeyBackupUnlockProofAuthData::new(
        arkret_sdk::DidUrl::new(verification_method).map_err(anyhow::Error::msg)?,
        arkret_sdk::KeyBackupSignatureAlgorithm::Ed25519,
    )?;
    let unsigned = arkret_sdk::UnsignedKeyBackupUnlockProof::new(
        recovery_session_id,
        crate::mls_api_helpers::principal_core_id(principal_id)?,
        arkret_sdk::DeviceId::new(requesting_device_id.to_owned())?,
        backup.backup_id.clone(),
        backup.backup_kind,
        backup.series_id.clone(),
        arkret_sdk::Hash::new(backup.ciphertext_digest.clone())?,
        proof_kind,
        proof_digest,
        None,
        issued_at,
        auth,
    )?;
    let payload = unsigned.signing_payload_bytes()?;
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
    unsigned
        .attach_signature(
            arkret_sdk::Base64UrlString::new(B64.encode(signature)).map_err(anyhow::Error::msg)?,
        )
        .map_err(anyhow::Error::from)
}

pub async fn fetch_key_backup_with_device_unlock_proof(
    api: &crate::transport::TransportClient,
    backup_metadata: &Value,
    principal_id: &str,
    requesting_device_id: &str,
    signer: Option<&std::sync::Arc<crate::event_signer::InksonEventSigner>>,
) -> anyhow::Result<Value> {
    fetch_key_backup_with_unlock_proof(
        api,
        backup_metadata,
        principal_id,
        requesting_device_id,
        None,
        None,
        signer,
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
    if recovery_session.principal_authority.principal_id.as_str() != principal_id
        || recovery_session.requesting_device_id.as_str() != requesting_device_id
        || !matches!(
            recovery_session.state,
            arkret_sdk::SessionState::Verified | arkret_sdk::SessionState::Completed
        )
    {
        anyhow::bail!("key backup unlock recovery session binding mismatch");
    }
    fetch_key_backup_with_unlock_proof(
        api,
        backup_metadata,
        principal_id,
        requesting_device_id,
        Some(recovery_session),
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
        None,
    )
    .await
}

async fn fetch_key_backup_with_unlock_proof(
    api: &crate::transport::TransportClient,
    backup_metadata: &Value,
    principal_id: &str,
    requesting_device_id: &str,
    recovery_session: Option<&arkret_sdk::RecoverySessionState>,
    recovery_key: Option<(&[u8; 32], &str)>,
    signer: Option<&std::sync::Arc<crate::event_signer::InksonEventSigner>>,
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
        recovery_session.map(|session| session.recovery_session_id.as_str()),
    )?;
    if let Some(cached) = unlocked_key_backup_cache_get(&cache_key) {
        return Ok(cached);
    }
    let summary = serde_json::from_value::<arkret_sdk::KeyBackupSummary>(backup_metadata.clone())?;
    let backup_id = summary.backup_id.to_string();
    let proof = build_key_backup_unlock_proof(
        &summary,
        principal_id,
        requesting_device_id,
        recovery_session,
        recovery_key,
        signer,
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
    use crate::event_signer::build_ed25519_signer;

    #[test]
    fn unlock_proof_auth_data_matches_sdk_schema() {
        let signer = Arc::new(build_ed25519_signer([11u8; 32], "did:web:alice.example"));
        let backup = arkret_sdk::KeyBackupSummary {
            backup_id: arkret_sdk::BackupId::new("ak:backup:0196419b-0000-7000-8000-000000000001")
                .unwrap(),
            actor_id: crate::mls_api_helpers::principal_core_id("did:web:alice.example").unwrap(),
            device_id: None,
            backup_kind: arkret_sdk::BackupKind::MlsHistory,
            backup_version: "kb_1".to_owned(),
            created_at: chrono::Utc::now(),
            updated_at: None,
            expires_at: None,
            ciphertext_digest:
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned(),
            encryption: arkret_sdk::KeyBackupSummaryEncryption {
                recipient_method: arkret_sdk::KeyBackupRecipientMethod::SecretStorageKey,
                recipient_key_ref: Some("mls_group_secrets_backup_key".to_owned()),
            },
            series_id: arkret_sdk::BackupSeriesId::new(
                "ak:backup_series:0196419b-0000-7000-8000-000000000002",
            )
            .unwrap(),
            series_seq: 0,
            recovery_policy_ref: None,
            contents: Vec::new(),
        };

        let proof = build_key_backup_unlock_proof(
            &backup,
            "did:web:alice.example",
            "ak:device:0196419b-0000-7000-8000-000000000003",
            None,
            None,
            Some(&signer),
        )
        .expect("unlock proof builds");
        proof.validate().expect("unlock proof validates");

        let proof_value = serde_json::to_value(&proof).unwrap();
        assert!(proof_value["auth_data"].get("device_id").is_none());
        // The device-signed path (no recovery session) MUST declare
        // `principal_signing`: it is the only proof_kind the server exempts from
        // requiring a durable recovery-session record. Declaring a recovery-
        // ceremony kind (e.g. `recovery_unlock`) makes the server fail closed with
        // `recovery_evidence_unbound` and permanently locks shared-history cards.
        assert_eq!(
            proof.proof_kind,
            arkret_models_crypto::ProofKind::PrincipalSigning
        );
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
