use std::cell::RefCell;
use std::fmt;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
#[cfg(test)]
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde_json::Value;

use super::required_str_anyhow;

const KEY_BACKUP_UNLOCK_BACKOFF_MAX_ENTRIES: usize = 32;

/// Host receipt for one exact holder-bound request. A saved ciphertext is
/// local material; re-reading it does not consume another server unlock.
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredUnlockRequest {
    proof: arkret_sdk::KeyBackupUnlockProof,
    backup: Option<arkret_sdk::KeyBackup>,
}

pub(crate) fn backup_matches_summary(
    backup: &arkret_sdk::KeyBackup,
    summary: &arkret_sdk::KeyBackupSummary,
) -> bool {
    backup.validate().is_ok()
        && backup.backup_id == summary.backup_id
        && backup.actor_id == summary.actor_id
        && backup.device_id == summary.device_id
        && backup.backup_kind == summary.backup_kind
        && backup.backup_version == summary.backup_version.as_str()
        && backup.series_id == summary.series_id
        && backup.series_seq == summary.series_seq
        && backup.ciphertext_digest == summary.ciphertext_digest
        && backup.supersedes_id == summary.supersedes_id.clone().flatten()
        && backup.supersedes_digest == summary.supersedes_digest
        && backup.created_at == summary.created_at
        && backup.updated_at == summary.updated_at
        && backup.expires_at == summary.expires_at.flatten()
        && backup.encryption.recipient_method == summary.encryption.recipient_method
        && backup.encryption.recipient_key_ref == summary.encryption.recipient_key_ref
}

thread_local! {
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

#[cfg(test)]
/// Check a key-backup envelope's `auth_data.signature` against
/// `verifying_key`, recomputing `canonical_json(envelope without
/// auth_data.signature)`. SDK validation first enforces the closed transcript
/// shape and all envelope cross-field invariants.
/// Returns `Err` (caller maps to `untrusted_backup_signature`) on any mismatch.
pub fn verify_key_backup_auth_data(
    backup: &arkret_sdk::KeyBackup,
    verifying_key: &VerifyingKey,
) -> Result<(), String> {
    backup.validate().map_err(|error| error.to_string())?;
    let auth = &backup.auth_data;
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

pub fn build_key_backup_unlock_proof(
    backup: &arkret_sdk::KeyBackupSummary,
    principal_id: &str,
    requesting_device_id: &str,
    recovery_session: Option<&arkret_sdk::RecoverySession>,
    challenge: Option<&arkret_sdk::KeysBackupsUnlockChallenge>,
    audience: &str,
    signer: &std::sync::Arc<crate::event_signer::InksonEventSigner>,
) -> anyhow::Result<arkret_sdk::KeyBackupUnlockProof> {
    let account = backup
        .actor_id
        .as_account_id()
        .ok_or_else(|| anyhow::anyhow!("backup owner is not an account"))?
        .clone();
    anyhow::ensure!(
        account.principal_id == crate::mls_api_helpers::principal_core_id(principal_id)?,
        "backup account mismatch"
    );
    let device_id = arkret_sdk::DeviceId::new(requesting_device_id.to_owned())?;
    anyhow::ensure!(
        signer.device_id() == Some(requesting_device_id),
        "unlock signer device mismatch"
    );
    let issued_at = crate::clock::now_utc();
    let (authority, challenge_bytes, expires_at, method) = if let Some(session) = recovery_session {
        session.validate_shape()?;
        anyhow::ensure!(
            session.state == arkret_sdk::RecoverySessionState::Verified
                && session.expires_at > issued_at
                && session.account_id == account
                && session.requesting_device_id == device_id,
            "recovery unlock session is not current"
        );
        let multibase = signer
            .public_key_multibase()
            .ok_or_else(|| anyhow::anyhow!("replacement device identity key missing"))?;
        let did = format!("did:key:{multibase}");
        anyhow::ensure!(
            session.requesting_device_public_key_did.as_str() == did,
            "unlock signer differs from frozen replacement identity"
        );
        (
            arkret_sdk::KeyBackupUnlockAuthority::RecoverySession {
                recovery_session_id: session.recovery_session_id.clone(),
            },
            session.challenge.clone(),
            session.expires_at,
            format!("{did}#{multibase}"),
        )
    } else {
        let challenge = challenge
            .ok_or_else(|| anyhow::anyhow!("server-issued unlock challenge is required"))?;
        anyhow::ensure!(
            challenge.account_id == account
                && challenge.requesting_device_id == device_id
                && challenge.backup_id == backup.backup_id
                && challenge.series_id == backup.series_id
                && challenge.ciphertext_digest == backup.ciphertext_digest
                && challenge.audience.as_str() == audience
                && challenge.service_id == account.station_id
                && challenge.operation == "ak.self.keys.backups.command.unlock.v1"
                && challenge.issued_at <= issued_at
                && challenge.expires_at > issued_at,
            "server unlock challenge binding mismatch"
        );
        (
            arkret_sdk::KeyBackupUnlockAuthority::CurrentDevice {
                challenge_id: challenge.challenge_id.clone(),
                nonce: challenge.nonce.clone(),
            },
            challenge.challenge.clone(),
            challenge.expires_at,
            signer.verification_method().to_owned(),
        )
    };
    let mut proof = arkret_sdk::KeyBackupUnlockProof {
        schema: arkret_sdk::KeyBackupUnlockProof::SCHEMA.to_owned(),
        authority,
        account_id: account.clone(),
        requesting_device_id: device_id,
        backup_id: backup.backup_id.clone(),
        backup_kind: backup.backup_kind,
        series_id: backup.series_id.clone(),
        ciphertext_digest: backup.ciphertext_digest.clone(),
        challenge: challenge_bytes,
        service_id: account.station_id,
        audience: arkret_sdk::NonEmptyString::new(audience.to_owned())
            .map_err(anyhow::Error::msg)?,
        issued_at,
        expires_at,
        auth_data: arkret_sdk::KeyBackupUnlockProofAuthData {
            verification_method: arkret_sdk::DidUrl::new(method).map_err(anyhow::Error::msg)?,
            signature_algorithm: arkret_sdk::KeyBackupSignatureAlgorithm::Ed25519,
            // The signature is excluded from the canonical transcript. A
            // schema-shaped placeholder lets the current closed public type
            // produce those bytes before the exact signature is attached.
            signature: arkret_sdk::Base64UrlString::new(B64.encode([0u8; 64]))
                .map_err(anyhow::Error::msg)?,
        },
    };
    let signature = signer.sign_raw(&proof.signing_payload_bytes()?)?;
    proof.auth_data.signature =
        arkret_sdk::Base64UrlString::new(B64.encode(signature)).map_err(anyhow::Error::msg)?;
    proof.validate()?;
    Ok(proof)
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
        signer,
    )
    .await
}

pub(crate) fn key_backup_unlock_retry_delay(error: &anyhow::Error) -> Option<std::time::Duration> {
    let delay = error
        .downcast_ref::<KeyBackupUnlockBackoff>()
        .map(KeyBackupUnlockBackoff::retry_after_ms)
        .or_else(|| crate::api_error::rate_limited_retry_after(error))?;
    Some(std::time::Duration::from_millis(if delay == 0 {
        60_000
    } else {
        delay
    }))
}

async fn retry_key_backup_unlock<T, F, R, W, S>(mut fetch: F, mut wait: W) -> anyhow::Result<T>
where
    F: FnMut() -> R,
    R: std::future::Future<Output = anyhow::Result<T>>,
    W: FnMut(std::time::Duration) -> S,
    S: std::future::Future<Output = ()>,
{
    loop {
        let error = match fetch().await {
            Ok(body) => return Ok(body),
            Err(error) => error,
        };
        let Some(delay) = key_backup_unlock_retry_delay(&error) else {
            return Err(error);
        };
        wait(delay).await;
    }
}

/// Wait only on a download's typed unlock rate limit, before an uploader
/// generates or submits a successor. The underlying fetch retains the exact
/// holder-bound proof and verified ciphertext receipt across these attempts.
pub(crate) async fn fetch_key_backup_with_device_unlock_proof_retrying(
    api: &crate::transport::TransportClient,
    backup_metadata: &Value,
    principal_id: &str,
    requesting_device_id: &str,
    signer: Option<&std::sync::Arc<crate::event_signer::InksonEventSigner>>,
) -> anyhow::Result<Value> {
    retry_key_backup_unlock(
        || {
            fetch_key_backup_with_device_unlock_proof(
                api,
                backup_metadata,
                principal_id,
                requesting_device_id,
                signer,
            )
        },
        crate::runtime_helpers::sleep_for,
    )
    .await
}

pub async fn fetch_key_backup_with_recovery_session_unlock_proof(
    api: &crate::transport::TransportClient,
    backup_metadata: &Value,
    principal_id: &str,
    requesting_device_id: &str,
    recovery_session: &arkret_sdk::RecoverySession,
) -> anyhow::Result<Value> {
    recovery_session.validate_shape()?;
    if recovery_session.account_id.principal_id.as_str() != principal_id
        || recovery_session.requesting_device_id.as_str() != requesting_device_id
        || !matches!(
            recovery_session.state,
            arkret_sdk::RecoverySessionState::Verified
        )
    {
        anyhow::bail!("key backup unlock recovery session binding mismatch");
    }
    let signer = crate::event_signer::active_signer()
        .ok_or_else(|| anyhow::anyhow!("replacement device identity signer is required"))?;
    fetch_key_backup_with_unlock_proof(
        api,
        backup_metadata,
        principal_id,
        requesting_device_id,
        Some(recovery_session),
        Some(&signer),
    )
    .await
}

async fn fetch_key_backup_with_unlock_proof(
    api: &crate::transport::TransportClient,
    backup_metadata: &Value,
    principal_id: &str,
    requesting_device_id: &str,
    recovery_session: Option<&arkret_sdk::RecoverySession>,
    signer: Option<&std::sync::Arc<crate::event_signer::InksonEventSigner>>,
) -> anyhow::Result<Value> {
    let backoff_scope = key_backup_unlock_backoff_scope(api, principal_id)?;
    let request_key = unlock_request_storage_key(
        api,
        backup_metadata,
        principal_id,
        requesting_device_id,
        recovery_session.map(|session| session.recovery_session_id.as_str()),
    )?;
    let summary = serde_json::from_value::<arkret_sdk::KeyBackupSummary>(backup_metadata.clone())?;
    let backup_id = summary.backup_id.to_string();
    let audience = api
        .endpoint("_arkret/self/keys/backups")?
        .origin()
        .ascii_serialization();
    let request_lock = unlock_request_lock(&request_key);
    let _guard = request_lock.lock().await;
    let secure_store = crate::secure_key_store::default_secure_key_store("inkson");
    let stored = load_unlock_request(secure_store.as_ref(), &request_key)?;
    if let Some(backup) = stored.as_ref().and_then(|stored| stored.backup.as_ref()) {
        anyhow::ensure!(
            backup_matches_summary(backup, &summary),
            "saved unlock result differs from current metadata"
        );
        return Ok(serde_json::to_value(backup)?);
    }
    if let Some(retry_after_ms) = key_backup_unlock_backoff_remaining_ms(&backoff_scope) {
        return Err(KeyBackupUnlockBackoff { retry_after_ms }.into());
    }
    let proof = if let Some(stored) = stored {
        stored.proof
    } else {
        let issued = if recovery_session.is_none() {
            let request = arkret_sdk::KeysBackupsIssueUnlockChallengeRequestBody {
                request_id: arkret_sdk::Base64UrlString::new(
                    B64.encode(crate::operation::uuid_v7().as_bytes()),
                )
                .map_err(anyhow::Error::msg)?,
            };
            Some(
                api.sdk_http_client()?
                    .issue_key_backup_unlock_challenge(&summary.backup_id, &request)
                    .await?,
            )
        } else {
            None
        };
        let proof = build_key_backup_unlock_proof(
            &summary,
            principal_id,
            requesting_device_id,
            recovery_session,
            issued.as_ref(),
            &audience,
            signer.ok_or_else(|| anyhow::anyhow!("unlock identity signer missing"))?,
        )?;
        // Persist the exact signed request before the first send so process restart
        // and a lost response cannot re-sign an already-consumed recovery allowance.
        store_unlock_request(secure_store.as_ref(), &request_key, &proof, None).await?;
        proof
    };
    let backup = match api
        .get_key_backup_with_unlock_proof(&backup_id, &proof)
        .await
    {
        Ok(backup) => backup,
        Err(error) => {
            // A terminal rejection of an expired ordinary challenge permits a new
            // issuance on the next user retry. Transport uncertainty retains the
            // exact request, as does every recovery-session allowance.
            if recovery_session.is_none()
                && proof.expires_at <= crate::clock::now_utc()
                && crate::api_error::api_error_status_and_envelope(&error)
                    .is_some_and(|(status, _)| status == reqwest::StatusCode::CONFLICT)
            {
                secure_store.delete_secret(&request_key)?;
            }
            if let Some(retry_after_ms) = crate::api_error::rate_limited_retry_after(&error) {
                note_key_backup_unlock_backoff(&backoff_scope, retry_after_ms);
            }
            return Err(error);
        }
    };
    anyhow::ensure!(
        backup_matches_summary(&backup, &summary),
        "unlock result differs from current metadata"
    );
    store_unlock_request(secure_store.as_ref(), &request_key, &proof, Some(&backup)).await?;
    // Callers fold the full backup envelope through lenient `Value` accessors;
    // serialize the typed `KeyBackup` back to its wire JSON.
    let backup = serde_json::to_value(&backup)?;
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
    let delay = if retry_after_ms == 0 {
        60_000
    } else {
        retry_after_ms.max(1_000)
    };
    let until_ms = crate::clock::now_unix_ms().saturating_add(delay);
    KEY_BACKUP_UNLOCK_BACKOFFS.with(|backoffs| backoffs.borrow_mut().note_until(scope, until_ms));
}

fn unlock_request_storage_key(
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
    let holder_scope = if recovery_session_id.is_some() {
        String::new()
    } else {
        arkret_sdk::canonical::sha256_digest(api.context().credential.as_bytes())
    };
    let scope = format!(
        "{}|principal={}|device={}|recovery_session={}|holder={holder_scope}|backup={backup_id}|class={backup_kind}|series={series_id}|digest={ciphertext_digest}",
        endpoint.as_str(),
        principal_id.trim(),
        requesting_device_id.trim(),
        recovery_session_id.unwrap_or("none")
    );
    let summary: arkret_sdk::KeyBackupSummary = serde_json::from_value(backup_metadata.clone())?;
    let account = summary
        .actor_id
        .as_account_id()
        .ok_or_else(|| anyhow::anyhow!("backup owner is not an account"))?;
    let user_store = crate::secure_key_store::UserLocalStore::new(
        account.clone(),
        arkret_sdk::DeviceId::new(requesting_device_id.to_owned())?,
    )?;
    Ok(user_store.secret_key(&format!(
        "key_backup.unlock_request.v1.{}",
        arkret_sdk::canonical::sha256_digest(scope.as_bytes())
    )))
}

fn unlock_request_lock(key: &str) -> std::sync::Arc<tokio::sync::Mutex<()>> {
    use std::sync::{Arc, Mutex, OnceLock, Weak};
    type Locks = std::collections::BTreeMap<String, Weak<tokio::sync::Mutex<()>>>;
    static LOCKS: OnceLock<Mutex<Locks>> = OnceLock::new();
    let mut locks = LOCKS
        .get_or_init(|| Mutex::new(Locks::new()))
        .lock()
        .expect("unlock lock registry");
    locks.retain(|_, value| value.strong_count() > 0);
    if let Some(lock) = locks.get(key).and_then(Weak::upgrade) {
        return lock;
    }
    let lock = Arc::new(tokio::sync::Mutex::new(()));
    locks.insert(key.to_owned(), Arc::downgrade(&lock));
    lock
}

fn load_unlock_request(
    store: &dyn crate::secure_key_store::SecureKeyStore,
    key: &str,
) -> anyhow::Result<Option<StoredUnlockRequest>> {
    store
        .get_secret(key)?
        .map(|value| serde_json::from_str(&value).map_err(anyhow::Error::from))
        .transpose()
}
async fn store_unlock_request(
    store: &dyn crate::secure_key_store::SecureKeyStore,
    key: &str,
    proof: &arkret_sdk::KeyBackupUnlockProof,
    backup: Option<&arkret_sdk::KeyBackup>,
) -> anyhow::Result<()> {
    store
        .store_secret_durable(
            key,
            &serde_json::to_string(&StoredUnlockRequest {
                proof: proof.clone(),
                backup: backup.cloned(),
            })?,
        )
        .await?;
    Ok(())
}

#[cfg(test)]
fn clear_key_backup_unlock_memory() {
    KEY_BACKUP_UNLOCK_BACKOFFS.with(|backoffs| backoffs.borrow_mut().clear());
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use serde_json::json;

    use super::*;

    fn cached_body() -> arkret_sdk::KeyBackup {
        let mut value = crate::test_support::key_backup_envelope_fixture(
            0,
            "ak:backup_series:0196419b-0000-7000-8000-000000000010",
            "private_account_state",
            "secret_storage_key",
        );
        value["encryption"]["recipient_key_ref"] = json!("local-test-key");
        let body: arkret_sdk::KeyBackup = serde_json::from_value(value).unwrap();
        body.validate().unwrap();
        body
    }

    #[test]
    fn cached_ciphertext_requires_the_same_complete_metadata_binding() {
        let body = cached_body();
        let summary =
            crate::test_support::key_backup_summary_fixture(&serde_json::to_value(&body).unwrap());
        assert!(backup_matches_summary(&body, &summary));
        let mut changed = summary.clone();
        changed.ciphertext_digest =
            arkret_sdk::Hash::new(format!("sha256:{}", "b".repeat(64))).unwrap();
        assert!(!backup_matches_summary(&body, &changed));
        let mut changed = summary.clone();
        changed.actor_id = arkret_sdk::ActorId::account(arkret_sdk::AccountId::new(
            arkret_sdk::DidCoreId::new("ak:did_core:web:alice.example").unwrap(),
            arkret_sdk::DidCoreId::new("ak:did_core:web:other.example").unwrap(),
        ));
        assert!(!backup_matches_summary(&body, &changed));
        let mut changed = summary;
        changed.series_seq += 1;
        assert!(!backup_matches_summary(&body, &changed));
    }

    #[tokio::test]
    async fn unlock_proof_auth_data_matches_sdk_schema_and_survives_retry() {
        let signer = Arc::new(crate::event_signer::build_ed25519_device_signer(
            [11u8; 32],
            "did:web:alice.example",
            "ak:device:0196419b-0000-7000-8000-000000000003",
        ));
        let backup = arkret_sdk::KeyBackupSummary {
            backup_id: arkret_sdk::BackupId::new("ak:backup:0196419b-0000-7000-8000-000000000001")
                .unwrap(),
            actor_id: crate::mls_api_helpers::local_account_actor_id("did:web:alice.example")
                .unwrap(),
            device_id: None,
            backup_kind: arkret_sdk::BackupKind::SecretStorage,
            backup_version: arkret_sdk::NonEmptyString::new("kb_1").unwrap(),
            supersedes_id: None,
            supersedes_digest: None,
            created_at: chrono::Utc::now(),
            updated_at: None,
            expires_at: None,
            retention: None,
            ciphertext_digest: arkret_sdk::Hash::new(
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            )
            .unwrap(),
            encryption: arkret_sdk::KeyBackupSummaryEncryption {
                recipient_method: arkret_sdk::KeyBackupRecipientMethod::SecretStorageKey,
                recipient_key_ref: Some("mls_group_secrets_backup_key".to_owned()),
            },
            series_id: arkret_sdk::BackupSeriesId::new(
                "ak:backup_series:0196419b-0000-7000-8000-000000000002",
            )
            .unwrap(),
            series_seq: 0,
        };

        let account = backup.actor_id.as_account_id().unwrap().clone();
        let now = crate::clock::now_utc_canonical();
        let challenge = arkret_sdk::KeysBackupsUnlockChallenge {
            challenge_id: arkret_sdk::Base64UrlString::new("A".repeat(22)).unwrap(),
            challenge: arkret_sdk::Base64UrlString::new("A".repeat(43)).unwrap(),
            nonce: arkret_sdk::Base64UrlString::new(B64.encode([1u8; 16])).unwrap(),
            operation: "ak.self.keys.backups.command.unlock.v1".to_owned(),
            account_id: account.clone(),
            requesting_device_id: arkret_sdk::DeviceId::new(
                "ak:device:0196419b-0000-7000-8000-000000000003",
            )
            .unwrap(),
            backup_id: backup.backup_id.clone(),
            series_id: backup.series_id.clone(),
            ciphertext_digest: backup.ciphertext_digest.clone(),
            audience: arkret_sdk::NonEmptyString::new("https://station.example").unwrap(),
            service_id: account.station_id,
            request_id: arkret_sdk::Base64UrlString::new(B64.encode([2u8; 16])).unwrap(),
            issued_at: now,
            expires_at: now + chrono::Duration::seconds(300),
        };
        let proof = build_key_backup_unlock_proof(
            &backup,
            "did:web:alice.example",
            "ak:device:0196419b-0000-7000-8000-000000000003",
            None,
            Some(&challenge),
            "https://station.example",
            &signer,
        )
        .unwrap();
        proof.validate().expect("unlock proof validates");
        let signature =
            Signature::from_slice(&B64.decode(proof.auth_data.signature.as_str()).unwrap())
                .unwrap();
        ed25519_dalek::SigningKey::from_bytes(&[11u8; 32])
            .verifying_key()
            .verify_strict(&proof.signing_payload_bytes().unwrap(), &signature)
            .unwrap();

        let store = crate::secure_key_store::MemorySecureKeyStore::default();
        store_unlock_request(&store, "scoped-unlock-request", &proof, None)
            .await
            .unwrap();
        let replay = load_unlock_request(&store, "scoped-unlock-request")
            .unwrap()
            .unwrap();
        assert_eq!(
            serde_json::to_vec(&proof).unwrap(),
            serde_json::to_vec(&replay.proof).unwrap()
        );
        assert!(
            load_unlock_request(&store, "other-account-request")
                .unwrap()
                .is_none()
        );
        let mut body = cached_body();
        body.backup_id = proof.backup_id.clone();
        body.series_id = proof.series_id.clone();
        store_unlock_request(&store, "scoped-unlock-request", &proof, Some(&body))
            .await
            .unwrap();
        let receipt = load_unlock_request(&store, "scoped-unlock-request")
            .unwrap()
            .unwrap();
        assert_eq!(receipt.backup, Some(body));
        assert_eq!(
            serde_json::to_vec(&receipt.proof).unwrap(),
            serde_json::to_vec(&proof).unwrap()
        );
        let proof_value = serde_json::to_value(&proof).unwrap();
        assert!(proof_value["auth_data"].get("device_id").is_none());
        assert_eq!(proof_value["kind"], "current_device");
        assert!(proof_value.get("recovery_session_id").is_none());
        assert!(proof_value.get("proof_digest").is_none());
        let decoded: arkret_sdk::KeyBackupUnlockProof =
            serde_json::from_value(proof_value).unwrap();
        assert_eq!(
            decoded.signing_payload_bytes().unwrap(),
            proof.signing_payload_bytes().unwrap()
        );
    }

    #[test]
    fn recovery_session_unlock_uses_frozen_device_key_and_rejects_pending_session() {
        let signer = Arc::new(crate::event_signer::build_ed25519_device_signer(
            [12u8; 32],
            "did:web:alice.example",
            "ak:device:0196419b-0000-7000-8000-000000000003",
        ));
        let backup = arkret_sdk::KeyBackupSummary {
            backup_id: arkret_sdk::BackupId::new("ak:backup:0196419b-0000-7000-8000-000000000001")
                .unwrap(),
            actor_id: crate::mls_api_helpers::local_account_actor_id("did:web:alice.example")
                .unwrap(),
            device_id: None,
            backup_kind: arkret_sdk::BackupKind::SecretStorage,
            backup_version: arkret_sdk::NonEmptyString::new("kb_1").unwrap(),
            supersedes_id: None,
            supersedes_digest: None,
            created_at: chrono::Utc::now(),
            updated_at: None,
            expires_at: None,
            retention: None,
            ciphertext_digest: arkret_sdk::Hash::new(
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            )
            .unwrap(),
            encryption: arkret_sdk::KeyBackupSummaryEncryption {
                recipient_method: arkret_sdk::KeyBackupRecipientMethod::SecretStorageKey,
                recipient_key_ref: Some("mls_group_secrets_backup_key".to_owned()),
            },
            series_id: arkret_sdk::BackupSeriesId::new(
                "ak:backup_series:0196419b-0000-7000-8000-000000000002",
            )
            .unwrap(),
            series_seq: 0,
        };
        let account = backup.actor_id.as_account_id().unwrap().clone();
        let multibase = signer.public_key_multibase().unwrap();
        let frozen_did = format!("did:key:{multibase}");
        let verification_method = format!("{frozen_did}#{multibase}");
        let realm_id =
            arkret_sdk::RealmId::new("ak:realm:AS8XThowW7JnZc80U10gJh-_lqkA-iSQ-LAvBXj6_9O5")
                .unwrap();
        let commit_id = arkret_sdk::RealmCommitId::from_digest([9; 32]);
        let now = crate::clock::now_utc_canonical();
        let mut session_value = json!({
            "schema": "ak.schema.recovery_session.v1",
            "request_id": "ak:request:0198ff00-0000-7000-8000-00000000000b",
            "recovery_session_id": "ak:recovery_session:0198ff00-0000-7000-8000-00000000000c",
            "session_grant_id": "ak:session_grant:Af0GheZX08ev4L1fQoFdngIpe5c_9Lk7SQqfN4jztzDW",
            "session_grant_cnf_jkt": "Q25mSmt0Rml4dHVyZVZhbHVlMDAwMDAwMDAwMDAwMDAwMDAwMA",
            "account_id": account,
            "requesting_device_id": "ak:device:0196419b-0000-7000-8000-000000000003",
            "requesting_device_public_key_did": frozen_did,
            "trust_domain": "ak:trust_domain:example.net",
            "policy_id": "ak:policy:0198ff00-0000-7000-8000-000000000001",
            "policy_version": 1,
            "identity_model": "pcr_policy",
            "current_device_generation_ref": 3,
            "realm_stream_head": {
                "stream_ref": {"kind": "realm", "realm_id": realm_id},
                "stream_position": 12,
                "commit_id": commit_id
            },
            "publication_authority_context": {
                "authority_commit_id": commit_id,
                "scope_ref": {"kind": "realm", "realm_id": realm_id},
                "authority_set_policy": {
                    "schema": "ak.schema.authority_set_policy.v1",
                    "authority_set_id": "ak.authority_set.principal_control.v1",
                    "policy_kind": "principal_control",
                    "scope_ref": {"kind": "realm", "realm_id": realm_id},
                    "source_commit_id": commit_id,
                    "authorization_rules": [{
                        "rule_id": "identity_recovery",
                        "issuer_role": "identity_recovery",
                        "allowed_actions": ["ak.device.reanchor"],
                        "issuers": [{"verification_method": verification_method}],
                        "threshold": 1
                    }]
                },
                "allowed_actions": ["ak.device.reanchor"]
            },
            "publication_authority_context_digest":
                "sha256:abababababababababababababababababababababababababababababababab",
            "challenge": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "state": "verified",
            "proof_summary": {
                "kind": "recovery_unlock",
                "proof_digest":
                    "sha256:cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
                "verification_method": verification_method
            },
            "expires_at": now + chrono::Duration::minutes(10),
            "created_at": now - chrono::Duration::minutes(1),
            "updated_at": now
        });
        let session: arkret_sdk::RecoverySession =
            serde_json::from_value(session_value.clone()).unwrap();

        let proof = build_key_backup_unlock_proof(
            &backup,
            "did:web:alice.example",
            "ak:device:0196419b-0000-7000-8000-000000000003",
            Some(&session),
            None,
            "https://station.example",
            &signer,
        )
        .unwrap();
        assert!(matches!(
            proof.authority,
            arkret_sdk::KeyBackupUnlockAuthority::RecoverySession { .. }
        ));
        assert_eq!(
            proof.auth_data.verification_method.as_str(),
            verification_method
        );
        assert_eq!(proof.challenge.as_str(), session.challenge.as_str());
        assert_eq!(proof.expires_at, session.expires_at);
        let signature =
            Signature::from_slice(&B64.decode(proof.auth_data.signature.as_str()).unwrap())
                .unwrap();
        ed25519_dalek::SigningKey::from_bytes(&[12u8; 32])
            .verifying_key()
            .verify_strict(&proof.signing_payload_bytes().unwrap(), &signature)
            .unwrap();

        session_value["state"] = json!("pending");
        session_value
            .as_object_mut()
            .unwrap()
            .remove("proof_summary");
        let pending: arkret_sdk::RecoverySession = serde_json::from_value(session_value).unwrap();
        assert!(
            build_key_backup_unlock_proof(
                &backup,
                "did:web:alice.example",
                "ak:device:0196419b-0000-7000-8000-000000000003",
                Some(&pending),
                None,
                "https://station.example",
                &signer,
            )
            .is_err()
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
        let no_hint_scope = "server|principal=no-hint";
        note_key_backup_unlock_backoff(no_hint_scope, 0);
        let remaining = key_backup_unlock_backoff_remaining_ms(no_hint_scope).unwrap();
        assert!(remaining > 59_000 && remaining <= 60_000);
    }
    #[tokio::test]
    async fn backup_predecessor_download_waits_on_typed_rate_limits_only() {
        for (hint, expected) in [(Some(250), 250), (None, 60_000)] {
            let mut problem = arkret_sdk::Problem::new("rate_limited", 429, "slow down");
            if let Some(delay) = hint {
                problem = problem.with_extension("retry_after_ms", serde_json::json!(delay));
            }
            let error = anyhow::Error::from(arkret_sdk::Error::Api {
                status: 429,
                error: Box::new(problem),
            })
            .context("fetch active secret_storage series tail");
            let mut results = std::collections::VecDeque::from([Err(error), Ok(7_u32)]);
            let mut waits = Vec::new();
            let body = retry_key_backup_unlock(
                || std::future::ready(results.pop_front().unwrap()),
                |delay| {
                    waits.push(delay);
                    std::future::ready(())
                },
            )
            .await
            .unwrap();
            assert_eq!(body, 7);
            assert_eq!(waits, vec![std::time::Duration::from_millis(expected)]);
            assert!(results.is_empty());
        }
        let backoff = anyhow::Error::from(KeyBackupUnlockBackoff {
            retry_after_ms: 900,
        })
        .context("another caller observed the account cooldown");
        assert_eq!(
            key_backup_unlock_retry_delay(&backoff),
            Some(std::time::Duration::from_millis(900))
        );
        let mut waited = false;
        let rejected = retry_key_backup_unlock::<(), _, _, _, _>(
            || std::future::ready(Err(anyhow::anyhow!("signature invalid"))),
            |_| {
                waited = true;
                std::future::ready(())
            },
        )
        .await;
        assert!(rejected.is_err());
        assert!(!waited);
    }
}
