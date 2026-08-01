#[cfg(test)]
use std::collections::BTreeMap;

#[cfg(test)]
use base64::Engine as _;
#[cfg(test)]
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::Value;
#[cfg(test)]
use serde_json::json;

/// Canonical signing-input prefix for the `keys/upload` `device_signature`
/// (spec `device-lifecycle.md` §8.1).
// The keys/upload signing chain below is kept for wire-shape unit tests.
#[cfg(test)]
const KEYS_UPLOAD_SIGNATURE_PREFIX: &str = "ak.keys-upload-v1\n";

/// Build the spec `device-lifecycle.md` §8.1 canonical signing input for a
/// `keys/upload` `device_signature`:
///
/// ```text
/// "ak.keys-upload-v1\n" + canonical_json({device_id, one_time_keys, fallback_keys})
/// ```
///
/// Missing `one_time_keys` / `fallback_keys` batches MUST normalize to an empty
/// object `{}` (not be omitted) so sender and verifier hash byte-identical
/// input. The body object is canonicalized with RFC 8785 JCS via
/// [`crate::canonical`].
#[cfg(test)]
fn keys_upload_signing_input(
    device_id: &str,
    one_time_keys: &BTreeMap<String, Value>,
    fallback_keys: &BTreeMap<String, Value>,
) -> anyhow::Result<Vec<u8>> {
    let body = json!({
        "device_id": device_id,
        "one_time_keys": one_time_keys,
        "fallback_keys": fallback_keys,
    });
    let canonical = crate::canonical::canonical_json_bytes(&body)?;
    let mut input = Vec::with_capacity(KEYS_UPLOAD_SIGNATURE_PREFIX.len() + canonical.len());
    input.extend_from_slice(KEYS_UPLOAD_SIGNATURE_PREFIX.as_bytes());
    input.extend_from_slice(&canonical);
    Ok(input)
}

/// Produce the real raw-signature `device_signature` tuple for a `keys/upload` batch by
/// signing the §8.1 canonical input with the local event-signer (the device
/// identity Ed25519 `did:key`). Fail-closed (`bail!`) when no signer is
/// installed — never emit a placeholder.
#[cfg(test)]
pub(crate) fn device_signature_tuple_for_input(
    signer: &crate::event_signer::InksonEventSigner,
    signing_input: &[u8],
    context: &str,
) -> anyhow::Result<Value> {
    let sig = signer
        .sign_raw(signing_input)
        .map_err(|err| anyhow::anyhow!("{context} device_signature sign failed: {err}"))?;
    Ok(json!({
        "alg": signer.algorithm(),
        "kid": signer.verification_method(),
        "sig": URL_SAFE_NO_PAD.encode(sig),
    }))
}

#[cfg(test)]
pub(crate) fn sign_keys_upload_batch_with_signer(
    signer: &crate::event_signer::InksonEventSigner,
    device_id: &str,
    one_time_keys: &BTreeMap<String, Value>,
    fallback_keys: &BTreeMap<String, Value>,
) -> anyhow::Result<Value> {
    let input = keys_upload_signing_input(device_id, one_time_keys, fallback_keys)?;
    device_signature_tuple_for_input(signer, &input, "keys/upload")
}

fn key_backup_authorized_event_ref_for_device(viewer: &Value, device_id: &str) -> Option<String> {
    viewer
        .get("devices")
        .and_then(Value::as_array)?
        .iter()
        .find(|device| {
            device.get("device_id").and_then(Value::as_str) == Some(device_id)
                && device.get("status").and_then(Value::as_str) == Some("active")
        })
        .and_then(|device| {
            device
                .get("device_authorize_event_id")
                .or_else(|| device.get("authorized_event_ref"))
                .and_then(Value::as_str)
        })
        .map(str::trim)
        .filter(|event_id| !event_id.is_empty())
        .map(str::to_owned)
}

impl crate::transport::TransportClient {
    pub async fn put_key_backup(
        &self,
        backup_id: &str,
        payload: serde_json::Value,
        signer: crate::key_backup::KeyBackupSigner<'_>,
    ) -> anyhow::Result<arkret_sdk::KeysBackupsReplaceOutcome> {
        let (record, _) = self
            .prepare_key_backup_put_payload(backup_id, payload, signer)
            .await?;
        let backup_id = arkret_sdk::BackupId::new(backup_id.to_owned())
            .map_err(|err| anyhow::anyhow!("invalid key backup id: {err}"))?;
        let idempotency_key = key_backup_idempotency_key(&backup_id, &record)?;
        self.sdk_http_client()?
            .put_key_backup(&backup_id, &record, &idempotency_key)
            .await
            .map_err(anyhow::Error::from)
    }

    pub async fn put_key_backup_returning_sent_body(
        &self,
        backup_id: &str,
        payload: serde_json::Value,
        signer: crate::key_backup::KeyBackupSigner<'_>,
    ) -> anyhow::Result<(arkret_sdk::KeysBackupsReplaceOutcome, serde_json::Value)> {
        let (record, sent_body) = self
            .prepare_key_backup_put_payload(backup_id, payload, signer)
            .await?;
        let backup_id = arkret_sdk::BackupId::new(backup_id.to_owned())
            .map_err(|err| anyhow::anyhow!("invalid key backup id: {err}"))?;
        let idempotency_key = key_backup_idempotency_key(&backup_id, &record)?;
        let response = self
            .sdk_http_client()?
            .put_key_backup(&backup_id, &record, &idempotency_key)
            .await
            .map_err(anyhow::Error::from)?;
        Ok((response, sent_body))
    }

    async fn prepare_key_backup_put_payload(
        &self,
        backup_id: &str,
        payload: serde_json::Value,
        signer: crate::key_backup::KeyBackupSigner<'_>,
    ) -> anyhow::Result<(arkret_sdk::KeyBackup, serde_json::Value)> {
        crate::key_backup::validate_key_backup_put_request(backup_id, &payload)
            .map_err(|err| anyhow::anyhow!("invalid key backup envelope: {err}"))?;
        let record: arkret_sdk::KeyBackup = serde_json::from_value(payload)?;
        let mut payload = serde_json::to_value(&record)?;
        self.attach_key_backup_current_device_trust_anchor(&mut payload, signer)
            .await?;
        crate::key_backup::validate_key_backup_put_request(backup_id, &payload)
            .map_err(|err| anyhow::anyhow!("invalid key backup envelope: {err}"))?;
        let record: arkret_sdk::KeyBackup = serde_json::from_value(payload)?;
        let sent_body = serde_json::to_value(&record)?;
        Ok((record, sent_body))
    }

    async fn attach_key_backup_current_device_trust_anchor(
        &self,
        payload: &mut Value,
        signer: crate::key_backup::KeyBackupSigner<'_>,
    ) -> anyhow::Result<()> {
        let Some(device_id) = payload
            .get("device_id")
            .and_then(Value::as_str)
            .or_else(|| {
                payload
                    .get("auth_data")
                    .and_then(|auth| auth.get("device_id"))
                    .and_then(Value::as_str)
            })
            .map(str::to_owned)
        else {
            return Ok(());
        };
        let http = self.sdk_http_client()?;
        let viewer = crate::transport::keys::list_devices(&http).await.ok();
        // `key_backup_authorized_event_ref_for_device` reads the viewer's
        // `devices[]` leniently via `Value` accessors; serialize the typed
        // `AccountView` back to its wire JSON so the helper sees the same shape.
        let viewer_event_id = viewer
            .map(serde_json::to_value)
            .transpose()?
            .as_ref()
            .and_then(|viewer| key_backup_authorized_event_ref_for_device(viewer, &device_id));
        let actor_id = payload
            .get("actor_id")
            .and_then(Value::as_str)
            .or_else(|| payload.get("principal_id").and_then(Value::as_str));
        let query_event_id = if viewer_event_id.is_none() {
            if let Some(actor_id) = actor_id {
                let actor = arkret_sdk::Did::new(actor_id.to_owned())?;
                let device = arkret_sdk::DeviceId::new(device_id.clone())?;
                let outcome =
                    crate::transport::keys::query_keys(&http, actor_id, &device_id).await?;
                outcome
                    .device_keys
                    .get(&actor)
                    .and_then(|devices| devices.get(&device))
                    .and_then(|record| record.device_authorize_event_id.as_ref())
                    .map(ToString::to_string)
            } else {
                None
            }
        } else {
            None
        };
        let Some(event_id) = viewer_event_id.or(query_event_id) else {
            return Ok(());
        };
        let signed = crate::key_backup::sign_key_backup_with_device_and_trust_anchor(
            payload,
            &device_id,
            signer,
            Some(crate::key_backup::KeyBackupDeviceTrustAnchor::DeviceAuthorizeEventId(event_id)),
        )?;
        if !signed {
            anyhow::bail!("active device signer is required for service-attested key backup");
        }
        Ok(())
    }

    pub async fn list_key_backups(&self) -> anyhow::Result<arkret_sdk::KeysBackupsList> {
        let http = self.sdk_http_client()?;
        let mut backups = Vec::new();
        let mut cursor = None;
        let mut seen_cursors = std::collections::BTreeSet::new();
        loop {
            let page = http
                .list_key_backups(&arkret_sdk::KeyBackupsListQuery {
                    series_id: None,
                    backup_kind: None,
                    cursor: cursor.clone(),
                    limit: None,
                })
                .await
                .map_err(anyhow::Error::from)?;
            backups.extend(page.backups);
            if !page.has_more {
                return Ok(arkret_sdk::KeysBackupsList {
                    backups,
                    next_cursor: None,
                    has_more: false,
                });
            }
            let next = page
                .next_cursor
                .ok_or_else(|| anyhow::anyhow!("key backup page omitted required next_cursor"))?;
            if !seen_cursors.insert(next.to_string()) {
                anyhow::bail!("key backup pagination cursor repeated");
            }
            cursor = Some(next);
        }
    }

    // ── REC-1 recovery policy + session (6.1 / 6.3) ─────────────────────────

    /// 6.1 — read the principal's currently accepted recovery policy.
    /// Returns `{ "active_policy": <policy summary | null> }`.
    pub async fn get_recovery_policy(
        &self,
    ) -> anyhow::Result<arkret_sdk::RecoveryPolicyActiveOutcome> {
        self.sdk_http_client()?
            .get("/_arkret/root/identity/recovery-policy")
            .await
            .map_err(anyhow::Error::from)
    }

    /// Publish or rotate the principal's signed recovery policy.
    ///
    /// The request is the canonical `ak.policy.set` EventInitialSubmission
    /// required by `ak.root.identity.recovery_policy.command.publish`.
    pub async fn put_recovery_policy(
        &self,
        body: &arkret_sdk::RecoveryPolicyPublishRequest,
    ) -> anyhow::Result<arkret_sdk::RecoveryPolicyPublishOutcome> {
        self.sdk_http_client()?
            .post("/_arkret/root/identity/recovery-policy", body)
            .await
            .map_err(anyhow::Error::from)
    }

    /// 6.3 — open a recovery session bound to the active policy. `body` is the
    /// `recovery-session.schema.json` `create_request`
    /// (`principal_id`, `requesting_device_id`, `trust_domain`, optional
    /// `expected_recovery_policy_ref`). The server derives the A/B model and
    /// authoritative generation snapshot; the client cannot self-report them.
    pub async fn create_recovery_session(
        &self,
        body: &arkret_models_crypto::RecoverySessionCreateRequestBody,
    ) -> anyhow::Result<arkret_sdk::RecoverySessionState> {
        self.sdk_http_client()?
            .post("/_arkret/root/identity/recovery-sessions", body)
            .await
            .map_err(anyhow::Error::from)
    }

    /// Read the server-authoritative recovery session after proof submission.
    pub async fn recovery_session(
        &self,
        recovery_session_id: &str,
    ) -> anyhow::Result<arkret_sdk::RecoverySessionState> {
        self.sdk_http_client()?
            .get(&format!(
                "/_arkret/root/identity/recovery-sessions/{recovery_session_id}"
            ))
            .await
            .map_err(anyhow::Error::from)
    }

    /// 6.3 — submit a recovery proof (e.g. from
    /// [`crate::recovery_proof::build_principal_signing_proof`]) for a pending
    /// session. `body` is `{ "proof": <proof> }`.
    pub async fn submit_recovery_proof(
        &self,
        recovery_session_id: &str,
        body: &arkret_models_crypto::RecoverySessionProofSubmitRequestBody,
    ) -> anyhow::Result<arkret_sdk::RecoverySessionProofSubmitOutcome> {
        self.sdk_http_client()?
            .post(
                &format!("/_arkret/root/identity/recovery-sessions/{recovery_session_id}/proofs"),
                body,
            )
            .await
            .map_err(anyhow::Error::from)
    }

    pub async fn get_recovery_session(
        &self,
        recovery_session_id: &str,
    ) -> anyhow::Result<arkret_sdk::RecoverySessionState> {
        self.sdk_http_client()?
            .get(&format!(
                "/_arkret/root/identity/recovery-sessions/{recovery_session_id}"
            ))
            .await
            .map_err(anyhow::Error::from)
    }

    /// AKP B-C / spec head 37ce729 — `LIST?series_id=` query path the
    /// recovery strand uses to rebuild a backup series by sequence. When
    /// `series_id` is `None` and `backup_kind` is `None`, this lists all
    /// key backups.
    ///
    /// Soland P2 (aa76b91) added the `?series_id=` + `?backup_kind=`
    /// query parameters; the chain reconstruction MUST decrypt only
    /// from the tail and surface `backup_frontier_stale` /
    /// `backup_post_reset_stale` errors per AKP B-C §3.3.
    ///
    /// TODO(P3-impl): the deep series-chain decryption / frontier
    /// validation lives in `key_backup` / `recovery_crypto` and is out
    /// of scope for the wire-contract pass.
    pub async fn list_key_backups_by_series(
        &self,
        series_id: Option<&str>,
        backup_kind: Option<&str>,
    ) -> anyhow::Result<arkret_sdk::KeysBackupsList> {
        let series_id = series_id
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(|value| arkret_sdk::BackupSeriesId::new(value.to_owned()))
            .transpose()
            .map_err(|err| anyhow::anyhow!("invalid backup series id: {err}"))?;
        let backup_kind = backup_kind
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(|value| match value {
                "did_recovery" => Ok(arkret_sdk::BackupKind::DidRecovery),
                "secret_storage" => Ok(arkret_sdk::BackupKind::SecretStorage),
                "mls_history" => Ok(arkret_sdk::BackupKind::MlsHistory),
                other => Err(anyhow::anyhow!("unknown backup_kind `{other}`")),
            })
            .transpose()?;
        let query = arkret_sdk::KeyBackupsListQuery {
            series_id,
            backup_kind,
            cursor: None,
            limit: None,
        };
        self.sdk_http_client()?
            .list_key_backups(&query)
            .await
            .map_err(anyhow::Error::from)
    }

    pub async fn get_key_backup_with_unlock_proof(
        &self,
        backup_id: &str,
        unlock_proof: &serde_json::Value,
    ) -> anyhow::Result<arkret_sdk::KeyBackup> {
        let backup_id = arkret_sdk::BackupId::new(backup_id.to_owned())
            .map_err(|err| anyhow::anyhow!("invalid key backup id: {err}"))?;
        let proof: arkret_sdk::KeyBackupUnlockProof = serde_json::from_value(unlock_proof.clone())?;
        let body = arkret_sdk::KeysBackupsUnlockRequestBody { proof };
        self.sdk_http_client()?
            .unlock_key_backup(&backup_id, &body)
            .await
            .map_err(anyhow::Error::from)
    }

    /// Delete a key-backup envelope through the `key-management.md` §7.8.1
    /// high-risk authority flow.
    ///
    /// Two round trips, in this order and no other: ask the service for the
    /// single-use delete challenge, then sign the canonical delete-intent
    /// transcript it fixes. The service issues the freshness — §7.8.1 does not
    /// accept a caller-minted nonce — so there is no way to build the proof
    /// before the first call returns.
    ///
    /// `request_id` is the caller's retry identity: the service keys its
    /// idempotency record on `(principal_id, backup_id, request_id)` and returns
    /// the *same* challenge while one is still valid, so a network retry MUST
    /// reuse the value rather than mint a new one. A genuinely new delete
    /// attempt uses a new `request_id`.
    ///
    /// The proof branch is `principal_signing`: the private half of the current
    /// cross-signing principal signing key, whose `kid` is a verification method
    /// of the principal's own DID document. The receiver resolves the method
    /// through that document, which is what excludes the device key this client
    /// signs Events with.
    pub async fn delete_key_backup(
        &self,
        backup_id: &str,
        actor_id: &str,
        request_id: &str,
        reason: Option<&str>,
        state_store: &crate::state::LocalStateStore,
        secure_store: &dyn crate::secure_key_store::SecureKeyStore,
    ) -> anyhow::Result<arkret_sdk::KeysBackupsDeleteOutcome> {
        let backup_id = arkret_sdk::BackupId::new(backup_id.to_owned())
            .map_err(|err| anyhow::anyhow!("invalid key backup id: {err}"))?;
        let request_id = arkret_sdk::Base64UrlString::new(request_id.to_owned())
            .map_err(|err| anyhow::anyhow!("invalid delete request_id: {err}"))?;

        let client = self.sdk_http_client()?;
        let challenge = client
            .issue_key_backup_delete_challenge(
                &backup_id,
                &arkret_sdk::KeysBackupsIssueDeleteChallengeRequestBody {
                    request_id: request_id.clone(),
                },
            )
            .await?;

        let (verification_method, principal_key) =
            crate::key_backup::principal_signing_key(state_store, secure_store, actor_id)?;
        let proof = crate::key_backup::key_backup_delete_principal_signing_proof(
            &challenge,
            reason,
            &verification_method,
            &principal_key,
            crate::clock::now_utc(),
        )?;

        let body = arkret_sdk::KeysBackupsDeleteRequestBody {
            request_id,
            challenge_id: challenge.challenge_id.clone(),
            proof,
            reason: reason.map(str::to_owned),
        };
        client
            .delete_key_backup(&backup_id, &body)
            .await
            .map_err(anyhow::Error::from)
    }
}

fn key_backup_idempotency_key(
    backup_id: &arkret_sdk::BackupId,
    record: &arkret_sdk::KeyBackup,
) -> anyhow::Result<String> {
    let digest = arkret_sdk::canonical::canonical_sha256(&serde_json::json!({
        "backup_id": backup_id,
        "body": record,
    }))
    .map_err(|error| anyhow::anyhow!("key backup idempotency digest: {error}"))?;
    Ok(format!(
        "inkson-key-backup-{}",
        digest.trim_start_matches("sha256:")
    ))
}
