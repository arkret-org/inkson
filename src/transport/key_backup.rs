#[cfg(test)]
use std::collections::BTreeMap;

#[cfg(test)]
use base64::Engine as _;
#[cfg(test)]
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::Value;
#[cfg(test)]
use serde_json::json;

use crate::models::SubmitEventResult;

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
        .and_then(|device| device.get("authorized_event_ref").and_then(Value::as_str))
        .map(str::trim)
        .filter(|event_id| !event_id.is_empty())
        .map(str::to_owned)
}

impl crate::transport::TransportClient {
    pub async fn put_key_backup(
        &self,
        backup_id: &str,
        payload: serde_json::Value,
    ) -> anyhow::Result<arkret_sdk::KeysBackupsReplaceOutcome> {
        let (record, _) = self
            .prepare_key_backup_put_payload(backup_id, payload)
            .await?;
        let backup_id = arkret_sdk::BackupId::new(backup_id.to_owned())
            .map_err(|err| anyhow::anyhow!("invalid key backup id: {err}"))?;
        self.sdk_http_client()?
            .put_key_backup(&backup_id, &record)
            .await
            .map_err(anyhow::Error::from)
    }

    pub async fn put_key_backup_returning_sent_body(
        &self,
        backup_id: &str,
        payload: serde_json::Value,
    ) -> anyhow::Result<(arkret_sdk::KeysBackupsReplaceOutcome, serde_json::Value)> {
        let (record, sent_body) = self
            .prepare_key_backup_put_payload(backup_id, payload)
            .await?;
        let backup_id = arkret_sdk::BackupId::new(backup_id.to_owned())
            .map_err(|err| anyhow::anyhow!("invalid key backup id: {err}"))?;
        let response = self
            .sdk_http_client()?
            .put_key_backup(&backup_id, &record)
            .await
            .map_err(anyhow::Error::from)?;
        Ok((response, sent_body))
    }

    async fn prepare_key_backup_put_payload(
        &self,
        backup_id: &str,
        payload: serde_json::Value,
    ) -> anyhow::Result<(arkret_sdk::KeyBackup, serde_json::Value)> {
        crate::key_backup::validate_key_backup_put_request(backup_id, &payload)
            .map_err(|err| anyhow::anyhow!("invalid key backup envelope: {err}"))?;
        let record: arkret_sdk::KeyBackup = serde_json::from_value(payload)?;
        let mut payload = serde_json::to_value(&record)?;
        self.attach_key_backup_current_device_trust_anchor(&mut payload)
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
        let viewer = match crate::transport::keys::list_devices(&self.sdk_http_client()?).await {
            Ok(viewer) => viewer,
            Err(_) => return Ok(()),
        };
        // `key_backup_authorized_event_ref_for_device` reads the viewer's
        // `devices[]` leniently via `Value` accessors; serialize the typed
        // `AccountView` back to its wire JSON so the helper sees the same shape.
        let viewer = serde_json::to_value(&viewer)?;
        let Some(event_id) = key_backup_authorized_event_ref_for_device(&viewer, &device_id) else {
            return Ok(());
        };
        let signed = crate::key_backup::sign_key_backup_with_active_device_and_trust_anchor(
            payload,
            &device_id,
            Some(crate::key_backup::KeyBackupDeviceTrustAnchor::DeviceAuthorizeEventId(event_id)),
        )?;
        if !signed {
            anyhow::bail!("active device signer is required for service-attested key backup");
        }
        Ok(())
    }

    pub async fn list_key_backups(&self) -> anyhow::Result<arkret_sdk::KeysBackupsList> {
        let query = arkret_sdk::KeyBackupsListQuery {
            series_id: None,
            backup_kind: None,
            cursor: None,
            limit: None,
        };
        self.sdk_http_client()?
            .list_key_backups(&query)
            .await
            .map_err(anyhow::Error::from)
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
    /// `body` stays a raw `Value`: it is a fully-signed recovery policy
    /// envelope built by `recovery_strand::build_signed_genesis_recovery_policy_*`,
    /// and round-tripping it through `arkret_sdk::RecoveryPolicy` (which carries
    /// a flattened `extra` map and an `auth_data` detached-JWS) risks
    /// re-canonicalizing the signed bytes. The response is the typed
    /// publish outcome.
    pub async fn put_recovery_policy(
        &self,
        body: serde_json::Value,
    ) -> anyhow::Result<arkret_sdk::RecoveryPolicyPublishOutcome> {
        self.sdk_http_client()?
            .post("/_arkret/root/identity/recovery-policy", &body)
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

    pub async fn delete_key_backup(
        &self,
        backup_id: &str,
        actor_id: &str,
    ) -> anyhow::Result<arkret_sdk::KeysBackupsDeleteOutcome> {
        let backup_id = arkret_sdk::BackupId::new(backup_id.to_owned())
            .map_err(|err| anyhow::anyhow!("invalid key backup id: {err}"))?;
        let proof =
            crate::key_backup::key_backup_delete_ownership_proof(actor_id, backup_id.as_str());
        let body = arkret_sdk::KeysBackupsDeleteRequestBody {
            proof: arkret_sdk::KeyBackupDeleteProof::Development(
                arkret_sdk::KeyBackupDeleteDevelopmentProof::new(proof),
            ),
            reason: Some("user_requested".to_owned()),
        };
        self.sdk_http_client()?
            .delete_key_backup(&backup_id, &body)
            .await
            .map_err(anyhow::Error::from)
    }

    // ── Device & Crypto ─────────────────────────────────────────────

    /// User-driven device revoke over the spec-canonical durable Control
    /// Move `ak.device.revoke`.
    pub async fn revoke_device(
        &self,
        actor_id: &str,
        revoked_by_device_id: &str,
        target_device_id: &str,
    ) -> anyhow::Result<SubmitEventResult> {
        if target_device_id == revoked_by_device_id {
            anyhow::bail!(
                "a device cannot revoke itself; revoke from a peer device (cannot_self_revoke)"
            );
        }
        let principal = arkret_sdk::Did::new(actor_id.to_owned())
            .map_err(|err| anyhow::anyhow!("invalid principal DID for device revoke: {err}"))?;
        let control_realm = arkret_sdk::principal_control_realm_id(&principal);
        let seal_view = self
            .event_submitter()?
            .events_frontier_realm_seal_view(&control_realm)
            .await?;
        let basis = seal_view.seal_basis();
        let event = crate::operation::ak_ops::device_revoke(
            &control_realm,
            actor_id,
            target_device_id,
            revoked_by_device_id,
            "user_request",
        )?
        .seal_basis(basis)
        .build_sdk_event(revoked_by_device_id)?;
        self.event_submitter()?.submit_sdk_event(&event).await
    }
}
