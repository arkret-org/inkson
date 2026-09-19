use std::sync::Arc;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;

fn key_backup_authorized_event_ref_for_device(
    devices: &[arkret_sdk::AccountDeviceSummary],
    device_id: &arkret_sdk::DeviceId,
) -> Option<arkret_sdk::EventId> {
    devices
        .iter()
        .find(|device| {
            &device.device_id == device_id
                && device.status == arkret_sdk::DeviceSummaryStatus::Active
        })
        .and_then(|device| {
            device
                .authorization_ref
                .as_ref()
                .map(|reference| reference.event_id.clone())
        })
}

impl crate::transport::TransportClient {
    pub async fn put_key_backup(
        &self,
        backup_id: &str,
        payload: arkret_sdk::KeyBackup,
        signer: &Arc<crate::event_signer::InksonEventSigner>,
    ) -> anyhow::Result<arkret_sdk::KeysBackupsReplaceOutcome> {
        let record = self
            .prepare_key_backup_put_payload(backup_id, payload, signer)
            .await?;
        let backup_id = arkret_sdk::BackupId::new(backup_id.to_owned())
            .map_err(|err| anyhow::anyhow!("invalid key backup id: {err}"))?;
        if record.backup_id != backup_id {
            anyhow::bail!("key backup path id does not match envelope backup_id");
        }
        arkret_sdk::http_client::KeyBackupClient::new(self.sdk_http_client()?)
            .put_key_backup(&record)
            .await
            .map_err(anyhow::Error::from)
    }

    pub async fn put_key_backup_returning_sent_body(
        &self,
        backup_id: &str,
        payload: arkret_sdk::KeyBackup,
        signer: &Arc<crate::event_signer::InksonEventSigner>,
    ) -> anyhow::Result<(arkret_sdk::KeysBackupsReplaceOutcome, arkret_sdk::KeyBackup)> {
        let record = self
            .prepare_key_backup_put_payload(backup_id, payload, signer)
            .await?;
        let backup_id = arkret_sdk::BackupId::new(backup_id.to_owned())
            .map_err(|err| anyhow::anyhow!("invalid key backup id: {err}"))?;
        if record.backup_id != backup_id {
            anyhow::bail!("key backup path id does not match envelope backup_id");
        }
        let response = arkret_sdk::http_client::KeyBackupClient::new(self.sdk_http_client()?)
            .put_key_backup(&record)
            .await
            .map_err(anyhow::Error::from)?;
        Ok((response, record))
    }

    async fn prepare_key_backup_put_payload(
        &self,
        backup_id: &str,
        payload: arkret_sdk::KeyBackup,
        signer: &Arc<crate::event_signer::InksonEventSigner>,
    ) -> anyhow::Result<arkret_sdk::KeyBackup> {
        let expected_backup_id = arkret_sdk::BackupId::new(backup_id.to_owned())?;
        if payload.backup_id != expected_backup_id {
            anyhow::bail!("key backup path id does not match envelope backup_id");
        }
        let record = self
            .attach_key_backup_current_device_trust_anchor(payload, signer)
            .await?;
        record
            .validate()
            .map_err(|err| anyhow::anyhow!("invalid signed key backup envelope: {err}"))?;
        Ok(record)
    }

    /// Bind the envelope to this device's accepted `ak.device.authorize` and
    /// sign it.
    ///
    /// `auth_data` is a closed required member of the key-backup envelope, so
    /// the trust anchor is written in place and the detached signature is taken
    /// over the canonical envelope with `auth_data.signature` removed
    /// ([`arkret_sdk::KeyBackup::signing_payload_bytes`]).
    async fn attach_key_backup_current_device_trust_anchor(
        &self,
        mut payload: arkret_sdk::KeyBackup,
        signer: &Arc<crate::event_signer::InksonEventSigner>,
    ) -> anyhow::Result<arkret_sdk::KeyBackup> {
        if !payload.auth_data.signature.as_str().is_empty() {
            anyhow::bail!("key backup builder must provide an unsigned envelope");
        }
        let signer_device_id = signer
            .device_id()
            .ok_or_else(|| anyhow::anyhow!("active key backup signer has no bound device id"))?;
        let device_id = arkret_sdk::DeviceId::new(signer_device_id.to_owned())?;
        if payload
            .device_id
            .as_ref()
            .is_some_and(|envelope_device_id| envelope_device_id != &device_id)
        {
            anyhow::bail!("key backup envelope device_id does not match active signer");
        }
        let http = self.sdk_http_client()?;
        let viewer = crate::transport::keys::list_devices(&http).await.ok();
        let viewer_event_id = viewer.as_ref().and_then(|viewer| {
            key_backup_authorized_event_ref_for_device(&viewer.devices, &device_id)
        });
        let query_event_id = if viewer_event_id.is_none() {
            let account_id = payload
                .actor_id
                .as_account_id()
                .ok_or_else(|| anyhow::anyhow!("key backup requires an exact account actor"))?;
            let outcome =
                crate::transport::keys::query_keys(&http, account_id, device_id.as_str()).await?;
            let generation = outcome.generation_for(account_id);
            let now = chrono::Utc::now();
            outcome
                .devices_for(account_id)
                .and_then(|devices| devices.get(&device_id))
                .filter(|record| record.is_usable_in_generation(generation))
                // The row was read at the exact `(account_id, device_id)`
                // selectors; the remaining client-side checks are the evidence
                // reference, the status and the temporal windows.
                .and_then(|record| {
                    crate::identity::device_directory::validate_self_device_row(record).ok()
                })
                .filter(|projection| {
                    crate::identity::device_directory::projection_observation_is_fresh(
                        projection, now,
                    ) && crate::identity::device_directory::projection_authorization_window_contains(
                        projection, now,
                    )
                })
                .map(|projection| projection.device_authorize_event_id.clone())
        } else {
            None
        };
        let Some(event_id) = viewer_event_id.or(query_event_id) else {
            anyhow::bail!("current device has no accepted device.authorize event");
        };
        payload.auth_data = arkret_sdk::KeyBackupAuthData {
            device_id,
            verification_method: arkret_sdk::DidUrl::new(signer.verification_method().to_owned())
                .map_err(anyhow::Error::msg)?,
            signature_algorithm: arkret_sdk::KeyBackupSignatureAlgorithm::Ed25519,
            signature: payload.auth_data.signature,
            device_authorize_event_id: event_id,
        };
        let signature = signer.sign_raw(&payload.signing_payload_bytes()?)?;
        payload.auth_data.signature =
            arkret_sdk::Base64UrlString::new(B64.encode(signature)).map_err(anyhow::Error::msg)?;
        Ok(payload)
    }

    pub async fn list_key_backups(&self) -> anyhow::Result<arkret_sdk::KeysBackupsList> {
        self.list_key_backups_page(&arkret_sdk::KeyBackupsListQuery {
            series_id: None,
            backup_kind: None,
            cursor: None,
            limit: None,
        })
        .await
    }

    pub async fn list_key_backups_page(
        &self,
        query: &arkret_sdk::KeyBackupsListQuery,
    ) -> anyhow::Result<arkret_sdk::KeysBackupsList> {
        self.sdk_http_client()?
            .list_key_backups(query)
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
    /// The request is the canonical `ak.policy.set` single-Event commit
    /// submission required by
    /// `ak.root.identity.recovery_policy.command.publish.v1`
    /// (`recovery-policy.schema.json#/$defs/recovery_policy_publish_request`).
    pub async fn put_recovery_policy(
        &self,
        body: &arkret_wire::EventCommitSubmission,
    ) -> anyhow::Result<arkret_sdk::RecoveryPolicyPublishOutcome> {
        self.sdk_http_client()?
            .post("/_arkret/root/identity/recovery-policy", body)
            .await
            .map_err(anyhow::Error::from)
    }

    /// 6.3 — open a recovery session bound to the active policy. `body` is the
    /// closed `recovery_session_create_request_body`: exact AccountId,
    /// replacement device id/key, possession signature, trust domain and an
    /// optional accepted-policy CAS hint. The server derives the identity model
    /// and authoritative generation snapshot; the client cannot self-report
    /// them.
    pub async fn create_recovery_session(
        &self,
        body: &arkret_models_crypto::RecoverySessionCreateRequestBody,
    ) -> anyhow::Result<arkret_sdk::RecoverySession> {
        self.sdk_http_client()?
            .post("/_arkret/root/identity/recovery-sessions", body)
            .await
            .map_err(anyhow::Error::from)
    }

    /// Read the server-authoritative recovery session after proof submission.
    pub async fn recovery_session(
        &self,
        recovery_session_id: &str,
    ) -> anyhow::Result<arkret_sdk::RecoverySession> {
        self.sdk_http_client()?
            .get(&format!(
                "/_arkret/root/identity/recovery-sessions/{recovery_session_id}"
            ))
            .await
            .map_err(anyhow::Error::from)
    }

    /// 6.3 — submit a recovery proof (e.g. from
    /// signed by the recovering device) for a pending
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

    pub async fn get_key_backup_with_unlock_proof(
        &self,
        backup_id: &str,
        proof: &arkret_sdk::KeyBackupUnlockProof,
    ) -> anyhow::Result<arkret_sdk::KeyBackup> {
        let backup_id = arkret_sdk::BackupId::new(backup_id.to_owned())
            .map_err(|err| anyhow::anyhow!("invalid key backup id: {err}"))?;
        let body = arkret_sdk::KeysBackupsUnlockRequestBody {
            proof: proof.clone(),
        };
        self.sdk_http_client()?
            .unlock_key_backup(&backup_id, &body)
            .await
            .map_err(anyhow::Error::from)
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn backup_trust_anchor_uses_active_device_committed_authorization_event() {
        let device_id =
            arkret_sdk::DeviceId::new("ak:device:0196419b-0000-7000-8000-000000000001").unwrap();
        let event_id =
            arkret_sdk::EventId::new("ak:event:AfAnsJqSlM9bHVI7P1QBMOEW3p5P1PNQu7BBMpiSnD_e")
                .unwrap();
        let active: arkret_sdk::AccountDeviceSummary = serde_json::from_value(json!({
            "device_id": device_id,
            "status": "active",
            "verification_state": "verified",
            "verification_source": "pairing_code",
            "authorization_ref": {
                "event_id": event_id,
                "commit_id": arkret_sdk::RealmCommitId::from_digest([7; 32]),
                "stream_ref": {
                    "kind": "realm",
                    "realm_id": "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19"
                },
                "stream_position": 1
            }
        }))
        .unwrap();
        let expected = active.authorization_ref.as_ref().unwrap().event_id.clone();

        assert_eq!(
            key_backup_authorized_event_ref_for_device(&[active], &device_id),
            Some(expected)
        );
    }

    #[test]
    fn backup_trust_anchor_rejects_non_active_or_uncommitted_device() {
        let device_id =
            arkret_sdk::DeviceId::new("ak:device:0196419b-0000-7000-8000-000000000001").unwrap();
        let revoked: arkret_sdk::AccountDeviceSummary = serde_json::from_value(json!({
            "device_id": device_id,
            "status": "revoked",
            "verification_state": "verified",
            "verification_source": "recovery",
            "authorization_ref": {
                "event_id": "ak:event:AfAnsJqSlM9bHVI7P1QBMOEW3p5P1PNQu7BBMpiSnD_e",
                "commit_id": arkret_sdk::RealmCommitId::from_digest([7; 32]),
                "stream_ref": {
                    "kind": "realm",
                    "realm_id": "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19"
                },
                "stream_position": 1
            }
        }))
        .unwrap();
        let active_without_commit: arkret_sdk::AccountDeviceSummary =
            serde_json::from_value(json!({
                "device_id": device_id,
                "status": "active",
                "verification_state": "unresolved"
            }))
            .unwrap();

        assert!(key_backup_authorized_event_ref_for_device(&[revoked], &device_id).is_none());
        assert!(
            key_backup_authorized_event_ref_for_device(&[active_without_commit], &device_id)
                .is_none()
        );
    }
}
