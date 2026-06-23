use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

use super::*;

/// Canonical signing-input prefix for the `keys/upload` `device_signature`
/// (spec `device-lifecycle.md` §8.1).
const KEYS_UPLOAD_SIGNATURE_PREFIX: &str = "ck-keys-upload-v1\n";

/// Build the spec `device-lifecycle.md` §8.1 canonical signing input for a
/// `keys/upload` `device_signature`:
///
/// ```text
/// "ck-keys-upload-v1\n" + canonical_json({device_id, one_time_keys, fallback_keys})
/// ```
///
/// Missing `one_time_keys` / `fallback_keys` batches MUST normalize to an empty
/// object `{}` (not be omitted) so sender and verifier hash byte-identical
/// input. The body object is canonicalized with RFC 8785 JCS via
/// [`crate::canonical`].
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
pub(crate) fn device_signature_tuple_for_input(
    signer: &crate::event_signer::YougenEventSigner,
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

pub(crate) fn sign_keys_upload_batch_with_signer(
    signer: &crate::event_signer::YougenEventSigner,
    device_id: &str,
    one_time_keys: &BTreeMap<String, Value>,
    fallback_keys: &BTreeMap<String, Value>,
) -> anyhow::Result<Value> {
    let input = keys_upload_signing_input(device_id, one_time_keys, fallback_keys)?;
    device_signature_tuple_for_input(signer, &input, "keys/upload")
}

pub(crate) fn sign_keys_upload_batch(
    device_id: &str,
    one_time_keys: &BTreeMap<String, Value>,
    fallback_keys: &BTreeMap<String, Value>,
) -> anyhow::Result<Value> {
    let signer = crate::event_signer::active_signer().ok_or_else(|| {
        anyhow::anyhow!(
            "keys/upload device_signature requires an active event-signer (fail-closed)"
        )
    })?;
    sign_keys_upload_batch_with_signer(&signer, device_id, one_time_keys, fallback_keys)
}

impl CokretApi {
    pub async fn upload_keys(&self, device_id: &str) -> anyhow::Result<KeysUploadOutcome> {
        let mut one_time_keys = BTreeMap::new();
        one_time_keys.insert(
            "signed_curve25519:yougen-otk-1".to_owned(),
            json!({
                "key_id": "yougen-otk-1",
                "key": "yougen-one-time"
            }),
        );
        let fallback_keys: BTreeMap<String, Value> = BTreeMap::new();
        let device_signature = sign_keys_upload_batch(device_id, &one_time_keys, &fallback_keys)?;
        let body = cokret_sdk::models::KeysUploadRequestBody {
            device_id: cokret_sdk::DeviceId::new(device_id.to_owned())
                .map_err(|err| anyhow::anyhow!("invalid device_id `{device_id}`: {err}"))?,
            one_time_keys,
            fallback_keys,
            device_signature,
        };
        self.post_json("_cokret/self/keys/upload", &body).await
    }

    pub async fn claim_keys(
        &self,
        actor: &str,
        device_id: &str,
        algorithm: &str,
    ) -> anyhow::Result<KeysClaimOutcome> {
        let actor = cokret_sdk::Did::new(actor.to_owned())
            .map_err(|err| anyhow::anyhow!("invalid actor DID `{actor}`: {err}"))?;
        let device_id = cokret_sdk::DeviceId::new(device_id.to_owned())
            .map_err(|err| anyhow::anyhow!("invalid device_id `{device_id}`: {err}"))?;
        let mut device_map = BTreeMap::new();
        device_map.insert(device_id, algorithm.to_owned());
        let mut one_time_keys = BTreeMap::new();
        one_time_keys.insert(actor, device_map);
        let body = cokret_sdk::models::KeysClaimRequestBody { one_time_keys };
        self.post_json("_cokret/self/keys/claim", &body).await
    }

    pub async fn query_keys(
        &self,
        actor: &str,
        device_id: &str,
    ) -> anyhow::Result<KeysQueryOutcome> {
        let actor = cokret_sdk::Did::new(actor.to_owned())
            .map_err(|err| anyhow::anyhow!("invalid actor DID `{actor}`: {err}"))?;
        let device_id = cokret_sdk::DeviceId::new(device_id.to_owned())
            .map_err(|err| anyhow::anyhow!("invalid device_id `{device_id}`: {err}"))?;
        let mut device_keys = BTreeMap::new();
        device_keys.insert(actor, vec![device_id]);
        let body = cokret_sdk::models::KeysQueryRequestBody {
            device_keys,
            timeout_ms: None,
        };
        self.post_json("_cokret/self/keys/query", &body).await
    }

    #[cfg(feature = "demo-crypto")]
    pub async fn send_to_device(
        &self,
        actor: &str,
        device_id: &str,
    ) -> anyhow::Result<DeviceMessagesSendOutcome> {
        self.ensure_demo_crypto_fallback_allowed("device_messages opaque test ciphertext")?;
        self.send_device_message_envelope(
            "yougen-txn-1",
            actor,
            device_id,
            "ck.mls.test",
            &crate::clock::rfc3339_secs_in(60),
            json!({"ciphertext": "opaque-yougen-test"}),
        )
        .await
    }

    #[cfg(not(feature = "demo-crypto"))]
    pub async fn send_to_device(
        &self,
        _actor: &str,
        _device_id: &str,
    ) -> anyhow::Result<DeviceMessagesSendOutcome> {
        anyhow::bail!(
            "send_to_device ships an opaque test ciphertext and requires the `demo-crypto` build feature"
        )
    }

    /// POST a typed `ck.schema.device_message.v1` envelope to soland's
    /// `/_cokret/self/device_messages` endpoint. Used by device
    /// verification strands (R3), secret sharing (`ck.secret.*`) and any
    /// other strand that needs to deliver a message to a specific
    /// (actor, device_id) pair without going through Space history. The
    /// body shape is the canonical
    /// `messages -> actor -> device_id -> {kind, expires_at, content}` map
    /// required by the SDK `DeviceMessageTarget` and `device-lifecycle.md`
    /// §7. `expires_at` is an RFC3339 timestamp; per §7 it MUST NOT be
    /// later than the kind/profile TTL cap (24h default). Idempotency is
    /// conveyed via the `Idempotency-Key` request header (previously the
    /// trailing `{txn_id}` path segment).
    pub async fn send_device_message_envelope(
        &self,
        txn_id: &str,
        target_actor: &str,
        target_device_id: &str,
        kind: &str,
        expires_at: &str,
        content: serde_json::Value,
    ) -> anyhow::Result<DeviceMessagesSendOutcome> {
        let path = "_cokret/self/device_messages";
        let payload = build_device_message_envelope(
            target_actor,
            target_device_id,
            kind,
            expires_at,
            content,
        )?;
        let request = self
            .http
            .post(self.endpoint(path)?)
            .header("Idempotency-Key", txn_id)
            .json(&payload);
        self.send_json(self.prepare_request(request), Method::POST)
            .await
    }

    pub async fn receive_device_messages(&self) -> anyhow::Result<DeviceMessagesGetOutcome> {
        self.get_json("_cokret/self/device_messages").await
    }

    pub async fn receive_device_messages_page(
        &self,
        from: Option<&str>,
        limit: Option<u32>,
    ) -> anyhow::Result<DeviceMessagesGetOutcome> {
        let mut url = self.endpoint("_cokret/self/device_messages")?;
        {
            let mut query = url.query_pairs_mut();
            if let Some(from) = from.map(str::trim).filter(|value| !value.is_empty()) {
                query.append_pair("from", from);
            }
            if let Some(limit) = limit {
                query.append_pair("limit", &limit.to_string());
            }
        }
        let request = self.http.get(url);
        self.send_json(self.prepare_request(request), Method::GET)
            .await
    }

    pub async fn ack_device_messages(
        &self,
        ack_token: &str,
    ) -> anyhow::Result<DeviceMessagesAckOutcome> {
        let body = DeviceMessagesAckRequestBody {
            ack_token: ack_token.to_owned(),
        };
        self.post_json("_cokret/self/device_messages/ack", &body)
            .await
    }

    pub async fn put_key_backup(
        &self,
        backup_id: &str,
        payload: serde_json::Value,
    ) -> anyhow::Result<serde_json::Value> {
        crate::key_backup::validate_key_backup_put_request(backup_id, &payload)
            .map_err(|err| anyhow::anyhow!("invalid key backup envelope: {err}"))?;
        let record: cokret_sdk::KeyBackup = serde_json::from_value(payload)?;
        let body = cokret_sdk::KeysBackupsPutRequestBody(record);
        self.put_json(&format!("_cokret/self/keys/backups/{backup_id}"), &body)
            .await
    }

    pub async fn list_key_backups(&self) -> anyhow::Result<serde_json::Value> {
        self.get_json("_cokret/self/keys/backups").await
    }

    // ── REC-1 recovery policy + session (6.1 / 6.3) ─────────────────────────

    /// 6.1 — read the principal's currently accepted recovery policy.
    /// Returns `{ "active_policy": <policy summary | null> }`.
    pub async fn get_recovery_policy(&self) -> anyhow::Result<serde_json::Value> {
        self.get_json("_cokret/root/identity/recovery-policy").await
    }

    /// Publish or rotate the principal's signed recovery policy.
    pub async fn put_recovery_policy(
        &self,
        body: serde_json::Value,
    ) -> anyhow::Result<serde_json::Value> {
        self.post_json("_cokret/root/identity/recovery-policy", &body)
            .await
    }

    /// 6.3 — open a recovery session bound to the active policy. `body` is the
    /// `recovery-session.schema.json` `create_request`
    /// (`principal_id`, `requesting_device_id`, `trust_domain`, `ssk_generation`,
    /// optional `expected_recovery_policy_ref`). Returns the session JSON.
    pub async fn create_recovery_session(
        &self,
        body: &cokret_sdk::models::RecoverySessionCreateRequestBody,
    ) -> anyhow::Result<serde_json::Value> {
        self.post_json("_cokret/root/identity/recovery-sessions", body)
            .await
    }

    /// 6.3 — submit a recovery proof (e.g. from
    /// [`crate::recovery_proof::build_principal_signing_proof`]) for a pending
    /// session. `body` is `{ "proof": <proof> }`.
    pub async fn submit_recovery_proof(
        &self,
        recovery_session_id: &str,
        body: &cokret_sdk::models::RecoverySessionProofSubmitRequestBody,
    ) -> anyhow::Result<serde_json::Value> {
        self.post_json(
            &format!("_cokret/root/identity/recovery-sessions/{recovery_session_id}/proofs"),
            body,
        )
        .await
    }

    /// 6.3 — finalize a verified recovery session. `body` carries the client-
    /// signed `device_authorize` material (`complete_request`).
    pub async fn complete_recovery_session(
        &self,
        recovery_session_id: &str,
        body: &cokret_sdk::models::RecoverySessionCompleteRequestBody,
    ) -> anyhow::Result<serde_json::Value> {
        self.post_json(
            &format!("_cokret/root/identity/recovery-sessions/{recovery_session_id}/complete"),
            body,
        )
        .await
    }

    /// CKP B-C / spec head 37ce729 — `LIST?series_id=` query path the
    /// recovery strand uses to rebuild a backup series by sequence. When
    /// `series_id` is `None` and `backup_class` is `None`, this lists all
    /// key backups.
    ///
    /// Soland P2 (aa76b91) added the `?series_id=` + `?backup_class=`
    /// query parameters; the chain reconstruction MUST decrypt only
    /// from the tail and surface `backup_frontier_stale` /
    /// `backup_post_reset_stale` errors per CKP B-C §3.3.
    ///
    /// TODO(P3-impl): the deep series-chain decryption / frontier
    /// validation lives in `key_backup` / `recovery_crypto` and is out
    /// of scope for the wire-contract pass.
    pub async fn list_key_backups_by_series(
        &self,
        series_id: Option<&str>,
        backup_class: Option<&str>,
    ) -> anyhow::Result<serde_json::Value> {
        let mut query: Vec<(String, String)> = Vec::new();
        if let Some(series_id) = series_id
            && !series_id.trim().is_empty()
        {
            query.push(("series_id".to_owned(), series_id.to_owned()));
        }
        if let Some(class) = backup_class
            && !class.trim().is_empty()
        {
            query.push(("backup_class".to_owned(), class.to_owned()));
        }
        if query.is_empty() {
            return self.get_json("_cokret/self/keys/backups").await;
        }
        let query_string = query
            .into_iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join("&");
        self.get_json(&format!("_cokret/self/keys/backups?{query_string}"))
            .await
    }

    pub async fn get_key_backup_with_unlock_proof(
        &self,
        backup_id: &str,
        unlock_proof: &serde_json::Value,
    ) -> anyhow::Result<serde_json::Value> {
        let proof: cokret_sdk::KeyBackupUnlockProof = serde_json::from_value(unlock_proof.clone())?;
        let body = cokret_sdk::KeysBackupsUnlockRequestBody { proof };
        self.post_json(
            &format!("_cokret/self/keys/backups/{backup_id}/unlock"),
            &body,
        )
        .await
    }

    pub async fn delete_key_backup(
        &self,
        backup_id: &str,
        actor_id: &str,
    ) -> anyhow::Result<serde_json::Value> {
        let proof = crate::key_backup::key_backup_delete_ownership_proof(actor_id, backup_id);
        let body = cokret_sdk::KeysBackupsDeleteRequestBody {
            proof: cokret_sdk::KeyBackupDeleteProof::Development(
                cokret_sdk::KeyBackupDeleteDevelopmentProof::new(proof),
            ),
            reason: Some("user_requested".to_owned()),
        };
        let request = self
            .http
            .delete(self.endpoint(&format!("_cokret/self/keys/backups/{backup_id}"))?)
            .json(&body);
        self.send_json(self.prepare_request(request), Method::DELETE)
            .await
    }

    // ── Device & Crypto ─────────────────────────────────────────────

    /// User-driven device revoke over the spec-canonical durable Control
    /// Move `ck.device.revoke`.
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
        let principal = cokret_sdk::Did::new(actor_id.to_owned())
            .map_err(|err| anyhow::anyhow!("invalid principal DID for device revoke: {err}"))?;
        let control_realm = cokret_sdk::auth::principal_control_realm_id(&principal);
        let seal_view = self.events_frontier_realm_seal_view(&control_realm).await?;
        let basis = seal_view.seal_basis();
        let event = crate::operation::ck_ops::device_revoke(
            &control_realm,
            actor_id,
            target_device_id,
            revoked_by_device_id,
            "user_request",
        )
        .seal_basis(basis)
        .build_sdk_event(revoked_by_device_id)?;
        self.submit_sdk_event(&event).await
    }

    /// Rename is not exposed as a spec-defined Cokret HTTP endpoint.
    pub async fn rename_device(
        &self,
        device_id: &str,
        display_name: &str,
    ) -> anyhow::Result<Value> {
        let _ = (device_id, display_name);
        anyhow::bail!("rename_device has no spec-defined Cokret HTTP endpoint")
    }

    /// List the principal's active devices from the spec account viewer
    /// (`GET /_cokret/self/account/viewer`). Returns the raw JSON response
    /// shape with `devices[]`; the settings UI derives "current device" from
    /// the first device when the viewer projection has no explicit current
    /// marker.
    pub async fn list_devices(&self) -> anyhow::Result<Value> {
        self.get_json("_cokret/self/account/viewer").await
    }

    /// Pair a new sibling device through the spec account-auth gate.
    pub async fn account_device_pair(
        &self,
        body: &cokret_sdk::AccountDevicePairRequestBody,
    ) -> anyhow::Result<Value> {
        self.post_json("_cokret/gate/account/device-pair", body)
            .await
    }

    /// Device trust must be derived from the spec device-message strand.
    pub async fn get_device_trust(&self) -> anyhow::Result<DeviceTrustView> {
        anyhow::bail!("device trust table has no spec-defined Cokret HTTP endpoint")
    }

    /// Device verification must use the spec device-message strand.
    pub async fn verify_device(
        &self,
        device_id: &str,
        method: &str,
        proof: Value,
    ) -> anyhow::Result<VerifyDeviceResult> {
        ensure_device_verification_proof_is_signed(&proof)?;
        let _ = (device_id, method, proof);
        anyhow::bail!(
            "verify_device must use device messages; there is no spec HTTP verify endpoint"
        )
    }
}
