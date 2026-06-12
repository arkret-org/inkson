use super::*;

impl CokretApi {
    #[cfg(feature = "demo-crypto")]
    pub async fn upload_keys(&self, device_id: &str) -> anyhow::Result<KeysUploadOutcome> {
        self.ensure_demo_crypto_fallback_allowed("keys/upload demo device_signature")?;
        self.post_json(
            "_cokret/self/keys/upload",
            json!({
                "device_id": device_id,
                "one_time_keys": {
                    "signed_curve25519:yougen-otk-1": {
                        "key_id": "yougen-otk-1",
                        "key": "yougen-one-time"
                    }
                },
                "fallback_keys": {},
                "device_signature": {"alg": "EdDSA", "signature": "yougen-dev-signature"}
            }),
        )
        .await
    }

    #[cfg(not(feature = "demo-crypto"))]
    pub async fn upload_keys(&self, _device_id: &str) -> anyhow::Result<KeysUploadOutcome> {
        anyhow::bail!(
            "upload_keys ships a dev `device_signature` placeholder and requires the `demo-crypto` build feature"
        )
    }

    pub async fn claim_keys(
        &self,
        actor: &str,
        device_id: &str,
        algorithm: &str,
    ) -> anyhow::Result<KeysClaimOutcome> {
        self.post_json(
            "_cokret/self/keys/claim",
            json!({"one_time_keys": {actor: {device_id: algorithm}}}),
        )
        .await
    }

    pub async fn query_keys(
        &self,
        actor: &str,
        device_id: &str,
    ) -> anyhow::Result<KeysQueryOutcome> {
        self.post_json(
            "_cokret/self/keys/query",
            json!({"device_keys": {actor: [device_id]}}),
        )
        .await
    }

    #[cfg(feature = "demo-crypto")]
    pub async fn send_to_device(
        &self,
        actor: &str,
        device_id: &str,
    ) -> anyhow::Result<DeviceMessagesPutOutcome> {
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
    ) -> anyhow::Result<DeviceMessagesPutOutcome> {
        anyhow::bail!(
            "send_to_device ships an opaque test ciphertext and requires the `demo-crypto` build feature"
        )
    }

    /// POST a typed `ck.schema.device_message.v1` envelope to soland's
    /// `/_cokret/self/device_messages` endpoint. Used by device
    /// verification flows (R3), secret sharing (`ck.secret.*`) and any
    /// other flow that needs to deliver a message to a specific
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
    ) -> anyhow::Result<DeviceMessagesPutOutcome> {
        let path = "_cokret/self/device_messages";
        let payload = build_device_message_envelope(
            target_actor,
            target_device_id,
            kind,
            expires_at,
            content,
        );
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

    pub async fn ack_device_messages(
        &self,
        ack_token: &str,
    ) -> anyhow::Result<DeviceMessagesAckOutcome> {
        self.post_json(
            "_cokret/self/device_messages/ack",
            serde_json::to_value(DeviceMessagesAckRequestBody {
                ack_token: ack_token.to_owned(),
            })?,
        )
        .await
    }

    pub async fn put_key_backup(
        &self,
        backup_id: &str,
        payload: serde_json::Value,
    ) -> anyhow::Result<serde_json::Value> {
        crate::key_backup::validate_key_backup_put_request(backup_id, &payload)
            .map_err(|err| anyhow::anyhow!("invalid key backup envelope: {err}"))?;
        self.put_json(&format!("_cokret/self/keys/backups/{backup_id}"), payload)
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

    /// 6.3 — open a recovery session bound to the active policy. `body` is the
    /// `recovery-session.schema.json` `create_request`
    /// (`principal_id`, `requesting_device_id`, `trust_domain`, `ssk_generation`,
    /// optional `expected_recovery_policy_ref`). Returns the session JSON.
    pub async fn create_recovery_session(
        &self,
        body: serde_json::Value,
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
        body: serde_json::Value,
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
        body: serde_json::Value,
    ) -> anyhow::Result<serde_json::Value> {
        self.post_json(
            &format!("_cokret/root/identity/recovery-sessions/{recovery_session_id}/complete"),
            body,
        )
        .await
    }

    /// CKP B-C / spec head 37ce729 — `LIST?series_id=` query path the
    /// recovery flow uses to rebuild a backup series by sequence. When
    /// `series_id` is `None` and `backup_class` is `None`, this falls
    /// back to the legacy plain `GET /_cokret/self/keys/backups` shape.
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

    pub async fn get_key_backup(&self, backup_id: &str) -> anyhow::Result<serde_json::Value> {
        self.get_json(&format!("_cokret/self/keys/backups/{backup_id}"))
            .await
    }

    pub async fn get_key_backup_with_unlock_proof(
        &self,
        backup_id: &str,
        unlock_proof: &serde_json::Value,
    ) -> anyhow::Result<serde_json::Value> {
        let proof_header = serde_json::to_string(unlock_proof)?;
        let request = self
            .http
            .get(self.endpoint(&format!("_cokret/self/keys/backups/{backup_id}"))?)
            .header(
                crate::key_backup::KEY_BACKUP_UNLOCK_PROOF_HEADER,
                proof_header,
            );
        self.send_json(self.prepare_request(request), Method::GET)
            .await
    }

    pub async fn delete_key_backup(
        &self,
        backup_id: &str,
        actor_id: &str,
    ) -> anyhow::Result<serde_json::Value> {
        let proof = crate::key_backup::key_backup_delete_ownership_proof(actor_id, backup_id);
        let request = self
            .http
            .delete(self.endpoint(&format!("_cokret/self/keys/backups/{backup_id}"))?)
            .header(crate::key_backup::KEY_BACKUP_DELETE_PROOF_HEADER, proof);
        self.send_json(self.prepare_request(request), Method::DELETE)
            .await
    }

    // ── Device & Crypto ─────────────────────────────────────────────

    /// User-driven device revoke. Hits soland's deployment-local
    /// `ck.devices.revoke` (`POST /_cokret/self/devices/{device_id}/revoke`) —
    /// NOT spec's `ck.admin.revoke_device` (`POST /_soland/admin/devices/{id}/revoke`),
    /// which is an operator-scope endpoint we don't expose from the UI.
    pub async fn revoke_device(&self, device_id: &str) -> anyhow::Result<OkOutcome> {
        self.post_json(
            &format!("_cokret/self/devices/{device_id}/revoke"),
            json!({}),
        )
        .await
    }

    /// Rename a device the caller controls by updating its user-facing
    /// `display_name`. Hits soland's `ck.devices.rename`
    /// (`POST /_cokret/self/devices/{device_id}/rename`). `display_name` is the
    /// optional, mutable, UI-only device name per
    /// `crypto-media/device-lifecycle.md` §4; the canonical id is always
    /// `device_id`. Returns the updated device record JSON.
    pub async fn rename_device(
        &self,
        device_id: &str,
        display_name: &str,
    ) -> anyhow::Result<Value> {
        self.post_json(
            &format!("_cokret/self/devices/{device_id}/rename"),
            json!({ "display_name": display_name }),
        )
        .await
    }

    /// List the principal's active devices from the spec account viewer
    /// (`GET /_cokret/self/account/viewer`). Returns the raw JSON response
    /// shape with `devices[]`; the settings UI derives "current device" from
    /// the first device when the viewer projection has no explicit current
    /// marker.
    pub async fn list_devices(&self) -> anyhow::Result<Value> {
        self.get_json("_cokret/self/account/viewer").await
    }

    /// Request a short-lived legacy pairing challenge from soland's local
    /// scaffold. New device pairing should prefer [`account_device_pair`].
    pub async fn device_pairing_challenge(&self, body: Value) -> anyhow::Result<Value> {
        self.post_json("_soland/self/devices/pairing-challenge", body)
            .await
    }

    /// Finalize legacy local scaffold pairing. New device pairing should
    /// prefer [`account_device_pair`].
    pub async fn authorize_device_pairing(&self, body: Value) -> anyhow::Result<Value> {
        self.post_json("_soland/self/devices/authorize-pairing", body)
            .await
    }

    /// Pair a new sibling device through the spec account-auth gate.
    pub async fn account_device_pair(&self, body: Value) -> anyhow::Result<Value> {
        self.post_json("_cokret/gate/account/device-pair", body)
            .await
    }

    /// Create a server-mediated pending device-pairing request for approval
    /// from an already-authorized device.
    pub async fn create_device_pairing_request(&self, body: Value) -> anyhow::Result<Value> {
        self.post_json("_cokret/gate/account/device-pairing-requests", body)
            .await
    }

    /// List pending device-pairing requests visible to this authenticated
    /// device.
    pub async fn list_device_pairing_requests(&self) -> anyhow::Result<Value> {
        self.get_json("_cokret/self/devices/pairing-requests").await
    }

    /// Approve a pending device-pairing request from this authenticated
    /// device.
    pub async fn approve_device_pairing_request(
        &self,
        pairing_request_id: &str,
    ) -> anyhow::Result<Value> {
        self.post_json(
            &format!("_cokret/self/devices/pairing-requests/{pairing_request_id}/approve"),
            json!({}),
        )
        .await
    }

    pub async fn get_device_trust(&self) -> anyhow::Result<DeviceTrustOutcome> {
        self.get_json("_cokret/self/devices/trust").await
    }

    pub async fn verify_device(
        &self,
        device_id: &str,
        method: &str,
        proof: Value,
    ) -> anyhow::Result<VerifyDeviceOutcome> {
        ensure_device_verification_proof_is_signed(&proof)?;
        self.post_json(
            &format!("_cokret/self/devices/{device_id}/verify"),
            json!({"method": method, "proof": proof}),
        )
        .await
    }
}
