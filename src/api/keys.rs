#[cfg(any(test, feature = "demo-crypto"))]
use base64::Engine as _;
#[cfg(any(test, feature = "demo-crypto"))]
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

use super::*;

/// Canonical signing-input prefix for the `keys/upload` `device_signature`
/// (spec `device-lifecycle.md` §8.1).
// The keys/upload signing chain below is only exercised by the `demo-crypto`
// `upload_keys` path (the non-demo build fails closed before signing) and by
// the wire-shape unit tests; gate it accordingly so the default build stays
// warning-free.
#[cfg(any(test, feature = "demo-crypto"))]
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
#[cfg(any(test, feature = "demo-crypto"))]
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
#[cfg(any(test, feature = "demo-crypto"))]
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

#[cfg(any(test, feature = "demo-crypto"))]
pub(crate) fn sign_keys_upload_batch_with_signer(
    signer: &crate::event_signer::YougenEventSigner,
    device_id: &str,
    one_time_keys: &BTreeMap<String, Value>,
    fallback_keys: &BTreeMap<String, Value>,
) -> anyhow::Result<Value> {
    let input = keys_upload_signing_input(device_id, one_time_keys, fallback_keys)?;
    device_signature_tuple_for_input(signer, &input, "keys/upload")
}

// Only the `demo-crypto` `upload_keys` path ships placeholder one-time keys;
// the active-signer convenience wrapper is therefore gated with it (the
// non-demo build fails closed in `upload_keys` before any signing happens).
#[cfg(feature = "demo-crypto")]
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

impl CokretApi {
    /// Upload one-time / fallback prekeys to `/_cokret/self/keys/upload`.
    ///
    /// The one-time-key MATERIAL produced here is a fixed placeholder
    /// (`key:"yougen-one-time"`), NOT a real curve25519 prekey, so it is
    /// gated behind the `demo-crypto` feature alongside the other
    /// dev-placeholder entry points. A real production keys/upload must
    /// source one-time keys from the device key store (not yet wired); the
    /// non-`demo-crypto` build therefore fails closed before any wire byte
    /// leaves the device — mirroring `send_to_device` /
    /// `device-lifecycle.md §8.1` (one-time keys MUST be real curve25519
    /// prekeys redeemable via `keys/claim`).
    #[cfg(feature = "demo-crypto")]
    pub async fn upload_keys(&self, device_id: &str) -> anyhow::Result<KeysUploadOutcome> {
        self.ensure_demo_crypto_fallback_allowed("keys/upload placeholder one-time key material")?;
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

    #[cfg(not(feature = "demo-crypto"))]
    pub async fn upload_keys(&self, _device_id: &str) -> anyhow::Result<KeysUploadOutcome> {
        anyhow::bail!(
            "keys/upload ships placeholder one-time key material and requires the `demo-crypto` build feature; \
             a production upload must source real curve25519 prekeys from the device key store"
        )
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

    /// Submit an ephemeral `ck.realm_key.request` (realm-and-space.md
    /// history-sharing): a late-joining device asks the provider device named by
    /// `target_source_ref` to seal the retained `history_secret` range to
    /// `recipient_hpke_public_key`. soland relays it to the provider's to-device
    /// queue (`relay_ephemeral_realm_key_request`); the provider answers with a
    /// durable `ck.realm_key.share`.
    ///
    /// Posts directly to `/_cokret/self/ephemeral` rather than via
    /// [`Self::submit_ephemeral_envelope`], whose SDK guard only admits the
    /// broadcast ephemeral allowlist (`ck.realm_key.request` is a directed relay,
    /// not a broadcast signal).
    #[allow(clippy::too_many_arguments)]
    pub async fn submit_realm_key_request(
        &self,
        realm_id: &str,
        actor_id: &str,
        device_id: &str,
        provider_device_ref: &str,
        provider_principal_id: &str,
        recipient_hpke_public_key: &str,
        from_epoch: u64,
        to_epoch: u64,
    ) -> anyhow::Result<cokret_sdk::EphemeralSubmitOutcome> {
        let payload = cokret_sdk::RealmKeyRequestPayload {
            key_scope: cokret_sdk::RealmKeyRequestScope {
                effective_scope: json!({ "realm_id": crate::operation::trim_realm_id(realm_id) }),
                policy_digest: None,
                membership_frontier_digest: None,
                from_epoch,
                to_epoch,
                history_visibility: None,
            },
            recipient_principal_id: cokret_sdk::Did::new(actor_id.trim().to_owned())?,
            recipient_device_id: device_id.trim().to_owned(),
            recipient_hpke_public_key: recipient_hpke_public_key.trim().to_owned(),
            requested_source_class: cokret_sdk::HistoryKeySource::VerifiedMemberDevice,
            target_source_ref: provider_device_ref.trim().to_owned(),
            // The principal that owns `target_source_ref` (the provider device the
            // requester picked as its history source). Required by the SDK request
            // schema so the relay can route to the provider's to-device queue.
            target_principal_id: cokret_sdk::Did::new(provider_principal_id.trim().to_owned())?,
            created_at: crate::clock::now_utc(),
        };
        payload
            .validate()
            .map_err(|err| anyhow::anyhow!("ck.realm_key.request invalid: {err}"))?;
        let sent_at = crate::clock::now_utc();
        let envelope = cokret_sdk::EphemeralEnvelope {
            // `ck.realm_key.request` is a directed ephemeral relay, not a broadcast
            // signal, so it has no `events::kinds` constant; the literal is the
            // wire kind soland's `relay_ephemeral_realm_key_request` matches on.
            kind: "ck.realm_key.request".to_owned(),
            realm_id: cokret_sdk::RealmId::new(crate::operation::trim_realm_id(realm_id))?,
            actor_id: cokret_sdk::Did::new(actor_id.trim().to_owned())?,
            device_id: Some(cokret_sdk::DeviceId::new(device_id.trim().to_owned())?),
            sent_at,
            // Directed relay; soland enforces its own TTL. Stay well under the
            // 5-minute ephemeral ceiling.
            expires_at: sent_at + chrono::Duration::minutes(5),
            payload: serde_json::to_value(&payload)?,
            proof: None,
        };
        self.post_json("_cokret/self/ephemeral", &envelope).await
    }

    /// Generic typed to-device push of a `ck.realm_key.share` (or any directed
    /// kind) straight to a recipient device's queue. The provider's primary path
    /// is the durable `ck.realm_key.share` event (soland projects it to-device);
    /// this is the direct-push fallback for an out-of-band reply.
    pub async fn submit_to_device_message(
        &self,
        txn_id: &str,
        target_actor: &str,
        target_device_id: &str,
        kind: &str,
        content: Value,
    ) -> anyhow::Result<DeviceMessagesSendOutcome> {
        self.send_device_message_envelope(
            txn_id,
            target_actor,
            target_device_id,
            kind,
            &crate::clock::rfc3339_secs_in(60),
            content,
        )
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
    ) -> anyhow::Result<cokret_sdk::KeysBackupsPutOutcome> {
        let (record, _) = self
            .prepare_key_backup_put_payload(backup_id, payload)
            .await?;
        let body = cokret_sdk::KeysBackupsPutRequestBody(record);
        self.put_json(&format!("_cokret/self/keys/backups/{backup_id}"), &body)
            .await
    }

    pub async fn put_key_backup_returning_sent_body(
        &self,
        backup_id: &str,
        payload: serde_json::Value,
    ) -> anyhow::Result<(cokret_sdk::KeysBackupsPutOutcome, serde_json::Value)> {
        let (record, sent_body) = self
            .prepare_key_backup_put_payload(backup_id, payload)
            .await?;
        let body = cokret_sdk::KeysBackupsPutRequestBody(record);
        let response = self
            .put_json(&format!("_cokret/self/keys/backups/{backup_id}"), &body)
            .await?;
        Ok((response, sent_body))
    }

    async fn prepare_key_backup_put_payload(
        &self,
        backup_id: &str,
        payload: serde_json::Value,
    ) -> anyhow::Result<(cokret_sdk::KeyBackup, serde_json::Value)> {
        crate::key_backup::validate_key_backup_put_request(backup_id, &payload)
            .map_err(|err| anyhow::anyhow!("invalid key backup envelope: {err}"))?;
        let record: cokret_sdk::KeyBackup = serde_json::from_value(payload)?;
        let mut payload = serde_json::to_value(&record)?;
        self.attach_key_backup_current_device_trust_anchor(&mut payload)
            .await?;
        crate::key_backup::validate_key_backup_put_request(backup_id, &payload)
            .map_err(|err| anyhow::anyhow!("invalid key backup envelope: {err}"))?;
        let record: cokret_sdk::KeyBackup = serde_json::from_value(payload)?;
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
        let viewer = match self.list_devices().await {
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

    pub async fn list_key_backups(&self) -> anyhow::Result<cokret_sdk::KeysBackupsList> {
        self.get_json("_cokret/self/keys/backups").await
    }

    // ── REC-1 recovery policy + session (6.1 / 6.3) ─────────────────────────

    /// 6.1 — read the principal's currently accepted recovery policy.
    /// Returns `{ "active_policy": <policy summary | null> }`.
    pub async fn get_recovery_policy(
        &self,
    ) -> anyhow::Result<cokret_sdk::RecoveryPolicyActiveOutcome> {
        self.get_json("_cokret/root/identity/recovery-policy").await
    }

    /// Publish or rotate the principal's signed recovery policy.
    ///
    /// `body` stays a raw `Value`: it is a fully-signed recovery policy
    /// envelope built by `recovery_strand::build_signed_genesis_recovery_policy_*`,
    /// and round-tripping it through `cokret_sdk::RecoveryPolicy` (which carries
    /// a flattened `extra` map and an `auth_data` detached-JWS) risks
    /// re-canonicalizing the signed bytes. The response is the typed
    /// publish outcome.
    pub async fn put_recovery_policy(
        &self,
        body: serde_json::Value,
    ) -> anyhow::Result<cokret_sdk::RecoveryPolicyPublishOutcome> {
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
    ) -> anyhow::Result<cokret_sdk::RecoverySessionState> {
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
    ) -> anyhow::Result<cokret_sdk::RecoverySessionProofSubmitOutcome> {
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
    ) -> anyhow::Result<cokret_sdk::RecoverySessionCompleteOutcome> {
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
    ) -> anyhow::Result<cokret_sdk::KeysBackupsList> {
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
    ) -> anyhow::Result<cokret_sdk::KeyBackup> {
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
    ) -> anyhow::Result<cokret_sdk::KeysBackupsDeleteOutcome> {
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
    pub async fn list_devices(&self) -> anyhow::Result<cokret_sdk::AccountView> {
        self.get_json("_cokret/self/account/viewer").await
    }

    /// Pair a new sibling device through the spec account-auth gate.
    pub async fn account_device_pair(
        &self,
        body: &cokret_sdk::AccountDevicePairRequestBody,
    ) -> anyhow::Result<cokret_sdk::AccountDevicePairOutcome> {
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
