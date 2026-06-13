use super::*;

impl CokretApi {
    // ── WebRTC calls ───────────────────────────────────────────────
    //
    // Spec (`crypto-media/webrtc-signaling.md` §5): call signaling frames
    // are `ck.schema.ephemeral_envelope.v1` broadcast envelopes carried on
    // `POST /_cokret/self/ephemeral`; the `ck.call.signal` branch MUST carry
    // `device_id` + `proof` (a detached signature over the canonical
    // envelope bytes, excluding `proof`). Recording is a durable
    // `ck.call.recording.start` event. There is NO `/_cokret/self/webrtc/*`
    // session or signal endpoint in the spec OpenAPI — the prior
    // session/signal/recording HTTP shims (and their `yougen-device-proof`
    // placeholder proof) have been removed.

    /// Build, device-sign, and submit a `ck.call.signal` ephemeral
    /// envelope over the canonical ephemeral channel. The proof is a real
    /// detached JWS from the active signer; submission fails closed if no
    /// signer is installed rather than shipping a placeholder proof.
    pub async fn submit_call_signal_v1(
        &self,
        realm_id: &str,
        actor_id: &str,
        device_id: &str,
        call_id: &str,
        signal_type: &str,
        seq: u64,
        data: Value,
    ) -> anyhow::Result<EphemeralSubmitResult> {
        let mut envelope = build_call_signal_envelope_v1(
            realm_id,
            actor_id,
            device_id,
            call_id,
            signal_type,
            seq,
            data,
        )?;

        // Detached signature over canonical envelope bytes excluding
        // `proof` itself (webrtc-signaling.md §5; RFC 8785 JCS).
        let signer = crate::event_signer::active_signer().ok_or_else(|| {
            anyhow::anyhow!(
                "no active signer configured \u{2014} cannot submit ck.call.signal without device proof"
            )
        })?;
        let mut canonical = serde_json::to_value(&envelope)?;
        if let Value::Object(object) = &mut canonical {
            object.remove("proof");
        }
        let canonical_bytes = cokret_sdk::signatures::proof::EventProofBuilder::new()
            .canonical_bytes(&canonical)
            .map_err(|err| anyhow::anyhow!("ck.call.signal canonical encoding failed: {err}"))?;
        let jws = signer
            .detached_jws_over(&canonical_bytes)
            .map_err(|err| anyhow::anyhow!("ck.call.signal proof signing failed: {err}"))?;
        envelope.proof = Some(json!({
            "kind": "detached_jws",
            "alg": signer.algorithm(),
            "verification_method": format!("{actor_id}#device"),
            "jws": jws,
        }));

        self.submit_ephemeral_envelope(&envelope).await
    }

    /// Submit a durable `ck.call.recording.start` event marking opt-in
    /// recording (webrtc-signaling.md §7 / event-kind-registry). The
    /// envelope is signed and submitted through the unified
    /// `ck.self.events.submit` path.
    pub async fn submit_call_recording_start(
        &self,
        realm_id: &str,
        actor_id: &str,
        call_id: &str,
        recording_id: &str,
        consent_actors: Vec<String>,
    ) -> anyhow::Result<SubmitEventResult> {
        let op = crate::webrtc::build_call_recording_start(
            realm_id,
            actor_id,
            call_id,
            recording_id,
            consent_actors,
        )
        .build("yougen");
        self.submit_event_envelope(&op).await
    }

    // ── Media ───────────────────────────────────────────────────────

    /// `POST /_cokret/self/rtc/ice-config` using the SDK's authoritative
    /// wire types (YOU-05-004). NB: when the WebRTC surface consumes the
    /// outcome, each `ice_servers` entry MUST be parsed through
    /// `cokret_sdk::IceServer` and pass
    /// `IceServer::validate_credential_privacy()` before use.
    pub async fn ice_config(
        &self,
        request: &MediaIceConfigRequestBody,
    ) -> anyhow::Result<MediaIceConfigOutcome> {
        self.post_json("_cokret/self/rtc/ice-config", request).await
    }
}
