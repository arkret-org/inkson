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
    ) -> anyhow::Result<cokret_sdk::EphemeralSubmitOutcome> {
        let mut envelope = build_call_signal_envelope_v1(
            realm_id,
            actor_id,
            device_id,
            call_id,
            signal_type,
            seq,
            data,
        )?;

        // ephemeral-envelope.schema.json / webrtc-signaling.md §5.1: the proof
        // is detached-JWS, isomorphic to the persistent Event proof, with
        // verification_method `{actor_id}#{device_id}` (fragment = the full
        // ck:device id) over the canonical envelope bytes without `proof`.
        super::ephemeral::attach_broadcast_ephemeral_proof(&mut envelope)?;

        self.submit_ephemeral_envelope(&envelope).await
    }

    /// Submit a durable `ck.call.recording.start` event marking opt-in
    /// recording (webrtc-signaling.md §7 / event-kind-registry). The
    /// envelope is signed and submitted through the unified
    /// `ck.self.events.command.submit` path.
    pub async fn submit_call_recording_start(
        &self,
        realm_id: &str,
        actor_id: &str,
        call_id: &str,
        recording_id: &str,
        mode: cokret_sdk::RecordingMode,
    ) -> anyhow::Result<SubmitEventResult> {
        self.submit_call_capture_start(
            realm_id,
            actor_id,
            call_id,
            recording_id,
            cokret_sdk::RecordingCaptureKind::Recording,
            mode,
        )
        .await
    }

    /// Submit the transcript branch of `ck.call.recording.start`
    /// (`capture_kind=transcript`). The resulting transcript lifecycle is
    /// then projected through `ck.call.state.transcript_state`.
    pub async fn submit_call_transcription_start(
        &self,
        realm_id: &str,
        actor_id: &str,
        call_id: &str,
        transcript_id: &str,
        mode: cokret_sdk::RecordingMode,
    ) -> anyhow::Result<SubmitEventResult> {
        self.submit_call_capture_start(
            realm_id,
            actor_id,
            call_id,
            transcript_id,
            cokret_sdk::RecordingCaptureKind::Transcript,
            mode,
        )
        .await
    }

    async fn submit_call_capture_start(
        &self,
        realm_id: &str,
        actor_id: &str,
        call_id: &str,
        recording_id: &str,
        capture_kind: cokret_sdk::RecordingCaptureKind,
        mode: cokret_sdk::RecordingMode,
    ) -> anyhow::Result<SubmitEventResult> {
        let event = crate::webrtc::build_call_recording_start(
            realm_id,
            actor_id,
            call_id,
            recording_id,
            capture_kind,
            mode,
            true,
        )
        .build_sdk_event("yougen")?;
        self.submit_sdk_event(&event).await
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

    /// `POST /_cokret/self/rtc/token` — `ck.self.call.media.exchange.issue_token`.
    /// Returns the raw outcome (backend connect URL + token + participant
    /// binding). Callers MUST run the response through
    /// `cokret_sdk::verify_call_media_token_outcome` against the realm
    /// media-service anchors before trusting the backend token.
    pub async fn media_token_exchange(
        &self,
        request: &cokret_sdk::CallMediaTokenExchangeRequestBody,
    ) -> anyhow::Result<cokret_sdk::CallMediaTokenExchangeOutcome> {
        self.post_json("_cokret/self/rtc/token", request).await
    }
}
