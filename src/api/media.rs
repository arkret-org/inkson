use super::*;

impl CokretApi {
    // ── WebRTC calls ───────────────────────────────────────────────

    pub async fn create_webrtc_session(
        &self,
        realm_id: &str,
        participants: Vec<String>,
        mode: &str,
        recording_policy: &str,
    ) -> anyhow::Result<CreateWebrtcSessionOutcome> {
        self.post_json(
            "_cokret/self/webrtc/sessions",
            json!({
                "realm_id": realm_id,
                "participants": participants,
                "mode": mode,
                "recording_policy": recording_policy,
                "ttl_ms": 120_000
            }),
        )
        .await
    }

    pub async fn append_webrtc_signal(
        &self,
        session_id: &str,
        actor_id: &str,
        device_id: &str,
        message_type: &str,
        seq: u64,
        payload: Value,
    ) -> anyhow::Result<WebrtcSignalOutcome> {
        self.post_json(
            &format!("_cokret/self/webrtc/sessions/{session_id}/signals"),
            json!({
                "message_type": message_type,
                "seq": seq,
                "payload": payload,
                "proofs": [{
                    "actor": actor_id,
                    "kid": format!("{actor_id}#{device_id}"),
                    "sig": "yougen-device-proof"
                }]
            }),
        )
        .await
    }

    pub async fn start_call_recording(
        &self,
        session_id: &str,
        realm_id: &str,
    ) -> anyhow::Result<CallRecordingStartOutcome> {
        self.post_json(
            &format!("_cokret/self/calls/{session_id}/recording/start"),
            json!({ "realm_id": realm_id }),
        )
        .await
    }

    // ── Media ───────────────────────────────────────────────────────

    pub async fn ice_config(
        &self,
        request: &IceConfigRequestBody,
    ) -> anyhow::Result<IceConfigOutcome> {
        self.post_json(
            "_cokret/self/rtc/ice-config",
            serde_json::to_value(request)?,
        )
        .await
    }
}
