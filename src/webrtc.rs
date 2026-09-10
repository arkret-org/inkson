//! WebRTC signaling builders (`crypto-media/webrtc-signaling.md`).
//!
//! Inkson does NOT bundle a WebRTC stack — SDP / ICE / SFU plumbing belongs to
//! the platform renderer. This module provides the typed operation builder for
//! the spec's durable recording marker so the renderer can publish into the
//! durable event chain without re-discovering the body shape:
//!
//! - `ak.call.recording.start` — durable opt-in recording marker.

use crate::operation::TypedOperationBuilder;

// NOTE: `ak.call.signal` MUST route through the encrypted Signal rail
// (`crate::signal::SignalPayload::CallSignal` -> `POST /_arkret/self/signal`),
// NOT through `ak.self.events.command.submit.v1`. The signal kind is one of the
// canonical values represented by `arkret_sdk::CallSignalData` and lives in
// the ciphertext. Do NOT re-introduce a durable `OperationBuilder`-based
// helper, a plaintext envelope, or a parallel kind list here.

// Invariant assertions: each `expect` message names the check that
// establishes it a few lines earlier. Rewriting them as `?` would add
// error paths no caller can reach.
#[allow(clippy::expect_used)]
/// Build a `ak.call.recording.start` event — durable opt-in recording marker.
/// The spec REQUIRES this be written before any recording stream begins so
/// participants have an auditable signal.
pub fn build_call_recording_start(
    realm_id: &str,
    actor: &str,
    call_id: &str,
    recording_id: &str,
    capture_kind: arkret_sdk::RecordingCaptureKind,
    mode: arkret_sdk::RecordingMode,
    visible_notice: bool,
) -> anyhow::Result<TypedOperationBuilder> {
    if !visible_notice {
        anyhow::bail!("call recording start requires visible_notice=true");
    }
    let payload = arkret_sdk::CallRecordingStartPayload {
        call_id: arkret_sdk::CallId::new(call_id.to_owned())?,
        recording_id: arkret_sdk::CallRecordingId::new(recording_id.to_owned())?,
        recording_agent_id: crate::mls_api_helpers::principal_core_id(actor)?,
        capture_kind,
        mode,
        visible_notice: arkret_sdk::VisibleCaptureNotice,
        result: arkret_sdk::RecordingStartOutcome {
            retention: arkret_sdk::CallRecordingRetention {
                retention_expires_at: None,
                deletion_trigger: None,
                audit_lock: None,
                consent_confirmed: Some(true),
            },
        },
    };
    Ok(
        TypedOperationBuilder::new::<arkret_sdk::event_spec::CallRecordingStart>(
            realm_id, actor, payload,
        )
        .target_ref(call_id),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Restates `call_signal_classifies_as_ephemeral_in_registry`.
    ///
    /// The `ephemeral_event` wire scope existed to classify the plaintext rail
    /// v1 deleted. `ak.call.signal` is not an Event kind at all now — it is a
    /// Signal payload type inside the ciphertext — so the registry must not
    /// know it, and any code that resolved it as a registered kind would be
    /// reaching for the deleted rail.
    #[test]
    fn call_signal_is_not_a_registered_event_kind() {
        assert_eq!(
            arkret_sdk::events::kinds::event_wire_scope("ak.call.signal"),
            arkret_sdk::events::kinds::EventWireScope::Custom
        );
        assert_eq!(
            serde_json::to_value(arkret_sdk::CallSignalKind::Invite).unwrap(),
            serde_json::json!("invite")
        );
    }

    #[test]
    fn call_recording_start_uses_current_schema() {
        let op = build_call_recording_start(
            "ak:realm:AedjkD9d4O8HsmPTELawvNXaIESdgksYx6jB4w3TZG0J",
            "did:web:alice",
            "ak:call:AV2POYJXMfLYPg5u4jsNfpIyQjrEWx4_pWcsA9U7yXJQ",
            "rtc-recording-r1",
            arkret_sdk::RecordingCaptureKind::Recording,
            arkret_sdk::RecordingMode::AudioVideo,
            true,
        )
        .unwrap()
        .build("node");
        assert_eq!(op.kind(), "ak.call.recording.start");
        assert_eq!(op.payload()["recording_agent_id"], "ak:did_core:web:alice");
        assert_eq!(op.payload()["capture_kind"], "recording");
        assert_eq!(op.payload()["mode"], "audio_video");
        assert_eq!(op.payload()["visible_notice"], true);
        assert!(
            op.payload()["result"]
                .get("recording_start_event_id")
                .is_none()
        );
        assert!(
            op.payload()["result"]
                .get("transcript_start_event_id")
                .is_none()
        );
        assert_eq!(
            op.payload()["result"]["retention"]["consent_confirmed"],
            true
        );
        assert!(!op.payload().contains_key("consent_actors"));
    }

    #[test]
    fn call_recording_start_supports_transcript_capture_kind() {
        let op = build_call_recording_start(
            "ak:realm:AedjkD9d4O8HsmPTELawvNXaIESdgksYx6jB4w3TZG0J",
            "did:web:alice",
            "ak:call:AV2POYJXMfLYPg5u4jsNfpIyQjrEWx4_pWcsA9U7yXJQ",
            "rtc-transcript-t1",
            arkret_sdk::RecordingCaptureKind::Transcript,
            arkret_sdk::RecordingMode::AudioOnly,
            true,
        )
        .unwrap()
        .build("node");
        assert_eq!(op.kind(), "ak.call.recording.start");
        assert_eq!(op.payload()["capture_kind"], "transcript");
        assert_eq!(op.payload()["mode"], "audio");
        assert!(
            op.payload()["result"]
                .get("recording_start_event_id")
                .is_none()
        );
        assert!(
            op.payload()["result"]
                .get("transcript_start_event_id")
                .is_none()
        );
    }
}
