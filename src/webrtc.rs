//! WebRTC signaling builders (`crypto-media/webrtc-signaling.md`).
//!
//! Inkson does NOT bundle a WebRTC stack — SDP / ICE / SFU plumbing belongs to
//! the platform renderer. This module provides typed operation builders for
//! the spec's three signaling event kinds so the renderer can publish into the
//! durable event chain without re-discovering the body shape:
//!
//! - `ak.call.signal` — ephemeral SDP / ICE candidate exchange (classified `ephemeral_event`;
//!   reducers MUST NOT use it as state input). Round 4 wire shape; carries `device_id` + `proof`
//!   + `payload.{call_id, signal_type, seq}`. Receivers use [`CallSignalReceiver`] to reject
//!     replay/rollback per `(realm, call, actor, device)` and SHOULD emit `hangup` for that call on
//!     a rollback.
//! - `ak.call.state` — durable call state transitions (start / answer / end).
//! - `ak.call.recording.start` — durable opt-in recording marker.

use serde_json::json;

use crate::operation::OperationBuilder;

// NOTE: `ak.call.signal` is an ephemeral kind and MUST route through
// `EphemeralEnvelope` (`ak.schema.ephemeral_envelope.v1`), NOT through
// `ak.self.events.command.submit`. The canonical builder lives in
// `crate::ephemeral::build_call_signal_envelope_v1` and accepts the v1
// canonical signal_type values (`invite`, `answer`, `candidate`,
// `renegotiate`, `hangup`, `ack`, `reject`, `mute_state`, `media_state`,
// `speaking`, `focus_join`, `focus_leave`, `error`). Do
// NOT re-introduce a durable `OperationBuilder`-based helper or a parallel
// `CallSignalKind` enum here — it would violate the wire spec.

/// Call lifecycle state for `ak.call.state`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CallState {
    Scheduled,
    Ringing,
    Connecting,
    Active,
    Ended,
    Missed,
    Failed,
    Cancelled,
}

impl CallState {
    pub fn as_wire(self) -> &'static str {
        match self {
            Self::Scheduled => "scheduled",
            Self::Ringing => "ringing",
            Self::Connecting => "connecting",
            Self::Active => "active",
            Self::Ended => "ended",
            Self::Missed => "missed",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
        }
    }
}

/// Build a `ak.call.state` event — durable call lifecycle transition.
pub fn build_call_state(
    realm_id: &str,
    actor: &str,
    call_id: &str,
    from: Option<CallState>,
    to: CallState,
) -> OperationBuilder {
    OperationBuilder::new(
        realm_id,
        actor,
        arkret_sdk::events::kinds::EventKind::CallState,
    )
    .target_ref(call_id)
    .body(json!({
        "call_id": call_id,
        "state_transition": {
            "from": from.map(CallState::as_wire),
            "to": to.as_wire()
        }
    }))
}

/// Round 4 — outcome of feeding an incoming `ak.call.signal` envelope
/// through the receiver. Carries the canonical
/// [`arkret_sdk::CallSignalPayload`] when accepted; on a seq rollback
/// the renderer SHOULD emit a local `hangup` for the offending call.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CallSignalIngestOutcome {
    /// Envelope passed Round 4 validation, the proof was present, and the
    /// per-`(realm, call, actor, device)` seq advanced strictly forward.
    Accepted {
        payload: arkret_sdk::CallSignalPayload,
    },
    /// `payload.seq` rolled back or repeated — the receiver drops the
    /// signal and SHOULD emit a local `hangup` for `call_id`. The
    /// `seq` field carries the offending value for telemetry.
    SeqRollback { call_id: String, seq: u64 },
    /// Envelope failed Round 4 validation (missing device_id / proof,
    /// non-canonical signal_type, malformed payload). The receiver drops
    /// the signal; UI MAY surface a "remote sent malformed signal" toast.
    Rejected { reason: String },
}

/// Round 4 — typed receiver for incoming `ak.call.signal` envelopes.
///
/// Wraps [`arkret_sdk::CallSignalState`] so the renderer can plug a
/// single state into the signal stream and get back a typed outcome
/// without touching the SDK's mutable `observe` method directly.
pub struct CallSignalReceiver {
    state: arkret_sdk::CallSignalState,
}

impl CallSignalReceiver {
    pub fn new() -> Self {
        Self {
            state: arkret_sdk::CallSignalState::new(),
        }
    }

    /// Run the Round 4 envelope validator + per-key monotonicity guard. The
    /// caller is responsible for the proof-verification step BEFORE
    /// invoking this (the SDK only asserts `proof.is_some()`).
    pub fn ingest(&mut self, envelope: &arkret_sdk::EphemeralEnvelope) -> CallSignalIngestOutcome {
        let payload = match arkret_sdk::validate_call_signal_envelope(envelope) {
            Ok(p) => p,
            Err(err) => {
                return CallSignalIngestOutcome::Rejected {
                    reason: format!("{err}"),
                };
            }
        };
        let device_id = &envelope.device_id;
        let key = arkret_sdk::CallSignalSeqKey::new(
            envelope.realm_id.clone(),
            payload.call_id.clone(),
            envelope.actor_id.clone(),
            device_id.clone(),
        );
        if let Err(err) = self.state.observe(&key, payload.seq) {
            tracing::warn!(
                target: "inkson::webrtc",
                "ak.call.signal seq rollback: {err}"
            );
            return CallSignalIngestOutcome::SeqRollback {
                call_id: payload.call_id.as_str().to_owned(),
                seq: payload.seq,
            };
        }
        CallSignalIngestOutcome::Accepted { payload }
    }
}

impl Default for CallSignalReceiver {
    fn default() -> Self {
        Self::new()
    }
}

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
) -> OperationBuilder {
    let event_id = arkret_sdk::EventId::new(arkret_sdk::new_prefixed_uuid7("ak:event:"))
        .expect("generated recording start Event id must be canonical");
    let start_ref_field = match capture_kind {
        arkret_sdk::RecordingCaptureKind::Recording => "recording_start_event_id",
        arkret_sdk::RecordingCaptureKind::Transcript => "transcript_start_event_id",
    };
    OperationBuilder::new(
        realm_id,
        actor,
        arkret_sdk::events::kinds::EventKind::CallRecordingStart,
    )
    .event_id(event_id.clone())
    .target_ref(call_id)
    .body(json!({
        "call_id": call_id,
        "recording_id": recording_id,
        "recording_agent": actor,
        "capture_kind": capture_kind,
        "mode": mode,
        "visible_notice": visible_notice,
        "result": {
            start_ref_field: event_id,
            "retention": {
                "consent_confirmed": true
            }
        }
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn call_signal_classifies_as_ephemeral_in_registry() {
        assert_eq!(
            arkret_sdk::events::kinds::event_wire_scope("ak.call.signal"),
            arkret_sdk::events::kinds::EventWireScope::EphemeralEvent
        );
    }

    #[test]
    fn call_state_durable_kind_lookup() {
        assert_eq!(
            arkret_sdk::events::kinds::event_wire_scope("ak.call.state"),
            arkret_sdk::events::kinds::EventWireScope::DurableEvent
        );
    }

    #[test]
    fn call_state_emits_canonical_kind() {
        let op = build_call_state(
            "ak:realm:0196419b-0000-7000-8000-0000000000ac",
            "did:web:alice",
            "ak:call:c1",
            Some(CallState::Connecting),
            CallState::Active,
        )
        .build("node");
        assert_eq!(op.kind, "ak.call.state");
        assert_eq!(op.payload["state_transition"]["from"], "connecting");
        assert_eq!(op.payload["state_transition"]["to"], "active");
    }

    #[test]
    fn call_recording_start_uses_current_schema() {
        let op = build_call_recording_start(
            "ak:realm:0196419b-0000-7000-8000-0000000000ac",
            "did:web:alice",
            "ak:call:c1",
            "rtc-recording-r1",
            arkret_sdk::RecordingCaptureKind::Recording,
            arkret_sdk::RecordingMode::AudioVideo,
            true,
        )
        .build("node");
        assert_eq!(op.kind, "ak.call.recording.start");
        assert_eq!(op.payload["recording_agent"], "did:web:alice");
        assert_eq!(op.payload["capture_kind"], "recording");
        assert_eq!(op.payload["mode"], "audio_video");
        assert_eq!(op.payload["visible_notice"], true);
        assert_eq!(
            op.payload["result"]["recording_start_event_id"],
            op.event_id.as_str()
        );
        assert_eq!(op.payload["result"]["retention"]["consent_confirmed"], true);
        assert!(op.payload.get("consent_actors").is_none());
    }

    #[test]
    fn call_recording_start_supports_transcript_capture_kind() {
        let op = build_call_recording_start(
            "ak:realm:0196419b-0000-7000-8000-0000000000ac",
            "did:web:alice",
            "ak:call:c1",
            "rtc-transcript-t1",
            arkret_sdk::RecordingCaptureKind::Transcript,
            arkret_sdk::RecordingMode::AudioOnly,
            true,
        )
        .build("node");
        assert_eq!(op.kind, "ak.call.recording.start");
        assert_eq!(op.payload["capture_kind"], "transcript");
        assert_eq!(op.payload["mode"], "audio");
        assert_eq!(
            op.payload["result"]["transcript_start_event_id"],
            op.event_id.as_str()
        );
    }

    fn make_v1_envelope(seq: u64, signal_type: &str) -> arkret_sdk::EphemeralEnvelope {
        crate::ephemeral::build_call_signal_envelope_v1(
            "ak:realm:01904100-0000-7000-8000-000000000001",
            "did:web:alice.example",
            "ak:device:01904100-0000-7000-8000-000000000002",
            "ak:call:01904100-0000-7000-8000-000000000003",
            signal_type,
            seq,
            serde_json::json!({}),
        )
        .expect("envelope must build")
    }

    #[test]
    fn v1_builder_accepts_canonical_signal_types() {
        for st in arkret_sdk::CALL_SIGNAL_TYPES {
            let env = make_v1_envelope(1, st);
            assert_eq!(env.kind, "ak.call.signal");
            assert!(!env.device_id.as_str().is_empty());
        }
    }

    #[test]
    fn v1_builder_rejects_unknown_signal_type() {
        let err = crate::ephemeral::build_call_signal_envelope_v1(
            "ak:realm:01904100-0000-7000-8000-000000000001",
            "did:web:alice.example",
            "ak:device:01904100-0000-7000-8000-000000000002",
            "ak:call:01904100-0000-7000-8000-000000000003",
            "sdp_offer",
            1,
            serde_json::json!({}),
        )
        .expect_err("non-canonical signal_type must be rejected");
        assert!(err.to_string().contains("signal_type"));
    }

    #[test]
    fn receiver_accepts_then_rejects_seq_rollback() {
        let mut rx = CallSignalReceiver::new();
        let outcome = rx.ingest(&make_v1_envelope(1, "invite"));
        assert!(matches!(outcome, CallSignalIngestOutcome::Accepted { .. }));

        let outcome = rx.ingest(&make_v1_envelope(2, "answer"));
        assert!(matches!(outcome, CallSignalIngestOutcome::Accepted { .. }));

        let outcome = rx.ingest(&make_v1_envelope(2, "candidate"));
        match outcome {
            CallSignalIngestOutcome::SeqRollback { seq, .. } => assert_eq!(seq, 2),
            other => panic!("expected SeqRollback, got {other:?}"),
        }
    }

    #[test]
    fn wire_decode_rejects_envelope_without_proof() {
        let mut value = serde_json::to_value(make_v1_envelope(1, "invite")).unwrap();
        value.as_object_mut().unwrap().remove("proof");
        assert!(serde_json::from_value::<arkret_sdk::EphemeralEnvelope>(value).is_err());
    }
}
