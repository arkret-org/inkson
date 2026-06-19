//! WebRTC signaling builders (`crypto-media/webrtc-signaling.md`).
//!
//! Yougen does NOT bundle a WebRTC stack — SDP / ICE / SFU plumbing belongs to
//! the platform renderer. This module provides typed operation builders for
//! the spec's three signaling event kinds so the renderer can publish into the
//! durable event chain without re-discovering the body shape:
//!
//! - `ck.call.signal` — ephemeral SDP / ICE candidate exchange (classified `ephemeral_event`;
//!   reducers MUST NOT use it as state input). Round 4 wire shape; carries `device_id` + `proof`
//!   + `payload.{call_id, signal_type, seq}`. Receivers use [`CallSignalReceiver`] to reject
//!     replay/rollback per `(realm, call, actor, device)` and SHOULD emit `hangup` for that call on
//!     a rollback.
//! - `ck.call.state` — durable call state transitions (start / answer / end).
//! - `ck.call.recording.start` — durable opt-in recording marker.

use serde_json::json;

use crate::operation::OperationBuilder;

// NOTE: `ck.call.signal` is an ephemeral kind and MUST route through
// `EphemeralEnvelope` (`ck.schema.ephemeral_envelope.v1`), NOT through
// `ck.self.events.command.submit`. The canonical builder lives in
// `crate::api::build_call_signal_envelope_v1` and accepts the v1
// canonical signal_type values (`invite`, `answer`, `candidate`,
// `renegotiate`, `hangup`, `ack`, `reject`, `mute_state`, `media_state`,
// `speaking`, `focus_join`, `focus_leave`, `error`). Do
// NOT re-introduce a durable `OperationBuilder`-based helper or a parallel
// `CallSignalKind` enum here — it would violate the wire spec.

/// Call lifecycle state for `ck.call.state`.
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

/// Build a `ck.call.state` event — durable call lifecycle transition.
pub fn build_call_state(
    realm_id: &str,
    actor: &str,
    call_id: &str,
    state: CallState,
    reason: Option<&str>,
) -> OperationBuilder {
    OperationBuilder::new(realm_id, actor, "ck.call.state")
        .target_ref(call_id)
        .body(json!({
            "call_id": call_id,
            "state": state.as_wire(),
            "reason": reason,
        }))
}

/// Round 4 — outcome of feeding an incoming `ck.call.signal` envelope
/// through the receiver. Carries the canonical
/// [`cokret_sdk::CallSignalPayload`] when accepted; on a seq rollback
/// the renderer SHOULD emit a local `hangup` for the offending call.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CallSignalIngestOutcome {
    /// Envelope passed Round 4 validation, the proof was present, and the
    /// per-`(realm, call, actor, device)` seq advanced strictly forward.
    Accepted {
        payload: cokret_sdk::CallSignalPayload,
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

/// Round 4 — typed receiver for incoming `ck.call.signal` envelopes.
///
/// Wraps [`cokret_sdk::CallSignalState`] so the renderer can plug a
/// single state into the signal stream and get back a typed outcome
/// without touching the SDK's mutable `observe` method directly.
pub struct CallSignalReceiver {
    state: cokret_sdk::CallSignalState,
}

impl CallSignalReceiver {
    pub fn new() -> Self {
        Self {
            state: cokret_sdk::CallSignalState::new(),
        }
    }

    /// Run the Round 4 envelope validator + per-key monotonicity guard. The
    /// caller is responsible for the proof-verification step BEFORE
    /// invoking this (the SDK only asserts `proof.is_some()`).
    pub fn ingest(&mut self, envelope: &cokret_sdk::EphemeralEnvelope) -> CallSignalIngestOutcome {
        let payload = match cokret_sdk::validate_call_signal_envelope(envelope) {
            Ok(p) => p,
            Err(err) => {
                return CallSignalIngestOutcome::Rejected {
                    reason: format!("{err}"),
                };
            }
        };
        let device_id = match envelope.device_id.as_ref() {
            Some(d) => d,
            None => {
                return CallSignalIngestOutcome::Rejected {
                    reason: "ck.call.signal envelope missing device_id".to_owned(),
                };
            }
        };
        let key = cokret_sdk::CallSignalSeqKey::new(
            envelope.realm_id.clone(),
            payload.call_id.clone(),
            envelope.actor_id.clone(),
            device_id.clone(),
        );
        if let Err(err) = self.state.observe(&key, payload.seq) {
            tracing::warn!(
                target: "yougen::webrtc",
                "ck.call.signal seq rollback: {err}"
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

/// Build a `ck.call.recording.start` event — durable opt-in recording marker.
/// The spec REQUIRES this be written before any recording stream begins so
/// participants have an auditable signal.
pub fn build_call_recording_start(
    realm_id: &str,
    actor: &str,
    call_id: &str,
    recording_id: &str,
    capture_kind: cokret_sdk::RecordingCaptureKind,
    mode: cokret_sdk::RecordingMode,
    visible_notice: bool,
) -> OperationBuilder {
    OperationBuilder::new(realm_id, actor, "ck.call.recording.start")
        .target_ref(call_id)
        .body(json!({
            "call_id": call_id,
            "recording_id": recording_id,
            "recording_agent": actor,
            "capture_kind": capture_kind,
            "mode": mode,
            "visible_notice": visible_notice,
        }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn call_signal_classifies_as_ephemeral_in_registry() {
        use crate::conformance::{EventKindWireScope, event_kind_wire_scope};
        assert_eq!(
            event_kind_wire_scope("ck.call.signal"),
            Some(EventKindWireScope::Ephemeral)
        );
    }

    #[test]
    fn call_state_durable_kind_lookup() {
        use crate::conformance::{EventKindWireScope, event_kind_wire_scope};
        assert_eq!(
            event_kind_wire_scope("ck.call.state"),
            Some(EventKindWireScope::Durable)
        );
    }

    #[test]
    fn call_state_emits_canonical_kind() {
        let op = build_call_state(
            "ck:realm:s1",
            "did:web:alice",
            "ck:call:c1",
            CallState::Active,
            None,
        )
        .build("node");
        assert_eq!(op.kind, "ck.call.state");
        assert_eq!(op.payload["state"], "active");
    }

    #[test]
    fn call_recording_start_uses_current_schema() {
        let op = build_call_recording_start(
            "ck:realm:s1",
            "did:web:alice",
            "ck:call:c1",
            "rtc-recording-r1",
            cokret_sdk::RecordingCaptureKind::Recording,
            cokret_sdk::RecordingMode::AudioVideo,
            true,
        )
        .build("node");
        assert_eq!(op.kind, "ck.call.recording.start");
        assert_eq!(op.payload["recording_agent"], "did:web:alice");
        assert_eq!(op.payload["capture_kind"], "recording");
        assert_eq!(op.payload["mode"], "audio_video");
        assert_eq!(op.payload["visible_notice"], true);
        assert!(op.payload.get("consent_actors").is_none());
    }

    #[test]
    fn call_recording_start_supports_transcript_capture_kind() {
        let op = build_call_recording_start(
            "ck:realm:s1",
            "did:web:alice",
            "ck:call:c1",
            "rtc-transcript-t1",
            cokret_sdk::RecordingCaptureKind::Transcript,
            cokret_sdk::RecordingMode::AudioOnly,
            true,
        )
        .build("node");
        assert_eq!(op.kind, "ck.call.recording.start");
        assert_eq!(op.payload["capture_kind"], "transcript");
        assert_eq!(op.payload["mode"], "audio");
    }

    fn make_v1_envelope(seq: u64, signal_type: &str) -> cokret_sdk::EphemeralEnvelope {
        let mut env = crate::api::build_call_signal_envelope_v1(
            "ck:realm:01904100-0000-7000-8000-000000000001",
            "did:web:alice.example",
            "ck:device:01904100-0000-7000-8000-000000000002",
            "ck:call:01904100-0000-7000-8000-000000000003",
            signal_type,
            seq,
            serde_json::json!({}),
        )
        .expect("envelope must build");
        // Round 4 — receiver requires `proof` to be present; the
        // caller normally attaches a real signature before submit.
        // Drop a placeholder here so we exercise the receiver path.
        env.proof = Some(serde_json::json!({"alg":"EdDSA","sig":"placeholder"}));
        env
    }

    #[test]
    fn v1_builder_accepts_canonical_signal_types() {
        for st in cokret_sdk::CALL_SIGNAL_TYPES {
            let env = make_v1_envelope(1, st);
            assert_eq!(env.kind, "ck.call.signal");
            assert!(env.device_id.is_some());
        }
    }

    #[test]
    fn v1_builder_rejects_unknown_signal_type() {
        let err = crate::api::build_call_signal_envelope_v1(
            "ck:realm:01904100-0000-7000-8000-000000000001",
            "did:web:alice.example",
            "ck:device:01904100-0000-7000-8000-000000000002",
            "ck:call:01904100-0000-7000-8000-000000000003",
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
    fn receiver_rejects_envelope_without_device_id_or_proof() {
        // Hand-build an envelope without proof to verify the receiver
        // rejects it (the Round 4 schema requires proof).
        let env = cokret_sdk::EphemeralEnvelope::new(
            "ck.call.signal",
            cokret_sdk::RealmId::new("ck:realm:01904100-0000-7000-8000-000000000001").unwrap(),
            cokret_sdk::Did::new("did:web:alice.example").unwrap(),
            Some(
                cokret_sdk::DeviceId::new("ck:device:01904100-0000-7000-8000-000000000002")
                    .unwrap(),
            ),
            chrono::Utc::now(),
            chrono::Utc::now() + chrono::Duration::seconds(60),
            serde_json::json!({
                "call_id": "ck:call:01904100-0000-7000-8000-000000000003",
                "signal_type": "invite",
                "seq": 1u64,
                "data": {},
            }),
            None, // ← missing proof
        )
        .unwrap();
        let mut rx = CallSignalReceiver::new();
        let outcome = rx.ingest(&env);
        assert!(matches!(outcome, CallSignalIngestOutcome::Rejected { .. }));
    }
}
