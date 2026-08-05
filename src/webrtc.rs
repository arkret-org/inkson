//! WebRTC signaling builders (`crypto-media/webrtc-signaling.md`).
//!
//! Inkson does NOT bundle a WebRTC stack — SDP / ICE / SFU plumbing belongs to
//! the platform renderer. This module provides typed operation builders for
//! the spec's three signaling event kinds so the renderer can publish into the
//! durable event chain without re-discovering the body shape:
//!
//! - `ak.call.signal` — SDP / ICE candidate exchange. In v1 this is not a wire object at all: it is
//!   AEAD plaintext inside a `SignalEnvelope` (`crate::signal`). Receivers decrypt first, then use
//!   [`CallSignalReceiver`] to reject replay/rollback per `(realm, call, actor, device)` and SHOULD
//!   emit `hangup` for that call on a rollback.
//! - `ak.call.state` — durable call state transitions (start / answer / end).
//! - `ak.call.recording.start` — durable opt-in recording marker.

use serde_json::json;

use crate::operation::OperationBuilder;

// NOTE: `ak.call.signal` MUST route through the encrypted Signal rail
// (`crate::signal::SignalPayload::CallSignal` -> `POST /_arkret/self/signal`),
// NOT through `ak.self.events.command.submit`. The signal kind is one of the
// canonical values (`invite`, `answer`, `candidate`, `renegotiate`, `hangup`,
// `ack`, `reject`, `mute_state`, `media_state`, `speaking`, `focus_join`,
// `focus_leave`, `moderation`, `error`) and lives in the ciphertext. Do NOT
// re-introduce a durable `OperationBuilder`-based helper, a plaintext
// envelope, or a parallel `CallSignalKind` enum here.
pub const CALL_SIGNAL_KINDS: &[&str] = &[
    "invite",
    "answer",
    "candidate",
    "renegotiate",
    "hangup",
    "ack",
    "reject",
    "mute_state",
    "media_state",
    "speaking",
    "focus_join",
    "focus_leave",
    "moderation",
    "error",
];

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
    OperationBuilder::new(realm_id, actor, arkret_sdk::EventKind::CallState)
        .target_ref(call_id)
        .body(json!({
            "call_id": call_id,
            "state_transition": {
                "from": from.map(CallState::as_wire),
                "to": to.as_wire()
            }
        }))
}

/// Outcome of feeding a decrypted `ak.call.signal` body through the receiver.
#[derive(Clone, Debug, PartialEq)]
pub enum CallSignalIngestOutcome {
    /// The body validated and the per-`(realm, call, actor, device)` sequence
    /// advanced strictly forward.
    Accepted {
        body: arkret_sdk::CallSignalPlaintext,
    },
    /// `payload_sequence` rolled back or repeated — the receiver drops the
    /// signal and SHOULD emit a local `hangup` for `call_id`.
    SeqRollback { call_id: String, seq: u64 },
    /// The decrypted body failed validation (wrong payload type, non-canonical
    /// signal_kind, missing sequence).
    Rejected { reason: String },
}

/// Dedupe key. `signal.md` §2 makes the receiver dedupe on
/// `(sender_device_id, scope_ref, payload_sequence)`; the call id is kept in
/// the key as well so two concurrent calls on one scope do not share a counter.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct CallSignalSeqKey {
    pub realm_id: String,
    pub call_id: String,
    pub sender_actor_id: String,
    pub sender_device_id: String,
}

/// Monotonicity guard over decrypted call-signal sequences.
///
/// This replaces the deleted `arkret_sdk::CallSignalState`. The sequence is
/// inside the ciphertext now, so only a receiver that has already decrypted can
/// run this check — a service can suppress replays by envelope digest alone.
pub struct CallSignalReceiver {
    seen: std::collections::BTreeMap<CallSignalSeqKey, u64>,
}

impl CallSignalReceiver {
    pub fn new() -> Self {
        Self {
            seen: std::collections::BTreeMap::new(),
        }
    }

    /// Validate a decrypted body and advance the per-key sequence.
    ///
    /// The caller is responsible for verifying the envelope proof and the
    /// sender's Seal-relative device authorization BEFORE decrypting.
    pub fn ingest(
        &mut self,
        key: CallSignalSeqKey,
        body: &serde_json::Value,
    ) -> CallSignalIngestOutcome {
        let body = match serde_json::from_value::<arkret_sdk::CallSignalPlaintext>(body.clone()) {
            Ok(body) => body,
            Err(error) => {
                return CallSignalIngestOutcome::Rejected {
                    reason: error.to_string(),
                };
            }
        };
        if let Some(previous) = self.seen.get(&key)
            && body.seq <= *previous
        {
            tracing::warn!(
                target: "inkson::webrtc",
                "ak.call.signal sequence rollback: {} <= {previous}",
                body.seq
            );
            return CallSignalIngestOutcome::SeqRollback {
                call_id: body.call_id.as_str().to_owned(),
                seq: body.seq,
            };
        }
        self.seen.insert(key, body.seq);
        CallSignalIngestOutcome::Accepted { body }
    }
}

impl Default for CallSignalReceiver {
    fn default() -> Self {
        Self::new()
    }
}

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
) -> OperationBuilder {
    let event_id = arkret_sdk::EventId::new_v7_at(crate::clock::now_unix_ms());
    let start_ref_field = match capture_kind {
        arkret_sdk::RecordingCaptureKind::Recording => "recording_start_event_id",
        arkret_sdk::RecordingCaptureKind::Transcript => "transcript_start_event_id",
    };
    OperationBuilder::new(realm_id, actor, arkret_sdk::EventKind::CallRecordingStart)
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
        assert!(CALL_SIGNAL_KINDS.contains(&"invite"));
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
            "ak:realm:0196419b-0000-8000-8000-0000000000ac",
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
            "ak:realm:0196419b-0000-8000-8000-0000000000ac",
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
        assert!(!op.payload.contains_key("consent_actors"));
    }

    #[test]
    fn call_recording_start_supports_transcript_capture_kind() {
        let op = build_call_recording_start(
            "ak:realm:0196419b-0000-8000-8000-0000000000ac",
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

    const TEST_ACTOR: &str = "did:web:alice.example";
    const TEST_DEVICE: &str = "ak:device:01904100-0000-7000-8000-000000000002";
    const TEST_CALL: &str = "ak:call:01904100-0000-7000-8000-000000000003";

    /// Produce a decrypted `ak.call.signal` body the way the sender does.
    ///
    /// The pre-v1 form of this helper built a plaintext wire envelope. In v1
    /// there is no such object: the body only exists as the AEAD plaintext the
    /// sender encodes, so the fixture goes through the real sender encoder and
    /// the receiver parses what would actually come out of the AEAD.
    fn call_signal_body(seq: u64, signal_kind: &str) -> serde_json::Value {
        let bytes = crate::signal::SignalPayload::CallSignal {
            call_id: arkret_sdk::CallId::new(TEST_CALL).unwrap(),
            signal_kind: signal_kind.to_owned(),
            data: Some(serde_json::json!({})),
        }
        .to_plaintext(
            &arkret_sdk::Did::new(TEST_ACTOR).unwrap(),
            crate::signal::SignalSequence(seq),
        )
        .expect("call signal plaintext must encode");
        serde_json::from_slice(&bytes).unwrap()
    }

    fn seq_key() -> CallSignalSeqKey {
        CallSignalSeqKey {
            realm_id: "ak:realm:01904100-0000-8000-8000-000000000001".to_owned(),
            call_id: TEST_CALL.to_owned(),
            sender_actor_id: TEST_ACTOR.to_owned(),
            sender_device_id: TEST_DEVICE.to_owned(),
        }
    }

    #[test]
    fn every_canonical_signal_kind_round_trips_sender_to_receiver() {
        for kind in CALL_SIGNAL_KINDS {
            let body: arkret_sdk::CallSignalPlaintext =
                serde_json::from_value(call_signal_body(1, kind))
                    .expect("canonical signal_kind must parse");
            assert_eq!(
                serde_json::to_value(body.signal_kind).unwrap(),
                serde_json::json!(kind)
            );
            assert_eq!(body.call_id.as_str(), TEST_CALL);
            assert_eq!(body.seq, 1);
        }
    }

    #[test]
    fn non_canonical_signal_kind_is_rejected_on_both_sides() {
        // Sender side: the encoder refuses to seal it.
        let sender_error = crate::signal::SignalPayload::CallSignal {
            call_id: arkret_sdk::CallId::new(TEST_CALL).unwrap(),
            signal_kind: "sdp_offer".to_owned(),
            data: None,
        }
        .to_plaintext(
            &arkret_sdk::Did::new(TEST_ACTOR).unwrap(),
            crate::signal::SignalSequence(1),
        )
        .expect_err("non-canonical signal_kind must be rejected");
        assert!(sender_error.to_string().contains("signal_kind"));

        // Receiver side: a peer that sealed it anyway is still refused, since
        // the ciphertext is authenticated but not trusted.
        let mut hostile = call_signal_body(1, "invite");
        hostile["signal_kind"] = serde_json::json!("sdp_offer");
        assert!(serde_json::from_value::<arkret_sdk::CallSignalPlaintext>(hostile).is_err());
    }

    #[test]
    fn receiver_accepts_then_rejects_seq_rollback() {
        let mut rx = CallSignalReceiver::new();
        let outcome = rx.ingest(seq_key(), &call_signal_body(1, "invite"));
        assert!(matches!(outcome, CallSignalIngestOutcome::Accepted { .. }));

        let outcome = rx.ingest(seq_key(), &call_signal_body(2, "answer"));
        assert!(matches!(outcome, CallSignalIngestOutcome::Accepted { .. }));

        let outcome = rx.ingest(seq_key(), &call_signal_body(2, "candidate"));
        match outcome {
            CallSignalIngestOutcome::SeqRollback { seq, .. } => assert_eq!(seq, 2),
            other => panic!("expected SeqRollback, got {other:?}"),
        }
    }

    /// Restates `wire_decode_rejects_envelope_without_proof`.
    ///
    /// Its premise died with the plaintext envelope: a call signal is no longer
    /// a wire object whose `proof` can be stripped, and envelope-level proof
    /// coverage now lives on `SignalEnvelope`
    /// (`signal::signal_proof_binds_the_header_and_verifies_under_the_device_key`
    /// and `device_directory::verify_signal_envelope_proof`). What remains at
    /// this layer is the plaintext contract: a body that omits the dedupe
    /// sequence, or that is not a call signal at all, must not reach the FSM.
    #[test]
    fn plaintext_missing_the_dedupe_sequence_is_rejected() {
        let mut without_sequence = call_signal_body(1, "invite");
        without_sequence.as_object_mut().unwrap().remove("seq");
        assert!(
            serde_json::from_value::<arkret_sdk::CallSignalPlaintext>(without_sequence.clone())
                .is_err()
        );

        // `payload_sequence` was the pre-`bcf57efa` field name. The closed
        // `CallSignalPlaintext` schema must reject it as an unknown field rather
        // than accept it as an alias for `seq`.
        let mut legacy_sequence = call_signal_body(1, "invite");
        {
            let object = legacy_sequence.as_object_mut().unwrap();
            let seq = object.remove("seq").expect("encoder emits seq");
            object.insert("payload_sequence".to_owned(), seq);
        }
        assert!(
            serde_json::from_value::<arkret_sdk::CallSignalPlaintext>(legacy_sequence).is_err()
        );

        let mut wrong_kind = call_signal_body(1, "invite");
        wrong_kind["kind"] = serde_json::json!("ak.typing");
        assert!(serde_json::from_value::<arkret_sdk::CallSignalPlaintext>(wrong_kind).is_err());

        let mut rx = CallSignalReceiver::new();
        assert!(matches!(
            rx.ingest(seq_key(), &without_sequence),
            CallSignalIngestOutcome::Rejected { .. }
        ));
    }
}
