//! WebRTC signaling builders (`crypto-media/webrtc-signaling.md`).
//!
//! Yougen does NOT bundle a WebRTC stack — SDP / ICE / SFU plumbing belongs to
//! the platform renderer. This module provides typed operation builders for
//! the spec's three signaling event kinds so the renderer can publish into the
//! durable event chain without re-discovering the body shape:
//!
//! - `cx.call.signal` — ephemeral SDP / ICE candidate exchange (classified
//!   `ephemeral_event`; reducers MUST NOT use it as state input).
//! - `cx.call.state` — durable call state transitions (start / answer / end).
//! - `cx.call.recording.start` — durable opt-in recording marker.

use serde_json::json;

use crate::operation::OperationBuilder;

// NOTE: `cx.call.signal` is an ephemeral kind and MUST route through
// `EphemeralEnvelope` (`cx.schema.ephemeral_envelope.v1`), NOT through
// `cx.events.submit`. The canonical builder lives in
// `crate::api::build_call_signal_envelope` and accepts the wire string
// directly (`sdp_offer` / `sdp_answer` / `ice_candidate` / `hangup`). Do
// NOT re-introduce a durable `OperationBuilder`-based helper or a parallel
// `CallSignalKind` enum here — it would violate the wire spec.

/// Call lifecycle state for `cx.call.state`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CallState {
    Ringing,
    Connected,
    Ended,
    Failed,
}

impl CallState {
    pub fn as_wire(self) -> &'static str {
        match self {
            Self::Ringing => "ringing",
            Self::Connected => "connected",
            Self::Ended => "ended",
            Self::Failed => "failed",
        }
    }
}

/// Build a `cx.call.state` event — durable call lifecycle transition.
pub fn build_call_state(
    space_id: &str,
    actor: &str,
    call_id: &str,
    state: CallState,
    reason: Option<&str>,
) -> OperationBuilder {
    OperationBuilder::new(space_id, actor, "cx.call.state")
        .target_ref(call_id)
        .body(json!({
            "call_id": call_id,
            "state": state.as_wire(),
            "reason": reason,
        }))
}

/// Build a `cx.call.recording.start` event — durable opt-in recording marker.
/// The spec REQUIRES this be written before any recording stream begins so
/// participants have an auditable signal.
pub fn build_call_recording_start(
    space_id: &str,
    actor: &str,
    call_id: &str,
    recording_id: &str,
    consent_actors: Vec<String>,
) -> OperationBuilder {
    OperationBuilder::new(space_id, actor, "cx.call.recording.start")
        .target_ref(call_id)
        .body(json!({
            "call_id": call_id,
            "recording_id": recording_id,
            "consent_actors": consent_actors,
        }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn call_signal_classifies_as_ephemeral_in_registry() {
        use crate::conformance::{EventKindWireScope, event_kind_wire_scope};
        assert_eq!(
            event_kind_wire_scope("cx.call.signal"),
            Some(EventKindWireScope::Ephemeral)
        );
    }

    #[test]
    fn call_state_durable_kind_lookup() {
        use crate::conformance::{EventKindWireScope, event_kind_wire_scope};
        assert_eq!(
            event_kind_wire_scope("cx.call.state"),
            Some(EventKindWireScope::Durable)
        );
    }

    #[test]
    fn call_state_emits_canonical_kind() {
        let op = build_call_state(
            "cx:space:s1",
            "did:web:alice",
            "cx:call:c1",
            CallState::Connected,
            None,
        )
        .build("node");
        assert_eq!(op.kind, "cx.call.state");
        assert_eq!(op.payload["state"], "connected");
    }

    #[test]
    fn call_recording_start_lists_consents() {
        let op = build_call_recording_start(
            "cx:space:s1",
            "did:web:alice",
            "cx:call:c1",
            "cx:recording:r1",
            vec!["did:web:alice".into(), "did:web:bob".into()],
        )
        .build("node");
        assert_eq!(op.kind, "cx.call.recording.start");
        assert_eq!(op.payload["consent_actors"][1], "did:web:bob");
    }
}
