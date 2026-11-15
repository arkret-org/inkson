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

#[expect(
    clippy::too_many_arguments,
    reason = "The exact actor, Grant, recorder and original MLS Q are separate signed sources."
)]
/// Build a `ak.call.recording.start` event — durable opt-in recording marker.
/// The spec REQUIRES this be written before any recording stream begins so
/// participants have an auditable signal.
/// Recording freezes the native current winner Q; transcript omits this field.
/// The builder validates shape; the Station independently admits the real cut.
pub fn build_call_recording_start(
    scope: &arkret_sdk::ScopeRef,
    actor: &arkret_sdk::ActorId,
    call_id: &arkret_sdk::CallId,
    recording_id: &arkret_sdk::CallRecordingId,
    grant: &arkret_sdk::GrantId,
    recorder: &arkret_sdk::DidCoreId,
    key_ref: Option<&arkret_sdk::EncryptedAttachmentKeyRef>,
    capture_kind: arkret_sdk::RecordingCaptureKind,
    mode: arkret_sdk::RecordingMode,
    visible_notice: bool,
) -> anyhow::Result<TypedOperationBuilder> {
    if !visible_notice {
        anyhow::bail!("call recording start requires visible_notice=true");
    }
    let payload = arkret_sdk::CallRecordingStartPayload {
        call_id: call_id.clone(),
        recording_id: recording_id.clone(),
        recording_agent_id: recorder.clone(),
        capture_kind,
        mode,
        visible_notice: arkret_sdk::VisibleCaptureNotice,
        capture_metadata: arkret_sdk::RecordingStartMetadata {
            key_ref: key_ref.cloned(),
            retention: arkret_sdk::CallRecordingRetention {
                retention_expires_at: None,
                deletion_trigger: None,
                audit_lock: None,
                consent_confirmed: Some(true),
            },
        },
    };
    payload.validate().map_err(anyhow::Error::msg)?;
    Ok(
        TypedOperationBuilder::new_for_actor::<arkret_sdk::event_spec::CallRecordingStart>(
            scope.clone(),
            actor.clone(),
            payload,
        )
        .authorization_ref(grant.as_str())
        .target_ref(call_id.as_str()),
    )
}

/// Close only the selected capture axis. The native one-way `from` guard
/// supplies concurrency control; the historical Start grant is not a Stop permit.
pub(crate) fn build_call_capture_stop(
    scope: &arkret_sdk::ScopeRef,
    actor: &arkret_sdk::ActorId,
    call_id: &arkret_sdk::CallId,
    recording_id: &arkret_sdk::CallRecordingId,
    kind: arkret_sdk::RecordingCaptureKind,
) -> anyhow::Result<TypedOperationBuilder> {
    let recording = kind == arkret_sdk::RecordingCaptureKind::Recording;
    let payload = arkret_sdk::CallStatePayload {
        call_id: call_id.clone(),
        state_transition: None,
        focus: None,
        roster_delta: None,
        moderation_delta: None,
        mute_override: None,
        recording_transition: recording.then(|| arkret_sdk::CallRecordingTransition {
            recording_id: recording_id.clone(),
            from: arkret_sdk::CallRecordingState::Recording,
            to: arkret_sdk::CallRecordingState::Stopped,
            expected_commit_id: None,
            capture_metadata: None,
        }),
        transcript_transition: (!recording).then(|| arkret_sdk::CallTranscriptTransition {
            recording_id: recording_id.clone(),
            from: arkret_sdk::CallTranscriptState::Transcribing,
            to: arkret_sdk::CallTranscriptState::Stopped,
            expected_commit_id: None,
            capture_metadata: None,
        }),
    };
    payload.validate().map_err(anyhow::Error::msg)?;
    Ok(
        TypedOperationBuilder::new_for_actor::<arkret_sdk::event_spec::CallState>(
            scope.clone(),
            actor.clone(),
            payload,
        )
        .target_ref(call_id.as_str()),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn capture(
        kind: arkret_sdk::RecordingCaptureKind,
        mode: arkret_sdk::RecordingMode,
    ) -> crate::operation::LocalOperation {
        let realm =
            arkret_sdk::RealmId::new("ak:realm:AedjkD9d4O8HsmPTELawvNXaIESdgksYx6jB4w3TZG0J")
                .unwrap();
        let actor = arkret_sdk::ActorId::account(arkret_sdk::AccountId::new(
            "ak:did_core:web:alice".parse().unwrap(),
            "ak:did_core:web:station.example".parse().unwrap(),
        ));
        let key_ref = (kind == arkret_sdk::RecordingCaptureKind::Recording).then(|| {
            arkret_sdk::EncryptedAttachmentKeyRef {
                algorithm: arkret_sdk::EncryptedAttachmentKeyAlgorithm::Mls,
                group_state_ref: arkret_sdk::EncryptedAttachmentGroupStateRef::Event(
                    arkret_sdk::EventId::from_digest(arkret_sdk::DigestSuite::Sha256, [72; 32]),
                ),
            }
        });
        build_call_recording_start(
            &arkret_sdk::ScopeRef::Realm { realm_id: realm },
            &actor,
            &"ak:call:AV2POYJXMfLYPg5u4jsNfpIyQjrEWx4_pWcsA9U7yXJQ"
                .parse()
                .unwrap(),
            &arkret_sdk::CallRecordingId::new("rtc-capture-1").unwrap(),
            &arkret_sdk::GrantId::from_event_id(&arkret_sdk::EventId::from_digest(
                arkret_sdk::DigestSuite::Sha256,
                [71; 32],
            )),
            &"ak:did_core:web:media.example".parse().unwrap(),
            key_ref.as_ref(),
            kind,
            mode,
            true,
        )
        .unwrap()
        .build("node")
    }

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
        let op = capture(
            arkret_sdk::RecordingCaptureKind::Recording,
            arkret_sdk::RecordingMode::AudioVideo,
        );
        assert_eq!(op.kind(), "ak.call.recording.start");
        assert_eq!(
            op.payload()["recording_agent_id"],
            "ak:did_core:web:media.example"
        );
        assert!(op.intent().authorization_ref().is_some());
        assert_eq!(op.payload()["capture_kind"], "recording");
        assert_eq!(op.payload()["mode"], "audio_video");
        assert_eq!(op.payload()["visible_notice"], true);
        assert_eq!(
            op.payload()["capture_metadata"]["key_ref"]["algorithm"],
            "MLS"
        );
        assert_eq!(
            op.payload()["capture_metadata"]["key_ref"]["group_state_ref"],
            arkret_sdk::EventId::from_digest(arkret_sdk::DigestSuite::Sha256, [72; 32]).as_str()
        );
        assert!(
            op.payload()["capture_metadata"]
                .get("recording_start_event_id")
                .is_none()
        );
        assert!(
            op.payload()["capture_metadata"]
                .get("transcript_start_event_id")
                .is_none()
        );
        assert_eq!(
            op.payload()["capture_metadata"]["retention"]["consent_confirmed"],
            true
        );
        assert!(!op.payload().contains_key("consent_actors"));
        assert!(!op.payload().contains_key("result"));
        let payload: arkret_sdk::CallRecordingStartPayload =
            serde_json::from_value(serde_json::to_value(op.payload()).unwrap()).unwrap();
        assert_eq!(
            payload.capture_metadata.retention.consent_confirmed,
            Some(true)
        );
    }

    #[test]
    fn call_recording_start_supports_transcript_capture_kind() {
        let op = capture(
            arkret_sdk::RecordingCaptureKind::Transcript,
            arkret_sdk::RecordingMode::AudioOnly,
        );
        assert_eq!(op.kind(), "ak.call.recording.start");
        assert_eq!(op.payload()["capture_kind"], "transcript");
        assert_eq!(op.payload()["mode"], "audio");
        assert!(op.payload()["capture_metadata"].get("key_ref").is_none());
        assert!(
            op.payload()["capture_metadata"]
                .get("recording_start_event_id")
                .is_none()
        );
        assert!(
            op.payload()["capture_metadata"]
                .get("transcript_start_event_id")
                .is_none()
        );
        assert!(!op.payload().contains_key("result"));
        let payload: arkret_sdk::CallRecordingStartPayload =
            serde_json::from_value(serde_json::to_value(op.payload()).unwrap()).unwrap();
        assert_eq!(
            payload.capture_metadata.retention.consent_confirmed,
            Some(true)
        );
    }
}
