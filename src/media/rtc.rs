//! RTC client integration scaffolding (CKP-0010, spec head b47ff6ec).
//!
//! This module captures the client-side wire contract for the new media
//! binding profile that landed in cokret-spec round R3:
//!
//! - **CALL-1** — `ck.self.call.media.token_exchange`: obtain a backend token and `participant_binding`
//!   from soland's `POST /rtc/token` endpoint via the SDK helper
//!   [`cokret_sdk::media::call_media_token_exchange`].
//! - **CALL-2** — render `focus_unavailable_for_client` as a hard failure with retry / leave
//!   options. No silent fallback to a different focus.
//! - **MEDIA-1** — SFrame key provider derives keys from the MLS Exporter with label
//!   `cx-rtc-frame-key/v1` (length=19, Context="", KDF.Nh=32). Any backend-supplied key is rejected
//!   with `e2ee_key_source_unauthorised`.
//! - **MEDIA-2** — `ParticipantConnected` (LiveKit / SFU signal) must be cross-checked against
//!   `ck.call.state.participants[]`. A mismatch fails closed with
//!   `participant_identity_unrecognised`.
//! - **MEDIA-3** — recording artifact pipeline rejects Egress destinations that bypass the Cokret
//!   authenticated blob upload (`recording_artifact_pipeline_bypassed`).
//!
//! The actual SFU integration (LiveKit / mediasoup / janus / cokret-native)
//! lives in the platform renderer; yougen ships the typed wire contract,
//! validation predicates, and error reasons so the renderer wires into a
//! single source of truth.
//!
//! TODO(R3.1): the live transport-backed paths (real HTTP POST against
//! `/rtc/token`, real `MlsGroup::export_secret` invocation, real SFU
//! `ParticipantConnected` callback wiring) are deferred; the predicates
//! and error reasons here are the contract those integrations consume.

use std::collections::BTreeSet;

/// Stable label registered on the `ck.profile.media_service_binding.v1`
/// profile for the SFrame frame key derivation (`media-service-binding.md
/// §8.1`). The MLS exporter MUST be invoked with exactly this
/// label, length=19, and empty Context. KDF.Nh=32 is enforced by the
/// MLS ciphersuite (HKDF-SHA256).
pub const SFRAME_FRAME_KEY_LABEL: &str = "cx-rtc-frame-key/v1";

/// Length parameter for the MLS exporter call (matches spec §11).
pub const SFRAME_FRAME_KEY_LENGTH: u16 = 19;

/// Empty context for the MLS exporter call (matches spec §11).
pub const SFRAME_FRAME_KEY_CONTEXT: &[u8] = &[];

/// Spec-mandated TTL ceiling for media tokens (`ck.self.call.media.token_exchange`).
/// Soland defaults to 300s; the ceiling is 600s.
pub const MEDIA_TOKEN_TTL_MAX_SECS: u64 = 600;

/// Error reasons surfaced by the RTC client integration. These map 1:1
/// to the new error code enum landed in cokret-spec round R3 (§0.7).
///
/// Toast layer copy is keyed by `error.call.<wire>` (see `i18n.rs`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RtcClientError {
    /// Focus selected by the client is not usable by this client build.
    /// Renderer MUST display a failure card with "Retry" + "Leave call"
    /// — no silent fallback to a different focus.
    FocusUnavailableForClient,
    /// Server-reported focus disagrees with the call-state commit.
    FocusMismatch,
    /// `ck.realm.media_service.foci[].type` not one of the five
    /// canonical enums (`livekit | mediasoup | janus | cokret-native
    /// | moq-relay`).
    UnknownFocusType,
    /// Token issuer kid does not resolve to the current
    /// `ck.realm.media_service.service_id`.
    TokenIssuerUnauthorised,
    /// `participant_binding` failed signature / TTL / tuple validation.
    ParticipantBindingInvalid,
    /// SFU reported a `ParticipantConnected` whose identity is NOT in
    /// `ck.call.state.participants[]`. Receiver MUST fail closed.
    ParticipantIdentityUnrecognised,
    /// Frame key source was not the MLS Exporter. Any backend-supplied
    /// key (e.g. LiveKit-side key vault) is rejected.
    E2eeKeySourceUnauthorised,
    /// Egress destination is not a Cokret-authenticated blob upload.
    /// Recording is refused.
    RecordingArtifactPipelineBypassed,
}

impl RtcClientError {
    /// Wire-form error code (matches the soland HTTP `code` field).
    pub fn as_wire(self) -> &'static str {
        match self {
            Self::FocusUnavailableForClient => "focus_unavailable_for_client",
            Self::FocusMismatch => "focus_mismatch",
            Self::UnknownFocusType => "unknown_focus_type",
            Self::TokenIssuerUnauthorised => "token_issuer_unauthorised",
            Self::ParticipantBindingInvalid => "participant_binding_invalid",
            Self::ParticipantIdentityUnrecognised => "participant_identity_unrecognised",
            Self::E2eeKeySourceUnauthorised => "e2ee_key_source_unauthorised",
            Self::RecordingArtifactPipelineBypassed => "recording_artifact_pipeline_bypassed",
        }
    }

    /// i18n key for the user-facing toast string.
    pub fn i18n_key(self) -> &'static str {
        match self {
            Self::FocusUnavailableForClient => "error.call.focus_unavailable_for_client",
            Self::FocusMismatch => "error.call.focus_mismatch",
            Self::UnknownFocusType => "error.call.unknown_focus_type",
            Self::TokenIssuerUnauthorised => "error.call.token_issuer_unauthorised",
            Self::ParticipantBindingInvalid => "error.call.participant_binding_invalid",
            Self::ParticipantIdentityUnrecognised => "error.call.participant_identity_unrecognised",
            Self::E2eeKeySourceUnauthorised => "error.call.e2ee_key_source_unauthorised",
            Self::RecordingArtifactPipelineBypassed => {
                "error.call.recording_artifact_pipeline_bypassed"
            }
        }
    }

    /// Parses a soland error `code` string into a typed [`RtcClientError`].
    /// Returns `None` for codes outside the CKP-0010 media binding set —
    /// callers should fall back to the generic error path.
    pub fn from_wire(code: &str) -> Option<Self> {
        Some(match code {
            "focus_unavailable_for_client" => Self::FocusUnavailableForClient,
            "focus_mismatch" => Self::FocusMismatch,
            "unknown_focus_type" => Self::UnknownFocusType,
            "token_issuer_unauthorised" => Self::TokenIssuerUnauthorised,
            "participant_binding_invalid" => Self::ParticipantBindingInvalid,
            "participant_identity_unrecognised" => Self::ParticipantIdentityUnrecognised,
            "e2ee_key_source_unauthorised" => Self::E2eeKeySourceUnauthorised,
            "recording_artifact_pipeline_bypassed" => Self::RecordingArtifactPipelineBypassed,
            _ => return None,
        })
    }
}

/// Canonical list of accepted media focus backend types
/// (`zh/crypto-media/bindings/`). Any focus whose `type` field is not in
/// this set must be rejected with [`RtcClientError::UnknownFocusType`].
pub const ALLOWED_FOCUS_TYPES: &[&str] = &[
    "livekit",
    "mediasoup",
    "janus",
    "cokret-native",
    "moq-relay",
];

/// Returns `true` iff `focus_type` is one of the canonical backend
/// types. The check is intentionally case-sensitive to match the spec's
/// wire form.
pub fn is_known_focus_type(focus_type: &str) -> bool {
    ALLOWED_FOCUS_TYPES.contains(&focus_type)
}

/// Source classification for a candidate SFrame frame key (MEDIA-1).
///
/// The only accepted source is [`Self::MlsExporter`] — any backend or
/// out-of-band key delivery must be rejected with
/// [`RtcClientError::E2eeKeySourceUnauthorised`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrameKeySource {
    /// Derived from the MLS group's exporter secret with the canonical
    /// label + length + (empty) context.
    MlsExporter,
    /// Key supplied by the SFU / media backend (e.g. LiveKit keyprovider
    /// API). MUST be rejected — backend cloud is not in the trust path.
    Backend,
    /// Key supplied by an out-of-band channel (e.g. shared password).
    /// Not part of the v1 trust model.
    OutOfBand,
}

/// MEDIA-1 — validates the frame key source before SFrame keying is
/// installed. Returns `Ok(())` only when the source is the MLS exporter.
///
/// TODO(R3.1): wire this predicate into the actual SFrame keyprovider
/// callback when the renderer integrates `livekit-client` /
/// `mediasoup-client`. For now the predicate is the contract the
/// integration will consume.
pub fn validate_frame_key_source(source: FrameKeySource) -> Result<(), RtcClientError> {
    match source {
        FrameKeySource::MlsExporter => Ok(()),
        FrameKeySource::Backend | FrameKeySource::OutOfBand => {
            Err(RtcClientError::E2eeKeySourceUnauthorised)
        }
    }
}

/// MEDIA-2 — cross-checks an SFU-reported `ParticipantConnected`
/// identity against the `ck.call.state.participants[]` projection.
///
/// `expected_identities` is the set of `participant_identity` values
/// stamped onto the durable call state by the soland reducer. A
/// mismatch is fail-closed; the renderer MUST drop the connection.
///
/// TODO(R3.1): wire this into the platform renderer's
/// `ParticipantConnected` callback. For now the predicate is the
/// contract the integration will consume.
pub fn cross_check_participant_identity(
    reported_identity: &str,
    expected_identities: &BTreeSet<String>,
) -> Result<(), RtcClientError> {
    if expected_identities.contains(reported_identity) {
        Ok(())
    } else {
        Err(RtcClientError::ParticipantIdentityUnrecognised)
    }
}

/// Egress destination classification for the recording pipeline (MEDIA-3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EgressDestination {
    /// Cokret-authenticated blob upload (the only allowed sink).
    CokretBlob,
    /// Direct cloud-storage egress (S3 / GCS / Azure Blob). REJECTED.
    DirectCloudStorage,
    /// Custom webhook / RTMP / file. REJECTED.
    Other,
}

/// MEDIA-3 — validates a recording artifact destination. Only the
/// Cokret blob pipeline is accepted; any direct egress to S3/GCS/etc.
/// is rejected with [`RtcClientError::RecordingArtifactPipelineBypassed`].
///
/// TODO(R3.1): wire this predicate into the renderer's Egress
/// configuration before any `ck.call.recording.start` envelope is
/// signed.
pub fn validate_recording_destination(
    destination: EgressDestination,
) -> Result<(), RtcClientError> {
    match destination {
        EgressDestination::CokretBlob => Ok(()),
        EgressDestination::DirectCloudStorage | EgressDestination::Other => {
            Err(RtcClientError::RecordingArtifactPipelineBypassed)
        }
    }
}

/// CALL-1 — placeholder integration point for the SDK token-exchange
/// helper. Builds the request the SDK exposes via
/// [`cokret_sdk::media::call_media_token_exchange`] and documents the
/// fail-closed contract the renderer will eventually enforce.
///
/// The actual HTTP POST + signature verification is deferred (the SDK
/// helper currently returns the request body only; transport-backed
/// `BaseClient::call_media_token_exchange` lands in R3.1 per the
/// `media.rs` comment in the SDK).
///
/// TODO(R3.1): once the SDK exposes a transport-backed helper, replace
/// this stub with a real `async fn token_exchange` that:
///   1. POSTs the request to `/rtc/token`.
///   2. Verifies `service_signature.kid` against the current `ck.realm.media_service.service_id`.
///   3. Validates `participant_binding` (signature, TTL ≤ 600s, all tuple fields match the call
///      state).
///   4. Returns `Err(RtcClientError::FocusUnavailableForClient)` when soland replies with that
///      error code — and the renderer surfaces the failure with retry + leave-call options, NEVER
///      silently falling back to a different focus.
pub fn token_exchange_request(
    realm_id: &str,
    call_id: &str,
    actor_id: &str,
    device_id: &str,
    focus_id: &str,
) -> serde_json::Value {
    serde_json::json!({
        "realm_id": realm_id,
        "call_id": call_id,
        "actor_id": actor_id,
        "device_id": device_id,
        "focus_id": focus_id,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_key_source_only_accepts_mls_exporter() {
        assert!(validate_frame_key_source(FrameKeySource::MlsExporter).is_ok());
        assert_eq!(
            validate_frame_key_source(FrameKeySource::Backend),
            Err(RtcClientError::E2eeKeySourceUnauthorised)
        );
        assert_eq!(
            validate_frame_key_source(FrameKeySource::OutOfBand),
            Err(RtcClientError::E2eeKeySourceUnauthorised)
        );
    }

    #[test]
    fn focus_type_enum_matches_spec() {
        assert!(is_known_focus_type("livekit"));
        assert!(is_known_focus_type("mediasoup"));
        assert!(is_known_focus_type("janus"));
        assert!(is_known_focus_type("cokret-native"));
        assert!(is_known_focus_type("moq-relay"));
        assert!(!is_known_focus_type("LiveKit")); // case-sensitive
        assert!(!is_known_focus_type("zoom"));
    }

    #[test]
    fn participant_identity_cross_check_fails_closed_on_unknown() {
        let mut known = BTreeSet::new();
        known.insert("ck:rtc_participant:00000000-0000-0000-0000-000000000001".to_owned());
        assert!(
            cross_check_participant_identity(
                "ck:rtc_participant:00000000-0000-0000-0000-000000000001",
                &known
            )
            .is_ok()
        );
        assert_eq!(
            cross_check_participant_identity("ck:rtc_participant:unknown", &known),
            Err(RtcClientError::ParticipantIdentityUnrecognised)
        );
    }

    #[test]
    fn recording_destination_only_accepts_cokret_blob() {
        assert!(validate_recording_destination(EgressDestination::CokretBlob).is_ok());
        assert_eq!(
            validate_recording_destination(EgressDestination::DirectCloudStorage),
            Err(RtcClientError::RecordingArtifactPipelineBypassed)
        );
        assert_eq!(
            validate_recording_destination(EgressDestination::Other),
            Err(RtcClientError::RecordingArtifactPipelineBypassed)
        );
    }

    #[test]
    fn rtc_error_wire_round_trip() {
        for err in [
            RtcClientError::FocusUnavailableForClient,
            RtcClientError::FocusMismatch,
            RtcClientError::UnknownFocusType,
            RtcClientError::TokenIssuerUnauthorised,
            RtcClientError::ParticipantBindingInvalid,
            RtcClientError::ParticipantIdentityUnrecognised,
            RtcClientError::E2eeKeySourceUnauthorised,
            RtcClientError::RecordingArtifactPipelineBypassed,
        ] {
            assert_eq!(RtcClientError::from_wire(err.as_wire()), Some(err));
            assert!(err.i18n_key().starts_with("error.call."));
        }
    }

    #[test]
    fn token_exchange_request_carries_required_fields() {
        let body = token_exchange_request(
            "ck:realm:abc",
            "ck:call:xyz",
            "did:web:example:users:alice",
            "ck:device:dev-1",
            "ck:focus:foo",
        );
        assert_eq!(body["realm_id"], "ck:realm:abc");
        assert_eq!(body["call_id"], "ck:call:xyz");
        assert_eq!(body["focus_id"], "ck:focus:foo");
    }

    #[test]
    fn frame_key_label_matches_spec() {
        // Pinned per `media-service-binding.md §8.1`.
        assert_eq!(SFRAME_FRAME_KEY_LABEL, "cx-rtc-frame-key/v1");
        assert_eq!(SFRAME_FRAME_KEY_LENGTH, 19);
        assert!(SFRAME_FRAME_KEY_CONTEXT.is_empty());
        assert_eq!(MEDIA_TOKEN_TTL_MAX_SECS, 600);
    }
}
