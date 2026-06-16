//! Real RTC media wiring (CKP-0010, `media-service-binding.md`).
//!
//! This module is the single source of truth for joining a call's media
//! plane. The flow is:
//!
//! 1. **CALL-1** — `media_token_exchange` POSTs `ck.self.call.media.exchange.issue_token` to
//!    soland's `/_cokret/self/rtc/token`, then anchors + verifies the response via
//!    [`cokret_sdk::verify_call_media_token_outcome`] (issuer anchoring, ≤600s TTL, six-tuple
//!    binding).
//! 2. **ICE** — `ice_config` POSTs to `/_cokret/self/rtc/ice-config` and runs
//!    [`cokret_sdk::verify_ice_config_outcome`] (issuer anchoring, TURN credential privacy,
//!    refresh-lead invariants).
//! 3. **MEDIA-1** — the SFrame frame key is derived from the live MLS exporter via
//!    [`cokret_sdk::derive_frame_key`]. Any non-MLS key source is unrepresentable: the helper only
//!    accepts a [`cokret_sdk::MlsExporterSource`], so a backend KMS key can never be installed
//!    (fail-closed → `e2ee_key_source_unauthorised`).
//!
//! The platform RTC transport (`crate::rtc_transport`) consumes the
//! verified [`JoinedMediaSession`] this module returns: connect URL,
//! backend token, ICE servers, and the SFrame key bytes.

/// Stable label registered on the `ck.profile.media_service_binding.v1`
/// profile for the SFrame frame key derivation (`media-service-binding.md
/// §8.1`). Re-exported from the SDK so the renderer pins exactly one value.
pub use cokret_sdk::FRAME_KEY_LABEL as SFRAME_FRAME_KEY_LABEL;
use cokret_sdk::{
    CallId, CallMediaDesiredMedia, CallMediaParticipantBinding, CallMediaTokenExchangeOutcome,
    CallMediaTokenExchangeRequestBody, DeviceId, Did, FrameKeyContext, IceConfig,
    MediaIceConfigRequestBody, MediaIceMode, MediaServiceAnchors, MlsExporterSource, RealmId,
    call_media_token_exchange, derive_frame_key, verify_call_media_token_outcome,
    verify_ice_config_outcome,
};

use crate::api::CokretApi;

/// Spec-mandated TTL ceiling for media tokens
/// (`ck.self.call.media.exchange.issue_token`). Soland defaults to 300s; the
/// ceiling is 600s.
pub const MEDIA_TOKEN_TTL_MAX_SECS: u64 = cokret_sdk::MEDIA_TOKEN_TTL_MAX_SECS;

/// Error reasons surfaced by the RTC client integration. These map 1:1
/// to the error code enum landed in cokret-spec round R3 (§0.7).
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
    /// Desktop (native) build has no real media transport: this milestone
    /// ships without a bundled libwebrtc / LiveKit-Rust stack, so there is
    /// no RTP path. The call surface MUST surface this as "desktop calling
    /// is not ready yet" and keep the call FSM out of `Connected` — it never
    /// pretends a media session connected. This is a client-only reason; it
    /// never originates from a soland wire `code`.
    DesktopMediaUnavailable,
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
            Self::DesktopMediaUnavailable => "desktop_media_unavailable",
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
            Self::DesktopMediaUnavailable => "error.call.desktop_media_unavailable",
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
            "desktop_media_unavailable" => Self::DesktopMediaUnavailable,
            _ => return None,
        })
    }

    /// Map a soland API error into the typed reason, classifying the
    /// wire `code` carried by the error envelope. Unknown codes collapse
    /// to [`Self::ParticipantBindingInvalid`] so the renderer still fails
    /// closed instead of silently joining.
    fn from_api_error(error: &anyhow::Error) -> Self {
        if let Some(api_error) = error.downcast_ref::<crate::api::CokretApiError>()
            && let Some(typed) = Self::from_wire(api_error.error.code())
        {
            return typed;
        }
        Self::ParticipantBindingInvalid
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

/// What media tracks the joining device intends to publish. Forwarded to
/// soland in the token-exchange request so the focus can pre-allocate
/// publisher slots.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DesiredMedia {
    pub audio: bool,
    pub video: bool,
    pub screen: bool,
}

impl DesiredMedia {
    pub fn audio_video() -> Self {
        Self {
            audio: true,
            video: true,
            screen: false,
        }
    }

    pub fn audio_only() -> Self {
        Self {
            audio: true,
            video: false,
            screen: false,
        }
    }

    fn into_wire(self) -> CallMediaDesiredMedia {
        CallMediaDesiredMedia {
            audio: Some(self.audio),
            video: Some(self.video),
            screen: Some(self.screen),
        }
    }
}

/// Parameters identifying the local participant joining a call's media
/// plane. All ids are canonical protocol ids (`ck:realm:…`, `ck:call:…`,
/// `did:…`, `ck:device:…`).
#[derive(Clone, Debug)]
pub struct MediaJoinRequest {
    pub realm_id: String,
    pub call_id: String,
    pub actor_id: String,
    pub device_id: String,
    pub focus_id: String,
    pub epoch_id: u64,
    pub desired_media: DesiredMedia,
    /// Media-service DIDs anchored by the realm's current
    /// `ck.realm.media_service.service_id`. Token + ICE issuers MUST
    /// resolve to one of these; an empty set fails closed.
    pub media_service_dids: Vec<String>,
}

impl MediaJoinRequest {
    fn typed_ids(&self) -> Result<TypedJoinIds, RtcClientError> {
        let realm_id =
            RealmId::new(self.realm_id.clone()).map_err(|_| RtcClientError::FocusMismatch)?;
        let call_id =
            CallId::new(self.call_id.clone()).map_err(|_| RtcClientError::FocusMismatch)?;
        let actor_id =
            Did::new(self.actor_id.clone()).map_err(|_| RtcClientError::FocusMismatch)?;
        let device_id =
            DeviceId::new(self.device_id.clone()).map_err(|_| RtcClientError::FocusMismatch)?;
        Ok(TypedJoinIds {
            realm_id,
            call_id,
            actor_id,
            device_id,
        })
    }

    fn anchors(&self) -> Result<MediaServiceAnchors, RtcClientError> {
        let dids = self
            .media_service_dids
            .iter()
            .map(|did| Did::new(did.clone()))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| RtcClientError::TokenIssuerUnauthorised)?;
        let anchors = MediaServiceAnchors::new(dids);
        if anchors.is_empty() {
            // Fail closed: with no anchored media service we cannot trust
            // any issuer kid.
            return Err(RtcClientError::TokenIssuerUnauthorised);
        }
        Ok(anchors)
    }
}

struct TypedJoinIds {
    realm_id: RealmId,
    call_id: CallId,
    actor_id: Did,
    device_id: DeviceId,
}

/// The verified, ready-to-connect media session. Everything here has
/// passed issuer anchoring + TTL + tuple binding; the SFrame key is the
/// MLS-exporter-derived secret the transport installs into its
/// keyprovider.
#[derive(Clone, Debug)]
pub struct JoinedMediaSession {
    /// SFU backend type (`livekit` / `mediasoup` / …) — already checked
    /// against [`ALLOWED_FOCUS_TYPES`].
    pub backend_type: String,
    /// Authoritative focus id echoed by the token issuer.
    pub focus_id: String,
    /// Backend WebSocket connect URL (e.g. LiveKit `wss://…`).
    pub connect_url: String,
    /// Opaque backend join token (LiveKit JWT, etc.).
    pub backend_token: String,
    /// SFU-local participant identity, cross-checked against
    /// `ck.call.state.participants[]` on `ParticipantConnected`.
    pub participant_identity: String,
    /// Token issuer's signed tuple for the local participant. The call
    /// controller writes this into `ck.call.state.participants[]` before
    /// connecting the SFU so remote streams have a durable roster to check.
    pub participant_binding: CallMediaParticipantBinding,
    /// Verified ICE configuration (STUN/TURN + force_turn + ttl).
    pub ice_config: IceConfig,
    /// 32-byte SFrame frame key derived from the MLS exporter
    /// (`ck-rtc-frame-key/v1`). Installed as the E2EE keyprovider seed.
    pub frame_key: Vec<u8>,
    /// `desired_media` echoed for the transport's publisher setup.
    pub desired_media: DesiredMedia,
}

/// Run the full media-plane join: token exchange → verify → ICE config →
/// verify → MLS-exporter SFrame key. `mls_exporter` MUST be the live
/// realm MLS group; passing a non-MLS source is impossible by the
/// [`MlsExporterSource`] bound, which is what enforces MEDIA-1.
pub async fn join_call_media(
    api: &CokretApi,
    request: &MediaJoinRequest,
    mls_exporter: &impl MlsExporterSource,
) -> Result<JoinedMediaSession, RtcClientError> {
    let ids = request.typed_ids()?;
    let anchors = request.anchors()?;

    // CALL-1 — token exchange + anchored verification.
    let mut token_request: CallMediaTokenExchangeRequestBody = call_media_token_exchange(
        ids.realm_id.clone(),
        ids.call_id.clone(),
        ids.actor_id.clone(),
        ids.device_id.clone(),
        request.focus_id.clone(),
    );
    token_request.desired_media = Some(request.desired_media.into_wire());

    let outcome: CallMediaTokenExchangeOutcome = api
        .media_token_exchange(&token_request)
        .await
        .map_err(|err| RtcClientError::from_api_error(&err))?;

    if !is_known_focus_type(&outcome.backend_type) {
        return Err(RtcClientError::UnknownFocusType);
    }

    let now = chrono::Utc::now();
    let verification = verify_call_media_token_outcome(&token_request, &outcome, &anchors, now)
        .map_err(|err| classify_protocol_error(&err))?;

    // ICE config — verified against the same anchors. A focus-bound call
    // always relays through the SFU media plane.
    let ice_request = MediaIceConfigRequestBody {
        realm_id: ids.realm_id.clone(),
        call_id: request.call_id.clone(),
        actor_id: ids.actor_id.clone(),
        device_id: ids.device_id.clone(),
        mode: MediaIceMode::Sfu,
    };
    let ice_outcome = api
        .ice_config(&ice_request)
        .await
        .map_err(|err| RtcClientError::from_api_error(&err))?;
    let ice_config = verify_ice_config_outcome(&ice_outcome, &anchors)
        .map_err(|err| classify_protocol_error(&err))?;

    // MEDIA-1 — SFrame frame key from the live MLS exporter. The
    // participant_identity is the verified SFU-local handle from the
    // token binding, so the key is sender-bound per §8.1.
    let frame_context = FrameKeyContext {
        realm_id: ids.realm_id,
        call_id: ids.call_id,
        focus_id: request.focus_id.clone(),
        epoch_id: request.epoch_id,
        participant_identity: verification.participant_identity.clone(),
        device_id: ids.device_id,
    };
    let frame_key = derive_frame_key(mls_exporter, &frame_context)
        .map_err(|_| RtcClientError::E2eeKeySourceUnauthorised)?;

    Ok(JoinedMediaSession {
        backend_type: outcome.backend_type,
        focus_id: outcome.focus_id,
        connect_url: outcome.connect_url,
        backend_token: outcome.backend_token,
        participant_binding: outcome.participant_binding,
        participant_identity: verification.participant_identity,
        ice_config,
        frame_key,
        desired_media: request.desired_media,
    })
}

/// MEDIA-2 — cross-check an SFU-reported `ParticipantConnected` identity
/// against the `ck.call.state.participants[]` projection. A mismatch is
/// fail-closed; the transport MUST drop the connection.
pub fn cross_check_participant_identity(
    reported_identity: &str,
    expected_identities: &std::collections::BTreeSet<String>,
) -> Result<(), RtcClientError> {
    if expected_identities.contains(reported_identity) {
        Ok(())
    } else {
        Err(RtcClientError::ParticipantIdentityUnrecognised)
    }
}

/// MLS exporter backing the SFrame frame-key derivation.
///
/// This wraps the live [`cokret_sdk::CokretMlsGroup`] restored from this
/// device's persisted per-realm MLS snapshot — the same synchronised group
/// (full membership, applied Welcomes/commits) the message E2EE send/receive
/// path uses via `crate::mls::runtime`. The exported secret is therefore a
/// real RFC 9420 §8 MLS-Exporter output that every member's device can
/// reproduce, never a per-device value and never a backend KMS key (MEDIA-1).
///
/// If the realm has no synchronised MLS group on this device yet (no
/// persisted snapshot, or the device snapshot secret is unavailable / cannot
/// decrypt the snapshot), construction fails closed with
/// `e2ee_key_source_unauthorised` rather than fabricating an isolated
/// single-member group: an isolated group's exporter secret differs across
/// devices, so the media could never be decrypted by peers.
///
/// The same construction runs on wasm: the browser build links the full SDK
/// MLS stack (the chat/reaction path already restores the group and reads the
/// epoch exporter secret on wasm via `crate::mls::runtime`, with no platform
/// gate). The web call surface therefore derives the SFrame keyprovider seed
/// in-process from the realm's real MLS exporter secret — identical bytes to
/// every other member's device — instead of relying on an external host MLS
/// bridge or a self-minted key.
pub struct RealmMlsExporter {
    group: cokret_sdk::CokretMlsGroup,
}

impl RealmMlsExporter {
    /// Restore the realm's live, synchronised MLS group from this device's
    /// persisted snapshot so the SFrame exporter secret matches every other
    /// member's. `snapshot` is the per-realm
    /// [`crate::mls::persistence::MlsSnapshotEnvelope`] the caller reads from
    /// `LocalStateStore::mls_snapshot_for` (passed by value so the caller can
    /// drop the store read-guard before this synchronous KDF runs, never
    /// holding it across an `.await`); `secure_store` provides the account
    /// MLS snapshot secret that unwraps it. This is the exact restore path
    /// `crate::mls::runtime::reaction_routing_tag_v1` (and the message
    /// send/receive helpers) use to read the current epoch's exporter
    /// secret — read-only, it neither commits nor advances the ratchet.
    ///
    /// Fails closed with [`RtcClientError::E2eeKeySourceUnauthorised`] when
    /// the realm has no synchronised group on this device (`snapshot` is
    /// `None`, the device snapshot secret is unavailable, or the snapshot
    /// cannot be decrypted). The caller surfaces this as "this realm's MLS
    /// group has not synced on this device yet, so no media key can be
    /// derived".
    pub fn for_realm(
        snapshot: Option<crate::mls::persistence::MlsSnapshotEnvelope>,
        secure_store: &dyn crate::secure_key_store::SecureKeyStore,
        actor_id: &str,
        device_id: &str,
    ) -> Result<Self, RtcClientError> {
        let snapshot = snapshot.ok_or(RtcClientError::E2eeKeySourceUnauthorised)?;
        let secret =
            crate::mls::runtime::load_device_snapshot_secret(secure_store, actor_id, device_id)
                .map_err(|_| RtcClientError::E2eeKeySourceUnauthorised)?;
        let group = crate::mls::persistence::restore_envelope(&snapshot, &secret, 0)
            .map_err(|_| RtcClientError::E2eeKeySourceUnauthorised)?;
        Ok(Self { group })
    }

    /// Current MLS epoch of the restored realm group. Bound into the
    /// SFrame [`FrameKeyContext`] so the frame key rotates with the group
    /// epoch instead of being pinned to a hard-coded `0`.
    pub fn epoch(&self) -> u64 {
        self.group.epoch()
    }
}

impl MlsExporterSource for RealmMlsExporter {
    fn export_secret(
        &self,
        label: &str,
        context: &[u8],
        length: usize,
    ) -> cokret_sdk::Result<Vec<u8>> {
        self.group.export_secret(label, context, length)
    }
}

/// Map an SDK [`cokret_sdk::Error`]'s protocol message into the typed
/// reason. The SDK helpers stamp the wire code into the message
/// (`participant_binding_invalid: …` / `token_issuer_unauthorised: …` /
/// `ice_config_denied: …`); scan for the first known code substring so a
/// `Display` prefix from the `Error` enum does not shadow it.
fn classify_protocol_error(err: &cokret_sdk::Error) -> RtcClientError {
    let message = err.to_string();
    const CODES: &[RtcClientError] = &[
        RtcClientError::TokenIssuerUnauthorised,
        RtcClientError::E2eeKeySourceUnauthorised,
        RtcClientError::ParticipantIdentityUnrecognised,
        RtcClientError::FocusUnavailableForClient,
        RtcClientError::FocusMismatch,
        RtcClientError::UnknownFocusType,
        RtcClientError::RecordingArtifactPipelineBypassed,
        RtcClientError::ParticipantBindingInvalid,
    ];
    for candidate in CODES {
        if message.contains(candidate.as_wire()) {
            return *candidate;
        }
    }
    // `ice_config_denied` is the ICE-path issuer/ttl rejection; surface it
    // as a focus-unavailable failure so the renderer offers retry/leave.
    if message.contains("ice_config_denied") {
        return RtcClientError::FocusUnavailableForClient;
    }
    RtcClientError::ParticipantBindingInvalid
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;

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
            RtcClientError::DesktopMediaUnavailable,
        ] {
            assert_eq!(RtcClientError::from_wire(err.as_wire()), Some(err));
            assert!(err.i18n_key().starts_with("error.call."));
        }
    }

    #[test]
    fn empty_anchor_set_fails_closed() {
        let request = MediaJoinRequest {
            realm_id: "ck:realm:01904100-0000-7000-8000-9b64700c6ee8".to_owned(),
            call_id: "ck:call:0196441c-0000-7000-8000-000000000000".to_owned(),
            actor_id: "did:web:alice.example".to_owned(),
            device_id: "ck:device:01904100-0000-7000-8000-000000000005".to_owned(),
            focus_id: "fra-1".to_owned(),
            epoch_id: 7,
            desired_media: DesiredMedia::audio_video(),
            media_service_dids: Vec::new(),
        };
        assert_eq!(
            request.anchors().unwrap_err(),
            RtcClientError::TokenIssuerUnauthorised
        );
    }

    #[test]
    fn classify_protocol_error_reads_wire_prefix() {
        let err = cokret_sdk::Error::Protocol(
            "token_issuer_unauthorised: issuer not anchored".to_owned(),
        );
        assert_eq!(
            classify_protocol_error(&err),
            RtcClientError::TokenIssuerUnauthorised
        );
        let err = cokret_sdk::Error::Protocol(
            "e2ee_key_source_unauthorised: frame key context missing".to_owned(),
        );
        assert_eq!(
            classify_protocol_error(&err),
            RtcClientError::E2eeKeySourceUnauthorised
        );
    }

    #[test]
    fn frame_key_label_matches_spec() {
        assert_eq!(SFRAME_FRAME_KEY_LABEL, "ck-rtc-frame-key/v1");
        assert_eq!(MEDIA_TOKEN_TTL_MAX_SECS, 600);
    }

    // ── RealmMlsExporter (T5 — wasm MLS exporter unlock) ────────────────────
    //
    // The exporter is no longer gated to native: the browser build links the
    // same SDK MLS stack the chat/reaction send path already uses on wasm, so
    // the web call surface derives the SFrame frame key in-process from the
    // realm's real MLS exporter secret. These tests build a genuine MLS group,
    // persist its snapshot exactly like the message E2EE path, and assert the
    // exporter restores it and derives a real 32-byte frame key — never a
    // placeholder — while every no-key path still fails closed.

    const EXPORTER_ACTOR: &str = "did:web:alice.example";
    const EXPORTER_DEVICE: &str = "ck:device:01904100-0000-7000-8000-000000000001";
    const EXPORTER_REALM: &str = "ck:realm:01904100-0000-7000-8000-000000000003";

    /// Build a real MLS group for `EXPORTER_REALM`, store its account snapshot
    /// secret in `store`, and return the encrypted snapshot envelope — the same
    /// construction `crate::mls::runtime` uses for chat/reaction restore.
    fn seed_realm_snapshot(
        store: &crate::secure_key_store::MemorySecureKeyStore,
    ) -> crate::mls::persistence::MlsSnapshotEnvelope {
        use cokret_sdk::{CokretMlsIdentity, DeviceId, Did};

        let secret = crate::mls::runtime::load_or_create_device_snapshot_secret(
            store,
            EXPORTER_ACTOR,
            EXPORTER_DEVICE,
        )
        .unwrap();
        let identity = CokretMlsIdentity::new_basic(
            Did::new(EXPORTER_ACTOR.to_owned()).unwrap(),
            DeviceId::new(EXPORTER_DEVICE.to_owned()).unwrap(),
        )
        .unwrap();
        let group = identity.create_group(EXPORTER_REALM.as_bytes()).unwrap();
        let record = group.export_state_record().unwrap();
        let bytes = serde_json::to_vec(&record).unwrap();
        crate::mls::persistence::encrypt_state(
            EXPORTER_REALM,
            &record.group_id,
            record.epoch,
            &bytes,
            &secret,
            b"deterministic-salt",
        )
    }

    #[test]
    fn realm_mls_exporter_derives_real_frame_key_from_snapshot() {
        let store = crate::secure_key_store::MemorySecureKeyStore::new();
        let snapshot = seed_realm_snapshot(&store);

        let exporter = RealmMlsExporter::for_realm(
            Some(snapshot),
            &store,
            EXPORTER_ACTOR,
            EXPORTER_DEVICE,
        )
        .expect("a synced snapshot + account secret must restore the group");

        // Derive the SFrame frame key the way join_call_media does. The key is
        // a real RFC 9420 §8 MLS-Exporter output, not a placeholder.
        let ctx = FrameKeyContext {
            realm_id: RealmId::new(EXPORTER_REALM.to_owned()).unwrap(),
            call_id: CallId::new("ck:call:0196441c-0000-7000-8000-000000000000".to_owned())
                .unwrap(),
            focus_id: "fra-1".to_owned(),
            epoch_id: exporter.epoch(),
            participant_identity:
                "ck:rtc_participant:00000000-0000-0000-0000-000000000001".to_owned(),
            device_id: cokret_sdk::DeviceId::new(EXPORTER_DEVICE.to_owned()).unwrap(),
        };
        let key = derive_frame_key(&exporter, &ctx).expect("frame key derivation");

        assert_eq!(key.len(), cokret_sdk::MEDIA_KEY_LEN);
        assert_eq!(key.len(), 32);
        // Not a placeholder: a real exporter secret is not all-zero.
        assert!(key.iter().any(|&b| b != 0));

        // Deterministic for the same group epoch + context (peers reproduce it).
        let key_again = derive_frame_key(&exporter, &ctx).unwrap();
        assert_eq!(key, key_again);
    }

    #[test]
    fn realm_mls_exporter_fails_closed_without_snapshot() {
        let store = crate::secure_key_store::MemorySecureKeyStore::new();
        // Even with the account secret present, no snapshot means no synced
        // group on this device: honest fail-closed, no fabricated key.
        let _ = crate::mls::runtime::load_or_create_device_snapshot_secret(
            &store,
            EXPORTER_ACTOR,
            EXPORTER_DEVICE,
        )
        .unwrap();

        let result =
            RealmMlsExporter::for_realm(None, &store, EXPORTER_ACTOR, EXPORTER_DEVICE);
        assert!(matches!(
            result.err(),
            Some(RtcClientError::E2eeKeySourceUnauthorised)
        ));
    }

    #[test]
    fn realm_mls_exporter_fails_closed_without_account_secret() {
        // Snapshot present, but the device has no account MLS secret to unwrap
        // it (e.g. fresh browser before account recovery): fail closed.
        let seed_store = crate::secure_key_store::MemorySecureKeyStore::new();
        let snapshot = seed_realm_snapshot(&seed_store);

        let empty_store = crate::secure_key_store::MemorySecureKeyStore::new();
        let result = RealmMlsExporter::for_realm(
            Some(snapshot),
            &empty_store,
            EXPORTER_ACTOR,
            EXPORTER_DEVICE,
        );
        assert!(matches!(
            result.err(),
            Some(RtcClientError::E2eeKeySourceUnauthorised)
        ));
    }
}
