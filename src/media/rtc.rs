//! Real RTC media wiring (`media-service-binding.md`).
//!
//! This module is the single source of truth for joining a call's media
//! plane. The flow is:
//!
//! 1. **CALL-1** — `media_token_exchange` POSTs `ak.self.call.media.exchange.issue_token.v1` to
//!    soland's `/_arkret/self/rtc/token`, then anchors + verifies the response via
//!    [`arkret_signatures::media::verify_call_media_token_outcome`] (issuer anchoring, ≤600s TTL,
//!    six-tuple binding).
//! 2. **ICE** — `ice_config` POSTs to `/_arkret/self/rtc/ice-config` and runs
//!    [`arkret_signatures::media::verify_ice_config_outcome`] (issuer anchoring, TURN credential
//!    privacy, refresh-lead invariants).
//! 3. **MEDIA-1** — the SFrame frame key is derived from the live MLS exporter via
//!    [`arkret_crypto::sframe::derive_frame_key`]. Any non-MLS key source is unrepresentable: the
//!    helper only accepts an [`arkret_crypto::sframe::MlsExporterSource`], so a backend KMS key can
//!    never be installed (fail-closed → `e2ee_key_source_unauthorised`).
//!
//! The platform RTC transport (`crate::rtc_transport`) consumes the
//! verified [`JoinedMediaSession`] this module returns: connect URL,
//! backend token, ICE servers, and the SFrame key bytes.

/// Stable label registered on the `ak.profile.media_service_binding.v1`
/// profile for the SFrame frame key derivation (`media-service-binding.md
/// §8.1`). Re-exported from the SDK so the renderer pins exactly one value.
use arkret_crypto::sframe::{FrameKeyContext, MlsExporterSource, derive_frame_key};
use arkret_sdk::{
    CallId, CallMediaDesiredMedia, CallMediaParticipantBinding, CallMediaTokenExchangeOutcome,
    CallMediaTokenExchangeRequestBody, DeviceId, DidCoreId, MediaBackendKind, MediaBackendToken,
    MediaIceConfigRequestBody, MediaIceMode, MlsGovernanceBindingPayload, PlaintextDataClassKind,
    PlaintextVisibleServicesPayload, RealmId, resolve_verification_method_key_from_document,
};
use arkret_signatures::media::{
    IceConfig, MediaServiceAnchors, call_media_token_exchange, verify_call_media_token_outcome,
    verify_ice_config_outcome,
};
use ed25519_dalek::VerifyingKey;
use garth::RouteResolution;
use serde_json::Value;

use crate::transport::TransportClient;

/// Spec-mandated TTL ceiling for media tokens
/// (`ak.self.call.media.exchange.issue_token.v1`). Soland defaults to 300s; the
/// ceiling is 600s.
pub const MEDIA_TOKEN_TTL_MAX_SECS: u64 = arkret_sdk::MEDIA_TOKEN_TTL_MAX_SECS;

/// Error reasons surfaced by the RTC client integration. These map 1:1
/// to the error code enum landed in arkret-spec round R3 (§0.7).
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
    /// `ak.realm.media_service.foci[].type` not one of the five
    /// canonical enums (`livekit | mediasoup | janus | arkret_native
    /// | moq_relay`).
    UnknownFocusType,
    /// Token issuer kid does not resolve to the current
    /// `ak.realm.media_service.service_id`.
    TokenIssuerUnauthorised,
    /// `participant_binding` failed signature / TTL / tuple validation.
    ParticipantBindingInvalid,
    /// SFU reported a `ParticipantConnected` whose identity is not in the
    /// effective `ak.component.call.roster.v1` OR-Set. Receiver MUST fail closed.
    ParticipantIdUnrecognised,
    /// Frame key source was not the MLS Exporter. Any backend-supplied
    /// key (e.g. LiveKit-side key vault) is rejected.
    E2eeKeySourceUnauthorised,
    /// Egress destination is not a Arkret-authenticated blob upload.
    /// Recording is refused.
    RecordingArtifactPipelineBypassed,
    /// Transcription artifact was produced outside the Arkret blob pipeline.
    TranscriptionArtifactPipelineBypassed,
    /// `ak.realm.media_service` is not covered by the current epoch's MLS
    /// governance binding, so issuer anchoring must not proceed.
    MediaServiceBindingUncovered,
    /// The Realm policy did not authorize this media service to see
    /// plaintext media.
    MediaPlaintextServiceNotAuthorised,
    /// The local MLS governance binding does not cover the current media
    /// plaintext / policy cell values.
    MlsGovernanceBindingStale,
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
            Self::ParticipantIdUnrecognised => "participant_id_unrecognised",
            Self::E2eeKeySourceUnauthorised => "e2ee_key_source_unauthorised",
            Self::RecordingArtifactPipelineBypassed => "recording_artifact_pipeline_bypassed",
            Self::TranscriptionArtifactPipelineBypassed => {
                "transcription_artifact_pipeline_bypassed"
            }
            Self::MediaServiceBindingUncovered => "media_service_binding_uncovered",
            Self::MediaPlaintextServiceNotAuthorised => "media_plaintext_service_not_authorised",
            Self::MlsGovernanceBindingStale => "mls_governance_binding_stale",
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
            Self::ParticipantIdUnrecognised => "error.call.participant_id_unrecognised",
            Self::E2eeKeySourceUnauthorised => "error.call.e2ee_key_source_unauthorised",
            Self::RecordingArtifactPipelineBypassed => {
                "error.call.recording_artifact_pipeline_bypassed"
            }
            Self::TranscriptionArtifactPipelineBypassed => {
                "error.call.transcription_artifact_pipeline_bypassed"
            }
            Self::MediaServiceBindingUncovered => "error.call.media_service_binding_uncovered",
            Self::MediaPlaintextServiceNotAuthorised => {
                "error.call.media_plaintext_service_not_authorised"
            }
            Self::MlsGovernanceBindingStale => "error.call.mls_governance_binding_stale",
            Self::DesktopMediaUnavailable => "error.call.desktop_media_unavailable",
        }
    }

    /// Parses a soland error `code` string into a typed [`RtcClientError`].
    /// Returns `None` for codes outside the media binding set —
    /// callers should fall back to the generic error path.
    pub fn from_wire(code: &str) -> Option<Self> {
        Some(match code {
            "focus_unavailable_for_client" => Self::FocusUnavailableForClient,
            "focus_mismatch" => Self::FocusMismatch,
            "unknown_focus_type" => Self::UnknownFocusType,
            "token_issuer_unauthorised" => Self::TokenIssuerUnauthorised,
            "participant_binding_invalid" => Self::ParticipantBindingInvalid,
            "participant_id_unrecognised" => Self::ParticipantIdUnrecognised,
            "e2ee_key_source_unauthorised" => Self::E2eeKeySourceUnauthorised,
            "recording_artifact_pipeline_bypassed" => Self::RecordingArtifactPipelineBypassed,
            "transcription_artifact_pipeline_bypassed" => {
                Self::TranscriptionArtifactPipelineBypassed
            }
            "media_service_binding_uncovered" => Self::MediaServiceBindingUncovered,
            "media_plaintext_service_not_authorised" => Self::MediaPlaintextServiceNotAuthorised,
            "mls_governance_binding_stale" => Self::MlsGovernanceBindingStale,
            "desktop_media_unavailable" => Self::DesktopMediaUnavailable,
            _ => return None,
        })
    }

    /// Map a soland API error into the typed reason, classifying the
    /// wire `code` carried by the error envelope. Unknown codes collapse
    /// to [`Self::ParticipantBindingInvalid`] so the renderer still fails
    /// closed instead of silently joining.
    fn from_api_error(error: &anyhow::Error) -> Self {
        if let Some(api_error) = error.downcast_ref::<crate::api_error::TransportClientError>()
            && let Some(typed) = Self::from_wire(api_error.error.code())
        {
            return typed;
        }
        Self::ParticipantBindingInvalid
    }
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
/// plane. All ids are canonical protocol ids (`ak:realm:…`, `ak:call:…`,
/// `did:…`, `ak:device:…`).
#[derive(Clone, Debug)]
pub struct MediaJoinRequest {
    pub realm_id: String,
    pub call_id: String,
    pub actor_id: String,
    pub device_id: String,
    pub focus_id: String,
    pub epoch_id: u64,
    pub desired_media: DesiredMedia,
    /// Stable media-service identities anchored by the realm's current
    /// `ak.realm.media_service.service_id`. Token + ICE issuers MUST
    /// resolve to one of these; an empty set fails closed.
    pub media_service_ids: Vec<String>,
    /// Evaluator-produced route material for every accepted stable service
    /// identity. A DID, DID document, URL or generic principal
    /// resolution is intentionally not accepted at this boundary.
    pub verified_media_routes: Vec<RouteResolution>,
    /// Local evidence that the selected `ak.realm.media_service` event is
    /// covered by the current MLS governance binding. Token/ICE issuer anchors
    /// are not trusted until this verifies.
    pub governance_evidence: Option<MediaGovernanceEvidence>,
}

impl MediaJoinRequest {
    fn typed_ids(&self) -> Result<TypedJoinIds, RtcClientError> {
        let realm_id =
            RealmId::new(self.realm_id.clone()).map_err(|_| RtcClientError::FocusMismatch)?;
        let call_id =
            CallId::new(self.call_id.clone()).map_err(|_| RtcClientError::FocusMismatch)?;
        let actor_id = crate::mls_api_helpers::principal_core_id(&self.actor_id)
            .map_err(|_| RtcClientError::FocusMismatch)?;
        let device_id =
            DeviceId::new(self.device_id.clone()).map_err(|_| RtcClientError::FocusMismatch)?;
        Ok(TypedJoinIds {
            realm_id,
            call_id,
            actor_id,
            device_id,
        })
    }

    fn media_service_core_ids(&self) -> Result<Vec<DidCoreId>, RtcClientError> {
        let ids = self
            .media_service_ids
            .iter()
            .map(|service_id| DidCoreId::new(service_id.clone()))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| RtcClientError::TokenIssuerUnauthorised)?;
        if ids.is_empty() {
            // Fail closed: with no anchored media service we cannot trust
            // any issuer kid.
            return Err(RtcClientError::TokenIssuerUnauthorised);
        }
        let mut unique = ids.clone();
        unique.sort();
        unique.dedup();
        if unique.len() != ids.len() {
            return Err(RtcClientError::TokenIssuerUnauthorised);
        }
        Ok(ids)
    }

    fn anchors(&self) -> Result<MediaServiceAnchors, RtcClientError> {
        let service_ids = self.media_service_core_ids()?;
        if self.verified_media_routes.len() != service_ids.len() {
            return Err(RtcClientError::TokenIssuerUnauthorised);
        }

        let mut route_pairs = Vec::with_capacity(service_ids.len());
        for service_id in &service_ids {
            let route = self
                .verified_media_routes
                .iter()
                .find(|route| route.route().service_id() == service_id)
                .ok_or(RtcClientError::TokenIssuerUnauthorised)?;
            let cached = route.route();
            let authenticated = route.authenticated_resolution();
            let record = authenticated
                .projection()
                .map_err(|_| RtcClientError::TokenIssuerUnauthorised)?;
            // The cached route holds the whole projection this evidence
            // derives, so the two can only differ by being different
            // projections.
            if record.service_kind != "media_service"
                || record.service_id != *service_id
                || cached.projection != record
                || &authenticated.normalized_did_document.id != cached.did()
            {
                return Err(RtcClientError::TokenIssuerUnauthorised);
            }
            route_pairs.push((service_id.clone(), cached.did().clone()));
        }

        let mut anchors = MediaServiceAnchors::new(route_pairs)
            .map_err(|_| RtcClientError::TokenIssuerUnauthorised)?;
        for route in &self.verified_media_routes {
            register_media_service_keys(&mut anchors, route)?;
        }
        Ok(anchors)
    }

    fn verify_governance_evidence(&self) -> Result<(), RtcClientError> {
        let evidence = self
            .governance_evidence
            .as_ref()
            .ok_or(RtcClientError::MediaServiceBindingUncovered)?;
        evidence.verify_for_join(self)
    }
}

#[derive(Clone, Debug)]
pub struct MediaGovernanceEvidence {
    pub governance_binding: MlsGovernanceBindingPayload,
    pub media_service_payload: Value,
    pub policy_bundle_payload: Option<Value>,
    pub plaintext_visible_services_payload: Option<PlaintextVisibleServicesPayload>,
    pub media_plaintext_ui_confirmed: bool,
}

impl MediaGovernanceEvidence {
    pub fn media_service_decrypts_enabled(&self) -> bool {
        policy_media_service_decrypts(self.policy_bundle_payload.as_ref())
    }

    fn verify_for_join(&self, request: &MediaJoinRequest) -> Result<(), RtcClientError> {
        if self.governance_binding.next_epoch() != request.epoch_id {
            return Err(RtcClientError::MlsGovernanceBindingStale);
        }
        let service_id = media_service_payload_service_id(&self.media_service_payload)
            .ok_or(RtcClientError::MediaServiceBindingUncovered)?;
        if !request
            .media_service_ids
            .iter()
            .any(|did| did == service_id)
        {
            return Err(RtcClientError::TokenIssuerUnauthorised);
        }
        if !media_service_payload_has_focus(&self.media_service_payload, &request.focus_id) {
            return Err(RtcClientError::FocusMismatch);
        }

        if self.media_service_decrypts_enabled() {
            self.verify_plaintext_media_authorization(service_id)?;
        }
        Ok(())
    }

    fn verify_plaintext_media_authorization(&self, service_id: &str) -> Result<(), RtcClientError> {
        if !self.media_plaintext_ui_confirmed {
            return Err(RtcClientError::MediaPlaintextServiceNotAuthorised);
        }
        let plaintext_payload = self
            .plaintext_visible_services_payload
            .as_ref()
            .ok_or(RtcClientError::MediaPlaintextServiceNotAuthorised)?;
        let service_id = DidCoreId::new(service_id.to_owned())
            .map_err(|_| RtcClientError::MediaPlaintextServiceNotAuthorised)?;
        let authorized = plaintext_payload.services.iter().any(|service| {
            service.service_id == service_id
                && service
                    .data_classes
                    .iter()
                    .any(|class| matches!(class, PlaintextDataClassKind::MediaPlaintext))
        });
        if !authorized {
            return Err(RtcClientError::MediaPlaintextServiceNotAuthorised);
        }

        Ok(())
    }
}

fn media_service_payload_service_id(payload: &Value) -> Option<&str> {
    payload.get("service_id").and_then(Value::as_str)
}

fn media_service_payload_has_focus(payload: &Value, focus_id: &str) -> bool {
    payload
        .get("foci")
        .and_then(Value::as_array)
        .map(|foci| {
            foci.iter()
                .any(|focus| focus.get("focus_id").and_then(Value::as_str) == Some(focus_id))
        })
        .unwrap_or(false)
}

fn policy_media_service_decrypts(payload: Option<&Value>) -> bool {
    payload
        .and_then(|value| {
            value
                .get("media_service_decrypts")
                .or_else(|| value.pointer("/components/media_service_decrypts"))
                .or_else(|| value.pointer("/media/media_service_decrypts"))
        })
        .and_then(Value::as_bool)
        .unwrap_or(false)
}

fn register_media_service_keys(
    anchors: &mut MediaServiceAnchors,
    route: &RouteResolution,
) -> Result<(), RtcClientError> {
    let document = &route.authenticated_resolution().normalized_did_document;
    let service_did = route.route().did().as_str();

    let mut registered = 0usize;
    for method in document.verification_methods.keys() {
        let resolved = resolve_verification_method_key_from_document(document, method)
            .map_err(|_| RtcClientError::TokenIssuerUnauthorised)?;
        if resolved.did.as_str() != service_did {
            return Err(RtcClientError::TokenIssuerUnauthorised);
        }
        let key_bytes = resolved
            .public_key
            .ed25519_bytes()
            .map_err(|_| RtcClientError::TokenIssuerUnauthorised)?;
        let verifying_key = VerifyingKey::from_bytes(&key_bytes)
            .map_err(|_| RtcClientError::TokenIssuerUnauthorised)?;
        let kid = normalize_verification_method_kid(service_did, &resolved.verification_method);
        anchors
            .insert_key(kid, verifying_key)
            .map_err(|_| RtcClientError::TokenIssuerUnauthorised)?;
        registered += 1;
    }

    if registered == 0 {
        return Err(RtcClientError::TokenIssuerUnauthorised);
    }
    Ok(())
}

fn normalize_verification_method_kid(service_did: &str, method: &str) -> String {
    if method.starts_with("did:") {
        method.to_owned()
    } else if method.starts_with('#') {
        format!("{service_did}{method}")
    } else {
        format!("{service_did}#{method}")
    }
}

struct TypedJoinIds {
    realm_id: RealmId,
    call_id: CallId,
    actor_id: DidCoreId,
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
    pub backend_kind: String,
    /// Authoritative focus id echoed by the token issuer.
    pub focus_id: String,
    /// Backend WebSocket connect URL (e.g. LiveKit `wss://…`).
    pub connect_url: String,
    /// Opaque backend join token (LiveKit JWT, etc.).
    pub backend_token: String,
    /// SFU-local participant identity, cross-checked against the effective
    /// `ak.component.call.roster.v1` OR-Set on `ParticipantConnected`.
    pub participant_id: String,
    /// Token issuer's signed tuple for the local participant. The call
    /// controller joins this into `ak.component.call.roster.v1` before
    /// connecting the SFU so remote streams have a durable roster to check.
    pub participant_binding: CallMediaParticipantBinding,
    /// Verified ICE configuration (STUN/TURN + turn_required + ttl).
    pub ice_config: IceConfig,
    /// 32-byte SFrame frame key derived from the MLS exporter
    /// (`ak-rtc-frame-key/v1`). Installed as the E2EE keyprovider seed.
    /// Key material — kept [`zeroize::Zeroizing`] so it is wiped on drop.
    pub frame_key: zeroize::Zeroizing<Vec<u8>>,
    /// `desired_media` echoed for the transport's publisher setup.
    pub desired_media: DesiredMedia,
    /// Local participant's own `device_id` — bound into the local sender's
    /// SFrame [`FrameKeyContext`] (`media-service-binding.md` §8.1) and used to
    /// build the per-sender key install so peers can recompute it.
    pub device_id: String,
    /// Static SFrame context fields shared by every sender in this call leg:
    /// `realm_id`, `call_id`, `focus_id`, and the MLS `epoch_id`. A remote
    /// sender's key is the same MLS group exporter (same epoch) evaluated over
    /// the remote sender's `(participant_id, device_id)`.
    pub realm_id: String,
    pub call_id: String,
    pub epoch_id: u64,
}

/// Per-sender SFrame key derivation for a joined call leg.
///
/// Every member of the call shares the same MLS group exporter secret at a
/// given epoch, so any member can reproduce *another* sender's frame key by
/// evaluating the exporter over that sender's
/// `Context = canonical_json({realm_id, call_id, focus_id, epoch_id,
/// participant_id, device_id})` (`media-service-binding.md` §8.1). This
/// is what lets the receiver install the remote sender's key and decrypt its
/// frames — without it, two members each only know their own key and can never
/// decrypt each other.
///
/// The deriver retains the live [`RealmMlsExporter`] (so the MLS group is not
/// dropped after the local key is derived at join time) plus the static
/// per-leg context. It is held behind an `Rc` and invoked from the transport's
/// `ParticipantConnected` callback to install each remote sender's key.
pub struct PerSenderFrameKeys {
    exporter: RealmMlsExporter,
    realm_id: RealmId,
    call_id: CallId,
    focus_id: String,
    epoch_id: u64,
}

impl PerSenderFrameKeys {
    /// Build the per-sender deriver from the joined leg's static context and the
    /// retained MLS exporter. `epoch_id` MUST be the exporter's live epoch so a
    /// remote key is derived under the same group secret as the local key.
    pub fn new(
        exporter: RealmMlsExporter,
        realm_id: RealmId,
        call_id: CallId,
        focus_id: String,
        epoch_id: u64,
    ) -> Self {
        Self {
            exporter,
            realm_id,
            call_id,
            focus_id,
            epoch_id,
        }
    }

    /// The live MLS epoch the local key was derived at. Remote keys are derived
    /// at the same epoch.
    pub fn epoch(&self) -> u64 {
        self.epoch_id
    }

    /// Derive the SFrame frame key for one *remote* sender, identified by its
    /// `(participant_id, device_id)` from the verified effective
    /// `ak.component.call.roster.v1` OR-Set.
    ///
    /// Fail-closed (`Err`) when the ids are malformed or the exporter rejects
    /// the context; the caller skips installing that one remote's key (its
    /// frames stay undecryptable) without affecting any other remote. The same
    /// MLS group exporter at the same epoch is used, so the bytes are identical
    /// to what the remote sender derived for itself.
    pub fn derive_remote_key(
        &self,
        participant_id: &str,
        device_id: &str,
    ) -> Result<zeroize::Zeroizing<Vec<u8>>, RtcClientError> {
        let realm_id = self.realm_id.clone();
        let call_id = self.call_id.clone();
        let device_id = DeviceId::new(device_id.to_owned())
            .map_err(|_| RtcClientError::E2eeKeySourceUnauthorised)?;
        let context = FrameKeyContext {
            realm_id,
            call_id,
            focus_id: self.focus_id.clone(),
            epoch_id: self.epoch_id,
            participant_id: participant_id.to_owned(),
            device_id,
        };
        derive_frame_key(&self.exporter, &context)
            .map_err(|_| RtcClientError::E2eeKeySourceUnauthorised)
    }
}

/// Run the full media-plane join: token exchange → verify → ICE config →
/// verify → MLS-exporter SFrame key. `mls_exporter` MUST be the live
/// realm MLS group; passing a non-MLS source is impossible by the
/// [`MlsExporterSource`] bound, which is what enforces MEDIA-1.
pub async fn join_call_media(
    api: &TransportClient,
    request: &MediaJoinRequest,
    mls_exporter: &impl MlsExporterSource,
) -> Result<JoinedMediaSession, RtcClientError> {
    let ids = request.typed_ids()?;
    request.verify_governance_evidence()?;
    let anchors = request.anchors()?;

    // CALL-1 — token exchange + anchored verification.
    let mut token_request: CallMediaTokenExchangeRequestBody = call_media_token_exchange(
        ids.realm_id.clone(),
        ids.call_id.clone(),
        crate::mls_api_helpers::local_account_actor_id(ids.actor_id.as_str())
            .map_err(|_| RtcClientError::ParticipantBindingInvalid)?,
        ids.device_id.clone(),
        request.focus_id.clone(),
    );
    token_request.desired_media = Some(request.desired_media.into_wire());

    let outcome: CallMediaTokenExchangeOutcome = async {
        crate::transport::EndpointClients::from_http(api.sdk_http_client()?)
            .media()
            .token_exchange(&token_request)
            .await
    }
    .await
    .map_err(|err| RtcClientError::from_api_error(&err))?;

    let now = chrono::Utc::now();
    let verification = verify_call_media_token_outcome(&token_request, &outcome, &anchors, now)
        .map_err(|err| classify_protocol_error(&err))?;

    // Inkson's current RTC transports are LiveKit drivers. Consume the closed
    // backend/token union exhaustively and fail before connecting for every
    // backend that has no host driver; in particular, never stringify the
    // structured Arkret-native token into an opaque credential.
    let backend_token = match (&outcome.backend_kind, &outcome.backend_token) {
        (MediaBackendKind::Livekit, MediaBackendToken::Opaque(token)) => token.clone(),
        (
            MediaBackendKind::Mediasoup
            | MediaBackendKind::Janus
            | MediaBackendKind::ArkretNative
            | MediaBackendKind::MoqRelay,
            _,
        ) => return Err(RtcClientError::UnknownFocusType),
        (MediaBackendKind::Livekit, MediaBackendToken::ArkretNative(_)) => {
            return Err(RtcClientError::UnknownFocusType);
        }
    };

    // ICE config — verified against the same anchors. A focus-bound call
    // always relays through the SFU media plane.
    let ice_request = MediaIceConfigRequestBody {
        realm_id: ids.realm_id.clone(),
        call_id: request.call_id.clone(),
        actor_id: crate::mls_api_helpers::local_account_actor_id(ids.actor_id.as_str())
            .map_err(|_| RtcClientError::ParticipantBindingInvalid)?,
        device_id: ids.device_id.clone(),
        mode: MediaIceMode::Sfu,
    };
    let ice_outcome = async {
        crate::transport::EndpointClients::from_http(api.sdk_http_client()?)
            .media()
            .ice_config(&ice_request)
            .await
    }
    .await
    .map_err(|err| RtcClientError::from_api_error(&err))?;
    let ice_config = verify_ice_config_outcome(&ice_outcome, &anchors)
        .map_err(|err| classify_protocol_error(&err))?;

    // MEDIA-1 — SFrame frame key from the live MLS exporter. The
    // participant_id is the verified SFU-local handle from the
    // token binding, so the key is sender-bound per §8.1.
    let frame_context = FrameKeyContext {
        realm_id: ids.realm_id.clone(),
        call_id: ids.call_id.clone(),
        focus_id: request.focus_id.clone(),
        epoch_id: request.epoch_id,
        participant_id: verification.participant_id.clone(),
        device_id: ids.device_id.clone(),
    };
    let frame_key = derive_frame_key(mls_exporter, &frame_context)
        .map_err(|_| RtcClientError::E2eeKeySourceUnauthorised)?;

    Ok(JoinedMediaSession {
        backend_kind: "livekit".to_owned(),
        focus_id: outcome.focus_id,
        connect_url: outcome.connect_url,
        backend_token,
        participant_binding: outcome.participant_binding,
        participant_id: verification.participant_id,
        ice_config,
        frame_key,
        desired_media: request.desired_media,
        device_id: request.device_id.clone(),
        realm_id: request.realm_id.clone(),
        call_id: request.call_id.clone(),
        epoch_id: request.epoch_id,
    })
}

/// MEDIA-2 — cross-check an SFU-reported `ParticipantConnected` identity
/// against the effective `ak.component.call.roster.v1` projection. A mismatch is
/// fail-closed; the transport MUST drop the connection.
pub fn cross_check_participant_id(
    reported_identity: &str,
    expected_identities: &std::collections::BTreeSet<String>,
) -> Result<(), RtcClientError> {
    if expected_identities.contains(reported_identity) {
        Ok(())
    } else {
        Err(RtcClientError::ParticipantIdUnrecognised)
    }
}

/// MLS exporter backing the SFrame frame-key derivation.
///
/// This wraps the live [`arkret_sdk::ArkretMlsGroup`] restored from this
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
    group: arkret_sdk::ArkretMlsGroup,
}

impl RealmMlsExporter {
    /// Restore the realm's live, synchronised MLS group from this device's
    /// persisted snapshot so the SFrame exporter secret matches every other
    /// member's. `snapshot` is the per-realm
    /// [`crate::mls::persistence::MlsLocalCheckpointEnvelope`] the caller reads from
    /// `LocalStateStore::mls_checkpoint_for` (passed by value so the caller can
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
        snapshot: Option<crate::mls::persistence::MlsLocalCheckpointEnvelope>,
        secure_store: &dyn crate::secure_key_store::SecureKeyStore,
        authority: &arkret_sdk::AccountId,
        device_id: &arkret_sdk::DeviceId,
    ) -> Result<Self, RtcClientError> {
        let snapshot = snapshot.ok_or(RtcClientError::E2eeKeySourceUnauthorised)?;
        let secret =
            crate::mls::runtime::load_device_checkpoint_secret(secure_store, authority, device_id)
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
    ) -> arkret_crypto::Result<zeroize::Zeroizing<Vec<u8>>> {
        // Delegate to ArkretMlsGroup's own MlsExporterSource impl, which
        // bridges the MLS behavior error into the crypto-boundary error.
        <arkret_sdk::ArkretMlsGroup as MlsExporterSource>::export_secret(
            &self.group,
            label,
            context,
            length,
        )
    }
}

/// Map a Signatures owner [`arkret_signatures::Error`]'s protocol message into
/// the typed reason. The verification helpers stamp the wire code into the message
/// (`participant_binding_invalid: …` / `token_issuer_unauthorised: …` /
/// `ice_config_denied: …`); scan for the first known code substring so a
/// `Display` prefix from the `Error` enum does not shadow it.
fn classify_protocol_error(err: &arkret_signatures::Error) -> RtcClientError {
    let message = err.to_string();
    const CODES: &[RtcClientError] = &[
        RtcClientError::TokenIssuerUnauthorised,
        RtcClientError::E2eeKeySourceUnauthorised,
        RtcClientError::ParticipantIdUnrecognised,
        RtcClientError::FocusUnavailableForClient,
        RtcClientError::FocusMismatch,
        RtcClientError::UnknownFocusType,
        RtcClientError::RecordingArtifactPipelineBypassed,
        RtcClientError::MediaServiceBindingUncovered,
        RtcClientError::MediaPlaintextServiceNotAuthorised,
        RtcClientError::MlsGovernanceBindingStale,
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

    use serde_json::json;

    use super::*;
    use crate::test_support as fixture;

    #[test]
    fn participant_id_cross_check_fails_closed_on_unknown() {
        let mut known = BTreeSet::new();
        known.insert("ak:rtc_participant:00000000-0000-0000-0000-000000000001".to_owned());
        assert!(
            cross_check_participant_id(
                "ak:rtc_participant:00000000-0000-0000-0000-000000000001",
                &known
            )
            .is_ok()
        );
        assert_eq!(
            cross_check_participant_id("ak:rtc_participant:unknown", &known),
            Err(RtcClientError::ParticipantIdUnrecognised)
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
            RtcClientError::ParticipantIdUnrecognised,
            RtcClientError::E2eeKeySourceUnauthorised,
            RtcClientError::RecordingArtifactPipelineBypassed,
            RtcClientError::TranscriptionArtifactPipelineBypassed,
            RtcClientError::MediaServiceBindingUncovered,
            RtcClientError::MediaPlaintextServiceNotAuthorised,
            RtcClientError::MlsGovernanceBindingStale,
            RtcClientError::DesktopMediaUnavailable,
        ] {
            assert_eq!(RtcClientError::from_wire(err.as_wire()), Some(err));
            assert!(err.i18n_key().starts_with("error.call."));
        }
    }

    #[test]
    fn empty_anchor_set_fails_closed() {
        let request = MediaJoinRequest {
            realm_id: "ak:realm:AVxu7KCm9qmiOqakDKBXUia9rbZ3NBurP875XbqG1rbs".to_owned(),
            call_id: "ak:call:AYf05kF8z4cSo8r6qmqXgu4KPuv2YtKBlsE00FOmblaz".to_owned(),
            actor_id: "ak:did_core:web:alice.example".to_owned(),
            device_id: "ak:device:01904100-0000-7000-8000-000000000005".to_owned(),
            focus_id: "fra-1".to_owned(),
            epoch_id: 7,
            desired_media: DesiredMedia::audio_video(),
            media_service_ids: Vec::new(),
            verified_media_routes: Vec::new(),
            governance_evidence: None,
        };
        assert_eq!(
            request.media_service_core_ids().unwrap_err(),
            RtcClientError::TokenIssuerUnauthorised
        );
    }

    #[test]
    fn media_join_requires_current_governance_binding() {
        let request = governed_join_request(None);
        assert_eq!(
            request.verify_governance_evidence(),
            Err(RtcClientError::MediaServiceBindingUncovered)
        );
    }

    #[test]
    fn media_plaintext_decrypt_requires_ui_confirmation() {
        let request = governed_join_request(Some(media_governance_evidence(true, false)));
        assert_eq!(
            request.verify_governance_evidence(),
            Err(RtcClientError::MediaPlaintextServiceNotAuthorised)
        );
    }

    #[test]
    fn media_plaintext_decrypt_accepts_three_layer_evidence() {
        let request = governed_join_request(Some(media_governance_evidence(true, true)));
        assert!(request.verify_governance_evidence().is_ok());
    }

    #[test]
    fn media_plaintext_authorization_ignores_free_text_purpose() {
        let request = governed_join_request(Some(media_governance_evidence(true, true)));
        let purposes = &request
            .governance_evidence
            .as_ref()
            .unwrap()
            .plaintext_visible_services_payload
            .as_ref()
            .unwrap()
            .services[0]
            .purposes;
        assert_eq!(purposes, &["video_transcoding"]);
        assert!(request.verify_governance_evidence().is_ok());
    }

    #[test]
    fn opaque_media_service_accepts_binding_coverage_without_plaintext_grant() {
        let request = governed_join_request(Some(media_governance_evidence(false, false)));
        assert!(request.verify_governance_evidence().is_ok());
    }

    fn governed_join_request(
        governance_evidence: Option<MediaGovernanceEvidence>,
    ) -> MediaJoinRequest {
        MediaJoinRequest {
            realm_id: "ak:realm:AVxu7KCm9qmiOqakDKBXUia9rbZ3NBurP875XbqG1rbs".to_owned(),
            call_id: "ak:call:AYf05kF8z4cSo8r6qmqXgu4KPuv2YtKBlsE00FOmblaz".to_owned(),
            actor_id: "ak:did_core:web:alice.example".to_owned(),
            device_id: "ak:device:01904100-0000-7000-8000-000000000005".to_owned(),
            focus_id: "fra-1".to_owned(),
            epoch_id: 7,
            desired_media: DesiredMedia::audio_video(),
            media_service_ids: vec!["ak:did_core:web:media.example".to_owned()],
            verified_media_routes: Vec::new(),
            governance_evidence,
        }
    }

    fn media_governance_evidence(
        media_service_decrypts: bool,
        media_plaintext_ui_confirmed: bool,
    ) -> MediaGovernanceEvidence {
        let media_service_payload = json!({
            "service_id": "ak:did_core:web:media.example",
            "ice_config_endpoint": "https://media.example/_arkret/self/rtc/ice-config",
            "foci": [
                {
                    "focus_id": "fra-1",
                    "type": "livekit",
                    "token_endpoint": "https://media.example/_arkret/self/rtc/token"
                }
            ]
        });
        let policy_bundle_payload = media_service_decrypts.then(|| {
            json!({
                "policy_revision": 3,
                "media_service_decrypts": true
            })
        });
        let plaintext_visible_services_payload = media_service_decrypts.then(|| {
            PlaintextVisibleServicesPayload::new(vec![arkret_sdk::PlaintextVisibleService::new(
                crate::mls_api_helpers::principal_core_id("did:web:media.example").unwrap(),
                "media_service",
                vec![PlaintextDataClassKind::MediaPlaintext],
                vec!["video_transcoding".to_owned()],
                arkret_sdk::PlaintextServiceVisibility::PrivatePlaintext,
            )])
        });
        let governance_binding = MlsGovernanceBindingPayload::realm(
            RealmId::new("ak:realm:AVxu7KCm9qmiOqakDKBXUia9rbZ3NBurP875XbqG1rbs".to_owned())
                .unwrap(),
            "Z3JvdXA",
            6,
            7,
            arkret_sdk::Hash::new(format!("sha256:{}", "00".repeat(32))).unwrap(),
            arkret_sdk::ContentScheme::MlsRfc9420,
            None,
            arkret_sdk::ProfileId::MLS_GOVERNANCE_BINDING_FULL_V1,
            arkret_sdk::CORE_REDUCER_PROFILE,
        )
        .unwrap();
        MediaGovernanceEvidence {
            governance_binding,
            media_service_payload,
            policy_bundle_payload,
            plaintext_visible_services_payload,
            media_plaintext_ui_confirmed,
        }
    }

    /// Positive wiring path (task 2026-08-19-1857): route material produced by
    /// the real `garth::ServiceRouteEvaluator` over a signed fixture record
    /// satisfies the token-exchange issuer anchoring, while the empty set
    /// keeps failing closed. This is the proof that "wired" does not mean
    /// "always rejects".
    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn evaluator_route_material_satisfies_token_issuer_anchors() {
        use chrono::TimeZone as _;
        use garth::service_route_material::test_fixture::current_web_route_fixture;

        let now = chrono::Utc.with_ymd_and_hms(2026, 8, 20, 1, 0, 0).unwrap();
        let fixture = current_web_route_fixture("media.example", "media_service", 31);
        let resolution = garth::authenticate_fetched_resolution(
            fixture.resolution.clone(),
            arkret_identity::ResolvedDid::proofless(fixture.document.clone()),
            now,
        )
        .expect("fixture record must authenticate");
        let mut evaluator = garth::ServiceRouteEvaluator::new(
            garth::MemoryServiceRouteStateStore::default(),
            chrono::Duration::minutes(1),
        )
        .unwrap();
        let mut source = garth::PrefetchedRouteSource::new(Some(resolution));
        source.insert_describe(
            garth::describe_route_binding(&fixture.resolution, &fixture.describe, now).unwrap(),
        );
        let route = evaluator
            .resolve(&fixture.service_id, "media_service", now, &mut source)
            .expect("evaluator must accept the verified current record");

        let mut request = governed_join_request(Some(media_governance_evidence(false, false)));
        request.verified_media_routes = vec![route];
        request
            .anchors()
            .expect("evaluator-produced route material must satisfy issuer anchoring");

        // The fail-closed half stays intact: same ids, no verified routes.
        let empty = governed_join_request(Some(media_governance_evidence(false, false)));
        assert_eq!(
            empty.anchors().unwrap_err(),
            RtcClientError::TokenIssuerUnauthorised
        );
    }

    #[test]
    fn classify_protocol_error_reads_wire_prefix() {
        let err = arkret_signatures::Error::Protocol(
            "token_issuer_unauthorised: issuer not anchored".to_owned(),
        );
        assert_eq!(
            classify_protocol_error(&err),
            RtcClientError::TokenIssuerUnauthorised
        );
        let err = arkret_signatures::Error::Protocol(
            "e2ee_key_source_unauthorised: frame key context missing".to_owned(),
        );
        assert_eq!(
            classify_protocol_error(&err),
            RtcClientError::E2eeKeySourceUnauthorised
        );
    }

    #[test]
    fn frame_key_label_matches_spec() {
        assert_eq!(
            arkret_crypto::sframe::FRAME_KEY_LABEL,
            "ak.rtc-frame-key/v1"
        );
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
    const EXPORTER_DEVICE: &str = "ak:device:01904100-0000-7000-8000-000000000001";
    const EXPORTER_REALM: &str = "ak:realm:AcsFZ3o2tOdN3EFpNceeLV-aI3jZkB9S34_4YIwJ5DLy";

    /// Build a real MLS group for `EXPORTER_REALM`, store its account snapshot
    /// secret in `store`, and return the encrypted snapshot envelope — the same
    /// construction `crate::mls::runtime` uses for chat/reaction restore.
    fn seed_realm_snapshot(
        store: &crate::secure_key_store::MemorySecureKeyStore,
    ) -> crate::mls::persistence::MlsLocalCheckpointEnvelope {
        use arkret_sdk::{ArkretMlsIdentity, DeviceId};

        let secret = crate::mls::runtime::load_or_create_account_mls_secret(
            store,
            &fixture::authority(EXPORTER_ACTOR),
        )
        .unwrap();
        let identity = ArkretMlsIdentity::new_test_human_device(
            crate::mls_api_helpers::principal_core_id(EXPORTER_ACTOR).unwrap(),
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
            &fixture::authority(EXPORTER_ACTOR),
            &fixture::device_id(EXPORTER_DEVICE),
        )
        .expect("a synced snapshot + account secret must restore the group");

        // Derive the SFrame frame key the way join_call_media does. The key is
        // a real RFC 9420 §8 MLS-Exporter output, not a placeholder.
        let ctx = FrameKeyContext {
            realm_id: RealmId::new(EXPORTER_REALM.to_owned()).unwrap(),
            call_id: CallId::new("ak:call:AYf05kF8z4cSo8r6qmqXgu4KPuv2YtKBlsE00FOmblaz".to_owned())
                .unwrap(),
            focus_id: "fra-1".to_owned(),
            epoch_id: exporter.epoch(),
            participant_id: "ak:rtc_participant:00000000-0000-0000-0000-000000000001".to_owned(),
            device_id: arkret_sdk::DeviceId::new(EXPORTER_DEVICE.to_owned()).unwrap(),
        };
        let key = derive_frame_key(&exporter, &ctx).expect("frame key derivation");

        assert_eq!(key.len(), arkret_crypto::sframe::MEDIA_KEY_LEN);
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
        let _ = crate::mls::runtime::load_or_create_account_mls_secret(
            &store,
            &fixture::authority(EXPORTER_ACTOR),
        )
        .unwrap();

        let result = RealmMlsExporter::for_realm(
            None,
            &store,
            &fixture::authority(EXPORTER_ACTOR),
            &fixture::device_id(EXPORTER_DEVICE),
        );
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
            &fixture::authority(EXPORTER_ACTOR),
            &fixture::device_id(EXPORTER_DEVICE),
        );
        assert!(matches!(
            result.err(),
            Some(RtcClientError::E2eeKeySourceUnauthorised)
        ));
    }

    // ── Cross-member SFrame key interop (the core receiver-side fix) ─────────
    //
    // The structural bug being fixed: each member only installed *its own*
    // frame key, so two members could never decrypt each other. §8.1 frame keys
    // are sender-bound, but every member of the same MLS group shares the epoch
    // exporter secret, so any member can recompute *another* sender's key by
    // evaluating the exporter over that sender's
    // `Context = {realm_id, call_id, focus_id, epoch_id, participant_id,
    // device_id}`. This test builds a REAL two-member MLS group (Alice + Bob,
    // distinct participant_id + device_id), and proves Bob — using the
    // production `PerSenderFrameKeys::derive_remote_key` path — recomputes the
    // exact bytes Alice derived for herself. Unlike the single-exporter
    // determinism tests, this is a genuine *cross-member* recomputation: two
    // different groups, same exporter secret.

    const ALICE_ACTOR: &str = "did:web:alice.example";
    const ALICE_DEVICE: &str = "ak:device:01904100-0000-7000-8000-00000000000a";
    const ALICE_IDENTITY: &str = "ak:rtc_participant:0198c2f4-0000-7000-8000-00000000000a";
    const BOB_ACTOR: &str = "did:web:bob.example";
    const BOB_DEVICE: &str = "ak:device:01904100-0000-7000-8000-00000000000b";
    const BOB_IDENTITY: &str = "ak:rtc_participant:0198c2f4-0000-7000-8000-00000000000b";
    const INTEROP_REALM: &str = "ak:realm:AQdmOQIzsGDs6LjeW5Icy92GXh1n9_6SGgVCJJ_2a3FV";
    const INTEROP_CALL: &str = "ak:call:AYf05kF8z4cSo8r6qmqXgu4KPuv2YtKBlsE00FOmblaz";

    /// Snapshot a live MLS `group` under `(actor, device)`'s account secret in
    /// `store` and restore it through the exact production `RealmMlsExporter`
    /// path, so the test exporter is byte-identical to what the call surface
    /// builds at join time.
    fn exporter_from_group(
        store: &crate::secure_key_store::MemorySecureKeyStore,
        group: &arkret_sdk::ArkretMlsGroup,
        actor: &str,
        device: &str,
    ) -> RealmMlsExporter {
        let secret = crate::mls::runtime::load_or_create_account_mls_secret(
            store,
            &fixture::authority(actor),
        )
        .unwrap();
        let record = group.export_state_record().unwrap();
        let bytes = serde_json::to_vec(&record).unwrap();
        let envelope = crate::mls::persistence::encrypt_state(
            INTEROP_REALM,
            &record.group_id,
            record.epoch,
            &bytes,
            &secret,
            b"deterministic-salt",
        );
        RealmMlsExporter::for_realm(
            Some(envelope),
            store,
            &fixture::authority(actor),
            &fixture::device_id(device),
        )
        .unwrap()
    }

    #[test]
    fn receiver_recomputes_remote_sender_frame_key_cross_member() {
        use arkret_sdk::{ArkretMlsIdentity, DeviceId};

        // Build a REAL two-member MLS group: Alice creates, Bob joins via Welcome.
        let alice_identity = ArkretMlsIdentity::new_test_human_device(
            crate::mls_api_helpers::principal_core_id(ALICE_ACTOR).unwrap(),
            DeviceId::new(ALICE_DEVICE.to_owned()).unwrap(),
        )
        .unwrap();
        let bob_identity = ArkretMlsIdentity::new_test_human_device(
            crate::mls_api_helpers::principal_core_id(BOB_ACTOR).unwrap(),
            DeviceId::new(BOB_DEVICE.to_owned()).unwrap(),
        )
        .unwrap();
        let bob_key_package = bob_identity.key_package_record().unwrap();
        let alice_endpoint = alice_identity.endpoint_identity();
        let bob_endpoint = bob_identity.endpoint_identity();

        let mut alice_group = alice_identity
            .create_group(INTEROP_REALM.as_bytes())
            .unwrap();
        let add = alice_group.add_member(&bob_key_package).unwrap();
        let mut bob_group =
            arkret_sdk::ArkretMlsGroup::join_from_welcome(bob_identity, &add.welcome).unwrap();
        bob_group
            .install_test_leaf_bindings(vec![alice_endpoint, bob_endpoint])
            .unwrap();

        // Both members are now on the same epoch with the same exporter secret.
        assert_eq!(alice_group.epoch(), bob_group.epoch());
        let epoch = alice_group.epoch();

        // Restore each member's exporter through the production path.
        let alice_store = crate::secure_key_store::MemorySecureKeyStore::new();
        let bob_store = crate::secure_key_store::MemorySecureKeyStore::new();
        let alice_exporter =
            exporter_from_group(&alice_store, &alice_group, ALICE_ACTOR, ALICE_DEVICE);
        let bob_exporter = exporter_from_group(&bob_store, &bob_group, BOB_ACTOR, BOB_DEVICE);

        let realm_id = RealmId::new(INTEROP_REALM.to_owned()).unwrap();
        let call_id = CallId::new(INTEROP_CALL.to_owned()).unwrap();
        let focus_id = "fra-1".to_owned();

        // Alice derives HER OWN sender frame key (the local install path) using
        // her own (participant_id, device_id).
        let alice_self_ctx = FrameKeyContext {
            realm_id: realm_id.clone(),
            call_id: call_id.clone(),
            focus_id: focus_id.clone(),
            epoch_id: epoch,
            participant_id: ALICE_IDENTITY.to_owned(),
            device_id: DeviceId::new(ALICE_DEVICE.to_owned()).unwrap(),
        };
        let key_alice_self = derive_frame_key(&alice_exporter, &alice_self_ctx).unwrap();
        assert_eq!(key_alice_self.len(), arkret_crypto::sframe::MEDIA_KEY_LEN);
        assert!(key_alice_self.iter().any(|&b| b != 0));

        // THE FIX: Bob (the RECEIVER, a different member) recomputes ALICE's
        // sender key via the production `PerSenderFrameKeys::derive_remote_key`,
        // using ALICE's (participant_id, device_id) over Bob's own
        // exporter at the same epoch.
        let bob_per_sender = PerSenderFrameKeys::new(
            bob_exporter,
            realm_id.clone(),
            call_id.clone(),
            focus_id.clone(),
            epoch,
        );
        let key_alice_recomputed_by_bob = bob_per_sender
            .derive_remote_key(ALICE_IDENTITY, ALICE_DEVICE)
            .expect("a co-member MUST be able to recompute the remote sender's key");

        // The crux: two DIFFERENT members compute the SAME sender key bytes, so
        // Bob can decrypt Alice's frames.
        assert_eq!(
            key_alice_self, key_alice_recomputed_by_bob,
            "receiver (Bob) MUST recompute the exact frame key the sender (Alice) installed"
        );

        // Symmetric: Alice recomputes Bob's sender key, equal to Bob's own.
        let bob_self_ctx = FrameKeyContext {
            realm_id: realm_id.clone(),
            call_id: call_id.clone(),
            focus_id: focus_id.clone(),
            epoch_id: epoch,
            participant_id: BOB_IDENTITY.to_owned(),
            device_id: DeviceId::new(BOB_DEVICE.to_owned()).unwrap(),
        };
        let key_bob_self = derive_frame_key(&bob_per_sender.exporter, &bob_self_ctx).unwrap();
        let alice_per_sender =
            PerSenderFrameKeys::new(alice_exporter, realm_id, call_id, focus_id, epoch);
        let key_bob_recomputed_by_alice = alice_per_sender
            .derive_remote_key(BOB_IDENTITY, BOB_DEVICE)
            .unwrap();
        assert_eq!(key_bob_self, key_bob_recomputed_by_alice);

        // Sender binding holds: Alice's and Bob's keys differ (distinct context).
        assert_ne!(
            key_alice_self, key_bob_self,
            "distinct senders MUST get distinct keys (§8.1 sender-bound)"
        );

        // Fail-closed: an unresolved/garbage remote device_id MUST error, not
        // fabricate a key.
        assert!(
            alice_per_sender
                .derive_remote_key(BOB_IDENTITY, "not-a-device-id")
                .is_err(),
            "a malformed remote device_id MUST fail closed, not fabricate a key"
        );
    }
}
