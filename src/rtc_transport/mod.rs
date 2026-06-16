//! Cross-platform WebRTC transport for Cokret calls.
//!
//! Dioxus targets two platforms with completely different media stacks, so
//! the transport is `cfg`-split behind a single [`MediaTransport`] trait:
//!
//! - **wasm (`target_arch = "wasm32"`)** — [`web::WebRtcTransport`] drives the browser's native
//!   `RtcPeerConnection` / `getUserMedia` / `getDisplayMedia` via `web-sys`. This is the real media
//!   path for the web build: it captures local tracks, performs SDP offer/answer, and exchanges ICE
//!   candidates. SFU rooms connect to the verified `connect_url` with the backend token.
//! - **native (`not(target_arch = "wasm32")`)** — [`native::NativeRtcTransport`] reuses the web
//!   media path: Dioxus desktop is native Rust hosting a `wry` webview, so the **SFU / conference
//!   path** drives the genuine `livekit-client` SDK inside that webview over a long-lived Dioxus
//!   `document::eval` bridge ([`assets/livekit_desktop_driver.js`]) — real `room.connect`, real MLS
//!   E2EE key injection, real publish, and the real `RoomEvent.ParticipantConnected` stream pushed
//!   back to native for the MEDIA-2 cross-check. Desktop ships without a bundled libwebrtc, so the
//!   1:1 P2P path (raw `RtcPeerConnection`) is still honestly not-ready and fails closed with
//!   [`crate::media::rtc::RtcClientError::DesktopMediaUnavailable`]; the call surface maps that to
//!   the "desktop calling is not ready yet" toast for P2P only. The SFU path never fabricates a
//!   session: a rejected `room.connect` keeps the state out of [`TransportState::Connected`].
//!
//! The SFrame keyprovider seed is ALWAYS the MLS-exporter-derived key from
//! [`crate::media::rtc::join_call_media`]; [`MediaTransport::install_frame_key`]
//! refuses any key whose provenance is not that derivation (MEDIA-1).

use std::collections::{BTreeMap, BTreeSet};
use std::rc::Rc;

use crate::media::rtc::{JoinedMediaSession, PerSenderFrameKeys, RtcClientError};

#[cfg(target_arch = "wasm32")]
pub mod livekit_shim;
#[cfg(not(target_arch = "wasm32"))]
pub mod native;
#[cfg(target_arch = "wasm32")]
pub mod web;

/// Direction of a local media track relative to the peer/SFU.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TrackKind {
    Audio,
    Video,
    Screen,
}

/// A remote participant the transport has observed connecting. The
/// `identity` is the SFU-local participant identity; before a remote is
/// surfaced to the UI it MUST be cross-checked against
/// `ck.call.state.participants[]` (MEDIA-2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RemoteParticipant {
    pub identity: String,
    pub audio_active: bool,
    pub video_active: bool,
    pub screen_active: bool,
}

/// One SDP / ICE signaling frame produced by the transport that the call
/// controller must relay to the peer over the `ck.call.signal` ephemeral
/// channel (1:1 P2P path).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LocalSignal {
    Offer {
        sdp: String,
    },
    Answer {
        sdp: String,
    },
    Candidate {
        candidate: String,
        sdp_mid: Option<String>,
        sdp_m_line_index: Option<u32>,
    },
}

/// Connection lifecycle of the transport, mirrored into the call FSM.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransportState {
    Idle,
    Connecting,
    Connected,
    Failed,
    Closed,
}

/// Local capture / publish state the transport maintains.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LocalMediaState {
    pub audio_captured: bool,
    pub video_captured: bool,
    pub screen_captured: bool,
    pub audio_muted: bool,
    pub video_muted: bool,
}

/// The platform-agnostic transport surface the call controller drives.
///
/// Implementations are NOT `Send`/`Sync`: the wasm backend holds
/// `RtcPeerConnection` JS handles that are single-threaded, and Dioxus
/// drives everything on one task per platform. Callers keep the transport
/// in a `Rc`/component-local signal, never across threads.
pub trait MediaTransport {
    /// Capture local microphone / camera per the joined session's
    /// `desired_media`. Returns the resulting capture state.
    fn start_local_capture(&mut self) -> Result<LocalMediaState, RtcClientError>;

    /// Toggle the local audio publish (mute / unmute). Returns the new
    /// muted flag.
    fn set_audio_muted(&mut self, muted: bool) -> Result<bool, RtcClientError>;

    /// Toggle the local video publish.
    fn set_video_muted(&mut self, muted: bool) -> Result<bool, RtcClientError>;

    /// Start / stop screen-share capture (`getDisplayMedia`). Returns the
    /// new screen-capture flag.
    fn set_screen_share(&mut self, enabled: bool) -> Result<bool, RtcClientError>;

    /// Install the local sender's MLS-exporter-derived SFrame frame key into
    /// the transport's E2EE keyprovider, bound to the local
    /// `participant_identity` (`media-service-binding.md` §8.1: the frame key is
    /// sender-bound, so it is installed under the sender's own identity, never a
    /// room-wide slot). MUST reject any 0-length / non-32-byte key (the only
    /// valid source is [`crate::media::rtc::join_call_media`]). Failing to
    /// install MUST fail closed — the call MUST NOT reach `Connected`.
    fn install_frame_key(
        &mut self,
        participant_identity: &str,
        key: &[u8],
    ) -> Result<(), RtcClientError>;

    /// Provide the per-sender remote frame-key deriver plus the
    /// `participant_identity → device_id` map read from the verified
    /// `ck.call.state.participants[]` roster. When a remote sender connects, the
    /// transport derives that sender's frame key (same MLS group exporter, same
    /// epoch, the remote's own `(participant_identity, device_id)` context) and
    /// installs it under the remote's identity — which is the only way the
    /// receiver can decrypt that sender's frames. Default no-op: the 1:1 P2P
    /// path has a single shared peer and does not use SFU per-sender keys.
    fn set_remote_key_source(
        &mut self,
        _keys: Rc<PerSenderFrameKeys>,
        _identity_to_device: BTreeMap<String, String>,
    ) {
    }

    /// Seed the expected `ck.call.state.participants[]` SFU-local identity
    /// set BEFORE [`Self::connect_sfu`], so the SFU's asynchronous
    /// `ParticipantConnected` events (delivered by the LiveKit SDK on the web
    /// backend) can be cross-checked fail-closed (MEDIA-2) against the durable
    /// roster without a synchronous controller round-trip. Default is a no-op:
    /// the native backend has no SFU path, and the 1:1 P2P path does not use
    /// SFU participant events.
    fn set_expected_participants(&mut self, _expected: &BTreeSet<String>) {}

    /// Connect to the SFU room described by the joined session (group
    /// calls). Drives state to [`TransportState::Connecting`].
    fn connect_sfu(&mut self, session: &JoinedMediaSession) -> Result<(), RtcClientError>;

    /// Cross-check an SFU `ParticipantConnected` identity against the
    /// durable `ck.call.state.participants[]` set, and on success register
    /// the remote. Fail-closed on an unrecognised identity (MEDIA-2).
    fn on_participant_connected(
        &mut self,
        identity: &str,
        expected: &BTreeSet<String>,
    ) -> Result<(), RtcClientError>;

    /// Current connection state.
    fn state(&self) -> TransportState;

    /// Current remote roster (cross-checked participants only).
    fn remotes(&self) -> Vec<RemoteParticipant>;

    /// Tear down all peer connections / room sessions and release local
    /// media.
    fn close(&mut self);

    // ── 1:1 P2P path ────────────────────────────────────────────────
    //
    // SDP creation in the browser is promise-based, so offer/answer
    // generation is kicked off here and the resulting description is
    // delivered asynchronously through [`MediaTransport::drain_local_signals`]
    // alongside gathered ICE candidates. Both backends use the same model
    // so the call controller's relay loop is platform-agnostic.

    /// Begin creating the SDP offer for a 1:1 call. The offer (and any
    /// gathered candidates) surface via [`Self::drain_local_signals`].
    fn begin_offer(&mut self) -> Result<(), RtcClientError>;

    /// Apply the peer's SDP offer and begin producing the answer. The
    /// answer surfaces via [`Self::drain_local_signals`].
    fn accept_offer(&mut self, sdp: &str) -> Result<(), RtcClientError>;

    /// Apply the peer's SDP answer to a previously created offer.
    fn accept_answer(&mut self, sdp: &str) -> Result<(), RtcClientError>;

    /// Apply a remote ICE candidate.
    fn add_remote_candidate(
        &mut self,
        candidate: &str,
        sdp_mid: Option<&str>,
        sdp_m_line_index: Option<u32>,
    ) -> Result<(), RtcClientError>;

    /// Drain locally-produced signaling (SDP offer/answer + gathered ICE
    /// candidates) that the controller must relay to the peer over
    /// `ck.call.signal`. Returns an empty vec when nothing is pending.
    fn drain_local_signals(&mut self) -> Vec<LocalSignal>;
}

/// Construct the platform transport. Web build returns the `web-sys`
/// backend; native build returns the desktop backend.
pub fn new_transport(session: &JoinedMediaSession) -> Box<dyn MediaTransport> {
    #[cfg(target_arch = "wasm32")]
    {
        Box::new(web::WebRtcTransport::new(session))
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        Box::new(native::NativeRtcTransport::new(session))
    }
}

/// SFrame frame-key guard: the key MUST be exactly the 32-byte
/// MLS-exporter output. Anything else is rejected with
/// `e2ee_key_source_unauthorised`. Used by the wasm (web) backend, which is
/// the only target with a real media transport this milestone; the native
/// backend is honestly not-ready and never installs a key, so this is
/// unused outside tests there.
#[cfg_attr(all(not(target_arch = "wasm32"), not(test)), allow(dead_code))]
pub(crate) fn ensure_valid_frame_key(key: &[u8]) -> Result<(), RtcClientError> {
    if key.len() == cokret_sdk::MEDIA_KEY_LEN {
        Ok(())
    } else {
        Err(RtcClientError::E2eeKeySourceUnauthorised)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_key_guard_requires_32_bytes() {
        assert!(ensure_valid_frame_key(&[0u8; 32]).is_ok());
        assert_eq!(
            ensure_valid_frame_key(&[0u8; 16]).unwrap_err(),
            RtcClientError::E2eeKeySourceUnauthorised
        );
        assert!(ensure_valid_frame_key(&[]).is_err());
    }

    #[test]
    fn local_media_state_default_is_uncaptured() {
        let state = LocalMediaState::default();
        assert!(!state.audio_captured);
        assert!(!state.video_captured);
        assert!(!state.audio_muted);
    }
}
