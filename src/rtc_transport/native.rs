//! Native (desktop) WebRTC transport — honestly not-ready.
//!
//! The desktop build does not bundle libwebrtc: webrtc-rs and the LiveKit
//! Rust client both require a C++ build toolchain and platform codec
//! libraries that are outside this milestone's footprint. There is no RTP
//! path on desktop yet.
//!
//! This backend therefore does NOT fake a call. It owns no synthetic SDP, no
//! synthetic ICE candidates, and never advances its state to
//! [`TransportState::Connected`]. Every method that would drive a real media
//! session fails closed with [`RtcClientError::DesktopMediaUnavailable`], and
//! [`MediaTransport::state`] stays [`TransportState::Failed`] from
//! construction onward. The call surface maps the error to the
//! `error.call.desktop_media_unavailable` toast ("desktop calling is not
//! ready yet") and keeps the call FSM out of `Active`, so the UI never
//! pretends a connection succeeded.
//!
//! Read-only setters (`set_audio_muted`, etc.) are also refused: there is no
//! local capture to toggle. The verified [`JoinedMediaSession`] inputs
//! (connect URL, backend token, ICE servers, MLS-derived SFrame key) are
//! accepted by the constructor only so the cross-platform `new_transport`
//! signature stays uniform; none of them are used to mint media.

use std::collections::BTreeSet;

use super::{LocalMediaState, LocalSignal, MediaTransport, RemoteParticipant, TransportState};
use crate::media::rtc::{JoinedMediaSession, RtcClientError};

/// Desktop transport that honestly reports "no media transport available".
///
/// Holds no peer-connection / room state because there is none to hold: the
/// desktop build ships without a media stack this milestone.
pub struct NativeRtcTransport {
    _private: (),
}

impl NativeRtcTransport {
    pub fn new(_session: &JoinedMediaSession) -> Self {
        Self { _private: () }
    }
}

impl MediaTransport for NativeRtcTransport {
    fn start_local_capture(&mut self) -> Result<LocalMediaState, RtcClientError> {
        Err(RtcClientError::DesktopMediaUnavailable)
    }

    fn set_audio_muted(&mut self, _muted: bool) -> Result<bool, RtcClientError> {
        Err(RtcClientError::DesktopMediaUnavailable)
    }

    fn set_video_muted(&mut self, _muted: bool) -> Result<bool, RtcClientError> {
        Err(RtcClientError::DesktopMediaUnavailable)
    }

    fn set_screen_share(&mut self, _enabled: bool) -> Result<bool, RtcClientError> {
        Err(RtcClientError::DesktopMediaUnavailable)
    }

    fn install_frame_key(&mut self, _key: &[u8]) -> Result<(), RtcClientError> {
        Err(RtcClientError::DesktopMediaUnavailable)
    }

    fn connect_sfu(&mut self, _session: &JoinedMediaSession) -> Result<(), RtcClientError> {
        Err(RtcClientError::DesktopMediaUnavailable)
    }

    fn on_participant_connected(
        &mut self,
        _identity: &str,
        _expected: &BTreeSet<String>,
    ) -> Result<(), RtcClientError> {
        Err(RtcClientError::DesktopMediaUnavailable)
    }

    fn state(&self) -> TransportState {
        // Never `Connected`: desktop has no media path, so the FSM must not be
        // told a session is up.
        TransportState::Failed
    }

    fn remotes(&self) -> Vec<RemoteParticipant> {
        Vec::new()
    }

    fn close(&mut self) {}

    fn begin_offer(&mut self) -> Result<(), RtcClientError> {
        Err(RtcClientError::DesktopMediaUnavailable)
    }

    fn accept_offer(&mut self, _sdp: &str) -> Result<(), RtcClientError> {
        Err(RtcClientError::DesktopMediaUnavailable)
    }

    fn accept_answer(&mut self, _sdp: &str) -> Result<(), RtcClientError> {
        Err(RtcClientError::DesktopMediaUnavailable)
    }

    fn add_remote_candidate(
        &mut self,
        _candidate: &str,
        _sdp_mid: Option<&str>,
        _sdp_m_line_index: Option<u32>,
    ) -> Result<(), RtcClientError> {
        Err(RtcClientError::DesktopMediaUnavailable)
    }

    fn drain_local_signals(&mut self) -> Vec<LocalSignal> {
        // No synthetic SDP / candidates are ever produced on desktop.
        Vec::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::media::rtc::DesiredMedia;

    fn session() -> JoinedMediaSession {
        JoinedMediaSession {
            backend_type: "livekit".to_owned(),
            connect_url: "wss://livekit.example".to_owned(),
            backend_token: "jwt".to_owned(),
            participant_identity: "ck:rtc_participant:self".to_owned(),
            ice_config: ice_config(),
            frame_key: vec![7u8; 32],
            desired_media: DesiredMedia::audio_video(),
        }
    }

    fn ice_config() -> cokret_sdk::IceConfig {
        cokret_sdk::IceConfig {
            realm_id: cokret_sdk::RealmId::new("ck:realm:01904100-0000-7000-8000-9b64700c6ee8")
                .unwrap(),
            call_id: "ck:call:0196441c-0000-7000-8000-000000000000".to_owned(),
            actor_id: cokret_sdk::Did::new("did:web:alice.example").unwrap(),
            ice_servers: Vec::new(),
            ttl_seconds: 300,
            refresh_lead_seconds: 60,
            force_turn: false,
            issuer_did: cokret_sdk::Did::new("did:web:media.example").unwrap(),
        }
    }

    #[test]
    fn desktop_transport_is_never_connected() {
        let session = session();
        let t = NativeRtcTransport::new(&session);
        // Honest not-ready: the FSM is never told a session is up.
        assert_eq!(t.state(), TransportState::Failed);
        assert!(t.remotes().is_empty());
    }

    #[test]
    fn every_drive_method_fails_closed_desktop_unavailable() {
        let session = session();
        let mut t = NativeRtcTransport::new(&session);
        assert_eq!(
            t.start_local_capture().unwrap_err(),
            RtcClientError::DesktopMediaUnavailable
        );
        assert_eq!(
            t.install_frame_key(&session.frame_key).unwrap_err(),
            RtcClientError::DesktopMediaUnavailable
        );
        assert_eq!(
            t.connect_sfu(&session).unwrap_err(),
            RtcClientError::DesktopMediaUnavailable
        );
        assert_eq!(
            t.begin_offer().unwrap_err(),
            RtcClientError::DesktopMediaUnavailable
        );
        assert_eq!(
            t.accept_offer("v=0").unwrap_err(),
            RtcClientError::DesktopMediaUnavailable
        );
        assert_eq!(
            t.accept_answer("v=0").unwrap_err(),
            RtcClientError::DesktopMediaUnavailable
        );
        let expected = BTreeSet::new();
        assert_eq!(
            t.on_participant_connected("ck:rtc_participant:bob", &expected)
                .unwrap_err(),
            RtcClientError::DesktopMediaUnavailable
        );
        // No synthetic signaling is ever emitted.
        assert!(t.drain_local_signals().is_empty());
        // State remains Failed, never Connected.
        assert_eq!(t.state(), TransportState::Failed);
    }
}
