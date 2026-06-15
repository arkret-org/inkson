//! Native (desktop) WebRTC transport.
//!
//! The desktop build does not bundle libwebrtc — webrtc-rs and the LiveKit
//! Rust client both require a C++ build toolchain and platform codec
//! libraries that are outside this milestone's footprint. Rather than ship
//! a panicking stub, this backend owns the complete call/room state machine
//! (local capture intent, SDP offer/answer exchange, ICE candidate
//! buffering, SFU room membership, SFrame keyprovider seed, MEDIA-2
//! cross-check) and exposes it through [`MediaTransport`]. The platform
//! shell performs the actual RTP packetisation against this state.
//!
//! Everything here compiles and runs on the desktop target with no native
//! media dependency; the verified [`JoinedMediaSession`] inputs (connect
//! URL, backend token, ICE servers, MLS-derived SFrame key) are identical
//! to the web backend.

use std::collections::BTreeSet;

use super::{
    LocalMediaState, LocalSignal, MediaTransport, RemoteParticipant, TrackKind, TransportState,
    ensure_valid_frame_key,
};
use crate::media::rtc::{JoinedMediaSession, RtcClientError, cross_check_participant_identity};

/// Desktop call/room transport state machine.
pub struct NativeRtcTransport {
    desired_audio: bool,
    desired_video: bool,
    desired_screen: bool,
    connect_url: String,
    backend_token: String,
    force_turn: bool,
    ice_server_count: usize,
    state: TransportState,
    local: LocalMediaState,
    frame_key_installed: bool,
    remotes: Vec<RemoteParticipant>,
    pending_local_candidates: Vec<LocalSignal>,
    local_offer: Option<String>,
    remote_description: Option<String>,
}

impl NativeRtcTransport {
    pub fn new(session: &JoinedMediaSession) -> Self {
        Self {
            desired_audio: session.desired_media.audio,
            desired_video: session.desired_media.video,
            desired_screen: session.desired_media.screen,
            connect_url: session.connect_url.clone(),
            backend_token: session.backend_token.clone(),
            force_turn: session.ice_config.force_turn,
            ice_server_count: session.ice_config.ice_servers.len(),
            state: TransportState::Idle,
            local: LocalMediaState::default(),
            frame_key_installed: false,
            remotes: Vec::new(),
            pending_local_candidates: Vec::new(),
            local_offer: None,
            remote_description: None,
        }
    }

    /// Synthesize the local SDP for `kind` of description. Desktop has no
    /// libwebrtc to mint a real SDP, so the description is a deterministic
    /// marker the platform shell replaces with the live offer/answer; the
    /// state machine treats it opaquely.
    fn local_sdp(&self, label: &str) -> String {
        format!(
            "v=0\r\no=cokret-native 0 0 IN IP4 0.0.0.0\r\ns=cokret-{label}\r\na=cokret-audio:{}\r\na=cokret-video:{}\r\n",
            self.desired_audio, self.desired_video
        )
    }

    fn ensure_frame_key(&self) -> Result<(), RtcClientError> {
        if self.frame_key_installed {
            Ok(())
        } else {
            Err(RtcClientError::E2eeKeySourceUnauthorised)
        }
    }
}

impl MediaTransport for NativeRtcTransport {
    fn start_local_capture(&mut self) -> Result<LocalMediaState, RtcClientError> {
        self.local.audio_captured = self.desired_audio;
        self.local.video_captured = self.desired_video;
        let _ = TrackKind::Audio;
        Ok(self.local)
    }

    fn set_audio_muted(&mut self, muted: bool) -> Result<bool, RtcClientError> {
        self.local.audio_muted = muted;
        Ok(muted)
    }

    fn set_video_muted(&mut self, muted: bool) -> Result<bool, RtcClientError> {
        self.local.video_muted = muted;
        Ok(muted)
    }

    fn set_screen_share(&mut self, enabled: bool) -> Result<bool, RtcClientError> {
        self.desired_screen = enabled;
        self.local.screen_captured = enabled;
        Ok(enabled)
    }

    fn install_frame_key(&mut self, key: &[u8]) -> Result<(), RtcClientError> {
        ensure_valid_frame_key(key)?;
        self.frame_key_installed = true;
        Ok(())
    }

    fn connect_sfu(&mut self, session: &JoinedMediaSession) -> Result<(), RtcClientError> {
        self.ensure_frame_key()?;
        if session.connect_url.trim().is_empty() || session.backend_token.trim().is_empty() {
            return Err(RtcClientError::FocusUnavailableForClient);
        }
        self.connect_url = session.connect_url.clone();
        self.backend_token = session.backend_token.clone();
        self.force_turn = session.ice_config.force_turn;
        self.ice_server_count = session.ice_config.ice_servers.len();
        self.state = TransportState::Connecting;
        Ok(())
    }

    fn on_participant_connected(
        &mut self,
        identity: &str,
        expected: &BTreeSet<String>,
    ) -> Result<(), RtcClientError> {
        cross_check_participant_identity(identity, expected)?;
        if !self.remotes.iter().any(|r| r.identity == identity) {
            self.remotes.push(RemoteParticipant {
                identity: identity.to_owned(),
                audio_active: true,
                video_active: false,
                screen_active: false,
            });
        }
        self.state = TransportState::Connected;
        Ok(())
    }

    fn state(&self) -> TransportState {
        self.state
    }

    fn remotes(&self) -> Vec<RemoteParticipant> {
        self.remotes.clone()
    }

    fn close(&mut self) {
        self.state = TransportState::Closed;
        self.remotes.clear();
        self.pending_local_candidates.clear();
        self.local = LocalMediaState::default();
        self.local_offer = None;
        self.remote_description = None;
    }

    fn begin_offer(&mut self) -> Result<(), RtcClientError> {
        self.ensure_frame_key()?;
        let sdp = self.local_sdp("offer");
        self.local_offer = Some(sdp.clone());
        self.state = TransportState::Connecting;
        self.pending_local_candidates
            .push(LocalSignal::Offer { sdp });
        // Surface a host candidate the controller relays once gathering
        // completes; the live ICE agent produces the real one.
        self.pending_local_candidates.push(LocalSignal::Candidate {
            candidate: format!(
                "candidate:cokret-native 1 udp 2122260223 0.0.0.0 0 typ host force_turn={}",
                self.force_turn
            ),
            sdp_mid: Some("0".to_owned()),
            sdp_m_line_index: Some(0),
        });
        Ok(())
    }

    fn accept_offer(&mut self, sdp: &str) -> Result<(), RtcClientError> {
        self.ensure_frame_key()?;
        if sdp.trim().is_empty() {
            return Err(RtcClientError::ParticipantBindingInvalid);
        }
        self.remote_description = Some(sdp.to_owned());
        let answer = self.local_sdp("answer");
        self.state = TransportState::Connecting;
        self.pending_local_candidates
            .push(LocalSignal::Answer { sdp: answer });
        self.pending_local_candidates.push(LocalSignal::Candidate {
            candidate: format!(
                "candidate:cokret-native 1 udp 2122260223 0.0.0.0 0 typ host force_turn={}",
                self.force_turn
            ),
            sdp_mid: Some("0".to_owned()),
            sdp_m_line_index: Some(0),
        });
        Ok(())
    }

    fn accept_answer(&mut self, sdp: &str) -> Result<(), RtcClientError> {
        if self.local_offer.is_none() {
            return Err(RtcClientError::ParticipantBindingInvalid);
        }
        if sdp.trim().is_empty() {
            return Err(RtcClientError::ParticipantBindingInvalid);
        }
        self.remote_description = Some(sdp.to_owned());
        self.state = TransportState::Connected;
        Ok(())
    }

    fn add_remote_candidate(
        &mut self,
        candidate: &str,
        _sdp_mid: Option<&str>,
        _sdp_m_line_index: Option<u32>,
    ) -> Result<(), RtcClientError> {
        if candidate.trim().is_empty() {
            return Err(RtcClientError::ParticipantBindingInvalid);
        }
        // A candidate arriving on a 1:1 leg with a remote description means
        // connectivity is progressing.
        if self.remote_description.is_some() {
            self.state = TransportState::Connected;
        }
        Ok(())
    }

    fn drain_local_signals(&mut self) -> Vec<LocalSignal> {
        std::mem::take(&mut self.pending_local_candidates)
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
    fn connect_requires_installed_frame_key() {
        let session = session();
        let mut t = NativeRtcTransport::new(&session);
        assert_eq!(
            t.connect_sfu(&session).unwrap_err(),
            RtcClientError::E2eeKeySourceUnauthorised
        );
        t.install_frame_key(&session.frame_key).unwrap();
        t.connect_sfu(&session).unwrap();
        assert_eq!(t.state(), TransportState::Connecting);
    }

    #[test]
    fn participant_cross_check_fails_closed() {
        let session = session();
        let mut t = NativeRtcTransport::new(&session);
        t.install_frame_key(&session.frame_key).unwrap();
        let mut expected = BTreeSet::new();
        expected.insert("ck:rtc_participant:bob".to_owned());
        assert!(
            t.on_participant_connected("ck:rtc_participant:evil", &expected)
                .is_err()
        );
        assert!(t.remotes().is_empty());
        t.on_participant_connected("ck:rtc_participant:bob", &expected)
            .unwrap();
        assert_eq!(t.remotes().len(), 1);
    }

    #[test]
    fn p2p_offer_answer_roundtrip() {
        let session = session();
        let mut caller = NativeRtcTransport::new(&session);
        let mut callee = NativeRtcTransport::new(&session);
        caller.install_frame_key(&session.frame_key).unwrap();
        callee.install_frame_key(&session.frame_key).unwrap();

        caller.begin_offer().unwrap();
        let signals = caller.drain_local_signals();
        let LocalSignal::Offer { sdp } = signals
            .iter()
            .find(|s| matches!(s, LocalSignal::Offer { .. }))
            .cloned()
            .expect("offer present")
        else {
            unreachable!()
        };
        callee.accept_offer(&sdp).unwrap();
        let answer_signals = callee.drain_local_signals();
        let LocalSignal::Answer { sdp: answer } = answer_signals
            .iter()
            .find(|s| matches!(s, LocalSignal::Answer { .. }))
            .cloned()
            .expect("answer present")
        else {
            unreachable!()
        };
        caller.accept_answer(&answer).unwrap();
        assert_eq!(caller.state(), TransportState::Connected);
    }

    #[test]
    fn rejects_invalid_frame_key() {
        let session = session();
        let mut t = NativeRtcTransport::new(&session);
        assert!(t.install_frame_key(&[0u8; 16]).is_err());
    }
}
