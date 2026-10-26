//! Desktop SFU media runs the genuine bundled LiveKit SDK in a dedicated Wry process.
//! The Glory window owns its private pipe, task, and bounded shutdown. Verified roster
//! identities and sender-bound MLS exporter keys remain enforced in this transport.
//! Desktop P2P remains unavailable because no native RtcPeerConnection is linked.
use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::rc::Rc;

use zeroize::Zeroize;

use super::native_host::{DriverCommand, DriverConfig, DriverEvent, MediaHost, MediaKind};
use super::{
    LocalMediaState, LocalSignal, MediaTransport, RemoteParticipant, TransportState,
    ensure_valid_frame_key,
};
use crate::media::rtc::{
    JoinedMediaSession, PerSenderFrameKeys, RtcClientError, cross_check_participant_id,
};

/// One call owns one isolated media process.
pub struct NativeRtcTransport {
    desired_audio: bool,
    desired_video: bool,
    desired_screen: bool,
    connect_url: String,
    backend_token: String,
    frame_key: Vec<u8>,
    frame_key_installed: bool,
    /// Local sender's SFU participant identity, bound into the local frame-key
    /// install (`media-service-binding.md` §8.1: keys are sender-bound).
    local_identity: String,
    /// Per-sender remote frame-key deriver (retains the live MLS exporter) plus
    /// the `participant_id → device_id` map from the verified
    /// `ak.component.call.roster.v1` effective OR-Set. Moved into the driver event loop
    /// so each remote sender's recomputed key is injected into the webview
    /// LiveKit provider under the remote identity.
    remote_keys: Option<Rc<PerSenderFrameKeys>>,
    identity_to_device: BTreeMap<String, String>,
    local: LocalMediaState,
    state: Rc<RefCell<TransportState>>,
    remotes: Rc<RefCell<Vec<RemoteParticipant>>>,
    /// Expected effective call-roster SFU-local identities, seeded by
    /// the controller before `connect_sfu` and read inside the event loop for
    /// the MEDIA-2 cross-check.
    expected_participants: Rc<RefCell<BTreeSet<String>>>,
    bridge: Option<Rc<MediaHost>>,
}

impl NativeRtcTransport {
    pub fn new(session: &JoinedMediaSession) -> Self {
        Self {
            desired_audio: session.desired_media.audio,
            desired_video: session.desired_media.video,
            desired_screen: session.desired_media.screen,
            connect_url: session.connect_url.clone(),
            backend_token: session.backend_token.clone(),
            frame_key: Vec::new(),
            frame_key_installed: false,
            local_identity: session.participant_id.clone(),
            remote_keys: None,
            identity_to_device: BTreeMap::new(),
            local: LocalMediaState::default(),
            state: Rc::new(RefCell::new(TransportState::Idle)),
            remotes: Rc::new(RefCell::new(Vec::new())),
            expected_participants: Rc::new(RefCell::new(BTreeSet::new())),
            bridge: None,
        }
    }

    fn ensure_frame_key(&self) -> Result<(), RtcClientError> {
        if self.frame_key_installed {
            Ok(())
        } else {
            Err(RtcClientError::E2eeKeySourceUnauthorised)
        }
    }

    fn drive_sfu_mute(&self, kind: MediaKind, muted: bool) -> Result<bool, RtcClientError> {
        let Some(bridge) = self.bridge.as_ref() else {
            return Ok(false);
        };
        bridge
            .send(DriverCommand::SetMuted { kind, muted })
            .map_err(|_| RtcClientError::FocusUnavailableForClient)?;
        Ok(true)
    }
}

impl MediaTransport for NativeRtcTransport {
    fn start_local_capture(&mut self) -> Result<LocalMediaState, RtcClientError> {
        // On desktop the actual mic/cam capture is performed by the
        // livekit-client SDK inside the webview when `connect_sfu` publishes;
        // there is no separate native capture step. Record the desired capture
        // intent so the FSM/UI reflects it, mirroring the web backend.
        self.local.audio_captured = self.desired_audio;
        self.local.video_captured = self.desired_video;
        Ok(self.local)
    }

    fn set_audio_muted(&mut self, muted: bool) -> Result<bool, RtcClientError> {
        if self.drive_sfu_mute(MediaKind::Audio, muted)? {
            self.local.audio_muted = muted;
            return Ok(muted);
        }
        // No SFU bridge: the 1:1 P2P path is not driven on desktop.
        Err(RtcClientError::DesktopMediaUnavailable)
    }

    fn set_video_muted(&mut self, muted: bool) -> Result<bool, RtcClientError> {
        if self.drive_sfu_mute(MediaKind::Video, muted)? {
            self.local.video_muted = muted;
            return Ok(muted);
        }
        Err(RtcClientError::DesktopMediaUnavailable)
    }

    fn set_screen_share(&mut self, enabled: bool) -> Result<bool, RtcClientError> {
        let Some(bridge) = self.bridge.as_ref() else {
            return Err(RtcClientError::DesktopMediaUnavailable);
        };
        bridge
            .send(DriverCommand::SetScreen { enabled })
            .map_err(|_| RtcClientError::FocusUnavailableForClient)?;
        self.desired_screen = enabled;
        self.local.screen_captured = enabled;
        Ok(enabled)
    }

    fn install_frame_key(
        &mut self,
        participant_id: &str,
        key: &[u8],
    ) -> Result<(), RtcClientError> {
        ensure_valid_frame_key(key)?;
        if let Some(bridge) = &self.bridge {
            bridge
                .send(DriverCommand::SetE2eeKey {
                    identity: participant_id.to_owned(),
                    key: key.to_vec(),
                    key_index: 0,
                })
                .map_err(|_| RtcClientError::FocusUnavailableForClient)?;
        }
        // Retain the verified 32-byte MLS-exporter key and the local sender
        // identity it is bound to so `connect_sfu` can inject it into the
        // LiveKit ExternalE2EEKeyProvider under that identity in the webview.
        self.frame_key = key.to_vec();
        if !participant_id.trim().is_empty() {
            self.local_identity = participant_id.to_owned();
        }
        self.frame_key_installed = true;
        Ok(())
    }

    fn set_remote_key_source(
        &mut self,
        keys: Rc<PerSenderFrameKeys>,
        identity_to_device: BTreeMap<String, String>,
    ) {
        self.remote_keys = Some(keys);
        self.identity_to_device = identity_to_device;
    }

    fn set_expected_participants(&mut self, expected: &BTreeSet<String>) {
        *self.expected_participants.borrow_mut() = expected.clone();
    }

    fn connect_sfu(&mut self, session: &JoinedMediaSession) -> Result<(), RtcClientError> {
        self.ensure_frame_key()?;
        if session.connect_url.trim().is_empty() || session.backend_token.trim().is_empty() {
            return Err(RtcClientError::FocusUnavailableForClient);
        }
        self.connect_url = session.connect_url.clone();
        self.backend_token = session.backend_token.clone();

        let owner = crate::presentation::current_context()
            .and_then(|context| context.state_scope())
            .ok_or(RtcClientError::FocusUnavailableForClient)?;
        let (bridge, mut receiver) = MediaHost::launch(DriverConfig {
            connect_url: session.connect_url.clone(),
            backend_token: session.backend_token.clone(),
            audio: self.desired_audio,
            video: self.desired_video,
            frame_key: self.frame_key.clone(),
            local_identity: self.local_identity.clone(),
        })
        .map_err(|_| RtcClientError::FocusUnavailableForClient)?;
        let bridge = Rc::new(bridge);
        self.bridge = Some(bridge.clone());
        *self.state.borrow_mut() = TransportState::Connecting;
        let state = self.state.clone();
        let remotes = self.remotes.clone();
        let expected = self.expected_participants.clone();
        let remote_keys = self.remote_keys.clone();
        let identity_to_device = self.identity_to_device.clone();
        owner
            .spawn(async move {
                while let Some(event) = receiver.recv().await {
                    if *state.borrow() == TransportState::Closed {
                        let _ = bridge.send(DriverCommand::Leave);
                        return;
                    }
                    match event {
                        DriverEvent::Ready => {}
                        DriverEvent::Connected => *state.borrow_mut() = TransportState::Connected,
                        DriverEvent::Participant { identity } => {
                            if cross_check_participant_id(&identity, &expected.borrow()).is_err() {
                                continue;
                            }
                            if let Some(keys) = remote_keys.as_ref()
                                && let Some(device) = identity_to_device.get(&identity)
                                && let Ok(key) = keys.derive_remote_key(&identity, device)
                                && bridge
                                    .send(DriverCommand::SetE2eeKey {
                                        identity: identity.clone(),
                                        key: key.to_vec(),
                                        key_index: 0,
                                    })
                                    .is_err()
                            {
                                *state.borrow_mut() = TransportState::Failed;
                                break;
                            }
                            let mut roster = remotes.borrow_mut();
                            if !roster.iter().any(|remote| remote.identity == identity) {
                                roster.push(RemoteParticipant {
                                    identity,
                                    audio_active: true,
                                    video_active: false,
                                    screen_active: false,
                                });
                            }
                        }
                        DriverEvent::Failed { .. } => {
                            let mut current = state.borrow_mut();
                            if *current != TransportState::Connected {
                                *current = TransportState::Failed;
                            }
                        }
                        DriverEvent::Left => {
                            *state.borrow_mut() = TransportState::Closed;
                            return;
                        }
                    }
                }
                if *state.borrow() != TransportState::Closed {
                    *state.borrow_mut() = TransportState::Failed;
                }
            })
            .map_err(|_| RtcClientError::FocusUnavailableForClient)?;

        Ok(())
    }

    fn on_participant_connected(
        &mut self,
        identity: &str,
        expected: &BTreeSet<String>,
    ) -> Result<(), RtcClientError> {
        cross_check_participant_id(identity, expected)?;
        let mut roster = self.remotes.borrow_mut();
        if !roster.iter().any(|r| r.identity == identity) {
            roster.push(RemoteParticipant {
                identity: identity.to_owned(),
                audio_active: true,
                video_active: false,
                screen_active: false,
            });
        }
        drop(roster);
        Ok(())
    }

    fn state(&self) -> TransportState {
        *self.state.borrow()
    }

    fn remotes(&self) -> Vec<RemoteParticipant> {
        self.remotes.borrow().clone()
    }

    fn close(&mut self) {
        // Ask the webview driver to disconnect the real room, then drop the
        // bridge so its event loop ends.
        if let Some(bridge) = self.bridge.take() {
            bridge.shutdown();
        }
        self.remotes.borrow_mut().clear();
        self.local = LocalMediaState::default();
        self.frame_key.zeroize();
        self.backend_token.zeroize();
        self.frame_key_installed = false;
        *self.state.borrow_mut() = TransportState::Closed;
    }

    fn begin_offer(&mut self) -> Result<(), RtcClientError> {
        // 1:1 P2P uses a raw RtcPeerConnection (web-sys), not linked on native.
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
        // The SFU path runs entirely inside the webview driver (LiveKit owns
        // its own signaling); no SDP/ICE is relayed by the controller. The
        // 1:1 P2P path is not driven on desktop, so no synthetic signaling is
        // ever produced.
        Vec::new()
    }
}

impl Drop for NativeRtcTransport {
    fn drop(&mut self) {
        self.close();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::media::rtc::DesiredMedia;

    fn session() -> JoinedMediaSession {
        let participant_binding = arkret_sdk::CallMediaParticipantBinding {
            signature: "signature".to_owned(),
            issuer_kid: arkret_sdk::DidUrl::new("did:web:media.example#key-1").unwrap(),
            expires_at: chrono::DateTime::parse_from_rfc3339("2026-04-26T00:05:00.000Z")
                .unwrap()
                .with_timezone(&chrono::Utc),
        };
        JoinedMediaSession {
            backend_kind: "livekit".to_owned(),
            focus_id: "fra-1".to_owned(),
            connect_url: "wss://livekit.example".to_owned(),
            backend_token: "jwt".to_owned(),
            participant_id: "ak:rtc_participant:self".to_owned(),
            participant_binding,
            device_id: "ak:device:01904100-0000-7000-8000-000000000005".to_owned(),
            actor_id: ice_config().actor_id,
            ice_config: ice_config(),
            frame_key: zeroize::Zeroizing::new(vec![7u8; 32]),
            desired_media: DesiredMedia::audio_video(),
            realm_id: "ak:realm:AVxu7KCm9qmiOqakDKBXUia9rbZ3NBurP875XbqG1rbs".to_owned(),
            call_id: "ak:call:AYf05kF8z4cSo8r6qmqXgu4KPuv2YtKBlsE00FOmblaz".to_owned(),
            epoch_id: 0,
        }
    }

    fn ice_config() -> arkret_sdk::IceConfig {
        arkret_sdk::IceConfig {
            realm_id: arkret_sdk::RealmId::new(
                "ak:realm:AVxu7KCm9qmiOqakDKBXUia9rbZ3NBurP875XbqG1rbs",
            )
            .unwrap(),
            call_id: "ak:call:AYf05kF8z4cSo8r6qmqXgu4KPuv2YtKBlsE00FOmblaz".to_owned(),
            actor_id: crate::mls_api_helpers::local_account_actor_id("did:web:alice.example")
                .unwrap(),
            ice_servers: Vec::new(),
            ttl_seconds: 300,
            refresh_lead_seconds: 60,
            turn_required: false,
            issuer_did: arkret_sdk::Did::new("did:web:media.example").unwrap(),
        }
    }

    #[test]
    fn starts_idle_before_connect() {
        let session = session();
        let t = NativeRtcTransport::new(&session);
        // The transport does not fabricate a session before connect_sfu runs.
        assert_eq!(t.state(), TransportState::Idle);
        assert!(t.remotes().is_empty());
    }

    #[test]
    fn frame_key_guard_rejects_short_key() {
        let session = session();
        let mut t = NativeRtcTransport::new(&session);
        assert_eq!(
            t.install_frame_key("ak:rtc_participant:self", &[0u8; 16])
                .unwrap_err(),
            RtcClientError::E2eeKeySourceUnauthorised
        );
        assert!(
            t.install_frame_key("ak:rtc_participant:self", &[0u8; 32])
                .is_ok()
        );
    }

    #[test]
    fn connect_sfu_requires_installed_frame_key() {
        let session = session();
        let mut t = NativeRtcTransport::new(&session);
        // Without install_frame_key the E2EE provenance gate fails closed.
        assert_eq!(
            t.connect_sfu(&session).unwrap_err(),
            RtcClientError::E2eeKeySourceUnauthorised
        );
    }

    #[test]
    fn p2p_methods_fail_closed_on_desktop() {
        let session = session();
        let mut t = NativeRtcTransport::new(&session);
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
        // No synthetic signaling is ever emitted.
        assert!(t.drain_local_signals().is_empty());
    }

    #[test]
    fn on_participant_connected_cross_checks_roster() {
        let session = session();
        let mut t = NativeRtcTransport::new(&session);
        let mut expected = BTreeSet::new();
        expected.insert("ak:rtc_participant:bob".to_owned());
        // Unknown identity is rejected (MEDIA-2).
        assert!(
            t.on_participant_connected("ak:rtc_participant:mallory", &expected)
                .is_err()
        );
        assert!(t.remotes().is_empty());
        // Known identity is surfaced.
        assert!(
            t.on_participant_connected("ak:rtc_participant:bob", &expected)
                .is_ok()
        );
        assert_eq!(t.remotes().len(), 1);
    }
}
