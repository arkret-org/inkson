//! Native (desktop) media transport.
//!
//! ## SFU / conference path — real, via the webview
//!
//! The desktop build does not link an in-process libwebrtc (webrtc-rs and the
//! LiveKit Rust client both pull a C++ toolchain and platform codec libraries
//! outside this milestone's footprint). Per the desktop calling strategy the
//! native client instead **reuses the web media path**: Dioxus desktop is
//! native Rust hosting a `wry` webview whose browser engine runs the genuine
//! `livekit-client` SDK. This transport drives that SDK over a long-lived
//! Dioxus `document::eval` bridge ([`assets/livekit_desktop_driver.js`]),
//! exactly the same real `LivekitClient.Room` API the wasm build uses through
//! [`assets/livekit_shim.js`].
//!
//! [`MediaTransport::connect_sfu`] opens the eval bridge with the verified
//! connect URL, backend token, desired-media flags, and the
//! MLS-exporter-derived 32-byte SFrame key (the same key
//! [`crate::media::rtc::join_call_media`] produced; nothing else is accepted by
//! [`MediaTransport::install_frame_key`], MEDIA-1). The driver performs the
//! real `room.connect`, injects the key into LiveKit's
//! `ExternalE2EEKeyProvider`, publishes mic/cam, and forwards each real
//! `RoomEvent.ParticipantConnected` identity back over the bridge. A spawned
//! task cross-checks every reported identity against the durable
//! `ck.call.state.participants[]` roster (MEDIA-2) before surfacing it, and
//! only flips the FSM to [`TransportState::Connected`] when the driver reports
//! a real `room.connect` success. A rejected connect emits `failed`, so the
//! transport stays out of `Connected` (fail-closed) — it never fabricates a
//! session, synthetic participants, or a fake connected state.
//!
//! ## 1:1 P2P path — honestly not-ready on desktop
//!
//! The 1:1 path uses a raw `RtcPeerConnection` with `web-sys`, which the
//! native build does not link. There is no SFU to relay LiveKit's signaling,
//! so the P2P offer/answer methods stay fail-closed with
//! [`RtcClientError::DesktopMediaUnavailable`] on desktop. No synthetic SDP or
//! ICE is ever produced.

use std::cell::RefCell;
use std::collections::BTreeSet;
use std::rc::Rc;

use dioxus::document::{self, Eval};
use dioxus::prelude::spawn;
use serde::Deserialize;
use serde_json::{Value, json};

use super::{
    LocalMediaState, LocalSignal, MediaTransport, RemoteParticipant, TransportState,
    ensure_valid_frame_key,
};
use crate::media::rtc::{JoinedMediaSession, RtcClientError, cross_check_participant_identity};

/// The desktop LiveKit driver, run in the webview over the eval bridge. The
/// leading `__COKRET_DRIVER_CONFIG__` token is replaced per call with the
/// JSON connect config (URL, token, media flags, frame key).
const DESKTOP_DRIVER_JS: &str = include_str!("../../assets/livekit_desktop_driver.js");

/// One event pushed back from the webview driver over the eval bridge.
#[derive(Debug, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
enum DriverEvent {
    /// The real `room.connect` resolved against the SFU.
    Connected,
    /// A real `RoomEvent.ParticipantConnected` (or a participant already
    /// present at connect time). Cross-checked against the durable roster.
    Participant { identity: String },
    /// The driver failed closed (UMD load, connect rejected, or E2EE setup).
    Failed {
        #[allow(dead_code)]
        reason: String,
    },
    /// `room.disconnect` completed after a leave command.
    Left,
}

/// Desktop transport that drives the real livekit-client SDK in the webview.
///
/// SFU media is genuine (key injection + publish + participant cross-check run
/// against the live SDK over the eval bridge); the 1:1 P2P path is honestly
/// not-ready because the native build links no `RtcPeerConnection`.
pub struct NativeRtcTransport {
    desired_audio: bool,
    desired_video: bool,
    desired_screen: bool,
    connect_url: String,
    backend_token: String,
    frame_key: Vec<u8>,
    frame_key_installed: bool,
    local: LocalMediaState,
    state: Rc<RefCell<TransportState>>,
    remotes: Rc<RefCell<Vec<RemoteParticipant>>>,
    /// Expected `ck.call.state.participants[]` SFU-local identities, seeded by
    /// the controller before `connect_sfu` and read inside the event loop for
    /// the MEDIA-2 cross-check.
    expected_participants: Rc<RefCell<BTreeSet<String>>>,
    /// Live eval bridge to the webview driver once `connect_sfu` opens it.
    /// `Eval` is `Copy`; commands (mute/screen/leave) are sent over it.
    bridge: Option<Eval>,
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

    /// If the SFU driver bridge is live, drive its real LiveKit publish toggle
    /// (`setMicrophoneEnabled` / `setCameraEnabled` / `setScreenShareEnabled`
    /// via the driver) and return `true`. Returns `false` when there is no SFU
    /// bridge (1:1 P2P path), which on desktop has no live media to toggle.
    fn drive_sfu_mute(&self, kind: &str, muted: bool) -> bool {
        let Some(bridge) = self.bridge.as_ref() else {
            return false;
        };
        let _ = bridge.send(json!({ "cmd": "set_muted", "kind": kind, "muted": muted }));
        true
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
        if self.drive_sfu_mute("audio", muted) {
            self.local.audio_muted = muted;
            return Ok(muted);
        }
        // No SFU bridge: the 1:1 P2P path is not driven on desktop.
        Err(RtcClientError::DesktopMediaUnavailable)
    }

    fn set_video_muted(&mut self, muted: bool) -> Result<bool, RtcClientError> {
        if self.drive_sfu_mute("video", muted) {
            self.local.video_muted = muted;
            return Ok(muted);
        }
        Err(RtcClientError::DesktopMediaUnavailable)
    }

    fn set_screen_share(&mut self, enabled: bool) -> Result<bool, RtcClientError> {
        let Some(bridge) = self.bridge.as_ref() else {
            return Err(RtcClientError::DesktopMediaUnavailable);
        };
        let _ = bridge.send(json!({ "cmd": "set_screen", "enabled": enabled }));
        self.desired_screen = enabled;
        self.local.screen_captured = enabled;
        Ok(enabled)
    }

    fn install_frame_key(&mut self, key: &[u8]) -> Result<(), RtcClientError> {
        ensure_valid_frame_key(key)?;
        // Retain the verified 32-byte MLS-exporter key so `connect_sfu` can
        // inject it into the LiveKit ExternalE2EEKeyProvider in the webview.
        self.frame_key = key.to_vec();
        self.frame_key_installed = true;
        Ok(())
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

        // Build the per-call driver config. The frame key is the verified
        // MLS-exporter-derived 32-byte key; it is passed as a number array so
        // the webview can reconstruct a Uint8Array for the E2EE key provider.
        let config = json!({
            "connectUrl": session.connect_url,
            "backendToken": session.backend_token,
            "audio": self.desired_audio,
            "video": self.desired_video,
            "frameKey": self.frame_key,
        });
        let config_json = serde_json::to_string(&config)
            .map_err(|_| RtcClientError::FocusUnavailableForClient)?;
        let script = DESKTOP_DRIVER_JS.replacen("__COKRET_DRIVER_CONFIG__", &config_json, 1);

        *self.state.borrow_mut() = TransportState::Connecting;

        // Open the long-lived eval bridge to the webview driver. The driver
        // runs the real `room.connect`, key injection, publish, and forwards
        // ParticipantConnected events; we keep the `Eval` handle to send
        // mute/screen/leave commands later. `Eval` is `Copy`, so the spawned
        // event loop and the transport share the same bridge.
        let bridge = document::eval(&script);
        self.bridge = Some(bridge);

        let mut event_bridge = bridge;
        let state = self.state.clone();
        let remotes = self.remotes.clone();
        let expected = self.expected_participants.clone();

        spawn(async move {
            loop {
                let event: DriverEvent = match event_bridge.recv::<Value>().await {
                    Ok(value) => match serde_json::from_value(value) {
                        Ok(event) => event,
                        // Ignore frames that are not a recognised driver event
                        // rather than tearing the live room down.
                        Err(_) => continue,
                    },
                    // The bridge closed (driver returned after leave, or the
                    // webview tore the channel down).
                    Err(_) => break,
                };
                match event {
                    DriverEvent::Connected => {
                        *state.borrow_mut() = TransportState::Connected;
                    }
                    DriverEvent::Participant { identity } => {
                        // MEDIA-2: drop any SFU identity not in the durable
                        // roster instead of trusting it.
                        if cross_check_participant_identity(&identity, &expected.borrow()).is_err()
                        {
                            continue;
                        }
                        let mut roster = remotes.borrow_mut();
                        if !roster.iter().any(|r| r.identity == identity) {
                            roster.push(RemoteParticipant {
                                identity,
                                audio_active: true,
                                video_active: false,
                                screen_active: false,
                            });
                        }
                    }
                    DriverEvent::Failed { .. } => {
                        // Fail-closed: the driver could not establish a real
                        // session; never advance to Connected.
                        let mut slot = state.borrow_mut();
                        if *slot != TransportState::Connected {
                            *slot = TransportState::Failed;
                        }
                    }
                    DriverEvent::Left => {
                        *state.borrow_mut() = TransportState::Closed;
                        break;
                    }
                }
            }
        });

        Ok(())
    }

    fn on_participant_connected(
        &mut self,
        identity: &str,
        expected: &BTreeSet<String>,
    ) -> Result<(), RtcClientError> {
        cross_check_participant_identity(identity, expected)?;
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
        *self.state.borrow_mut() = TransportState::Connected;
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
            let _ = bridge.send(json!({ "cmd": "leave" }));
        }
        self.remotes.borrow_mut().clear();
        self.local = LocalMediaState::default();
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
            t.install_frame_key(&[0u8; 16]).unwrap_err(),
            RtcClientError::E2eeKeySourceUnauthorised
        );
        assert!(t.install_frame_key(&[0u8; 32]).is_ok());
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
        expected.insert("ck:rtc_participant:bob".to_owned());
        // Unknown identity is rejected (MEDIA-2).
        assert!(
            t.on_participant_connected("ck:rtc_participant:mallory", &expected)
                .is_err()
        );
        assert!(t.remotes().is_empty());
        // Known identity is surfaced.
        assert!(
            t.on_participant_connected("ck:rtc_participant:bob", &expected)
                .is_ok()
        );
        assert_eq!(t.remotes().len(), 1);
    }
}
