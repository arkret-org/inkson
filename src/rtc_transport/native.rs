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
use std::collections::{BTreeMap, BTreeSet};
use std::rc::Rc;

use dioxus::document::{self, Eval};
use dioxus::prelude::spawn;
use serde::Deserialize;
use serde_json::{Value, json};

use super::{
    LocalMediaState, LocalSignal, MediaTransport, RemoteParticipant, TransportState,
    ensure_valid_frame_key,
};
use crate::media::rtc::{
    JoinedMediaSession, PerSenderFrameKeys, RtcClientError, cross_check_participant_identity,
};

/// The desktop LiveKit driver, run in the webview over the eval bridge. The
/// leading `__COKRET_DRIVER_CONFIG__` token is replaced per call with the
/// JSON connect config (URL, token, media flags, frame key); the
/// `__COKRET_LIVEKIT_UMD_SOURCE__` token is replaced once with the vendored
/// UMD body so the SDK ships inside the binary (no runtime CDN fetch).
const DESKTOP_DRIVER_JS: &str = include_str!("../../assets/livekit_desktop_driver.js");

/// Vendored livekit-client UMD (pinned 2.19.2), bundled into the desktop
/// binary. Injected into the driver as a JS string literal so the webview can
/// evaluate it offline. Refresh with `scripts/vendor_livekit.sh`.
const LIVEKIT_UMD_SOURCE: &str = include_str!("../../assets/vendor/livekit-client.umd.min.js");

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
    /// Local sender's SFU participant identity, bound into the local frame-key
    /// install (`media-service-binding.md` §8.1: keys are sender-bound).
    local_identity: String,
    /// Per-sender remote frame-key deriver (retains the live MLS exporter) plus
    /// the `participant_identity → device_id` map from the verified
    /// `ck.call.state.participants[]` roster. Moved into the driver event loop
    /// so each remote sender's recomputed key is injected into the webview
    /// LiveKit provider under the remote identity.
    remote_keys: Option<Rc<PerSenderFrameKeys>>,
    identity_to_device: BTreeMap<String, String>,
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
            local_identity: session.participant_identity.clone(),
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

    fn install_frame_key(
        &mut self,
        participant_identity: &str,
        key: &[u8],
    ) -> Result<(), RtcClientError> {
        ensure_valid_frame_key(key)?;
        // Retain the verified 32-byte MLS-exporter key and the local sender
        // identity it is bound to so `connect_sfu` can inject it into the
        // LiveKit ExternalE2EEKeyProvider under that identity in the webview.
        self.frame_key = key.to_vec();
        if !participant_identity.trim().is_empty() {
            self.local_identity = participant_identity.to_owned();
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

        // Build the per-call driver config. The frame key is the verified
        // MLS-exporter-derived 32-byte key; it is passed as a number array so
        // the webview can reconstruct a Uint8Array for the E2EE key provider.
        let config = json!({
            "connectUrl": session.connect_url,
            "backendToken": session.backend_token,
            "audio": self.desired_audio,
            "video": self.desired_video,
            "frameKey": self.frame_key,
            // §8.1: the local key is sender-bound; install it under the local
            // participant identity, never a room-wide slot.
            "localIdentity": self.local_identity,
        });
        let config_json = serde_json::to_string(&config)
            .map_err(|_| RtcClientError::FocusUnavailableForClient)?;
        // Embed the vendored UMD as a JS string literal. serde_json produces a
        // valid double-quoted JS string (escaping quotes/backslashes/newlines),
        // which the driver evaluates via `new Function(...)` to register
        // `window.LivekitClient` offline.
        let umd_literal = serde_json::to_string(LIVEKIT_UMD_SOURCE)
            .map_err(|_| RtcClientError::FocusUnavailableForClient)?;
        let script = DESKTOP_DRIVER_JS
            .replacen("__COKRET_DRIVER_CONFIG__", &config_json, 1)
            .replacen("__COKRET_LIVEKIT_UMD_SOURCE__", &umd_literal, 1);

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
        let remote_keys = self.remote_keys.clone();
        let identity_to_device = self.identity_to_device.clone();

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
                        // §8.1 receiver side: recompute THIS remote sender's
                        // frame key from the same MLS group exporter at the same
                        // epoch (the remote's own (participant_identity,
                        // device_id) context) and inject it into the webview
                        // LiveKit provider under the remote identity so its
                        // frames decrypt. Fail-closed: unknown device_id or a
                        // derivation failure skips this one remote (its frames
                        // stay undecryptable) without affecting any other.
                        if let Some(keys) = remote_keys.as_ref()
                            && let Some(device_id) = identity_to_device.get(&identity)
                            && let Ok(remote_key) = keys.derive_remote_key(&identity, device_id)
                        {
                            let _ = event_bridge.send(json!({
                                "cmd": "set_e2ee_key",
                                "identity": identity,
                                "key": remote_key,
                                "keyIndex": 0,
                            }));
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
            focus_id: "fra-1".to_owned(),
            connect_url: "wss://livekit.example".to_owned(),
            backend_token: "jwt".to_owned(),
            participant_identity: "ck:rtc_participant:self".to_owned(),
            participant_binding: cokret_sdk::CallMediaParticipantBinding {
                scheme: cokret_sdk::PARTICIPANT_BINDING_SCHEMA.to_owned(),
                sig: "sig".to_owned(),
                issuer_kid: "did:web:media.example#key-1".to_owned(),
                realm_id: cokret_sdk::RealmId::new("ck:realm:01904100-0000-7000-8000-9b64700c6ee8")
                    .unwrap(),
                call_id: cokret_sdk::CallId::new("ck:call:0196441c-0000-7000-8000-000000000000")
                    .unwrap(),
                focus_id: "fra-1".to_owned(),
                actor_id: cokret_sdk::Did::new("did:web:alice.example").unwrap(),
                device_id: cokret_sdk::DeviceId::new(
                    "ck:device:01904100-0000-7000-8000-000000000005",
                )
                .unwrap(),
                participant_identity: "ck:rtc_participant:self".to_owned(),
                issued_at: chrono::DateTime::parse_from_rfc3339("2026-04-26T00:00:00Z")
                    .unwrap()
                    .with_timezone(&chrono::Utc),
                expires_at: chrono::DateTime::parse_from_rfc3339("2026-04-26T00:05:00Z")
                    .unwrap()
                    .with_timezone(&chrono::Utc),
            },
            ice_config: ice_config(),
            frame_key: vec![7u8; 32],
            desired_media: DesiredMedia::audio_video(),
            device_id: "ck:device:01904100-0000-7000-8000-000000000005".to_owned(),
            realm_id: "ck:realm:01904100-0000-7000-8000-9b64700c6ee8".to_owned(),
            call_id: "ck:call:0196441c-0000-7000-8000-000000000000".to_owned(),
            epoch_id: 0,
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
            t.install_frame_key("ck:rtc_participant:self", &[0u8; 16])
                .unwrap_err(),
            RtcClientError::E2eeKeySourceUnauthorised
        );
        assert!(
            t.install_frame_key("ck:rtc_participant:self", &[0u8; 32])
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
