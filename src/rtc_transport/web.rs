//! Browser (wasm) WebRTC transport built on `web-sys`.
//!
//! This is the live web media path: it owns a real
//! [`web_sys::RtcPeerConnection`] configured with the verified ICE servers,
//! captures local microphone / camera via `navigator.mediaDevices`, and
//! performs SDP offer/answer over promises. Because the browser RTC API is
//! promise-based and the [`MediaTransport`] trait is synchronous, SDP and
//! ICE results are produced asynchronously into a shared queue drained by
//! [`MediaTransport::drain_local_signals`].
//!
//! ## Two media paths
//!
//! - **1:1 P2P** stays on the native browser [`web_sys::RtcPeerConnection`]: the SDP offer/answer
//!   is relayed over `ak.call.signal`, so no SFU-specific signaling protocol is involved and a raw
//!   peer connection is correct.
//! - **SFU group calls** go through the real **livekit-client** JS SDK via the thin shim in
//!   [`assets/livekit_shim.js`] (bound by [`crate::rtc_transport::livekit_shim`]). LiveKit speaks a
//!   proprietary signaling protocol that cannot be reimplemented over bare `web-sys`, so
//!   [`MediaTransport::connect_sfu`] drives `room.connect`, local publish, and the
//!   `ExternalE2EEKeyProvider` instead of an `RtcPeerConnection`.
//!
//! The SFrame frame key (MLS-exporter-derived) is held until the SFU room
//! exists, then injected into LiveKit's E2EE key provider; on the P2P path it
//! gates offer/answer. [`MediaTransport::install_frame_key`] refuses any
//! non-32-byte key (MEDIA-1).

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::rc::Rc;

use wasm_bindgen::JsCast;
use wasm_bindgen::closure::Closure;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::{JsFuture, spawn_local};
use web_sys::{
    MediaStream, MediaStreamConstraints, RtcConfiguration, RtcIceCandidate, RtcIceCandidateInit,
    RtcPeerConnection, RtcPeerConnectionIceEvent, RtcSdpType, RtcSessionDescriptionInit,
};

use super::{
    LocalMediaState, LocalSignal, MediaTransport, RemoteParticipant, TransportState,
    ensure_valid_frame_key, livekit_shim,
};
use crate::media::rtc::{
    JoinedMediaSession, PerSenderFrameKeys, RtcClientError, cross_check_participant_id,
};

type SignalQueue = Rc<RefCell<Vec<LocalSignal>>>;

type ParticipantCallback = Rc<RefCell<Option<Closure<dyn FnMut(JsValue)>>>>;

/// Shared opaque LiveKit room handle string set once `room.connect` resolves.
type RoomHandle = Rc<RefCell<Option<String>>>;

pub struct WebRtcTransport {
    pc: Option<RtcPeerConnection>,
    desired_audio: bool,
    desired_video: bool,
    desired_screen: bool,
    connect_url: String,
    backend_token: String,
    ice_servers_json: String,
    state: Rc<RefCell<TransportState>>,
    local: LocalMediaState,
    frame_key_installed: bool,
    /// 32-byte MLS-exporter-derived SFrame key, retained so it can be injected
    /// into the LiveKit `ExternalE2EEKeyProvider` once the SFU room exists.
    frame_key: Vec<u8>,
    /// Shared remote roster (cross-checked SFU participants on the LiveKit
    /// path; populated synchronously on the P2P path).
    remotes: Rc<RefCell<Vec<RemoteParticipant>>>,
    /// Expected effective call-roster SFU-local identities, seeded by
    /// the controller before `connect_sfu` and read inside the LiveKit
    /// `ParticipantConnected` callback for the MEDIA-2 cross-check.
    expected_participants: Rc<RefCell<BTreeSet<String>>>,
    /// Local sender's SFU participant identity, bound into the local frame-key
    /// install (`media-service-binding.md` §8.1: keys are sender-bound).
    local_identity: String,
    /// Per-sender remote frame-key deriver (retains the live MLS exporter) plus
    /// the `participant_id → device_id` map from the verified
    /// `ak.component.call.roster.v1` OR-Set. Shared into the LiveKit
    /// `ParticipantConnected` callback so each remote sender's key is derived
    /// (same group exporter + epoch, the remote's own context) and installed.
    remote_keys: Rc<RefCell<Option<Rc<PerSenderFrameKeys>>>>,
    identity_to_device: Rc<RefCell<BTreeMap<String, String>>>,
    /// Live LiveKit room handle (SFU path) once `room.connect` resolves.
    room: RoomHandle,
    outbound: SignalQueue,
    local_stream: Rc<RefCell<Option<MediaStream>>>,
    // Retained so the JS callbacks are not dropped while the connection
    // is alive.
    _ice_cb: Option<Closure<dyn FnMut(RtcPeerConnectionIceEvent)>>,
    /// Retained LiveKit `ParticipantConnected` callback closure; dropping it
    /// would detach the SDK event listener. Shared so the async connect task
    /// can install it while the transport keeps it alive.
    participant_cb: ParticipantCallback,
}

impl WebRtcTransport {
    pub fn new(session: &JoinedMediaSession) -> Self {
        Self {
            pc: None,
            desired_audio: session.desired_media.audio,
            desired_video: session.desired_media.video,
            desired_screen: session.desired_media.screen,
            connect_url: session.connect_url.clone(),
            backend_token: session.backend_token.clone(),
            ice_servers_json: ice_servers_to_json(session),
            state: Rc::new(RefCell::new(TransportState::Idle)),
            local: LocalMediaState::default(),
            frame_key_installed: false,
            frame_key: Vec::new(),
            remotes: Rc::new(RefCell::new(Vec::new())),
            expected_participants: Rc::new(RefCell::new(BTreeSet::new())),
            local_identity: session.participant_id.clone(),
            remote_keys: Rc::new(RefCell::new(None)),
            identity_to_device: Rc::new(RefCell::new(BTreeMap::new())),
            room: Rc::new(RefCell::new(None)),
            outbound: Rc::new(RefCell::new(Vec::new())),
            local_stream: Rc::new(RefCell::new(None)),
            _ice_cb: None,
            participant_cb: Rc::new(RefCell::new(None)),
        }
    }

    /// Lazily build the `RtcPeerConnection` with the verified ICE servers
    /// and wire the `onicecandidate` relay into the outbound queue.
    fn ensure_pc(&mut self) -> Result<RtcPeerConnection, RtcClientError> {
        if let Some(pc) = &self.pc {
            return Ok(pc.clone());
        }
        let config = RtcConfiguration::new();
        let servers = js_sys::JSON::parse(&self.ice_servers_json)
            .map_err(|_| RtcClientError::FocusUnavailableForClient)?;
        config.set_ice_servers(&servers);
        let pc = RtcPeerConnection::new_with_configuration(&config)
            .map_err(|_| RtcClientError::FocusUnavailableForClient)?;

        let queue = self.outbound.clone();
        let ice_cb = Closure::wrap(Box::new(move |event: RtcPeerConnectionIceEvent| {
            if let Some(candidate) = event.candidate() {
                queue.borrow_mut().push(LocalSignal::Candidate {
                    candidate: candidate.candidate(),
                    sdp_mid: candidate.sdp_mid(),
                    sdp_m_line_index: candidate.sdp_m_line_index().map(u32::from),
                });
            }
        }) as Box<dyn FnMut(RtcPeerConnectionIceEvent)>);
        pc.set_onicecandidate(Some(ice_cb.as_ref().unchecked_ref()));
        self._ice_cb = Some(ice_cb);
        self.pc = Some(pc.clone());
        Ok(pc)
    }

    fn ensure_frame_key(&self) -> Result<(), RtcClientError> {
        if self.frame_key_installed {
            Ok(())
        } else {
            Err(RtcClientError::E2eeKeySourceUnauthorised)
        }
    }

    /// If a LiveKit SFU room is live, drive its real publish toggle
    /// (`setMicrophoneEnabled` / `setCameraEnabled` / `setScreenShareEnabled`
    /// via the shim) and return `true`. Returns `false` when there is no SFU
    /// room (1:1 P2P path), so the caller falls back to the local track
    /// enable/disable. `kind` = "audio" | "video" | "screen".
    fn drive_sfu_mute(&self, kind: &str, muted: bool) -> bool {
        let handle = match self.room.borrow().clone() {
            Some(h) => h,
            None => return false,
        };
        if let Ok(promise) = livekit_shim::set_muted(&handle, kind, muted) {
            spawn_local(async move {
                let _ = JsFuture::from(promise).await;
            });
        }
        true
    }
}

impl MediaTransport for WebRtcTransport {
    fn start_local_capture(&mut self) -> Result<LocalMediaState, RtcClientError> {
        let pc = self.ensure_pc()?;
        let window = web_sys::window().ok_or(RtcClientError::FocusUnavailableForClient)?;
        let media_devices = window
            .navigator()
            .media_devices()
            .map_err(|_| RtcClientError::FocusUnavailableForClient)?;
        let constraints = MediaStreamConstraints::new();
        constraints.set_audio(&JsValue::from_bool(self.desired_audio));
        constraints.set_video(&JsValue::from_bool(self.desired_video));
        let promise = media_devices
            .get_user_media_with_constraints(&constraints)
            .map_err(|_| RtcClientError::FocusUnavailableForClient)?;

        let state = self.state.clone();
        let stream_slot = self.local_stream.clone();
        spawn_local(async move {
            match JsFuture::from(promise).await {
                Ok(stream_value) => {
                    if let Ok(stream) = stream_value.dyn_into::<MediaStream>() {
                        for track in stream.get_tracks().iter() {
                            if let Ok(track) = track.dyn_into::<web_sys::MediaStreamTrack>() {
                                let _ = pc.add_track_0(&track, &stream);
                            }
                        }
                        *stream_slot.borrow_mut() = Some(stream);
                    }
                }
                Err(_) => {
                    *state.borrow_mut() = TransportState::Failed;
                }
            }
        });

        self.local.audio_captured = self.desired_audio;
        self.local.video_captured = self.desired_video;
        Ok(self.local)
    }

    fn set_audio_muted(&mut self, muted: bool) -> Result<bool, RtcClientError> {
        // SFU path: drive the real LiveKit localParticipant publish toggle.
        if self.drive_sfu_mute("audio", muted) {
            self.local.audio_muted = muted;
            return Ok(muted);
        }
        // P2P path: enable/disable the captured local track in place.
        if let Some(stream) = self.local_stream.borrow().as_ref() {
            for track in stream.get_audio_tracks().iter() {
                if let Ok(track) = track.dyn_into::<web_sys::MediaStreamTrack>() {
                    track.set_enabled(!muted);
                }
            }
        }
        self.local.audio_muted = muted;
        Ok(muted)
    }

    fn set_video_muted(&mut self, muted: bool) -> Result<bool, RtcClientError> {
        if self.drive_sfu_mute("video", muted) {
            self.local.video_muted = muted;
            return Ok(muted);
        }
        if let Some(stream) = self.local_stream.borrow().as_ref() {
            for track in stream.get_video_tracks().iter() {
                if let Ok(track) = track.dyn_into::<web_sys::MediaStreamTrack>() {
                    track.set_enabled(!muted);
                }
            }
        }
        self.local.video_muted = muted;
        Ok(muted)
    }

    fn set_screen_share(&mut self, enabled: bool) -> Result<bool, RtcClientError> {
        // SFU path: drive the real LiveKit screen-share publish via the shim
        // (`localParticipant.setScreenShareEnabled`).
        self.drive_sfu_mute("screen", !enabled);
        self.desired_screen = enabled;
        self.local.screen_captured = enabled;
        // On the P2P path getDisplayMedia capture is driven by the platform
        // shell's screen picker; the publish toggle is reflected here and
        // surfaced to the peer via a `media_state` signal by the controller.
        Ok(enabled)
    }

    fn install_frame_key(
        &mut self,
        participant_id: &str,
        key: &[u8],
    ) -> Result<(), RtcClientError> {
        ensure_valid_frame_key(key)?;
        // Retain the verified 32-byte MLS-exporter key (and the local sender
        // identity it is bound to) so the SFU path can inject it into the
        // LiveKit ExternalE2EEKeyProvider under that identity once the room
        // exists. The P2P path only needs the installed flag as an offer gate.
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
        *self.remote_keys.borrow_mut() = Some(keys);
        *self.identity_to_device.borrow_mut() = identity_to_device;
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
        *self.state.borrow_mut() = TransportState::Connecting;

        // Spin the real livekit-client join. The SFU path does NOT use the
        // raw RtcPeerConnection: LiveKit owns its own signaling. Everything
        // below drives genuine SDK APIs through the shim; a rejected
        // `room.connect` leaves the state out of `Connected` (fail-closed).
        let connect_url = session.connect_url.clone();
        let backend_token = session.backend_token.clone();
        let frame_key = self.frame_key.clone();
        let local_identity = self.local_identity.clone();
        let desired_audio = self.desired_audio;
        let desired_video = self.desired_video;
        let room_slot = self.room.clone();
        let state = self.state.clone();
        let remotes = self.remotes.clone();
        let expected = self.expected_participants.clone();
        let participant_cb_slot = self.participant_cb.clone();
        let remote_keys = self.remote_keys.clone();
        let identity_to_device = self.identity_to_device.clone();

        spawn_local(async move {
            let opts = js_sys::Object::new();
            let _ = js_sys::Reflect::set(
                &opts,
                &JsValue::from_str("autoSubscribe"),
                &JsValue::from_bool(true),
            );
            let join_promise = match livekit_shim::join(&connect_url, &backend_token, &opts) {
                Ok(p) => p,
                Err(_) => {
                    *state.borrow_mut() = TransportState::Failed;
                    return;
                }
            };
            let handle = match JsFuture::from(join_promise).await {
                Ok(value) => value.as_string().unwrap_or_default(),
                Err(_) => {
                    *state.borrow_mut() = TransportState::Failed;
                    return;
                }
            };
            if handle.is_empty() {
                *state.borrow_mut() = TransportState::Failed;
                return;
            }
            *room_slot.borrow_mut() = Some(handle.clone());

            // Inject the local sender's MLS-exporter-derived frame key into
            // LiveKit's E2EE key provider, bound to the local participant
            // identity (§8.1: keys are sender-bound, never a room-wide slot),
            // and enable room E2EE BEFORE publishing so local media is
            // encrypted from the first frame. Fail-closed: if the install does
            // not resolve, the room MUST NOT reach Connected — peers could not
            // decrypt our media otherwise.
            match livekit_shim::set_e2ee_key(&handle, &local_identity, &frame_key, 0) {
                Ok(key_promise) => {
                    if JsFuture::from(key_promise).await.is_err() {
                        *state.borrow_mut() = TransportState::Failed;
                        return;
                    }
                }
                Err(_) => {
                    *state.borrow_mut() = TransportState::Failed;
                    return;
                }
            }

            // Publish local mic/cam per desired_media (real SDK toggles).
            let media = js_sys::Object::new();
            let _ = js_sys::Reflect::set(
                &media,
                &JsValue::from_str("audio"),
                &JsValue::from_bool(desired_audio),
            );
            let _ = js_sys::Reflect::set(
                &media,
                &JsValue::from_str("video"),
                &JsValue::from_bool(desired_video),
            );
            if let Ok(pub_promise) = livekit_shim::publish(&handle, &media) {
                let _ = JsFuture::from(pub_promise).await;
            }

            // Wire the real RoomEvent.ParticipantConnected listener. The
            // callback cross-checks each SFU identity against the durable
            // roster (MEDIA-2); unrecognised identities are dropped (their
            // stream is never surfaced) instead of trusted.
            let remotes_cb = remotes.clone();
            let expected_cb = expected.clone();
            let remote_keys_cb = remote_keys.clone();
            let identity_to_device_cb = identity_to_device.clone();
            let key_room = handle.clone();
            let cb = Closure::wrap(Box::new(move |identity: JsValue| {
                let identity = identity.as_string().unwrap_or_default();
                if cross_check_participant_id(&identity, &expected_cb.borrow()).is_err() {
                    return;
                }
                // §8.1 receiver side: derive THIS remote sender's frame key from
                // the same MLS group exporter at the same epoch, using the
                // remote's own (participant_id, device_id) context, and
                // install it under the remote identity so its frames decrypt.
                // Fail-closed: if the device_id is unknown or derivation fails,
                // skip this one remote (its frames stay undecryptable) without
                // affecting any other remote or local media.
                if let Some(keys) = remote_keys_cb.borrow().clone() {
                    let device_id = identity_to_device_cb.borrow().get(&identity).cloned();
                    if let Some(device_id) = device_id
                        && let Ok(remote_key) = keys.derive_remote_key(&identity, &device_id)
                        && let Ok(promise) =
                            livekit_shim::set_e2ee_key(&key_room, &identity, &remote_key, 0)
                    {
                        spawn_local(async move {
                            let _ = JsFuture::from(promise).await;
                        });
                    }
                }
                let mut roster = remotes_cb.borrow_mut();
                if !roster.iter().any(|r| r.identity == identity) {
                    roster.push(RemoteParticipant {
                        identity,
                        audio_active: true,
                        video_active: false,
                        screen_active: false,
                    });
                }
            }) as Box<dyn FnMut(JsValue)>);
            let _ = livekit_shim::on_participant(&handle, cb.as_ref().unchecked_ref());
            // Park the closure on the transport-owned shared slot so it
            // outlives this task and keeps the SDK listener attached.
            *participant_cb_slot.borrow_mut() = Some(cb);

            *state.borrow_mut() = TransportState::Connected;
        });

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
        // Tear down the LiveKit room (SFU path) if one is live.
        if let Some(handle) = self.room.borrow_mut().take()
            && let Ok(promise) = livekit_shim::leave(&handle)
        {
            spawn_local(async move {
                let _ = JsFuture::from(promise).await;
            });
        }
        *self.participant_cb.borrow_mut() = None;
        if let Some(pc) = self.pc.take() {
            pc.close();
        }
        self._ice_cb = None;
        if let Some(stream) = self.local_stream.borrow().as_ref() {
            for track in stream.get_tracks().iter() {
                if let Ok(track) = track.dyn_into::<web_sys::MediaStreamTrack>() {
                    track.stop();
                }
            }
        }
        *self.local_stream.borrow_mut() = None;
        self.remotes.borrow_mut().clear();
        self.outbound.borrow_mut().clear();
        self.local = LocalMediaState::default();
        *self.state.borrow_mut() = TransportState::Closed;
    }

    fn begin_offer(&mut self) -> Result<(), RtcClientError> {
        self.ensure_frame_key()?;
        let pc = self.ensure_pc()?;
        let queue = self.outbound.clone();
        let state = self.state.clone();
        *self.state.borrow_mut() = TransportState::Connecting;
        spawn_local(async move {
            if let Ok(offer) = JsFuture::from(pc.create_offer()).await {
                let sdp = sdp_from_description(&offer);
                let init = RtcSessionDescriptionInit::new(RtcSdpType::Offer);
                init.set_sdp(&sdp);
                if JsFuture::from(pc.set_local_description(&init))
                    .await
                    .is_ok()
                {
                    queue.borrow_mut().push(LocalSignal::Offer { sdp });
                } else {
                    *state.borrow_mut() = TransportState::Failed;
                }
            } else {
                *state.borrow_mut() = TransportState::Failed;
            }
        });
        Ok(())
    }

    fn accept_offer(&mut self, sdp: &str) -> Result<(), RtcClientError> {
        self.ensure_frame_key()?;
        if sdp.trim().is_empty() {
            return Err(RtcClientError::ParticipantBindingInvalid);
        }
        let pc = self.ensure_pc()?;
        let queue = self.outbound.clone();
        let state = self.state.clone();
        let remote_sdp = sdp.to_owned();
        *self.state.borrow_mut() = TransportState::Connecting;
        spawn_local(async move {
            let remote = RtcSessionDescriptionInit::new(RtcSdpType::Offer);
            remote.set_sdp(&remote_sdp);
            if JsFuture::from(pc.set_remote_description(&remote))
                .await
                .is_err()
            {
                *state.borrow_mut() = TransportState::Failed;
                return;
            }
            if let Ok(answer) = JsFuture::from(pc.create_answer()).await {
                let sdp = sdp_from_description(&answer);
                let init = RtcSessionDescriptionInit::new(RtcSdpType::Answer);
                init.set_sdp(&sdp);
                if JsFuture::from(pc.set_local_description(&init))
                    .await
                    .is_ok()
                {
                    queue.borrow_mut().push(LocalSignal::Answer { sdp });
                } else {
                    *state.borrow_mut() = TransportState::Failed;
                }
            } else {
                *state.borrow_mut() = TransportState::Failed;
            }
        });
        Ok(())
    }

    fn accept_answer(&mut self, sdp: &str) -> Result<(), RtcClientError> {
        if sdp.trim().is_empty() {
            return Err(RtcClientError::ParticipantBindingInvalid);
        }
        let pc = self.ensure_pc()?;
        let state = self.state.clone();
        let remote_sdp = sdp.to_owned();
        spawn_local(async move {
            let remote = RtcSessionDescriptionInit::new(RtcSdpType::Answer);
            remote.set_sdp(&remote_sdp);
            if JsFuture::from(pc.set_remote_description(&remote))
                .await
                .is_ok()
            {
                *state.borrow_mut() = TransportState::Connected;
            } else {
                *state.borrow_mut() = TransportState::Failed;
            }
        });
        Ok(())
    }

    fn add_remote_candidate(
        &mut self,
        candidate: &str,
        sdp_mid: Option<&str>,
        sdp_m_line_index: Option<u32>,
    ) -> Result<(), RtcClientError> {
        if candidate.trim().is_empty() {
            return Err(RtcClientError::ParticipantBindingInvalid);
        }
        let pc = self.ensure_pc()?;
        let init = RtcIceCandidateInit::new(candidate);
        init.set_sdp_mid(sdp_mid);
        if let Some(index) = sdp_m_line_index {
            init.set_sdp_m_line_index(Some(index as u16));
        }
        if let Ok(ice) = RtcIceCandidate::new(&init) {
            let _ = pc.add_ice_candidate_with_opt_rtc_ice_candidate(Some(&ice));
        }
        Ok(())
    }

    fn drain_local_signals(&mut self) -> Vec<LocalSignal> {
        std::mem::take(&mut self.outbound.borrow_mut())
    }
}

/// Build the JSON `iceServers` array web-sys's `RtcConfiguration` expects
/// from the verified [`arkret_sdk::IceConfig`].
fn ice_servers_to_json(session: &JoinedMediaSession) -> String {
    let entries: Vec<serde_json::Value> = session
        .ice_config
        .ice_servers
        .iter()
        .map(|server| {
            let mut obj = serde_json::json!({ "urls": server.urls });
            if let Some(username) = &server.username {
                obj["username"] = serde_json::Value::String(username.clone());
            }
            if let Some(credential) = &server.credential {
                obj["credential"] = serde_json::Value::String(credential.clone());
            }
            obj
        })
        .collect();
    serde_json::Value::Array(entries).to_string()
}

/// Pull the `sdp` string out of a resolved `createOffer` / `createAnswer`
/// description value.
fn sdp_from_description(value: &JsValue) -> String {
    js_sys::Reflect::get(value, &JsValue::from_str("sdp"))
        .ok()
        .and_then(|v| v.as_string())
        .unwrap_or_default()
}
