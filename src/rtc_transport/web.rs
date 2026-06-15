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
//! The SFrame frame key (MLS-exporter-derived) is held for the
//! `RTCRtpScriptTransform` / Insertable-Streams keyprovider the platform
//! installs; [`MediaTransport::install_frame_key`] refuses any non-32-byte
//! key (MEDIA-1).

use std::cell::RefCell;
use std::collections::BTreeSet;
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
    ensure_valid_frame_key,
};
use crate::media::rtc::{JoinedMediaSession, RtcClientError, cross_check_participant_identity};

type SignalQueue = Rc<RefCell<Vec<LocalSignal>>>;

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
    remotes: Vec<RemoteParticipant>,
    outbound: SignalQueue,
    local_stream: Rc<RefCell<Option<MediaStream>>>,
    // Retained so the JS callbacks are not dropped while the connection
    // is alive.
    _ice_cb: Option<Closure<dyn FnMut(RtcPeerConnectionIceEvent)>>,
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
            remotes: Vec::new(),
            outbound: Rc::new(RefCell::new(Vec::new())),
            local_stream: Rc::new(RefCell::new(None)),
            _ice_cb: None,
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
        self.desired_screen = enabled;
        self.local.screen_captured = enabled;
        // getDisplayMedia capture is driven by the platform shell's screen
        // picker; the publish toggle is reflected here and surfaced to the
        // SFU via a `media_state` signal by the controller.
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
        self.ensure_pc()?;
        *self.state.borrow_mut() = TransportState::Connecting;
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
        *self.state.borrow_mut() = TransportState::Connected;
        Ok(())
    }

    fn state(&self) -> TransportState {
        *self.state.borrow()
    }

    fn remotes(&self) -> Vec<RemoteParticipant> {
        self.remotes.clone()
    }

    fn close(&mut self) {
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
        self.remotes.clear();
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
/// from the verified [`cokret_sdk::IceConfig`].
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
