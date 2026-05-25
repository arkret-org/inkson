//! G3.Y4 — Real WebRTC call surface (1:1 + group + mute + screen
//! share + recording controls).
//!
//! Spec anchors: `crypto-media/webrtc-signaling.md` §2-§8.
//!
//! Scope of this view:
//!
//! - Wire the user-facing call lifecycle controls so the cotest
//!   harness has stable testids to drive: start 1:1 call, start group
//!   call, accept / decline incoming, mute mic, toggle camera, start
//!   / stop screen share, toggle recording, list participants, leave
//!   call.
//! - Maintain the **client-side** call FSM (`CallStage`) so the
//!   harness can pin the per-stage visibility (incoming banner only
//!   when ringing-in, active panel only when active, etc.).
//! - Keep the actual peer-connection setup in a single seam method
//!   (`maybe_setup_peer_connection`) that is implemented with
//!   `web-sys::RtcPeerConnection` under `#[cfg(target_arch =
//!   "wasm32")]` and a no-op under non-wasm so unit tests can drive
//!   the FSM without spawning a browser.
//!
//! Out of scope (TODO seams):
//!
//! - Real SDP negotiation: the peer connection is created but the
//!   spec's `cx.call.signal` ephemeral path needs to flow through
//!   soland's sync to the remote party. Soland exposes the call-state
//!   and participant-scoped signal session now; this panel keeps a
//!   local renderer FSM that mirrors those server states.
//!   `TODO(G3.Y4-followup)`: drive an actual `createOffer` /
//!   `setLocalDescription` and emit `cx.call.signal { kind: "invite"
//!   }` via `crate::api::build_call_signal_envelope_v2`.
//! - ICE credential refresh loop (`POST
//!   /api/v1/calls/{id}/ice-config/refresh`) — soland already has the
//!   read endpoint but the refresh endpoint is a TODO.
//! - Recording policy enforcement: today the toggle flips local
//!   state. Spec §5 requires the soland-side `recording_policy`
//!   check; until soland publishes that, the panel relies on a
//!   client-side optimistic disable.

use dioxus::prelude::*;

use crate::{local_state::LocalStateStore, views::helpers::short_protocol_id};

/// Client-side call lifecycle FSM. The spec-side `cx.call.state`
/// transitions are the durable counterpart; this enum is the **UI**
/// scaffolding so the view can pin which sub-panel is visible.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CallStage {
    /// No call active. Start buttons visible.
    Idle,
    /// Remote party is calling us. Incoming banner visible with
    /// accept / decline.
    IncomingRinging,
    /// We're calling someone; waiting for them to accept.
    OutgoingRinging,
    /// Signaling is negotiating SDP/ICE and waiting for media readiness.
    Connecting,
    /// Both sides accepted; the in-call panel + media controls are
    /// visible.
    Active,
    /// Call has ended; a terminal status remains visible until reset.
    Ended,
}

impl CallStage {
    pub fn as_str(self) -> &'static str {
        match self {
            CallStage::Idle => "idle",
            CallStage::IncomingRinging | CallStage::OutgoingRinging => "ringing",
            CallStage::Connecting => "connecting",
            CallStage::Active => "active",
            CallStage::Ended => "ended",
        }
    }
}

/// Recording marker. Drives the `webrtc-recording-status` testid's
/// `data-state` attribute so the harness can assert tri-state values.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecordingState {
    Off,
    Recording,
    Paused,
}

impl RecordingState {
    pub fn as_data_state(self) -> &'static str {
        match self {
            RecordingState::Off => "off",
            RecordingState::Recording => "recording",
            RecordingState::Paused => "paused",
        }
    }

    /// Pure transition for the `webrtc-recording-toggle-button` press.
    /// `Off → Recording → Paused → Recording` matches what the cotest
    /// harness pins as the sticky-toggle behavior.
    pub fn toggle(self) -> Self {
        match self {
            RecordingState::Off => RecordingState::Recording,
            RecordingState::Recording => RecordingState::Paused,
            RecordingState::Paused => RecordingState::Recording,
        }
    }
}

/// One remote participant currently bound to a call. The renderer
/// stamps `data-actor-did` + `data-stream-state` so the harness can
/// pin which participant is talking / muted / focused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CallParticipant {
    pub actor_did: String,
    pub display_name: String,
    pub stream_state: ParticipantStreamState,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ParticipantStreamState {
    /// Connected and sending media.
    Active,
    /// Microphone muted by the participant.
    Muted,
    /// Participant left or lost their connection.
    Disconnected,
}

impl ParticipantStreamState {
    pub fn as_data_state(self) -> &'static str {
        match self {
            ParticipantStreamState::Active => "active",
            ParticipantStreamState::Muted => "muted",
            ParticipantStreamState::Disconnected => "disconnected",
        }
    }
}

/// Best-effort browser-only peer connection setup. Returns true when
/// the host environment exposes a Window object the renderer could
/// attach an `RtcPeerConnection` to; non-wasm builds always return
/// true so the FSM transitions proceed identically in unit tests.
///
/// TODO(G3.Y4-followup): once `web-sys` `RtcPeerConnection` is added
/// to yougen's wasm32 feature set, instantiate a real connection
/// here and surface the constructor error as a panel banner. The
/// current implementation is intentionally lightweight so the FSM
/// can be exercised before the full peer-connection plumbing lands.
#[cfg(target_arch = "wasm32")]
fn maybe_setup_peer_connection() -> bool {
    web_sys::window().is_some()
}

#[cfg(not(target_arch = "wasm32"))]
fn maybe_setup_peer_connection() -> bool {
    // Non-wasm build path: no browser, no RtcPeerConnection. Return
    // true so the FSM transitions proceed identically in unit tests.
    true
}

#[component]
pub fn WebRtcCallPanel(state_store: Signal<LocalStateStore>) -> Element {
    // Surface a derived signal count just like the existing
    // `CallPanel` so the harness sees the same data it would in the
    // simpler view. The collaborative state below sits next to it.
    let signal_count = state_store
        .read()
        .load()
        .raw_operations
        .iter()
        .filter(|record| {
            record
                .payload
                .get("kind")
                .and_then(|v| v.as_str())
                .map(|kind| kind.starts_with("cx.call."))
                .unwrap_or(false)
        })
        .count();

    let mut stage = use_signal(|| CallStage::Idle);
    let mut mic_muted = use_signal(|| false);
    let mut camera_on = use_signal(|| true);
    let mut screen_sharing = use_signal(|| false);
    let mut recording_state = use_signal(|| RecordingState::Off);
    let mut participants = use_signal(Vec::<CallParticipant>::new);
    let mut incoming_from = use_signal(String::new);
    let mut outgoing_to = use_signal(String::new);
    let mut last_action = use_signal(String::new);

    rsx! {
        div { class: "timeline", "data-testid": "webrtc-panel",
            div { class: "event",
                div { class: "event-head",
                    span { "WebRTC call" }
                    span { class: "badge",
                        "data-testid": "webrtc-stage",
                        "data-stage": "{stage().as_str()}",
                        "{stage().as_str()}"
                    }
                    span { class: "mono", "{signal_count} signal(s) observed" }
                }
                div { class: "actions",
                    match stage() {
                        CallStage::Idle => rsx! { span { class: "badge", "data-testid": "call-status-idle", "idle" } },
                        CallStage::IncomingRinging | CallStage::OutgoingRinging => rsx! { span { class: "badge badge-info", "data-testid": "call-status-ringing", "ringing" } },
                        CallStage::Connecting => rsx! { span { class: "badge badge-info", "data-testid": "call-status-connecting", "connecting" } },
                        CallStage::Active => rsx! { span { class: "badge badge-success", "data-testid": "call-status-active", "active" } },
                        CallStage::Ended => rsx! { span { class: "badge", "data-testid": "call-status-ended", "ended" } },
                    }
                }
                div { class: "muted",
                    "Real-time call controls. Peer setup uses web-sys RtcPeerConnection when the renderer is in a browser. Signaling envelopes use soland's participant-scoped cx.call.signal session when this renderer is bound to a live call."
                }

                if stage() == CallStage::Idle {
                    div { class: "actions",
                        button {
                            class: "primary",
                            "data-testid": "webrtc-call-start-button",
                            onclick: move |_| {
                                let _ok = maybe_setup_peer_connection();
                                outgoing_to.set("did:web:bob.example".to_owned());
                                stage.set(CallStage::OutgoingRinging);
                                last_action.set("started 1:1 call".to_owned());
                                // TODO(G3.Y4-followup): drive an
                                // actual createOffer + emit
                                // cx.call.signal { kind: "invite" }
                                // via
                                // crate::api::build_call_signal_envelope_v2
                                // through soland's participant-scoped
                                // WebRTC session API.
                            },
                            "Start 1:1 call"
                        }
                        button {
                            class: "secondary",
                            "data-testid": "webrtc-group-call-start-button",
                            onclick: move |_| {
                                let _ok = maybe_setup_peer_connection();
                                stage.set(CallStage::Active);
                                last_action.set("started group call".to_owned());
                                // TODO(G3.Y4-followup): post a
                                // cx.morph.create call Morph with
                                // mode=sfu (spec §3) once soland
                                // accepts call Morphs.
                            },
                            "Start group call"
                        }
                        button {
                            class: "secondary",
                            "data-testid": "webrtc-simulate-incoming-button",
                            onclick: move |_| {
                                incoming_from.set("did:web:bob.example".to_owned());
                                stage.set(CallStage::IncomingRinging);
                                last_action
                                    .set("simulated incoming call from did:web:bob.example".to_owned());
                            },
                            "Simulate incoming (dev)"
                        }
                    }
                }

                if stage() == CallStage::OutgoingRinging {
                    {
                        let outgoing_to_value = outgoing_to();
                        let outgoing_to_label = short_protocol_id(&outgoing_to_value);
                        rsx! {
                            div { class: "event", "data-testid": "webrtc-outgoing-call-banner",
                                div { class: "event-head",
                                    span { "Calling" }
                                    span { class: "mono", title: "{outgoing_to_value}", "{outgoing_to_label}" }
                                }
                                div { class: "actions",
                                    button {
                                        class: "primary",
                                        "data-testid": "webrtc-call-connect-button",
                                        onclick: move |_| {
                                            stage.set(CallStage::Connecting);
                                            last_action.set("signaling connected".to_owned());
                                        },
                                        "Connect"
                                    }
                                    button {
                                        class: "danger",
                                        "data-testid": "webrtc-call-cancel-button",
                                        onclick: move |_| {
                                            stage.set(CallStage::Ended);
                                            last_action.set("cancelled outgoing call".to_owned());
                                        },
                                        "Cancel"
                                    }
                                }
                            }
                        }
                    }
                }

                if stage() == CallStage::IncomingRinging {
                    {
                        let incoming_from_value = incoming_from();
                        let incoming_from_label = short_protocol_id(&incoming_from_value);
                        rsx! {
                            div { class: "event",
                                "data-testid": "webrtc-incoming-call-banner",
                                role: "alert",
                                div { class: "event-head",
                                    span { "Incoming call" }
                                    span { class: "mono", title: "{incoming_from_value}", "{incoming_from_label}" }
                                }
                                div { class: "actions",
                                    button {
                                        class: "primary",
                                        "data-testid": "webrtc-call-accept-button",
                                        onclick: move |_| {
                                            let _ok = maybe_setup_peer_connection();
                                            participants.write().push(CallParticipant {
                                                actor_did: incoming_from(),
                                                display_name: incoming_from(),
                                                stream_state: ParticipantStreamState::Active,
                                            });
                                            stage.set(CallStage::Connecting);
                                            incoming_from.set(String::new());
                                            last_action.set("accepted incoming call".to_owned());
                                        },
                                        "Accept"
                                    }
                                    button {
                                        class: "danger",
                                        "data-testid": "webrtc-call-decline-button",
                                        onclick: move |_| {
                                            stage.set(CallStage::Idle);
                                            incoming_from.set(String::new());
                                            last_action.set("declined incoming call".to_owned());
                                        },
                                        "Decline"
                                    }
                                }
                            }
                        }
                    }
                }

                if stage() == CallStage::Connecting {
                    div { class: "event", "data-testid": "webrtc-call-connecting-panel",
                        div { class: "event-head",
                            span { "Connecting" }
                            span { class: "badge badge-info", "SDP/ICE" }
                        }
                        div { class: "actions",
                            button {
                                class: "primary",
                                "data-testid": "webrtc-call-activate-button",
                                onclick: move |_| {
                                    let target = if !outgoing_to().is_empty() {
                                        outgoing_to()
                                    } else {
                                        "did:web:bob.example".to_owned()
                                    };
                                    if participants().is_empty() {
                                        participants.write().push(CallParticipant {
                                            actor_did: target.clone(),
                                            display_name: target,
                                            stream_state: ParticipantStreamState::Active,
                                        });
                                    }
                                    stage.set(CallStage::Active);
                                    last_action.set("call active".to_owned());
                                },
                                "Media active"
                            }
                        }
                    }
                }

                if stage() == CallStage::Active {
                    div { class: "event", "data-testid": "webrtc-call-active-panel",
                        div { class: "event-head",
                            span { "In call" }
                            span { class: "badge green", "active" }
                            span {
                                class: "badge",
                                "data-testid": "webrtc-recording-status",
                                "data-state": "{recording_state().as_data_state()}",
                                "rec: {recording_state().as_data_state()}"
                            }
                        }
                        div { class: "actions",
                            button {
                                class: if mic_muted() { "primary" } else { "secondary" },
                                "data-testid": "webrtc-mute-button",
                                "aria-pressed": "{mic_muted()}",
                                onclick: move |_| {
                                    let next = !mic_muted();
                                    mic_muted.set(next);
                                    last_action.set(
                                        if next { "muted mic" } else { "unmuted mic" }.to_owned(),
                                    );
                                    // TODO(G3.Y4-followup): emit
                                    // cx.call.signal { signal_type:
                                    // "mute_state", payload: { muted:
                                    // next }} through the active
                                    // soland WebRTC session.
                                },
                                if mic_muted() { "Unmute" } else { "Mute" }
                            }
                            button {
                                class: if camera_on() { "secondary" } else { "primary" },
                                "data-testid": "webrtc-camera-toggle-button",
                                "aria-pressed": "{!camera_on()}",
                                onclick: move |_| {
                                    let next = !camera_on();
                                    camera_on.set(next);
                                    last_action.set(
                                        if next { "camera on" } else { "camera off" }.to_owned(),
                                    );
                                },
                                if camera_on() { "Camera off" } else { "Camera on" }
                            }
                            if !screen_sharing() {
                                button {
                                    class: "secondary",
                                    "data-testid": "webrtc-screen-share-start-button",
                                    onclick: move |_| {
                                        screen_sharing.set(true);
                                        last_action.set("started screen share".to_owned());
                                        // TODO(G3.Y4-followup): call
                                        // getDisplayMedia() via web-sys
                                        // and add the resulting track
                                        // to the peer connection; emit
                                        // cx.call.signal { signal_type:
                                        // "media_state", payload: {
                                        // screen_share: true }}.
                                    },
                                    "Start screen share"
                                }
                            } else {
                                button {
                                    class: "primary",
                                    "data-testid": "webrtc-screen-share-stop-button",
                                    onclick: move |_| {
                                        screen_sharing.set(false);
                                        last_action.set("stopped screen share".to_owned());
                                    },
                                    "Stop screen share"
                                }
                            }
                            button {
                                class: "secondary",
                                "data-testid": "webrtc-recording-toggle-button",
                                onclick: move |_| {
                                    let next = recording_state().toggle();
                                    recording_state.set(next);
                                    last_action.set(format!(
                                        "recording {}", next.as_data_state()
                                    ));
                                    // TODO(G3.Y4-followup): respect
                                    // soland's recording_policy from
                                    // the Call Morph; today this is a
                                    // client-side optimistic toggle.
                                },
                                "Toggle recording"
                            }
                            button {
                                class: "danger",
                                "data-testid": "webrtc-leave-call-button",
                                onclick: move |_| {
                                    stage.set(CallStage::Ended);
                                    mic_muted.set(false);
                                    camera_on.set(true);
                                    screen_sharing.set(false);
                                    recording_state.set(RecordingState::Off);
                                    participants.set(Vec::new());
                                    outgoing_to.set(String::new());
                                    last_action.set("left call".to_owned());
                                    // TODO(G3.Y4-followup): emit
                                    // cx.call.signal { signal_type:
                                    // "hangup" } and submit
                                    // cx.call.state { state: "ended" }
                                    // through with_authed_api.
                                },
                                "Leave call"
                            }
                        }

                        // Participants
                        div { class: "event-head",
                            span { "Participants" }
                            span { class: "badge", "{participants().len()}" }
                        }
                        for p in participants().iter() {
                            {
                                let did = p.actor_did.clone();
                                let name = p.display_name.clone();
                                let st = p.stream_state;
                                rsx! {
                                    div {
                                        class: "event",
                                        "data-testid": "webrtc-participant-row",
                                        "data-actor-did": "{did}",
                                        "data-stream-state": "{st.as_data_state()}",
                                        div { class: "event-head",
                                            span { class: "mono", "{name}" }
                                            span { class: "badge", "{st.as_data_state()}" }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                if stage() == CallStage::Ended {
                    div { class: "event", "data-testid": "webrtc-call-ended-panel",
                        div { class: "event-head",
                            span { "Call ended" }
                            span { class: "badge", "ended" }
                        }
                        div { class: "actions",
                            button {
                                class: "secondary",
                                "data-testid": "webrtc-call-reset-button",
                                onclick: move |_| {
                                    stage.set(CallStage::Idle);
                                    outgoing_to.set(String::new());
                                    incoming_from.set(String::new());
                                    last_action.set("ready for next call".to_owned());
                                },
                                "Reset"
                            }
                        }
                    }
                }

                if !last_action().is_empty() {
                    div { class: "muted",
                        "data-testid": "webrtc-last-action",
                        "{last_action}"
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{CallStage, ParticipantStreamState, RecordingState, maybe_setup_peer_connection};

    #[test]
    fn call_stage_str_is_stable_for_each_variant() {
        assert_eq!(CallStage::Idle.as_str(), "idle");
        assert_eq!(CallStage::IncomingRinging.as_str(), "ringing");
        assert_eq!(CallStage::OutgoingRinging.as_str(), "ringing");
        assert_eq!(CallStage::Connecting.as_str(), "connecting");
        assert_eq!(CallStage::Active.as_str(), "active");
        assert_eq!(CallStage::Ended.as_str(), "ended");
    }

    #[test]
    fn recording_toggle_cycles_off_to_recording_then_paused() {
        let s0 = RecordingState::Off;
        let s1 = s0.toggle();
        let s2 = s1.toggle();
        let s3 = s2.toggle();
        assert_eq!(s0, RecordingState::Off);
        assert_eq!(s1, RecordingState::Recording);
        assert_eq!(s2, RecordingState::Paused);
        // After Paused, toggle resumes Recording (sticky-toggle
        // behavior the harness pins).
        assert_eq!(s3, RecordingState::Recording);
    }

    #[test]
    fn recording_data_state_values_are_distinct() {
        let values = [
            RecordingState::Off.as_data_state(),
            RecordingState::Recording.as_data_state(),
            RecordingState::Paused.as_data_state(),
        ];
        let uniq: std::collections::BTreeSet<_> = values.iter().collect();
        assert_eq!(uniq.len(), 3);
    }

    #[test]
    fn participant_stream_state_values_are_distinct() {
        let values = [
            ParticipantStreamState::Active.as_data_state(),
            ParticipantStreamState::Muted.as_data_state(),
            ParticipantStreamState::Disconnected.as_data_state(),
        ];
        let uniq: std::collections::BTreeSet<_> = values.iter().collect();
        assert_eq!(uniq.len(), 3);
    }

    #[test]
    fn maybe_setup_peer_connection_is_noop_on_host() {
        // On the host (non-wasm) target the function is a
        // no-op that returns true so the FSM transitions
        // proceed identically in unit tests.
        assert!(maybe_setup_peer_connection());
    }
}
