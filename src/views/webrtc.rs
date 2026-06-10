//! WebRTC call surface for 1:1 and SFU calls.
//!
//! Spec anchors: `crypto-media/webrtc-signaling.md` sections 2-8.

use std::collections::BTreeSet;

use dioxus::prelude::*;
use serde_json::{Value, json};

use crate::local_state::LocalStateStore;
use crate::ui::button::{Button, ButtonVariant};
use crate::ui::input::Input;
use crate::ui::label::Label;
use crate::ui::textarea::Textarea;
use crate::views::helpers::{short_protocol_id, with_authed_api};

pub fn live_media_enabled() -> bool {
    cfg!(feature = "experimental-webrtc")
}

/// Client-side call lifecycle FSM. Soland owns the participant-scoped
/// `call_state`; this enum keeps the UI panels and testids stable.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CallStage {
    Idle,
    IncomingRinging,
    OutgoingRinging,
    Connecting,
    Active,
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

    /// `Off -> Recording -> Paused -> Recording` matches the sticky-toggle
    /// behavior pinned by the browser harness.
    pub fn toggle(self) -> Self {
        match self {
            RecordingState::Off => RecordingState::Recording,
            RecordingState::Recording => RecordingState::Paused,
            RecordingState::Paused => RecordingState::Recording,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CallParticipant {
    pub actor_id: String,
    pub display_name: String,
    pub stream_state: ParticipantStreamState,
    pub screen_sharing: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ParticipantStreamState {
    Active,
    Muted,
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

#[cfg(target_arch = "wasm32")]
fn maybe_setup_peer_connection() -> bool {
    web_sys::window().is_some()
}

#[cfg(not(target_arch = "wasm32"))]
fn maybe_setup_peer_connection() -> bool {
    true
}

#[component]
pub fn WebrtcCallPanel(
    base_url: String,
    token: Signal<String>,
    state_store: Signal<LocalStateStore>,
    selected_realm_id: String,
    account_did: String,
    device_id: String,
) -> Element {
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
                .map(|kind| kind.starts_with("ck.call."))
                .unwrap_or(false)
        })
        .count();

    let selected_realm_seed = selected_realm_id.clone();
    let mut stage = use_signal(|| CallStage::Idle);
    let mut mic_muted = use_signal(|| false);
    let mut camera_on = use_signal(|| true);
    let mut screen_sharing = use_signal(|| false);
    let mut recording_state = use_signal(|| RecordingState::Off);
    let mut participants = use_signal(Vec::<CallParticipant>::new);
    let mut incoming_from = use_signal(String::new);
    let mut outgoing_to = use_signal(String::new);
    let mut last_action = use_signal(String::new);
    let mut call_realm_id = use_signal(move || selected_realm_seed.clone());
    let mut peer_did = use_signal(|| "did:web:bob.example".to_owned());
    let mut group_participants_input =
        use_signal(|| "did:web:bob.example\ndid:web:carol.example".to_owned());
    let mut active_session_id = use_signal(String::new);
    let mut call_seq = use_signal(|| 0_u64);
    let mut call_mode = use_signal(|| "p2p".to_owned());
    let mut recording_policy = use_signal(|| "none".to_owned());
    let mut signal_status = use_signal(|| "ready".to_owned());
    let mut recording_blob_ref = use_signal(String::new);

    let account_label = short_protocol_id(&account_did);
    let device_label = short_protocol_id(&device_id);
    let can_record = recording_policy() == "allow";

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
                    span {
                        class: "badge",
                        "data-testid": "webrtc-call-mode",
                        "data-mode": "{call_mode}",
                        "{call_mode}"
                    }
                    span {
                        class: "badge",
                        "data-testid": "webrtc-recording-policy",
                        "data-policy": "{recording_policy}",
                        "recording {recording_policy}"
                    }
                }
                div { class: "event-head",
                    span {
                        class: "mono",
                        "data-testid": "webrtc-session-id",
                        "data-session-id": "{active_session_id}",
                        if active_session_id().is_empty() { "no call session" } else { "{active_session_id}" }
                    }
                    span { class: "mono", title: "{account_did}", "{account_label}" }
                    span { class: "mono", title: "{device_id}", "{device_label}" }
                }

                if stage() == CallStage::Idle {
                    div { class: "event", "data-testid": "webrtc-call-config",
                        Label { html_for: "webrtc-realm-id-input-input", "Realm" }
                        Input {
                            id: "webrtc-realm-id-input-input",
                            "data-testid": "webrtc-realm-id-input",
                            value: "{call_realm_id}",
                            placeholder: "ck:realm:...",
                            oninput: move |event: FormEvent| call_realm_id.set(event.value()),
                        }
                        Label { html_for: "webrtc-peer-did-input-input", "Peer" }
                        Input {
                            id: "webrtc-peer-did-input-input",
                            "data-testid": "webrtc-peer-did-input",
                            value: "{peer_did}",
                            placeholder: "did:web:bob.example",
                            oninput: move |event: FormEvent| peer_did.set(event.value()),
                        }
                        Label { html_for: "webrtc-group-participants-input-input", "Group participants" }
                        Textarea {
                            id: "webrtc-group-participants-input-input",
                            "data-testid": "webrtc-group-participants-input",
                            value: "{group_participants_input}",
                            oninput: move |event: FormEvent| group_participants_input.set(event.value()),
                        }
                        div { class: "actions",
                            Button {
                                variant: ButtonVariant::Primary,
                                "data-testid": "webrtc-call-start-button",
                                disabled: call_realm_id.read().trim().is_empty() || peer_did.read().trim().is_empty(),
                                onclick: {
                                    let base = base_url.clone();
                                    let actor = account_did.clone();
                                    let device = device_id.clone();
                                    move |_| {
                                        let _ok = maybe_setup_peer_connection();
                                        let base = base.clone();
                                        let api_token = token();
                                        let actor = actor.clone();
                                        let device = device.clone();
                                        let realm_id = call_realm_id().trim().to_owned();
                                        let peer = peer_did().trim().to_owned();
                                        outgoing_to.set(peer.clone());
                                        active_session_id.set(String::new());
                                        call_seq.set(0);
                                        call_mode.set("p2p".to_owned());
                                        recording_policy.set("none".to_owned());
                                        recording_state.set(RecordingState::Off);
                                        recording_blob_ref.set(String::new());
                                        stage.set(CallStage::OutgoingRinging);
                                        last_action.set("started 1:1 call".to_owned());
                                        signal_status.set("creating call session".to_owned());
                                        let mut active_session_id = active_session_id;
                                        let mut signal_status = signal_status;
                                        spawn(async move {
                                            match create_live_session(
                                                base,
                                                api_token,
                                                realm_id,
                                                actor.clone(),
                                                device.clone(),
                                                vec![peer],
                                            )
                                            .await
                                            {
                                                Ok(call_id) => {
                                                    active_session_id.set(call_id.clone());
                                                    signal_status.set(format!(
                                                        "call {call_id} ringing"
                                                    ));
                                                }
                                                Err(err) if actor.trim().is_empty() || device.trim().is_empty() => {
                                                    signal_status.set(format!("local-only: {err}"));
                                                }
                                                Err(err) => signal_status.set(format!("error {err}")),
                                            }
                                        });
                                    }
                                },
                                "Start 1:1 call"
                            }
                            Button {
                                variant: ButtonVariant::Secondary,
                                "data-testid": "webrtc-group-call-start-button",
                                disabled: call_realm_id.read().trim().is_empty(),
                                onclick: {
                                    let base = base_url.clone();
                                    let actor = account_did.clone();
                                    let device = device_id.clone();
                                    move |_| {
                                        let _ok = maybe_setup_peer_connection();
                                        let base = base.clone();
                                        let api_token = token();
                                        let actor = actor.clone();
                                        let device = device.clone();
                                        let realm_id = call_realm_id().trim().to_owned();
                                        let peers = participant_list_from_input(&group_participants_input());
                                        active_session_id.set(String::new());
                                        call_seq.set(0);
                                        call_mode.set("sfu".to_owned());
                                        recording_policy.set("allow".to_owned());
                                        recording_state.set(RecordingState::Off);
                                        recording_blob_ref.set(String::new());
                                        participants.set(build_roster(&actor, &peers));
                                        stage.set(CallStage::Active);
                                        last_action.set("started group call".to_owned());
                                        signal_status.set("creating sfu call session".to_owned());
                                        let mut active_session_id = active_session_id;
                                        let mut signal_status = signal_status;
                                        let roster_len = peers.len();
                                        spawn(async move {
                                            match create_live_session(
                                                base,
                                                api_token,
                                                realm_id,
                                                actor.clone(),
                                                device.clone(),
                                                peers,
                                            )
                                            .await
                                            {
                                                Ok(call_id) => {
                                                    active_session_id.set(call_id.clone());
                                                    signal_status.set(format!(
                                                        "call {call_id} active roster {roster_len}"
                                                    ));
                                                }
                                                Err(err) if actor.trim().is_empty() || device.trim().is_empty() => {
                                                    signal_status.set(format!("local-only: {err}"));
                                                }
                                                Err(err) => signal_status.set(format!("error {err}")),
                                            }
                                        });
                                    }
                                },
                                "Start group call"
                            }
                            Button {
                                variant: ButtonVariant::Secondary,
                                "data-testid": "webrtc-simulate-incoming-button",
                                onclick: move |_| {
                                    incoming_from.set(peer_did().trim().to_owned());
                                    stage.set(CallStage::IncomingRinging);
                                    last_action.set("simulated incoming call".to_owned());
                                },
                                "Simulate incoming"
                            }
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
                                    Button {
                                        variant: ButtonVariant::Primary,
                                        "data-testid": "webrtc-call-connect-button",
                                        onclick: {
                                            let base = base_url.clone();
                                            let actor = account_did.clone();
                                            let device = device_id.clone();
                                            move |_| {
                                                stage.set(CallStage::Connecting);
                                                last_action.set("signaling connected".to_owned());
                                                emit_signal_from_ui(
                                                    base.clone(),
                                                    token(),
                                                    call_realm_id(),
                                                    active_session_id(),
                                                    actor.clone(),
                                                    device.clone(),
                                                    "invite".to_owned(),
                                                    json!({ "target": outgoing_to() }),
                                                    call_seq,
                                                    signal_status,
                                                );
                                            }
                                        },
                                        "Connect"
                                    }
                                    Button {
                                        variant: ButtonVariant::Destructive,
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
                        let actor_for_accept = account_did.clone();
                        rsx! {
                            div { class: "event",
                                "data-testid": "webrtc-incoming-call-banner",
                                role: "alert",
                                div { class: "event-head",
                                    span { "Incoming call" }
                                    span { class: "mono", title: "{incoming_from_value}", "{incoming_from_label}" }
                                }
                                div { class: "actions",
                                    Button {
                                        variant: ButtonVariant::Primary,
                                        "data-testid": "webrtc-call-accept-button",
                                        onclick: move |_| {
                                            let _ok = maybe_setup_peer_connection();
                                            let peer = incoming_from();
                                            participants.set(build_roster(&actor_for_accept, &[peer]));
                                            stage.set(CallStage::Connecting);
                                            incoming_from.set(String::new());
                                            last_action.set("accepted incoming call".to_owned());
                                        },
                                        "Accept"
                                    }
                                    Button {
                                        variant: ButtonVariant::Destructive,
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
                            Button {
                                variant: ButtonVariant::Primary,
                                "data-testid": "webrtc-call-activate-button",
                                onclick: {
                                    let base = base_url.clone();
                                    let actor = account_did.clone();
                                    let device = device_id.clone();
                                    move |_| {
                                        let target = if !outgoing_to().is_empty() {
                                            outgoing_to()
                                        } else {
                                            peer_did()
                                        };
                                        participants.set(build_roster(&actor, std::slice::from_ref(&target)));
                                        stage.set(CallStage::Active);
                                        last_action.set("call active".to_owned());
                                        emit_signal_from_ui(
                                            base.clone(),
                                            token(),
                                            call_realm_id(),
                                            active_session_id(),
                                            actor.clone(),
                                            device.clone(),
                                            "answer".to_owned(),
                                            json!({ "target": target }),
                                            call_seq,
                                            signal_status,
                                        );
                                    }
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
                                "data-testid": "webrtc-local-mic-status",
                                "data-muted": "{mic_muted()}",
                                if mic_muted() { "mic muted" } else { "mic live" }
                            }
                            span {
                                class: "badge",
                                "data-testid": "webrtc-screen-share-status",
                                "data-state": if screen_sharing() { "sharing" } else { "off" },
                                if screen_sharing() { "screen sharing" } else { "screen off" }
                            }
                            span {
                                class: "badge",
                                "data-testid": "webrtc-recording-status",
                                "data-state": "{recording_state().as_data_state()}",
                                "rec: {recording_state().as_data_state()}"
                            }
                        }
                        if recording_state() == RecordingState::Recording {
                            div { class: "event", "data-testid": "webrtc-recording-indicator",
                                span { class: "badge danger", "recording" }
                                span {
                                    class: "mono",
                                    "data-testid": "webrtc-recording-blob-ref",
                                    "{recording_blob_ref}"
                                }
                            }
                        }
                        div { class: "actions",
                            Button {
                                variant: if mic_muted() { ButtonVariant::Primary } else { ButtonVariant::Secondary },
                                "data-testid": "webrtc-mute-button",
                                "aria-pressed": "{mic_muted()}",
                                onclick: {
                                    let base = base_url.clone();
                                    let actor = account_did.clone();
                                    let device = device_id.clone();
                                    move |_| {
                                        let next = !mic_muted();
                                        mic_muted.set(next);
                                        set_participant_state(
                                            &mut participants,
                                            &actor,
                                            if next {
                                                ParticipantStreamState::Muted
                                            } else {
                                                ParticipantStreamState::Active
                                            },
                                        );
                                        last_action.set(
                                            if next { "muted mic" } else { "unmuted mic" }.to_owned(),
                                        );
                                        emit_signal_from_ui(
                                            base.clone(),
                                            token(),
                                            call_realm_id(),
                                            active_session_id(),
                                            actor.clone(),
                                            device.clone(),
                                            "mute_state".to_owned(),
                                            json!({ "muted": next }),
                                            call_seq,
                                            signal_status,
                                        );
                                    }
                                },
                                if mic_muted() { "Unmute" } else { "Mute" }
                            }
                            Button {
                                variant: if camera_on() { ButtonVariant::Secondary } else { ButtonVariant::Primary },
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
                                Button {
                                    variant: ButtonVariant::Secondary,
                                    "data-testid": "webrtc-screen-share-start-button",
                                    onclick: {
                                        let base = base_url.clone();
                                        let actor = account_did.clone();
                                        let device = device_id.clone();
                                        move |_| {
                                            screen_sharing.set(true);
                                            set_participant_screen(&mut participants, &actor, true);
                                            last_action.set("started screen share".to_owned());
                                            emit_signal_from_ui(
                                                base.clone(),
                                                token(),
                                                call_realm_id(),
                                                active_session_id(),
                                                actor.clone(),
                                                device.clone(),
                                                "media_state".to_owned(),
                                                json!({ "screen_share": true }),
                                                call_seq,
                                                signal_status,
                                            );
                                        }
                                    },
                                    "Start screen share"
                                }
                            } else {
                                Button {
                                    variant: ButtonVariant::Primary,
                                    "data-testid": "webrtc-screen-share-stop-button",
                                    onclick: {
                                        let base = base_url.clone();
                                        let actor = account_did.clone();
                                        let device = device_id.clone();
                                        move |_| {
                                            screen_sharing.set(false);
                                            set_participant_screen(&mut participants, &actor, false);
                                            last_action.set("stopped screen share".to_owned());
                                            emit_signal_from_ui(
                                                base.clone(),
                                                token(),
                                                call_realm_id(),
                                                active_session_id(),
                                                actor.clone(),
                                                device.clone(),
                                                "media_state".to_owned(),
                                                json!({ "screen_share": false }),
                                                call_seq,
                                                signal_status,
                                            );
                                        }
                                    },
                                    "Stop screen share"
                                }
                            }
                            Button {
                                variant: ButtonVariant::Secondary,
                                "data-testid": "webrtc-recording-toggle-button",
                                disabled: !can_record && recording_state() == RecordingState::Off,
                                onclick: {
                                    let base = base_url.clone();
                                    let actor = account_did.clone();
                                    move |_| {
                                        if recording_state() == RecordingState::Off && recording_policy() == "allow" {
                                            signal_status.set("starting recording".to_owned());
                                            let base = base.clone();
                                            let api_token = token();
                                            let call_id = active_session_id();
                                            let realm_id = call_realm_id();
                                            let actor = actor.clone();
                                            let consent_actors: Vec<String> = participants()
                                                .iter()
                                                .map(|p| p.actor_id.clone())
                                                .collect();
                                            let mut recording_state = recording_state;
                                            let mut signal_status = signal_status;
                                            let mut last_action = last_action;
                                            spawn(async move {
                                                match start_live_recording(base, api_token, realm_id, actor, call_id, consent_actors).await {
                                                    Ok(recording_id) => {
                                                        recording_state.set(RecordingState::Recording);
                                                        signal_status.set(format!(
                                                            "recording {recording_id}"
                                                        ));
                                                        last_action.set("recording started".to_owned());
                                                    }
                                                    Err(err) => signal_status.set(format!("error {err}")),
                                                }
                                            });
                                        } else {
                                            let next = recording_state().toggle();
                                            recording_state.set(next);
                                            last_action.set(format!("recording {}", next.as_data_state()));
                                        }
                                    }
                                },
                                "Toggle recording"
                            }
                            Button {
                                variant: ButtonVariant::Destructive,
                                "data-testid": "webrtc-leave-call-button",
                                onclick: {
                                    let base = base_url.clone();
                                    let actor = account_did.clone();
                                    let device = device_id.clone();
                                    move |_| {
                                        emit_signal_from_ui(
                                            base.clone(),
                                            token(),
                                            call_realm_id(),
                                            active_session_id(),
                                            actor.clone(),
                                            device.clone(),
                                            "hangup".to_owned(),
                                            json!({ "reason": "user_hangup" }),
                                            call_seq,
                                            signal_status,
                                        );
                                        stage.set(CallStage::Ended);
                                        mic_muted.set(false);
                                        camera_on.set(true);
                                        screen_sharing.set(false);
                                        recording_state.set(RecordingState::Off);
                                        set_all_participants_disconnected(&mut participants);
                                        outgoing_to.set(String::new());
                                        last_action.set("left call".to_owned());
                                    }
                                },
                                "Leave call"
                            }
                        }
                        if !can_record {
                            div {
                                class: "muted",
                                "data-testid": "webrtc-recording-disabled-reason",
                                "recording policy none"
                            }
                        }
                        if screen_sharing() {
                            div { class: "event", "data-testid": "webrtc-screen-share-preview",
                                "Screen share"
                            }
                        }
                        div { class: "event-head",
                            span { "Participants" }
                            span {
                                class: "badge",
                                "data-testid": "webrtc-roster-count",
                                "{participants().len()}"
                            }
                        }
                        for p in participants().iter() {
                            {
                                let did = p.actor_id.clone();
                                let name = p.display_name.clone();
                                let st = p.stream_state;
                                let sharing = p.screen_sharing;
                                rsx! {
                                    div {
                                        class: "event",
                                        "data-testid": "webrtc-participant-row",
                                        "data-actor-did": "{did}",
                                        "data-stream-state": "{st.as_data_state()}",
                                        "data-screen-sharing": "{sharing}",
                                        div { class: "event-head",
                                            span { class: "mono", "{name}" }
                                            span { class: "badge", "{st.as_data_state()}" }
                                            if sharing {
                                                span { class: "badge badge-info", "screen" }
                                            }
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
                            Button {
                                variant: ButtonVariant::Secondary,
                                "data-testid": "webrtc-call-reset-button",
                                onclick: move |_| {
                                    stage.set(CallStage::Idle);
                                    active_session_id.set(String::new());
                                    call_seq.set(0);
                                    participants.set(Vec::new());
                                    outgoing_to.set(String::new());
                                    incoming_from.set(String::new());
                                    last_action.set("ready for next call".to_owned());
                                },
                                "Reset"
                            }
                        }
                    }
                }

                div {
                    class: "muted",
                    "data-testid": "webrtc-signal-status",
                    "{signal_status}"
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

fn participant_list_from_input(input: &str) -> Vec<String> {
    let mut seen = BTreeSet::new();
    input
        .split(['\n', ',', ';'])
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .filter(|value| seen.insert((*value).to_owned()))
        .map(ToOwned::to_owned)
        .collect()
}

fn build_roster(actor: &str, peers: &[String]) -> Vec<CallParticipant> {
    let mut ids = BTreeSet::new();
    let mut roster = Vec::new();
    for did in std::iter::once(actor).chain(peers.iter().map(String::as_str)) {
        let did = did.trim();
        if did.is_empty() || !ids.insert(did.to_owned()) {
            continue;
        }
        roster.push(CallParticipant {
            actor_id: did.to_owned(),
            display_name: short_protocol_id(did),
            stream_state: ParticipantStreamState::Active,
            screen_sharing: false,
        });
    }
    roster
}

fn set_participant_state(
    participants: &mut Signal<Vec<CallParticipant>>,
    actor: &str,
    state: ParticipantStreamState,
) {
    let mut roster = participants();
    for participant in &mut roster {
        if participant.actor_id == actor {
            participant.stream_state = state;
        }
    }
    participants.set(roster);
}

fn set_participant_screen(
    participants: &mut Signal<Vec<CallParticipant>>,
    actor: &str,
    sharing: bool,
) {
    let mut roster = participants();
    for participant in &mut roster {
        if participant.actor_id == actor {
            participant.screen_sharing = sharing;
        }
    }
    participants.set(roster);
}

fn set_all_participants_disconnected(participants: &mut Signal<Vec<CallParticipant>>) {
    let mut roster = participants();
    for participant in &mut roster {
        participant.stream_state = ParticipantStreamState::Disconnected;
        participant.screen_sharing = false;
    }
    participants.set(roster);
}

#[allow(clippy::too_many_arguments)]
fn emit_signal_from_ui(
    base: String,
    api_token: String,
    realm_id: String,
    call_id: String,
    actor: String,
    device: String,
    signal_type: String,
    data: Value,
    mut call_seq: Signal<u64>,
    mut signal_status: Signal<String>,
) {
    if call_id.trim().is_empty() || realm_id.trim().is_empty() {
        signal_status.set(format!("local-only {signal_type}"));
        return;
    }
    let seq = call_seq() + 1;
    call_seq.set(seq);
    signal_status.set(format!("sending {signal_type} #{seq}"));
    spawn(async move {
        match emit_live_signal(
            base,
            api_token,
            realm_id,
            call_id,
            actor,
            device,
            signal_type.clone(),
            seq,
            data,
        )
        .await
        {
            Ok(()) => {
                signal_status.set(format!("signal {signal_type} #{seq} accepted"));
            }
            Err(err) => signal_status.set(format!("error {err}")),
        }
    });
}

/// Open a call: per spec there is no session-create endpoint — the client
/// mints the `call_id` and the `invite` `ck.call.signal` IS the call
/// initiation. Returns the minted `call_id`.
async fn create_live_session(
    base: String,
    api_token: String,
    realm_id: String,
    actor: String,
    device: String,
    participants: Vec<String>,
) -> Result<String, String> {
    let call_id = format!("ck:call:{}", crate::operation::uuid_v7());
    let invite = call_id.clone();
    let invite_realm = realm_id.clone();
    with_authed_api(&base, api_token, |api| async move {
        api.submit_call_signal_v1(
            &invite_realm,
            &actor,
            &device,
            &invite,
            "invite",
            1,
            json!({ "participants": participants }),
        )
        .await
    })
    .await
    .map_err(|err| err.display())?;
    Ok(call_id)
}

async fn emit_live_signal(
    base: String,
    api_token: String,
    realm_id: String,
    call_id: String,
    actor: String,
    device: String,
    signal_type: String,
    seq: u64,
    data: Value,
) -> Result<(), String> {
    with_authed_api(&base, api_token, |api| async move {
        api.submit_call_signal_v1(
            &realm_id,
            &actor,
            &device,
            &call_id,
            &signal_type,
            seq,
            data,
        )
        .await
    })
    .await
    .map(|_| ())
    .map_err(|err| err.display())
}

/// Start opt-in recording by writing the durable `ck.call.recording.start`
/// event. Returns the minted `recording_id`.
async fn start_live_recording(
    base: String,
    api_token: String,
    realm_id: String,
    actor: String,
    call_id: String,
    consent_actors: Vec<String>,
) -> Result<String, String> {
    let recording_id = format!("ck:recording:{}", crate::operation::uuid_v7());
    let rec = recording_id.clone();
    with_authed_api(&base, api_token, |api| async move {
        api.submit_call_recording_start(&realm_id, &actor, &call_id, &rec, consent_actors)
            .await
    })
    .await
    .map_err(|err| err.display())?;
    Ok(recording_id)
}

#[cfg(test)]
mod tests {
    use super::{
        CallStage, ParticipantStreamState, RecordingState, build_roster,
        maybe_setup_peer_connection, participant_list_from_input,
    };

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
    fn participant_input_dedupes_common_separators() {
        assert_eq!(
            participant_list_from_input(
                "did:web:bob.example\ndid:web:carol.example, did:web:bob.example"
            ),
            vec!["did:web:bob.example", "did:web:carol.example"]
        );
    }

    #[test]
    fn roster_includes_actor_and_peers_once() {
        let roster = build_roster(
            "did:web:alice.example",
            &[
                "did:web:bob.example".to_owned(),
                "did:web:alice.example".to_owned(),
            ],
        );
        assert_eq!(roster.len(), 2);
        assert_eq!(roster[0].actor_id, "did:web:alice.example");
        assert_eq!(roster[1].actor_id, "did:web:bob.example");
    }

    #[test]
    fn maybe_setup_peer_connection_is_noop_on_host() {
        assert!(maybe_setup_peer_connection());
    }
}
