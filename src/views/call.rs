//! Production call surface — voice / video / conference.
//!
//! This panel drives the full media plane: token exchange + ICE config +
//! MLS-exporter SFrame keying (`crate::media::rtc::join_call_media`), the
//! platform WebRTC transport (`crate::rtc_transport`), and the call FSM
//! (idle → ringing → connecting → active → ended). It handles both the 1:1
//! P2P path (offer/answer/candidate relayed over `ck.call.signal`) and SFU
//! group calls (room join + participant cross-check), plus moderator
//! controls and opt-in recording.

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::rc::Rc;

use dioxus::prelude::*;
use serde_json::{Value, json};

use crate::local_state::LocalStateStore;
use crate::media::rtc::{
    DesiredMedia, JoinedMediaSession, MediaJoinRequest, PerSenderFrameKeys, RtcClientError,
};
use crate::rtc_transport::{LocalSignal, MediaTransport, new_transport};
use crate::ui::button::{Button, ButtonVariant};
use crate::views::call_signals::{CallSignalHub, CallSignalInboxItem};
use crate::views::helpers::{short_protocol_id, with_authed_api};

/// Client-side call lifecycle FSM.
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

/// Recording marker.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecordingState {
    Off,
    Recording,
}

impl RecordingState {
    pub fn as_data_state(self) -> &'static str {
        match self {
            RecordingState::Off => "off",
            RecordingState::Recording => "recording",
        }
    }
}

/// Roster entry for the participant grid.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CallParticipant {
    pub actor_id: String,
    pub display_name: String,
    pub muted: bool,
    pub speaking: bool,
    pub screen_sharing: bool,
}

/// Boxed platform transport kept behind `Rc<RefCell<…>>` so the
/// component can drive its synchronous methods from event handlers while
/// the `!Send` JS handles (wasm) stay on the single UI task.
type SharedTransport = Rc<RefCell<Box<dyn MediaTransport>>>;

#[derive(Clone, Copy, PartialEq)]
enum CallMode {
    P2p,
    Sfu,
}

#[component]
#[allow(clippy::too_many_arguments)]
pub fn CallPanel(
    base_url: String,
    token: Signal<String>,
    state_store: Signal<LocalStateStore>,
    selected_realm_id: String,
    account_did: String,
    device_id: String,
    /// Deep-linked call id (`ck:call:…`); empty when the user opens the
    /// dialer fresh.
    #[props(default)]
    call_id: String,
    /// 1:1 callee DID; empty for an SFU group call.
    #[props(default)]
    peer: String,
    /// Start with video enabled.
    #[props(default)]
    want_video: bool,
    /// This surface was opened to answer an inbound ring.
    #[props(default)]
    incoming: bool,
) -> Element {
    let initial_stage = if incoming {
        CallStage::IncomingRinging
    } else if !call_id.is_empty() {
        CallStage::OutgoingRinging
    } else {
        CallStage::Idle
    };

    let mut stage = use_signal(|| initial_stage);
    let mut status = use_signal(String::new);
    let mut last_error = use_signal(String::new);
    let mut mic_muted = use_signal(|| false);
    let mut camera_on = use_signal(|| want_video);
    let mut screen_sharing = use_signal(|| false);
    let mut recording = use_signal(|| RecordingState::Off);
    let mut participants = use_signal(Vec::<CallParticipant>::new);
    let mut active_call_id = use_signal(|| call_id.clone());
    let mut call_seq = use_signal(|| 0_u64);
    let mut active_realm = use_signal(|| selected_realm_id.clone());
    let mut peer_input = use_signal(|| peer.clone());
    let mut group_input = use_signal(|| "did:web:bob.example\ndid:web:carol.example".to_owned());
    let mut want_video_signal = use_signal(|| want_video);

    // Transport handle — `None` until a media session is joined.
    let transport = use_signal(|| Option::<SharedTransport>::None);
    let mut transport_handle = transport;

    // Receive side: the app-level signaling hub (`crate::views::call_signals`)
    // the sync apply paths feed inbound `ck.call.signal` envelopes into. The
    // drain effect below consumes this call's inbox and applies each item to
    // the transport / FSM. Best-effort: `None` under isolated unit renders.
    let call_signal_hub = CallSignalHub::try_use();

    // This panel now owns an active session for `call_id` (deep-link / dialer
    // start / accept). Mark it active so a re-delivered `invite` does not
    // raise a duplicate ring, and clear any pending incoming-ring state for it.
    if let Some(mut hub) = call_signal_hub {
        let owned = active_call_id();
        use_effect(move || {
            let id = active_call_id();
            if !id.trim().is_empty() {
                hub.mark_active(&id);
            }
        });
        let _ = owned;
    }

    // Release hub per-call state (inbox + active flag + pending ring) when
    // the call ends, regardless of which path ended it (Leave / Decline /
    // Cancel / inbound hangup / reset). Keeps the hub from leaking inbox
    // entries across calls.
    if let Some(mut hub) = call_signal_hub {
        use_effect(move || {
            if stage() == CallStage::Ended {
                let id = active_call_id();
                if !id.trim().is_empty() {
                    hub.forget_call(&id);
                }
            }
        });
    }

    // Drain effect — consume this call's inbox and drive the transport / FSM.
    // Re-runs whenever the hub inbox or the active call id changes. Each item
    // is removed as it is consumed (`drain_call`). Reads of the inbox `Signal`
    // inside the effect subscribe it to inbox mutations the sync path makes.
    if let Some(mut hub) = call_signal_hub {
        let base = base_url.clone();
        let actor = account_did.clone();
        let device = device_id.clone();
        use_effect(move || {
            let call = active_call_id();
            // Subscribe to inbox changes for this call id.
            let has_pending = hub
                .inbox
                .read()
                .get(&call)
                .map(|q| !q.is_empty())
                .unwrap_or(false);
            if call.trim().is_empty() || !has_pending {
                return;
            }
            let items = hub.drain_call(&call);
            if items.is_empty() {
                return;
            }
            apply_inbox_items(
                items,
                transport,
                base.clone(),
                token,
                actor.clone(),
                device.clone(),
                active_realm(),
                call,
                call_seq,
                stage,
                status,
                last_error,
                participants,
            );
        });
    }

    let account_label = short_protocol_id(&account_did);
    let device_label = short_protocol_id(&device_id);

    let observed_signals = state_store
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

    // ── Start an outgoing call (1:1 or SFU). ─────────────────────────
    let start_call = {
        let base = base_url.clone();
        let actor = account_did.clone();
        let device = device_id.clone();
        move |mode: CallMode| {
            let base = base.clone();
            let actor = actor.clone();
            let device = device.clone();
            let realm_id = active_realm();
            let api_token = token();
            let want_video = want_video_signal();

            let peers: Vec<String> = match mode {
                CallMode::P2p => vec![peer_input().trim().to_owned()]
                    .into_iter()
                    .filter(|p| !p.is_empty())
                    .collect(),
                CallMode::Sfu => participant_list_from_input(&group_input()),
            };

            let call = if active_call_id().is_empty() {
                format!("ck:call:{}", crate::operation::uuid_v7())
            } else {
                active_call_id()
            };
            let (
                media_dids,
                focus_id,
                known_participant_identities,
                known_participant_devices,
                realm_mls_snapshot,
            ) = {
                let store = state_store.read();
                let snapshot = store.load();
                let (media_dids, focus_id) = media_service_selection(&snapshot, &realm_id);
                (
                    media_dids,
                    focus_id,
                    call_state_participant_identities(&snapshot, &realm_id, &call),
                    call_state_participant_device_map(&snapshot, &realm_id, &call),
                    store.mls_snapshot_for(&realm_id),
                )
            };
            active_call_id.set(call.clone());
            call_seq.set(0);
            participants.set(build_roster(&actor, &peers));
            stage.set(CallStage::OutgoingRinging);
            status.set("placing call".to_owned());
            last_error.set(String::new());
            let invite_peers = peers.clone();

            spawn(async move {
                // 1) Invite signal opens the call (ephemeral `ck.call.signal`).
                if matches!(mode, CallMode::P2p) {
                    let invite_data =
                        json!({ "participants": invite_peers.clone(), "video": want_video });
                    if let Err(err) = emit_signal(
                        &base,
                        &api_token,
                        &realm_id,
                        &call,
                        &actor,
                        &device,
                        "invite",
                        1,
                        invite_data,
                    )
                    .await
                    {
                        last_error.set(format!("invite failed: {err}"));
                    }
                    call_seq.set(1);
                }

                // 2) Join the media plane (token + ICE + SFrame key).
                let join = MediaJoinRequest {
                    realm_id: realm_id.clone(),
                    call_id: call.clone(),
                    actor_id: actor.clone(),
                    device_id: device.clone(),
                    focus_id: focus_id.clone(),
                    epoch_id: 0,
                    desired_media: if want_video {
                        DesiredMedia::audio_video()
                    } else {
                        DesiredMedia::audio_only()
                    },
                    media_service_dids: media_dids,
                };
                match join_and_build_transport(
                    &base,
                    &api_token,
                    &join,
                    &actor,
                    &device,
                    realm_mls_snapshot,
                )
                .await
                {
                    Ok((session, shared, per_sender_keys)) => {
                        if let Err(err) = install_and_capture(&shared, &session) {
                            // Transport could not accept the media key (desktop
                            // is honestly not-ready). Surface it and stay out of
                            // any "connected" state.
                            last_error.set(media_error_label(err));
                            stage.set(CallStage::Ended);
                            return;
                        }
                        match mode {
                            CallMode::Sfu => {
                                if let Err(err) = submit_call_state_participant(
                                    &base,
                                    &api_token,
                                    &realm_id,
                                    &call,
                                    &actor,
                                    &device,
                                    "connecting",
                                    "sfu",
                                    &session,
                                )
                                .await
                                {
                                    last_error.set(format!("call state failed: {err}"));
                                    stage.set(CallStage::Ended);
                                    return;
                                }
                                let invite_data = json!({ "participants": invite_peers.clone(), "video": want_video });
                                if let Err(err) = emit_signal(
                                    &base,
                                    &api_token,
                                    &realm_id,
                                    &call,
                                    &actor,
                                    &device,
                                    "invite",
                                    1,
                                    invite_data,
                                )
                                .await
                                {
                                    last_error.set(format!("invite failed: {err}"));
                                }
                                call_seq.set(1);
                                let expected = expected_participant_set(
                                    &known_participant_identities,
                                    &session.participant_identity,
                                );
                                // MEDIA-2: seed the durable participant roster so
                                // the LiveKit `ParticipantConnected` callback can
                                // cross-check SFU identities fail-closed.
                                shared.borrow_mut().set_expected_participants(&expected);
                                // §8.1: hand the per-sender deriver + the durable
                                // identity→device_id map to the transport so each
                                // remote sender's frame key is recomputed and
                                // installed when it connects (receiver decrypt).
                                shared.borrow_mut().set_remote_key_source(
                                    per_sender_keys.clone(),
                                    known_participant_devices.clone(),
                                );
                                if let Err(err) = shared.borrow_mut().connect_sfu(&session) {
                                    last_error.set(media_error_label(err));
                                    stage.set(CallStage::Ended);
                                    return;
                                }
                                let _ = submit_call_state_participant(
                                    &base, &api_token, &realm_id, &call, &actor, &device, "active",
                                    "sfu", &session,
                                )
                                .await;
                                stage.set(CallStage::Active);
                                status.set(format!("joined SFU room ({})", session.backend_type));
                            }
                            CallMode::P2p => {
                                if let Err(err) = shared.borrow_mut().begin_offer() {
                                    last_error.set(media_error_label(err));
                                    stage.set(CallStage::Ended);
                                    return;
                                }
                                relay_local_signals(
                                    &shared, &base, &api_token, &realm_id, &call, &actor, &device,
                                    call_seq,
                                )
                                .await;
                                stage.set(CallStage::Connecting);
                                status.set("offer sent, awaiting answer".to_owned());
                            }
                        }
                        transport_handle.set(Some(shared));
                    }
                    Err(err) => {
                        last_error.set(media_error_label(err));
                        stage.set(CallStage::Ended);
                    }
                }
            });
        }
    };

    rsx! {
        div { class: "timeline", "data-testid": "call-panel", role: "region", "aria-label": "Calls",
            div { class: "event",
                div { class: "event-head",
                    span { "Calls" }
                    span {
                        class: "badge",
                        "data-testid": "call-stage",
                        "data-stage": "{stage().as_str()}",
                        "{stage().as_str()}"
                    }
                    span { class: "mono", "data-testid": "call-signal-count", "{observed_signals}" }
                }
                div { class: "event-head",
                    span {
                        class: "mono",
                        "data-testid": "call-active-id",
                        "data-call-id": "{active_call_id}",
                        if active_call_id().is_empty() { "no active call" } else { "{active_call_id}" }
                    }
                    span { class: "mono", title: "{account_did}", "{account_label}" }
                    span { class: "mono", title: "{device_id}", "{device_label}" }
                }

                // ── Dialer (idle). ───────────────────────────────────
                if stage() == CallStage::Idle {
                    div { class: "event", "data-testid": "call-dialer",
                        label { "Realm" }
                        input {
                            class: "input",
                            "data-testid": "call-realm-input",
                            value: "{active_realm}",
                            oninput: move |e| active_realm.set(e.value()),
                        }
                        label { "Peer (1:1)" }
                        input {
                            class: "input",
                            "data-testid": "call-peer-input",
                            value: "{peer_input}",
                            placeholder: "did:web:bob.example",
                            oninput: move |e| peer_input.set(e.value()),
                        }
                        label { "Group participants (SFU)" }
                        textarea {
                            class: "input",
                            "data-testid": "call-group-input",
                            value: "{group_input}",
                            oninput: move |e| group_input.set(e.value()),
                        }
                        div { class: "actions",
                            Button {
                                variant: ButtonVariant::Secondary,
                                "data-testid": "call-want-video-toggle",
                                "aria-pressed": "{want_video_signal()}",
                                onclick: move |_| {
                                    let next = !want_video_signal();
                                    want_video_signal.set(next);
                                    camera_on.set(next);
                                },
                                if want_video_signal() { "Video: on" } else { "Video: off" }
                            }
                            Button {
                                variant: ButtonVariant::Primary,
                                "data-testid": "call-start-voice-button",
                                disabled: active_realm.read().trim().is_empty() || peer_input.read().trim().is_empty(),
                                onclick: {
                                    let mut start = start_call.clone();
                                    move |_| start(CallMode::P2p)
                                },
                                "Start 1:1 call"
                            }
                            Button {
                                variant: ButtonVariant::Secondary,
                                "data-testid": "call-start-group-button",
                                disabled: active_realm.read().trim().is_empty(),
                                onclick: {
                                    let mut start = start_call.clone();
                                    move |_| start(CallMode::Sfu)
                                },
                                "Start group call"
                            }
                        }
                    }
                }

                // ── Outgoing ring. ───────────────────────────────────
                if stage() == CallStage::OutgoingRinging {
                    div { class: "event", "data-testid": "call-outgoing-banner",
                        div { class: "event-head",
                            span { "Calling" }
                            span { class: "mono", "{short_protocol_id(&peer_input())}" }
                        }
                        div { class: "actions",
                            Button {
                                variant: ButtonVariant::Destructive,
                                "data-testid": "call-cancel-button",
                                onclick: {
                                    let base = base_url.clone();
                                    let actor = account_did.clone();
                                    let device = device_id.clone();
                                    move |_| {
                                        end_call(
                                            &transport, &base, &token(), &active_realm(),
                                            &active_call_id(), &actor, &device, call_seq,
                                        );
                                        stage.set(CallStage::Ended);
                                        status.set("cancelled".to_owned());
                                    }
                                },
                                "Cancel"
                            }
                        }
                    }
                }

                // ── Incoming ring. ───────────────────────────────────
                if stage() == CallStage::IncomingRinging {
                    div { class: "event", "data-testid": "call-incoming-banner", role: "alert",
                        div { class: "event-head",
                            span { "Incoming call" }
                            span { class: "mono", "{short_protocol_id(&peer_input())}" }
                        }
                        div { class: "actions",
                            Button {
                                variant: ButtonVariant::Primary,
                                "data-testid": "call-accept-button",
                                onclick: {
                                    let base = base_url.clone();
                                    let actor = account_did.clone();
                                    let device = device_id.clone();
                                    move |_| {
                                        let base = base.clone();
                                        let actor = actor.clone();
                                        let device = device.clone();
                                        let realm_id = active_realm();
                                        let call = active_call_id();
                                        let api_token = token();
                                        let (
                                            media_dids,
                                            focus_id,
                                            known_participant_identities,
                                            known_participant_devices,
                                            realm_mls_snapshot,
                                        ) = {
                                            let store = state_store.read();
                                            let snapshot = store.load();
                                            let (media_dids, focus_id) =
                                                media_service_selection(&snapshot, &realm_id);
                                            (
                                                media_dids,
                                                focus_id,
                                                call_state_participant_identities(
                                                    &snapshot, &realm_id, &call,
                                                ),
                                                call_state_participant_device_map(
                                                    &snapshot, &realm_id, &call,
                                                ),
                                                store.mls_snapshot_for(&realm_id),
                                            )
                                        };
                                        let want_video = want_video_signal();
                                        stage.set(CallStage::Connecting);
                                        status.set("answering".to_owned());
                                        spawn(async move {
                                            let join = MediaJoinRequest {
                                                realm_id: realm_id.clone(),
                                                call_id: call.clone(),
                                                actor_id: actor.clone(),
                                                device_id: device.clone(),
                                                focus_id: focus_id.clone(),
                                                epoch_id: 0,
                                                desired_media: if want_video { DesiredMedia::audio_video() } else { DesiredMedia::audio_only() },
                                                media_service_dids: media_dids,
                                            };
                                            match join_and_build_transport(
                                                &base,
                                                &api_token,
                                                &join,
                                                &actor,
                                                &device,
                                                realm_mls_snapshot,
                                            )
                                            .await
                                            {
                                                Ok((session, shared, per_sender_keys)) => {
                                                    if let Err(err) = install_and_capture(&shared, &session) {
                                                        last_error.set(media_error_label(err));
                                                        stage.set(CallStage::Ended);
                                                        return;
                                                    }
                                                    if let Err(err) = submit_call_state_participant(
                                                        &base,
                                                        &api_token,
                                                        &realm_id,
                                                        &call,
                                                        &actor,
                                                        &device,
                                                        "connecting",
                                                        "sfu",
                                                        &session,
                                                    )
                                                    .await
                                                    {
                                                        last_error.set(format!(
                                                            "call state failed: {err}"
                                                        ));
                                                        stage.set(CallStage::Ended);
                                                        return;
                                                    }
                                                    // Multi-device: the first device to
                                                    // emit `answer` wins; the rest stop
                                                    // ringing on `answered_elsewhere`.
                                                    let _ = emit_signal(
                                                        &base,
                                                        &api_token,
                                                        &realm_id,
                                                        &call,
                                                        &actor,
                                                        &device,
                                                        "answer",
                                                        1,
                                                        json!({ "accepted": true }),
                                                    )
                                                    .await;
                                                    let expected = expected_participant_set(
                                                        &known_participant_identities,
                                                        &session.participant_identity,
                                                    );
                                                    shared
                                                        .borrow_mut()
                                                        .set_expected_participants(&expected);
                                                    // §8.1: hand the per-sender deriver +
                                                    // identity→device_id map so each remote
                                                    // sender's frame key is recomputed on
                                                    // connect (receiver decrypt).
                                                    shared.borrow_mut().set_remote_key_source(
                                                        per_sender_keys.clone(),
                                                        known_participant_devices.clone(),
                                                    );
                                                    let connect_result =
                                                        { shared.borrow_mut().connect_sfu(&session) };
                                                    match connect_result {
                                                        Ok(()) => {
                                                            let _ = submit_call_state_participant(
                                                                &base,
                                                                &api_token,
                                                                &realm_id,
                                                                &call,
                                                                &actor,
                                                                &device,
                                                                "active",
                                                                "sfu",
                                                                &session,
                                                            )
                                                            .await;
                                                            transport_handle.set(Some(shared));
                                                            stage.set(CallStage::Active);
                                                            status.set("connected".to_owned());
                                                        }
                                                        Err(err) => {
                                                            // Honestly not-ready (desktop) — do not
                                                            // pretend the call connected.
                                                            last_error.set(media_error_label(err));
                                                            stage.set(CallStage::Ended);
                                                        }
                                                    }
                                                }
                                                Err(err) => {
                                                    last_error.set(media_error_label(err));
                                                    stage.set(CallStage::Ended);
                                                }
                                            }
                                        });
                                    }
                                },
                                "Accept"
                            }
                            Button {
                                variant: ButtonVariant::Destructive,
                                "data-testid": "call-decline-button",
                                onclick: {
                                    let base = base_url.clone();
                                    let actor = account_did.clone();
                                    let device = device_id.clone();
                                    move |_| {
                                        let _ = crate::media::rtc::MEDIA_TOKEN_TTL_MAX_SECS;
                                        spawn_reject(
                                            base.clone(), token(), active_realm(), active_call_id(),
                                            actor.clone(), device.clone(),
                                        );
                                        stage.set(CallStage::Ended);
                                        status.set("declined".to_owned());
                                    }
                                },
                                "Decline"
                            }
                        }
                    }
                }

                // ── Connecting. ──────────────────────────────────────
                if stage() == CallStage::Connecting {
                    div { class: "event", "data-testid": "call-connecting-panel",
                        span { "Connecting" }
                        span { class: "badge badge-info", "SDP / ICE" }
                    }
                }

                // ── Active call grid + controls. ─────────────────────
                if stage() == CallStage::Active {
                    div { class: "event", "data-testid": "call-active-panel",
                        div { class: "event-head",
                            span { "In call" }
                            span { class: "badge green", "active" }
                            span {
                                class: "badge",
                                "data-testid": "call-mic-status",
                                "data-muted": "{mic_muted()}",
                                if mic_muted() { "mic muted" } else { "mic live" }
                            }
                            span {
                                class: "badge",
                                "data-testid": "call-screen-status",
                                "data-state": if screen_sharing() { "sharing" } else { "off" },
                                if screen_sharing() { "screen sharing" } else { "screen off" }
                            }
                            span {
                                class: "badge",
                                "data-testid": "call-recording-status",
                                "data-state": "{recording().as_data_state()}",
                                "rec: {recording().as_data_state()}"
                            }
                        }

                        if recording() == RecordingState::Recording {
                            div { class: "event", "data-testid": "call-recording-indicator",
                                span { class: "badge danger", "● recording" }
                            }
                        }

                        // Participant grid.
                        div { class: "call-grid", "data-testid": "call-grid",
                            for p in participants().iter() {
                                {
                                    let did = p.actor_id.clone();
                                    let name = p.display_name.clone();
                                    let muted = p.muted;
                                    let speaking = p.speaking;
                                    let sharing = p.screen_sharing;
                                    rsx! {
                                        div {
                                            class: if speaking { "call-tile speaking" } else { "call-tile" },
                                            "data-testid": "call-participant-tile",
                                            "data-actor-did": "{did}",
                                            "data-muted": "{muted}",
                                            "data-speaking": "{speaking}",
                                            "data-screen-sharing": "{sharing}",
                                            div { class: "call-tile-name mono", "{name}" }
                                            div { class: "call-tile-badges",
                                                if muted { span { class: "badge", "muted" } }
                                                if speaking { span { class: "badge badge-success", "speaking" } }
                                                if sharing { span { class: "badge badge-info", "screen" } }
                                            }
                                        }
                                    }
                                }
                            }
                        }

                        // Controls.
                        div { class: "actions", "data-testid": "call-controls",
                            Button {
                                variant: if mic_muted() { ButtonVariant::Primary } else { ButtonVariant::Secondary },
                                "data-testid": "call-mute-button",
                                "aria-pressed": "{mic_muted()}",
                                onclick: {
                                    let base = base_url.clone();
                                    let actor = account_did.clone();
                                    let device = device_id.clone();
                                    move |_| {
                                        let next = !mic_muted();
                                        mic_muted.set(next);
                                        if let Some(t) = transport() {
                                            let _ = t.borrow_mut().set_audio_muted(next);
                                        }
                                        set_local_state(&mut participants, &actor, next, screen_sharing());
                                        emit_async(
                                            &base, &token(), &active_realm(), &active_call_id(),
                                            &actor, &device, "mute_state",
                                            json!({ "audio_muted": next, "video_muted": !camera_on(), "by": "self" }),
                                            call_seq,
                                        );
                                    }
                                },
                                if mic_muted() { "Unmute" } else { "Mute" }
                            }
                            Button {
                                variant: if camera_on() { ButtonVariant::Secondary } else { ButtonVariant::Primary },
                                "data-testid": "call-camera-button",
                                "aria-pressed": "{!camera_on()}",
                                onclick: move |_| {
                                    let next = !camera_on();
                                    camera_on.set(next);
                                    if let Some(t) = transport() {
                                        let _ = t.borrow_mut().set_video_muted(!next);
                                    }
                                },
                                if camera_on() { "Camera off" } else { "Camera on" }
                            }
                            Button {
                                variant: ButtonVariant::Secondary,
                                "data-testid": "call-screen-share-button",
                                "aria-pressed": "{screen_sharing()}",
                                onclick: {
                                    let base = base_url.clone();
                                    let actor = account_did.clone();
                                    let device = device_id.clone();
                                    move |_| {
                                        let next = !screen_sharing();
                                        screen_sharing.set(next);
                                        if let Some(t) = transport() {
                                            let _ = t.borrow_mut().set_screen_share(next);
                                        }
                                        set_local_state(&mut participants, &actor, mic_muted(), next);
                                        emit_async(
                                            &base, &token(), &active_realm(), &active_call_id(),
                                            &actor, &device, "media_state",
                                            json!({ "screen": { "enabled": next } }),
                                            call_seq,
                                        );
                                    }
                                },
                                if screen_sharing() { "Stop sharing" } else { "Share screen" }
                            }
                            Button {
                                variant: ButtonVariant::Secondary,
                                "data-testid": "call-record-button",
                                onclick: {
                                    let base = base_url.clone();
                                    let actor = account_did.clone();
                                    move |_| {
                                        if recording() == RecordingState::Recording {
                                            recording.set(RecordingState::Off);
                                            status.set("recording stopped".to_owned());
                                        } else {
                                            // Two-step consent confirmation before
                                            // the durable `ck.call.recording.start`.
                                            status.set("confirm recording…".to_owned());
                                            let base = base.clone();
                                            let actor = actor.clone();
                                            let realm = active_realm();
                                            let call = active_call_id();
                                            let api_token = token();
                                            let consent: Vec<String> = participants().iter().map(|p| p.actor_id.clone()).collect();
                                            spawn(async move {
                                                let recording_id = format!("ck:recording:{}", crate::operation::uuid_v7());
                                                match with_authed_api(&base, api_token, |api| async move {
                                                    api.submit_call_recording_start(&realm, &actor, &call, &recording_id, consent).await
                                                }).await {
                                                    Ok(_) => {
                                                        recording.set(RecordingState::Recording);
                                                        status.set("recording started".to_owned());
                                                    }
                                                    Err(err) => last_error.set(err.display()),
                                                }
                                            });
                                        }
                                    }
                                },
                                if recording() == RecordingState::Recording { "Stop recording" } else { "Record" }
                            }
                            Button {
                                variant: ButtonVariant::Destructive,
                                "data-testid": "call-leave-button",
                                onclick: {
                                    let base = base_url.clone();
                                    let actor = account_did.clone();
                                    let device = device_id.clone();
                                    move |_| {
                                        end_call(
                                            &transport, &base, &token(), &active_realm(),
                                            &active_call_id(), &actor, &device, call_seq,
                                        );
                                        stage.set(CallStage::Ended);
                                        status.set("left call".to_owned());
                                    }
                                },
                                "Leave"
                            }
                        }

                        // Moderator controls.
                        ModeratorControls {
                            base_url: base_url.clone(),
                            token,
                            realm_id: active_realm(),
                            call_id: active_call_id(),
                            actor: account_did.clone(),
                            device: device_id.clone(),
                            participants,
                            call_seq,
                        }
                    }
                }

                if stage() == CallStage::Ended {
                    div { class: "event", "data-testid": "call-ended-panel",
                        span { "Call ended" }
                        Button {
                            variant: ButtonVariant::Secondary,
                            "data-testid": "call-reset-button",
                            onclick: move |_| {
                                stage.set(CallStage::Idle);
                                active_call_id.set(String::new());
                                participants.set(Vec::new());
                                transport_handle.set(None);
                                call_seq.set(0);
                                status.set(String::new());
                            },
                            "New call"
                        }
                    }
                }

                if !status().is_empty() {
                    div { class: "muted", "data-testid": "call-status", "{status}" }
                }
                if !last_error().is_empty() {
                    div { class: "muted error", "data-testid": "call-error", "{last_error}" }
                }
            }
        }
    }
}

/// Moderator controls (kick / ban / mute-all / end-for-all). Rendered inside
/// the active call panel. Per `webrtc-signaling.md` §3a / §6.1: kick / ban /
/// end-for-all ride `ck.call.signal{signal_type=moderation}` with a
/// `data.action`; moderator-forced mute rides `mute_state{by=moderator}` (it
/// is NOT a moderation action). All frames require `ck.call.moderate`.
#[component]
#[allow(clippy::too_many_arguments)]
fn ModeratorControls(
    base_url: String,
    token: Signal<String>,
    realm_id: String,
    call_id: String,
    actor: String,
    device: String,
    participants: Signal<Vec<CallParticipant>>,
    call_seq: Signal<u64>,
) -> Element {
    rsx! {
        div { class: "event", "data-testid": "call-moderator-controls",
            div { class: "event-head",
                span { "Moderator" }
                span { class: "muted", "mute all / kick / ban / end" }
            }
            div { class: "actions",
                Button {
                    variant: ButtonVariant::Secondary,
                    "data-testid": "call-mute-all-button",
                    onclick: {
                        let base = base_url.clone();
                        let actor = actor.clone();
                        let device = device.clone();
                        let realm_id = realm_id.clone();
                        let call_id = call_id.clone();
                        move |_| {
                            // §6.1 — moderator-forced mute is a `mute_state`
                            // frame per target, not a `moderation` action.
                            for p in participants().iter() {
                                if p.actor_id == actor {
                                    continue;
                                }
                                emit_async(
                                    &base, &token(), &realm_id, &call_id, &actor, &device,
                                    "mute_state",
                                    json!({
                                        "audio_muted": true,
                                        "video_muted": false,
                                        "by": "moderator",
                                        "target_actor_id": p.actor_id,
                                    }),
                                    call_seq,
                                );
                            }
                        }
                    },
                    "Mute all"
                }
                Button {
                    variant: ButtonVariant::Destructive,
                    "data-testid": "call-end-for-all-button",
                    onclick: {
                        let base = base_url.clone();
                        let actor = actor.clone();
                        let device = device.clone();
                        let realm_id = realm_id.clone();
                        let call_id = call_id.clone();
                        move |_| {
                            emit_async(
                                &base, &token(), &realm_id, &call_id, &actor, &device,
                                "moderation",
                                json!({ "signal_type": "moderation", "data": { "action": "end_for_all" } }),
                                call_seq,
                            );
                        }
                    },
                    "End for all"
                }
            }
            for p in participants().iter() {
                {
                    let target = p.actor_id.clone();
                    let label = p.display_name.clone();
                    let base = base_url.clone();
                    let actor = actor.clone();
                    let device = device.clone();
                    let realm_id = realm_id.clone();
                    let call_id = call_id.clone();
                    rsx! {
                        div { class: "event-head", "data-testid": "call-moderator-row", "data-target": "{target}",
                            span { class: "mono", "{label}" }
                            Button {
                                variant: ButtonVariant::Destructive,
                                "data-testid": "call-kick-{target}",
                                onclick: {
                                    let base = base.clone();
                                    let actor = actor.clone();
                                    let device = device.clone();
                                    let realm_id = realm_id.clone();
                                    let call_id = call_id.clone();
                                    let target = target.clone();
                                    move |_| {
                                        emit_async(
                                            &base, &token(), &realm_id, &call_id, &actor, &device,
                                            "moderation",
                                            json!({
                                                "signal_type": "moderation",
                                                "data": { "action": "kick", "target_actor_id": target },
                                            }),
                                            call_seq,
                                        );
                                    }
                                },
                                "Kick"
                            }
                            Button {
                                variant: ButtonVariant::Destructive,
                                "data-testid": "call-ban-{target}",
                                onclick: {
                                    let base = base.clone();
                                    let actor = actor.clone();
                                    let device = device.clone();
                                    let realm_id = realm_id.clone();
                                    let call_id = call_id.clone();
                                    let target = target.clone();
                                    move |_| {
                                        emit_async(
                                            &base, &token(), &realm_id, &call_id, &actor, &device,
                                            "moderation",
                                            json!({
                                                "signal_type": "moderation",
                                                "data": { "action": "ban", "target_actor_id": target },
                                            }),
                                            call_seq,
                                        );
                                    }
                                },
                                "Ban"
                            }
                        }
                    }
                }
            }
        }
    }
}

// ── Controller helpers ──────────────────────────────────────────────────

/// Run the media join and wrap the resulting transport in shared state.
///
/// `realm_mls_snapshot` is this device's persisted MLS snapshot for the
/// call's realm, read by the caller (and the store read-guard dropped)
/// before this async fn runs so the snapshot restore never holds a `Signal`
/// guard across an `.await`. It is `None` when the realm has not synced an
/// MLS group on this device, which makes the SFrame key derivation fail
/// closed.
async fn join_and_build_transport(
    base: &str,
    api_token: &str,
    join: &MediaJoinRequest,
    actor: &str,
    device: &str,
    realm_mls_snapshot: Option<crate::mls::persistence::MlsSnapshotEnvelope>,
) -> Result<(JoinedMediaSession, SharedTransport, Rc<PerSenderFrameKeys>), RtcClientError> {
    let (session, per_sender_keys) =
        join_via_api(base, api_token, join, actor, device, realm_mls_snapshot).await?;
    let transport = new_transport(&session);
    Ok((
        session,
        Rc::new(RefCell::new(transport)),
        Rc::new(per_sender_keys),
    ))
}

/// Build an authed API client and run `join_call_media`. The MLS exporter
/// is the realm's live, synchronised MLS group restored from this device's
/// persisted snapshot (the same group the message E2EE path uses), so the
/// SFrame exporter secret matches every other member's. When the realm has
/// not synced an MLS group on this device yet, the exporter construction
/// fails closed (`e2ee_key_source_unauthorised`) instead of fabricating an
/// isolated group.
///
/// This path is platform-uniform: the browser (wasm) build links the same SDK
/// MLS stack the chat/reaction send path already uses to restore the group and
/// read its epoch exporter secret, so the web call surface derives the SFrame
/// keyprovider seed in-process from the realm's real exporter secret — never a
/// self-minted key and never a backend bridge. A realm with no synced snapshot
/// on this device still fails closed on every platform.
async fn join_via_api(
    base: &str,
    api_token: &str,
    join: &MediaJoinRequest,
    actor: &str,
    device: &str,
    realm_mls_snapshot: Option<crate::mls::persistence::MlsSnapshotEnvelope>,
) -> Result<(JoinedMediaSession, PerSenderFrameKeys), RtcClientError> {
    let secure_store = crate::secure_key_store::default_secure_key_store("yougen");
    let exporter = crate::media::rtc::RealmMlsExporter::for_realm(
        realm_mls_snapshot,
        secure_store.as_ref(),
        actor,
        device,
    )?;
    // Bind the SFrame frame key to the realm group's real MLS epoch instead
    // of the hard-coded `0` the dialer seeds the request with, so the key
    // rotates with the group epoch.
    let mut join = join.clone();
    join.epoch_id = exporter.epoch();
    let api = crate::views::helpers::authed_api(base, api_token.to_owned())
        .map_err(|_| RtcClientError::FocusUnavailableForClient)?;
    let session = crate::media::rtc::join_call_media(&api, &join, &exporter).await?;
    // Retain the live MLS exporter (and the leg's static SFrame context) so the
    // transport can recompute every remote sender's frame key on
    // ParticipantConnected (§8.1). Building the deriver here keeps the exporter
    // alive past the local-key derivation instead of dropping it.
    let realm_id = cokret_sdk::RealmId::new(join.realm_id.clone())
        .map_err(|_| RtcClientError::FocusMismatch)?;
    let call_id = cokret_sdk::CallId::new(join.call_id.clone())
        .map_err(|_| RtcClientError::FocusMismatch)?;
    let per_sender_keys = PerSenderFrameKeys::new(
        exporter,
        realm_id,
        call_id,
        session.focus_id.clone(),
        session.epoch_id,
    );
    Ok((session, per_sender_keys))
}

/// Install the SFrame key and start local capture on a freshly built
/// transport.
///
/// Returns the transport's error when the keyprovider seed cannot be
/// installed (MEDIA-1: only the MLS-exporter-derived 32-byte key is accepted),
/// which the caller turns into a fail-closed end state rather than driving the
/// FSM to a fake `Active`/`Connecting`. On both web and desktop the SFU path
/// accepts the verified key here (desktop injects it into the webview LiveKit
/// E2EE provider during `connect_sfu`). Local capture is best-effort (a denied
/// camera/mic permission should not abort the call setup), so its failure is
/// not propagated.
fn install_and_capture(
    transport: &SharedTransport,
    session: &JoinedMediaSession,
) -> Result<(), RtcClientError> {
    let mut t = transport.borrow_mut();
    // §8.1: the local key is sender-bound, installed under our own identity.
    t.install_frame_key(&session.participant_identity, &session.frame_key)?;
    let _ = t.start_local_capture();
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn submit_call_state_participant(
    base: &str,
    api_token: &str,
    realm_id: &str,
    call_id: &str,
    actor: &str,
    device: &str,
    state: &str,
    mode: &str,
    session: &JoinedMediaSession,
) -> Result<(), String> {
    let participant_binding = serde_json::to_value(&session.participant_binding)
        .map_err(|err| format!("participant_binding serialize failed: {err}"))?;
    let desired = session.desired_media;
    let participant = json!({
        "actor_id": actor,
        "device_id": device,
        "joined_at": crate::clock::now_rfc3339_secs(),
        "foci_preferred": [session.focus_id.clone()],
        "participant_identity": session.participant_identity.clone(),
        "participant_binding": participant_binding,
        "media": {
            "audio": desired.audio,
            "video": desired.video,
            "screen": desired.screen,
        },
    });
    let body = json!({
        "call_id": call_id,
        "state": state,
        "mode": mode,
        "session_focus": session.focus_id.clone(),
        "participants": [participant],
    });
    let op = crate::operation::OperationBuilder::new(realm_id, actor, "ck.call.state")
        .target_ref(call_id)
        .body(body)
        .build("yougen");
    with_authed_api(base, api_token.to_owned(), move |api| async move {
        api.submit_event_envelope(&op).await?;
        Ok(())
    })
    .await
    .map_err(|err| err.display())
}

/// Drain and relay any local SDP/ICE signaling produced by the transport.
async fn relay_local_signals(
    transport: &SharedTransport,
    base: &str,
    api_token: &str,
    realm_id: &str,
    call_id: &str,
    actor: &str,
    device: &str,
    mut call_seq: Signal<u64>,
) {
    let signals = transport.borrow_mut().drain_local_signals();
    for signal in signals {
        let seq = call_seq() + 1;
        call_seq.set(seq);
        let (signal_type, data) = match signal {
            LocalSignal::Offer { sdp } => (
                "renegotiate",
                json!({ "offer": { "sdp_type": "offer", "sdp": sdp } }),
            ),
            LocalSignal::Answer { sdp } => (
                "renegotiate",
                json!({ "answer": { "sdp_type": "answer", "sdp": sdp } }),
            ),
            LocalSignal::Candidate {
                candidate,
                sdp_mid,
                sdp_m_line_index,
            } => (
                "candidate",
                json!({ "candidate": candidate, "sdp_mid": sdp_mid, "sdp_m_line_index": sdp_m_line_index }),
            ),
        };
        let _ = emit_signal(
            base,
            api_token,
            realm_id,
            call_id,
            actor,
            device,
            signal_type,
            seq,
            data,
        )
        .await;
    }
}

/// Apply a batch of inbound `ck.call.signal` items (the receive side) to the
/// transport and the call FSM.
///
/// Routing per `signal_type` (`data` shapes mirror the sender side —
/// `submit_call_signal_v1` / `relay_local_signals`):
///   * `answer`               — call-accept ack (`{accepted:true}`); the SDP answer itself rides
///     `renegotiate{answer}`. A bare ack only nudges the FSM toward `Active`.
///   * `renegotiate` w/ offer  — `transport.accept_offer(sdp)`, then relay the locally-produced
///     answer back to the peer.
///   * `renegotiate` w/ answer — `transport.accept_answer(sdp)`.
///   * `candidate`            — `transport.add_remote_candidate(...)`.
///   * `hangup` / `reject`    — end the call (`stage = Ended`).
///   * `mute_state` / `media_state` / `speaking` — update the peer's roster tile.
///   * `moderation`           — apply; if this device is the kick/ban target, end the call.
///
/// SDP / candidate writes that produce local signals (the answer from an
/// applied offer) are relayed back to the peer via [`relay_local_signals`].
#[allow(clippy::too_many_arguments)]
fn apply_inbox_items(
    items: Vec<CallSignalInboxItem>,
    transport: Signal<Option<SharedTransport>>,
    base: String,
    token: Signal<String>,
    actor: String,
    device: String,
    realm_id: String,
    call_id: String,
    mut call_seq: Signal<u64>,
    mut stage: Signal<CallStage>,
    mut status: Signal<String>,
    mut last_error: Signal<String>,
    mut participants: Signal<Vec<CallParticipant>>,
) {
    // Items that need an async relay (offer → answer) defer to a single
    // spawned task after the synchronous transport mutations are applied, so
    // we never hold a transport borrow across an `.await`.
    let mut relay_after = false;
    for item in items {
        match item.signal_type.as_str() {
            "answer" => {
                // Call-accept ack — the SDP answer itself arrives as
                // `renegotiate{answer}`. Promote a still-ringing/connecting
                // FSM toward Active; the real `Connected` transition lands
                // when `accept_answer` applies the SDP below.
                let s = stage();
                if matches!(
                    s,
                    CallStage::OutgoingRinging | CallStage::Connecting | CallStage::IncomingRinging
                ) {
                    status.set("peer answered".to_owned());
                }
            }
            "renegotiate" | "offer" => {
                if let Some(sdp) = sdp_from_data(&item.data, "offer") {
                    if let Some(t) = transport() {
                        match t.borrow_mut().accept_offer(&sdp) {
                            Ok(()) => {
                                relay_after = true;
                                stage.set(CallStage::Connecting);
                                status.set("applying remote offer".to_owned());
                            }
                            Err(err) => last_error.set(media_error_label(err)),
                        }
                    }
                } else if let Some(sdp) = sdp_from_data(&item.data, "answer") {
                    if let Some(t) = transport() {
                        match t.borrow_mut().accept_answer(&sdp) {
                            Ok(()) => {
                                stage.set(CallStage::Active);
                                status.set("connected".to_owned());
                            }
                            Err(err) => last_error.set(media_error_label(err)),
                        }
                    }
                }
            }
            "candidate" => {
                let candidate = item
                    .data
                    .get("candidate")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default()
                    .to_owned();
                if !candidate.is_empty()
                    && let Some(t) = transport()
                {
                    let sdp_mid = item.data.get("sdp_mid").and_then(|v| v.as_str());
                    let sdp_m_line_index = item
                        .data
                        .get("sdp_m_line_index")
                        .and_then(serde_json::Value::as_u64)
                        .map(|i| i as u32);
                    if let Err(err) =
                        t.borrow_mut()
                            .add_remote_candidate(&candidate, sdp_mid, sdp_m_line_index)
                    {
                        last_error.set(media_error_label(err));
                    }
                }
            }
            "hangup" | "reject" => {
                if let Some(t) = transport() {
                    t.borrow_mut().close();
                }
                stage.set(CallStage::Ended);
                let reason = item
                    .data
                    .get("reason")
                    .and_then(|v| v.as_str())
                    .unwrap_or(item.signal_type.as_str());
                status.set(format!("call ended: {reason}"));
            }
            "mute_state" | "media_state" | "speaking" => {
                apply_peer_state(&mut participants, &item);
            }
            "moderation" => {
                let action = item
                    .data
                    .get("data")
                    .and_then(|d| d.get("action"))
                    .or_else(|| item.data.get("action"))
                    .and_then(|v| v.as_str())
                    .unwrap_or_default();
                let target = item
                    .data
                    .get("data")
                    .and_then(|d| d.get("target_actor_id"))
                    .or_else(|| item.data.get("target_actor_id"))
                    .and_then(|v| v.as_str());
                let self_targeted =
                    matches!(action, "kick" | "ban") && target.map(|t| t == actor).unwrap_or(false);
                if action == "end_for_all" || self_targeted {
                    if let Some(t) = transport() {
                        t.borrow_mut().close();
                    }
                    stage.set(CallStage::Ended);
                    status.set(format!("removed by moderator ({action})"));
                } else if let Some(t) = target {
                    // A peer was kicked/banned — drop their roster tile.
                    let mut roster = participants();
                    roster.retain(|p| p.actor_id != t);
                    participants.set(roster);
                }
            }
            other => {
                tracing::debug!(
                    signal_type = other,
                    "ignoring unhandled inbound call signal"
                );
            }
        }
    }

    if relay_after && let Some(t) = transport() {
        spawn(async move {
            relay_local_signals(
                &t,
                &base,
                &token(),
                &realm_id,
                &call_id,
                &actor,
                &device,
                call_seq,
            )
            .await;
        });
    } else {
        // Keep `call_seq` mutable-captured even when no relay fires, so the
        // signature stays uniform; no-op otherwise.
        let _ = &mut call_seq;
    }
}

/// Read a nested SDP string out of an inbound `renegotiate` / `offer`
/// `payload.data`. The sender writes `{ "offer": { "sdp": … } }` /
/// `{ "answer": { "sdp": … } }` (see `relay_local_signals`); tolerate a flat
/// `{ "sdp": … }` too.
fn sdp_from_data(data: &serde_json::Value, key: &str) -> Option<String> {
    data.get(key)
        .and_then(|v| v.get("sdp"))
        .and_then(|v| v.as_str())
        .or_else(|| {
            // Flat form only counts when it matches the requested role.
            let role_matches = data
                .get("sdp_type")
                .and_then(|v| v.as_str())
                .map(|t| t == key)
                .unwrap_or(true);
            if role_matches {
                data.get("sdp").and_then(|v| v.as_str())
            } else {
                None
            }
        })
        .map(ToOwned::to_owned)
}

/// Apply an inbound `mute_state` / `media_state` / `speaking` signal to the
/// sender's roster tile. The sender's actor id is `item.sender_actor`.
fn apply_peer_state(participants: &mut Signal<Vec<CallParticipant>>, item: &CallSignalInboxItem) {
    let target = item
        .data
        .get("target_actor_id")
        .and_then(|v| v.as_str())
        .unwrap_or(item.sender_actor.as_str())
        .to_owned();
    let mut roster = participants();
    let mut changed = false;
    for p in &mut roster {
        if p.actor_id != target {
            continue;
        }
        match item.signal_type.as_str() {
            "mute_state" => {
                if let Some(muted) = item.data.get("audio_muted").and_then(|v| v.as_bool()) {
                    p.muted = muted;
                    changed = true;
                }
            }
            "media_state" => {
                if let Some(sharing) = item
                    .data
                    .get("screen")
                    .and_then(|s| s.get("enabled"))
                    .and_then(|v| v.as_bool())
                {
                    p.screen_sharing = sharing;
                    changed = true;
                }
            }
            "speaking" => {
                if let Some(speaking) = item.data.get("speaking").and_then(|v| v.as_bool()) {
                    p.speaking = speaking;
                    changed = true;
                }
            }
            _ => {}
        }
    }
    if changed {
        participants.set(roster);
    }
}

/// Fire-and-forget signal emit (non-SDP control signals).
#[allow(clippy::too_many_arguments)]
fn emit_async(
    base: &str,
    api_token: &str,
    realm_id: &str,
    call_id: &str,
    actor: &str,
    device: &str,
    signal_type: &str,
    data: serde_json::Value,
    mut call_seq: Signal<u64>,
) {
    if call_id.trim().is_empty() || realm_id.trim().is_empty() {
        return;
    }
    let seq = call_seq() + 1;
    call_seq.set(seq);
    let (base, api_token, realm_id, call_id, actor, device, signal_type) = (
        base.to_owned(),
        api_token.to_owned(),
        realm_id.to_owned(),
        call_id.to_owned(),
        actor.to_owned(),
        device.to_owned(),
        signal_type.to_owned(),
    );
    spawn(async move {
        let _ = emit_signal(
            &base,
            &api_token,
            &realm_id,
            &call_id,
            &actor,
            &device,
            &signal_type,
            seq,
            data,
        )
        .await;
    });
}

/// Submit a single `ck.call.signal` ephemeral envelope.
#[allow(clippy::too_many_arguments)]
async fn emit_signal(
    base: &str,
    api_token: &str,
    realm_id: &str,
    call_id: &str,
    actor: &str,
    device: &str,
    signal_type: &str,
    seq: u64,
    data: serde_json::Value,
) -> Result<(), String> {
    let (realm_id, call_id, actor, device, signal_type) = (
        realm_id.to_owned(),
        call_id.to_owned(),
        actor.to_owned(),
        device.to_owned(),
        signal_type.to_owned(),
    );
    with_authed_api(base, api_token.to_owned(), |api| async move {
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

/// Emit a `reject` signal and tear down (decline path).
fn spawn_reject(
    base: String,
    api_token: String,
    realm_id: String,
    call_id: String,
    actor: String,
    device: String,
) {
    spawn(async move {
        let _ = emit_signal(
            &base,
            &api_token,
            &realm_id,
            &call_id,
            &actor,
            &device,
            "reject",
            1,
            json!({ "reason": "declined" }),
        )
        .await;
    });
}

/// Hang up: emit `hangup`, close the transport, release media.
#[allow(clippy::too_many_arguments)]
fn end_call(
    transport: &Signal<Option<SharedTransport>>,
    base: &str,
    api_token: &str,
    realm_id: &str,
    call_id: &str,
    actor: &str,
    device: &str,
    call_seq: Signal<u64>,
) {
    if let Some(t) = transport.read().as_ref() {
        t.borrow_mut().close();
    }
    emit_async(
        base,
        api_token,
        realm_id,
        call_id,
        actor,
        device,
        "hangup",
        json!({ "reason": "user_hangup" }),
        call_seq,
    );
}

fn media_error_label(err: RtcClientError) -> String {
    format!("call failed: {} ({})", err.as_wire(), err.i18n_key())
}

fn operation_body(payload: &Value) -> &Value {
    payload
        .get("body")
        .or_else(|| payload.get("payload"))
        .unwrap_or(payload)
}

/// Derive the realm's anchored media-service DIDs and preferred focus from
/// the local `ck.realm.media_service` projection.
fn media_service_selection(
    state: &crate::local_state::ClientLocalState,
    realm_id: &str,
) -> (Vec<String>, String) {
    let mut dids = BTreeSet::new();
    let mut focus_ids = Vec::<String>::new();
    for record in &state.raw_operations {
        let kind = record
            .payload
            .get("kind")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        if kind != "ck.realm.media_service" || record.realm_id.as_deref() != Some(realm_id) {
            continue;
        }
        let body = operation_body(&record.payload);
        if let Some(service_id) = body.get("service_id").and_then(|v| v.as_str()) {
            dids.insert(service_id.to_owned());
        }
        if let Some(foci) = body.get("foci").and_then(|v| v.as_array()) {
            for focus in foci {
                let Some(focus_id) = focus.get("focus_id").and_then(|v| v.as_str()) else {
                    continue;
                };
                if !focus_id.trim().is_empty() && !focus_ids.iter().any(|known| known == focus_id) {
                    focus_ids.push(focus_id.to_owned());
                }
            }
        }
    }
    let media_dids: Vec<String> = dids.into_iter().collect();
    let focus_id = focus_ids
        .into_iter()
        .next()
        .unwrap_or_else(|| default_focus_id(&media_dids));
    (media_dids, focus_id)
}

/// Fallback used only before the media-service projection is hydrated. A
/// real media join still fails closed when the anchored issuer DID set is
/// empty.
fn default_focus_id(media_dids: &[String]) -> String {
    media_dids
        .first()
        .and_then(|did| did.rsplit(':').next())
        .map(|host| host.to_owned())
        .unwrap_or_else(|| "default".to_owned())
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

fn call_state_participant_identities(
    state: &crate::local_state::ClientLocalState,
    realm_id: &str,
    call_id: &str,
) -> BTreeSet<String> {
    let mut identities = BTreeSet::new();
    for record in &state.raw_operations {
        let kind = record
            .payload
            .get("kind")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        if kind != "ck.call.state" || record.realm_id.as_deref() != Some(realm_id) {
            continue;
        }
        let body = operation_body(&record.payload);
        if body.get("call_id").and_then(|v| v.as_str()) != Some(call_id) {
            continue;
        }
        let Some(participants) = body.get("participants").and_then(|v| v.as_array()) else {
            continue;
        };
        for participant in participants {
            if let Some(identity) = participant
                .get("participant_identity")
                .and_then(|v| v.as_str())
                && !identity.trim().is_empty()
            {
                identities.insert(identity.to_owned());
            }
        }
    }
    identities
}

/// Read the `participant_identity → device_id` map from the durable
/// `ck.call.state.participants[]` projection for this call. Used to build a
/// remote sender's SFrame [`FrameKeyContext`] (`media-service-binding.md` §8.1
/// binds the sender's own `(participant_identity, device_id)`): when a remote
/// connects, its `device_id` is looked up here so the receiver can recompute
/// that sender's frame key from the shared MLS exporter. Entries missing either
/// field are skipped (the remote's key cannot be derived → fail-closed for that
/// one remote).
fn call_state_participant_device_map(
    state: &crate::local_state::ClientLocalState,
    realm_id: &str,
    call_id: &str,
) -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    for record in &state.raw_operations {
        let kind = record
            .payload
            .get("kind")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        if kind != "ck.call.state" || record.realm_id.as_deref() != Some(realm_id) {
            continue;
        }
        let body = operation_body(&record.payload);
        if body.get("call_id").and_then(|v| v.as_str()) != Some(call_id) {
            continue;
        }
        let Some(participants) = body.get("participants").and_then(|v| v.as_array()) else {
            continue;
        };
        for participant in participants {
            let identity = participant
                .get("participant_identity")
                .and_then(|v| v.as_str())
                .unwrap_or_default();
            let device_id = participant
                .get("device_id")
                .and_then(|v| v.as_str())
                .unwrap_or_default();
            if !identity.trim().is_empty() && !device_id.trim().is_empty() {
                map.insert(identity.to_owned(), device_id.to_owned());
            }
        }
    }
    map
}

/// Build the MEDIA-2 expected-participant identity set from durable call
/// state, seeding the local token-exchange identity before the state sync
/// loop has replayed our own write.
fn expected_participant_set(
    durable_identities: &BTreeSet<String>,
    local_participant_identity: &str,
) -> BTreeSet<String> {
    let mut expected = durable_identities.clone();
    if !local_participant_identity.trim().is_empty() {
        expected.insert(local_participant_identity.to_owned());
    }
    expected
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
            muted: false,
            speaking: false,
            screen_sharing: false,
        });
    }
    roster
}

fn set_local_state(
    participants: &mut Signal<Vec<CallParticipant>>,
    actor: &str,
    muted: bool,
    sharing: bool,
) {
    let mut roster = participants();
    for p in &mut roster {
        if p.actor_id == actor {
            p.muted = muted;
            p.screen_sharing = sharing;
        }
    }
    participants.set(roster);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stage_strings_stable() {
        assert_eq!(CallStage::Idle.as_str(), "idle");
        assert_eq!(CallStage::OutgoingRinging.as_str(), "ringing");
        assert_eq!(CallStage::IncomingRinging.as_str(), "ringing");
        assert_eq!(CallStage::Connecting.as_str(), "connecting");
        assert_eq!(CallStage::Active.as_str(), "active");
        assert_eq!(CallStage::Ended.as_str(), "ended");
    }

    #[test]
    fn participant_input_dedupes() {
        assert_eq!(
            participant_list_from_input(
                "did:web:bob.example\ndid:web:carol.example, did:web:bob.example"
            ),
            vec!["did:web:bob.example", "did:web:carol.example"]
        );
    }

    #[test]
    fn roster_includes_actor_once() {
        let roster = build_roster(
            "did:web:alice.example",
            &[
                "did:web:bob.example".to_owned(),
                "did:web:alice.example".to_owned(),
            ],
        );
        assert_eq!(roster.len(), 2);
        assert_eq!(roster[0].actor_id, "did:web:alice.example");
    }

    #[test]
    fn default_focus_id_derives_from_service_did() {
        assert_eq!(
            default_focus_id(&["did:web:media.example".to_owned()]),
            "media.example"
        );
        assert_eq!(default_focus_id(&[]), "default");
    }

    #[test]
    fn media_service_selection_reads_declared_focus() {
        let mut state = crate::local_state::ClientLocalState::default();
        state
            .raw_operations
            .push(crate::local_state::RawOperationRecord {
                operation_id: "op-1".to_owned(),
                realm_id: Some("ck:realm:01904100-0000-7000-8000-9b64700c6ee8".to_owned()),
                received_at: chrono::Utc::now(),
                payload: json!({
                    "kind": "ck.realm.media_service",
                    "body": {
                        "service_id": "did:web:media.example",
                        "foci": [
                            {"focus_id": "fra-1", "type": "livekit"},
                            {"focus_id": "us-east-1", "type": "livekit"}
                        ]
                    }
                }),
            });
        let (dids, focus_id) =
            media_service_selection(&state, "ck:realm:01904100-0000-7000-8000-9b64700c6ee8");
        assert_eq!(dids, vec!["did:web:media.example"]);
        assert_eq!(focus_id, "fra-1");
    }

    #[test]
    fn call_state_participant_identities_read_sfu_handles() {
        let mut state = crate::local_state::ClientLocalState::default();
        state.raw_operations.push(crate::local_state::RawOperationRecord {
            operation_id: "op-1".to_owned(),
            realm_id: Some("ck:realm:01904100-0000-7000-8000-9b64700c6ee8".to_owned()),
            received_at: chrono::Utc::now(),
            payload: json!({
                "kind": "ck.call.state",
                "body": {
                    "call_id": "ck:call:0196441c-0000-7000-8000-000000000000",
                    "state": "connecting",
                    "participants": [
                        {"actor_id": "did:web:alice.example", "participant_identity": "ck:rtc_participant:alice"}
                    ]
                }
            }),
        });
        let identities = call_state_participant_identities(
            &state,
            "ck:realm:01904100-0000-7000-8000-9b64700c6ee8",
            "ck:call:0196441c-0000-7000-8000-000000000000",
        );
        assert!(identities.contains("ck:rtc_participant:alice"));
        assert!(!identities.contains("did:web:alice.example"));
    }

    #[test]
    fn call_state_participant_device_map_pairs_identity_and_device() {
        let mut state = crate::local_state::ClientLocalState::default();
        state.raw_operations.push(crate::local_state::RawOperationRecord {
            operation_id: "op-1".to_owned(),
            realm_id: Some("ck:realm:01904100-0000-7000-8000-9b64700c6ee8".to_owned()),
            received_at: chrono::Utc::now(),
            payload: json!({
                "kind": "ck.call.state",
                "body": {
                    "call_id": "ck:call:0196441c-0000-7000-8000-000000000000",
                    "state": "active",
                    "participants": [
                        {
                            "actor_id": "did:web:alice.example",
                            "device_id": "ck:device:01904100-0000-7000-8000-00000000000a",
                            "participant_identity": "ck:rtc_participant:alice"
                        },
                        {
                            // Missing device_id -> skipped (cannot derive its key).
                            "actor_id": "did:web:carol.example",
                            "participant_identity": "ck:rtc_participant:carol"
                        }
                    ]
                }
            }),
        });
        let map = call_state_participant_device_map(
            &state,
            "ck:realm:01904100-0000-7000-8000-9b64700c6ee8",
            "ck:call:0196441c-0000-7000-8000-000000000000",
        );
        assert_eq!(
            map.get("ck:rtc_participant:alice").map(String::as_str),
            Some("ck:device:01904100-0000-7000-8000-00000000000a")
        );
        // The participant with no device_id is fail-closed: not in the map.
        assert!(!map.contains_key("ck:rtc_participant:carol"));
    }

    #[test]
    fn expected_participant_set_uses_rtc_identities() {
        let mut durable = BTreeSet::new();
        durable.insert("ck:rtc_participant:remote".to_owned());
        let expected = expected_participant_set(&durable, "ck:rtc_participant:self");
        assert!(expected.contains("ck:rtc_participant:self"));
        assert!(expected.contains("ck:rtc_participant:remote"));
        assert!(!expected.contains("did:web:alice.example"));
    }
}
