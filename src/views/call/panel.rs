use dioxus::prelude::*;
use dioxus_primitives::checkbox::CheckboxState;

use super::media::{
    install_and_capture, join_and_build_transport, media_error_label, submit_call_state_participant,
};
use super::moderator::ModeratorControls;
use super::projection::{
    build_roster, call_state_participant_actor_device_map, call_state_participant_device_map,
    call_state_participant_identities, expected_participant_set, media_governance_evidence,
    media_service_decrypts_enabled, media_service_selection, participant_list_from_input,
    set_local_state,
};
use super::signaling::{
    apply_inbox_items, emit_async, emit_signal, end_call, relay_local_signals, spawn_reject,
};
use super::types::{
    CallMode, CallParticipant, CallStage, RecordingState, SharedTransport, TranscriptionState,
};
use crate::media::rtc::{DesiredMedia, MediaJoinRequest};
use crate::transport::auth::with_event_submitter;
use crate::ui::button::{Button, ButtonVariant};
use crate::ui::checkbox::Checkbox;
use crate::views::call_signals::CallSignalHub;
use crate::views::helpers::{actor_display_label, short_protocol_id};

#[component]
#[allow(clippy::too_many_arguments)]
pub fn CallPanel(
    token: Signal<String>,
    selected_realm_id: String,
    account_did: String,
    device_id: String,
    /// Deep-linked call id (`ak:call:…`); empty when the user opens the
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
    // A4 — base_url / state_store from session context instead of props.
    let base_url = crate::app::SessionContext::base_url_string();
    let state_store = crate::app::SessionContext::get().state_store;
    // Sealing a Signal burns the SDK-owned AEAD nonce counter into the
    // persisted MLS snapshot before submit, so every emit needs the store
    // itself and not just the key-material descriptor.
    let signal_store = crate::app::runtime_adapter::state_store_handle(state_store);
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
    let mut transcription = use_signal(|| TranscriptionState::Off);
    let mut pending_capture = use_signal(|| Option::<String>::None);
    let mut participants = use_signal(Vec::<CallParticipant>::new);
    let mut active_call_id = use_signal(|| call_id.clone());
    let mut call_seq = use_signal(|| 0_u64);
    let mut active_realm = use_signal(|| selected_realm_id.clone());
    let mut peer_input = use_signal(|| peer.clone());
    let mut group_input = use_signal(|| "did:web:bob.example\ndid:web:carol.example".to_owned());
    let mut want_video_signal = use_signal(|| want_video);
    let mut media_plaintext_confirmed = use_signal(|| false);

    // Transport handle — `None` until a media session is joined.
    let transport = use_signal(|| Option::<SharedTransport>::None);
    let mut transport_handle = transport;

    // Receive side: the app-level signaling hub (`crate::views::call_signals`)
    // the sync apply paths feed inbound `ak.call.signal` envelopes into. The
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
        let signal_store = signal_store.clone();
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
                mic_muted,
                signal_store.clone(),
            );
        });
    }

    let account_label = actor_display_label(&state_store.read(), &account_did);
    let device_label = short_protocol_id(&device_id);
    let peer_input_value = peer_input();
    let peer_input_label = actor_display_label(&state_store.read(), &peer_input_value);

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
                .map(|kind| kind.starts_with("ak.call."))
                .unwrap_or(false)
        })
        .count();
    let media_plaintext_confirmation_required = {
        let snapshot = state_store.read().load();
        media_service_decrypts_enabled(&snapshot, &active_realm())
    };

    // ── Start an outgoing call (1:1 or SFU). ─────────────────────────
    let start_call = {
        let base = base_url.clone();
        let actor = account_did.clone();
        let device = device_id.clone();
        let signal_store = signal_store.clone();
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

            let (call, call_create_event) = if active_call_id().is_empty() {
                let payload = arkret_sdk::CallCreatePayload {
                    initial_state: arkret_sdk::CallLifecycleState::Ringing,
                };
                let event = match crate::operation::TypedOperationBuilder::new::<
                    arkret_sdk::event_spec::CallCreate,
                >(&realm_id, &actor, payload)
                .build_sdk_event("inkson")
                {
                    Ok(event) => event,
                    Err(error) => {
                        last_error.set(format!("call create build failed: {error:#}"));
                        return;
                    }
                };
                let call_id = arkret_sdk::CallId::from_event_id(&event.event_id).to_string();
                (call_id, Some(event))
            } else {
                (active_call_id(), None)
            };
            let (
                media_dids,
                focus_id,
                known_actor_devices,
                known_participant_identities,
                known_participant_devices,
                governance_evidence,
                realm_mls_snapshot,
            ) = {
                let store = state_store.read();
                let snapshot = store.load();
                let (media_dids, focus_id) = media_service_selection(&snapshot, &realm_id);
                (
                    media_dids,
                    focus_id,
                    call_state_participant_actor_device_map(&snapshot, &realm_id, &call),
                    call_state_participant_identities(&snapshot, &realm_id, &call),
                    call_state_participant_device_map(&snapshot, &realm_id, &call),
                    media_governance_evidence(&snapshot, &realm_id, media_plaintext_confirmed()),
                    store.mls_snapshot_for(&realm_id),
                )
            };
            active_call_id.set(call.clone());
            call_seq.set(0);
            let roster = match build_roster(&actor, &peers, &known_actor_devices) {
                Ok(roster) => roster,
                Err(error) => {
                    last_error.set(format!("invalid call participant identity: {error}"));
                    return;
                }
            };
            participants.set(roster);
            stage.set(CallStage::OutgoingRinging);
            status.set("placing call".to_owned());
            last_error.set(String::new());
            let signal_store = signal_store.clone();

            spawn(async move {
                // The durable Call genesis must be accepted before any
                // signaling or media-plane request references its derived id.
                if let Some(call_create_event) = call_create_event
                    && let Err(err) =
                        with_event_submitter(&base, api_token.clone(), |submitter| async move {
                            submitter.submit_sdk_event(&call_create_event).await?;
                            Ok(())
                        })
                        .await
                {
                    last_error.set(format!("call create failed: {}", err.display()));
                    return;
                }

                // Join the media plane (token + ICE + SFrame key). P2P emits
                // its invite only after the transport produces the real SDP
                // offer; the closed signal model intentionally forbids a
                // placeholder invite without an offer.
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
                    media_service_ids: media_dids,
                    verified_media_routes: Vec::new(),
                    governance_evidence,
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
                                    arkret_sdk::CallLifecycleState::Connecting,
                                    &session,
                                )
                                .await
                                {
                                    last_error.set(format!("call state failed: {err}"));
                                    stage.set(CallStage::Ended);
                                    return;
                                }
                                if let Ok(focus_id) =
                                    arkret_sdk::NonEmptyString::new(focus_id.clone())
                                    && let Err(err) = emit_signal(
                                        &base,
                                        &api_token,
                                        &realm_id,
                                        &call,
                                        &actor,
                                        &device,
                                        1,
                                        arkret_sdk::CallSignalData::FocusJoin(
                                            arkret_sdk::CallFocusSignalData { focus_id },
                                        ),
                                        &signal_store,
                                    )
                                    .await
                                {
                                    last_error.set(format!("focus join signal failed: {err}"));
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
                                    &base,
                                    &api_token,
                                    &realm_id,
                                    &call,
                                    &actor,
                                    &device,
                                    arkret_sdk::CallLifecycleState::Active,
                                    &session,
                                )
                                .await;
                                stage.set(CallStage::Active);
                                status.set(format!("joined SFU room ({})", session.backend_kind));
                            }
                            CallMode::P2p => {
                                if let Err(err) = shared.borrow_mut().begin_offer() {
                                    last_error.set(media_error_label(err));
                                    stage.set(CallStage::Ended);
                                    return;
                                }
                                relay_local_signals(
                                    &shared,
                                    &base,
                                    &api_token,
                                    &realm_id,
                                    &call,
                                    &actor,
                                    &device,
                                    call_seq,
                                    Some(arkret_sdk::CallMediaSelection {
                                        audio: true,
                                        video: want_video,
                                        screen: Some(false),
                                    }),
                                    &signal_store,
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

    let start_confirmed_capture = {
        let base = base_url.clone();
        let actor = account_did.clone();
        move |capture_kind: String| {
            let base = base.clone();
            let actor = actor.clone();
            let realm = active_realm();
            let call = active_call_id();
            let api_token = token();
            let mode = if camera_on() {
                arkret_sdk::RecordingMode::AudioVideo
            } else {
                arkret_sdk::RecordingMode::AudioOnly
            };
            pending_capture.set(None);
            match capture_kind.as_str() {
                "recording" => {
                    status.set("starting recording".to_owned());
                    spawn(async move {
                        let recording_id = format!("rtc-recording-{}", crate::operation::uuid_v7());
                        match with_event_submitter(&base, api_token, |sub| async move {
                            crate::transport::media::submit_call_recording_start(
                                &sub,
                                &realm,
                                &actor,
                                &call,
                                &recording_id,
                                mode,
                            )
                            .await
                        })
                        .await
                        {
                            Ok(_) => {
                                recording.set(RecordingState::Recording);
                                status.set("recording started".to_owned());
                            }
                            Err(err) => last_error.set(err.display()),
                        }
                    });
                }
                "transcript" => {
                    status.set("starting transcription".to_owned());
                    spawn(async move {
                        let transcript_id =
                            format!("rtc-transcript-{}", crate::operation::uuid_v7());
                        match with_event_submitter(&base, api_token, |sub| async move {
                            crate::transport::media::submit_call_transcription_start(
                                &sub,
                                &realm,
                                &actor,
                                &call,
                                &transcript_id,
                                mode,
                            )
                            .await
                        })
                        .await
                        {
                            Ok(_) => {
                                transcription.set(TranscriptionState::Transcribing);
                                status.set("transcription started".to_owned());
                            }
                            Err(err) => last_error.set(err.display()),
                        }
                    });
                }
                _ => {
                    status.set("capture cancelled".to_owned());
                }
            }
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
                            oninput: move |e| {
                                active_realm.set(e.value());
                                media_plaintext_confirmed.set(false);
                            },
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
                        if media_plaintext_confirmation_required {
                            label { class: "checkbox-row",
                                Checkbox {
                                    "data-testid": "call-media-plaintext-confirm",
                                    checked: if media_plaintext_confirmed() { CheckboxState::Checked } else { CheckboxState::Unchecked },
                                    on_checked_change: move |state: CheckboxState| {
                                        media_plaintext_confirmed.set(bool::from(state));
                                    },
                                }
                                span { "Media service can decrypt this call" }
                            }
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
                                disabled: active_realm.read().trim().is_empty()
                                    || peer_input.read().trim().is_empty()
                                    || (media_plaintext_confirmation_required && !media_plaintext_confirmed()),
                                onclick: {
                                    let mut start = start_call.clone();
                                    move |_| start(CallMode::P2p)
                                },
                                "Start 1:1 call"
                            }
                            Button {
                                variant: ButtonVariant::Secondary,
                                "data-testid": "call-start-group-button",
                                disabled: active_realm.read().trim().is_empty()
                                    || (media_plaintext_confirmation_required && !media_plaintext_confirmed()),
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
                            span { title: "{peer_input_value}", "{peer_input_label}" }
                        }
                        div { class: "actions",
                            Button {
                                variant: ButtonVariant::Destructive,
                                "data-testid": "call-cancel-button",
                                onclick: {
                                    let base = base_url.clone();
                                    let actor = account_did.clone();
                                    let device = device_id.clone();
                                    let signal_store = signal_store.clone();
                                    move |_| {
                                        end_call(
                                            &transport, &base, &token(), &active_realm(),
                                            &active_call_id(), &actor, &device, call_seq,
                                            signal_store.clone(),
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
                            span { title: "{peer_input_value}", "{peer_input_label}" }
                        }
                        if media_plaintext_confirmation_required {
                            label { class: "checkbox-row",
                                Checkbox {
                                    "data-testid": "call-incoming-media-plaintext-confirm",
                                    checked: if media_plaintext_confirmed() { CheckboxState::Checked } else { CheckboxState::Unchecked },
                                    on_checked_change: move |state: CheckboxState| {
                                        media_plaintext_confirmed.set(bool::from(state));
                                    },
                                }
                                span { "Media service can decrypt this call" }
                            }
                        }
                        div { class: "actions",
                            Button {
                                variant: ButtonVariant::Primary,
                                "data-testid": "call-accept-button",
                                disabled: media_plaintext_confirmation_required && !media_plaintext_confirmed(),
                                onclick: {
                                    let base = base_url.clone();
                                    let actor = account_did.clone();
                                    let device = device_id.clone();
                                    let signal_store = signal_store.clone();
                                    move |_| {
                                        let base = base.clone();
                                        let actor = actor.clone();
                                        let device = device.clone();
                                        let realm_id = active_realm();
                                        let call = active_call_id();
                                        let api_token = token();
                                        let signal_store = signal_store.clone();
                                        let (
                                            media_dids,
                                            focus_id,
                                            known_participant_identities,
                                            known_participant_devices,
                                            governance_evidence,
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
                                                media_governance_evidence(
                                                    &snapshot,
                                                    &realm_id,
                                                    media_plaintext_confirmed(),
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
                                                media_service_ids: media_dids,
                                                verified_media_routes: Vec::new(),
                                                governance_evidence,
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
                                                        arkret_sdk::CallLifecycleState::Connecting,
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
                                                    if let Ok(focus_id) = arkret_sdk::NonEmptyString::new(focus_id.clone()) {
                                                        let _ = emit_signal(
                                                            &base,
                                                            &api_token,
                                                            &realm_id,
                                                            &call,
                                                            &actor,
                                                            &device,
                                                            1,
                                                            arkret_sdk::CallSignalData::FocusJoin(
                                                                arkret_sdk::CallFocusSignalData { focus_id },
                                                            ),
                                                            &signal_store,
                                                        )
                                                        .await;
                                                    }
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
                                                                arkret_sdk::CallLifecycleState::Active,
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
                                    let signal_store = signal_store.clone();
                                    move |_| {
                                        let _ = crate::media::rtc::MEDIA_TOKEN_TTL_MAX_SECS;
                                        spawn_reject(
                                            base.clone(), token(), active_realm(), active_call_id(),
                                            actor.clone(), device.clone(), signal_store.clone(),
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
                            span {
                                class: "badge",
                                "data-testid": "call-transcription-status",
                                "data-state": "{transcription().as_data_state()}",
                                "tx: {transcription().as_data_state()}"
                            }
                        }

                        if recording() == RecordingState::Recording {
                            div { class: "event", "data-testid": "call-recording-indicator",
                                span { class: "badge danger", "● recording" }
                            }
                        }
                        if transcription() == TranscriptionState::Transcribing {
                            div { class: "event", "data-testid": "call-transcription-indicator",
                                span { class: "badge danger", "transcribing" }
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
                                    let signal_store = signal_store.clone();
                                    move |_| {
                                        let next = !mic_muted();
                                        mic_muted.set(next);
                                        if let Some(t) = transport() {
                                            let _ = t.borrow_mut().set_audio_muted(next);
                                        }
                                        set_local_state(&mut participants, &actor, next, screen_sharing());
                                        emit_async(
                                            &base, &token(), &active_realm(), &active_call_id(),
                                            &actor, &device,
                                            arkret_sdk::CallSignalData::MuteState(
                                                arkret_sdk::CallMuteStateSignalData {
                                                    audio_muted: next,
                                                    video_muted: !camera_on(),
                                                    changed_by: arkret_sdk::MuteChangedBy::SelfActor,
                                                    target_actor_id: None,
                                                    target_device_id: None,
                                                },
                                            ),
                                            call_seq,
                                            signal_store.clone(),
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
                                    let signal_store = signal_store.clone();
                                    move |_| {
                                        let next = !screen_sharing();
                                        screen_sharing.set(next);
                                        if let Some(t) = transport() {
                                            let _ = t.borrow_mut().set_screen_share(next);
                                        }
                                        set_local_state(&mut participants, &actor, mic_muted(), next);
                                        emit_async(
                                            &base, &token(), &active_realm(), &active_call_id(),
                                            &actor, &device,
                                            arkret_sdk::CallSignalData::MediaState(
                                                arkret_sdk::CallMediaStateSignalData {
                                                    screen: Some(arkret_sdk::ScreenMediaState {
                                                        enabled: next,
                                                        source_id: None,
                                                        with_audio: None,
                                                    }),
                                                },
                                            ),
                                            call_seq,
                                            signal_store.clone(),
                                        );
                                    }
                                },
                                if screen_sharing() { "Stop sharing" } else { "Share screen" }
                            }
                            Button {
                                variant: ButtonVariant::Secondary,
                                "data-testid": "call-record-button",
                                onclick: {
                                    move |_| {
                                        if recording() == RecordingState::Recording {
                                            recording.set(RecordingState::Off);
                                            status.set("recording stopped".to_owned());
                                        } else {
                                            pending_capture.set(Some("recording".to_owned()));
                                            status.set("confirm recording".to_owned());
                                        }
                                    }
                                },
                                if recording() == RecordingState::Recording { "Stop recording" } else { "Record" }
                            }
                            Button {
                                variant: ButtonVariant::Secondary,
                                "data-testid": "call-transcribe-button",
                                onclick: move |_| {
                                    if transcription() == TranscriptionState::Transcribing {
                                        transcription.set(TranscriptionState::Off);
                                        status.set("transcription stopped".to_owned());
                                    } else {
                                        pending_capture.set(Some("transcript".to_owned()));
                                        status.set("confirm transcription".to_owned());
                                    }
                                },
                                if transcription() == TranscriptionState::Transcribing { "Stop transcribing" } else { "Transcribe" }
                            }
                            Button {
                                variant: ButtonVariant::Destructive,
                                "data-testid": "call-leave-button",
                                onclick: {
                                    let base = base_url.clone();
                                    let actor = account_did.clone();
                                    let device = device_id.clone();
                                    let signal_store = signal_store.clone();
                                    move |_| {
                                        end_call(
                                            &transport, &base, &token(), &active_realm(),
                                            &active_call_id(), &actor, &device, call_seq,
                                            signal_store.clone(),
                                        );
                                        stage.set(CallStage::Ended);
                                        recording.set(RecordingState::Off);
                                        transcription.set(TranscriptionState::Off);
                                        pending_capture.set(None);
                                        status.set("left call".to_owned());
                                    }
                                },
                                "Leave"
                            }
                        }

                        if let Some(capture_kind) = pending_capture() {
                            div {
                                class: "event",
                                "data-testid": "call-capture-confirmation",
                                "data-capture-kind": "{capture_kind}",
                                div { class: "event-head",
                                    span {
                                        if capture_kind == "recording" {
                                            "Confirm recording"
                                        } else {
                                            "Confirm transcription"
                                        }
                                    }
                                    span { class: "badge danger", "capture" }
                                }
                                div { class: "actions",
                                    Button {
                                        variant: ButtonVariant::Primary,
                                        "data-testid": "call-capture-confirm-button",
                                        onclick: {
                                            let mut start_confirmed_capture = start_confirmed_capture.clone();
                                            let capture_kind = capture_kind.clone();
                                            move |_| start_confirmed_capture(capture_kind.clone())
                                        },
                                        "Confirm"
                                    }
                                    Button {
                                        variant: ButtonVariant::Secondary,
                                        "data-testid": "call-capture-cancel-button",
                                        onclick: move |_| {
                                            pending_capture.set(None);
                                            status.set("capture cancelled".to_owned());
                                        },
                                        "Cancel"
                                    }
                                }
                            }
                        }

                        // Moderator controls.
                        ModeratorControls {
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
                                recording.set(RecordingState::Off);
                                transcription.set(TranscriptionState::Off);
                                pending_capture.set(None);
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
