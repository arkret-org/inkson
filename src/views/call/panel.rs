use std::rc::Rc;

use glory::prelude::*;

use super::media::{
    install_and_capture, join_and_build_transport, media_error_label, submit_call_state_participant,
};
use super::projection::{
    build_roster, call_state_participant_actor_device_map, call_state_participant_device_map,
    call_state_participant_identities, expected_participant_set, media_governance_evidence,
    media_service_decrypts_enabled, media_service_selection, participant_list_from_input,
    set_local_state,
};
use super::signaling::{
    apply_inbox_items, emit_async, emit_signal, end_call, relay_local_signals, spawn_reject,
};
use super::task::call_task;
use super::types::{
    CallParticipantView, CallStage, CallStartMode, RecordingState, SharedTransport,
    TranscriptionState,
};
use crate::media::rtc::{DesiredMedia, MediaJoinRequest};
use crate::presentation::{InksonContext, View};
use crate::transport::auth::with_event_submitter;

pub struct CallPanelProps {
    pub selected_realm_id: String,
    pub principal_id: String,
    pub device_id: String,
    pub call_id: String,
    pub peer: String,
    pub want_video: bool,
    pub incoming: bool,
}
pub fn call_panel(scope: &Scope, context: Rc<InksonContext>, props: CallPanelProps) -> View {
    let CallPanelProps {
        selected_realm_id,
        principal_id,
        device_id,
        call_id,
        peer,
        want_video,
        incoming,
    } = props;
    let token = context.token;
    let task_scope = scope.downgrade();
    // A4 — base_url / state_store from session context instead of props.
    let session_context = context.clone();
    let base_url = context.base_url.get();
    let state_store = session_context.state_store.clone();
    let active_account = session_context.active_account;
    // Sealing a Signal burns the SDK-owned AEAD nonce counter into the
    // persisted MLS snapshot before submit, so every emit needs the store
    // itself and not just the key-material descriptor.
    let signal_store = state_store.handle();
    let initial_stage = if incoming {
        CallStage::IncomingRinging
    } else if !call_id.is_empty() {
        CallStage::OutgoingRinging
    } else {
        CallStage::Idle
    };

    let stage = scope.cage(initial_stage);
    let status = scope.cage((String::new)());
    let last_error = scope.cage((String::new)());
    let mic_muted = scope.cage(false);
    let camera_on = scope.cage(want_video);
    let screen_sharing = scope.cage(false);
    let recording = scope.cage(RecordingState::Off);
    let transcription = scope.cage(TranscriptionState::Off);
    let recording_segment =
        scope.cage(Option::<(arkret_sdk::CallId, arkret_sdk::CallRecordingId)>::None);
    let transcript_segment =
        scope.cage(Option::<(arkret_sdk::CallId, arkret_sdk::CallRecordingId)>::None);
    let pending_capture = scope.cage(Option::<String>::None);
    let capture_confirmation = scope.cage(Option::<(String, String, arkret_sdk::AccountId)>::None);
    let mut participants = scope.cage((Vec::<CallParticipantView>::new)());
    let active_call_id = scope.cage(call_id.clone());
    let call_seq = scope.cage(0_u64);
    let active_realm = scope.cage(selected_realm_id.clone());
    let peer_input = scope.cage(peer.clone());
    let group_input = scope.cage(String::new());
    let want_video_signal = scope.cage(want_video);
    let media_plaintext_confirmed = scope.cage(false);

    // Transport handle — `None` until a media session is joined.
    let transport = scope.cage(Option::<SharedTransport>::None);
    let transport_handle = transport;

    // Receive side: the app-level signaling hub (`crate::views::call_signals`)
    // the sync apply paths feed inbound `ak.call.signal` envelopes into. The
    // drain effect below consumes this call's inbox and applies each item to
    // the transport / FSM. Best-effort: `None` under isolated unit renders.
    let call_signal_hub = Some(context.call_signal_hub);

    // This panel now owns an active session for `call_id` (deep-link / dialer
    // start / accept). Mark it active so a re-delivered `invite` does not
    // raise a duplicate ring, and clear any pending incoming-ring state for it.
    if let Some(mut hub) = call_signal_hub {
        let owned = active_call_id.get();
        scope.effect(move || {
            let id = active_call_id.get();
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
        scope.effect(move || {
            if stage.get() == CallStage::Ended {
                let id = active_call_id.get();
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
        let actor = principal_id.clone();
        let device = device_id.clone();
        let signal_store = signal_store.clone();
        scope.effect(move || {
            let call = active_call_id.get();
            // Subscribe to inbox changes for this call id.
            let has_pending = hub
                .inbox
                .get()
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
                active_realm.get(),
                call,
                call_seq,
                stage,
                status,
                last_error,
                participants,
                signal_store.clone(),
            );
        });
    }

    let media_plaintext_confirmation_required = {
        let state_store = state_store.clone();
        let revision = context.state_revision;
        scope.bond(move || {
            let _ = revision.get();
            state_store.read(|store| media_service_decrypts_enabled(store, &active_realm.get()))
        })
    };
    // ── Start an outgoing call (1:1 or SFU). ─────────────────────────
    let start_call = {
        let context = context.clone();
        let task_scope = task_scope.clone();
        let state_store = state_store.clone();
        let base = base_url.clone();
        let actor = principal_id.clone();
        let device = device_id.clone();
        let signal_store = signal_store.clone();
        move |mode: CallStartMode| {
            let base = base.clone();
            let actor = actor.clone();
            let device = device.clone();
            let realm_id = active_realm.get();
            let api_token = token.get();
            let want_video = want_video_signal.get();
            let Some(account) = active_account.get() else {
                {
                    let next_value = "active account is unavailable".to_owned();
                    last_error.revise(|value| *value = next_value);
                };
                return;
            };

            let peers: Vec<String> = match mode {
                CallStartMode::P2p => vec![peer_input.get().trim().to_owned()]
                    .into_iter()
                    .filter(|p| !p.is_empty())
                    .collect(),
                CallStartMode::Sfu => participant_list_from_input(&group_input.get()),
            };

            let existing_call = active_call_id.get();
            let call_create_operation = if existing_call.is_empty() {
                let payload = arkret_sdk::CallCreatePayload {
                    initial_state: arkret_sdk::CallLifecycleState::Ringing,
                };
                match crate::operation::TypedOperationBuilder::new::<
                    arkret_sdk::event_spec::CallCreate,
                >(&realm_id, &actor, payload)
                .build_sdk_event("inkson")
                {
                    Ok(operation) => Some(operation),
                    Err(error) => {
                        {
                            let next_value = format!("call create build failed: {error:#}");
                            last_error.revise(|value| *value = next_value);
                        };
                        return;
                    }
                }
            } else {
                None
            };
            let signal_store = signal_store.clone();
            let state_store = state_store.clone();
            call_task(context.clone(), Some(task_scope.clone()), async move {
                // The Call is named by `retype(create.event_id)`, so the durable
                // genesis must be ACCEPTED before anything — participant state,
                // the media plane, signaling — can name this Call. Its id comes
                // from the receipt, never from a draft.
                let call = match call_create_operation {
                    Some(operation) => {
                        let accepted = with_event_submitter(
                            &base,
                            api_token.clone(),
                            |submitter| async move { submitter.submit_sdk_event(&operation).await },
                        )
                        .await;
                        match accepted {
                            Ok(accepted) => {
                                match arkret_sdk::EventId::new(accepted.event_id.clone()) {
                                    Ok(event_id) => {
                                        arkret_sdk::CallId::from_event_id(&event_id).to_string()
                                    }
                                    Err(error) => {
                                        {
                                            let next_value = format!(
                                                "accepted call create id is invalid: {error}"
                                            );
                                            last_error.revise(|value| *value = next_value);
                                        };
                                        return;
                                    }
                                }
                            }
                            Err(err) => {
                                {
                                    let next_value =
                                        format!("call create failed: {}", err.display());
                                    last_error.revise(|value| *value = next_value);
                                };
                                return;
                            }
                        }
                    }
                    None => existing_call,
                };
                let (
                    media_service_ids,
                    focus_id,
                    known_actor_devices,
                    known_participant_identities,
                    known_participant_devices,
                    governance_evidence,
                    realm_mls_checkpoint,
                ) = state_store.read(|store| {
                    let (media_service_ids, focus_id) = media_service_selection(store, &realm_id);
                    (
                        media_service_ids,
                        focus_id,
                        call_state_participant_actor_device_map(store, &realm_id, &call),
                        call_state_participant_identities(store, &realm_id, &call),
                        call_state_participant_device_map(store, &realm_id, &call),
                        media_governance_evidence(
                            store,
                            &realm_id,
                            &device,
                            media_plaintext_confirmed.get(),
                        ),
                        store.mls_checkpoint_for(&realm_id),
                    )
                });
                {
                    let next_value = call.clone();
                    active_call_id.revise(|value| *value = next_value);
                };
                {
                    let next_value = 0;
                    call_seq.revise(|value| *value = next_value);
                };
                let roster = match build_roster(&actor, &peers, &known_actor_devices) {
                    Ok(roster) => roster,
                    Err(error) => {
                        {
                            let next_value = format!("invalid call participant identity: {error}");
                            last_error.revise(|value| *value = next_value);
                        };
                        return;
                    }
                };
                {
                    let next_value = roster;
                    participants.revise(|value| *value = next_value);
                };
                {
                    let next_value = CallStage::OutgoingRinging;
                    stage.revise(|value| *value = next_value);
                };
                {
                    let next_value = "placing call".to_owned();
                    status.revise(|value| *value = next_value);
                };
                {
                    let next_value = String::new();
                    last_error.revise(|value| *value = next_value);
                };

                // Evaluator-produced route material (service-surface.md §2.6
                // L183): fetch + verify the media service's signed resolution
                // and run it through the durable-floor / fail-closed route
                // evaluator. Any failure ends the call attempt visibly — the
                // token exchange never runs with unverified or empty routes.
                let verified_media_bindings =
                    match crate::media::service_route::evaluate_media_routes(
                        &base,
                        &realm_id,
                        &media_service_ids,
                    )
                    .await
                    {
                        Ok(routes) => routes,
                        Err(error) => {
                            {
                                let next_value =
                                    format!("media route evaluation failed: {error:#}");
                                last_error.revise(|value| *value = next_value);
                            };
                            {
                                let next_value = CallStage::Ended;
                                stage.revise(|value| *value = next_value);
                            };
                            return;
                        }
                    };

                // Join the media plane (token + ICE + SFrame key). P2P emits
                // its invite only after the transport produces the real SDP
                // offer; the closed signal model intentionally forbids a
                // placeholder invite without an offer.
                let media_service_decryption_requested = governance_evidence
                    .as_ref()
                    .is_some_and(|evidence| evidence.media_service_decrypts_enabled());
                let desired = if want_video {
                    DesiredMedia::audio_video()
                } else {
                    DesiredMedia::audio_only()
                };
                let restored = state_store.read(|store| {
                    super::projection::accepted_refresh_context(
                        store,
                        &account.authority,
                        &account.device_id,
                        &realm_id,
                        &call,
                        &focus_id,
                    )
                });
                let join_context = match restored {
                    Ok(Some(context)) => context,
                    Ok(None) => match crate::media::rtc::voluntary_join_context(
                        &realm_id,
                        &call,
                        &account.authority,
                        &account.device_id,
                        &focus_id,
                        desired,
                    ) {
                        Ok(context) => context,
                        Err(error) => {
                            {
                                let next_value = media_error_label(error).to_owned();
                                last_error.revise(|value| *value = next_value);
                            };
                            {
                                let next_value = CallStage::Ended;
                                stage.revise(|value| *value = next_value);
                            };
                            return;
                        }
                    },
                    Err(error) => {
                        {
                            let next_value = format!("media refresh recovery failed: {error:#}");
                            last_error.revise(|value| *value = next_value);
                        };
                        {
                            let next_value = CallStage::Ended;
                            stage.revise(|value| *value = next_value);
                        };
                        return;
                    }
                };
                let join = MediaJoinRequest {
                    account_id: account.authority.clone(),
                    join_context,
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
                    media_service_ids,
                    verified_media_bindings,
                    governance_evidence,
                    media_service_decryption_requested,
                };
                match join_and_build_transport(
                    &base,
                    &api_token,
                    &join,
                    &account.authority,
                    &account.device_id,
                    realm_mls_checkpoint,
                )
                .await
                {
                    Ok((session, shared, per_sender_keys)) => {
                        if let Err(err) = install_and_capture(&shared, &session) {
                            // Transport could not accept the media key (desktop
                            // is honestly not-ready). Surface it and stay out of
                            // Any unavailable transport stays outside the connected state.
                            last_error.revise(|value| *value = media_error_label(err));
                            {
                                let next_value = CallStage::Ended;
                                stage.revise(|value| *value = next_value);
                            };
                            return;
                        }
                        match mode {
                            CallStartMode::Sfu => {
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
                                    {
                                        let next_value = format!("call state failed: {err}");
                                        last_error.revise(|value| *value = next_value);
                                    };
                                    {
                                        let next_value = CallStage::Ended;
                                        stage.revise(|value| *value = next_value);
                                    };
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
                                    {
                                        let next_value = format!("focus join signal failed: {err}");
                                        last_error.revise(|value| *value = next_value);
                                    };
                                }
                                {
                                    let next_value = 1;
                                    call_seq.revise(|value| *value = next_value);
                                };
                                let expected = expected_participant_set(
                                    &known_participant_identities,
                                    &session.participant_id,
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
                                    {
                                        let next_value = media_error_label(err);
                                        last_error.revise(|value| *value = next_value);
                                    };
                                    {
                                        let next_value = CallStage::Ended;
                                        stage.revise(|value| *value = next_value);
                                    };
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
                                {
                                    let next_value = CallStage::Active;
                                    stage.revise(|value| *value = next_value);
                                };
                                {
                                    let next_value =
                                        format!("joined SFU room ({})", session.backend_kind);
                                    status.revise(|value| *value = next_value);
                                };
                            }
                            CallStartMode::P2p => {
                                if let Err(err) = shared.borrow_mut().begin_offer() {
                                    {
                                        let next_value = media_error_label(err);
                                        last_error.revise(|value| *value = next_value);
                                    };
                                    {
                                        let next_value = CallStage::Ended;
                                        stage.revise(|value| *value = next_value);
                                    };
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
                                {
                                    let next_value = CallStage::Connecting;
                                    stage.revise(|value| *value = next_value);
                                };
                                {
                                    let next_value = "offer sent, awaiting answer".to_owned();
                                    status.revise(|value| *value = next_value);
                                };
                            }
                        }
                        transport_handle.revise(|value| *value = Some(shared));
                    }
                    Err(err) => {
                        {
                            let next_value = media_error_label(err);
                            last_error.revise(|value| *value = next_value);
                        };
                        {
                            let next_value = CallStage::Ended;
                            stage.revise(|value| *value = next_value);
                        };
                    }
                }
            });
        }
    };

    // Only native current or a committed Start may declare a capture permission
    // active. These handles never stand in for a running encrypted recorder.
    {
        let state_store = state_store.clone();
        let revision = context.state_revision;
        scope.effect(move || {
            let _ = revision.get();
            let realm = active_realm.get();
            let call = active_call_id.get();
            let Ok(call_id) = arkret_sdk::CallId::new(call.clone()) else {
                return;
            };
            for kind in [
                arkret_sdk::RecordingCaptureKind::Recording,
                arkret_sdk::RecordingCaptureKind::Transcript,
            ] {
                let saved = if kind == arkret_sdk::RecordingCaptureKind::Recording {
                    recording_segment.get_untracked()
                } else {
                    transcript_segment.get_untracked()
                };
                let native = state_store.read(|store| {
                    super::projection::current_capture_segment(store, &realm, &call, kind)
                });
                let no_active_segment = matches!(&native, Ok(None));
                if let Ok(Some(id)) = native {
                    let next = Some((call_id.clone(), id));
                    if kind == arkret_sdk::RecordingCaptureKind::Recording {
                        if recording_segment.get_untracked() != next {
                            recording_segment.revise(|value| *value = next);
                        }
                        if recording.get_untracked() != RecordingState::Recording {
                            recording.revise(|value| *value = RecordingState::Recording);
                        }
                    } else {
                        if transcript_segment.get_untracked() != next {
                            transcript_segment.revise(|value| *value = next);
                        }
                        if transcription.get_untracked() != TranscriptionState::Transcribing {
                            transcription.revise(|value| *value = TranscriptionState::Transcribing);
                        }
                    }
                } else if no_active_segment
                    && saved
                        .as_ref()
                        .is_some_and(|(held_call, _)| held_call != &call_id)
                {
                    // Changing the displayed Call does not stop its old
                    // segment. This complete view has no active new segment.
                    if kind == arkret_sdk::RecordingCaptureKind::Recording {
                        recording_segment.revise(|value| *value = None);
                        recording.revise(|value| *value = RecordingState::Off);
                    } else {
                        transcript_segment.revise(|value| *value = None);
                        transcription.revise(|value| *value = TranscriptionState::Off);
                    }
                } else if let Some((held_call, segment)) = saved
                    && held_call == call_id
                    && state_store
                        .read(|store| {
                            super::projection::current_capture_stopped(
                                store, &realm, &call, &segment, kind,
                            )
                        })
                        .unwrap_or(false)
                {
                    if kind == arkret_sdk::RecordingCaptureKind::Recording {
                        recording_segment.revise(|value| *value = None);
                        recording.revise(|value| *value = RecordingState::Off);
                    } else {
                        transcript_segment.revise(|value| *value = None);
                        transcription.revise(|value| *value = TranscriptionState::Off);
                    }
                }
            }
        });
    }

    let start_confirmed_capture = {
        let context = context.clone();
        let task_scope = task_scope.clone();
        let base = base_url.clone();
        move |capture_kind: String| {
            let kind = match capture_kind.as_str() {
                "recording" => arkret_sdk::RecordingCaptureKind::Recording,
                "transcript" => arkret_sdk::RecordingCaptureKind::Transcript,
                _ => return,
            };
            let Some(account) = active_account.get() else {
                last_error.revise(|value| *value = "active account is unavailable".to_owned());
                return;
            };
            if capture_confirmation.get_untracked()
                != Some((
                    active_realm.get(),
                    active_call_id.get(),
                    account.authority.clone(),
                ))
            {
                pending_capture.revise(|value| *value = None);
                last_error.revise(|value| {
                    *value = "capture confirmation belongs to a replaced Call or Account".to_owned()
                });
                return;
            }
            let actor = arkret_sdk::ActorId::account(account.authority);
            let base = base.clone();
            let realm = active_realm.get();
            let call = active_call_id.get();
            let api_token = token.get();
            let mode = if camera_on.get() {
                arkret_sdk::RecordingMode::AudioVideo
            } else {
                arkret_sdk::RecordingMode::AudioOnly
            };
            pending_capture.revise(|value| *value = None);
            capture_confirmation.revise(|value| *value = None);
            status.revise(|value| *value = "capture permission pending".to_owned());
            call_task(context.clone(), Some(task_scope.clone()), async move {
                let id = match arkret_sdk::CallRecordingId::new(format!(
                    "rtc-{capture_kind}-{}",
                    crate::operation::uuid_v7()
                )) {
                    Ok(id) => id,
                    Err(error) => {
                        last_error.revise(|value| *value = error.to_string());
                        return;
                    }
                };
                let Ok(call_id) = arkret_sdk::CallId::new(call.clone()) else {
                    return;
                };
                let submitted_id = id.clone();
                let selected_call = call.clone();
                let result = with_event_submitter(&base, api_token, |sub| async move {
                    match kind {
                        arkret_sdk::RecordingCaptureKind::Recording => {
                            crate::transport::media::submit_call_recording_start(
                                &sub,
                                &realm,
                                &actor,
                                &call,
                                &submitted_id,
                                mode,
                            )
                            .await
                        }
                        arkret_sdk::RecordingCaptureKind::Transcript => {
                            crate::transport::media::submit_call_transcription_start(
                                &sub,
                                &realm,
                                &actor,
                                &call,
                                &submitted_id,
                                mode,
                            )
                            .await
                        }
                    }
                })
                .await;
                if active_call_id.get_untracked() != selected_call {
                    return;
                }
                match result {
                    Ok(progress) if progress.status == garth::SendQueueStatus::Rejected => {
                        last_error.revise(|value| {
                            *value = progress
                                .rejection_reason_code
                                .unwrap_or_else(|| "capture permission rejected".to_owned())
                        });
                    }
                    Ok(progress) => {
                        let committed =
                            crate::transport::media::capture_progress_is_committed(&progress);
                        if kind == arkret_sdk::RecordingCaptureKind::Recording {
                            recording_segment.revise(|value| *value = Some((call_id, id)));
                            recording.revise(|value| {
                                *value = if committed {
                                    RecordingState::Recording
                                } else {
                                    RecordingState::Pending
                                }
                            });
                        } else {
                            transcript_segment.revise(|value| *value = Some((call_id, id)));
                            transcription.revise(|value| {
                                *value = if committed {
                                    TranscriptionState::Transcribing
                                } else {
                                    TranscriptionState::Pending
                                }
                            });
                        }
                        status.revise(|value| {
                            *value = if committed {
                                "capture permission accepted"
                            } else {
                                "capture permission pending"
                            }
                            .to_owned()
                        });
                    }
                    Err(error) => last_error.revise(|value| *value = error.display()),
                }
            });
        }
    };

    let stop_capture: Rc<dyn Fn(arkret_sdk::RecordingCaptureKind)> = {
        let context = context.clone();
        let task_scope = task_scope.clone();
        let base = base_url.clone();
        Rc::new(move |kind| {
            let Some(account) = active_account.get() else {
                last_error.revise(|value| *value = "active account is unavailable".to_owned());
                return;
            };
            let actor = arkret_sdk::ActorId::account(account.authority);
            let realm = active_realm.get();
            let call = active_call_id.get();
            let saved = if kind == arkret_sdk::RecordingCaptureKind::Recording {
                recording_segment.get()
            } else {
                transcript_segment.get()
            };
            if saved
                .as_ref()
                .is_some_and(|(held_call, _)| held_call.as_str() != call)
            {
                last_error
                    .revise(|value| *value = "capture segment belongs to another Call".to_owned());
                return;
            }
            let segment = saved.map(|(_, segment)| segment);
            let api_token = token.get();
            let base = base.clone();
            let selected_call = call.clone();
            status.revise(|value| *value = "capture Stop pending".to_owned());
            call_task(context.clone(), Some(task_scope.clone()), async move {
                let result = with_event_submitter(&base, api_token, |sub| async move {
                    crate::transport::media::submit_call_capture_stop(
                        &sub,
                        &realm,
                        &actor,
                        &call,
                        segment.as_ref(),
                        kind,
                    )
                    .await
                })
                .await;
                if active_call_id.get_untracked() != selected_call {
                    return;
                }
                match result {
                    Ok(outcome) if outcome.is_stopped() => {
                        if kind == arkret_sdk::RecordingCaptureKind::Recording {
                            recording.revise(|value| *value = RecordingState::Off);
                            recording_segment.revise(|value| *value = None);
                        } else {
                            transcription.revise(|value| *value = TranscriptionState::Off);
                            transcript_segment.revise(|value| *value = None);
                        }
                        status.revise(|value| *value = "capture permission stopped".to_owned());
                    }
                    Ok(_) => status.revise(|value| *value = "capture Stop pending".to_owned()),
                    Err(error) => last_error.revise(|value| *value = error.display()),
                }
            });
        })
    };

    let mut callbacks = super::surface::Callbacks::default();
    {
        let _state_store = state_store.clone();
        let _context = context.clone();
        let _task_scope = task_scope.clone();
        callbacks.add("call-want-video-toggle", move || {
            let next = !want_video_signal.get();
            {
                let next_value = next;
                want_video_signal.revise(|value| *value = next_value);
            };
            {
                let next_value = next;
                camera_on.revise(|value| *value = next_value);
            };
        });
    }
    {
        let _state_store = state_store.clone();
        let _context = context.clone();
        let _task_scope = task_scope.clone();
        callbacks.add("call-start-voice-button", {
            let start = start_call.clone();
            move || start(CallStartMode::P2p)
        });
    }
    {
        let _state_store = state_store.clone();
        let _context = context.clone();
        let _task_scope = task_scope.clone();
        callbacks.add("call-start-group-button", {
            let start = start_call.clone();
            move || start(CallStartMode::Sfu)
        });
    }
    {
        let _state_store = state_store.clone();
        let _context = context.clone();
        let _task_scope = task_scope.clone();
        callbacks.add("call-cancel-button", {
            let base = base_url.clone();
            let actor = principal_id.clone();
            let device = device_id.clone();
            let signal_store = signal_store.clone();
            move || {
                end_call(
                    &transport,
                    &base,
                    &token.get(),
                    &active_realm.get(),
                    &active_call_id.get(),
                    &actor,
                    &device,
                    call_seq,
                    signal_store.clone(),
                );
                {
                    let next_value = CallStage::Ended;
                    stage.revise(|value| *value = next_value);
                };
                {
                    let next_value = "cancelled".to_owned();
                    status.revise(|value| *value = next_value);
                };
            }
        });
    }
    {
        let state_store = state_store.clone();
        let context = context.clone();
        let task_scope = task_scope.clone();
        callbacks.add("call-accept-button", {
            let base = base_url.clone();
            let actor = principal_id.clone();
            let device = device_id.clone();
            let signal_store = signal_store.clone();
            move || {
                let base = base.clone();
                let actor = actor.clone();
                let device = device.clone();
                let realm_id = active_realm.get();
                let call = active_call_id.get();
                let api_token = token.get();
                let signal_store = signal_store.clone();
                let Some(account) = active_account.get() else {
                    {
                        let next_value = "active account is unavailable".to_owned();
                        last_error.revise(|value| *value = next_value);
                    };
                    return;
                };
                let (
                    media_service_ids,
                    focus_id,
                    known_participant_identities,
                    known_participant_devices,
                    governance_evidence,
                    realm_mls_checkpoint,
                ) = state_store.read(|store| {
                    let (media_service_ids, focus_id) = media_service_selection(store, &realm_id);
                    (
                        media_service_ids,
                        focus_id,
                        call_state_participant_identities(store, &realm_id, &call),
                        call_state_participant_device_map(store, &realm_id, &call),
                        media_governance_evidence(
                            store,
                            &realm_id,
                            &device,
                            media_plaintext_confirmed.get(),
                        ),
                        store.mls_checkpoint_for(&realm_id),
                    )
                });
                let want_video = want_video_signal.get();
                {
                    let next_value = CallStage::Connecting;
                    stage.revise(|value| *value = next_value);
                };
                {
                    let next_value = "answering".to_owned();
                    status.revise(|value| *value = next_value);
                };
                let _state_store = state_store.clone();
                call_task(context.clone(), Some(task_scope.clone()), async move {
                    // Evaluator-produced route material — same
                    // fail-closed gate as the outgoing path.
                    let verified_media_bindings =
                        match crate::media::service_route::evaluate_media_routes(
                            &base,
                            &realm_id,
                            &media_service_ids,
                        )
                        .await
                        {
                            Ok(routes) => routes,
                            Err(error) => {
                                {
                                    let next_value =
                                        format!("media route evaluation failed: {error:#}");
                                    last_error.revise(|value| *value = next_value);
                                };
                                {
                                    let next_value = CallStage::Ended;
                                    stage.revise(|value| *value = next_value);
                                };
                                return;
                            }
                        };
                    let media_service_decryption_requested = governance_evidence
                        .as_ref()
                        .is_some_and(|evidence| evidence.media_service_decrypts_enabled());
                    let delivery = call_signal_hub
                        .as_ref()
                        .and_then(|hub| hub.invitation_contexts.get().get(&call).cloned());
                    let Some(delivery) = delivery else {
                        {
                            let next_value =
                                "accepted invitation context is unavailable".to_owned();
                            last_error.revise(|value| *value = next_value);
                        };
                        {
                            let next_value = CallStage::Ended;
                            stage.revise(|value| *value = next_value);
                        };
                        return;
                    };
                    let join_context = arkret_sdk::CallMediaJoinContext::Invitation(
                        arkret_sdk::CallInvitationJoinContext {
                            kind: arkret_sdk::CallInvitationJoinKind::Invitation,
                            invitation: delivery.invitation,
                            envelope: delivery.request.envelope,
                        },
                    );
                    let join = MediaJoinRequest {
                        account_id: account.authority.clone(),
                        join_context,
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
                        media_service_ids,
                        verified_media_bindings,
                        governance_evidence,
                        media_service_decryption_requested,
                    };
                    match join_and_build_transport(
                        &base,
                        &api_token,
                        &join,
                        &account.authority,
                        &account.device_id,
                        realm_mls_checkpoint,
                    )
                    .await
                    {
                        Ok((session, shared, per_sender_keys)) => {
                            if let Err(err) = install_and_capture(&shared, &session) {
                                {
                                    let next_value = media_error_label(err);
                                    last_error.revise(|value| *value = next_value);
                                };
                                {
                                    let next_value = CallStage::Ended;
                                    stage.revise(|value| *value = next_value);
                                };
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
                                {
                                    let next_value = format!("call state failed: {err}");
                                    last_error.revise(|value| *value = next_value);
                                };
                                {
                                    let next_value = CallStage::Ended;
                                    stage.revise(|value| *value = next_value);
                                };
                                return;
                            }
                            if let Ok(focus_id) = arkret_sdk::NonEmptyString::new(focus_id.clone())
                            {
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
                                &session.participant_id,
                            );
                            shared.borrow_mut().set_expected_participants(&expected);
                            // §8.1: hand the per-sender deriver +
                            // identity→device_id map so each remote
                            // sender's frame key is recomputed on
                            // connect (receiver decrypt).
                            shared.borrow_mut().set_remote_key_source(
                                per_sender_keys.clone(),
                                known_participant_devices.clone(),
                            );
                            let connect_result = { shared.borrow_mut().connect_sfu(&session) };
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
                                    transport_handle.revise(|value| *value = Some(shared));
                                    {
                                        let next_value = CallStage::Active;
                                        stage.revise(|value| *value = next_value);
                                    };
                                    {
                                        let next_value = "connected".to_owned();
                                        status.revise(|value| *value = next_value);
                                    };
                                }
                                Err(err) => {
                                    // Honestly not-ready (desktop) — do not
                                    // Do not publish a connected state for a failed transport.
                                    last_error.revise(|value| *value = media_error_label(err));
                                    {
                                        let next_value = CallStage::Ended;
                                        stage.revise(|value| *value = next_value);
                                    };
                                }
                            }
                        }
                        Err(err) => {
                            {
                                let next_value = media_error_label(err);
                                last_error.revise(|value| *value = next_value);
                            };
                            {
                                let next_value = CallStage::Ended;
                                stage.revise(|value| *value = next_value);
                            };
                        }
                    }
                });
            }
        });
    }
    {
        let _state_store = state_store.clone();
        let _context = context.clone();
        let _task_scope = task_scope.clone();
        callbacks.add("call-decline-button", {
            let base = base_url.clone();
            let actor = principal_id.clone();
            let device = device_id.clone();
            let signal_store = signal_store.clone();
            move || {
                let _ = crate::media::rtc::MEDIA_TOKEN_TTL_MAX_SECS;
                spawn_reject(
                    base.clone(),
                    token.get(),
                    active_realm.get(),
                    active_call_id.get(),
                    actor.clone(),
                    device.clone(),
                    signal_store.clone(),
                );
                {
                    let next_value = CallStage::Ended;
                    stage.revise(|value| *value = next_value);
                };
                {
                    let next_value = "declined".to_owned();
                    status.revise(|value| *value = next_value);
                };
            }
        });
    }
    {
        let _state_store = state_store.clone();
        let _context = context.clone();
        let _task_scope = task_scope.clone();
        callbacks.add("call-mute-button", {
            let base = base_url.clone();
            let actor = principal_id.clone();
            let device = device_id.clone();
            let signal_store = signal_store.clone();
            move || {
                let next = !mic_muted.get();
                {
                    let next_value = next;
                    mic_muted.revise(|value| *value = next_value);
                };
                if let Some(t) = transport.get() {
                    let _ = t.borrow_mut().set_audio_muted(next);
                }
                set_local_state(&mut participants, &actor, next, screen_sharing.get());
                emit_async(
                    &base,
                    &token.get(),
                    &active_realm.get(),
                    &active_call_id.get(),
                    &actor,
                    &device,
                    arkret_sdk::CallSignalData::MuteState(arkret_sdk::CallMuteStateSignalData {
                        audio_muted: next,
                        video_muted: !camera_on.get(),
                        changed_by: arkret_sdk::MuteChangedBy::SelfActor,
                        target_actor_id: None,
                        target_device_id: None,
                    }),
                    call_seq,
                    signal_store.clone(),
                );
            }
        });
    }
    {
        let _state_store = state_store.clone();
        let _context = context.clone();
        let _task_scope = task_scope.clone();
        callbacks.add("call-camera-button", move || {
            let next = !camera_on.get();
            {
                let next_value = next;
                camera_on.revise(|value| *value = next_value);
            };
            if let Some(t) = transport.get() {
                let _ = t.borrow_mut().set_video_muted(!next);
            }
        });
    }
    {
        let _state_store = state_store.clone();
        let _context = context.clone();
        let _task_scope = task_scope.clone();
        callbacks.add("call-screen-share-button", {
            let base = base_url.clone();
            let actor = principal_id.clone();
            let device = device_id.clone();
            let signal_store = signal_store.clone();
            move || {
                let next = !screen_sharing.get();
                {
                    let next_value = next;
                    screen_sharing.revise(|value| *value = next_value);
                };
                if let Some(t) = transport.get() {
                    let _ = t.borrow_mut().set_screen_share(next);
                }
                set_local_state(&mut participants, &actor, mic_muted.get(), next);
                emit_async(
                    &base,
                    &token.get(),
                    &active_realm.get(),
                    &active_call_id.get(),
                    &actor,
                    &device,
                    arkret_sdk::CallSignalData::MediaState(arkret_sdk::CallMediaStateSignalData {
                        screen: Some(arkret_sdk::ScreenMediaState {
                            enabled: next,
                            source_id: None,
                            with_audio: None,
                        }),
                    }),
                    call_seq,
                    signal_store.clone(),
                );
            }
        });
    }
    {
        let state_store = state_store.clone();
        let stop_capture = stop_capture.clone();
        callbacks.add("call-record-button", move || {
            if recording.get() != RecordingState::Off {
                stop_capture(arkret_sdk::RecordingCaptureKind::Recording);
                return;
            }
            if let Err(error) = state_store.read(|store| {
                super::projection::capture_start_available(
                    store,
                    &active_realm.get(),
                    &active_call_id.get(),
                    arkret_sdk::RecordingCaptureKind::Recording,
                )
            }) {
                last_error.revise(|value| *value = error.to_string());
                return;
            }
            let Some(account) = active_account.get() else {
                last_error.revise(|value| *value = "active account is unavailable".to_owned());
                return;
            };
            capture_confirmation.revise(|value| {
                *value = Some((active_realm.get(), active_call_id.get(), account.authority))
            });
            pending_capture.revise(|value| *value = Some("recording".to_owned()));
            status.revise(|value| *value = "confirm recording".to_owned());
        });
    }
    {
        let state_store = state_store.clone();
        let stop_capture = stop_capture.clone();
        callbacks.add("call-transcribe-button", move || {
            if transcription.get() != TranscriptionState::Off {
                stop_capture(arkret_sdk::RecordingCaptureKind::Transcript);
                return;
            }
            if let Err(error) = state_store.read(|store| {
                super::projection::capture_start_available(
                    store,
                    &active_realm.get(),
                    &active_call_id.get(),
                    arkret_sdk::RecordingCaptureKind::Transcript,
                )
            }) {
                last_error.revise(|value| *value = error.to_string());
                return;
            }
            let Some(account) = active_account.get() else {
                last_error.revise(|value| *value = "active account is unavailable".to_owned());
                return;
            };
            capture_confirmation.revise(|value| {
                *value = Some((active_realm.get(), active_call_id.get(), account.authority))
            });
            pending_capture.revise(|value| *value = Some("transcript".to_owned()));
            status.revise(|value| *value = "confirm transcription".to_owned());
        });
    }
    {
        let _state_store = state_store.clone();
        let _context = context.clone();
        let _task_scope = task_scope.clone();
        callbacks.add("call-leave-button", {
            let base = base_url.clone();
            let actor = principal_id.clone();
            let device = device_id.clone();
            let signal_store = signal_store.clone();
            move || {
                end_call(
                    &transport,
                    &base,
                    &token.get(),
                    &active_realm.get(),
                    &active_call_id.get(),
                    &actor,
                    &device,
                    call_seq,
                    signal_store.clone(),
                );
                {
                    let next_value = CallStage::Ended;
                    stage.revise(|value| *value = next_value);
                };
                {
                    let next_value = None;
                    pending_capture.revise(|value| *value = next_value);
                };
                {
                    let next_value = "left call".to_owned();
                    status.revise(|value| *value = next_value);
                };
            }
        });
    }
    {
        let _state_store = state_store.clone();
        let _context = context.clone();
        let _task_scope = task_scope.clone();
        callbacks.add("call-capture-cancel-button", move || {
            {
                let next_value = None;
                pending_capture.revise(|value| *value = next_value);
            };
            {
                let next_value = "capture cancelled".to_owned();
                status.revise(|value| *value = next_value);
            };
        });
    }
    {
        let _state_store = state_store.clone();
        let _context = context.clone();
        let _task_scope = task_scope.clone();
        callbacks.add("call-reset-button", move || {
            {
                let next_value = CallStage::Idle;
                stage.revise(|value| *value = next_value);
            };
            {
                let next_value = String::new();
                active_call_id.revise(|value| *value = next_value);
            };
            {
                let next_value = Vec::new();
                participants.revise(|value| *value = next_value);
            };
            transport_handle.revise(|value| *value = None);
            {
                let next_value = None;
                pending_capture.revise(|value| *value = next_value);
            };
            {
                let next_value = 0;
                call_seq.revise(|value| *value = next_value);
            };
            {
                let next_value = String::new();
                status.revise(|value| *value = next_value);
            };
        });
    }
    let capture = start_confirmed_capture.clone();
    callbacks.add("call-capture-confirm-button", move || {
        if let Some(kind) = pending_capture.get_untracked() {
            capture(kind);
        }
    });

    let cleanup_transport = transport;
    let _ = scope.on_cleanup(move || {
        if let Ok(Some(transport)) = cleanup_transport.try_get() {
            transport.borrow_mut().close();
        }
    });
    super::surface::surface(
        scope,
        context,
        super::surface::CallSurface {
            stage,
            status,
            last_error,
            mic_muted,
            camera_on,
            screen_sharing,
            recording,
            transcription,
            pending_capture,
            participants,
            active_call_id,
            active_realm,
            peer_input,
            group_input,
            want_video_signal,
            media_plaintext_confirmed,
            call_seq,
        },
        callbacks,
        media_plaintext_confirmation_required,
        principal_id,
        device_id,
    )
}
