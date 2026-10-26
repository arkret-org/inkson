use glory::prelude::*;

use super::media::media_error_label;
use super::types::{CallParticipantView, CallStage, SharedTransport};
use crate::rtc_transport::LocalSignal;
use crate::transport::auth::with_event_submitter;
use crate::views::call_signals::CallSignalInboxItem;

/// Drain and relay any local SDP/ICE signaling produced by the transport.
pub(super) async fn relay_local_signals(
    transport: &SharedTransport,
    base: &str,
    api_token: &str,
    realm_id: &str,
    call_id: &str,
    actor: &str,
    device: &str,
    call_seq: Cage<u64>,
    initial_invite_media: Option<arkret_sdk::CallMediaSelection>,
    state_store: &crate::runtime::input::StateStoreHandle,
) {
    let signals = transport.borrow_mut().drain_local_signals();
    for signal in signals {
        if !call_seq.is_alive() {
            break;
        }
        let sequence = call_seq.get() + 1;
        {
            let next_value = sequence;
            call_seq.revise(|value| *value = next_value);
        };
        let signal = match signal {
            LocalSignal::Offer { sdp } => {
                let offer = arkret_sdk::SessionDescription {
                    sdp_type: arkret_sdk::SessionDescriptionType::Offer,
                    sdp,
                };
                if let Some(media) = initial_invite_media.clone() {
                    arkret_sdk::CallSignalData::Invite(arkret_sdk::CallInviteSignalData {
                        lifetime_ms: 60_000,
                        offer,
                        media,
                    })
                } else {
                    arkret_sdk::CallSignalData::Renegotiate(arkret_sdk::CallRenegotiateSignalData {
                        reason: arkret_sdk::RenegotiationReason::AddTrack,
                        ice_restart: false,
                        offer: Some(offer),
                        answer: None,
                        media: None,
                    })
                }
            }
            LocalSignal::Answer { sdp } => {
                arkret_sdk::CallSignalData::Renegotiate(arkret_sdk::CallRenegotiateSignalData {
                    reason: arkret_sdk::RenegotiationReason::AddTrack,
                    ice_restart: false,
                    offer: None,
                    answer: Some(arkret_sdk::SessionDescription {
                        sdp_type: arkret_sdk::SessionDescriptionType::Answer,
                        sdp,
                    }),
                    media: None,
                })
            }
            LocalSignal::Candidate {
                candidate,
                sdp_mid,
                sdp_m_line_index,
            } => arkret_sdk::CallSignalData::Candidate(arkret_sdk::CallCandidateSignalData {
                candidates: vec![arkret_sdk::IceCandidate {
                    candidate,
                    sdp_mid,
                    sdp_m_line_index,
                }],
            }),
        };
        let _ = emit_signal(
            base,
            api_token,
            realm_id,
            call_id,
            actor,
            device,
            sequence,
            signal,
            state_store,
        )
        .await;
    }
}

/// Apply a batch of inbound `ak.call.signal` items (the receive side) to the
/// transport and the call FSM.
///
/// Routing per `signal_kind` (`data` shapes mirror the sender side —
/// `signal::SignalPayload::CallSignal` / `relay_local_signals`):
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
pub(super) fn apply_inbox_items(
    items: Vec<CallSignalInboxItem>,
    transport: Cage<Option<SharedTransport>>,
    base: String,
    token: Cage<String>,
    actor: String,
    device: String,
    realm_id: String,
    call_id: String,
    mut call_seq: Cage<u64>,
    stage: Cage<CallStage>,
    status: Cage<String>,
    last_error: Cage<String>,
    mut participants: Cage<Vec<CallParticipantView>>,
    relay_store: crate::runtime::input::StateStoreHandle,
) {
    // Items that need an async relay (offer → answer) defer to a single
    // spawned task after the synchronous transport mutations are applied, so
    // we never hold a transport borrow across an `.await`.
    let mut relay_after = false;
    for item in items {
        match &item.signal {
            arkret_sdk::CallSignalData::Answer(data) => {
                if let Some(t) = transport.get() {
                    match t.borrow_mut().accept_answer(&data.answer.sdp) {
                        Ok(()) => {
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
                            let next_value = media_error_label(err);
                            last_error.revise(|value| *value = next_value);
                        }
                    }
                }
            }
            arkret_sdk::CallSignalData::Renegotiate(data) => {
                if let Some(offer) = &data.offer {
                    if let Some(t) = transport.get() {
                        match t.borrow_mut().accept_offer(&offer.sdp) {
                            Ok(()) => {
                                relay_after = true;
                                {
                                    let next_value = CallStage::Connecting;
                                    stage.revise(|value| *value = next_value);
                                };
                                {
                                    let next_value = "applying remote offer".to_owned();
                                    status.revise(|value| *value = next_value);
                                };
                            }
                            Err(err) => {
                                let next_value = media_error_label(err);
                                last_error.revise(|value| *value = next_value);
                            }
                        }
                    }
                } else if let Some(answer) = &data.answer
                    && let Some(t) = transport.get()
                {
                    match t.borrow_mut().accept_answer(&answer.sdp) {
                        Ok(()) => {
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
                            let next_value = media_error_label(err);
                            last_error.revise(|value| *value = next_value);
                        }
                    }
                }
            }
            arkret_sdk::CallSignalData::Candidate(data) => {
                if let Some(t) = transport.get() {
                    for candidate in &data.candidates {
                        if let Err(err) = t.borrow_mut().add_remote_candidate(
                            &candidate.candidate,
                            candidate.sdp_mid.as_deref(),
                            candidate.sdp_m_line_index,
                        ) {
                            {
                                let next_value = media_error_label(err);
                                last_error.revise(|value| *value = next_value);
                            };
                        }
                    }
                }
            }
            arkret_sdk::CallSignalData::Hangup(data) | arkret_sdk::CallSignalData::Reject(data) => {
                if let Some(t) = transport.get() {
                    t.borrow_mut().close();
                }
                {
                    let next_value = CallStage::Ended;
                    stage.revise(|value| *value = next_value);
                };
                {
                    let next_value = format!("call ended: {}", data.reason.as_str());
                    status.revise(|value| *value = next_value);
                };
            }
            arkret_sdk::CallSignalData::MuteState(data) => {
                if data.changed_by == arkret_sdk::MuteChangedBy::Moderator {
                    {
                        let next_value =
                            "unsupported_feature: moderator force-mute is deferred in v1"
                                .to_owned();
                        last_error.revise(|value| *value = next_value);
                    };
                    continue;
                }
                apply_peer_state(&mut participants, &item);
            }
            arkret_sdk::CallSignalData::MediaState(_) | arkret_sdk::CallSignalData::Speaking(_) => {
                apply_peer_state(&mut participants, &item);
            }
            arkret_sdk::CallSignalData::Moderation(data) => {
                let target = data.target_actor_id.as_ref();
                let self_targeted = match data.action {
                    arkret_sdk::CallModerationAction::Kick => {
                        target.is_some_and(|target| {
                            crate::mls_api_helpers::local_account_actor_id(&actor)
                                .is_ok_and(|local| *target == local)
                        }) && data
                            .target_device_id
                            .as_ref()
                            .is_some_and(|target| target.as_str() == device)
                    }
                    arkret_sdk::CallModerationAction::Ban => target.is_some_and(|target| {
                        crate::mls_api_helpers::local_account_actor_id(&actor)
                            .is_ok_and(|local| *target == local)
                    }),
                    arkret_sdk::CallModerationAction::EndForAll => true,
                };
                if self_targeted {
                    if let Some(t) = transport.get() {
                        t.borrow_mut().close();
                    }
                    {
                        let next_value = CallStage::Ended;
                        stage.revise(|value| *value = next_value);
                    };
                    {
                        let next_value = format!("removed by moderator ({:?})", data.action);
                        status.revise(|value| *value = next_value);
                    };
                } else if let Some(target) = target {
                    // A peer was kicked/banned — drop their roster tile.
                    let mut roster = participants.get();
                    roster.retain(|p| p.actor_id != target.to_string());
                    {
                        let next_value = roster;
                        participants.revise(|value| *value = next_value);
                    };
                }
            }
            other => {
                tracing::debug!(
                    signal_kind = ?other.kind(),
                    "ignoring unhandled inbound call signal"
                );
            }
        }
    }

    if relay_after && let Some(t) = transport.get() {
        dispatch_signal_work(async move {
            relay_local_signals(
                &t,
                &base,
                &token.get(),
                &realm_id,
                &call_id,
                &actor,
                &device,
                call_seq,
                None,
                &relay_store,
            )
            .await;
        });
    } else {
        // Keep `call_seq` mutable-captured even when no relay fires, so the
        // signature stays uniform; no-op otherwise.
        let _ = &mut call_seq;
    }
}

/// Apply an inbound `mute_state` / `media_state` / `speaking` signal to the
/// sender's roster tile. The sender's actor id is `item.sender_actor`.
fn apply_peer_state(participants: &mut Cage<Vec<CallParticipantView>>, item: &CallSignalInboxItem) {
    let target = item.sender_actor.as_str();
    let mut roster = participants.get();
    let mut changed = false;
    for p in &mut roster {
        if p.actor_id != target {
            continue;
        }
        match &item.signal {
            arkret_sdk::CallSignalData::MuteState(data) => {
                p.muted = data.audio_muted;
                changed = true;
            }
            arkret_sdk::CallSignalData::MediaState(data) => {
                if let Some(screen) = &data.screen {
                    p.screen_sharing = screen.enabled;
                    changed = true;
                }
            }
            arkret_sdk::CallSignalData::Speaking(data) => {
                p.speaking = data.speaking;
                changed = true;
            }
            _ => {}
        }
    }
    if changed {
        {
            let next_value = roster;
            participants.revise(|value| *value = next_value);
        };
    }
}

/// Fire-and-forget signal emit (non-SDP control signals).
#[allow(clippy::too_many_arguments)]
pub(super) fn emit_async(
    base: &str,
    api_token: &str,
    realm_id: &str,
    call_id: &str,
    actor: &str,
    device: &str,
    signal: arkret_sdk::CallSignalData,
    call_seq: Cage<u64>,
    state_store: crate::runtime::input::StateStoreHandle,
) {
    if call_id.trim().is_empty() || realm_id.trim().is_empty() {
        return;
    }
    let sequence = call_seq.get() + 1;
    {
        let next_value = sequence;
        call_seq.revise(|value| *value = next_value);
    };
    let (base, api_token, realm_id, call_id, actor, device) = (
        base.to_owned(),
        api_token.to_owned(),
        realm_id.to_owned(),
        call_id.to_owned(),
        actor.to_owned(),
        device.to_owned(),
    );
    dispatch_signal_work(async move {
        if let Err(error) = emit_signal(
            &base,
            &api_token,
            &realm_id,
            &call_id,
            &actor,
            &device,
            sequence,
            signal.clone(),
            &state_store,
        )
        .await
        {
            // Fire-and-forget by design (candidate / hangup / moderator
            // controls): the rail tolerates loss. A withdrawn scope capability
            // is still worth a trace so it is not mistaken for packet loss.
            tracing::warn!(%error, signal_kind = ?signal.kind(), "call signal was not sent");
        }
    });
}

/// Send a single `ak.call.signal` on the encrypted Signal rail.
///
/// The scope's accepted MLS key material is resolved here rather than passed
/// in: every caller would otherwise have to remember to fetch it, and a caller
/// that forgets produces a call that silently never signals. A scope with no
/// accepted group state has its Signal capability withdrawn (`signal.md` §3)
/// and v1 has no plaintext fallback, so this returns an error the call flow
/// surfaces instead of degrading. The accepted Seal the receiver resolves the
/// sender's live-send eligibility under is fetched by the submitter.
#[allow(clippy::too_many_arguments)]
pub(super) async fn emit_signal(
    base: &str,
    api_token: &str,
    realm_id: &str,
    call_id: &str,
    actor: &str,
    device: &str,
    sequence: u64,
    signal: arkret_sdk::CallSignalData,
    state_store: &crate::runtime::input::StateStoreHandle,
) -> std::result::Result<(), String> {
    let account = crate::presentation::require_current_context()
        .map_err(|error| error.to_string())?
        .active_account
        .get()
        .ok_or_else(|| "active account context is unavailable".to_owned())?;
    if account.principal_id().as_str() != actor.trim()
        || account.device_id.as_str() != device.trim()
    {
        return Err("call signal identity does not match the active account".to_owned());
    }
    // Call signalling is Realm-scoped, so the effective scope has no Circle.
    let material = state_store
        .read(|store| crate::signal::key_material_for_scope(store, realm_id, None))
        .map_err(|error| error.to_string())?;
    let scope_ref = arkret_sdk::ScopeRef::Realm {
        realm_id: arkret_sdk::RealmId::new(realm_id.trim().to_owned())
            .map_err(|error| format!("invalid call signal realm_id: {error}"))?,
    };
    let payload = crate::signal::SignalPayload::CallSignal {
        call_id: arkret_sdk::CallId::new(call_id)
            .map_err(|error| format!("invalid call_id: {error}"))?,
        sequence,
        signal,
    };
    let authority = account.authority;
    let device = account.device_id;
    let material = material.clone();
    let state_store = state_store.clone();
    with_event_submitter(base, api_token.to_owned(), |sub| async move {
        if matches!(
            &payload,
            crate::signal::SignalPayload::CallSignal {
                signal: arkret_sdk::CallSignalData::Invite(_),
                ..
            }
        ) {
            sub.send_call_invitation(
                scope_ref,
                &authority,
                &device,
                &material,
                &payload,
                &state_store,
            )
            .await
        } else {
            sub.send_scope_signal(
                scope_ref,
                &authority,
                &device,
                &material,
                &payload,
                &state_store,
            )
            .await
            .map(|_| ())
        }
    })
    .await
    .map(|_| ())
    .map_err(|err| err.display())
}

/// Emit a `reject` signal and tear down (decline path).
pub(super) fn spawn_reject(
    base: String,
    api_token: String,
    realm_id: String,
    call_id: String,
    actor: String,
    device: String,
    state_store: crate::runtime::input::StateStoreHandle,
) {
    dispatch_signal_work(async move {
        let Ok(reason) = arkret_sdk::NonEmptyString::new("declined") else {
            return;
        };
        let _ = emit_signal(
            &base,
            &api_token,
            &realm_id,
            &call_id,
            &actor,
            &device,
            1,
            arkret_sdk::CallSignalData::Reject(arkret_sdk::CallEndSignalData { reason }),
            &state_store,
        )
        .await;
    });
}

/// Hang up: emit `hangup`, close the transport, release media.
#[allow(clippy::too_many_arguments)]
pub(super) fn end_call(
    transport: &Cage<Option<SharedTransport>>,
    base: &str,
    api_token: &str,
    realm_id: &str,
    call_id: &str,
    actor: &str,
    device: &str,
    call_seq: Cage<u64>,
    state_store: crate::runtime::input::StateStoreHandle,
) {
    if let Some(t) = transport.get().as_ref() {
        t.borrow_mut().close();
    }
    let Ok(reason) = arkret_sdk::NonEmptyString::new("user_hangup") else {
        return;
    };
    emit_async(
        base,
        api_token,
        realm_id,
        call_id,
        actor,
        device,
        arkret_sdk::CallSignalData::Hangup(arkret_sdk::CallEndSignalData { reason }),
        call_seq,
        state_store,
    );
}

fn dispatch_signal_work(future: impl std::future::Future<Output = ()> + 'static) {
    if let Some(context) = crate::presentation::current_context() {
        super::task::call_task(context, None, future);
    }
}
