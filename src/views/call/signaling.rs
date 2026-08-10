use dioxus::prelude::*;

use super::media::media_error_label;
use super::types::{CallParticipant, CallStage, SharedTransport};
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
    mut call_seq: Signal<u64>,
    initial_invite_media: Option<arkret_sdk::CallMediaSelection>,
    state_store: &crate::runtime::input::StateStoreHandle,
) {
    let signals = transport.borrow_mut().drain_local_signals();
    for signal in signals {
        let seq = call_seq() + 1;
        call_seq.set(seq);
        let signal = match signal {
            LocalSignal::Offer { sdp } => {
                let offer = arkret_sdk::SessionDescription {
                    sdp_type: arkret_sdk::SessionDescriptionType::Offer,
                    sdp,
                };
                if let Some(media) = initial_invite_media.clone() {
                    arkret_sdk::CallSignalData::Invite(arkret_sdk::CallInviteSignalData {
                        lifetime_ms: 60_000,
                        mode: arkret_models_collaboration::call_signal::CallMode::P2p,
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
            seq,
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
    mut mic_muted: Signal<bool>,
    relay_store: crate::runtime::input::StateStoreHandle,
) {
    // Items that need an async relay (offer → answer) defer to a single
    // spawned task after the synchronous transport mutations are applied, so
    // we never hold a transport borrow across an `.await`.
    let mut relay_after = false;
    for item in items {
        match &item.signal {
            arkret_sdk::CallSignalData::Answer(data) => {
                if let Some(t) = transport() {
                    match t.borrow_mut().accept_answer(&data.answer.sdp) {
                        Ok(()) => {
                            stage.set(CallStage::Active);
                            status.set("connected".to_owned());
                        }
                        Err(err) => last_error.set(media_error_label(err)),
                    }
                }
            }
            arkret_sdk::CallSignalData::Renegotiate(data) => {
                if let Some(offer) = &data.offer {
                    if let Some(t) = transport() {
                        match t.borrow_mut().accept_offer(&offer.sdp) {
                            Ok(()) => {
                                relay_after = true;
                                stage.set(CallStage::Connecting);
                                status.set("applying remote offer".to_owned());
                            }
                            Err(err) => last_error.set(media_error_label(err)),
                        }
                    }
                } else if let Some(answer) = &data.answer
                    && let Some(t) = transport()
                {
                    match t.borrow_mut().accept_answer(&answer.sdp) {
                        Ok(()) => {
                            stage.set(CallStage::Active);
                            status.set("connected".to_owned());
                        }
                        Err(err) => last_error.set(media_error_label(err)),
                    }
                }
            }
            arkret_sdk::CallSignalData::Candidate(data) => {
                if let Some(t) = transport() {
                    for candidate in &data.candidates {
                        if let Err(err) = t.borrow_mut().add_remote_candidate(
                            &candidate.candidate,
                            candidate.sdp_mid.as_deref(),
                            candidate.sdp_m_line_index,
                        ) {
                            last_error.set(media_error_label(err));
                        }
                    }
                }
            }
            arkret_sdk::CallSignalData::Hangup(data) | arkret_sdk::CallSignalData::Reject(data) => {
                if let Some(t) = transport() {
                    t.borrow_mut().close();
                }
                stage.set(CallStage::Ended);
                status.set(format!("call ended: {}", data.reason.as_str()));
            }
            arkret_sdk::CallSignalData::MuteState(data) => {
                if moderator_mute_targets_this_device(&item, &actor, &device) {
                    mic_muted.set(data.audio_muted);
                    if let Some(t) = transport() {
                        let _ = t.borrow_mut().set_audio_muted(data.audio_muted);
                    }
                    status.set(if data.audio_muted {
                        format!("muted by moderator ({})", item.sender_actor)
                    } else {
                        format!("unmuted by moderator ({})", item.sender_actor)
                    });
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
                        target.is_some_and(|target| target.as_str() == actor)
                            && data
                                .target_device_id
                                .as_ref()
                                .is_some_and(|target| target.as_str() == device)
                    }
                    arkret_sdk::CallModerationAction::Ban => {
                        target.is_some_and(|target| target.as_str() == actor)
                    }
                    arkret_sdk::CallModerationAction::EndForAll => true,
                };
                if self_targeted {
                    if let Some(t) = transport() {
                        t.borrow_mut().close();
                    }
                    stage.set(CallStage::Ended);
                    status.set(format!("removed by moderator ({:?})", data.action));
                } else if let Some(target) = target {
                    // A peer was kicked/banned — drop their roster tile.
                    let mut roster = participants();
                    roster.retain(|p| p.actor_id != target.as_str());
                    participants.set(roster);
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
fn apply_peer_state(participants: &mut Signal<Vec<CallParticipant>>, item: &CallSignalInboxItem) {
    let target = match &item.signal {
        arkret_sdk::CallSignalData::MuteState(data) => data
            .target_actor_id
            .as_ref()
            .map_or(item.sender_actor.as_str(), arkret_sdk::DidCoreId::as_str),
        _ => item.sender_actor.as_str(),
    };
    let mut roster = participants();
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
        participants.set(roster);
    }
}

fn moderator_mute_targets_this_device(
    item: &CallSignalInboxItem,
    actor: &str,
    device: &str,
) -> bool {
    matches!(
        &item.signal,
        arkret_sdk::CallSignalData::MuteState(data)
            if data.changed_by == arkret_sdk::MuteChangedBy::Moderator
                && data
                    .target_actor_id
                    .as_ref()
                    .is_some_and(|target| target.as_str() == actor)
                && data
                    .target_device_id
                    .as_ref()
                    .is_some_and(|target| target.as_str() == device)
    )
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
    mut call_seq: Signal<u64>,
    state_store: crate::runtime::input::StateStoreHandle,
) {
    if call_id.trim().is_empty() || realm_id.trim().is_empty() {
        return;
    }
    let seq = call_seq() + 1;
    call_seq.set(seq);
    let (base, api_token, realm_id, call_id, actor, device) = (
        base.to_owned(),
        api_token.to_owned(),
        realm_id.to_owned(),
        call_id.to_owned(),
        actor.to_owned(),
        device.to_owned(),
    );
    spawn(async move {
        if let Err(error) = emit_signal(
            &base,
            &api_token,
            &realm_id,
            &call_id,
            &actor,
            &device,
            seq,
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
    seq: u64,
    signal: arkret_sdk::CallSignalData,
    state_store: &crate::runtime::input::StateStoreHandle,
) -> Result<(), String> {
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
        seq,
        signal,
    };
    let (actor, device) = (actor.to_owned(), device.to_owned());
    let material = material.clone();
    let state_store = state_store.clone();
    with_event_submitter(base, api_token.to_owned(), |sub| async move {
        sub.send_scope_signal(
            scope_ref,
            &actor,
            &device,
            &material,
            &payload,
            &state_store,
        )
        .await
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
    spawn(async move {
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
    transport: &Signal<Option<SharedTransport>>,
    base: &str,
    api_token: &str,
    realm_id: &str,
    call_id: &str,
    actor: &str,
    device: &str,
    call_seq: Signal<u64>,
    state_store: crate::runtime::input::StateStoreHandle,
) {
    if let Some(t) = transport.read().as_ref() {
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

#[cfg(test)]
mod tests {
    use super::*;

    fn inbox_item() -> CallSignalInboxItem {
        CallSignalInboxItem {
            realm_id: "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19".to_owned(),
            call_id: "ak:call:Ae5vV8Lwlft2Dp8x2y6Dv4NysvsHJwrADG-6PXdUz1Sl".to_owned(),
            seq: 1,
            sender_actor: "did:web:moderator.example".to_owned(),
            sender_device: "ak:device:01904100-0000-7000-8000-000000000003".to_owned(),
            signal: arkret_sdk::CallSignalData::MuteState(arkret_sdk::CallMuteStateSignalData {
                audio_muted: true,
                video_muted: false,
                changed_by: arkret_sdk::MuteChangedBy::Moderator,
                target_actor_id: Some(
                    crate::mls_api_helpers::principal_core_id("did:web:alice.example").unwrap(),
                ),
                target_device_id: Some(
                    arkret_sdk::DeviceId::new("ak:device:01904100-0000-7000-8000-000000000004")
                        .unwrap(),
                ),
            }),
        }
    }

    #[test]
    fn moderator_mute_targets_exact_actor_device() {
        let item = inbox_item();
        assert!(moderator_mute_targets_this_device(
            &item,
            "did:web:alice.example",
            "ak:device:01904100-0000-7000-8000-000000000004"
        ));
        assert!(!moderator_mute_targets_this_device(
            &item,
            "did:web:alice.example",
            "ak:device:01904100-0000-7000-8000-000000000005"
        ));
    }
}
