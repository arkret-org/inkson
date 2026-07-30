use dioxus::prelude::*;
use serde_json::json;

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
) {
    let signals = transport.borrow_mut().drain_local_signals();
    for signal in signals {
        let seq = call_seq() + 1;
        call_seq.set(seq);
        let (signal_kind, data) = match signal {
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
            None,
            call_id,
            actor,
            device,
            signal_kind,
            seq,
            data,
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
) {
    // Items that need an async relay (offer → answer) defer to a single
    // spawned task after the synchronous transport mutations are applied, so
    // we never hold a transport borrow across an `.await`.
    let mut relay_after = false;
    for item in items {
        match item.signal_kind.as_str() {
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
                } else if let Some(sdp) = sdp_from_data(&item.data, "answer")
                    && let Some(t) = transport()
                {
                    match t.borrow_mut().accept_answer(&sdp) {
                        Ok(()) => {
                            stage.set(CallStage::Active);
                            status.set("connected".to_owned());
                        }
                        Err(err) => last_error.set(media_error_label(err)),
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
                    .unwrap_or(item.signal_kind.as_str());
                status.set(format!("call ended: {reason}"));
            }
            "mute_state" | "media_state" | "speaking" => {
                if moderator_mute_targets_this_device(&item, &actor, &device)
                    && let Some(muted) = item.data.get("audio_muted").and_then(|v| v.as_bool())
                {
                    mic_muted.set(muted);
                    if let Some(t) = transport() {
                        let _ = t.borrow_mut().set_audio_muted(muted);
                    }
                    status.set(if muted {
                        format!("muted by moderator ({})", item.sender_actor)
                    } else {
                        format!("unmuted by moderator ({})", item.sender_actor)
                    });
                }
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
                let target_device = item
                    .data
                    .get("data")
                    .and_then(|d| d.get("target_device_id"))
                    .or_else(|| item.data.get("target_device_id"))
                    .and_then(|v| v.as_str());
                let self_targeted = matches!(action, "kick" | "ban")
                    && target.map(|t| t == actor).unwrap_or(false)
                    && target_device.map(|t| t == device).unwrap_or(false);
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
                    signal_kind = other,
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
        match item.signal_kind.as_str() {
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

fn moderator_mute_targets_this_device(
    item: &CallSignalInboxItem,
    actor: &str,
    device: &str,
) -> bool {
    item.signal_kind == "mute_state"
        && item.data.get("by").and_then(|v| v.as_str()) == Some("moderator")
        && item
            .data
            .get("target_actor_id")
            .and_then(|v| v.as_str())
            .is_some_and(|target| target == actor)
        && item
            .data
            .get("target_device_id")
            .and_then(|v| v.as_str())
            .is_some_and(|target| target == device)
}

/// Fire-and-forget signal emit (non-SDP control signals).
#[allow(clippy::too_many_arguments)]
pub(super) fn emit_async(
    base: &str,
    api_token: &str,
    realm_id: &str,
    material: Option<&crate::signal::SignalKeyMaterial>,
    call_id: &str,
    actor: &str,
    device: &str,
    signal_kind: &str,
    data: serde_json::Value,
    mut call_seq: Signal<u64>,
) {
    if call_id.trim().is_empty() || realm_id.trim().is_empty() {
        return;
    }
    let seq = call_seq() + 1;
    call_seq.set(seq);
    let (base, api_token, realm_id, call_id, actor, device, signal_kind) = (
        base.to_owned(),
        api_token.to_owned(),
        realm_id.to_owned(),
        call_id.to_owned(),
        actor.to_owned(),
        device.to_owned(),
        signal_kind.to_owned(),
    );
    let material = material.cloned();
    spawn(async move {
        let _ = emit_signal(
            &base,
            &api_token,
            &realm_id,
            material.as_ref(),
            &call_id,
            &actor,
            &device,
            &signal_kind,
            seq,
            data,
        )
        .await;
    });
}

/// Send a single `ak.call.signal` on the encrypted Signal rail.
///
/// `material` is the scope's accepted MLS key material: a scope without it has
/// its Signal capability withdrawn, and v1 has no plaintext fallback. The
/// accepted Seal the receiver resolves the sender's live-send eligibility under
/// is fetched by the submitter.
#[allow(clippy::too_many_arguments)]
pub(super) async fn emit_signal(
    base: &str,
    api_token: &str,
    realm_id: &str,
    material: Option<&crate::signal::SignalKeyMaterial>,
    call_id: &str,
    actor: &str,
    device: &str,
    signal_kind: &str,
    seq: u64,
    data: serde_json::Value,
) -> Result<(), String> {
    // No accepted MLS key material for the scope means the Signal capability is
    // withdrawn there (`signal.md` §3). v1 has no plaintext branch.
    let material = material.ok_or_else(|| {
        format!("signal rail unavailable for {realm_id}: no accepted MLS key material")
    })?;
    let scope_ref = arkret_sdk::ScopeRef::Realm {
        realm_id: arkret_sdk::RealmId::new(realm_id.trim().to_owned())
            .map_err(|error| format!("invalid call signal realm_id: {error}"))?,
    };
    if !data.is_object() {
        return Err("call signal data must be an object".to_owned());
    }
    let payload = crate::signal::SignalPayload::CallSignal {
        call_id: arkret_sdk::CallId::new(call_id)
            .map_err(|error| format!("invalid call_id: {error}"))?,
        signal_kind: signal_kind.to_owned(),
        data: Some(data),
    };
    let (actor, device) = (actor.to_owned(), device.to_owned());
    let material = material.clone();
    with_event_submitter(base, api_token.to_owned(), |sub| async move {
        sub.send_scope_signal(
            scope_ref,
            &actor,
            &device,
            &material,
            &payload,
            crate::signal::SignalSequence(seq),
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
) {
    spawn(async move {
        let _ = emit_signal(
            &base,
            &api_token,
            &realm_id,
            None,
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
pub(super) fn end_call(
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
        None,
        call_id,
        actor,
        device,
        "hangup",
        json!({ "reason": "user_hangup" }),
        call_seq,
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn inbox_item(data: serde_json::Value) -> CallSignalInboxItem {
        CallSignalInboxItem {
            realm_id: "ak:realm:01904100-0000-7000-8000-000000000001".to_owned(),
            call_id: "ak:call:01904100-0000-7000-8000-000000000002".to_owned(),
            signal_kind: "mute_state".to_owned(),
            seq: 1,
            sender_actor: "did:web:moderator.example".to_owned(),
            sender_device: "ak:device:01904100-0000-7000-8000-000000000003".to_owned(),
            data,
        }
    }

    #[test]
    fn moderator_mute_targets_exact_actor_device() {
        let item = inbox_item(json!({
            "audio_muted": true,
            "by": "moderator",
            "target_actor_id": "did:web:alice.example",
            "target_device_id": "ak:device:01904100-0000-7000-8000-000000000004"
        }));
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
