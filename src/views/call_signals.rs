//! App-level call-signaling hub — the receive side of `ak.call.signal`.
//!
//! soland delivers inbound call signaling inline on each realm's sync body:
//! `body.ephemeral[]` carries a typed item
//! `{ "type":"ak.call.signal", "realm_id":…, "call_signals":[ <envelope> ] }`
//! where each envelope is the full signed
//! `{kind, realm_id, actor_id, device_id, sent_at, expires_at,
//!   payload:{call_id, signal_type, seq, data}, proof}` shape submitted by the
//! sender side (`submit_call_signal_v1`).
//!
//! This module owns the cross-component plumbing that turns those envelopes
//! into FSM/transport drive signals:
//!   * [`CallSignalHub`] is `provide_context`-ed once at the app root.
//!   * The sync apply paths (`app.rs` full boot sync + `sync_engine.rs` incremental sync) call
//!     [`route_realm_call_signals`] for every realm body, which dedups, sets `incoming_call` on a
//!     fresh `invite`, and queues every other signal type into the per-call inbox.
//!   * `CallPanel` (`views/call.rs`) pulls the hub via `use_context`, drains its `active_call_id`
//!     inbox in an effect, and applies each item to the `MediaTransport` / call FSM.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use dioxus::prelude::*;
use serde_json::Value;

use crate::api::ArkretApi;

/// Inbound invite presented to the user as a ring. Set on the hub when an
/// `invite` arrives for a call the local client has no active session for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IncomingCallInfo {
    pub realm_id: String,
    pub call_id: String,
    /// Caller actor DID (`envelope.actor_id`).
    pub peer_actor: String,
    /// The caller's sending device id (`envelope.device_id`).
    pub sender_device: String,
    /// Invite requested video (`payload.data.video`, or `data.media.video`).
    pub video: bool,
}

/// A non-invite signal queued for the active `CallPanel` to apply. Carries
/// the decoded routing fields plus the raw `payload.data` object so the panel
/// can read SDP / candidate / mute fields with the exact shape the sender
/// side wrote (`submit_call_signal_v1` / `relay_local_signals`).
#[derive(Clone, Debug, PartialEq)]
pub struct CallSignalInboxItem {
    pub realm_id: String,
    pub call_id: String,
    pub signal_type: String,
    pub seq: u64,
    /// Sender actor DID (`envelope.actor_id`).
    pub sender_actor: String,
    /// Sender device id (`envelope.device_id`).
    pub sender_device: String,
    /// The `payload.data` object verbatim.
    pub data: Value,
}

/// Dedup identity for a single inbound signal:
/// `(realm, call, sender_actor, sender_device, seq)`. soland already delivers
/// once; this is the client-side belt-and-braces guard so a redelivered sync
/// frame (catchup overlap, reconnect replay) never double-drives the FSM.
pub type SignalDedupKey = (String, String, String, String, u64);
pub type SignalSeqKey = (String, String, String, String);

/// The cross-component signaling hub. Cloned cheaply (every field is a
/// `Signal`, which is `Copy`). Provided once at the app root and read by
/// `CallPanel` via `use_context`.
#[derive(Clone, Copy)]
pub struct CallSignalHub {
    /// Set when an inbound `invite` arrives and no active call owns it.
    /// Cleared by `CallPanel` once the ring is presented / answered, or when
    /// the call ends.
    pub incoming_call: Signal<Option<IncomingCallInfo>>,
    /// Per-call FIFO inbox of non-invite signals awaiting `CallPanel`.
    pub inbox: Signal<BTreeMap<String, VecDeque<CallSignalInboxItem>>>,
    /// Processed-signal dedup set.
    pub seen: Signal<BTreeSet<SignalDedupKey>>,
    /// Highest accepted seq per `(realm, call, sender_actor, sender_device)`.
    pub last_seq: Signal<BTreeMap<SignalSeqKey, u64>>,
    /// Call ids the local client currently owns an active session for. An
    /// `invite` for a call already in this set is treated as a re-invite and
    /// does NOT raise a fresh ring.
    pub active_calls: Signal<BTreeSet<String>>,
}

impl CallSignalHub {
    /// Construct an empty hub. Call inside `use_context_provider`.
    pub fn new() -> Self {
        Self {
            incoming_call: Signal::new(None),
            inbox: Signal::new(BTreeMap::new()),
            seen: Signal::new(BTreeSet::new()),
            last_seq: Signal::new(BTreeMap::new()),
            active_calls: Signal::new(BTreeSet::new()),
        }
    }

    /// Best-effort context read. Returns `None` when no provider is mounted
    /// (unit tests / isolated component renders) so callers stay non-fatal.
    pub fn try_use() -> Option<Self> {
        try_consume_context::<CallSignalHub>()
    }

    /// Pop every queued item for `call_id` (FIFO), leaving the inbox entry
    /// empty. Used by `CallPanel`'s drain effect.
    pub fn drain_call(&mut self, call_id: &str) -> Vec<CallSignalInboxItem> {
        let mut inbox = self.inbox.write();
        match inbox.get_mut(call_id) {
            Some(queue) => queue.drain(..).collect(),
            None => Vec::new(),
        }
    }

    /// Mark `call_id` as locally active (answered / placed) so a re-delivered
    /// `invite` does not re-ring, and clear a matching pending `incoming_call`.
    pub fn mark_active(&mut self, call_id: &str) {
        self.active_calls.write().insert(call_id.to_owned());
        let clear = self
            .incoming_call
            .read()
            .as_ref()
            .is_some_and(|info| info.call_id == call_id);
        if clear {
            self.incoming_call.set(None);
        }
    }

    /// Drop all per-call state (inbox + active flag) when a call ends.
    pub fn forget_call(&mut self, call_id: &str) {
        self.inbox.write().remove(call_id);
        self.active_calls.write().remove(call_id);
        self.last_seq.write().retain(|key, _| key.1 != call_id);
        let clear = self
            .incoming_call
            .read()
            .as_ref()
            .is_some_and(|info| info.call_id == call_id);
        if clear {
            self.incoming_call.set(None);
        }
    }
}

impl Default for CallSignalHub {
    fn default() -> Self {
        Self::new()
    }
}

/// A decoded inbound `ak.call.signal` envelope, ready to route.
#[derive(Clone, Debug, PartialEq)]
pub struct DecodedCallSignal {
    pub realm_id: String,
    pub call_id: String,
    pub signal_type: String,
    pub seq: u64,
    pub sender_actor: String,
    pub sender_device: String,
    pub video: bool,
    pub data: Value,
    /// The full signed envelope `Value` (kind / realm_id / actor_id /
    /// device_id / sent_at / expires_at / payload / proof). Retained so the
    /// receive path can verify the ephemeral `proof` (`webrtc-signaling.md`
    /// §5.1) against the sender's directory verify key before any UI side
    /// effect. `Null` only in unit-test constructors that bypass decoding.
    pub envelope: Value,
}

/// Pull the `call_signals[]` envelopes out of one realm sync body's
/// `ephemeral[]` array and decode each into a [`DecodedCallSignal`].
///
/// Receiver-side proof verification (spec §5 — the receiver MUST verify the
/// envelope's `proof`) is intentionally not performed in this structural
/// decoder. [`route_realm_call_signals`] is the only public receive entrypoint
/// used by sync apply; it verifies each decoded envelope fail-closed before any
/// ring or inbox side effect.
pub fn decode_realm_call_signals(realm_id: &str, body: &Value) -> Vec<DecodedCallSignal> {
    let mut out = Vec::new();
    let Some(ephemeral) = body.get("ephemeral").and_then(Value::as_array) else {
        return out;
    };
    for item in ephemeral {
        let is_call_signal = item
            .get("type")
            .and_then(Value::as_str)
            .map(|t| t == "ak.call.signal")
            .unwrap_or(false);
        if !is_call_signal {
            continue;
        }
        // Prefer the item's own realm_id; fall back to the sync key.
        let item_realm = item
            .get("realm_id")
            .and_then(Value::as_str)
            .unwrap_or(realm_id);
        let Some(envelopes) = item.get("call_signals").and_then(Value::as_array) else {
            continue;
        };
        for envelope in envelopes {
            if let Some(decoded) = decode_call_signal_envelope(item_realm, envelope) {
                out.push(decoded);
            }
        }
    }
    out
}

/// Decode a single signed `ak.call.signal` envelope. Returns `None` when the
/// envelope is structurally invalid (wrong kind, missing
/// `payload.{call_id,signal_type,seq}` / `actor_id`).
fn decode_call_signal_envelope(realm_id: &str, envelope: &Value) -> Option<DecodedCallSignal> {
    let kind = envelope.get("kind").and_then(Value::as_str)?;
    if kind != "ak.call.signal" {
        return None;
    }
    let sender_actor = envelope.get("actor_id").and_then(Value::as_str)?.to_owned();
    let sender_device = envelope
        .get("device_id")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    let payload = envelope.get("payload")?;
    let call_id = payload.get("call_id").and_then(Value::as_str)?.to_owned();
    let signal_type = payload
        .get("signal_type")
        .and_then(Value::as_str)?
        .to_owned();
    let seq = payload.get("seq").and_then(Value::as_u64).unwrap_or(0);
    let data = payload.get("data").cloned().unwrap_or(Value::Null);
    let video = invite_wants_video(&data);
    Some(DecodedCallSignal {
        realm_id: realm_id.to_owned(),
        call_id,
        signal_type,
        seq,
        sender_actor,
        sender_device,
        video,
        data,
        envelope: envelope.clone(),
    })
}

/// Read whether an `invite` requested video. The sender side
/// (`start_call`) writes `data.video`; tolerate the `data.media.video`
/// nesting too for forward compatibility.
fn invite_wants_video(data: &Value) -> bool {
    if let Some(v) = data.get("video").and_then(Value::as_bool) {
        return v;
    }
    data.get("media")
        .and_then(|m| m.get("video"))
        .and_then(Value::as_bool)
        .unwrap_or(false)
}

/// Route every decoded call signal from one realm body into the hub:
/// dedup → `invite` raises `incoming_call` (when no active session owns the
/// call) → everything else queues into the per-call inbox.
///
/// `local_actor` is this device's account DID; signals this client itself
/// emitted (echoed back through sync) are skipped so we never self-drive.
///
/// **Receiver proof verification (`webrtc-signaling.md` §5.1, fail-closed).**
/// Before any signal reaches [`route_decoded_signal`] it MUST pass detached-JWS
/// proof verification against the sender's authoritative directory verify key
/// (resolved via [`crate::device_directory`]). The sync-apply path is
/// synchronous but the directory query is async, so this fn is `async` and
/// takes an optional authenticated [`ArkretApi`]:
///
/// - cache **Hit** → verify inline; pass routes, fail drops;
/// - cache **NegativeHit** (revoked / absent / no key) → fail-closed drop;
/// - cache **Miss** → `await` an async resolve, then verify and route on success. This covers
///   `invite` as well as the first `answer`/`candidate` after an outbound call; one-shot signaling
///   frames are not discarded merely because the directory cache was cold.
///
/// When `api` is `None` (no authenticated client yet) a cache Miss cannot be
/// resolved and the signal is dropped fail-closed.
pub async fn route_realm_call_signals(
    hub: &mut CallSignalHub,
    realm_id: &str,
    body: &Value,
    local_actor: &str,
    api: Option<&ArkretApi>,
    did_anchor: &dyn crate::device_directory::DidAnchor,
) {
    for decoded in decode_realm_call_signals(realm_id, body) {
        // Self-echo: skip verification + routing entirely (we trust our own
        // outbound frames and never resolve our own key here).
        if !local_actor.is_empty() && decoded.sender_actor == local_actor {
            continue;
        }
        match crate::device_directory::cached_device_signing_key(
            &decoded.sender_actor,
            &decoded.sender_device,
        ) {
            crate::device_directory::CacheLookup::Hit(key) => {
                if verify_decoded_proof(&decoded, &key)
                    && moderator_signal_authorized(&decoded, api).await
                {
                    route_verified_decoded_signal(hub, decoded, local_actor);
                }
                // verify failed → fail-closed drop.
            }
            crate::device_directory::CacheLookup::NegativeHit => {
                // Revoked / absent / no key → fail-closed drop.
            }
            crate::device_directory::CacheLookup::Miss => {
                let Some(api) = api else {
                    // No client to resolve with → fail-closed drop.
                    continue;
                };
                if let Ok(Some(key)) = crate::device_directory::resolve_device_signing_key(
                    api,
                    did_anchor,
                    &decoded.sender_actor,
                    &decoded.sender_device,
                )
                .await
                    && verify_decoded_proof(&decoded, &key)
                    && moderator_signal_authorized(&decoded, Some(api)).await
                {
                    route_verified_decoded_signal(hub, decoded, local_actor);
                }
            }
        }
    }
}

/// Verify a decoded signal's envelope `proof` against `key` using the shared
/// receiver primitive. Pure wrapper so the routing loop reads cleanly and the
/// gate is unit-testable.
fn verify_decoded_proof(
    decoded: &DecodedCallSignal,
    key: &arkret_sdk::signatures::PublicKeyMaterial,
) -> bool {
    crate::device_directory::verify_ephemeral_envelope_proof(&decoded.envelope, key)
}

async fn moderator_signal_authorized(decoded: &DecodedCallSignal, api: Option<&ArkretApi>) -> bool {
    if !requires_call_moderate(decoded) {
        return true;
    }
    if !moderator_payload_shape_is_valid(decoded) {
        tracing::warn!(
            realm_id = %decoded.realm_id,
            call_id = %decoded.call_id,
            sender = %decoded.sender_actor,
            signal_type = %decoded.signal_type,
            "dropping malformed moderator call signal"
        );
        return false;
    }
    let Some(api) = api else {
        tracing::warn!(
            realm_id = %decoded.realm_id,
            call_id = %decoded.call_id,
            sender = %decoded.sender_actor,
            signal_type = %decoded.signal_type,
            "dropping moderator call signal without authz client"
        );
        return false;
    };
    match async {
        crate::realm_read_api::authz_check_resource_raw(
            &api.sdk_http_client()?,
            &decoded.sender_actor,
            "ak.call.moderate",
            Some(serde_json::json!({
                "kind": "call",
                "realm_id": decoded.realm_id.clone(),
                "call_id": decoded.call_id.clone(),
            })),
        )
        .await
    }
    .await
    {
        Ok(outcome) if authz_check_allows_moderation(&outcome) => true,
        Ok(outcome) => {
            tracing::warn!(
                realm_id = %decoded.realm_id,
                call_id = %decoded.call_id,
                sender = %decoded.sender_actor,
                signal_type = %decoded.signal_type,
                outcome = %outcome,
                "dropping unauthorised moderator call signal"
            );
            false
        }
        Err(error) => {
            tracing::warn!(
                realm_id = %decoded.realm_id,
                call_id = %decoded.call_id,
                sender = %decoded.sender_actor,
                signal_type = %decoded.signal_type,
                ?error,
                "dropping moderator call signal after authz check failure"
            );
            false
        }
    }
}

fn requires_call_moderate(decoded: &DecodedCallSignal) -> bool {
    decoded.signal_type == "moderation"
        || (decoded.signal_type == "mute_state"
            && decoded.data.get("by").and_then(Value::as_str) == Some("moderator"))
}

fn moderator_payload_shape_is_valid(decoded: &DecodedCallSignal) -> bool {
    match decoded.signal_type.as_str() {
        "moderation" => match moderation_action(decoded) {
            Some("kick" | "ban") => {
                !moderation_target_actor(decoded).unwrap_or("").is_empty()
                    && !moderation_target_device(decoded).unwrap_or("").is_empty()
            }
            Some("end_for_all") => true,
            _ => false,
        },
        "mute_state" => {
            decoded.data.get("by").and_then(Value::as_str) == Some("moderator")
                && !decoded
                    .data
                    .get("target_actor_id")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .is_empty()
                && !decoded
                    .data
                    .get("target_device_id")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .is_empty()
        }
        _ => true,
    }
}

fn moderation_action(decoded: &DecodedCallSignal) -> Option<&str> {
    decoded
        .data
        .get("data")
        .and_then(|data| data.get("action"))
        .or_else(|| decoded.data.get("action"))
        .and_then(Value::as_str)
}

fn moderation_target_actor(decoded: &DecodedCallSignal) -> Option<&str> {
    decoded
        .data
        .get("data")
        .and_then(|data| data.get("target_actor_id"))
        .or_else(|| decoded.data.get("target_actor_id"))
        .and_then(Value::as_str)
}

fn moderation_target_device(decoded: &DecodedCallSignal) -> Option<&str> {
    decoded
        .data
        .get("data")
        .and_then(|data| data.get("target_device_id"))
        .or_else(|| decoded.data.get("target_device_id"))
        .and_then(Value::as_str)
}

fn authz_check_allows_moderation(outcome: &Value) -> bool {
    let allowed = outcome
        .get("decision")
        .and_then(Value::as_str)
        .map(|decision| matches!(decision, "allow" | "allowed"))
        .unwrap_or_else(|| {
            outcome
                .get("allowed")
                .and_then(Value::as_bool)
                .unwrap_or(false)
        });
    if !allowed {
        return false;
    }
    let stale_freshness = outcome
        .get("freshness_state")
        .and_then(Value::as_str)
        .is_some_and(|state| matches!(state, "stale" | "unknown"));
    let stale_notary = outcome
        .get("notary_status")
        .and_then(Value::as_str)
        .is_some_and(|state| matches!(state, "lagging" | "unreachable" | "unknown"));
    !(stale_freshness || stale_notary)
}

/// Current ring/active snapshot a routing decision is taken against. Pulled
/// out so the decision logic is a pure function, testable without a Dioxus
/// runtime (which `Signal::new` requires).
#[derive(Clone, Debug, Default)]
pub struct RouteState {
    /// call_id of the pending incoming ring, if any.
    pub ringing_call: Option<String>,
    /// Whether the ringing call (if any) has been answered on THIS device.
    pub ringing_answered_here: bool,
}

/// The action `route_decoded_signal` must apply to the hub for one signal.
#[derive(Clone, Debug, PartialEq)]
pub enum RouteDecision {
    /// Self-echo, duplicate, or a no-op re-invite — drop silently.
    Drop,
    /// Raise an incoming ring.
    Ring(IncomingCallInfo),
    /// Clear the pending ring (answered elsewhere / caller hung up).
    ClearRing,
    /// Queue a non-invite signal into the per-call inbox.
    Enqueue(CallSignalInboxItem),
}

/// Pure routing decision for a single decoded signal. `is_duplicate` is the
/// dedup-set membership result (true ⇒ already processed), computed by the
/// caller against the hub's `seen` set. `local_actor` empty ⇒ no self-echo
/// filtering.
pub fn decide_route(
    decoded: &DecodedCallSignal,
    local_actor: &str,
    is_duplicate: bool,
    state: &RouteState,
) -> RouteDecision {
    if !local_actor.is_empty() && decoded.sender_actor == local_actor {
        return RouteDecision::Drop;
    }
    if is_duplicate {
        return RouteDecision::Drop;
    }

    if decoded.signal_type == "invite" {
        let already_ringing = state.ringing_call.as_deref() == Some(decoded.call_id.as_str());
        // `ringing_answered_here` covers the active-session case the caller
        // folds in (a call this device owns is surfaced as answered-here).
        if already_ringing || state.ringing_answered_here {
            return RouteDecision::Drop;
        }
        return RouteDecision::Ring(IncomingCallInfo {
            realm_id: decoded.realm_id.clone(),
            call_id: decoded.call_id.clone(),
            peer_actor: decoded.sender_actor.clone(),
            sender_device: decoded.sender_device.clone(),
            video: decoded.video,
        });
    }

    // Multi-device stop-ring: if THIS device is still ringing for the call
    // but has NOT answered, an inbound `answer` / `reject{call_already_answered}`
    // / `hangup` means another device (or the caller) resolved the ring.
    let still_ringing_here = state.ringing_call.as_deref() == Some(decoded.call_id.as_str())
        && !state.ringing_answered_here;
    if still_ringing_here {
        let call_already_answered = decoded.signal_type == "answer"
            || decoded.signal_type == "hangup"
            || (decoded.signal_type == "reject"
                && decoded
                    .data
                    .get("reason")
                    .and_then(Value::as_str)
                    .map(|r| r == "call_already_answered")
                    .unwrap_or(false));
        if call_already_answered {
            return RouteDecision::ClearRing;
        }
    }

    RouteDecision::Enqueue(CallSignalInboxItem {
        realm_id: decoded.realm_id.clone(),
        call_id: decoded.call_id.clone(),
        signal_type: decoded.signal_type.clone(),
        seq: decoded.seq,
        sender_actor: decoded.sender_actor.clone(),
        sender_device: decoded.sender_device.clone(),
        data: decoded.data.clone(),
    })
}

fn route_verified_decoded_signal(
    hub: &mut CallSignalHub,
    decoded: DecodedCallSignal,
    local_actor: &str,
) {
    if !advance_signal_seq(hub, &decoded, local_actor) {
        return;
    }
    route_decoded_signal(hub, decoded, local_actor);
}

fn advance_signal_seq(
    hub: &mut CallSignalHub,
    decoded: &DecodedCallSignal,
    local_actor: &str,
) -> bool {
    if !local_actor.is_empty() && decoded.sender_actor == local_actor {
        return true;
    }
    let key: SignalSeqKey = (
        decoded.realm_id.clone(),
        decoded.call_id.clone(),
        decoded.sender_actor.clone(),
        decoded.sender_device.clone(),
    );
    let mut last_seq = hub.last_seq.write();
    if last_seq.get(&key).is_some_and(|prev| decoded.seq <= *prev) {
        return false;
    }
    last_seq.insert(key, decoded.seq);
    true
}

/// Route a single decoded signal: compute the pure [`decide_route`] decision
/// against the hub's current state, then apply it to the hub Signals.
pub fn route_decoded_signal(
    hub: &mut CallSignalHub,
    decoded: DecodedCallSignal,
    local_actor: &str,
) {
    let key: SignalDedupKey = (
        decoded.realm_id.clone(),
        decoded.call_id.clone(),
        decoded.sender_actor.clone(),
        decoded.sender_device.clone(),
        decoded.seq,
    );
    // Compute duplicate status and insert atomically: a self-echo never
    // reaches here as a duplicate (it is dropped first), so only genuine
    // routable signals consume a dedup slot.
    let is_self_echo = !local_actor.is_empty() && decoded.sender_actor == local_actor;
    let is_duplicate = if is_self_echo {
        false
    } else {
        !hub.seen.write().insert(key)
    };

    let ring_state = {
        let ringing = hub.incoming_call.read();
        let ringing_call = ringing.as_ref().map(|info| info.call_id.clone());
        let answered_here = hub.active_calls.read().contains(&decoded.call_id);
        RouteState {
            ringing_call,
            ringing_answered_here: answered_here,
        }
    };

    match decide_route(&decoded, local_actor, is_duplicate, &ring_state) {
        RouteDecision::Drop => {}
        RouteDecision::Ring(info) => hub.incoming_call.set(Some(info)),
        RouteDecision::ClearRing => hub.incoming_call.set(None),
        RouteDecision::Enqueue(item) => {
            let call_id = item.call_id.clone();
            hub.inbox
                .write()
                .entry(call_id)
                .or_default()
                .push_back(item);
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn envelope(
        actor: &str,
        device: &str,
        call: &str,
        signal_type: &str,
        seq: u64,
        data: Value,
    ) -> Value {
        json!({
            "kind": "ak.call.signal",
            "realm_id": "ak:realm:r",
            "actor_id": actor,
            "device_id": device,
            "sent_at": 1,
            "expires_at": 2,
            "payload": {
                "call_id": call,
                "signal_type": signal_type,
                "seq": seq,
                "data": data,
            },
            "proof": { "sig": "deadbeef" },
        })
    }

    fn body_with(envelopes: Vec<Value>) -> Value {
        json!({
            "ephemeral": [
                {
                    "type": "ak.call.signal",
                    "realm_id": "ak:realm:r",
                    "call_signals": envelopes,
                }
            ]
        })
    }

    #[test]
    fn decodes_invite_and_video_flag() {
        let body = body_with(vec![envelope(
            "did:web:bob",
            "dev-b",
            "ak:call:1",
            "invite",
            1,
            json!({ "video": true, "participants": ["did:web:alice"] }),
        )]);
        let decoded = decode_realm_call_signals("ak:realm:r", &body);
        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded[0].signal_type, "invite");
        assert_eq!(decoded[0].call_id, "ak:call:1");
        assert_eq!(decoded[0].sender_actor, "did:web:bob");
        assert_eq!(decoded[0].sender_device, "dev-b");
        assert!(decoded[0].video);
    }

    #[test]
    fn decode_skips_non_call_ephemeral_and_bad_kind() {
        let body = json!({
            "ephemeral": [
                { "type": "ak.typing", "actor_id": "x" },
                {
                    "type": "ak.call.signal",
                    "call_signals": [
                        json!({ "kind": "ak.not.call", "actor_id": "y", "payload": {} }),
                    ],
                }
            ]
        });
        assert!(decode_realm_call_signals("ak:realm:r", &body).is_empty());
    }

    fn decoded(signal_type: &str, seq: u64, data: Value) -> DecodedCallSignal {
        DecodedCallSignal {
            realm_id: "ak:realm:r".into(),
            call_id: "ak:call:1".into(),
            signal_type: signal_type.into(),
            seq,
            sender_actor: "did:web:bob".into(),
            sender_device: "dev-b".into(),
            video: data.get("video").and_then(Value::as_bool).unwrap_or(false),
            data,
            envelope: Value::Null,
        }
    }

    #[test]
    fn invite_decides_ring_then_dedup_drops() {
        let d = decoded("invite", 1, json!({ "video": true }));
        let fresh = RouteState::default();
        match decide_route(&d, "did:web:alice", false, &fresh) {
            RouteDecision::Ring(info) => {
                assert_eq!(info.call_id, "ak:call:1");
                assert_eq!(info.peer_actor, "did:web:bob");
                assert!(info.video);
            }
            other => panic!("expected Ring, got {other:?}"),
        }
        // Duplicate (already in `seen`) → dropped even with fresh ring state.
        assert_eq!(
            decide_route(&d, "did:web:alice", true, &fresh),
            RouteDecision::Drop
        );
    }

    #[test]
    fn non_invite_enqueues() {
        let d = decoded("candidate", 2, json!({ "candidate": "cand" }));
        match decide_route(&d, "did:web:alice", false, &RouteState::default()) {
            RouteDecision::Enqueue(item) => {
                assert_eq!(item.signal_type, "candidate");
                assert_eq!(item.call_id, "ak:call:1");
            }
            other => panic!("expected Enqueue, got {other:?}"),
        }
    }

    #[test]
    fn moderator_signal_shape_requires_targets() {
        let kick = decoded(
            "moderation",
            3,
            json!({
                "data": {
                    "action": "kick",
                    "target_actor_id": "did:web:carol",
                    "target_device_id": "ak:device:01904100-0000-7000-8000-00000000000c"
                }
            }),
        );
        assert!(requires_call_moderate(&kick));
        assert!(moderator_payload_shape_is_valid(&kick));

        let kick_without_target = decoded("moderation", 4, json!({ "data": { "action": "kick" } }));
        assert!(!moderator_payload_shape_is_valid(&kick_without_target));

        let kick_without_device = decoded(
            "moderation",
            4,
            json!({ "data": { "action": "kick", "target_actor_id": "did:web:carol" } }),
        );
        assert!(!moderator_payload_shape_is_valid(&kick_without_device));

        let force_mute = decoded(
            "mute_state",
            5,
            json!({
                "audio_muted": true,
                "by": "moderator",
                "target_actor_id": "did:web:carol",
                "target_device_id": "ak:device:01904100-0000-7000-8000-00000000000c"
            }),
        );
        assert!(requires_call_moderate(&force_mute));
        assert!(moderator_payload_shape_is_valid(&force_mute));

        let force_mute_without_device = decoded(
            "mute_state",
            6,
            json!({
                "audio_muted": true,
                "by": "moderator",
                "target_actor_id": "did:web:carol"
            }),
        );
        assert!(!moderator_payload_shape_is_valid(
            &force_mute_without_device
        ));
    }

    #[test]
    fn moderator_authz_requires_allow_and_freshness() {
        assert!(authz_check_allows_moderation(&json!({
            "decision": "allow",
            "freshness_state": "fresh",
            "notary_status": "fresh"
        })));
        assert!(!authz_check_allows_moderation(&json!({
            "decision": "hard_deny",
            "freshness_state": "fresh"
        })));
        assert!(!authz_check_allows_moderation(&json!({
            "decision": "allow",
            "freshness_state": "unknown"
        })));
        assert!(!authz_check_allows_moderation(&json!({
            "decision": "allow",
            "notary_status": "unreachable"
        })));
    }

    #[test]
    fn self_echo_dropped() {
        let mut d = decoded("answer", 1, json!({}));
        d.sender_actor = "did:web:alice".into();
        assert_eq!(
            decide_route(&d, "did:web:alice", false, &RouteState::default()),
            RouteDecision::Drop
        );
    }

    #[test]
    fn invite_for_active_call_does_not_ring() {
        let d = decoded("invite", 9, json!({}));
        let state = RouteState {
            ringing_call: None,
            ringing_answered_here: true,
        };
        assert_eq!(
            decide_route(&d, "did:web:alice", false, &state),
            RouteDecision::Drop
        );
    }

    #[test]
    fn answer_while_ringing_clears_ring() {
        let d = decoded("answer", 5, json!({ "accepted": true }));
        let state = RouteState {
            ringing_call: Some("ak:call:1".into()),
            ringing_answered_here: false,
        };
        assert_eq!(
            decide_route(&d, "did:web:alice", false, &state),
            RouteDecision::ClearRing
        );
    }

    // ── Receiver proof verification (device-identity Phase 2) ──────────

    /// Build a real signed `ak.call.signal` envelope the same way the sender
    /// (`ephemeral::attach_broadcast_ephemeral_proof`) does: a detached JWS
    /// over the SDK's authoritative proof binding object (which folds in the
    /// `context = "ak.event-proof-v1"` domain tag), with `event_digest` =
    /// canonical hash of the envelope without `proof`.
    fn signed_call_signal_envelope(
        signer: &crate::event_signer::InksonEventSigner,
        actor_id: &str,
        device_id: &str,
    ) -> Value {
        let mut envelope = json!({
            "kind": "ak.call.signal",
            "realm_id": "ak:realm:r",
            "actor_id": actor_id,
            "device_id": device_id,
            "sent_at": "2026-06-16T00:00:00Z",
            "expires_at": "2026-06-16T00:01:00Z",
            "payload": {
                "call_id": "ak:call:verify-1",
                "signal_type": "invite",
                "seq": 1,
                "data": { "video": true }
            }
        });
        let canonical_bytes = crate::canonical::canonical_json_bytes(&envelope).unwrap();
        let event_digest = crate::canonical::sha256_digest(&canonical_bytes);
        // Binding transcript via the SDK's authoritative `canonical_binding_bytes`
        // (context tag folded in), matching the production ephemeral sender and the
        // receiver-side verifier — so this test can never drift from the wire binding.
        // Use a fresh `created_at` so the receiver-side ephemeral replay-window gate
        // (`verify_ephemeral_envelope_proof`) accepts these fixtures.
        let created_at = chrono::Utc::now();
        let did = arkret_sdk::Did::new(actor_id.to_owned()).unwrap();
        let mut proof = arkret_sdk::Proof {
            kind: arkret_sdk::proof_kind::DETACHED_JWS.to_owned(),
            alg: signer.algorithm().to_owned(),
            verification_method: format!("{actor_id}#device"),
            event_digest: arkret_sdk::Hash::new(event_digest).unwrap(),
            created_at,
            domain: None,
            audience: None,
            jws: String::new(),
        };
        let binding_bytes = proof.canonical_binding_bytes(&did).unwrap();
        proof.jws = signer.detached_jws_over(&binding_bytes).unwrap();
        envelope
            .as_object_mut()
            .unwrap()
            .insert("proof".to_owned(), serde_json::to_value(&proof).unwrap());
        envelope
    }

    fn pubkey_material(seed: u8) -> arkret_sdk::signatures::PublicKeyMaterial {
        let sk = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]);
        let did = crate::did_key::did_key_from_verifying_key(&sk.verifying_key());
        crate::device_directory::public_key_from_directory_value(&did).unwrap()
    }

    #[test]
    fn valid_call_proof_verifies_and_routes_to_ring() {
        let actor = "did:web:caller.example";
        let device = "ak:device:caller-1";
        let seed = 71u8;
        let signer = crate::event_signer::build_ed25519_signer([seed; 32], actor);
        let envelope = signed_call_signal_envelope(&signer, actor, device);
        let key = pubkey_material(seed);

        // Verifies under the correct key.
        assert!(crate::device_directory::verify_ephemeral_envelope_proof(
            &envelope, &key
        ));

        // And a verified invite produces a Ring decision.
        let decoded = decode_call_signal_envelope("ak:realm:r", &envelope).expect("decodes");
        assert!(verify_decoded_proof(&decoded, &key));
        match decide_route(&decoded, "did:web:me", false, &RouteState::default()) {
            RouteDecision::Ring(info) => assert_eq!(info.peer_actor, actor),
            other => panic!("expected Ring, got {other:?}"),
        }
    }

    #[test]
    fn call_proof_fails_closed_under_wrong_key() {
        let actor = "did:web:caller.example";
        let device = "ak:device:caller-1";
        let signer = crate::event_signer::build_ed25519_signer([71u8; 32], actor);
        let envelope = signed_call_signal_envelope(&signer, actor, device);
        // A different device's key MUST NOT verify the proof.
        let wrong_key = pubkey_material(99);
        assert!(!crate::device_directory::verify_ephemeral_envelope_proof(
            &envelope, &wrong_key
        ));
    }

    #[test]
    fn call_proof_fails_closed_under_tampered_signature() {
        let actor = "did:web:caller.example";
        let device = "ak:device:caller-1";
        let seed = 71u8;
        let signer = crate::event_signer::build_ed25519_signer([seed; 32], actor);
        let mut envelope = signed_call_signal_envelope(&signer, actor, device);
        // Flip the JWS tail → signature no longer matches the binding object.
        // Replace the last base64url char with a guaranteed-different one (a bare
        // "always set to 'A'" is a no-op when the signature already ends in 'A',
        // which flaked once the binding — and thus the signature — changed).
        let jws = envelope["proof"]["jws"].as_str().unwrap().to_owned();
        let last = jws.chars().next_back().unwrap();
        let replacement = if last == 'A' { 'B' } else { 'A' };
        let tampered = format!("{}{}", &jws[..jws.len() - 1], replacement);
        envelope["proof"]["jws"] = json!(tampered);
        let key = pubkey_material(seed);
        assert!(!crate::device_directory::verify_ephemeral_envelope_proof(
            &envelope, &key
        ));
    }

    #[test]
    fn call_proof_fails_closed_when_replayed_outside_freshness_window() {
        // S-4: a valid, correctly-signed call-signal proof that is presented
        // long after its `created_at` MUST be dropped by the ephemeral replay
        // window, even though the signature still verifies.
        let actor = "did:web:caller.example";
        let device = "ak:device:caller-1";
        let seed = 71u8;
        let signer = crate::event_signer::build_ed25519_signer([seed; 32], actor);
        let envelope = signed_call_signal_envelope(&signer, actor, device);
        let key = pubkey_material(seed);
        // Fresh at signing time.
        assert!(crate::device_directory::verify_ephemeral_envelope_proof(
            &envelope, &key
        ));
        // Replayed two hours later → rejected by the freshness gate.
        let later = chrono::Utc::now() + chrono::Duration::hours(2);
        assert!(
            !crate::device_directory::verify_ephemeral_envelope_proof_at(&envelope, &key, later)
        );
    }

    #[test]
    fn call_proof_fails_closed_when_controller_differs_from_actor() {
        // verification_method controller != envelope actor_id → reject, even if
        // the signature itself is valid for the embedded method.
        let actor = "did:web:caller.example";
        let device = "ak:device:caller-1";
        let seed = 71u8;
        let signer = crate::event_signer::build_ed25519_signer([seed; 32], actor);
        let mut envelope = signed_call_signal_envelope(&signer, actor, device);
        envelope["proof"]["verification_method"] = json!("did:web:someone-else.example#device");
        let key = pubkey_material(seed);
        assert!(!crate::device_directory::verify_ephemeral_envelope_proof(
            &envelope, &key
        ));
    }

    #[test]
    fn answer_after_local_accept_enqueues_not_clears() {
        // Once this device answered (`ringing_answered_here`), a peer answer
        // (SDP path) must reach the inbox, not clear a ring.
        let d = decoded("answer", 5, json!({}));
        let state = RouteState {
            ringing_call: Some("ak:call:1".into()),
            ringing_answered_here: true,
        };
        assert!(matches!(
            decide_route(&d, "did:web:alice", false, &state),
            RouteDecision::Enqueue(_)
        ));
    }
}
