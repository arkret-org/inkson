//! App-level call-signaling hub — the receive side of `ak.call.signal`.
//!
//! v1 removed the plaintext ephemeral bucket from Realm sync. Inbound call
//! signalling arrives on the Signal rail (`GET /_arkret/self/signal/subscribe`)
//! as encrypted `SignalEnvelope`s whose outer header exposes only the scope and
//! `signal_class`; `call_id`, `signal_kind` and the sender sequence exist only
//! after decryption.
//!
//! This module owns the cross-component plumbing that turns decrypted signals
//! into FSM/transport drive signals:
//!   * [`CallSignalHub`] is `provide_context`-ed once at the app root.
//!   * The Signal receive path calls [`route_decrypted_call_signals`], which dedups, sets
//!     `incoming_call` on a fresh `invite`, and queues every other signal type into the per-call
//!     inbox.
//!   * `CallPanel` (`views/call.rs`) pulls the hub via `use_context`, drains its `active_call_id`
//!     inbox in an effect, and applies each item to the `MediaTransport` / call FSM.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use arkret_wire::CapabilityActionId;
use dioxus::prelude::*;
use serde_json::Value;

use crate::transport::TransportClient;

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
    /// Invite requested video (`payload.data.media.video`).
    pub video: bool,
}

/// A non-invite signal queued for the active `CallPanel` to apply.
#[derive(Clone, Debug, PartialEq)]
pub struct CallSignalInboxItem {
    pub realm_id: String,
    pub call_id: String,
    pub seq: u64,
    /// Sender actor DID (`envelope.actor_id`).
    pub sender_actor: String,
    /// Sender device id (`envelope.device_id`).
    pub sender_device: String,
    pub signal: arkret_sdk::CallSignalData,
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
    pub seq: u64,
    pub sender_actor: String,
    pub sender_device: String,
    pub signal: arkret_sdk::CallSignalData,
}

/// Decode one already-decrypted call Signal.
///
/// Returns `None` when the plaintext is not an `ak.call.signal` body or omits
/// a required field. This product adapter is reached only from
/// [`garth::SignalReceiver`] after the envelope's structure, current sender
/// authority, proof, expiry, replay state and AEAD have all been admitted.
pub fn decode_call_signal(
    envelope: &arkret_wire::SignalEnvelope,
    plaintext: &Value,
) -> Option<DecodedCallSignal> {
    let body = serde_json::from_value::<arkret_sdk::CallSignalPlaintext>(plaintext.clone()).ok()?;
    Some(DecodedCallSignal {
        realm_id: envelope.realm_id.as_str().to_owned(),
        call_id: body.call_id.as_str().to_owned(),
        seq: body.seq,
        sender_actor: envelope
            .sender_actor_id
            .signing_principal_id()
            .as_str()
            .to_owned(),
        sender_device: envelope.sender_device_id.as_ref()?.as_str().to_owned(),
        signal: body.signal,
    })
}

/// Route every decoded call signal from one realm body into the hub:
/// dedup → `invite` raises `incoming_call` (when no active session owns the
/// call) → everything else queues into the per-call inbox.
///
/// `local_actor` is this device's account DID; signals this client itself
/// emitted (echoed back through sync) are skipped so we never self-drive.
///
/// Envelope admission belongs exclusively to [`garth::SignalReceiver`]. This
/// product layer performs only call-specific authorization (moderation) and UI
/// routing; repeating directory resolution or proof verification here would
/// create a second admission implementation that can drift from garth.
pub async fn route_decrypted_call_signals(
    hub: &mut CallSignalHub,
    signals: &[(arkret_wire::SignalEnvelope, Value)],
    local_actor: &str,
    api: Option<&TransportClient>,
) {
    for (envelope, plaintext) in signals {
        let Some(decoded) = decode_call_signal(envelope, plaintext) else {
            continue;
        };
        // Self-echo: skip verification + routing entirely (we trust our own
        // outbound frames and never resolve our own key here).
        if !local_actor.is_empty() && decoded.sender_actor == local_actor {
            continue;
        }
        if moderator_signal_authorized(&decoded, api).await {
            route_verified_decoded_signal(hub, decoded, local_actor);
        }
    }
}

async fn moderator_signal_authorized(
    decoded: &DecodedCallSignal,
    api: Option<&TransportClient>,
) -> bool {
    if !requires_call_moderate(decoded) {
        return true;
    }
    let Some(api) = api else {
        tracing::warn!(
            realm_id = %decoded.realm_id,
            call_id = %decoded.call_id,
            sender = %decoded.sender_actor,
            signal_kind = ?decoded.signal.kind(),
            "dropping moderator call signal without authz client"
        );
        return false;
    };
    match async {
        crate::transport::realm_read::authz_check_resource(
            &api.sdk_http_client()?,
            &decoded.sender_actor,
            CapabilityActionId::CALL_MODERATE,
            Some(arkret_sdk::WireResourceSelector::realm(
                arkret_sdk::RealmId::new(decoded.realm_id.clone())?,
            )),
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
                signal_kind = ?decoded.signal.kind(),
                ?outcome,
                "dropping unauthorised moderator call signal"
            );
            false
        }
        Err(error) => {
            tracing::warn!(
                realm_id = %decoded.realm_id,
                call_id = %decoded.call_id,
                sender = %decoded.sender_actor,
                signal_kind = ?decoded.signal.kind(),
                ?error,
                "dropping moderator call signal after authz check failure"
            );
            false
        }
    }
}

fn requires_call_moderate(decoded: &DecodedCallSignal) -> bool {
    matches!(&decoded.signal, arkret_sdk::CallSignalData::Moderation(_))
        || matches!(
            &decoded.signal,
            arkret_sdk::CallSignalData::MuteState(data)
                if data.changed_by == arkret_sdk::MuteChangedBy::Moderator
        )
}

fn authz_check_allows_moderation(outcome: &crate::models::AuthzCheckOutcome) -> bool {
    if !crate::transport::realm_read::authz_allowed(outcome) {
        return false;
    }
    let freshness_acceptable = matches!(
        outcome.freshness_state,
        None | Some(arkret_sdk::FreshnessState::Fresh)
    );
    let notary_acceptable = matches!(
        outcome.notary_status,
        None | Some(arkret_sdk::NotaryStatus::Fresh)
    );
    freshness_acceptable && notary_acceptable
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

    if let arkret_sdk::CallSignalData::Invite(invite) = &decoded.signal {
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
            video: invite.media.video,
        });
    }

    // Multi-device stop-ring: if THIS device is still ringing for the call
    // but has NOT answered, an inbound `answer` / `reject{call_already_answered}`
    // / `hangup` means another device (or the caller) resolved the ring.
    let still_ringing_here = state.ringing_call.as_deref() == Some(decoded.call_id.as_str())
        && !state.ringing_answered_here;
    if still_ringing_here {
        let call_already_answered = matches!(
            &decoded.signal,
            arkret_sdk::CallSignalData::Answer(_) | arkret_sdk::CallSignalData::Hangup(_)
        ) || matches!(
            &decoded.signal,
            arkret_sdk::CallSignalData::Reject(data)
                if data.reason.as_str() == "call_already_answered"
        );
        if call_already_answered {
            return RouteDecision::ClearRing;
        }
    }

    RouteDecision::Enqueue(CallSignalInboxItem {
        realm_id: decoded.realm_id.clone(),
        call_id: decoded.call_id.clone(),
        seq: decoded.seq,
        sender_actor: decoded.sender_actor.clone(),
        sender_device: decoded.sender_device.clone(),
        signal: decoded.signal.clone(),
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

    const TEST_REALM: &str = "ak:realm:AZQnaSleDidYaYIvfwYy3au5gnd_DSinxyUHEl7ewtxk";
    const TEST_CALL: &str = "ak:call:ASejwMK0oLxZuMdthmzN01YReWWY3mzf6iJafILErPab";
    const PEER_ACTOR: &str = "did:web:bob.example";
    const PEER_DEVICE: &str = "ak:device:01904100-0000-7000-8000-b0b0b0000001";

    /// A real signed `SignalEnvelope` and the plaintext body a receiver gets
    /// out of it.
    ///
    /// The pre-v1 fixture hand-wrote a plaintext wire envelope with
    /// `payload.{call_id,signal_kind,seq}` on the header. That object no longer
    /// exists: `signal.md` §6 makes exactly those fields ciphertext, so the
    /// fixture now goes through the production sender path and the assertions
    /// move to the decrypted body.
    fn media(video: bool) -> arkret_sdk::CallMediaSelection {
        arkret_sdk::CallMediaSelection {
            audio: true,
            video,
            screen: Some(false),
        }
    }

    fn invite(video: bool) -> arkret_sdk::CallSignalData {
        arkret_sdk::CallSignalData::Invite(arkret_sdk::CallInviteSignalData {
            lifetime_ms: 60_000,
            offer: arkret_sdk::SessionDescription {
                sdp_type: arkret_sdk::SessionDescriptionType::Offer,
                sdp: "v=0".to_owned(),
            },
            media: media(video),
        })
    }

    fn candidate() -> arkret_sdk::CallSignalData {
        arkret_sdk::CallSignalData::Candidate(arkret_sdk::CallCandidateSignalData {
            candidates: vec![arkret_sdk::IceCandidate {
                candidate: "candidate:1".to_owned(),
                sdp_mid: Some("0".to_owned()),
                sdp_m_line_index: Some(0),
            }],
        })
    }

    fn answer() -> arkret_sdk::CallSignalData {
        arkret_sdk::CallSignalData::Answer(arkret_sdk::CallAnswerSignalData {
            answer: arkret_sdk::SessionDescription {
                sdp_type: arkret_sdk::SessionDescriptionType::Answer,
                sdp: "v=0".to_owned(),
            },
            accepted_media: media(true),
        })
    }

    fn sealed_call_signal(
        seed: u8,
        actor: &str,
        device: &str,
        seq: u64,
        signal: arkret_sdk::CallSignalData,
    ) -> (arkret_wire::SignalEnvelope, Value) {
        let signer = std::sync::Arc::new(crate::event_signer::build_ed25519_device_signer(
            [seed; 32], actor, device,
        ));
        crate::signal::test_support::sealed_signal(
            signer.as_ref(),
            &crate::signal::SignalPayload::CallSignal {
                call_id: arkret_sdk::CallId::new(TEST_CALL).unwrap(),
                seq,
                signal,
            },
            &arkret_sdk::RealmId::new(TEST_REALM).unwrap(),
            &crate::mls_api_helpers::principal_core_id(actor).unwrap(),
            &arkret_sdk::DeviceId::new(device).unwrap(),
            crate::signal::SignalSequence::new(seq),
        )
        .expect("fixture signal must seal")
    }

    #[test]
    fn decodes_invite_and_video_flag() {
        let (envelope, plaintext) =
            sealed_call_signal(41, PEER_ACTOR, PEER_DEVICE, 1, invite(true));

        let decoded = decode_call_signal(&envelope, &plaintext).expect("decodes");

        assert!(matches!(
            decoded.signal,
            arkret_sdk::CallSignalData::Invite(_)
        ));
        assert_eq!(decoded.call_id, TEST_CALL);
        assert_eq!(decoded.sender_actor, "ak:did_core:web:bob.example");
        assert_eq!(decoded.sender_device, PEER_DEVICE);
        assert_eq!(decoded.realm_id, TEST_REALM);
        assert!(matches!(
            decoded.signal,
            arkret_sdk::CallSignalData::Invite(ref data) if data.media.video
        ));
    }

    /// Restates `decodes_canonical_ephemeral_container`: there is no
    /// `body.ephemeral.events[]` container in v1 sync, so the surviving
    /// assertion is that the dedupe sequence survives the plaintext boundary.
    #[test]
    fn decoded_signal_carries_the_in_ciphertext_sequence() {
        let (envelope, plaintext) = sealed_call_signal(42, PEER_ACTOR, PEER_DEVICE, 2, candidate());

        let decoded = decode_call_signal(&envelope, &plaintext).expect("decodes");

        assert!(matches!(
            decoded.signal,
            arkret_sdk::CallSignalData::Candidate(_)
        ));
        assert_eq!(decoded.seq, 2);
        // The outer header exposes only the scope and the class — never the
        // call id or the signal kind (`signal.md` §6).
        let header = serde_json::to_value(&envelope).unwrap();
        assert!(header.get("call_id").is_none());
        assert!(header.get("signal_kind").is_none());
        assert_eq!(header["signal_class"], "session");
    }

    #[test]
    fn decode_skips_plaintext_that_is_not_a_call_signal() {
        let (envelope, _) = sealed_call_signal(43, PEER_ACTOR, PEER_DEVICE, 1, invite(false));

        // A typing body decrypted out of the same rail is not a call signal.
        assert!(decode_call_signal(&envelope, &json!({"kind": "ak.typing"})).is_none());
        // Neither is a call body whose signal_kind is outside the canonical
        // enum, even though the envelope authenticated.
        assert!(
            decode_call_signal(
                &envelope,
                &json!({
                    "kind": "ak.call.signal",
                    "call_id": TEST_CALL,
                    "signal_kind": "sdp_offer",
                    "payload_sequence": 1
                })
            )
            .is_none()
        );
    }

    fn decoded(signal: arkret_sdk::CallSignalData, seq: u64) -> DecodedCallSignal {
        DecodedCallSignal {
            realm_id: "ak:realm:r".into(),
            call_id: "ak:call:1".into(),
            seq,
            sender_actor: "did:web:bob".into(),
            sender_device: "dev-b".into(),
            signal,
        }
    }

    #[test]
    fn invite_decides_ring_then_dedup_drops() {
        let d = decoded(invite(true), 1);
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
        let d = decoded(candidate(), 2);
        match decide_route(&d, "did:web:alice", false, &RouteState::default()) {
            RouteDecision::Enqueue(item) => {
                assert!(matches!(
                    item.signal,
                    arkret_sdk::CallSignalData::Candidate(_)
                ));
                assert_eq!(item.call_id, "ak:call:1");
            }
            other => panic!("expected Enqueue, got {other:?}"),
        }
    }

    #[test]
    fn moderator_signals_require_authz() {
        let kick = decoded(
            arkret_sdk::CallSignalData::Moderation(arkret_sdk::CallModerationSignalData {
                action: arkret_sdk::CallModerationAction::Kick,
                target_actor_id: Some(
                    crate::mls_api_helpers::principal_core_id("did:web:carol").unwrap(),
                ),
                target_device_id: Some(
                    arkret_sdk::DeviceId::new("ak:device:01904100-0000-7000-8000-00000000000c")
                        .unwrap(),
                ),
                reason: None,
            }),
            3,
        );
        assert!(requires_call_moderate(&kick));
        let force_mute = decoded(
            arkret_sdk::CallSignalData::MuteState(arkret_sdk::CallMuteStateSignalData {
                audio_muted: true,
                video_muted: false,
                changed_by: arkret_sdk::MuteChangedBy::Moderator,
                target_actor_id: Some(
                    crate::mls_api_helpers::principal_core_id("did:web:carol").unwrap(),
                ),
                target_device_id: Some(
                    arkret_sdk::DeviceId::new("ak:device:01904100-0000-7000-8000-00000000000c")
                        .unwrap(),
                ),
            }),
            5,
        );
        assert!(requires_call_moderate(&force_mute));
    }

    #[test]
    fn moderator_authz_requires_allow_and_freshness() {
        let outcome = |value| serde_json::from_value(value).unwrap();
        assert!(authz_check_allows_moderation(&outcome(json!({
            "decision": "allow",
            "freshness_state": "fresh",
            "notary_status": "fresh"
        }))));
        assert!(!authz_check_allows_moderation(&outcome(json!({
            "decision": "hard_deny",
            "freshness_state": "fresh"
        }))));
        assert!(!authz_check_allows_moderation(&outcome(json!({
            "decision": "allow",
            "freshness_state": "unknown"
        }))));
        assert!(!authz_check_allows_moderation(&outcome(json!({
            "decision": "allow",
            "notary_status": "unreachable"
        }))));
    }

    #[test]
    fn self_echo_dropped() {
        let mut d = decoded(answer(), 1);
        d.sender_actor = "did:web:alice".into();
        assert_eq!(
            decide_route(&d, "did:web:alice", false, &RouteState::default()),
            RouteDecision::Drop
        );
    }

    #[test]
    fn invite_for_active_call_does_not_ring() {
        let d = decoded(invite(false), 9);
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
        let d = decoded(answer(), 5);
        let state = RouteState {
            ringing_call: Some("ak:call:1".into()),
            ringing_answered_here: false,
        };
        assert_eq!(
            decide_route(&d, "did:web:alice", false, &state),
            RouteDecision::ClearRing
        );
    }

    #[test]
    fn garth_admitted_call_routes_without_a_second_proof_gate() {
        let actor = "did:web:caller.example";
        let device = "ak:device:01904100-0000-7000-8000-ca11e1000001";
        let (envelope, plaintext) = sealed_call_signal(71, actor, device, 1, invite(true));

        // The product adapter receives only the envelope-derived identity and
        // already-opened body. Cryptographic admission was completed by garth.
        let decoded = decode_call_signal(&envelope, &plaintext).expect("decodes");
        match decide_route(&decoded, "did:web:me", false, &RouteState::default()) {
            RouteDecision::Ring(info) => {
                assert_eq!(info.peer_actor, "ak:did_core:web:caller.example")
            }
            other => panic!("expected Ring, got {other:?}"),
        }
    }

    #[test]
    fn answer_after_local_accept_enqueues_not_clears() {
        // Once this device answered (`ringing_answered_here`), a peer answer
        // (SDP path) must reach the inbox, not clear a ring.
        let d = decoded(answer(), 5);
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
