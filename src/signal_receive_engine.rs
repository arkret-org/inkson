//! Encrypted Signal receive rail (`ak.self.signal.stream.subscribe`).
//!
//! This is the third subscribe engine, alongside [`crate::sync_engine`]
//! (account aggregate) and [`crate::realm_events_engine`] (per-Realm events).
//! It is deliberately the poorest of the three: `signal.md` §4.1 gives the rail
//! no cursor, catch-up, ack or delivery receipt, so this engine persists
//! nothing, and a reconnect only re-establishes live fanout. Anything here that
//! looked like a resume position would be a guarantee the protocol does not
//! make.
//!
//! Admission is entirely garth's [`garth::SignalReceiver`], driven by
//! [`garth::SignalStreamDriver`]. This module supplies only the two seams that
//! need host state:
//!
//! * [`DirectorySenderKeyResolver`] answers "which active signing key did `sender_actor_id`
//!   authorize for `sender_device_id`" from the accepted device directory. It is an authorization
//!   lookup — a revoked or absent device is a negative verdict, never a fallback to the
//!   `verification_method` fragment (`signal.md` §1).
//! * [`MlsSignalDecryptor`] restores the scope's persisted MLS group and opens the AEAD through the
//!   SDK, which enforces `aead_profile` equality with the group's negotiated ciphersuite, epoch
//!   equality, the sender nonce prefix domain, the recomputed AAD and the per-sender nonce-counter
//!   replay window.
//!
//! Product routing then splits three ways: call signalling and message-stream
//! previews go to the app-mounted hubs through
//! [`crate::runtime::projection::SignalProductSink`], while presence and typing
//! bodies land in the bounded live projection the chat views read.

use std::collections::BTreeMap;
use std::sync::Mutex;
use std::time::Duration;

use garth::{
    RunOptions, SignalReceiveHandlers, SignalRejection, SignalSink, SyncLoopControl,
    TransportProvider,
};
use serde_json::Value;

use crate::config::MultiProfileConfig;
use crate::runtime::projection::{SignalProductRouter, SignalProductSink};

/// Failure-backoff bounds, matching the account and realm engines so all three
/// recover on the same human-scale cadence.
const BACKOFF_FLOOR: Duration = Duration::from_secs(1);
const BACKOFF_CEILING: Duration = Duration::from_secs(60);

/// Upper bound on live presence/typing bodies retained for the chat views.
/// Signals expire within 120 seconds at the very most (`signal.md` §2), so this
/// is a memory guard against a hostile fanout, not a functional limit.
const MAX_LIVE_PRESENCE_BODIES: usize = 512;

/// Runtime inputs consumed by the Signal receive engine. UI frameworks stay in
/// the app adapter that builds these handles.
#[derive(Clone)]
pub struct SignalReceiveEngineContext {
    pub base_url: crate::runtime::input::ValueReader<String>,
    pub token: crate::runtime::input::ValueReader<String>,
    pub state_store: crate::runtime::input::StateStoreHandle,
    pub account_did: String,
    pub device_id: String,
    /// Active multi-profile snapshot — the engine exits when the active profile
    /// rotates, mirroring the other two engines.
    pub profiles: crate::runtime::input::ValueReader<MultiProfileConfig>,
    pub client_runtime: crate::client_core::InksonClientRuntime,
    pub effect: crate::runtime::effects::EffectHandle,
    pub products: SignalProductRouter,
}

/// Fail-closed [`garth::SignalSenderKeyResolver`] over the accepted device
/// directory.
///
/// [`garth::SignalReceiver::accept`] resolves the sending device's key before
/// it will touch the AEAD, so the lookup has to be synchronous; only the local
/// device-directory cache can answer that. A cache miss fails the Signal closed
/// rather than admitting it, and the async prefetch that fills the cache is
/// owned by the account sync path.
///
/// Device authorization is resolved against the **current** accepted directory,
/// not against `envelope.seal_ref`. `signal.md` §1 still reads as if the
/// lookup were Seal-relative, but no verifier can do that: device authorization
/// is principal-control state that a target-Realm Seal does not locate, and
/// `keys_query_request_body` deliberately has no as-of basis. soland's
/// `verify_signal_device_proof` resolves the same way, so ingress does **not**
/// enforce a Seal-relative form either.
///
/// `seal_ref` selects the Realm/scope basis only. The split is adjudicated in
/// `arkret-work/review/spec-open/2026-07-31-signal-receiver-seal-basis-device-authorization.md`;
/// the spec text has not been rewritten yet, so do not describe this as
/// satisfying §1 as currently written.
pub struct DirectorySenderKeyResolver;

impl garth::SignalSenderKeyResolver for DirectorySenderKeyResolver {
    fn resolve_sender_key(
        &self,
        envelope: &arkret_wire::SignalEnvelope,
    ) -> Option<arkret_sdk::signatures::PublicKeyMaterial> {
        match crate::identity::device_directory::cached_device_signing_key(
            envelope.sender_actor_id.as_str(),
            envelope.sender_device_id.as_str(),
        ) {
            crate::identity::device_directory::CacheLookup::Hit(key) => Some(key),
            crate::identity::device_directory::CacheLookup::NegativeHit
            | crate::identity::device_directory::CacheLookup::Miss => None,
        }
    }
}

/// [`garth::SignalDecryptor`] backed by the persisted MLS group of the
/// envelope's scope.
///
/// The group is restored per envelope rather than cached: an epoch rotation
/// must take effect on the very next Signal, and a stale cached group would
/// open ciphertext under a key the scope has already left.
pub struct MlsSignalDecryptor {
    state_store: crate::runtime::input::StateStoreHandle,
    secure_store: std::sync::Arc<dyn crate::secure_key_store::SecureKeyStore + Send + Sync>,
    account_did: String,
    device_id: String,
    /// §10.1 obliges a receiver to keep a seen-counter set per
    /// `(key_ref, epoch, device_id, purpose, aead_profile)`. It is shared
    /// across every envelope this engine opens, and bounded by the SDK.
    replay: Mutex<arkret_sdk::AeadNonceReplayTracker>,
}

impl MlsSignalDecryptor {
    pub fn new(
        state_store: crate::runtime::input::StateStoreHandle,
        account_did: String,
        device_id: String,
    ) -> Self {
        Self {
            state_store,
            secure_store: crate::secure_key_store::default_secure_key_store("inkson"),
            account_did,
            device_id,
            replay: Mutex::new(arkret_sdk::AeadNonceReplayTracker::new()),
        }
    }
}

impl garth::SignalDecryptor for MlsSignalDecryptor {
    fn open(&self, envelope: &arkret_wire::SignalEnvelope) -> garth::Result<Vec<u8>> {
        let realm_id = envelope.scope_ref.realm_id().as_str().to_owned();
        let circle_id = envelope
            .scope_ref
            .circle_id()
            .map(|circle_id| circle_id.as_str().to_owned());
        let epoch = envelope.encrypted_payload.epoch;
        let snapshot = self
            .state_store
            .read(|store| store.mls_snapshot_for_effective_scope(&realm_id, circle_id.as_deref()))
            .ok_or_else(|| {
                garth::Error::Protocol(
                    "no accepted MLS group state for the signal scope".to_owned(),
                )
            })?;
        // The MLS exporter only evaluates the group's current epoch
        // (`crates/mls/src/signal.rs::signal_suite_for`), so a Signal naming
        // any other epoch is dropped here rather than routed around. Restoring
        // a retained historical snapshot to open it would resurrect a key the
        // scope has already rotated away from; a Signal lives at most 120
        // seconds and the rail tolerates loss by design (`signal.md` §4.5), so
        // the straddling window is not worth spending forward secrecy on.
        // No decryption queue, no downgrade, no backfill.
        if snapshot.epoch != epoch {
            return Err(garth::Error::Protocol(format!(
                "signal names MLS epoch {epoch}, but the scope is at epoch {}",
                snapshot.epoch
            )));
        }
        let snapshot_secret = crate::mls::runtime::load_device_snapshot_secret(
            self.secure_store.as_ref(),
            &self.account_did,
            &self.device_id,
        )
        .map_err(|error| {
            garth::Error::Protocol(format!("load signal MLS snapshot secret: {error}"))
        })?;
        let group =
            crate::mls::persistence::restore_envelope(&snapshot, &snapshot_secret, snapshot.epoch)
                .map_err(|error| {
                    garth::Error::Protocol(format!("restore signal MLS snapshot: {error}"))
                })?;
        let mut replay = self.replay.lock().map_err(|error| {
            garth::Error::Protocol(format!("signal replay tracker poisoned: {error}"))
        })?;
        group
            .open_signal_envelope(envelope, &mut replay)
            .map_err(|error| garth::Error::Protocol(error.to_string()))
    }
}

/// One live presence/typing body plus the sequence it arrived with.
#[derive(Clone, Debug, PartialEq)]
struct LiveBody {
    payload_sequence: u64,
    expires_at: chrono::DateTime<chrono::Utc>,
    body: Value,
}

/// Bounded set of unexpired `ak.presence` / `ak.typing` bodies.
///
/// The rail allows loss, duplication and reordering (`signal.md` §4.5), so the
/// per-key sequence guard is what keeps a reordered older presence from
/// overwriting a newer one. Everything here is memory-only: presence is a TTL
/// projection, not durable state.
#[derive(Debug, Default)]
struct LivePresenceProjection {
    bodies: BTreeMap<String, LiveBody>,
}

impl LivePresenceProjection {
    /// Drop every body at or past its effective expiry. Returns `true` when
    /// the stored set changed.
    fn expire(&mut self, now: chrono::DateTime<chrono::Utc>) -> bool {
        let before = self.bodies.len();
        self.bodies.retain(|_, live| live.expires_at > now);
        self.bodies.len() != before
    }

    /// Fold one body in. Returns `true` when the stored set changed and the
    /// local projection must be rewritten.
    fn apply(
        &mut self,
        key: String,
        payload_sequence: u64,
        expires_at: chrono::DateTime<chrono::Utc>,
        body: Value,
        now: chrono::DateTime<chrono::Utc>,
    ) -> bool {
        let mut changed = self.expire(now);
        if expires_at <= now {
            return changed;
        }
        if let Some(existing) = self.bodies.get(&key)
            && existing.payload_sequence >= payload_sequence
        {
            return changed;
        }
        self.bodies.insert(
            key,
            LiveBody {
                payload_sequence,
                expires_at,
                body,
            },
        );
        changed = true;
        while self.bodies.len() > MAX_LIVE_PRESENCE_BODIES {
            let Some(soonest) = self
                .bodies
                .iter()
                .min_by_key(|(_, live)| live.expires_at)
                .map(|(key, _)| key.clone())
            else {
                break;
            };
            self.bodies.remove(&soonest);
        }
        changed
    }

    fn bodies(&self) -> Vec<Value> {
        self.bodies.values().map(|live| live.body.clone()).collect()
    }
}

/// Routes admitted plaintext to the three product consumers.
struct InksonSignalSink {
    state_store: crate::runtime::input::StateStoreHandle,
    products: SignalProductRouter,
    live: Mutex<LivePresenceProjection>,
}

impl SignalSink for InksonSignalSink {
    fn prepare_admission<'a>(
        &'a self,
        envelope: &'a arkret_wire::SignalEnvelope,
    ) -> impl std::future::Future<Output = ()> {
        // The device-directory lookup inside admission is synchronous and
        // cache-only, so a first contact would otherwise always fail closed.
        self.products.prefetch_sender_key(envelope)
    }

    async fn deliver<'a>(
        &'a self,
        envelope: &'a arkret_wire::SignalEnvelope,
        plaintext: garth::SignalPlaintext,
    ) -> garth::Result<()> {
        {
            match plaintext.kind.as_str() {
                garth::SIGNAL_PLAINTEXT_KIND_CALL => {
                    // The decrypted body verbatim: `CallSignalPlaintext` is a
                    // closed `deny_unknown_fields` shape, so the
                    // envelope-derived fields the presence projection wants
                    // would make every call signal fail to decode. The router
                    // already receives the envelope alongside it.
                    self.products
                        .call_signal(envelope, decrypted_body_value(&plaintext))
                        .await;
                }
                garth::SIGNAL_PLAINTEXT_KIND_MESSAGE_STREAM => {
                    self.products.message_stream(&plaintext).await;
                }
                garth::SIGNAL_PLAINTEXT_KIND_PRESENCE | SIGNAL_PLAINTEXT_KIND_TYPING => {
                    self.apply_live_body(&plaintext);
                }
                other => {
                    // Admitted and authenticated, but no local consumer yet
                    // (`ak.receipt.read` today). Dropping it is correct on a
                    // rail with no delivery guarantee; tracing it keeps the
                    // gap visible instead of silent.
                    tracing::debug!(kind = other, "admitted Signal has no local product route");
                }
            }
            Ok(())
        }
    }

    fn idle(&self, now: chrono::DateTime<chrono::Utc>) {
        self.products.advance_clock(now);
        self.expire_live_bodies(now);
    }

    fn rejected(
        &self,
        envelope: &arkret_wire::SignalEnvelope,
        _rejection: SignalRejection,
        error: &garth::Error,
    ) {
        // Sender identity is already server-visible on this rail, so naming it
        // here leaks nothing the transport did not. The plaintext never exists
        // for a rejected envelope, so nothing product-level can be logged.
        tracing::debug!(
            %error,
            actor = %envelope.sender_actor_id,
            device = %envelope.sender_device_id,
            "inbound Signal failed receiver admission and was dropped"
        );
    }
}

const SIGNAL_PLAINTEXT_KIND_TYPING: &str = "ak.typing";

impl InksonSignalSink {
    /// Drop presence/typing bodies whose effective TTL has passed.
    ///
    /// A typing indicator lives five seconds and a presence signal thirty, so
    /// without a clock edge the last body from a peer who stopped typing would
    /// stay in the projection until that peer sent something else.
    fn expire_live_bodies(&self, now: chrono::DateTime<chrono::Utc>) {
        let Ok(mut live) = self.live.lock() else {
            return;
        };
        if !live.expire(now) {
            return;
        }
        let bodies = live.bodies();
        drop(live);
        self.state_store
            .write(|store| store.save_presence_projection(&bodies));
    }

    fn apply_live_body(&self, plaintext: &garth::SignalPlaintext) {
        let body = live_body_value(plaintext);
        let target = plaintext
            .body
            .get("strand_id")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let key = format!(
            "{}|{}|{}|{target}",
            plaintext.kind, plaintext.actor_id, plaintext.sender_device_id
        );
        let now = crate::clock::now_utc();
        let Ok(mut live) = self.live.lock() else {
            return;
        };
        if !live.apply(
            key,
            plaintext.payload_sequence,
            plaintext.expires_at,
            body,
            now,
        ) {
            return;
        }
        let bodies = live.bodies();
        drop(live);
        self.state_store
            .write(|store| store.save_presence_projection(&bodies));
    }
}

/// The decrypted body exactly as the sender canonicalized it.
fn decrypted_body_value(plaintext: &garth::SignalPlaintext) -> Value {
    Value::Object(serde_json::Map::from_iter(plaintext.body.clone()))
}

/// The decrypted body plus the envelope-derived fields the chat projections
/// read. `expires_at` is garth's effective expiry — the earlier of the outer
/// `expires_at` and the plaintext `ttl_ms` — so a consumer never has to
/// recombine the two TTLs itself.
///
/// Only for payload profiles whose consumer accepts an open object. A closed
/// `deny_unknown_fields` plaintext (call signalling) must get
/// [`decrypted_body_value`] instead.
fn live_body_value(plaintext: &garth::SignalPlaintext) -> Value {
    let mut body = serde_json::Map::from_iter(plaintext.body.clone());
    body.insert(
        "actor_id".to_owned(),
        Value::String(plaintext.actor_id.as_str().to_owned()),
    );
    body.insert(
        "device_id".to_owned(),
        Value::String(plaintext.sender_device_id.as_str().to_owned()),
    );
    body.insert(
        "sent_at".to_owned(),
        Value::String(arkret_sdk::canonical::format_timestamp_canonical(
            plaintext.sent_at,
        )),
    );
    body.insert(
        "expires_at".to_owned(),
        Value::String(arkret_sdk::canonical::format_timestamp_canonical(
            plaintext.expires_at,
        )),
    );
    Value::Object(body)
}

#[derive(Clone, Copy, Default)]
struct SignalHostClock;

impl garth::HostClock for SignalHostClock {
    fn now(&self) -> chrono::DateTime<chrono::Utc> {
        crate::clock::now_utc()
    }
}

/// Run the Signal receive rail until the generation is bumped, the active
/// profile rotates, or the session ends.
pub async fn run_signal_receive_engine(
    start_generation: u64,
    generation: crate::runtime::input::ValueReader<u64>,
    ctx: SignalReceiveEngineContext,
) {
    let start_profile_id = ctx.profiles.get().active_profile_id;
    let provider = SignalTransportProvider {
        ctx: ctx.clone(),
        generation,
        start_generation,
        start_profile_id,
    };
    let resolver = DirectorySenderKeyResolver;
    let decryptor = MlsSignalDecryptor::new(
        ctx.state_store.clone(),
        ctx.account_did.clone(),
        ctx.device_id.clone(),
    );
    let sink = InksonSignalSink {
        state_store: ctx.state_store.clone(),
        products: ctx.products.clone(),
        live: Mutex::new(LivePresenceProjection::default()),
    };
    let result = ctx
        .client_runtime
        .client()
        .run_signal(
            &provider,
            SignalReceiveHandlers::new(&resolver, &decryptor, &sink),
            &SignalHostClock,
            &SyncLoopControl::new(),
            RunOptions {
                beat: Duration::from_millis(250),
                min_backoff: BACKOFF_FLOOR,
                max_backoff: BACKOFF_CEILING,
                jitter_ratio: 0.2,
            },
        )
        .await;
    if let Err(error) = result {
        tracing::warn!(error = %error, "signal receive runner stopped with error");
    }
}

struct SignalTransportProvider {
    ctx: SignalReceiveEngineContext,
    generation: crate::runtime::input::ValueReader<u64>,
    start_generation: u64,
    start_profile_id: Option<String>,
}

impl TransportProvider for SignalTransportProvider {
    type Transport = arkret_sdk::http_client::Client;

    async fn provide(&self) -> garth::Result<Self::Transport> {
        crate::identity::session_refresh::provide_authenticated_sdk_client(&self.ctx.base_url.get())
            .await
            .map_err(|error| garth::Error::Protocol(error.to_string()))
    }

    async fn recover_unauthorized(&self) -> garth::Result<bool> {
        crate::identity::session_refresh::refresh_authenticated_session_after_unauthorized(
            &self.ctx.base_url.get(),
        )
        .await
        .map(|_| true)
        .map_err(|error| garth::Error::Http(error.to_string()))
    }

    fn is_active(&self) -> bool {
        self.generation.get() == self.start_generation
            && self.ctx.profiles.get().active_profile_id == self.start_profile_id
            && !self.ctx.effect.is_cancelled()
            && !self.ctx.base_url.get().trim().is_empty()
            && !self.ctx.token.get().trim().is_empty()
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn at(seconds: i64) -> chrono::DateTime<chrono::Utc> {
        chrono::DateTime::from_timestamp(1_800_000_000 + seconds, 0).unwrap()
    }

    fn plaintext_of(kind: &str, body: Value) -> garth::SignalPlaintext {
        let Value::Object(body) = body else {
            unreachable!("test body must be an object");
        };
        garth::SignalPlaintext {
            kind: kind.to_owned(),
            actor_id: arkret_sdk::Did::new("did:web:alice.example").unwrap(),
            payload_sequence: 7,
            ttl_ms: Some(30_000),
            body: body.into_iter().collect(),
            sent_at: at(0),
            expires_at: at(30),
            scope_ref: arkret_sdk::ScopeRef::Realm {
                realm_id: arkret_sdk::RealmId::new("ak:realm:01904100-0000-7000-8000-000000000001")
                    .unwrap(),
            },
            seal_ref: arkret_sdk::SealId::new(format!("ak:seal:sha256:{}", "a".repeat(64)))
                .unwrap(),
            sender_device_id: arkret_sdk::DeviceId::new(
                "ak:device:01904100-0000-7000-8000-000000000002",
            )
            .unwrap(),
        }
    }

    /// `CallSignalPlaintext` is `deny_unknown_fields`, so the call route MUST
    /// hand the router the decrypted body verbatim. Merging the envelope-derived
    /// fields the presence projection wants would make every inbound call
    /// signal fail to decode — silently, because a signal that cannot be
    /// decoded is simply dropped.
    #[test]
    fn the_call_route_body_still_parses_as_the_closed_call_plaintext() {
        let plaintext = plaintext_of(
            garth::SIGNAL_PLAINTEXT_KIND_CALL,
            json!({
                "kind": "ak.call.signal",
                "call_id": "ak:call:01904100-0000-7000-8000-000000000003",
                "signal_kind": "invite",
                "seq": 7,
                "data": {"media": {"video": true}}
            }),
        );

        let body = decrypted_body_value(&plaintext);
        serde_json::from_value::<arkret_sdk::CallSignalPlaintext>(body)
            .expect("the call route must not add fields to the closed plaintext");

        assert!(
            serde_json::from_value::<arkret_sdk::CallSignalPlaintext>(live_body_value(&plaintext))
                .is_err(),
            "the presence-shaped body is deliberately not the call shape"
        );
    }

    #[test]
    fn the_live_projection_body_carries_the_envelope_derived_expiry() {
        let plaintext = plaintext_of(
            garth::SIGNAL_PLAINTEXT_KIND_PRESENCE,
            json!({"kind": "ak.presence", "state": "online"}),
        );

        let body = live_body_value(&plaintext);
        assert_eq!(body["actor_id"], json!("did:web:alice.example"));
        assert_eq!(
            body["device_id"],
            json!("ak:device:01904100-0000-7000-8000-000000000002")
        );
        // The chat projection reads `expires_at` directly instead of
        // recombining the outer TTL with the plaintext `ttl_ms`.
        assert_eq!(
            body["expires_at"],
            json!(arkret_sdk::canonical::format_timestamp_canonical(at(30)))
        );
    }

    #[test]
    fn a_reordered_older_presence_does_not_overwrite_the_newer_one() {
        let mut live = LivePresenceProjection::default();
        let key = "ak.presence|did:web:alice.example|ak:device:one|".to_owned();

        assert!(live.apply(key.clone(), 4, at(30), json!({"state": "online"}), at(0)));
        assert!(!live.apply(key.clone(), 3, at(30), json!({"state": "dnd"}), at(0)));
        assert_eq!(live.bodies(), vec![json!({"state": "online"})]);

        assert!(live.apply(key, 5, at(30), json!({"state": "idle"}), at(0)));
        assert_eq!(live.bodies(), vec![json!({"state": "idle"})]);
    }

    #[test]
    fn expired_bodies_are_pruned_and_an_already_expired_one_is_never_stored() {
        let mut live = LivePresenceProjection::default();
        live.apply(
            "ak.typing|a|d|s".to_owned(),
            1,
            at(5),
            json!({"typing": true}),
            at(0),
        );

        // The prune alone is a change, so the projection is rewritten without
        // the stale body; the new body is itself already expired.
        assert!(live.apply(
            "ak.typing|b|d|s".to_owned(),
            1,
            at(6),
            json!({"typing": true}),
            at(10)
        ));
        assert!(live.bodies().is_empty());
    }

    /// A peer who stops typing sends nothing more, so only a clock edge can
    /// clear their indicator (`signal.md` §7.4 makes the same point for
    /// message-stream previews). The rail's keepalives supply that edge.
    #[test]
    fn an_idle_clock_edge_clears_a_body_whose_ttl_passed() {
        let mut live = LivePresenceProjection::default();
        live.apply(
            "ak.typing|a|d|s".to_owned(),
            1,
            at(5),
            json!({"typing": true}),
            at(0),
        );

        assert!(!live.expire(at(4)), "nothing has expired yet");
        assert_eq!(live.bodies().len(), 1);
        assert!(live.expire(at(5)), "the effective expiry is exclusive");
        assert!(live.bodies().is_empty());
        assert!(!live.expire(at(9)), "a second sweep changes nothing");
    }

    #[test]
    fn the_live_set_stays_bounded_by_evicting_the_soonest_expiry() {
        let mut live = LivePresenceProjection::default();
        for index in 0..(MAX_LIVE_PRESENCE_BODIES + 10) {
            live.apply(
                format!("ak.presence|actor-{index}|device|"),
                1,
                at(60 + index as i64),
                json!({ "state": "online", "index": index }),
                at(0),
            );
        }

        assert_eq!(live.bodies().len(), MAX_LIVE_PRESENCE_BODIES);
        // The ten shortest-lived entries were the ones dropped.
        assert!(
            live.bodies
                .values()
                .all(|body| body.expires_at >= at(60 + 10))
        );
    }
}
