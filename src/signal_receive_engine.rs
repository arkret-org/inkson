//! Encrypted Signal receive rail (`ak.self.signal.stream.subscribe.v1`).
//!
//! This is the momentary-announcement engine, alongside [`crate::sync_engine`]
//! (account aggregate) and [`crate::realm_events_engine`] (Realm commit
//! streams). It is deliberately the poorest of the three: the rail has no
//! cursor, catch-up, ack or delivery receipt, so this engine persists nothing,
//! and a reconnect only re-establishes live fanout. Anything here that looked
//! like a resume position would be a guarantee the protocol does not make.
//!
//! Admission is entirely [`garth::SignalReceiver`]. The client no longer
//! resolves a sender key of its own: the Station issues the
//! [`arkret_wire::SignalDeliveryAuthority`] inside the authenticated stream
//! frame, and the receiver binds the envelope to it, verifies the producer
//! proof, and enforces the per-endpoint sequence high-water. This module
//! supplies only the two seams that need host state:
//!
//! * [`MlsSignalDecryptor`] restores the scope's persisted MLS group through the same
//!   [`crate::signal::restore_signal_mls_session`] helper the send path uses, then opens the AEAD
//!   through the SDK, which enforces `aead_profile` equality with the group's negotiated
//!   ciphersuite, epoch equality, the sender nonce prefix domain, the recomputed AAD and the
//!   per-sender nonce-counter replay window.
//! * [`InksonSignalSink`] routes the admitted plaintext to the product consumers.
//!
//! Product routing then splits four ways: call signalling, message-stream
//! previews and read receipts go to the app-mounted hubs through
//! [`crate::runtime::projection::SignalProductSink`], while presence and typing
//! bodies land in the bounded live projection the chat views read.
//!
//! Local revocation still overrides the Station's authority: a cached public
//! key alone is never current authorization, so a delivery naming a device this
//! client already knows to be revoked is dropped before decryption.

use std::collections::BTreeMap;
use std::sync::Mutex;
use std::time::Duration;

use chrono::{DateTime, Utc};
use garth::signal::{SignalReceiveOutcome, SignalReceiver, SignalSink, SignalStreamStopReason};
use garth::{RetrySchedule, RunOptions, SyncLoopControl, TransportProvider};
use serde_json::Value;

use crate::config::MultiProfileConfig;
use crate::runtime::projection::{AdmittedSignal, SignalProductRouter, SignalProductSink};

/// Failure-backoff bounds, matching the account and realm engines so all three
/// recover on the same human-scale cadence.
const BACKOFF_FLOOR: Duration = Duration::from_secs(1);
const BACKOFF_CEILING: Duration = Duration::from_secs(60);

/// Most live TTL bodies the chat projection retains at once.
const MAX_LIVE_SIGNAL_BODIES: usize = 512;

/// Runtime inputs consumed by the Signal receive engine. UI frameworks stay in
/// the app adapter that builds these handles.
#[derive(Clone)]
pub struct SignalReceiveEngineContext {
    pub token: crate::runtime::input::ValueReader<String>,
    pub state_store: crate::runtime::input::StateStoreHandle,
    pub account: crate::config::ActiveAccountContext,
    pub principal_id: arkret_sdk::DidCoreId,
    pub device_id: String,
    /// Active multi-profile snapshot — the engine exits when the active profile
    /// rotates, mirroring the other two engines.
    pub profiles: crate::runtime::input::ValueReader<MultiProfileConfig>,
    pub client_runtime: crate::client_core::InksonClientRuntime,
    pub effect: crate::runtime::effects::EffectHandle,
    pub products: SignalProductRouter,
    /// The session's optional WebSocket. A live rail supplies the Signal
    /// channel; otherwise this engine stays on the canonical NDJSON rail.
    pub websocket_rail: crate::transport::websocket_rail::WebSocketRail,
}

/// [`garth::SignalDecryptor`] backed by the persisted MLS group of the
/// envelope's scope.
///
/// The group is restored per envelope rather than cached: an epoch rotation
/// must take effect on the very next Signal, and a stale cached group would
/// open ciphertext under a key the scope has already left.
///
/// The sender's current authority is the Station-issued delivery authority the
/// receiver already bound to this envelope; this decryptor only re-checks the
/// one fact the Station cannot know, which is whether this client has locally
/// observed the sending device as revoked.
pub struct MlsSignalDecryptor {
    state_store: crate::runtime::input::StateStoreHandle,
    secure_store: std::sync::Arc<dyn crate::secure_key_store::SecureKeyStore + Send + Sync>,
    authority: arkret_sdk::AccountId,
    device_id: arkret_sdk::DeviceId,
    /// A receiver keeps a seen-counter set per
    /// `(key_ref, epoch, device_id, purpose, aead_profile)`. It is shared
    /// across every envelope this engine opens, and bounded by the SDK.
    replay: Mutex<arkret_sdk::AeadNonceReplayTracker>,
}

impl MlsSignalDecryptor {
    pub fn new(
        state_store: crate::runtime::input::StateStoreHandle,
        authority: arkret_sdk::AccountId,
        device_id: arkret_sdk::DeviceId,
    ) -> Self {
        Self {
            state_store,
            secure_store: crate::secure_key_store::default_secure_key_store("inkson"),
            authority,
            device_id,
            replay: Mutex::new(arkret_sdk::AeadNonceReplayTracker::new()),
        }
    }
}

impl garth::signal::SignalDecryptor for MlsSignalDecryptor {
    async fn decrypt(&self, envelope: &arkret_wire::SignalEnvelope) -> garth::Result<Vec<u8>> {
        if let Some(device_id) = &envelope.sender_device_id
            && crate::identity::device_directory::known_device_revoked(
                &envelope.sender_actor_id.to_string(),
                device_id.as_str(),
            )
        {
            return Err(garth::Error::Protocol(
                "Signal sender device is locally known to be revoked".to_owned(),
            ));
        }
        // The MLS exporter only evaluates the group's current epoch, so the
        // shared restore helper's epoch gate drops a Signal naming any other
        // epoch rather than routing around it. No decryption queue, no
        // downgrade, no backfill.
        let session = self
            .state_store
            .read(|store| {
                crate::signal::restore_signal_mls_session(
                    store,
                    self.secure_store.as_ref(),
                    &envelope.scope_ref,
                    &self.authority,
                    &self.device_id,
                    envelope.encrypted_payload.epoch,
                )
            })
            .map_err(|error| garth::Error::Protocol(error.to_string()))?;
        let group = session.group;
        let mut replay = self.replay.lock().map_err(|error| {
            garth::Error::Protocol(format!("signal replay tracker poisoned: {error}"))
        })?;
        group
            .open_signal_envelope(envelope, session.content_scheme, &mut replay)
            .map_err(|error| garth::Error::Protocol(error.to_string()))
    }
}

/// One live TTL body retained under its projection key.
#[derive(Clone, Debug)]
struct LiveSignalBody {
    payload_sequence: u64,
    expires_at: DateTime<Utc>,
    body: Value,
}

/// The bounded in-memory presence / typing projection the chat views read.
///
/// The rail allows loss, duplication and reordering, so the per-key sequence
/// guard is what keeps a reordered older presence from overwriting a newer one.
/// Everything here is memory-only: presence is a TTL projection, not durable
/// state, and it is a host concept with no wire form.
#[derive(Clone, Debug, Default)]
pub struct LiveSignalProjection {
    bodies: BTreeMap<String, LiveSignalBody>,
}

impl LiveSignalProjection {
    pub fn new() -> Self {
        Self::default()
    }

    /// Drop every body at or past its effective expiry. Returns `true` when
    /// the stored set changed.
    pub fn expire(&mut self, now: DateTime<Utc>) -> bool {
        let before = self.bodies.len();
        self.bodies.retain(|_, live| live.expires_at > now);
        self.bodies.len() != before
    }

    /// Fold one already-serialized body in under its own projection key.
    /// Returns `true` when the stored set changed and the host projection must
    /// be rewritten.
    pub fn apply(
        &mut self,
        key: String,
        payload_sequence: u64,
        expires_at: DateTime<Utc>,
        body: Value,
        now: DateTime<Utc>,
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
            LiveSignalBody {
                payload_sequence,
                expires_at,
                body,
            },
        );
        changed = true;
        while self.bodies.len() > MAX_LIVE_SIGNAL_BODIES {
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

    /// Fold one admitted Signal in, deriving its projection key from the
    /// verified sender domain and the typed profile.
    ///
    /// An Agent sender is keyed by the public key it signed with, so a key
    /// rotation would otherwise leave the retired key's body live until its TTL
    /// passed. The newest key is the only active endpoint for that Agent, so
    /// earlier ones are collapsed first.
    pub fn apply_admitted(
        &mut self,
        signal: &AdmittedSignal,
        body: Value,
        now: DateTime<Utc>,
    ) -> garth::Result<bool> {
        let key = live_signal_projection_key(signal)?;
        if matches!(
            signal.sender_endpoint(),
            arkret_sdk::SignalSequenceEndpoint::AgentKey { .. }
        ) {
            let prefix = format!("{}|{}|", signal.kind().as_str(), signal.actor_id());
            self.bodies
                .retain(|existing, _| !existing.starts_with(&prefix) || existing == &key);
        }
        Ok(self.apply(key, signal.payload_sequence(), signal.expires_at, body, now))
    }

    /// The retained bodies, in projection-key order.
    pub fn bodies(&self) -> Vec<Value> {
        self.bodies.values().map(|live| live.body.clone()).collect()
    }

    pub fn len(&self) -> usize {
        self.bodies.len()
    }

    pub fn is_empty(&self) -> bool {
        self.bodies.is_empty()
    }
}

/// The `(kind, actor, sender endpoint, target)` coordinates one live body is
/// stored under. Only the two TTL profiles have a live projection; any other
/// admitted kind is a caller error rather than a silently dropped body.
pub fn live_signal_projection_key(signal: &AdmittedSignal) -> garth::Result<String> {
    let target = match &signal.payload {
        arkret_sdk::SignalPlaintext::Presence(_) => String::new(),
        arkret_sdk::SignalPlaintext::Typing(typing) => typing.strand_id.to_string(),
        _ => {
            return Err(garth::Error::Protocol(
                "only presence and typing have a live projection key".to_owned(),
            ));
        }
    };
    let endpoint = match signal.sender_endpoint() {
        arkret_sdk::SignalSequenceEndpoint::AccountDevice { device_id } => {
            device_id.as_str().to_owned()
        }
        arkret_sdk::SignalSequenceEndpoint::AgentKey { public_key_digest } => {
            public_key_digest.as_str().to_owned()
        }
    };
    Ok(format!(
        "{}|{}|{}|{}",
        signal.kind().as_str(),
        signal.actor_id(),
        endpoint,
        target
    ))
}

/// Routes admitted plaintext to the three product consumers.
struct InksonSignalSink {
    state_store: crate::runtime::input::StateStoreHandle,
    products: SignalProductRouter,
    live: Mutex<LiveSignalProjection>,
}

impl SignalSink for InksonSignalSink {
    /// One receiver decision.
    ///
    /// Stale and expired outcomes are not failures: the rail allows loss,
    /// duplication and reordering, so the receiver's sequence high-water and
    /// TTL gate discarding an envelope is the ordinary path. Only an admitted
    /// plaintext reaches a product consumer.
    async fn handle(&self, outcome: SignalReceiveOutcome) -> garth::Result<()> {
        let SignalReceiveOutcome::Accepted {
            domain,
            plaintext,
            effective_expires_at,
        } = outcome
        else {
            return Ok(());
        };
        let signal = AdmittedSignal {
            expires_at: effective_expires_at,
            domain: *domain,
            payload: plaintext,
        };
        match signal.kind() {
            arkret_sdk::SignalPlaintextKind::CallSignal => {
                // The decrypted body verbatim: `CallSignalPlaintext` is a
                // closed `deny_unknown_fields` shape, so the
                // envelope-derived fields the presence projection wants
                // would make every call signal fail to decode.
                self.products
                    .call_signal(&signal, decrypted_body_value(&signal)?)
                    .await;
            }
            arkret_sdk::SignalPlaintextKind::MessageStream => {
                self.products.message_stream(&signal).await;
            }
            arkret_sdk::SignalPlaintextKind::Presence | arkret_sdk::SignalPlaintextKind::Typing => {
                self.apply_live_body(&signal)?;
            }
            arkret_sdk::SignalPlaintextKind::ReadReceipt => {
                // Not a live body: presence and typing are TTL projections
                // that must disappear, whereas a read position stays true
                // after the receipt that carried it expires
                // (`read-receipts.md` §1.1).
                //
                // The Realm policy travels with it because §2.5 puts the
                // `disabled` / `private` discard on the receiving client:
                // the receipt is inside the ciphertext, so the Station
                // could not have filtered it.
                let policy = self.realm_read_receipt_policy(&signal);
                self.products.read_receipt(&signal, &policy);
            }
        }
        Ok(())
    }
}

const SIGNAL_PLAINTEXT_KIND_TYPING: &str = "ak.typing";
const SIGNAL_PLAINTEXT_KIND_READ_RECEIPT: &str = "ak.receipt.read";

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

    /// The Realm's accepted `ak.realm.read_receipt_policy`, as last projected
    /// from the Seal view.
    ///
    /// A Realm with no projected snapshot resolves to the spec default
    /// (`disclosure=optional`, `visibility=members`), which is what
    /// `read-receipts.md` §2.5 says an undeclared policy means.
    fn realm_read_receipt_policy(&self, signal: &AdmittedSignal) -> arkret_sdk::ReadReceiptPolicy {
        let realm_id = signal.scope_ref().realm_id().as_str().to_owned();
        let snapshot = self
            .state_store
            .read(|store| store.read_receipt_policy_for_realm(&realm_id));
        let mut policy = arkret_sdk::ReadReceiptPolicy::default();
        let Some(snapshot) = snapshot else {
            return policy;
        };
        // An unrecognized wire value is NOT silently treated as the default:
        // a value this build cannot parse is one whose privacy meaning it does
        // not know, so it falls closed to the strictest reading.
        policy.disclosure = match snapshot.disclosure.as_str() {
            "optional" => arkret_sdk::ReadReceiptDisclosure::Optional,
            "required" => arkret_sdk::ReadReceiptDisclosure::Required,
            _ => arkret_sdk::ReadReceiptDisclosure::Disabled,
        };
        policy.visibility = match snapshot.visibility.as_deref() {
            Some("public") => arkret_sdk::ReadReceiptVisibility::Public,
            Some("members") | None => arkret_sdk::ReadReceiptVisibility::Members,
            _ => arkret_sdk::ReadReceiptVisibility::Private,
        };
        policy
    }

    fn apply_live_body(&self, signal: &AdmittedSignal) -> garth::Result<()> {
        let body = live_body_value(signal)?;
        let now = crate::clock::now_utc();
        let Ok(mut live) = self.live.lock() else {
            return Ok(());
        };
        if !live.apply_admitted(signal, body, now)? {
            return Ok(());
        }
        let bodies = live.bodies();
        drop(live);
        self.state_store
            .write(|store| store.save_presence_projection(&bodies));
        Ok(())
    }
}

/// Serialize the already-admitted SDK profile for product adapters that still
/// consume JSON. Dispatch remains on the typed union; no raw body is retained.
fn decrypted_body_value(signal: &AdmittedSignal) -> garth::Result<Value> {
    let body = match &signal.payload {
        arkret_models_collaboration::signal_plaintext::SignalPlaintext::Presence(payload) => {
            serde_json::to_value(payload)
        }
        arkret_models_collaboration::signal_plaintext::SignalPlaintext::Typing(payload) => {
            serde_json::to_value(payload)
        }
        arkret_models_collaboration::signal_plaintext::SignalPlaintext::ReadReceipt(payload) => {
            serde_json::to_value(payload)
        }
        arkret_models_collaboration::signal_plaintext::SignalPlaintext::CallSignal(payload) => {
            serde_json::to_value(payload)
        }
        arkret_models_collaboration::signal_plaintext::SignalPlaintext::MessageStream(payload) => {
            serde_json::to_value(payload)
        }
    };
    body.map_err(|error| {
        garth::Error::Protocol(format!("serialize admitted Signal plaintext: {error}"))
    })
}

/// The decrypted body plus the envelope-derived fields the chat projections
/// read. `expires_at` is garth's effective expiry — the earlier of the outer
/// `expires_at` and the plaintext `ttl_ms` — so a consumer never has to
/// recombine the two TTLs itself.
///
/// Only for payload profiles whose consumer accepts an open object. A closed
/// `deny_unknown_fields` plaintext (call signalling) must get
/// [`decrypted_body_value`] instead.
fn live_body_value(signal: &AdmittedSignal) -> garth::Result<Value> {
    let Value::Object(mut body) = decrypted_body_value(signal)? else {
        return Err(garth::Error::Protocol(
            "admitted Signal plaintext must serialize as an object".to_owned(),
        ));
    };
    body.insert(
        "actor_id".to_owned(),
        serde_json::to_value(signal.actor_id()).map_err(|error| {
            garth::Error::Protocol(format!("serialize Signal ActorId: {error}"))
        })?,
    );
    match signal.sender_endpoint() {
        arkret_sdk::SignalSequenceEndpoint::AccountDevice { device_id } => {
            body.insert(
                "device_id".to_owned(),
                Value::String(device_id.as_str().to_owned()),
            );
        }
        arkret_sdk::SignalSequenceEndpoint::AgentKey { public_key_digest } => {
            body.insert(
                "agent_public_key_digest".to_owned(),
                Value::String(public_key_digest.as_str().to_owned()),
            );
        }
    }
    // No `sent_at`: the admitted outcome carries the receiver-computed
    // effective expiry (the earlier of the envelope expiry and
    // `sent_at + ttl_ms`) and never the sender's own instant, so a `sent_at`
    // here could only be guessed back out of a TTL that may not be the binding
    // constraint. Consumers that need "which of this actor's live bodies is the
    // newest" order by `expires_at`, which is the same order for a fixed TTL
    // profile and is comparable across endpoints.
    body.insert(
        "expires_at".to_owned(),
        Value::String(arkret_sdk::canonical::format_timestamp_canonical(
            signal.expires_at,
        )),
    );
    Ok(Value::Object(body))
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
    let resolver = DirectorySenderKeyResolver {
        state_store: Some(ctx.state_store.clone()),
        account: Some(ctx.account.clone()),
    };
    let decryptor = MlsSignalDecryptor::new(
        ctx.state_store.clone(),
        ctx.account.authority.clone(),
        ctx.account.device_id.clone(),
    );
    let sink = InksonSignalSink {
        state_store: ctx.state_store.clone(),
        products: ctx.products.clone(),
        live: Mutex::new(LiveSignalProjection::new()),
    };
    let mut restart_backoff = RetrySchedule::new(BACKOFF_FLOOR, BACKOFF_CEILING);
    while provider.is_active() {
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
                    // The per-instance jitter seed is the SDK's; this loop has
                    // no reason to vary it and must not silently pin it to 0.
                    ..RunOptions::default()
                },
            )
            .await;
        let Some(retry_delay) = crate::runtime_helpers::next_reconnect_delay(
            provider.is_active(),
            &mut restart_backoff,
        ) else {
            break;
        };
        match result {
            Ok(reason) => tracing::warn!(
                reason = ?reason,
                retry_delay_ms = retry_delay.as_millis(),
                "signal receive runner stopped while still active; reconnecting"
            ),
            Err(error) => tracing::warn!(
                error = %error,
                retry_delay_ms = retry_delay.as_millis(),
                "signal receive runner stopped with error; reconnecting"
            ),
        }
        crate::runtime_helpers::sleep_for(retry_delay).await;
    }
}

struct SignalTransportProvider {
    ctx: SignalReceiveEngineContext,
    generation: crate::runtime::input::ValueReader<u64>,
    start_generation: u64,
    start_profile_id: Option<String>,
}

impl TransportProvider for SignalTransportProvider {
    type Transport = crate::transport::websocket_rail::StreamRail<arkret_sdk::http_client::Client>;

    /// §6.2 — the Signal channel has no cursor, no catch-up and no receipt on
    /// either transport, so choosing between them is purely a transport
    /// decision and needs no state to carry across.
    async fn provide(&self) -> garth::Result<Self::Transport> {
        let http = crate::identity::session_refresh::provide_authenticated_sdk_client(
            self.ctx.account.server_url.as_str(),
        )
        .await
        .map_err(|error| garth::Error::Protocol(error.to_string()))?;
        Ok(crate::transport::websocket_rail::StreamRail::select(
            &self.ctx.websocket_rail,
            http,
        ))
    }

    async fn recover_unauthorized(&self) -> garth::Result<bool> {
        crate::identity::session_refresh::refresh_authenticated_session_after_unauthorized(
            self.ctx.account.server_url.as_str(),
        )
        .await
        .map(|_| true)
        .map_err(|error| garth::Error::Http(error.to_string()))
    }

    fn is_active(&self) -> bool {
        self.generation.get() == self.start_generation
            && self.ctx.profiles.get().active_profile_id == self.start_profile_id
            && !self.ctx.effect.is_cancelled()
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
        let Value::Object(mut body) = body else {
            unreachable!("test body must be an object");
        };
        // The registered closed profile the receiver dispatches on. The tests
        // below assert how each route reshapes the typed profile, so admission
        // parses the same object rather than keeping a parallel raw body.
        body.entry("payload_sequence").or_insert(json!(7));
        if kind == garth::SIGNAL_PLAINTEXT_KIND_PRESENCE {
            body.entry("actor_id").or_insert(json!({
                "kind": "account",
                "account_id": {
                    "principal_id": "ak:did_core:web:alice.example",
                    "station_id": "ak:did_core:web:principal.example"
                }
            }));
            body.entry("ttl_ms").or_insert(json!(30_000));
        }
        let payload_bytes = arkret_sdk::canonical::canonical_json_bytes(&Value::Object(body))
            .expect("test plaintext is canonicalizable");
        let payload = garth::open_signal_plaintext(&payload_bytes)
            .expect("test plaintext matches its registered closed profile");
        garth::SignalPlaintext {
            payload,
            kind: kind.to_owned(),
            actor_id: arkret_sdk::ActorId::account(arkret_sdk::AccountId::new(
                arkret_sdk::DidCoreId::new("ak:did_core:web:alice.example").unwrap(),
                arkret_sdk::DidCoreId::new("ak:did_core:web:principal.example").unwrap(),
            )),
            payload_sequence: 7,
            ttl_ms: Some(30_000),
            sent_at: at(0),
            expires_at: at(30),
            scope_ref: arkret_sdk::ScopeRef::Realm {
                realm_id: arkret_sdk::RealmId::new(
                    "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19",
                )
                .unwrap(),
            },
            seal_ref: arkret_sdk::SealId::new(format!("ak:seal:sha256:{}", "a".repeat(64)))
                .unwrap(),
            sender_endpoint: arkret_sdk::SignalSequenceEndpoint::AccountDevice {
                device_id: arkret_sdk::DeviceId::new(
                    "ak:device:01904100-0000-7000-8000-000000000002",
                )
                .unwrap(),
            },
        }
    }

    fn sender_resolution_envelope() -> arkret_wire::SignalEnvelope {
        let now = crate::clock::now_utc();
        let actor_id =
            crate::mls_api_helpers::local_account_actor_id("ak:did_core:web:alice.example")
                .unwrap();
        let sender_device_id =
            arkret_sdk::DeviceId::new("ak:device:01904100-0000-7000-8000-000000000002").unwrap();
        let mut envelope = arkret_wire::SignalEnvelope {
            realm_id: arkret_sdk::RealmId::new(
                "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19",
            )
            .unwrap(),
            scope_ref: arkret_sdk::ScopeRef::Realm {
                realm_id: arkret_sdk::RealmId::new(
                    "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19",
                )
                .unwrap(),
            },
            sender_actor_id: actor_id,
            sender_device_id: Some(sender_device_id.clone()),
            seal_ref: arkret_sdk::SealId::new(format!("ak:seal:sha256:{}", "a".repeat(64)))
                .unwrap(),
            signal_class: arkret_wire::SignalClass::Session,
            sent_at: now,
            expires_at: now + chrono::Duration::seconds(30),
            encrypted_payload: arkret_wire::SignalEncryptedPayload {
                scheme: arkret_wire::signal::SIGNAL_AEAD_SCHEME.to_owned(),
                key_ref: arkret_wire::SignalKeyRef {
                    algorithm: "MLS-EXPORTER-AEAD".to_owned(),
                    group_state_ref: "ak:event:AZVgkcivLIz2PjwUcjuT5bTb6295nnowDbSQak0QfNCa"
                        .to_owned(),
                },
                purpose: arkret_wire::signal::SIGNAL_AEAD_PURPOSE.to_owned(),
                aead_profile: "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519".to_owned(),
                epoch: 4,
                nonce: "AAAAAAAAAAAAAAAA".to_owned(),
                ciphertext: "AAAAAAAAAAAAAAAAAAAAAA".to_owned(),
                aad_digest: arkret_sdk::Hash::new(format!("sha256:{}", "0".repeat(64))).unwrap(),
            },
            proof: arkret_wire::SignalProof {
                kind: arkret_sdk::proof_kind::DETACHED_JWS.to_owned(),
                verification_method: arkret_sdk::DidUrl::new(format!(
                    "did:web:alice.example#{sender_device_id}"
                ))
                .unwrap(),
                envelope_digest: arkret_sdk::Hash::new(format!("sha256:{}", "0".repeat(64)))
                    .unwrap(),
                domain: None,
                audience: None,
                jws: String::new(),
            },
        };
        envelope.encrypted_payload.aad_digest = envelope.expected_aad_digest().unwrap();
        envelope.proof.envelope_digest = envelope.envelope_digest().unwrap();
        envelope.proof.jws = arkret_sdk::signatures::sign_ed25519_detached_jws(
            &ed25519_dalek::SigningKey::from_bytes(&[19; 32]),
            &envelope.proof_binding_bytes().unwrap(),
        )
        .unwrap();
        envelope.validate_wire_shape().unwrap();
        arkret_sdk::signatures::verify_ed25519_signal_proof(&envelope, &sender_resolution_key())
            .unwrap();
        envelope
    }

    fn sender_resolution_key() -> arkret_sdk::signatures::PublicKeyMaterial {
        arkret_sdk::signatures::PublicKeyMaterial::Ed25519Raw {
            bytes: ed25519_dalek::SigningKey::from_bytes(&[19; 32])
                .verifying_key()
                .to_bytes()
                .to_vec(),
        }
    }

    #[tokio::test]
    async fn cached_device_key_cannot_authorize_signal_without_an_authenticated_delivery() {
        use garth::SignalSenderKeyResolver as _;
        let envelope = sender_resolution_envelope();
        let actor = envelope.sender_actor_id.signing_principal_id().as_str();
        let device = envelope.sender_device_id.as_ref().unwrap().as_str();
        let key = sender_resolution_key();
        crate::identity::device_directory::seed_positive_for_test(actor, device, key);
        let delivery_authority = arkret_wire::SignalDeliveryAuthority {
            recipient_account_id: envelope.sender_actor_id.as_account_id().unwrap().clone(),
            key: arkret_wire::StationSigningKey {
                actor: envelope.sender_actor_id.clone(),
                verification_method: envelope.proof.verification_method.clone(),
                public_key_b64u: arkret_wire::Base64UrlString::new(arkret_sdk::base64url_encode(
                    ed25519_dalek::SigningKey::from_bytes(&[19; 32])
                        .verifying_key()
                        .to_bytes(),
                ))
                .unwrap(),
                authorization_ref: arkret_wire::EventId::from_digest(
                    arkret_sdk::DigestSuite::Sha256,
                    [0x42; 32],
                ),
            },
        };
        delivery_authority.validate_for_envelope(&envelope).unwrap();
        assert!(
            DirectorySenderKeyResolver::default()
                .resolve_sender_key(&envelope, &delivery_authority)
                .await
                .is_none()
        );
        crate::identity::device_directory::invalidate_actor(actor);
    }

    /// `CallSignalPlaintext` is `deny_unknown_fields`, so the call route MUST
    /// hand the router the decrypted body verbatim. Merging the envelope-derived
    /// fields the presence projection wants would make every inbound call
    /// signal fail to decode — silently, because a signal that cannot be
    /// decoded is simply dropped.
    #[test]
    fn the_call_route_body_still_parses_as_the_closed_call_plaintext() {
        let call_plaintext = arkret_sdk::CallSignalPlaintext::new(
            7,
            arkret_sdk::CallId::new(
                "ak:call:ASJkvorx6tEzdxoAC5naL70uFcivCk9bMINhB1IWdS80".to_owned(),
            )
            .unwrap(),
            7,
            arkret_sdk::CallSignalData::Invite(arkret_sdk::CallInviteSignalData {
                lifetime_ms: 30_000,
                offer: arkret_sdk::SessionDescription {
                    sdp_type: arkret_sdk::SessionDescriptionType::Offer,
                    sdp: "v=0".to_owned(),
                },
                media: arkret_sdk::CallMediaSelection {
                    audio: true,
                    video: true,
                    screen: None,
                },
            }),
        )
        .unwrap();
        let plaintext = plaintext_of(
            garth::SIGNAL_PLAINTEXT_KIND_CALL,
            serde_json::to_value(call_plaintext).unwrap(),
        );

        let body = decrypted_body_value(&plaintext).unwrap();
        serde_json::from_value::<arkret_sdk::CallSignalPlaintext>(body)
            .expect("the call route must not add fields to the closed plaintext");

        assert!(
            serde_json::from_value::<arkret_sdk::CallSignalPlaintext>(
                live_body_value(&plaintext).unwrap()
            )
            .is_err(),
            "the presence-shaped body is deliberately not the call shape"
        );
    }

    #[test]
    fn the_live_presence_projection_preserves_actor_identity_and_expiry() {
        let plaintext = plaintext_of(
            garth::SIGNAL_PLAINTEXT_KIND_PRESENCE,
            json!({"kind": "ak.presence", "state": "online"}),
        );

        let body = live_body_value(&plaintext).unwrap();
        assert_eq!(
            serde_json::from_value::<arkret_sdk::ActorId>(body["actor_id"].clone()).unwrap(),
            plaintext.actor_id,
        );
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
}
