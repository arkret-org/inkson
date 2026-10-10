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
use garth::RetrySchedule;
use garth::signal::{
    SignalFrameSource, SignalReceiveOutcome, SignalReceiver, SignalStreamStopReason,
};
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
    pub websocket_rail: crate::transport::websocket_rail::WebSocketRail,
    pub token: crate::runtime::input::ValueReader<String>,
    pub state_store: crate::runtime::input::StateStoreHandle,
    pub account: crate::config::ActiveAccountContext,
    /// Active multi-profile snapshot — the engine exits when the active profile
    /// rotates, mirroring the other two engines.
    pub profiles: crate::runtime::input::ValueReader<MultiProfileConfig>,
    pub effect: crate::runtime::effects::EffectHandle,
    pub products: SignalProductRouter,
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
        let accepted_group_state_ref = self
            .state_store
            .read(|store| {
                store.mls_group_state_ref_for_scope(
                    &envelope.scope_ref,
                    &group.group_id(),
                    group.epoch(),
                )
            })
            .map_err(garth::Error::Protocol)?;
        if envelope.encrypted_payload.key_ref.group_state_ref != accepted_group_state_ref.as_str() {
            return Err(garth::Error::Protocol(
                "Signal does not bind the accepted winning MLS group state".to_owned(),
            ));
        }
        let mut matching_leaves = group
            .verified_leaf_bindings()
            .map_err(|error| garth::Error::Protocol(error.to_string()))?
            .into_iter()
            .filter(|leaf| {
                leaf.actor_id == envelope.sender_actor_id
                    && match (&leaf.endpoint, envelope.sender_device_id.as_ref()) {
                        (
                            arkret_sdk::MlsEndpointIdentity::HumanDevice { device_id, .. },
                            Some(sender_device_id),
                        ) => device_id == sender_device_id,
                        (arkret_sdk::MlsEndpointIdentity::AgentRuntime { .. }, None) => true,
                        _ => false,
                    }
            });
        let leaf = matching_leaves.next().ok_or_else(|| {
            garth::Error::Protocol(
                "Signal sender does not resolve to an active MLS leaf".to_owned(),
            )
        })?;
        if matching_leaves.next().is_some() {
            return Err(garth::Error::Protocol(
                "Signal sender resolves to multiple active MLS leaves".to_owned(),
            ));
        }
        let public_key = arkret_sdk::signatures::PublicKeyMaterial::Ed25519Raw {
            bytes: arkret_sdk::base64url_decode(leaf.signature_key.as_str())
                .map_err(|error| garth::Error::Protocol(error.to_string()))?,
        };
        let sender_authority = match &leaf.endpoint {
            arkret_sdk::MlsEndpointIdentity::HumanDevice { .. } => {
                let device_authorize_event_id =
                    leaf.device_authorize_event_id.as_ref().ok_or_else(|| {
                        garth::Error::Protocol(
                            "Signal sender MLS leaf has no device authorization transition"
                                .to_owned(),
                        )
                    })?;
                arkret_sdk::mls::SignalSenderAuthority::AccountDevice {
                    public_key: &public_key,
                    device_authorize_event_id,
                }
            }
            arkret_sdk::MlsEndpointIdentity::AgentRuntime {
                verification_method,
                agent_key_authorize_event_id,
                ..
            } => arkret_sdk::mls::SignalSenderAuthority::Agent {
                public_key: &public_key,
                verification_method,
                agent_key_authorize_event_id,
            },
            arkret_sdk::MlsEndpointIdentity::MinimalMetadataPairwise { .. } => {
                return Err(garth::Error::Protocol(
                    "minimal-metadata MLS leaves cannot send Signal envelopes".to_owned(),
                ));
            }
        };
        let mut replay = self.replay.lock().map_err(|error| {
            garth::Error::Protocol(format!("signal replay tracker poisoned: {error}"))
        })?;
        // `SignalReceiver` has already checked this frame's exact Station
        // delivery authority and producer proof. Verify the same proof under
        // the active MLS leaf key as well, then rebuild AAD from the immutable
        // envelope header. The governing Station fresh-gated authority_commit_id
        // for this exact delivery; signal.md forbids replaying governance
        // history locally per frame, so that authenticated value is the
        // accepted head passed into the MLS opener.
        group
            .open_signal_envelope(
                envelope,
                sender_authority,
                accepted_group_state_ref.as_str(),
                &envelope.authority_commit_id,
                &mut replay,
            )
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
pub(crate) struct InksonSignalSink {
    pub(crate) state_store: crate::runtime::input::StateStoreHandle,
    pub(crate) products: SignalProductRouter,
    pub(crate) live: Mutex<LiveSignalProjection>,
}

impl InksonSignalSink {
    /// One receiver decision.
    ///
    /// Stale and expired outcomes are not failures: the rail allows loss,
    /// duplication and reordering, so the receiver's sequence high-water and
    /// TTL gate discarding an envelope is the ordinary path. Only an admitted
    /// plaintext reaches a product consumer.
    pub(crate) async fn handle(&self, outcome: SignalReceiveOutcome) -> garth::Result<()> {
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
                if !self.call_exists_at_verified_cut(&signal).await? {
                    return Ok(());
                }
                self.dispatch_call_product(&signal).await?;
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

fn call_current_attempt_matches(
    store: &crate::state::LocalStateStore,
    authority: &arkret_sdk::AccountId,
    generation: u64,
) -> bool {
    store.active_authority().as_ref() == Some(authority)
        && store.current_generation() == generation
        && !store.current_reset_required()
}

impl InksonSignalSink {
    async fn call_exists_at_verified_cut(&self, signal: &AdmittedSignal) -> garth::Result<bool> {
        let arkret_sdk::SignalPlaintext::CallSignal(call) = &signal.payload else {
            return Ok(false);
        };
        let (authority, reset, location) = self.state_store.read(|store| {
            (
                store.active_authority(),
                store.current_reset_required(),
                store.current_index_location(),
            )
        });
        let Some(authority) = authority else {
            return Ok(false);
        };
        if reset {
            return Ok(false);
        }
        let mut generation = 0;
        let index = crate::state::CurrentIndex::open_committed(&authority, location, || {
            generation = self.state_store.read(|store| store.current_generation());
            Ok(generation)
        })
        .await
        .map_err(|error| garth::Error::Protocol(format!("Call current is unavailable: {error}")))?;
        let current = index
            .read_call_state_ready(signal.scope_ref(), &call.call_id)
            .await
            .map_err(|error| {
                garth::Error::Protocol(format!("Call current is not ready: {error}"))
            })?;
        // A store await cannot carry the previous account's permission across
        // an account switch, current reset or a newly installed generation.
        let same_attempt = self
            .state_store
            .read(|store| call_current_attempt_matches(store, &authority, generation));
        Ok(current.is_some() && same_attempt)
    }

    /// The product boundary runs only after the accepted Call current gate.
    async fn dispatch_call_product(&self, signal: &AdmittedSignal) -> garth::Result<()> {
        if matches!(&signal.payload, arkret_sdk::SignalPlaintext::CallSignal(call)
            if matches!(&call.signal, arkret_sdk::CallSignalData::Invite(_)))
            && self.state_store.read(|store| {
                crate::account_data::blocks_call_invite(
                    &store.client_blocklist(),
                    signal.actor_id(),
                )
            })
        {
            return Ok(());
        }
        self.products
            .call_signal(signal, decrypted_body_value(signal)?)
            .await;
        Ok(())
    }

    /// Drop presence/typing bodies whose effective TTL has passed.
    ///
    /// A typing indicator lives five seconds and a presence signal thirty, so
    /// without a clock edge the last body from a peer who stopped typing would
    /// stay in the projection until that peer sent something else.
    fn expire_live_bodies(&self, now: chrono::DateTime<chrono::Utc>) {
        let Ok(mut live) = self.live.lock() else {
            return;
        };
        let changed = live.expire(now);
        let bodies = changed.then(|| live.bodies());
        drop(live);
        let cached = self
            .state_store
            .read(|store| store.load().presence_projection);
        // A restarted receiver has no in-memory keys for the prior projection.
        // Its admitted cached bodies still expire without a new network frame.
        let mut bodies = bodies.unwrap_or_else(|| cached.clone());
        bodies.retain(|body| {
            body.get("expires_at")
                .and_then(Value::as_str)
                .and_then(|value| DateTime::parse_from_rfc3339(value).ok())
                .is_some_and(|expiry| expiry > now)
        });
        if bodies != cached {
            self.state_store
                .write(|store| store.save_presence_projection(&bodies));
        }
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

/// Run the Signal receive rail until the generation is bumped, the active
/// profile rotates, or the session ends.
pub async fn run_signal_receive_engine(
    start_generation: u64,
    generation: crate::runtime::input::ValueReader<u64>,
    ctx: SignalReceiveEngineContext,
) {
    let start_profile_id = ctx.profiles.get().active_profile_id;
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
    let receive = run_signal_receive_loop(
        start_generation,
        &generation,
        &ctx,
        start_profile_id.as_deref(),
        &decryptor,
        &sink,
    );
    let clock = async {
        while signal_engine_is_active(
            &ctx,
            &generation,
            start_generation,
            start_profile_id.as_deref(),
        ) {
            let now = crate::clock::now_utc();
            sink.expire_live_bodies(now);
            sink.products.advance_clock(now);
            crate::runtime_helpers::sleep_for(Duration::from_secs(1)).await;
        }
    };
    futures_util::pin_mut!(receive, clock);
    // Keep the receive future intact while the local clock runs, including
    // blocked HTTP reads and reconnect backoff. Either lifecycle end cancels both.
    let _ = futures_util::future::select(receive, clock).await;
}

async fn run_signal_receive_loop(
    start_generation: u64,
    generation: &crate::runtime::input::ValueReader<u64>,
    ctx: &SignalReceiveEngineContext,
    start_profile_id: Option<&str>,
    decryptor: &MlsSignalDecryptor,
    sink: &InksonSignalSink,
) {
    let mut receiver = SignalReceiver::new();
    let mut jitter_seed = [0_u8; 8];
    let _ = getrandom::fill(&mut jitter_seed);
    let mut restart_backoff = RetrySchedule::new(BACKOFF_FLOOR, BACKOFF_CEILING)
        .with_jitter(0.2, u64::from_le_bytes(jitter_seed));
    while signal_engine_is_active(ctx, generation, start_generation, start_profile_id) {
        let mut healthy_progress = false;
        let result = run_signal_receive_attempt(
            ctx,
            generation,
            start_generation,
            start_profile_id,
            &mut receiver,
            decryptor,
            sink,
            &mut healthy_progress,
        )
        .await;
        if matches!(result, Ok(SignalStreamStopReason::Unauthorized { .. })) {
            match crate::identity::session_refresh::refresh_authenticated_session_after_unauthorized(
                ctx.account.server_url.as_str(),
            )
            .await
            {
                Ok(_) => {
                    tracing::info!("Signal subscription refreshed after unauthorized");
                    restart_backoff.reset();
                    continue;
                }
                Err(error) => tracing::warn!(
                    error = %error,
                    "Signal subscription could not refresh after unauthorized"
                ),
            }
        }
        if !signal_engine_is_active(ctx, generation, start_generation, start_profile_id) {
            break;
        }
        let retry_delay =
            signal_receive_restart_delay(&result, healthy_progress, &mut restart_backoff);
        match result {
            Ok(SignalStreamStopReason::ReconnectAfter { .. }) if healthy_progress => {
                tracing::info!(
                    retry_delay_ms = retry_delay.as_millis(),
                    "healthy Signal subscription window completed; reconnecting"
                )
            }
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

fn signal_receive_restart_delay(
    result: &garth::Result<SignalStreamStopReason>,
    healthy_progress: bool,
    backoff: &mut RetrySchedule,
) -> Duration {
    if healthy_progress {
        backoff.reset();
    }
    let hint = match result {
        Ok(SignalStreamStopReason::ReconnectAfter { reconnect_after_ms }) => {
            reconnect_after_ms.map(Duration::from_millis)
        }
        _ => None,
    };
    backoff.next_delay_with_hint(hint)
}

fn signal_engine_is_active(
    ctx: &SignalReceiveEngineContext,
    generation: &crate::runtime::input::ValueReader<u64>,
    start_generation: u64,
    start_profile_id: Option<&str>,
) -> bool {
    generation.get() == start_generation
        && ctx.profiles.get().active_profile_id.as_deref() == start_profile_id
        && !ctx.effect.is_cancelled()
        && !ctx.token.get().trim().is_empty()
}

async fn run_signal_receive_attempt(
    ctx: &SignalReceiveEngineContext,
    generation: &crate::runtime::input::ValueReader<u64>,
    start_generation: u64,
    start_profile_id: Option<&str>,
    receiver: &mut SignalReceiver,
    decryptor: &MlsSignalDecryptor,
    sink: &InksonSignalSink,
    healthy_progress: &mut bool,
) -> garth::Result<SignalStreamStopReason> {
    let client = crate::identity::session_refresh::provide_authenticated_sdk_client(
        ctx.account.server_url.as_str(),
    )
    .await
    .map_err(|error| garth::Error::Http(error.to_string()))?;
    let mut stream =
        crate::transport::websocket_rail::SignalRailSource::open(&client, &ctx.websocket_rail)
            .await?;
    let mut received_heartbeat = false;
    while signal_engine_is_active(ctx, generation, start_generation, start_profile_id) {
        let frame = loop {
            use futures_util::future::{Either, select};
            match select(
                Box::pin(stream.next_frame()),
                Box::pin(crate::runtime_helpers::sleep_for(Duration::from_millis(
                    250,
                ))),
            )
            .await
            {
                Either::Left((frame, _)) => break frame?,
                Either::Right(_)
                    if !signal_engine_is_active(
                        ctx,
                        generation,
                        start_generation,
                        start_profile_id,
                    ) =>
                {
                    return Ok(SignalStreamStopReason::Ended);
                }
                Either::Right(_) => {}
            }
        };
        let Some(frame) = frame else {
            return Ok(SignalStreamStopReason::Ended);
        };
        match frame {
            arkret_wire::SignalStreamFrame::Signal {
                envelope,
                delivery_authority,
            } => {
                let outcome = receiver
                    .receive(
                        &envelope,
                        &delivery_authority,
                        decryptor,
                        crate::clock::now_utc(),
                    )
                    .await?;
                sink.handle(outcome).await?;
                *healthy_progress = true;
            }
            arkret_wire::SignalStreamFrame::Heartbeat => {
                // The initial heartbeat alone must not reset a rapid failure
                // loop. A later heartbeat proves a sustained live window.
                if received_heartbeat {
                    *healthy_progress = true;
                }
                received_heartbeat = true;
                let now = crate::clock::now_utc();
                sink.expire_live_bodies(now);
                sink.products.advance_clock(now);
            }
            arkret_wire::SignalStreamFrame::Drain {
                reconnect_after_ms, ..
            } => {
                return Ok(SignalStreamStopReason::ReconnectAfter { reconnect_after_ms });
            }
            arkret_wire::SignalStreamFrame::Unauthorized { reason } => {
                return Ok(SignalStreamStopReason::Unauthorized { reason });
            }
        }
    }
    Ok(SignalStreamStopReason::Ended)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn healthy_signal_windows_do_not_accumulate_failure_backoff() {
        let drain = Ok(SignalStreamStopReason::ReconnectAfter {
            reconnect_after_ms: Some(250),
        });
        let mut backoff = RetrySchedule::new(Duration::from_secs(1), Duration::from_secs(60));
        for _ in 0..12 {
            assert_eq!(
                signal_receive_restart_delay(&drain, true, &mut backoff),
                Duration::from_secs(1)
            );
        }
        for seconds in [2, 4, 8] {
            assert_eq!(
                signal_receive_restart_delay(&drain, false, &mut backoff),
                Duration::from_secs(seconds)
            );
        }
        let failure = Err(garth::Error::Http("fixture disconnect".into()));
        assert_eq!(
            signal_receive_restart_delay(&failure, false, &mut backoff),
            Duration::from_secs(16)
        );
        assert_eq!(
            signal_receive_restart_delay(&drain, true, &mut backoff),
            Duration::from_secs(1)
        );
        let server_hint = Ok(SignalStreamStopReason::ReconnectAfter {
            reconnect_after_ms: Some(5_000),
        });
        assert_eq!(
            signal_receive_restart_delay(&server_hint, true, &mut backoff),
            Duration::from_secs(5)
        );
    }

    fn at(seconds: i64) -> chrono::DateTime<chrono::Utc> {
        chrono::DateTime::from_timestamp(1_800_000_000 + seconds, 0).unwrap()
    }

    #[test]
    fn restarted_projection_expires_without_a_transport_heartbeat() {
        use std::sync::Arc;

        let directory = tempfile::tempdir().unwrap();
        let store = Arc::new(Mutex::new(crate::LocalStateStore::with_path(
            directory.path().join("presence-clock.json"),
        )));
        let expired = json!({"kind": "ak.presence", "state": "online", "expires_at": at(30)});
        let live = json!({"kind": "ak.presence", "state": "idle", "expires_at": at(45)});
        store
            .lock()
            .unwrap()
            .save_presence_projection(&[expired.clone(), live.clone()]);
        let read = store.clone();
        let write = store.clone();
        let sink = InksonSignalSink {
            state_store: crate::runtime::input::StateStoreHandle::new(
                move |consume| consume(&read.lock().unwrap()),
                move |consume| consume(&mut write.lock().unwrap()),
            ),
            products: SignalProductRouter::default(),
            live: Mutex::new(Default::default()),
        };
        sink.expire_live_bodies(at(29));
        assert_eq!(
            store.lock().unwrap().load().presence_projection,
            [expired, live.clone()]
        );
        sink.expire_live_bodies(at(30));
        assert_eq!(store.lock().unwrap().load().presence_projection, [live]);
        sink.expire_live_bodies(at(45));
        assert!(store.lock().unwrap().load().presence_projection.is_empty());
    }

    fn plaintext_of(kind: &str, body: Value) -> AdmittedSignal {
        let Value::Object(mut body) = body else {
            unreachable!("test body must be an object");
        };
        // The registered closed profile the receiver dispatches on. The tests
        // below assert how each route reshapes the typed profile, so admission
        // parses the same object rather than keeping a parallel raw body.
        body.entry("payload_sequence").or_insert(json!(7));
        if kind == arkret_sdk::SignalPlaintextKind::Presence.as_str() {
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
        assert_eq!(payload.kind().as_str(), kind);
        AdmittedSignal {
            expires_at: at(30),
            domain: arkret_sdk::SignalSequenceDomain {
                sender_actor_id: arkret_sdk::ActorId::account(arkret_sdk::AccountId::new(
                    arkret_sdk::DidCoreId::new("ak:did_core:web:alice.example").unwrap(),
                    arkret_sdk::DidCoreId::new("ak:did_core:web:principal.example").unwrap(),
                )),
                endpoint: arkret_sdk::SignalSequenceEndpoint::AccountDevice {
                    device_id: arkret_sdk::DeviceId::new(
                        "ak:device:01904100-0000-7000-8000-000000000002",
                    )
                    .unwrap(),
                },
                scope_ref: arkret_sdk::ScopeRef::Realm {
                    realm_id: arkret_sdk::RealmId::new(
                        "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19",
                    )
                    .unwrap(),
                },
            },
            payload,
        }
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn blocklist_call_current_await_cannot_survive_account_reset_or_generation_change() {
        let directory = tempfile::tempdir().unwrap();
        let mut store =
            crate::LocalStateStore::with_path(directory.path().join("call-attempt.json"));
        store.promote_accepted_context_for_test(
            &arkret_sdk::Did::new("did:web:alice.example").unwrap(),
        );
        let authority = store.active_authority().unwrap();
        store.set_current_generation(7);
        assert!(call_current_attempt_matches(&store, &authority, 7));
        store.set_current_generation(8);
        assert!(!call_current_attempt_matches(&store, &authority, 7));
        store.set_current_generation(7);
        store.set_current_reset_required(true);
        assert!(!call_current_attempt_matches(&store, &authority, 7));
        store.set_current_reset_required(false);
        assert!(call_current_attempt_matches(&store, &authority, 7));
        store.promote_accepted_context_for_test(
            &arkret_sdk::Did::new("did:web:bob.example").unwrap(),
        );
        store.set_current_generation(7);
        assert!(!call_current_attempt_matches(&store, &authority, 7));
    }

    // These are product-layer regression checks. The already-admitted profile
    // fixture does not claim transport, producer proof or accepted CallCreate.
    #[cfg(not(target_arch = "wasm32"))]
    #[tokio::test]
    async fn blocklist_call_invite_product_tracks_private_revision_and_exact_actor() {
        use std::sync::Arc;
        async fn observe_private_product(
            state_store: crate::runtime::input::StateStoreHandle,
            outcome: SignalReceiveOutcome,
        ) -> anyhow::Result<usize> {
            use std::cell::Cell;
            use std::rc::Rc;
            struct Calls(Cell<usize>);
            impl SignalProductSink for Calls {
                fn call_signal<'a>(
                    &'a self,
                    _: &'a AdmittedSignal,
                    _: Value,
                ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + 'a>> {
                    self.0.set(self.0.get() + 1);
                    Box::pin(async {})
                }
                fn message_stream<'a>(
                    &'a self,
                    _: &'a AdmittedSignal,
                ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + 'a>> {
                    Box::pin(async {})
                }
                fn read_receipt(&self, _: &AdmittedSignal, _: &arkret_sdk::ReadReceiptPolicy) {}
                fn advance_clock(&self, _: DateTime<Utc>) {}
            }
            let calls = Rc::new(Calls(Cell::new(0)));
            let products = SignalProductRouter::default();
            products.install(calls.clone());
            let sink = InksonSignalSink {
                state_store,
                products,
                live: Mutex::new(Default::default()),
            };
            let SignalReceiveOutcome::Accepted {
                domain,
                plaintext,
                effective_expires_at,
            } = outcome
            else {
                return Ok(0);
            };
            let signal = AdmittedSignal {
                domain: *domain,
                payload: plaintext,
                expires_at: effective_expires_at,
            };
            // This test isolates the actual private product boundary. Unknown
            // accepted Call current is independently refused by the full sink.
            assert!(!sink.call_exists_at_verified_cut(&signal).await?);
            sink.dispatch_call_product(&signal).await?;
            Ok(calls.0.get())
        }
        let directory = tempfile::tempdir().unwrap();
        let store = Arc::new(Mutex::new(crate::LocalStateStore::with_path(
            directory.path().join("call-product.json"),
        )));
        let read = store.clone();
        let write = store.clone();
        let handle = crate::runtime::input::StateStoreHandle::new(
            move |consume| consume(&read.lock().unwrap()),
            move |consume| consume(&mut write.lock().unwrap()),
        );
        let call = arkret_sdk::CallSignalPlaintext::new(
            7,
            arkret_sdk::CallId::new("ak:call:ASJkvorx6tEzdxoAC5naL70uFcivCk9bMINhB1IWdS80")
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
                    video: false,
                    screen: None,
                },
            }),
        )
        .unwrap();
        let admitted = plaintext_of(
            arkret_sdk::SignalPlaintextKind::CallSignal.as_str(),
            serde_json::to_value(call).unwrap(),
        );
        let mut entry = crate::account_data::new_blocklist_entry(
            crate::account_data::BlocklistUiTargetKind::Actor,
            &admitted.actor_id().to_string(),
            None,
            vec![
                arkret_models_collaboration::objects::productivity::AccountBlocklistSurface::Calls,
            ],
            None,
            chrono::Utc::now() - chrono::Duration::seconds(120),
        )
        .unwrap();
        let outcome = |signal: AdmittedSignal| SignalReceiveOutcome::Accepted {
            domain: Box::new(signal.domain),
            plaintext: signal.payload,
            effective_expires_at: signal.expires_at,
        };
        store
            .lock()
            .unwrap()
            .set_client_blocklist(1, vec![entry.clone()]);
        assert_eq!(
            observe_private_product(handle.clone(), outcome(admitted.clone()))
                .await
                .unwrap(),
            0
        );
        let mut other_station = admitted.clone();
        other_station.domain.sender_actor_id =
            arkret_sdk::ActorId::account(arkret_sdk::AccountId::new(
                admitted
                    .actor_id()
                    .as_account_id()
                    .unwrap()
                    .principal_id
                    .clone(),
                arkret_sdk::DidCoreId::new("ak:did_core:web:other.example").unwrap(),
            ));
        assert_eq!(
            observe_private_product(handle.clone(), outcome(other_station))
                .await
                .unwrap(),
            1
        );
        entry.expires_at = Some(chrono::Utc::now() - chrono::Duration::seconds(1));
        store
            .lock()
            .unwrap()
            .set_client_blocklist(2, vec![entry.clone()]);
        assert_eq!(
            observe_private_product(handle.clone(), outcome(admitted.clone()))
                .await
                .unwrap(),
            1
        );
        entry.expires_at = None;
        for (revision, mode) in [
            (
                3,
                arkret_models_collaboration::objects::productivity::AccountBlocklistMode::Hide,
            ),
            (
                4,
                arkret_models_collaboration::objects::productivity::AccountBlocklistMode::Mute,
            ),
        ] {
            entry.mode = mode;
            store
                .lock()
                .unwrap()
                .set_client_blocklist(revision, vec![entry.clone()]);
            assert_eq!(
                observe_private_product(handle.clone(), outcome(admitted.clone()))
                    .await
                    .unwrap(),
                1
            );
        }
        entry.mode =
            arkret_models_collaboration::objects::productivity::AccountBlocklistMode::Block;
        store.lock().unwrap().set_client_blocklist(5, vec![entry]);
        assert_eq!(
            observe_private_product(handle.clone(), outcome(admitted.clone()))
                .await
                .unwrap(),
            0
        );
        store.lock().unwrap().set_client_blocklist(6, Vec::new());
        assert_eq!(
            observe_private_product(handle, outcome(admitted))
                .await
                .unwrap(),
            1
        );
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
            arkret_sdk::SignalPlaintextKind::CallSignal.as_str(),
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
            arkret_sdk::SignalPlaintextKind::Presence.as_str(),
            json!({"kind": "ak.presence", "state": "online"}),
        );

        let body = live_body_value(&plaintext).unwrap();
        assert_eq!(
            serde_json::from_value::<arkret_sdk::ActorId>(body["actor_id"].clone()).unwrap(),
            plaintext.actor_id().clone(),
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
