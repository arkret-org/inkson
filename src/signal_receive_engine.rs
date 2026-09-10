//! Encrypted Signal receive rail (`ak.self.signal.stream.subscribe.v1`).
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
//! * [`DirectorySenderKeyResolver`] consumes the exact sender/key/authorization instance in the
//!   authenticated frame's `delivery_authority`, bound to the active local Account. Local known
//!   revocation overrides that result; a cached public key alone is never current authorization
//!   (`signal.md` §1).
//! * [`MlsSignalDecryptor`] restores the scope's persisted MLS group through the same
//!   [`crate::signal::restore_signal_mls_session`] helper the send path uses, then opens the AEAD
//!   through the SDK, which enforces `aead_profile` equality with the group's negotiated
//!   ciphersuite, epoch equality, the sender nonce prefix domain, the recomputed AAD and the
//!   per-sender nonce-counter replay window.
//!
//! Product routing then splits four ways: call signalling, message-stream
//! previews and read receipts go to the app-mounted hubs through
//! [`crate::runtime::projection::SignalProductSink`], while presence and typing
//! bodies land in the bounded live projection the chat views read.

use std::sync::Mutex;
use std::time::Duration;

use garth::{
    RetrySchedule, RunOptions, SignalReceiveHandlers, SignalRejection, SignalSink, SyncLoopControl,
    TransportProvider,
};
use serde_json::Value;

use crate::config::MultiProfileConfig;
use crate::runtime::projection::{SignalProductRouter, SignalProductSink};

/// Failure-backoff bounds, matching the account and realm engines so all three
/// recover on the same human-scale cadence.
const BACKOFF_FLOOR: Duration = Duration::from_secs(1);
const BACKOFF_CEILING: Duration = Duration::from_secs(60);

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

/// Fail-closed [`garth::SignalSenderKeyResolver`] over accepted device and
/// current Agent authority evidence.
///
/// Device and Agent authority arrive bound to the exact authenticated stream frame.
/// No per-Signal self RPC or reusable current authorization cache is involved;
/// local revocation and full account checks precede producer-proof and AEAD checks.
///
/// The recipient Station applies the current device/Agent gate before delivery.
/// `envelope.seal_ref` selects Realm/scope state and does not replace that current
/// PCR check. The client binds the returned authority to this envelope and its
/// authenticated Account, then still verifies the producer signature and E2E data.
#[derive(Default)]
pub struct DirectorySenderKeyResolver {
    state_store: Option<crate::runtime::input::StateStoreHandle>,
    account: Option<crate::config::ActiveAccountContext>,
}

impl garth::SignalSenderKeyResolver for DirectorySenderKeyResolver {
    fn resolve_sender_key<'a>(
        &'a self,
        envelope: &'a arkret_wire::SignalEnvelope,
        delivery_authority: &'a arkret_wire::SignalDeliveryAuthority,
    ) -> garth::BoxSignalSenderKeyFuture<'a> {
        Box::pin(async move {
            let account = self.account.as_ref()?;
            let store = self.state_store.as_ref()?;
            let recipient = store.read(|store| store.active_authority())?;
            if recipient != account.authority {
                return None;
            }
            delivery_authority.validate_for_envelope(envelope).ok()?;
            if delivery_authority.recipient_account_id != recipient
                || envelope.expires_at <= crate::clock::now_utc()
            {
                return None;
            }
            let key = delivery_authority.key.clone();
            if let Some(device_id) = &envelope.sender_device_id {
                if crate::identity::device_directory::known_device_revoked(
                    &envelope.sender_actor_id.to_string(),
                    device_id.as_str(),
                ) {
                    return None;
                }
            }
            let public_key = arkret_sdk::signatures::PublicKeyMaterial::Ed25519Raw {
                bytes: arkret_sdk::base64url_decode(key.public_key_b64u.as_str().as_bytes())
                    .ok()?,
            };
            match envelope.sender_device_id.as_ref() {
                Some(device_id) => garth::VerifiedSignalSenderKey::from_directory_evidence(
                    public_key,
                    key.actor.clone(),
                    device_id.clone(),
                    key.verification_method,
                    key.actor.as_account_id()?.clone(),
                    key.authorization_ref,
                )
                .ok(),
                None => garth::VerifiedSignalSenderKey::from_agent_evidence(
                    public_key,
                    key.actor,
                    key.verification_method,
                    key.authorization_ref,
                )
                .ok(),
            }
        })
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
    authority: arkret_sdk::AccountId,
    device_id: arkret_sdk::DeviceId,
    /// §10.1 obliges a receiver to keep a seen-counter set per
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

impl garth::SignalDecryptor for MlsSignalDecryptor {
    fn open<'a>(
        &'a self,
        envelope: &'a arkret_wire::SignalEnvelope,
        verified_sender: &'a garth::VerifiedSignalSenderKey,
    ) -> garth::BoxSignalDecryptFuture<'a> {
        Box::pin(async move {
            // The MLS exporter only evaluates the group's current epoch
            // (`crates/mls/src/signal.rs::signal_suite_for`), so the shared restore
            // helper's epoch gate drops a Signal naming any other epoch rather than
            // routing around it. No decryption queue, no downgrade, no backfill.
            let (session, accepted_group_state_ref) = self
                .state_store
                .read(|store| {
                    let session = crate::signal::restore_signal_mls_session(
                        store,
                        self.secure_store.as_ref(),
                        &envelope.scope_ref,
                        &self.authority,
                        &self.device_id,
                        envelope.encrypted_payload.epoch,
                    )?;
                    let accepted_group_state_ref = store
                        .mls_group_state_ref_for_scope(
                            &envelope.scope_ref,
                            &session.group.group_id(),
                            session.group.epoch(),
                        )
                        .map_err(anyhow::Error::msg)?;
                    Ok::<_, anyhow::Error>((session, accepted_group_state_ref))
                })
                .map_err(|error| garth::Error::Protocol(error.to_string()))?;
            let group = session.group;
            let mut replay = self.replay.lock().map_err(|error| {
                garth::Error::Protocol(format!("signal replay tracker poisoned: {error}"))
            })?;
            let authority = match verified_sender.authority() {
                garth::VerifiedSignalSenderAuthority::AccountDevice {
                    device_authorize_event_id,
                    ..
                } => arkret_sdk::mls::SignalSenderAuthority::AccountDevice {
                    public_key: verified_sender.public_key(),
                    device_authorize_event_id,
                },
                garth::VerifiedSignalSenderAuthority::Agent {
                    agent_key_authorize_event_id,
                    ..
                } => arkret_sdk::mls::SignalSenderAuthority::Agent {
                    public_key: verified_sender.public_key(),
                    verification_method: &envelope.proof.verification_method,
                    agent_key_authorize_event_id,
                },
            };
            group
                .open_signal_envelope(
                    envelope,
                    session.content_scheme,
                    authority,
                    accepted_group_state_ref.as_str(),
                    &mut replay,
                )
                .map_err(|error| garth::Error::Protocol(error.to_string()))
        })
    }
}

/// Routes admitted plaintext to the three product consumers.
struct InksonSignalSink {
    state_store: crate::runtime::input::StateStoreHandle,
    products: SignalProductRouter,
    live: Mutex<garth::LiveSignalProjection>,
}

impl SignalSink for InksonSignalSink {
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
                        .call_signal(envelope, decrypted_body_value(&plaintext)?)
                        .await;
                }
                garth::MESSAGE_STREAM_KIND => {
                    self.products.message_stream(&plaintext).await;
                }
                garth::SIGNAL_PLAINTEXT_KIND_PRESENCE | SIGNAL_PLAINTEXT_KIND_TYPING => {
                    self.apply_live_body(&plaintext)?;
                }
                SIGNAL_PLAINTEXT_KIND_READ_RECEIPT => {
                    // Not a live body: presence and typing are TTL projections
                    // that must disappear, whereas a read position stays true
                    // after the receipt that carried it expires
                    // (`read-receipts.md` §1.1).
                    //
                    // The Realm policy travels with it because §2.5 puts the
                    // `disabled` / `private` discard on the receiving client:
                    // the receipt is inside the ciphertext, so the Sync Service
                    // could not have filtered it.
                    let policy = self.realm_read_receipt_policy(&plaintext);
                    self.products.read_receipt(&plaintext, &policy);
                }
                other => {
                    // Admitted and authenticated, but no local consumer.
                    // Dropping it is correct on a rail with no delivery
                    // guarantee; tracing it keeps the gap visible.
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
        rejection: SignalRejection,
        error: &garth::Error,
    ) {
        // Sender identity is already server-visible on this rail, so naming it
        // here leaks nothing the transport did not. The plaintext never exists
        // for a rejected envelope, so nothing product-level can be logged.
        tracing::warn!(
            rejection = ?rejection,
            %error,
            actor = %envelope.sender_actor_id,
            endpoint = ?envelope.sender_device_id,
            "inbound Signal failed receiver admission and was dropped"
        );
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
    fn realm_read_receipt_policy(
        &self,
        plaintext: &garth::SignalPlaintext,
    ) -> arkret_sdk::ReadReceiptPolicy {
        let realm_id = plaintext.scope_ref.realm_id().as_str().to_owned();
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

    fn apply_live_body(&self, plaintext: &garth::SignalPlaintext) -> garth::Result<()> {
        let body = live_body_value(plaintext)?;
        let now = crate::clock::now_utc();
        let Ok(mut live) = self.live.lock() else {
            return Ok(());
        };
        if !live.apply_plaintext(plaintext, body, now)? {
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
fn decrypted_body_value(plaintext: &garth::SignalPlaintext) -> garth::Result<Value> {
    let body = match &plaintext.payload {
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
fn live_body_value(plaintext: &garth::SignalPlaintext) -> garth::Result<Value> {
    let Value::Object(mut body) = decrypted_body_value(plaintext)? else {
        return Err(garth::Error::Protocol(
            "admitted Signal plaintext must serialize as an object".to_owned(),
        ));
    };
    body.insert(
        "actor_id".to_owned(),
        serde_json::to_value(&plaintext.actor_id).map_err(|error| {
            garth::Error::Protocol(format!("serialize Signal ActorId: {error}"))
        })?,
    );
    match &plaintext.sender_endpoint {
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
        live: Mutex::new(garth::LiveSignalProjection::new()),
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
