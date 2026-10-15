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
//! [`arkret_models_collaboration::SignalDeliveryAuthority`] inside the authenticated stream
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
    typing: Option<TypingAdmission>,
}

#[derive(Clone, Debug)]
struct TypingAdmission {
    signal: AdmittedSignal,
    recipient: Option<arkret_sdk::AccountId>,
    session_epoch: u64,
}

struct TypingSessionGuard<'a>(&'a InksonSignalSink);

impl Drop for TypingSessionGuard<'_> {
    fn drop(&mut self) {
        self.0.clear_typing();
    }
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
                typing: None,
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
    pub(crate) call_account: Option<crate::config::ActiveAccountContext>,
    pub(crate) call_http: Option<arkret_sdk::http_client::Client>,
    pub(crate) state_store: crate::runtime::input::StateStoreHandle,
    pub(crate) products: SignalProductRouter,
    pub(crate) live: Mutex<LiveSignalProjection>,
}

impl InksonSignalSink {
    fn clear_typing(&self) {
        let retained = if let Ok(mut live) = self.live.lock() {
            let retained = live
                .bodies
                .values()
                .filter(|body| body.typing.is_some())
                .map(|body| body.body.clone())
                .collect::<Vec<_>>();
            live.bodies.retain(|_, body| body.typing.is_none());
            retained
        } else {
            return;
        };
        self.state_store.write(|store| {
            let mut bodies = store.load().presence_projection;
            bodies.retain(|body| !retained.contains(body));
            store.save_presence_projection(&bodies);
        });
    }

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
            authority_commit_id,
            parent_realm_authority_commit_id,
            product_authority,
            call_invitation,
            signer_verification_method,
        } = outcome
        else {
            return Ok(());
        };
        let signal = AdmittedSignal {
            expires_at: effective_expires_at,
            domain: *domain,
            authority_commit_id,
            parent_realm_authority_commit_id,
            product_authority,
            call_invitation,
            signer_verification_method,
            payload: *plaintext,
        };
        #[cfg(all(target_arch = "wasm32", feature = "wasm-localstorage-secrets-test"))]
        let observation_owner = self.state_store.read(|store| store.active_principal_id());
        #[cfg(all(target_arch = "wasm32", feature = "wasm-localstorage-secrets-test"))]
        let observation_epoch = crate::identity::device_directory::session_cache_epoch();
        let target_scope_result = self.strand_target_at_verified_cut(&signal).await;
        #[cfg(all(target_arch = "wasm32", feature = "wasm-localstorage-secrets-test"))]
        let target_scope_error = target_scope_result.as_ref().err().map(ToString::to_string);
        let target_scope_matches = target_scope_result.unwrap_or(false);
        if !target_scope_matches {
            #[cfg(all(target_arch = "wasm32", feature = "wasm-localstorage-secrets-test"))]
            self.observe_typing(
                &signal,
                observation_owner,
                observation_epoch,
                false,
                false,
                target_scope_error,
            );
            return Ok(());
        }
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
                let applied = self.apply_live_body(&signal)?;
                #[cfg(all(target_arch = "wasm32", feature = "wasm-localstorage-secrets-test"))]
                self.observe_typing(
                    &signal,
                    observation_owner,
                    observation_epoch,
                    true,
                    applied,
                    None,
                );
                #[cfg(not(all(
                    target_arch = "wasm32",
                    feature = "wasm-localstorage-secrets-test"
                )))]
                let _ = applied;
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

/// Containment is a separate recipient check after genuine MLS decryption.
/// It grants no action permission; the existing product gates remain in place.
fn plaintext_strand_target(signal: &AdmittedSignal) -> garth::Result<Option<arkret_sdk::StrandId>> {
    match &signal.payload {
        arkret_sdk::SignalPlaintext::Typing(value) => Ok(Some(value.strand_id.clone())),
        arkret_sdk::SignalPlaintext::MessageStream(value) => Ok(Some(value.strand_id().clone())),
        arkret_sdk::SignalPlaintext::ReadReceipt(value)
            if value.read_scope.kind == arkret_sdk::ReadScopeKind::Strand =>
        {
            let id = value.read_scope.object_ref.as_ref().ok_or_else(|| {
                garth::Error::Protocol("Strand read receipt lacks a target".to_owned())
            })?;
            arkret_sdk::StrandId::new(id.clone())
                .map(Some)
                .map_err(|_| {
                    garth::Error::Protocol("Strand read receipt has an invalid target".to_owned())
                })
        }
        _ => Ok(None),
    }
}

fn strand_scope_matches(current: &arkret_sdk::Strand, scope: &arkret_sdk::ScopeRef) -> bool {
    match scope {
        arkret_sdk::ScopeRef::Realm { realm_id } => {
            current.realm_id == *realm_id && current.scope_circle_id.is_none()
        }
        arkret_sdk::ScopeRef::Circle {
            realm_id,
            circle_id,
        } => current.realm_id == *realm_id && current.scope_circle_id.as_ref() == Some(circle_id),
        _ => false,
    }
}

#[cfg(all(target_arch = "wasm32", feature = "wasm-localstorage-secrets-test"))]
static SIGNAL_RECEIVER_EVIDENCE: Mutex<Vec<(String, u64, Value)>> = Mutex::new(Vec::new());

#[cfg(all(target_arch = "wasm32", feature = "wasm-localstorage-secrets-test"))]
pub(crate) fn signal_receiver_evidence(principal: &str, clear: bool) -> String {
    let epoch = crate::identity::device_directory::session_cache_epoch();
    let Ok(mut rows) = SIGNAL_RECEIVER_EVIDENCE.lock() else {
        return "[]".to_owned();
    };
    let result: Vec<_> = rows
        .iter()
        .filter(|(owner, at, _)| owner == principal && *at == epoch)
        .map(|(_, _, value)| value.clone())
        .collect();
    if clear {
        rows.retain(|(owner, at, _)| owner != principal || *at != epoch);
    }
    serde_json::to_string(&result).unwrap_or_else(|_| "[]".to_owned())
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
    fn typing_blocked(&self, signal: &AdmittedSignal, now: DateTime<Utc>) -> bool {
        self.state_store.read(|store| {
            let row = garth::mls::membership::validated_realm_roster_entries(
                store
                    .realm_tree_projection(signal.scope_ref().realm_id().as_str())
                    .as_ref(),
            )
            .into_iter()
            .find(|row| row.actor_id == *signal.actor_id());
            let handles = row
                .map(|row| {
                    let Some(account) = row.subject_account_id.as_ref() else {
                        return Vec::new();
                    };
                    let policies =
                        crate::identity::member_identity_store::realm_handle_issuer_policies(
                            store,
                            signal.scope_ref().realm_id().as_str(),
                        );
                    row.handle_claims
                        .as_deref()
                        .unwrap_or_default()
                        .iter()
                        .filter_map(|claim| {
                            arkret_sdk::identity::select_primary_handle(
                                &arkret_sdk::identity::PrimaryHandleSelectInput {
                                    account_id: account,
                                    context: Some(signal.scope_ref().realm_id().as_str()),
                                    claim_set_snapshot: std::slice::from_ref(claim),
                                    handle_issuer_policies: &policies,
                                    holder_primary_handle_at_as_of: None,
                                    resolution_as_of: now,
                                },
                            )
                            .map(|verified| verified.claim.handle)
                        })
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            crate::account_data::hides_typing(&store.client_blocklist(), signal, &handles, now)
        })
    }

    fn typing_product_allowed(
        &self,
        signal: &AdmittedSignal,
        strand: &arkret_sdk::StrandId,
        now: DateTime<Utc>,
    ) -> bool {
        let Some(recipient) = self.state_store.read(|store| store.active_authority()) else {
            return false;
        };
        signal.expires_at > now
            && !self.typing_blocked(signal, now)
            && signal.product_authority.as_deref().is_some_and(|material| {
                material.authority_commit_id == signal.authority_commit_id
                    && material.parent_realm_authority_commit_id
                        == signal.parent_realm_authority_commit_id
                    && arkret_policy::signal_authorization::typing_visible(
                        material,
                        &arkret_sdk::ActorId::account(recipient.clone()),
                        signal.scope_ref(),
                        strand,
                        now,
                    )
                    && arkret_policy::signal_authorization::typing_allowed(
                        material,
                        signal.actor_id(),
                        signal.scope_ref(),
                        strand,
                        now,
                    )
            })
    }

    /// Recheck retained authenticated Typing without waiting for a peer frame.
    /// IO never holds the projection lock; comparison prevents an older refresh
    /// from erasing a newer admitted sequence that arrived while it waited.
    async fn refresh_typing(&self, now: DateTime<Utc>) {
        let retained = match self.live.lock() {
            Ok(live) => live
                .bodies
                .iter()
                .filter_map(|(key, body)| body.typing.clone().map(|typing| (key.clone(), typing)))
                .collect::<Vec<_>>(),
            Err(_) => return,
        };
        let mut rejected = Vec::new();
        for (key, typing) in retained {
            if typing.session_epoch != crate::identity::device_directory::session_cache_epoch()
                || typing.recipient != self.state_store.read(|store| store.active_authority())
                || typing.signal.expires_at <= now
                || !self
                    .strand_target_at_verified_cut(&typing.signal)
                    .await
                    .unwrap_or(false)
            {
                rejected.push((key, typing.signal));
            }
        }
        let Ok(mut live) = self.live.lock() else {
            return;
        };
        for (key, signal) in rejected {
            if live
                .bodies
                .get(&key)
                .and_then(|body| body.typing.as_ref())
                .is_some_and(|typing| typing.signal == signal)
            {
                live.bodies.remove(&key);
            }
        }
        let bodies = live.bodies();
        drop(live);
        let cached = self
            .state_store
            .read(|store| store.load().presence_projection);
        let mut next = cached.clone();
        next.retain(|body| {
            body.get("kind").and_then(Value::as_str) != Some("ak.typing") || bodies.contains(body)
        });
        if next != cached {
            self.state_store
                .write(|store| store.save_presence_projection(&next));
        }
    }

    async fn refresh_message_streams(&self, now: DateTime<Utc>) {
        let mut eligible = Vec::new();
        for signal in self.products.retained_message_streams() {
            let arkret_sdk::SignalPlaintext::MessageStream(frame) = &signal.payload else {
                continue;
            };
            if signal.expires_at > now
                && self
                    .strand_target_at_verified_cut(&signal)
                    .await
                    .unwrap_or(false)
                && signal.product_authority.as_deref().is_some_and(|material| {
                    arkret_policy::signal_authorization::message_stream_allowed(
                        material,
                        signal.actor_id(),
                        signal.scope_ref(),
                        frame.strand_id(),
                        now,
                    )
                })
            {
                eligible.push(signal);
            }
        }
        self.products.retain_message_streams(&eligible);
    }

    async fn strand_target_at_verified_cut(&self, signal: &AdmittedSignal) -> garth::Result<bool> {
        let Some(strand) = plaintext_strand_target(signal)? else {
            return Ok(true);
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
        let epoch = crate::identity::device_directory::session_cache_epoch();
        let mut generation = 0;
        let index = crate::state::CurrentIndex::open_committed(&authority, location, || {
            generation = self.state_store.read(|store| store.current_generation());
            Ok(generation)
        })
        .await
        .map_err(|_| garth::Error::Protocol("Signal Strand current is unavailable".to_owned()))?;
        if matches!(
            signal.kind(),
            arkret_sdk::SignalPlaintextKind::MessageStream
                | arkret_sdk::SignalPlaintextKind::Typing
        ) {
            let Some(material) = signal.product_authority.as_deref() else {
                return Ok(false);
            };
            if !index
                .signal_product_cut_current(material)
                .await
                .unwrap_or(false)
                || self.state_store.read(|store| {
                    crate::account_data::is_blocked(
                        &store.client_blocklist(),
                        &signal.actor_id().to_string(),
                    )
                })
            {
                return Ok(false);
            }
        }
        if let arkret_sdk::SignalPlaintext::Typing(typing) = &signal.payload {
            if !self.typing_product_allowed(signal, &typing.strand_id, crate::clock::now_utc()) {
                return Ok(false);
            }
        }
        let current = if matches!(
            signal.kind(),
            arkret_sdk::SignalPlaintextKind::Typing
                | arkret_sdk::SignalPlaintextKind::MessageStream
        ) {
            index
                .read_typing_strand_ready(
                    signal.scope_ref(),
                    &strand,
                    signal.actor_id(),
                    &arkret_sdk::ActorId::account(authority.clone()),
                )
                .await
        } else {
            index
                .read_strand_ready(signal.scope_ref().realm_id(), &strand)
                .await
        }
        .map_err(|_| garth::Error::Protocol("Signal Strand current is not ready".to_owned()))?;
        let same_attempt = self
            .state_store
            .read(|store| call_current_attempt_matches(store, &authority, generation))
            && epoch == crate::identity::device_directory::session_cache_epoch();
        Ok(same_attempt
            && current
                .as_ref()
                .is_some_and(|current| strand_scope_matches(current, signal.scope_ref())))
    }

    #[cfg(all(target_arch = "wasm32", feature = "wasm-localstorage-secrets-test"))]
    fn observe_typing(
        &self,
        signal: &AdmittedSignal,
        principal: Option<String>,
        epoch: u64,
        target_scope_matches: bool,
        live_applied: bool,
        target_scope_error: Option<String>,
    ) {
        let arkret_sdk::SignalPlaintext::Typing(typing) = &signal.payload else {
            return;
        };
        let Some(principal) = principal else {
            return;
        };
        let now = crate::clock::now_utc();
        let actor = serde_json::to_value(signal.actor_id()).ok();
        let visible_count = self.state_store.read(|store| {
            store
                .load()
                .presence_projection
                .iter()
                .filter(|body| {
                    body.get("strand_id").and_then(Value::as_str) == Some(typing.strand_id.as_str())
                        && body.get("actor_id") == actor.as_ref()
                        && body.get("typing").and_then(Value::as_bool) == Some(true)
                        && body
                            .get("expires_at")
                            .and_then(Value::as_str)
                            .and_then(|value| DateTime::parse_from_rfc3339(value).ok())
                            .is_some_and(|expiry| expiry > now)
                })
                .count()
        });
        if let Ok(mut rows) = SIGNAL_RECEIVER_EVIDENCE.lock() {
            rows.push((
                principal,
                epoch,
                serde_json::json!({
                    "scope_ref": signal.scope_ref(), "strand_id": typing.strand_id,
                "sender_actor_id": signal.actor_id(), "sender_endpoint": signal.sender_endpoint(),
                    "payload_sequence": signal.payload_sequence(), "typing": typing.typing,
                    "admitted_and_decrypted": true, "target_scope_matches": target_scope_matches,
                    "target_scope_error": target_scope_error,
                    "live_applied": live_applied, "visible_count": visible_count
                }),
            ));
            if rows.len() > 128 {
                rows.remove(0);
            }
        }
    }

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
        Ok(current.is_some_and(|state| {
            !matches!(
                state.to,
                arkret_sdk::CallLifecycleState::Ended
                    | arkret_sdk::CallLifecycleState::Failed
                    | arkret_sdk::CallLifecycleState::Cancelled
                    | arkret_sdk::CallLifecycleState::Missed
            )
        }) && same_attempt)
    }

    /// The product boundary runs only after the accepted Call current gate.
    async fn dispatch_call_product(&self, signal: &AdmittedSignal) -> garth::Result<()> {
        if signal.call_invitation.is_some()
            && !matches!(&signal.payload, arkret_sdk::SignalPlaintext::CallSignal(call)
                if matches!(&call.signal, arkret_sdk::CallSignalData::Invite(_)))
        {
            return Ok(());
        }
        if matches!(&signal.payload, arkret_sdk::SignalPlaintext::CallSignal(call)
            if matches!(&call.signal, arkret_sdk::CallSignalData::Invite(_)))
            && !self.call_consent_at_ring(signal).await.unwrap_or(false)
        {
            return Ok(());
        }
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

    async fn call_consent_at_ring(&self, signal: &AdmittedSignal) -> anyhow::Result<bool> {
        let Some(account) = &self.call_account else {
            return Ok(false);
        };
        let Some(delivery) = &signal.call_invitation else {
            return Ok(false);
        };
        let arkret_sdk::SignalPlaintext::CallSignal(call) = &signal.payload else {
            return Ok(false);
        };
        let arkret_sdk::CallSignalData::Invite(invite) = &call.signal else {
            return Ok(false);
        };
        if delivery.invitation.holder_account_id != account.authority
            || delivery.invitation.call_id != call.call_id
            || delivery.invitation.scope_ref != *signal.scope_ref()
            || delivery.invitation.inviter_actor_id != *signal.actor_id()
            || delivery.request.subject_device_id != account.device_id
            || delivery.invitation.media
                != (arkret_sdk::CallInvitationMedia {
                    audio: invite.media.audio,
                    video: invite.media.video,
                    screen: invite.media.screen.unwrap_or(false),
                })
            || delivery.invitation.expires_at <= crate::clock::now_utc()
            || signal.expires_at <= crate::clock::now_utc()
        {
            return Ok(false);
        }
        let session_epoch = crate::identity::device_directory::session_cache_epoch();
        let guard = || -> anyhow::Result<()> {
            anyhow::ensure!(
                self.state_store.read(|s| s.active_authority()) == Some(account.authority.clone())
                    && !self.state_store.read(|s| s.current_reset_required())
                    && crate::identity::device_directory::session_cache_epoch() == session_epoch,
                "ring attempt changed its account/device/current session"
            );
            Ok(())
        };
        guard()?;
        let http = match &self.call_http {
            Some(http) => http.clone(),
            None => {
                crate::identity::session_refresh::provide_authenticated_sdk_client(
                    account.server_url.as_str(),
                )
                .await?
            }
        };
        let client = crate::transport::own_station_results::client_for_http(&http).await?;
        let request = arkret_sdk::ConsentCurrentReadRequestBody {
            holder_account_id: account.authority.clone(),
            peer: arkret_sdk::ConsentPeer::Actor {
                actor_id: signal.actor_id().clone(),
            },
            consent_scope: delivery.invitation.media.consent_scope(),
            audience_actor_id: arkret_sdk::ActorId::service(account.authority.station_id.clone()),
            nonce: crate::random::base64url_token(32, "Consent read nonce unavailable")?,
        };
        let response = client.consent_current(&request).await?;
        guard()?;
        let permitted = install_call_consent_current(
            &self.state_store,
            account,
            &response,
            session_epoch,
            &guard,
        )
        .await?;
        // A fresh holder read cannot rehabilitate product material issued by
        // a previous authority generation or outside its original window.
        Ok(permitted
            && delivery
                .outcome
                .validate_for_request(
                    &delivery.request,
                    response.value()?.governance_generation,
                    crate::clock::now_utc(),
                )
                .is_ok())
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
        let blocklist = self.state_store.read(|store| store.client_blocklist());
        let before = live.bodies.len();
        live.bodies.retain(|_, body| {
            body.body.get("kind").and_then(Value::as_str) != Some("ak.typing")
                || body.typing.as_ref().is_some_and(|typing| {
                    typing.session_epoch == crate::identity::device_directory::session_cache_epoch()
                        && typing.recipient
                            == self.state_store.read(|store| store.active_authority())
                        && !self.typing_blocked(&typing.signal, now)
                })
        });
        let changed = live.expire(now) || live.bodies.len() != before;
        let bodies = changed.then(|| live.bodies());
        let retained_typing = live
            .bodies
            .values()
            .filter(|body| body.typing.is_some())
            .map(|body| body.body.clone())
            .collect::<Vec<_>>();
        drop(live);
        let cached = self
            .state_store
            .read(|store| store.load().presence_projection);
        // A restarted receiver has no in-memory keys for the prior projection.
        // Its admitted cached bodies still expire without a new network frame.
        let mut bodies = bodies.unwrap_or_else(|| cached.to_vec());
        bodies.retain(|body| {
            (body.get("kind").and_then(Value::as_str) != Some("ak.typing")
                || retained_typing.iter().any(|retained| retained == body))
                && !typing_body_blocked(body, &blocklist)
                && body
                    .get("expires_at")
                    .and_then(Value::as_str)
                    .and_then(|value| DateTime::parse_from_rfc3339(value).ok())
                    .is_some_and(|expiry| expiry > now)
        });
        if bodies != *cached {
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

    fn apply_live_body(&self, signal: &AdmittedSignal) -> garth::Result<bool> {
        if let arkret_sdk::SignalPlaintext::Typing(typing) = &signal.payload {
            if !self.typing_product_allowed(signal, &typing.strand_id, crate::clock::now_utc()) {
                return Ok(false);
            }
        }
        let body = live_body_value(signal)?;
        let now = crate::clock::now_utc();
        let Ok(mut live) = self.live.lock() else {
            return Ok(false);
        };
        if !live.apply_admitted(signal, body, now)? {
            return Ok(false);
        }
        if signal.kind() == arkret_sdk::SignalPlaintextKind::Typing {
            let key = live_signal_projection_key(signal)?;
            if let Some(body) = live.bodies.get_mut(&key) {
                body.typing = Some(TypingAdmission {
                    signal: signal.clone(),
                    recipient: self.state_store.read(|store| store.active_authority()),
                    session_epoch: crate::identity::device_directory::session_cache_epoch(),
                });
            }
        }
        let bodies = live.bodies();
        drop(live);
        self.state_store
            .write(|store| store.save_presence_projection(&bodies));
        Ok(true)
    }
}

fn typing_body_blocked(
    body: &Value,
    blocklist: &[arkret_models_collaboration::objects::productivity::AccountBlocklistEntry],
) -> bool {
    body.get("kind").and_then(Value::as_str) == Some("ak.typing")
        && body
            .get("actor_id")
            .and_then(|actor| serde_json::from_value::<arkret_sdk::ActorId>(actor.clone()).ok())
            .is_none_or(|actor| crate::account_data::is_blocked(blocklist, &actor.to_string()))
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
        call_account: Some(ctx.account.clone()),
        call_http: None,
        state_store: ctx.state_store.clone(),
        products: ctx.products.clone(),
        live: Mutex::new(LiveSignalProjection::new()),
    };
    let _typing_session = TypingSessionGuard(&sink);
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
            sink.refresh_typing(now).await;
            sink.refresh_message_streams(now).await;
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
            arkret_models_collaboration::SignalStreamFrame::Signal {
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
            arkret_models_collaboration::SignalStreamFrame::Heartbeat => {
                // The initial heartbeat alone must not reset a rapid failure
                // loop. A later heartbeat proves a sustained live window.
                if received_heartbeat {
                    *healthy_progress = true;
                }
                received_heartbeat = true;
                let now = crate::clock::now_utc();
                sink.expire_live_bodies(now);
                sink.refresh_typing(now).await;
                sink.products.advance_clock(now);
            }
            arkret_models_collaboration::SignalStreamFrame::Drain {
                reconnect_after_ms, ..
            } => {
                return Ok(SignalStreamStopReason::ReconnectAfter { reconnect_after_ms });
            }
            arkret_models_collaboration::SignalStreamFrame::Unauthorized { reason } => {
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
            call_account: None,
            call_http: None,
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
            call_invitation: None,
            signer_verification_method: arkret_sdk::DidUrl::new("did:web:alice.example#device-1")
                .unwrap(),
            product_authority: None,
            authority_commit_id: arkret_sdk::RealmCommitId::from_digest([41; 32]),
            parent_realm_authority_commit_id: None,
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

    #[test]
    fn decrypted_strand_target_requires_exact_realm_and_circle_scope() {
        let id = arkret_sdk::StrandId::from_event_id(&arkret_sdk::EventId::from_digest(
            arkret_sdk::DigestSuite::Sha256,
            [31; 32],
        ));
        let signal = plaintext_of(
            "ak.typing",
            json!({"kind":"ak.typing", "strand_id":id, "typing":true}),
        );
        assert_eq!(
            plaintext_strand_target(&signal).unwrap().as_ref(),
            Some(&id)
        );
        let realm = signal.scope_ref().realm_id().clone();
        let mut strand =
            arkret_sdk::Strand::discussion(id, realm.clone(), "Target", signal.actor_id().clone());
        assert!(strand_scope_matches(&strand, signal.scope_ref()));
        let other =
            arkret_sdk::RealmId::new("ak:realm:AQJmSg1s9QyzppFeJL40dN92YVHZeLdBBt3UWHa9XNOD")
                .unwrap();
        assert!(!strand_scope_matches(
            &strand,
            &arkret_sdk::ScopeRef::Realm { realm_id: other }
        ));
        let circle = arkret_sdk::CircleId::from_event_id(&arkret_sdk::EventId::from_digest(
            arkret_sdk::DigestSuite::Sha256,
            [33; 32],
        ));
        strand.scope_circle_id = Some(circle.clone());
        assert!(!strand_scope_matches(&strand, signal.scope_ref()));
        assert!(strand_scope_matches(
            &strand,
            &arkret_sdk::ScopeRef::Circle {
                realm_id: realm.clone(),
                circle_id: circle
            }
        ));
        let other_circle = arkret_sdk::CircleId::from_event_id(&arkret_sdk::EventId::from_digest(
            arkret_sdk::DigestSuite::Sha256,
            [34; 32],
        ));
        assert!(!strand_scope_matches(
            &strand,
            &arkret_sdk::ScopeRef::Circle {
                realm_id: realm,
                circle_id: other_circle
            }
        ));
    }

    fn authorize_typing(signal: &mut AdmittedSignal) {
        let head = arkret_sdk::CommitStreamHead {
            stream_ref: arkret_sdk::CommitStreamRef::from_scope(signal.scope_ref(), None).unwrap(),
            commit_id: signal.authority_commit_id.clone(),
            stream_position: 1,
        };
        let grant: arkret_models_collaboration::governance::grant_constraint::CapabilityGrant = serde_json::from_value(serde_json::json!({
            "id":arkret_sdk::GrantId::from_event_id(&arkret_sdk::EventId::from_digest(arkret_sdk::DigestSuite::Sha256,[72;32])),
            "schema":"ak.schema.capability.v1", "realm_id":signal.scope_ref().realm_id(),
            "issuer_id":signal.actor_id(), "subject":signal.actor_id(),
            "actions":[arkret_sdk::CapabilityActionId::TYPING_BROADCAST],
            "resources":[{"kind":"realm", "realm_id":signal.scope_ref().realm_id()}],
            "issuer_authority_refs":[{"kind":"realm_root", "realm_id":signal.scope_ref().realm_id(), "authority_event_ref":arkret_sdk::EventId::from_digest(arkret_sdk::DigestSuite::Sha256,[73;32]), "authority_generation":0}],
            "authority_root_refs":[{"kind":"realm_root", "realm_id":signal.scope_ref().realm_id(), "authority_event_ref":arkret_sdk::EventId::from_digest(arkret_sdk::DigestSuite::Sha256,[73;32]), "authority_generation":0}],
            "authority_depth":1, "status":"active", "issued_at":"2026-01-01T00:00:00.000Z"
        })).unwrap();
        signal.product_authority = Some(Box::new(arkret_sdk::SignalProductAuthority {
            authority_commit_id: signal.authority_commit_id.clone(),
            parent_realm_authority_commit_id: signal.parent_realm_authority_commit_id.clone(),
            current_realm_head: head.clone(),
            current_scope_head: head,
            sent_at: crate::clock::now_utc(),
            grants: vec![grant.clone()],
            current_grants: vec![grant],
            historical_product_policies: vec![],
            current_product_policies: vec![],
            owner_actions: vec![],
            profile_actions: vec![],
            agent: None,
        }));
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[tokio::test]
    async fn typing_authority_revocation_and_restart_clear_old_indicators_without_a_frame() {
        use std::sync::Arc;
        let directory = tempfile::tempdir().unwrap();
        let mut local =
            crate::LocalStateStore::with_path(directory.path().join("typing-revoke.json"));
        local.promote_accepted_context_for_test(&"did:web:bob.example".parse().unwrap());
        let recipient = arkret_sdk::ActorId::account(local.active_authority().unwrap());
        let index = crate::state::CurrentIndex::open(
            &local.active_authority().unwrap(),
            0,
            local.current_index_location(),
        )
        .await
        .unwrap();
        let store = Arc::new(Mutex::new(local));
        let read = store.clone();
        let write = store.clone();
        let sink = InksonSignalSink {
            call_account: None,
            call_http: None,
            state_store: crate::runtime::input::StateStoreHandle::new(
                move |consume| consume(&read.lock().unwrap()),
                move |consume| consume(&mut write.lock().unwrap()),
            ),
            products: SignalProductRouter::default(),
            live: Mutex::new(Default::default()),
        };
        let strand = arkret_sdk::StrandId::from_event_id(&arkret_sdk::EventId::from_digest(
            arkret_sdk::DigestSuite::Sha256,
            [71; 32],
        ));
        let mut signal = plaintext_of(
            "ak.typing",
            json!({"kind":"ak.typing","strand_id":strand,"typing":true}),
        );
        signal.expires_at = crate::clock::now_utc() + chrono::Duration::seconds(5);
        assert!(!sink.apply_live_body(&signal).unwrap());
        assert!(store.lock().unwrap().load().presence_projection.is_empty());
        authorize_typing(&mut signal);
        let realm = signal.scope_ref().realm_id().clone();
        let stream = arkret_sdk::CommitStreamRef::Realm {
            realm_id: realm.clone(),
        };
        let head = signal
            .product_authority
            .as_ref()
            .unwrap()
            .current_realm_head
            .clone();
        let row = |selector, value| arkret_sdk::TypedCurrentRow::Value {
            selector,
            source_stream_ref: stream.clone(),
            revision: arkret_sdk::CurrentRevision {
                commit_id: head.commit_id.clone(),
                stream_position: 1,
            },
            value,
        };
        let rows = vec![
            row(
                arkret_sdk::CurrentSelector::MemberState {
                    actor_id: signal.actor_id().clone(),
                },
                json!({"membership":"join"}),
            ),
            row(
                arkret_sdk::CurrentSelector::MemberState {
                    actor_id: recipient,
                },
                json!({"membership":"join"}),
            ),
            row(
                arkret_sdk::CurrentSelector::Strand {
                    strand_id: strand.clone(),
                },
                serde_json::to_value(arkret_sdk::Strand::discussion(
                    strand.clone(),
                    realm.clone(),
                    "Target",
                    signal.actor_id().clone(),
                ))
                .unwrap(),
            ),
        ];
        let frame = |position, entries: Vec<arkret_sdk::TypedCurrentRow>| {
            let head = arkret_sdk::CommitStreamHead {
                stream_ref: stream.clone(),
                commit_id: head.commit_id.clone(),
                stream_position: position,
            };
            serde_json::from_value::<arkret_sdk::sync::AccountSubscribeFrame>(json!({
                "kind":"delta", "cursor":"ak:cursor:YQ", "realms": {realm.to_string(): {
                    "current":{"realm_id":realm,"governance_generation":1,"stream_heads":[head],"entries":entries},
                    "baseline":{"snapshot_cursor":if position == 1 {"ak:cursor:Yg"} else {"ak:cursor:Yw"}, "cut_revision":position,
                        "coverage":{"realm_id":realm,"stream_heads":[head],"complete_for_authorized_streams":true},"complete":true}
                }}
            })).unwrap()
        };
        let stage = index.stage_frame(0, &frame(1, rows)).await.unwrap();
        store
            .lock()
            .unwrap()
            .commit_current_stage_for_test(stage)
            .unwrap();
        store.lock().unwrap().set_current_generation(1);
        assert!(sink.strand_target_at_verified_cut(&signal).await.unwrap());
        assert!(sink.apply_live_body(&signal).unwrap());
        sink.refresh_typing(crate::clock::now_utc()).await;
        assert_eq!(sink.live.lock().unwrap().len(), 1);
        let cached = store.lock().unwrap().load().presence_projection;
        let mut revoked = signal.clone();
        revoked
            .product_authority
            .as_mut()
            .unwrap()
            .current_grants
            .clear();
        assert!(!sink.apply_live_body(&revoked).unwrap());
        // An accepted governance advance invalidates the retained authority cut.
        // No new Typing frame is delivered and the original TTL is still live.
        let stage = index.stage_frame(1, &frame(2, vec![])).await.unwrap();
        store
            .lock()
            .unwrap()
            .commit_current_stage_for_test(stage)
            .unwrap();
        store.lock().unwrap().set_current_generation(2);
        assert!(signal.expires_at > crate::clock::now_utc());
        sink.refresh_typing(crate::clock::now_utc()).await;
        assert!(sink.live.lock().unwrap().is_empty());
        assert!(store.lock().unwrap().load().presence_projection.is_empty());
        store.lock().unwrap().save_presence_projection(&cached);
        sink.expire_live_bodies(crate::clock::now_utc());
        assert!(store.lock().unwrap().load().presence_projection.is_empty());
        // Ending the receiver session also removes its still-live indicators.
        assert!(sink.apply_live_body(&signal).unwrap());
        {
            let _guard = TypingSessionGuard(&sink);
        }
        assert!(sink.live.lock().unwrap().is_empty());
        assert!(store.lock().unwrap().load().presence_projection.is_empty());
    }

    #[test]
    fn typing_blocklist_uses_accepted_device_method_domain_and_verified_handle_only() {
        use arkret_models_collaboration::objects::productivity::{
            AccountBlocklistEntry, AccountBlocklistMode, AccountBlocklistSurface,
        };
        let strand = arkret_sdk::StrandId::from_event_id(&arkret_sdk::EventId::from_digest(
            arkret_sdk::DigestSuite::Sha256,
            [71; 32],
        ));
        let signal = plaintext_of(
            "ak.typing",
            json!({"kind":"ak.typing","strand_id":strand,"typing":true}),
        );
        let now = crate::clock::now_utc();
        let device = match signal.sender_endpoint() {
            arkret_sdk::SignalSequenceEndpoint::AccountDevice { device_id } => device_id,
            _ => unreachable!(),
        };
        for target in [
            json!({"kind":"actor","actor_id":signal.actor_id()}),
            json!({"kind":"device","object_ref":device}),
            json!({"kind":"device","value":signal.signer_verification_method}),
            json!({"kind":"domain","value":"alice.example"}),
            json!({"kind":"domain","value":"verified.example"}),
            json!({"kind":"handle","value":"alice:verified.example"}),
        ] {
            let mut entry: AccountBlocklistEntry = serde_json::from_value(json!({
                "target":target,"mode":"hide","applies_to":["messages"],
                "created_at":"2026-01-01T00:00:00.000Z"}))
            .unwrap();
            let handle = arkret_sdk::Handle::parse("alice:verified.example").unwrap();
            assert!(crate::account_data::hides_typing(
                &[entry.clone()],
                &signal,
                std::slice::from_ref(&handle),
                now
            ));
            if target.get("kind") == Some(&json!("handle"))
                || target.get("value") == Some(&json!("verified.example"))
            {
                assert!(!crate::account_data::hides_typing(
                    &[entry.clone()],
                    &signal,
                    &[],
                    now
                ));
            }
            entry.mode = AccountBlocklistMode::Mute;
            assert!(!crate::account_data::hides_typing(
                &[entry.clone()],
                &signal,
                std::slice::from_ref(&handle),
                now
            ));
            entry.mode = AccountBlocklistMode::Block;
            entry.applies_to = vec![AccountBlocklistSurface::Calls];
            assert!(!crate::account_data::hides_typing(
                &[entry.clone()],
                &signal,
                std::slice::from_ref(&handle),
                now
            ));
            entry.applies_to = vec![AccountBlocklistSurface::Messages];
            entry.expires_at = Some(now);
            assert!(!crate::account_data::hides_typing(
                &[entry],
                &signal,
                std::slice::from_ref(&handle),
                now
            ));
        }
        for target in [
            json!({"kind":"domain","value":"example"}),
            json!({"kind":"domain","value":"principal.example"}),
            json!({"kind":"keyword","value":"typing"}),
            json!({"kind":"device","value":"did:web:alice.example#other"}),
        ] {
            let entry = serde_json::from_value(json!({"target":target,"mode":"block","applies_to":["messages"],"created_at":"2026-01-01T00:00:00.000Z"})).unwrap();
            assert!(!crate::account_data::hides_typing(
                &[entry],
                &signal,
                &[],
                now
            ));
        }
        let handles = [
            arkret_sdk::Handle::parse("primary:first.example").unwrap(),
            arkret_sdk::Handle::parse("secondary:second.example").unwrap(),
        ];
        let entry: AccountBlocklistEntry = serde_json::from_value(json!({"target":{"kind":"handle","value":"secondary:second.example"},"mode":"hide","applies_to":["messages"],"created_at":"2026-01-01T00:00:00.000Z"})).unwrap();
        assert!(crate::account_data::hides_typing(
            &[entry],
            &signal,
            &handles,
            now
        ));
        let entry: AccountBlocklistEntry = serde_json::from_value(json!({"target":{"kind":"domain","value":"alice.example"},"mode":"hide","applies_to":["dm"],"created_at":"2026-01-01T00:00:00.000Z"})).unwrap();
        assert!(!crate::account_data::hides_typing(
            &[entry.clone()],
            &signal,
            &[],
            now
        ));
        let mut direct = signal.clone();
        authorize_typing(&mut direct);
        direct.product_authority.as_mut().unwrap().profile_actions =
            vec![arkret_sdk::CapabilityActionId::TYPING_BROADCAST.into()];
        assert!(crate::account_data::hides_typing(
            &[entry],
            &direct,
            &[],
            now
        ));
        let mut webvh = signal.clone();
        webvh.signer_verification_method =
            arkret_sdk::DidUrl::new("did:webvh:z6mkfixture:alice.example#device-1").unwrap();
        let entry = serde_json::from_value(json!({"target":{"kind":"domain","value":"alice.example"},"mode":"block","applies_to":["messages"],"created_at":"2026-01-01T00:00:00.000Z"})).unwrap();
        assert!(!crate::account_data::hides_typing(
            &[entry],
            &webvh,
            &[],
            now
        ));
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn typing_product_observes_exact_private_blocklist_and_clears_retained_bodies() {
        use std::sync::Arc;
        let directory = tempfile::tempdir().unwrap();
        let store = Arc::new(Mutex::new(crate::LocalStateStore::with_path(
            directory.path().join("typing-block.json"),
        )));
        store.lock().unwrap().promote_accepted_context_for_test(
            &arkret_sdk::Did::new("did:web:bob.example").unwrap(),
        );
        let read = store.clone();
        let write = store.clone();
        let sink = InksonSignalSink {
            call_account: None,
            call_http: None,
            state_store: crate::runtime::input::StateStoreHandle::new(
                move |consume| consume(&read.lock().unwrap()),
                move |consume| consume(&mut write.lock().unwrap()),
            ),
            products: SignalProductRouter::default(),
            live: Mutex::new(Default::default()),
        };
        let id = arkret_sdk::StrandId::from_event_id(&arkret_sdk::EventId::from_digest(
            arkret_sdk::DigestSuite::Sha256,
            [31; 32],
        ));
        let mut signal = plaintext_of(
            "ak.typing",
            json!({"kind":"ak.typing", "strand_id":id, "typing":true}),
        );
        signal.expires_at = crate::clock::now_utc() + chrono::Duration::seconds(30);
        authorize_typing(&mut signal);
        assert!(sink.apply_live_body(&signal).unwrap());
        let entry = crate::account_data::new_blocklist_entry(
            crate::account_data::BlocklistUiTargetKind::Actor, &signal.actor_id().to_string(), None,
            vec![arkret_models_collaboration::objects::productivity::AccountBlocklistSurface::Messages],
            None, chrono::Utc::now(),
        ).unwrap();
        store.lock().unwrap().set_client_blocklist(1, vec![entry]);
        assert!(!sink.apply_live_body(&signal).unwrap());
        sink.expire_live_bodies(crate::clock::now_utc());
        assert!(sink.live.lock().unwrap().is_empty());
        assert!(store.lock().unwrap().load().presence_projection.is_empty());
        if let arkret_sdk::ActorId::Account { account_id } = &mut signal.domain.sender_actor_id {
            account_id.station_id =
                arkret_sdk::DidCoreId::new("ak:did_core:web:other-station.example").unwrap();
        }
        authorize_typing(&mut signal);
        assert!(sink.apply_live_body(&signal).unwrap());
        sink.expire_live_bodies(crate::clock::now_utc());
        assert_eq!(sink.live.lock().unwrap().len(), 1);
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[tokio::test]
    async fn decrypted_typing_without_verified_current_produces_no_live_body() {
        use std::sync::Arc;
        let directory = tempfile::tempdir().unwrap();
        let store = Arc::new(Mutex::new(crate::LocalStateStore::with_path(
            directory.path().join("typing-target.json"),
        )));
        let read = store.clone();
        let write = store.clone();
        let sink = InksonSignalSink {
            call_account: None,
            call_http: None,
            state_store: crate::runtime::input::StateStoreHandle::new(
                move |consume| consume(&read.lock().unwrap()),
                move |consume| consume(&mut write.lock().unwrap()),
            ),
            products: SignalProductRouter::default(),
            live: Mutex::new(Default::default()),
        };
        let id = arkret_sdk::StrandId::from_event_id(&arkret_sdk::EventId::from_digest(
            arkret_sdk::DigestSuite::Sha256,
            [31; 32],
        ));
        let signal = plaintext_of(
            "ak.typing",
            json!({"kind":"ak.typing", "strand_id":id, "typing":true}),
        );
        // Accepted fixture isolates product containment; it claims no transport/MLS proof.
        sink.handle(SignalReceiveOutcome::Accepted {
            call_invitation: None,
            domain: Box::new(signal.domain),
            authority_commit_id: signal.authority_commit_id,
            parent_realm_authority_commit_id: signal.parent_realm_authority_commit_id,
            signer_verification_method: signal.signer_verification_method,
            product_authority: signal.product_authority,
            plaintext: Box::new(signal.payload),
            effective_expires_at: crate::clock::now_utc() + chrono::Duration::seconds(5),
        })
        .await
        .unwrap();
        assert!(sink.live.lock().unwrap().is_empty());
        assert!(store.lock().unwrap().load().presence_projection.is_empty());
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
                call_account: None,
                call_http: None,
                state_store,
                products,
                live: Mutex::new(Default::default()),
            };
            let SignalReceiveOutcome::Accepted {
                domain,
                plaintext,
                effective_expires_at,
                authority_commit_id,
                parent_realm_authority_commit_id,
                product_authority,
                call_invitation,
                signer_verification_method,
            } = outcome
            else {
                return Ok(0);
            };
            let signal = AdmittedSignal {
                domain: *domain,
                authority_commit_id,
                parent_realm_authority_commit_id,
                product_authority,
                call_invitation,
                signer_verification_method,
                payload: *plaintext,
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
            call_invitation: None,
            domain: Box::new(signal.domain),
            authority_commit_id: signal.authority_commit_id,
            parent_realm_authority_commit_id: signal.parent_realm_authority_commit_id,
            signer_verification_method: signal.signer_verification_method,
            product_authority: signal.product_authority,
            plaintext: Box::new(signal.payload),
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

/// Install the sealed complete holder read and enforce its persisted high-water.
pub(crate) async fn install_call_consent_current(
    state_store: &crate::runtime::input::StateStoreHandle,
    account: &crate::config::ActiveAccountContext,
    response: &arkret_sdk::http_client::own_station_results::BoundOwnStationResponse<
        arkret_sdk::ConsentCurrentReadRequestBody,
        arkret_sdk::ConsentCurrentReadOutcome,
    >,
    session_epoch: u64,
    guard: &dyn Fn() -> anyhow::Result<()>,
) -> anyhow::Result<bool> {
    install_consent_current_for_holder(
        state_store,
        &account.authority,
        &account.principal_control_realm_id,
        response,
        session_epoch,
        guard,
    )
    .await
}

pub(crate) async fn install_consent_current_for_holder(
    state_store: &crate::runtime::input::StateStoreHandle,
    holder: &arkret_sdk::AccountId,
    pcr_realm: &arkret_sdk::RealmId,
    response: &arkret_sdk::http_client::own_station_results::BoundOwnStationResponse<
        arkret_sdk::ConsentCurrentReadRequestBody,
        arkret_sdk::ConsentCurrentReadOutcome,
    >,
    session_epoch: u64,
    guard: &dyn Fn() -> anyhow::Result<()>,
) -> anyhow::Result<bool> {
    guard()?;
    anyhow::ensure!(
        response.value()?.realm_id == *pcr_realm,
        "Consent current differs from accepted holder PCR"
    );
    let index = crate::state::CurrentIndex::open_committed(
        holder,
        state_store.read(|s| s.current_index_location()),
        || Ok(state_store.read(|s| s.current_generation())),
    )
    .await?;
    let mut stage = index
        .stage_consent_current(
            || Ok(state_store.read(|s| s.current_generation())),
            &response,
            &guard,
        )
        .await?;
    state_store
        .write(|store| {
            store.verified_projection_transaction(|store| {
                if store.active_authority() != Some(holder.clone())
                    || store.current_reset_required()
                    || crate::identity::device_directory::session_cache_epoch() != session_epoch
                {
                    return Err("ring attempt changed before installation".to_owned());
                }
                response.value().map_err(|e| e.to_string())?;
                stage.arm_account_commit();
                store.set_current_generation(stage.generation());
                Ok(())
            })
        })
        .map_err(anyhow::Error::msg)?;
    let durable = state_store.read(|s| s.begin_durable_flush())?.wait().await;
    if let Err(error) = durable {
        index.poison();
        return Err(anyhow::anyhow!(error));
    }
    stage.finish();
    guard()?;
    let progress = index
        .read_progress(response.value()?.realm_id.as_str())
        .await?;
    if progress.observed_governance_generation != Some(response.value()?.governance_generation)
        || !progress
            .observed_heads
            .contains(&response.value()?.effective_stream_head)
    {
        return Ok(false);
    }
    Ok(response
        .value()?
        .permits(response.request(), crate::clock::now_utc()))
}
